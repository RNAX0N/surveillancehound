"""Notification dispatch — pluggable channels selected via config.

The operator picks 'whatever notification means' the deployment wants, in any
combination, by adding `[[notify]]` blocks to the config. Built-in channels:

  * stdout    — write to the daemon's stdout. Always available; a sane default.
  * logfile   — append to a rotating plain-text log file.
  * jsonlines — append one JSON object per line to a rotating file.
  * webhook   — POST a JSON body to a URL (Slack/Discord/PagerDuty/Teams/etc.).
  * syslog    — RFC 5424 to a UDP or TCP receiver (Security Onion, Graylog,
                rsyslog/syslog-ng, pfSense, OPNsense, generic SIEM).
  * email     — SMTP via stdlib `smtplib` (STARTTLS optional).
  * ftp       — upload one JSON file per alert to an FTP / FTPS server.

Every dispatch (success or failure) is logged into the `notifications` table —
the operator can audit which alerts went where. Adding another channel is a
small subclass of `NotifyChannel` + a `build_channel()` case; all stay
stdlib-only.
"""

from __future__ import annotations

import abc
import ftplib
import io
import json
import logging
import smtplib
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

from surveillancehound.alerts import Alert
from surveillancehound.config import NotifyChannelCfg
from surveillancehound.store import HoundStore

log = logging.getLogger(__name__)

def _oneline(text: str) -> str:
    """Collapse anything that could break a line-oriented log format."""
    return "".join(" " if ch < " " or ch == "\x7f" else ch for ch in str(text))


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _passes_level(alert_sev: str, channel_level: str) -> bool:
    return _SEVERITY_RANK.get(alert_sev, 0) >= _SEVERITY_RANK.get(channel_level, 0)


def _maybe_rotate(path: Path, max_bytes: int, keep: int) -> None:
    """Size-based log rotation. If the file exists and is ≥ max_bytes, shift:
    `path.<keep-1>` → drop, `path.<keep-2>` → `path.<keep-1>`, ..., `path` →
    `path.1`. `max_bytes <= 0` disables rotation."""
    if max_bytes <= 0 or not path.exists():
        return
    try:
        if path.stat().st_size < max_bytes:
            return
    except OSError:
        return
    # shift: drop the oldest, rename the rest one slot up
    oldest = path.with_name(f"{path.name}.{keep}")
    if oldest.exists():
        try:
            oldest.unlink()
        except OSError:
            pass
    for i in range(keep - 1, 0, -1):
        src = path.with_name(f"{path.name}.{i}")
        dst = path.with_name(f"{path.name}.{i + 1}")
        if src.exists():
            try:
                src.rename(dst)
            except OSError:
                pass
    try:
        path.rename(path.with_name(f"{path.name}.1"))
    except OSError:
        pass


# --- channel ABC + built-ins -------------------------------------------------


class NotifyChannel(abc.ABC):
    """One configured notification target."""

    type: str
    level: str

    @abc.abstractmethod
    def dispatch(self, alert: Alert) -> None:
        """Send the alert. Raises on failure (Dispatcher catches and logs)."""


@dataclass
class StdoutChannel(NotifyChannel):
    type: str = "stdout"
    level: str = "low"

    def dispatch(self, alert: Alert) -> None:
        import sys
        sys.stdout.write(
            f"[HOUND/{alert.severity}] {alert.kind}: {alert.summary}\n"
        )
        sys.stdout.flush()


@dataclass
class LogfileChannel(NotifyChannel):
    path: str
    type: str = "logfile"
    level: str = "info"
    max_bytes: int = 10 * 1024 * 1024
    keep: int = 5

    def dispatch(self, alert: Alert) -> None:
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        _maybe_rotate(p, self.max_bytes, self.keep)
        with p.open("a") as f:
            # One alert must be exactly one line. A newline inside summary
            # would otherwise forge additional records in a file that SIEMs
            # tail — and with relayed alerts the summary is not necessarily
            # produced by this host.
            f.write(
                f"{int(alert.ts)} [{alert.severity}] {alert.kind} "
                f"{alert.sensor} {alert.device_ip} — "
                f"{_oneline(alert.summary)}\n"
            )


@dataclass
class JsonLinesChannel(NotifyChannel):
    path: str
    type: str = "jsonlines"
    level: str = "low"
    max_bytes: int = 10 * 1024 * 1024
    keep: int = 5

    def dispatch(self, alert: Alert) -> None:
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        _maybe_rotate(p, self.max_bytes, self.keep)
        with p.open("a") as f:
            f.write(json.dumps(alert.as_dict()) + "\n")


@dataclass
class WebhookChannel(NotifyChannel):
    url: str
    type: str = "webhook"
    level: str = "medium"
    headers: dict = None
    timeout: float = 5.0

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}

    def dispatch(self, alert: Alert) -> None:
        body = json.dumps(alert.as_dict()).encode()
        req_headers = {"Content-Type": "application/json", **self.headers}
        req = urllib.request.Request(
            self.url, data=body, method="POST", headers=req_headers
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            resp.read()


# RFC 5424 severity numbers (lower = more urgent). Hound's labels map onto a
# sane subset of these. emergency(0)/alert(1) are reserved for things that
# call the on-call at 3 AM; nothing Hound emits warrants that.
_SYSLOG_SEVERITY = {
    "info":     6,  # informational
    "low":      5,  # notice
    "medium":   4,  # warning
    "high":     3,  # error
    "critical": 2,  # critical
}

# Placeholder Private Enterprise Number for syslog STRUCTURED-DATA.
# 32473 is IANA-reserved for documentation/examples (RFC 5612); swap in your
# org's assigned PEN if you have one.
_SD_ID = "hound@32473"


@dataclass
class SyslogChannel(NotifyChannel):
    """RFC 5424 syslog over UDP (default) or TCP (RFC 6587 octet-counting).

    Works with: Security Onion (syslog-ng on udp/514 by default),
    rsyslog / syslog-ng, Graylog (gelf/syslog input), Splunk (Universal
    Forwarder syslog input), Elastic (Logstash syslog input), pfSense /
    OPNsense remote syslog receivers, and any generic SIEM that speaks
    RFC 5424. Includes STRUCTURED-DATA so SIEMs can parse the fields
    without regex.
    """
    host: str
    type: str = "syslog"
    level: str = "low"
    port: int = 514
    proto: str = "udp"     # udp | tcp
    facility: int = 16     # local0
    app_name: str = "hound"
    timeout: float = 5.0

    def dispatch(self, alert: Alert) -> None:
        sev = _SYSLOG_SEVERITY.get(alert.severity, 5)
        prival = self.facility * 8 + sev
        ts = datetime.fromtimestamp(alert.ts, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ",
        )
        # The originating sensor, not this host — a relayed event did not
        # happen here, and stamping the firewall's hostname on it
        # mis-attributes it in the SIEM.
        hostname = (
            socket.gethostname() if alert.sensor == "local" else alert.sensor
        ) or "-"
        # escape STRUCTURED-DATA values per RFC 5424 §6.3.3
        def _esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
        sd = (
            f'[{_SD_ID} kind="{_esc(alert.kind)}" severity="{_esc(alert.severity)}" '
            f'device="{_esc(alert.device_ip)}"]'
        )
        # MSG body: BOM (per RFC 5424 §6.4 for UTF-8) + summary
        msg_body = f"﻿{alert.summary}"
        line = (
            f"<{prival}>1 {ts} {hostname} {self.app_name} - "
            f"{_esc(alert.kind)} {sd} {msg_body}"
        )
        data = line.encode("utf-8")
        if self.proto.lower() == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(data, (self.host, self.port))
            finally:
                sock.close()
        else:  # tcp
            # RFC 6587 octet-counting framing: "<len> <msg>"
            framed = f"{len(data)} ".encode() + data
            with socket.create_connection(
                (self.host, self.port), timeout=self.timeout,
            ) as s:
                s.sendall(framed)


@dataclass
class EmailChannel(NotifyChannel):
    """SMTP via stdlib smtplib. STARTTLS by default; set use_tls=False for
    plaintext (LAN-only relays). For Gmail-style SMTP-AUTH-LOGIN-with-app-
    password, set smtp_user + smtp_password.

    Default level is "medium" — email is noisier than chat; you usually want
    a higher threshold than for stdout/jsonlines.
    """
    smtp_host: str
    smtp_from: str
    smtp_to: list[str]
    type: str = "email"
    level: str = "medium"
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_subject_prefix: str = "[SurveillanceHound]"
    timeout: float = 10.0

    def dispatch(self, alert: Alert) -> None:
        msg = EmailMessage()
        msg["Subject"] = (
            f"{self.smtp_subject_prefix} {alert.severity.upper()} "
            f"{alert.kind} — {alert.device_ip}"
        )
        msg["From"] = self.smtp_from
        msg["To"] = ", ".join(self.smtp_to)
        ts_iso = datetime.fromtimestamp(alert.ts).isoformat(timespec="seconds")
        msg.set_content(
            f"SurveillanceHound alert\n"
            f"\n"
            f"  Kind:     {alert.kind}\n"
            f"  Severity: {alert.severity}\n"
            f"  Device:   {alert.device_ip}\n"
            f"  Time:     {ts_iso}\n"
            f"\n"
            f"Summary:\n  {alert.summary}\n"
            f"\n"
            f"Detail:\n  {alert.detail}\n"
            f"\n"
            f"— hound on {socket.gethostname()}\n",
        )
        smtp = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout)
        try:
            smtp.ehlo()
            if self.smtp_use_tls:
                smtp.starttls()
                smtp.ehlo()
            if self.smtp_user:
                smtp.login(self.smtp_user, self.smtp_password)
            smtp.send_message(msg)
        finally:
            try:
                smtp.quit()
            except smtplib.SMTPException:
                pass


@dataclass
class FtpChannel(NotifyChannel):
    """Upload one JSON file per alert to an FTP / FTPS server.

    File naming: `hound-<unix_ts>-<kind>-<device>.json`. FTPS = explicit
    AUTH TLS (`FTP_TLS` from ftplib). Default level is "high" — FTP per
    alert opens a fresh TCP connection per alert, so this isn't for chatty
    info/low traffic.
    """
    host: str
    type: str = "ftp"
    level: str = "high"
    port: int = 21
    ftp_user: str = "anonymous"
    ftp_password: str = "hound@localhost"
    ftp_dir: str = "/"
    ftp_use_tls: bool = False
    timeout: float = 15.0

    def dispatch(self, alert: Alert) -> None:
        payload = (json.dumps(alert.as_dict(), indent=2) + "\n").encode()
        safe_device = alert.device_ip.replace(":", "_").replace("/", "_")
        filename = (
            f"hound-{int(alert.ts)}-{alert.kind}-{safe_device}.json"
        )
        cls = ftplib.FTP_TLS if self.ftp_use_tls else ftplib.FTP
        ftp = cls(timeout=self.timeout)
        ftp.connect(self.host, self.port)
        try:
            ftp.login(self.ftp_user, self.ftp_password)
            if self.ftp_use_tls:
                ftp.prot_p()  # protect the data connection too
            if self.ftp_dir and self.ftp_dir not in ("", "/"):
                ftp.cwd(self.ftp_dir)
            ftp.storbinary(f"STOR {filename}", io.BytesIO(payload))
        finally:
            try:
                ftp.quit()
            except ftplib.all_errors:
                pass


_BUILTIN = {
    "stdout": StdoutChannel,
    "logfile": LogfileChannel,
    "jsonlines": JsonLinesChannel,
    "webhook": WebhookChannel,
    "syslog": SyslogChannel,
    "email": EmailChannel,
    "ftp": FtpChannel,
}


def build_channel(cfg: NotifyChannelCfg) -> NotifyChannel:
    """Construct a NotifyChannel from a config entry."""
    cls = _BUILTIN.get(cfg.type)
    if cls is None:
        raise ValueError(
            f"unknown notify channel type {cfg.type!r}; built-in: "
            f"{sorted(_BUILTIN)}"
        )
    if cls is StdoutChannel:
        return StdoutChannel(level=cfg.level)
    if cls is LogfileChannel:
        if not cfg.path:
            raise ValueError("logfile channel requires `path`")
        return LogfileChannel(
            path=cfg.path, level=cfg.level,
            max_bytes=cfg.max_bytes, keep=cfg.keep,
        )
    if cls is JsonLinesChannel:
        if not cfg.path:
            raise ValueError("jsonlines channel requires `path`")
        return JsonLinesChannel(
            path=cfg.path, level=cfg.level,
            max_bytes=cfg.max_bytes, keep=cfg.keep,
        )
    if cls is WebhookChannel:
        if not cfg.url:
            raise ValueError("webhook channel requires `url`")
        return WebhookChannel(
            url=cfg.url, level=cfg.level, headers=cfg.headers,
            timeout=cfg.timeout,
        )
    if cls is SyslogChannel:
        if not cfg.host:
            raise ValueError("syslog channel requires `host`")
        if cfg.proto.lower() not in ("udp", "tcp"):
            raise ValueError(
                f"syslog `proto` must be 'udp' or 'tcp' (got {cfg.proto!r})"
            )
        return SyslogChannel(
            host=cfg.host, port=cfg.port or 514,
            proto=cfg.proto, facility=cfg.facility, app_name=cfg.app_name,
            level=cfg.level, timeout=cfg.timeout,
        )
    if cls is EmailChannel:
        if not cfg.smtp_host:
            raise ValueError("email channel requires `smtp_host`")
        if not cfg.smtp_from:
            raise ValueError("email channel requires `smtp_from`")
        if not cfg.smtp_to:
            raise ValueError("email channel requires `smtp_to` (list of addrs)")
        return EmailChannel(
            smtp_host=cfg.smtp_host, smtp_port=cfg.smtp_port,
            smtp_from=cfg.smtp_from, smtp_to=list(cfg.smtp_to),
            smtp_user=cfg.smtp_user, smtp_password=cfg.smtp_password,
            smtp_use_tls=cfg.smtp_use_tls,
            smtp_subject_prefix=cfg.smtp_subject_prefix,
            level=cfg.level, timeout=cfg.timeout,
        )
    if cls is FtpChannel:
        if not cfg.host:
            raise ValueError("ftp channel requires `host`")
        return FtpChannel(
            host=cfg.host, port=cfg.port or 21,
            ftp_user=cfg.ftp_user, ftp_password=cfg.ftp_password,
            ftp_dir=cfg.ftp_dir, ftp_use_tls=cfg.ftp_use_tls,
            level=cfg.level, timeout=cfg.timeout,
        )
    raise AssertionError(f"unreachable: {cls}")


# --- dispatcher --------------------------------------------------------------


class Dispatcher:
    """Sends an alert through every channel whose level threshold it clears."""

    def __init__(
        self, channels: list[NotifyChannel], store: HoundStore
    ) -> None:
        self.channels = channels
        self.store = store

    def dispatch(self, alert: Alert, alert_id: int) -> list[str]:
        """Push to every applicable channel. Returns the channel types that
        accepted the alert (used for the alert row's notified_channels column)."""
        delivered: list[str] = []
        for ch in self.channels:
            if not _passes_level(alert.severity, ch.level):
                continue
            ok, err = True, ""
            try:
                ch.dispatch(alert)
            except (urllib.error.URLError, OSError, ValueError,
                    smtplib.SMTPException) as e:
                ok, err = False, f"{type(e).__name__}: {e}"
                log.warning("notify %s failed: %s", ch.type, err)
            except ftplib.all_errors as e:
                ok, err = False, f"{type(e).__name__}: {e}"
                log.warning("notify %s (ftp) failed: %s", ch.type, err)
            except Exception as e:  # noqa: BLE001
                ok, err = False, f"{type(e).__name__}: {e}"
                log.exception("notify %s errored", ch.type)
            self.store.record_notification(alert_id, ch.type, ok, err)
            if ok:
                delivered.append(ch.type)
        return delivered
