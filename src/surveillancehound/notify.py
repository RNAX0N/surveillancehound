"""Notification dispatch — pluggable channels selected via config.

The operator picks 'whatever notification means' the deployment wants, in any
combination, by adding `[[notify]]` blocks to the config. Built-in channels:

  * stdout    — write to the daemon's stdout. Always available; a sane default.
  * logfile   — append to a plain-text log file (one alert per line).
  * jsonlines — append one JSON object per line to a file. Easy to tail / pipe.
  * webhook   — POST a JSON body to a URL (Slack/Discord/PagerDuty/your own).

Email / syslog / native push-services are deliberately not bundled — they need
deployment-specific credentials. Adding one is a five-line subclass that
implements `dispatch(alert)`. The framework + the four channels above cover the
common deployments out of the box.

Every dispatch (success or failure) is logged into the `notifications` table —
the operator can audit which alerts went where.
"""

from __future__ import annotations

import abc
import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from surveillancehound.alerts import Alert
from surveillancehound.config import NotifyChannelCfg
from surveillancehound.store import HoundStore

log = logging.getLogger(__name__)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _passes_level(alert_sev: str, channel_level: str) -> bool:
    return _SEVERITY_RANK.get(alert_sev, 0) >= _SEVERITY_RANK.get(channel_level, 0)


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

    def dispatch(self, alert: Alert) -> None:
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a") as f:
            f.write(
                f"{int(alert.ts)} [{alert.severity}] {alert.kind} "
                f"{alert.device_ip} — {alert.summary}\n"
            )


@dataclass
class JsonLinesChannel(NotifyChannel):
    path: str
    type: str = "jsonlines"
    level: str = "low"

    def dispatch(self, alert: Alert) -> None:
        p = Path(self.path)
        p.parent.mkdir(parents=True, exist_ok=True)
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


_BUILTIN = {
    "stdout": StdoutChannel,
    "logfile": LogfileChannel,
    "jsonlines": JsonLinesChannel,
    "webhook": WebhookChannel,
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
        return LogfileChannel(path=cfg.path, level=cfg.level)
    if cls is JsonLinesChannel:
        if not cfg.path:
            raise ValueError("jsonlines channel requires `path`")
        return JsonLinesChannel(path=cfg.path, level=cfg.level)
    if cls is WebhookChannel:
        if not cfg.url:
            raise ValueError("webhook channel requires `url`")
        return WebhookChannel(
            url=cfg.url, level=cfg.level, headers=cfg.headers,
            timeout=cfg.timeout,
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
            except (urllib.error.URLError, OSError, ValueError) as e:
                ok, err = False, f"{type(e).__name__}: {e}"
                log.warning("notify %s failed: %s", ch.type, err)
            except Exception as e:  # noqa: BLE001
                ok, err = False, f"{type(e).__name__}: {e}"
                log.exception("notify %s errored", ch.type)
            self.store.record_notification(alert_id, ch.type, ok, err)
            if ok:
                delivered.append(ch.type)
        return delivered
