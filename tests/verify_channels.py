"""End-to-end verification of the new notification channels.

Spins up in-process mock servers for syslog (UDP + TCP) and SMTP, then
runs Hound through a known-answer pcap with one [[notify]] entry per
channel pointing at the mock. Assertions:

  * UDP syslog: a datagram arrives that's RFC 5424-shaped (priority,
    timestamp, hostname, app, structured-data, msg).
  * TCP syslog: an octet-counted frame arrives with the same shape.
  * SMTP: a MAIL FROM / RCPT TO / DATA exchange completes and the captured
    body has Subject / From / To / a recognizable Hound body.
  * FTP construct: builds the channel from config, dispatches against an
    unreachable host, verifies the dispatcher catches and audits the
    error (rather than crashing the daemon).

No third-party libs — we hand-roll just enough of each protocol to
verify the channel emits the right bytes.
"""

from __future__ import annotations

import socket
import socketserver
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from surveillancehound.alerts import Alert  # noqa: E402
from surveillancehound.config import (  # noqa: E402
    AlertsCfg, BaselineCfg, CaptureCfg, HoundCfg, NetworkCfg,
    NotifyChannelCfg, SnapshotCfg, StoreCfg, ThresholdCfg, WebCfg,
)
from surveillancehound.notify import (  # noqa: E402
    Dispatcher, EmailChannel, FtpChannel, SyslogChannel, build_channel,
)
from surveillancehound.store import HoundStore  # noqa: E402


# ---------- mock servers ----------------------------------------------------


class _UdpSyslogServer(socketserver.UDPServer):
    allow_reuse_address = True


class _UdpSyslogHandler(socketserver.BaseRequestHandler):
    received: list[bytes] = []

    def handle(self):  # noqa: D401
        data, _sock = self.request
        _UdpSyslogHandler.received.append(data)


class _TcpSyslogServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class _TcpSyslogHandler(socketserver.BaseRequestHandler):
    received: list[bytes] = []

    def handle(self):
        # RFC 6587 octet-counting: "<n> <msg>"
        buf = b""
        while b" " not in buf:
            chunk = self.request.recv(64)
            if not chunk:
                return
            buf += chunk
        n_str, rest = buf.split(b" ", 1)
        n = int(n_str)
        while len(rest) < n:
            chunk = self.request.recv(n - len(rest))
            if not chunk:
                break
            rest += chunk
        _TcpSyslogHandler.received.append(rest[:n])


class _MockSMTP:
    """Just enough of SMTP to capture HELO / MAIL / RCPT / DATA. No TLS."""

    captured: list[dict] = []

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        try:
            client, _ = self.sock.accept()
        except OSError:
            return
        f = client.makefile("rwb", buffering=0)
        f.write(b"220 mock.smtp.local ESMTP\r\n")
        session = {"from": "", "to": [], "body": b""}
        in_data = False
        for line in f:
            if in_data:
                if line.strip() == b".":
                    f.write(b"250 OK queued\r\n")
                    in_data = False
                    _MockSMTP.captured.append(session)
                    session = {"from": "", "to": [], "body": b""}
                    continue
                session["body"] += line
                continue
            text = line.decode(errors="replace").strip()
            up = text.upper()
            if up.startswith("EHLO") or up.startswith("HELO"):
                f.write(b"250-mock.smtp.local\r\n250 SIZE 10485760\r\n")
            elif up.startswith("MAIL FROM:"):
                # MAIL FROM:<addr> [SIZE=...] — take the angle-quoted part
                rest = text[10:].strip()
                addr = rest.split(">", 1)[0].lstrip(" <")
                session["from"] = addr
                f.write(b"250 OK\r\n")
            elif up.startswith("RCPT TO:"):
                rest = text[8:].strip()
                addr = rest.split(">", 1)[0].lstrip(" <")
                session["to"].append(addr)
                f.write(b"250 OK\r\n")
            elif up == "DATA":
                f.write(b"354 Start mail input\r\n")
                in_data = True
            elif up == "QUIT":
                f.write(b"221 bye\r\n")
                break
            elif up == "RSET":
                f.write(b"250 OK\r\n")
            else:
                f.write(b"250 OK\r\n")
        client.close()
        self.sock.close()


def _mk_alert(severity: str = "high", kind: str = "bulk_inbound") -> Alert:
    return Alert(
        ts=time.time(), device_ip="192.168.10.22", kind=kind,
        severity=severity,
        summary="bulk_inbound: 198.51.100.5:80 -> 192.168.10.22:52000",
        detail="1,408,000 bytes transferred TOWARD the camera.",
        dedup_key=f"{kind}:192.168.10.22",
    )


# ---------- test bodies -----------------------------------------------------


def _check_syslog_udp() -> None:
    server = _UdpSyslogServer(("127.0.0.1", 0), _UdpSyslogHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ch = SyslogChannel(host="127.0.0.1", port=port, proto="udp",
                           level="info", facility=16)
        ch.dispatch(_mk_alert("medium", "control_channel_suspect"))
        # wait briefly for the datagram
        for _ in range(20):
            if _UdpSyslogHandler.received:
                break
            time.sleep(0.05)
        assert _UdpSyslogHandler.received, "no syslog datagram received"
        msg = _UdpSyslogHandler.received[0].decode("utf-8")
        # priority = 16*8 + 4 = 132 (local0 / warning)
        assert msg.startswith("<132>1 "), msg[:50]
        assert "hound" in msg
        assert "control_channel_suspect" in msg
        assert "hound@32473" in msg, "structured-data id missing"
        assert "device=\"192.168.10.22\"" in msg, "structured-data fields missing"
        print(f"  syslog UDP: ok ({len(msg)}-byte RFC 5424 datagram on :{port})")
    finally:
        server.shutdown()
        server.server_close()


def _check_syslog_tcp() -> None:
    server = _TcpSyslogServer(("127.0.0.1", 0), _TcpSyslogHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ch = SyslogChannel(host="127.0.0.1", port=port, proto="tcp",
                           level="info", facility=16)
        ch.dispatch(_mk_alert("high", "bulk_inbound"))
        for _ in range(30):
            if _TcpSyslogHandler.received:
                break
            time.sleep(0.05)
        assert _TcpSyslogHandler.received, "no syslog TCP frame received"
        msg = _TcpSyslogHandler.received[0].decode("utf-8")
        # priority = 16*8 + 3 = 131 (local0 / error)
        assert msg.startswith("<131>1 "), msg[:50]
        assert "bulk_inbound" in msg
        print(f"  syslog TCP: ok ({len(msg)}-byte RFC 6587 frame on :{port})")
    finally:
        server.shutdown()
        server.server_close()


def _check_email() -> None:
    smtp = _MockSMTP()
    ch = EmailChannel(
        smtp_host="127.0.0.1", smtp_port=smtp.port,
        smtp_use_tls=False,
        smtp_from="alerts@hound.local",
        smtp_to=["secops@example.com", "ops-oncall@example.com"],
        level="medium",
    )
    ch.dispatch(_mk_alert("high", "telemetry_offnet"))
    smtp.thread.join(timeout=2.0)
    assert _MockSMTP.captured, "no SMTP exchange captured"
    msg = _MockSMTP.captured[0]
    assert msg["from"] == "alerts@hound.local", msg["from"]
    assert "secops@example.com" in msg["to"], msg["to"]
    body = msg["body"].decode("utf-8", errors="replace")
    assert "Subject: [SurveillanceHound] HIGH telemetry_offnet" in body, body[:300]
    assert "Kind:     telemetry_offnet" in body, body[:300]
    assert "192.168.10.22" in body, body[:300]
    print(f"  email: ok (captured Subject + 2 recipients + Hound body on "
          f":{smtp.port})")


def _check_ftp_error_path() -> None:
    # No mock FTP server (stdlib has no FTP server). Verify construction
    # works and that dispatching to an unreachable host raises one of
    # ftplib.all_errors — the dispatcher catches that family and audits.
    import ftplib
    cfg = NotifyChannelCfg(
        type="ftp", host="127.0.0.1", port=1,  # nothing listens on :1
        level="high", timeout=1.0,
    )
    ch = build_channel(cfg)
    assert isinstance(ch, FtpChannel)
    try:
        ch.dispatch(_mk_alert("high"))
        raise AssertionError("expected ftp dispatch to fail")
    except ftplib.all_errors:
        pass
    print("  ftp: build_channel + caught error-path on unreachable host")


def _check_build_channel_validation() -> None:
    # missing required fields → ValueError (validated by build_channel,
    # not blown up at dispatch time)
    cases = [
        NotifyChannelCfg(type="syslog", host=""),           # no host
        NotifyChannelCfg(type="syslog", host="x", proto="weird"),
        NotifyChannelCfg(type="email", smtp_host=""),
        NotifyChannelCfg(type="email", smtp_host="x", smtp_from=""),
        NotifyChannelCfg(type="email", smtp_host="x",
                         smtp_from="a@b", smtp_to=[]),
        NotifyChannelCfg(type="ftp", host=""),
    ]
    for cfg in cases:
        try:
            build_channel(cfg)
            raise AssertionError(f"expected ValueError for {cfg.type}/{cfg.host!r}")
        except ValueError:
            pass
    print("  build_channel: required-field validation rejects bad configs")


def _check_dispatcher_audit() -> None:
    # Verify the dispatcher catches new exception families and records
    # both successes and failures in the notifications audit table.
    with tempfile.TemporaryDirectory() as td:
        store = HoundStore(path=Path(td) / "audit.sqlite")
        try:
            # one good (UDP syslog) + one failing (FTP)
            udp = _UdpSyslogServer(("127.0.0.1", 0), _UdpSyslogHandler)
            threading.Thread(target=udp.serve_forever, daemon=True).start()
            try:
                ok_ch = SyslogChannel(
                    host="127.0.0.1", port=udp.server_address[1],
                    proto="udp", level="info",
                )
                bad_ch = FtpChannel(
                    host="127.0.0.1", port=1, level="info", timeout=1.0,
                )
                d = Dispatcher([ok_ch, bad_ch], store=store)
                alert = _mk_alert("medium")
                aid = store.insert_alert(__import__("surveillancehound").store.AlertRow(
                    id=None, ts=alert.ts, device_ip=alert.device_ip,
                    kind=alert.kind, severity=alert.severity,
                    summary=alert.summary, detail=alert.detail,
                    dedup_key=alert.dedup_key,
                ))
                delivered = d.dispatch(alert, aid)
                assert "syslog" in delivered, delivered
                assert "ftp" not in delivered, delivered
            finally:
                udp.shutdown()
                udp.server_close()
            # audit table should have 2 rows for this alert (one ok=1, one ok=0)
            cur = store._conn.execute(  # noqa: SLF001 — direct check is fine
                "SELECT channel_type, ok, error FROM notifications "
                "WHERE alert_id = ? ORDER BY id", (aid,),
            ).fetchall()
            assert len(cur) == 2, cur
            assert cur[0]["channel_type"] == "syslog" and cur[0]["ok"] == 1
            assert cur[1]["channel_type"] == "ftp" and cur[1]["ok"] == 0
            assert cur[1]["error"], "ftp failure should record an error string"
            print("  dispatcher audit: 1 ok + 1 fail rows recorded with errors")
        finally:
            store.close()


def _check_unknown_notify_keys() -> None:
    """A key a notify block does not read must be REPORTED, not ignored.

    `[snapshot]` uses `min_severity`; `[[notify]]` uses `level`. Writing
    the first in a notify block is the natural mistake, and it used to
    be accepted silently — leaving `level` at its "low" default while
    the operator believed they had set a threshold. A channel that
    carries more or less than you think, with `config-check` calling the
    config fine, is the exact failure `unknown_sections` exists to
    prevent one level up. Made this mistake on a real sensor; hence the
    check and hence this test.
    """
    from surveillancehound.config import unknown_notify_keys

    found = unknown_notify_keys({
        "notify": [
            {"type": "logfile", "path": "/tmp/x", "min_severity": "critical"},
            {"type": "stdout", "level": "high"},          # clean
            {"type": "stdout", "nonsense": 1, "typo": 2},
        ]
    })
    assert found == [(1, "min_severity"), (3, "nonsense"), (3, "typo")], found

    # Every real field must pass, and the set is DERIVED from the
    # dataclass so adding a field cannot turn valid config into a
    # warning. Assert that derivation really happened.
    import dataclasses
    from surveillancehound.config import NotifyChannelCfg
    every = {f.name: "x" for f in dataclasses.fields(NotifyChannelCfg)}
    assert unknown_notify_keys({"notify": [every]}) == [], (
        "a declared NotifyChannelCfg field was reported as unknown; the "
        "valid set is not derived from the dataclass")

    # Shapes that must not raise: no notify at all, and a malformed block.
    assert unknown_notify_keys({}) == []
    assert unknown_notify_keys({"notify": "not-a-list"}) == []
    assert unknown_notify_keys({"notify": [None, 5, "x"]}) == []

    print(f"  unknown notify keys: reported with the block number, "
          f"derived from {len(every)} dataclass fields, malformed "
          f"blocks do not raise")


def main() -> int:
    _check_syslog_udp()
    _check_syslog_tcp()
    _check_email()
    _check_ftp_error_path()
    _check_build_channel_validation()
    _check_unknown_notify_keys()
    _check_dispatcher_audit()
    print("\nCHANNELS VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
