"""Verification for relay / agent mode.

The relay is a write path into a firewall's data store from a less-trusted
host on a camera segment, so most of what is checked here is adversarial:
what a holder of the shared key, or anyone who can reach the ingest port,
can make the collector do.

Run: PYTHONPATH=src:tests python tests/verify_relay.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from surveillancehound import validate as V  # noqa: E402

T0 = 1_792_000_000.0


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def _rejects(fn, *args, what: str) -> None:
    try:
        fn(*args)
    except V.ValidationError:
        return
    raise AssertionError(f"accepted {what} — it should have been rejected")


def _check_json_constants() -> None:
    assert V.loads_strict(b'{"a": 1.5}') == {"a": 1.5}
    for bad in (b'{"a": NaN}', b'{"a": Infinity}', b'{"a": -Infinity}'):
        _rejects(V.loads_strict, bad, what=bad.decode())
    _rejects(V.loads_strict, b"{not json", what="malformed JSON")
    _rejects(V.loads_strict, b'{"a": "\xff\xfe"}', what="invalid UTF-8")
    print("  json: NaN/Infinity/malformed/bad-UTF-8 all rejected")


def _check_scalars() -> None:
    # the stored-XSS vector: a string where a number is expected
    _rejects(V.clean_int, "<img src=x onerror=alert(1)>", "flow.packets",
             what="a script tag in a numeric field")
    _rejects(V.clean_int, "12", "flow.packets", what="a numeric string")
    _rejects(V.clean_int, -1, "flow.packets", what="a negative counter")
    _rejects(V.clean_int, True, "flow.packets", what="a bool as a number")
    _rejects(V.clean_float, float("inf"), "x", what="infinity")
    assert V.clean_int(42, "x") == 42

    # control characters are stripped, not preserved — log/header injection
    assert V.clean_str("a\nb\r\tc\x00d", "summary") == "abcd"
    _rejects(V.clean_str, "x" * 5000, "summary", what="an oversized string")
    _rejects(V.clean_str, 5, "summary", what="a non-string")

    assert V.clean_ip("10.0.0.1", "ip") == "10.0.0.1"
    _rejects(V.clean_ip, "cam1.cams.lan", "ip", what="a hostname")
    _rejects(V.clean_ip, "", "ip", what="an empty address")
    assert V.clean_ip("", "ip", allow_empty=True) == ""

    _rejects(V.clean_choice, "../../etc/passwd", V.ALERT_KINDS, "kind",
             what="path traversal in kind")
    _rejects(V.clean_choice, "made_up", V.ALERT_KINDS, "kind",
             what="an out-of-set kind")
    assert V.clean_choice("camera_offline", V.ALERT_KINDS, "kind") == "camera_offline"
    print("  scalars: XSS, traversal, injection, out-of-range all rejected")


def _good_records() -> dict:
    return {
        "devices": [{"ip": "117.111.101.2", "role": "camera",
                     "first_seen": T0, "last_seen": T0 + 10,
                     "packet_count": 5, "byte_count": 500}],
        "flows": [{"remote_id": 1, "src_ip": "117.111.101.2", "src_port": 554,
                   "dst_ip": "88.255.5.11", "dst_port": 40000, "proto": "tcp",
                   "first_seen": T0, "last_seen": T0 + 5, "packets": 10,
                   "bytes": 1000, "bytes_to_camera": 100,
                   "bytes_from_camera": 900, "tcp_flags_seen": "PA",
                   "classification": "lan_normal"}],
        "alerts": [{"remote_id": 1, "ts": T0, "device_ip": "117.111.101.2",
                    "kind": "camera_offline", "severity": "medium",
                    "summary": "camera is silent", "detail": "d",
                    "dedup_key": "camera_offline:117.111.101.2:1"}],
        "outages": [{"remote_id": 1, "camera_ip": "117.111.101.2",
                     "down_since": T0, "up_at": None,
                     "last_seen_before": T0 - 60, "cause": "silence"}],
        "uptime": [{"ip": "117.111.101.2", "role": "camera", "state": "down",
                    "last_seen": T0, "first_seen": T0 - 1000,
                    "down_since": T0, "current_downtime": 60.0,
                    "outage_count": 1, "downtime_seconds": 60.0,
                    "monitored_seconds": 3600.0, "availability": 0.98}],
        "monitor": {"alive": True, "blind": False, "last_activity_ts": T0},
    }


def _check_records() -> None:
    ok = V.validate_records(_good_records(), max_per_kind=100)
    assert len(ok["flows"]) == 1 and ok["monitor"]["alive"] is True
    assert ok["alerts"][0]["kind"] == "camera_offline"

    # each of these must reject the WHOLE batch
    bad_cases = {
        "script tag in flow.packets":
            lambda r: r["flows"][0].__setitem__("packets", "<img src=x>"),
        "out-of-set alert kind":
            lambda r: r["alerts"][0].__setitem__("kind", "totally_new"),
        "traversal in alert kind":
            lambda r: r["alerts"][0].__setitem__("kind", "../../x"),
        "bogus severity":
            lambda r: r["alerts"][0].__setitem__("severity", "catastrophic"),
        "hostname as device ip":
            lambda r: r["devices"][0].__setitem__("ip", "cam.lan"),
        "availability above 1":
            lambda r: r["uptime"][0].__setitem__("availability", 42.0),
        "negative byte count":
            lambda r: r["devices"][0].__setitem__("byte_count", -5),
        "unknown record kind":
            lambda r: r.__setitem__("evil", [{"x": 1}]),
        "flows not a list":
            lambda r: r.__setitem__("flows", {"not": "a list"}),
    }
    for label, mutate in bad_cases.items():
        recs = _good_records()
        mutate(recs)
        _rejects(V.validate_records, recs, 100, what=label)

    # newline in a summary is stripped, not stored — SIEM log injection
    recs = _good_records()
    recs["alerts"][0]["summary"] = "ok\n1760000000 [critical] forged event"
    cleaned = V.validate_records(recs, 100)
    assert "\n" not in cleaned["alerts"][0]["summary"], "newline survived"

    # unknown keys inside a record are dropped rather than stored
    recs = _good_records()
    recs["flows"][0]["evil_column"] = "DROP TABLE flows"
    assert "evil_column" not in V.validate_records(recs, 100)["flows"][0]

    # per-kind cap
    recs = _good_records()
    recs["flows"] = recs["flows"] * 5
    _rejects(V.validate_records, recs, 2, what="a batch over the per-kind cap")
    print("  records: 9 hostile batches rejected; injection stripped; caps enforced")



# ---------------------------------------------------------------------------
# hardening of paths an untrusted record reaches
# ---------------------------------------------------------------------------

def _check_notification_hardening() -> None:
    """A relayed field must not be able to forge a log line or mis-attribute.

    These three paths all predate the relay and were safe only because the
    daemon produced every value itself.
    """
    import tempfile
    from surveillancehound.alerts import Alert
    from surveillancehound.notify import LogfileChannel, _oneline

    assert "\n" not in _oneline("a\nb") and _oneline("a\nb") == "a b"

    # one alert must be exactly one line, whatever the summary contains
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "hound.log"
        ch = LogfileChannel(level="info", path=str(path))
        ch.dispatch(Alert(
            ts=T0, device_ip="10.0.0.5", kind="new_device", severity="info",
            summary="ok\n1760000000 [critical] bulk_inbound 10.0.0.1 — forged",
            detail="d", dedup_key="k", sensor="frigate",
        ))
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1, f"log injection: wrote {len(lines)} lines"
        assert "forged" in lines[0] and "critical" in lines[0]

    # the alert carries its origin, and syslog attributes it to that sensor
    a = Alert(ts=T0, device_ip="10.0.0.5", kind="new_device", severity="info",
              summary="s", detail="d", dedup_key="k", sensor="frigate")
    assert a.as_dict()["sensor"] == "frigate"
    assert Alert(ts=T0, device_ip="", kind="new_device", severity="info",
                 summary="s", detail="d", dedup_key="k").as_dict()["sensor"] == "local"
    print("  notify: newline cannot forge a log line; alerts carry their sensor")


def _check_dashboard_numeric_escaping() -> None:
    """Numeric columns must be coerced before reaching innerHTML.

    SQLite is dynamically typed, so a relayed flow could carry a string in
    an INTEGER column; those fields are interpolated into innerHTML without
    escapeHTML, which would be stored XSS in the firewall UI.
    """
    web = (Path(__file__).resolve().parent.parent
           / "src/surveillancehound/web.py").read_text()
    assert "const num = (v) =>" in web, "web.py lost its numeric coercion helper"
    for raw in ("${f.packets}", "${f.bytes_to_camera ?", "${c.outage_count ?",
                "${s.packet_count}", "${b.n}", "${s.id}.pcap"):
        assert raw not in web, (
            f"web.py interpolates {raw} unguarded — a non-numeric value "
            f"from a relayed row would be rendered as markup"
        )
    print("  dashboard: numeric interpolations coerced, not trusted")


def main() -> int:
    print("=== relay validation ===")
    _check_json_constants()
    _check_scalars()
    _check_records()
    _check_notification_hardening()
    _check_dashboard_numeric_escaping()
    print("\nRELAY VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
