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



# ---------------------------------------------------------------------------
# config guards
# ---------------------------------------------------------------------------

def _check_relay_config() -> None:
    """The guards that separate a relay from an exfiltration channel."""
    from surveillancehound.config import load_from_dict

    base = {"capture": {"pcap_file": "x.pcap"},
            "network": {"lan_subnets": ["88.255.0.0/16"]}}

    def load(relay):
        return load_from_dict({**base, "relay": relay})

    def rejects(relay, what):
        try:
            load(relay)
        except ValueError:
            return
        raise AssertionError(f"accepted {what} — should have been refused")

    assert load({}).relay.mode == "off", "relay must default to off"

    agent = {"mode": "agent", "sensor_id": "frigate", "key": "k",
             "url": "https://88.255.5.1:18443/ingest/v1",
             "tls_fingerprint": "sha256:abc"}
    cfg = load(agent)
    assert cfg.relay.is_agent and cfg.relay.tls_fingerprint == ["sha256:abc"]

    rejects({**agent, "url": "https://collector.lan:18443/x"},
            "a hostname in relay.url (the daemon does no DNS)")
    rejects({**agent, "url": "https://203.0.113.9:18443/x"},
            "an off-network relay destination")
    assert load({**agent, "url": "https://203.0.113.9:18443/x",
                 "allow_any_destination": True}).relay.is_agent
    rejects({k: v for k, v in agent.items() if k != "tls_fingerprint"},
            "agent mode with no pinned fingerprint")
    rejects({k: v for k, v in agent.items() if k != "key"},
            "agent mode with no shared key")

    coll = {"mode": "collector", "listen_host": "88.255.5.1",
            "sensor": [{"id": "frigate", "key": "k"}]}
    assert load(coll).relay.key_for("frigate") == "k"
    assert load(coll).relay.key_for("nope") is None
    rejects({**coll, "listen_host": "0.0.0.0"},
            "a collector listening on every interface")
    assert load({**coll, "listen_host": "0.0.0.0",
                 "listen_allow_any": True}).relay.is_collector
    rejects({"mode": "collector", "listen_host": "88.255.5.1"},
            "a collector with no sensors")
    rejects({**coll, "sensor": [{"id": "a", "key": "k"}, {"id": "a", "key": "j"}]},
            "duplicate sensor ids")
    rejects({"mode": "sideways"}, "an unknown relay mode")
    print("  config: 12 relay guards hold; mode defaults to off")


def _check_key_never_printed() -> None:
    """config-check prints every other section; it must not print the key."""
    import io
    import contextlib
    import tempfile
    from surveillancehound import cli

    secret = "s3cr3t-relay-key-do-not-print"
    with tempfile.TemporaryDirectory() as td:
        cfg_path = Path(td) / "h.toml"
        cfg_path.write_text(
            '[capture]\npcap_file = "x.pcap"\n'
            '[network]\nlan_subnets = ["88.255.0.0/16"]\n'
            '[store]\npath = "s.sqlite"\n'
            '[relay]\nmode = "agent"\nsensor_id = "frigate"\n'
            f'key = "{secret}"\n'
            'url = "https://88.255.5.1:18443/ingest/v1"\n'
            'tls_fingerprint = ["sha256:abc"]\n'
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main(["config-check", str(cfg_path)])
        out = buf.getvalue()
    assert rc == 0, rc
    assert secret not in out, "config-check leaked the relay shared key"
    assert "relay: agent" in out and "frigate" in out
    print("  config-check: reports the relay, never the key")



# ---------------------------------------------------------------------------
# quarantine: the security property, machine-checked
# ---------------------------------------------------------------------------

# Every table that existed before relay mode. Ingest must never write any of
# them. v1 of the design listed six and missed four — notifications,
# snapshots, monitor_heartbeat and baseline_forests — which is exactly how
# relayed dispatch ended up able to write the audit trail.
CENTRAL_TABLES = (
    "devices", "flows", "alerts", "notifications", "baselines",
    "baseline_forests", "snapshots", "outages", "monitor_sessions",
    "monitor_heartbeat",
)

_WRITE_OPS = {
    __import__("sqlite3").SQLITE_INSERT,
    __import__("sqlite3").SQLITE_UPDATE,
    __import__("sqlite3").SQLITE_DELETE,
}


class QuarantineBreach(AssertionError):
    pass


class forbid_central_writes:
    """Fail if anything writes a non-remote_ table while this is active.

    An assertion on row counts proves one table was not touched. An
    authorizer proves *no* write reached *any* of them, including through a
    path nobody thought to assert on — which is how all three real breaches
    in this design were going to happen.

    sqlite3 swallows an exception raised inside the authorizer and turns it
    into a DENY, so violations are recorded and re-raised on exit; the DENY
    also makes the offending statement fail loudly in the meantime.
    """

    def __init__(self, store):
        self.store = store
        self.violations: list[str] = []

    def _auth(self, action, arg1, arg2, dbname, source):
        import sqlite3
        if action in _WRITE_OPS and arg1 and not str(arg1).startswith("remote_"):
            if str(arg1) != "sqlite_sequence":
                self.violations.append(str(arg1))
                return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    def __enter__(self):
        self.violations = []
        self.store._conn.set_authorizer(self._auth)
        return self

    def __exit__(self, exc_type, exc, tb):
        self.store._conn.set_authorizer(None)
        if self.violations and exc_type is None:
            raise QuarantineBreach(
                f"wrote central table(s) {sorted(set(self.violations))} — "
                f"relayed data must only ever touch remote_*"
            )
        return False


def _snapshot_central(store) -> dict:
    out = {}
    for t in CENTRAL_TABLES:
        rows = store._conn.execute(f"SELECT * FROM {t}").fetchall()
        out[t] = [tuple(r) for r in rows]
    return out


def _check_remote_store(tmp: Path) -> None:
    from surveillancehound.store import HoundStore

    store = HoundStore(path=tmp / "remote.sqlite")
    try:
        recs = V.validate_records(_good_records(), 100)
        with forbid_central_writes(store):
            counts = store.ingest_remote_batch(
                "frigate", "inst-1", 1, recs, T0 + 100, skew=0.5, body_bytes=900)
        assert counts["total"] == 5, counts

        sensor = store.get_remote_sensor("frigate")
        assert sensor.last_seq == 1 and sensor.batches == 1
        assert sensor.mon_alive is True and sensor.instance_id == "inst-1"

        # a recovery must close the open outage, not insert a second one
        recs2 = V.validate_records(_good_records(), 100)
        recs2["outages"][0]["up_at"] = T0 + 300
        recs2["uptime"][0]["state"] = "up"
        with forbid_central_writes(store):
            store.ingest_remote_batch("frigate", "inst-1", 2, recs2, T0 + 300)
        outages = store._conn.execute(
            "SELECT remote_id, up_at FROM remote_outages").fetchall()
        assert len(outages) == 1, f"outage duplicated: {[tuple(o) for o in outages]}"
        assert outages[0]["up_at"] == T0 + 300, "recovery did not close the outage"
        assert len(store._conn.execute("SELECT * FROM remote_uptime").fetchall()) == 1

        # stale gating: a sensor that stopped reporting shows unknown, not up
        assert store.remote_uptime_report(T0 + 310, 180)[0]["state"] == "up"
        stale = store.remote_uptime_report(T0 + 99999, 180)[0]
        assert stale["state"] == "unknown" and stale["stale"] is True, (
            "a dead sensor's cameras must read unknown, never the up they "
            "last claimed"
        )
        assert stale["availability"] is None, (
            "a dead sensor's availability figure is as stale as its state; "
            "rendering the last number as current is the same fabrication "
            "as inventing one from no observation"
        )

        # dedup lookups are scoped to remote_alerts
        assert store.remote_alert_last_at(
            "frigate", "camera_offline:117.111.101.2:1") == T0
        assert store.remote_alert_last_at("frigate", "nope") is None

        gone = store.forget_remote_sensor("frigate")
        assert gone["remote_sensors"] == 1 and store.list_remote_sensors() == []
        print("  store: batch atomic, outage closes in place, stale gates to "
              "unknown, forget is complete")
    finally:
        store.close()


def _check_quarantine(tmp: Path) -> None:
    """A hostile batch must not change one byte of central's own tables."""
    from surveillancehound.store import AlertRow, HoundStore, OutageRow

    store = HoundStore(path=tmp / "quarantine.sqlite")
    try:
        # give central some state of its own to protect
        store.upsert_device("117.111.101.2", "camera", T0, 10, 1000)
        local_alert_id = store.insert_alert(AlertRow(
            id=None, ts=T0, device_ip="117.111.101.2", kind="camera_offline",
            severity="medium", summary="local", detail="local",
            dedup_key="camera_offline:117.111.101.2:1"))
        store.record_notification(local_alert_id, "stdout", True)
        store.open_outage(OutageRow(
            None, "117.111.101.2", T0, None, T0, "silence", None))
        store.start_monitor_session(T0, "igb0")
        store.set_heartbeat(T0, T0)

        before = _snapshot_central(store)

        # a batch that names central's own camera, collides with its alert
        # dedup key, and reuses its row ids
        hostile = _good_records()
        hostile["devices"][0]["ip"] = "117.111.101.2"
        hostile["devices"][0]["role"] = "other"
        hostile["alerts"][0]["device_ip"] = "117.111.101.2"
        hostile["alerts"][0]["remote_id"] = local_alert_id
        hostile["alerts"][0]["dedup_key"] = "camera_offline:117.111.101.2:1"
        hostile["alerts"][0]["severity"] = "critical"
        hostile["outages"][0]["camera_ip"] = "117.111.101.2"
        recs = V.validate_records(hostile, 100)

        with forbid_central_writes(store):
            store.ingest_remote_batch("evil", "inst-x", 1, recs, T0 + 10)

        after = _snapshot_central(store)
        for table in CENTRAL_TABLES:
            assert before[table] == after[table], (
                f"hostile batch modified central's {table!r}"
            )

        # and it did land, quarantined
        assert len(store.list_remote_alerts()) == 1
        assert store.get_remote_sensor("evil") is not None

        # a local alert with the colliding key is still emitted
        assert store.last_alert_at("camera_offline:117.111.101.2:1") == T0
        print(f"  quarantine: hostile batch left all {len(CENTRAL_TABLES)} "
              f"central tables byte-identical")
    finally:
        store.close()


def _check_authorizer_actually_catches() -> None:
    """The guard must fail when something really does write central."""
    import tempfile
    from surveillancehound.store import AlertRow, HoundStore

    with tempfile.TemporaryDirectory() as td:
        store = HoundStore(path=Path(td) / "a.sqlite")
        try:
            guard = forbid_central_writes(store)
            raised = False
            try:
                with guard:
                    store.insert_alert(AlertRow(
                        id=None, ts=T0, device_ip="1.2.3.4", kind="new_device",
                        severity="info", summary="s", detail="d", dedup_key="k"))
            except Exception:
                pass          # the DENY itself also surfaces as an error
            raised = "alerts" in guard.violations
            assert raised, (
                "the quarantine guard did not fire on a write to `alerts` — "
                "it would not catch a real breach either"
            )
        finally:
            store.close()
    print("  quarantine guard: verified to fire on a real central write")



# ---------------------------------------------------------------------------
# listener: real TLS on loopback, every rejection path
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _free_port() -> int:
    import socket
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


def _collector_cfg(port: int, **over):
    from surveillancehound.config import RelayCfg, RelaySensorCfg
    cfg = RelayCfg(
        mode="collector", listen_host="127.0.0.1", listen_port=port,
        cert_file=str(FIXTURES / "ingest-test.crt"),
        key_file=str(FIXTURES / "ingest-test.key"),
        sensors=[RelaySensorCfg(id="frigate", key="shared-secret")],
    )
    for k, v in over.items():
        setattr(cfg, k, v)
    return cfg


def _pin() -> list[str]:
    import ssl as _ssl
    from surveillancehound.relay import fingerprint_of
    der = _ssl.PEM_cert_to_DER_cert((FIXTURES / "ingest-test.crt").read_text())
    return [fingerprint_of(der)]


def _check_listener(tmp: Path) -> None:
    import time as _time
    from surveillancehound import relay as R
    from surveillancehound.ingest import IngestServer
    from surveillancehound.store import HoundStore

    clock = {"t": T0}
    port = _free_port()
    store = HoundStore(path=tmp / "coll.sqlite")
    got_alerts = []
    srv = IngestServer(
        _collector_cfg(port), store,
        on_alerts=lambda sid, al: got_alerts.append((sid, len(al))),
        now=lambda: clock["t"],
    )
    assert srv.start(), "listener failed to start"
    url = f"https://127.0.0.1:{port}/ingest/v1"
    pins = _pin()

    def send(seq=1, key="shared-secret", sensor="frigate", instance="inst-1",
             sent_at=None, records=None, mutate=None):
        body = R.build_batch(sensor, instance, seq,
                             records if records is not None else _good_records(),
                             clock["t"] if sent_at is None else sent_at)
        if mutate:
            body = mutate(body)
        return R.post_batch(url, body, key, sensor, seq, pins, timeout=10)

    try:
        st, pay = send(seq=1)
        assert st == 200 and pay["ack_seq"] == 1, (st, pay)
        assert got_alerts == [("frigate", 1)], got_alerts

        st, pay = send(seq=1)
        assert st == 409 and pay["last_seq"] == 1, (st, pay)

        st, _ = send(seq=2)
        assert st == 200

        st, _ = send(seq=3, key="wrong-key")
        assert st == 401, st

        st, _ = send(seq=3, sensor="unknown-sensor")
        assert st == 401, st

        # the signed body wins: header says frigate, body claims someone else
        def claim_other(body):
            return body.replace(b'"sensor_id":"frigate"', b'"sensor_id":"other12"')
        st, _ = send(seq=3, mutate=claim_other)
        assert st in (400, 401), st

        st, pay = send(seq=3, sent_at=clock["t"] + 9999)
        assert st == 400 and "sent_at" in pay["error"], (st, pay)

        # a day-old SPOOLED batch, re-stamped at transmission, is fine —
        # this is the v1 contradiction that made the spool unreplayable
        old = R.build_batch("frigate", "inst-1", 3, _good_records(), T0 - 86400)
        fresh = R.restamp(old, clock["t"])
        st, _ = R.post_batch(url, fresh, "shared-secret", "frigate", 3, pins)
        assert st == 200, f"re-stamped spooled batch rejected: {st}"

        st, _ = send(seq=4, records={"flows": "not a list"})
        assert st == 400, st

        bad = _good_records(); bad["flows"][0]["packets"] = "<img src=x>"
        st, _ = send(seq=4, records=bad)
        assert st == 400, "a script tag in a numeric field was accepted"

        # a new instance id resets the sequence instead of wedging
        st, _ = send(seq=1, instance="inst-2")
        assert st == 200, f"instance change not accepted: {st}"

        print("  listener: 200/409/401/400 paths correct over real TLS; "
              "signed body authoritative; re-stamped spool accepted")
    finally:
        srv.stop()
        store.close()


def _check_listener_limits(tmp: Path) -> None:
    import http.client
    import ssl as _ssl
    from surveillancehound.ingest import IngestServer
    from surveillancehound.store import HoundStore

    clock = {"t": T0}
    port = _free_port()
    store = HoundStore(path=tmp / "lim.sqlite")
    srv = IngestServer(_collector_cfg(port, max_body_bytes=2048,
                                      max_batches_per_minute=3),
                       store, now=lambda: clock["t"])
    assert srv.start()

    def raw(method="POST", path="/ingest/v1", body=b"{}", headers=None):
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=10, context=ctx)
        try:
            h = {"Content-Length": str(len(body))}
            if headers:
                h.update(headers)
                if headers.get("Transfer-Encoding"):
                    h.pop("Content-Length", None)
            c.request(method, path, body=body, headers=h)
            return c.getresponse().status
        finally:
            c.close()

    try:
        assert raw(method="GET") == 405, "GET should be rejected"
        assert raw(path="/elsewhere") == 404, "unknown path should 404"
        assert raw(body=b"x" * 4096) == 413, "oversized body should 413"
        assert raw(headers={"Transfer-Encoding": "chunked"}) == 400, \
            "chunked should be rejected"

        # rate limit is by source address and fires before auth
        codes = [raw(body=b"{}") for _ in range(6)]
        assert 429 in codes, f"rate limit never fired: {codes}"
        print("  listener: 405/404/413/400-chunked enforced; rate limit is "
              "pre-auth and by source address")
    finally:
        srv.stop()
        store.close()


def _check_pinning(tmp: Path) -> None:
    from surveillancehound import relay as R
    from surveillancehound.ingest import IngestServer
    from surveillancehound.store import HoundStore

    port = _free_port()
    store = HoundStore(path=tmp / "pin.sqlite")
    srv = IngestServer(_collector_cfg(port), store, now=lambda: T0)
    assert srv.start()
    url = f"https://127.0.0.1:{port}/ingest/v1"
    body = R.build_batch("frigate", "i", 1, _good_records(), T0)
    try:
        st, _ = R.post_batch(url, body, "shared-secret", "frigate", 1, _pin())
        assert st == 200
        try:
            R.post_batch(url, body, "shared-secret", "frigate", 2,
                         ["sha256:" + "0" * 64])
            raise AssertionError("a wrong pinned fingerprint was accepted")
        except R.RelayError as e:
            assert "pinned set" in str(e)
        print("  pinning: correct fingerprint accepted, wrong one refuses to send")
    finally:
        srv.stop()
        store.close()



# ---------------------------------------------------------------------------
# end to end: a real agent pushing to a real collector over TLS
# ---------------------------------------------------------------------------

def _seed_agent_store(path: Path):
    """An agent store with the kind of rows a live sensor would have."""
    from surveillancehound.store import (
        AlertRow, FlowRow, HoundStore, OutageRow,
    )
    st = HoundStore(path=path)
    sid = st.start_monitor_session(T0 - 3600, "any")
    st.end_monitor_session(sid, T0, True)
    st.upsert_device("117.111.101.2", "camera", T0, 100, 10000)
    st.upsert_device("117.111.102.2", "camera", T0 - 7200, 50, 5000)
    st.set_heartbeat(T0, T0)
    for i in range(3):
        st.insert_flow(FlowRow(
            src_ip="117.111.101.2", src_port=554, dst_ip="88.255.5.11",
            dst_port=40000 + i, proto="tcp", first_seen=T0 - 10,
            last_seen=T0, packets=10, bytes=1000, bytes_to_camera=100,
            bytes_from_camera=900, tcp_flags_seen="PA",
            classification="lan_normal"))
    st.insert_alert(AlertRow(
        id=None, ts=T0, device_ip="117.111.102.2", kind="camera_offline",
        severity="medium", summary="camera 117.111.102.2 has been silent",
        detail="d", dedup_key="camera_offline:117.111.102.2:1"))
    oid = st.open_outage(OutageRow(
        None, "117.111.102.2", T0 - 600, None, T0 - 660, "silence", None))
    return st, oid


def _check_end_to_end(tmp: Path) -> None:
    from surveillancehound.config import RelayCfg
    from surveillancehound.ingest import IngestServer
    from surveillancehound.relay import RelayClient
    from surveillancehound.store import HoundStore

    port = _free_port()
    clock = {"t": T0 + 10}
    now = lambda: clock["t"]                                   # noqa: E731

    collector_store = HoundStore(path=tmp / "collector.sqlite")
    # give the collector its own state, which must survive untouched
    collector_store.upsert_device("88.255.5.11", "nvr", T0, 9, 900)
    before = _snapshot_central(collector_store)

    dispatched = []
    srv = IngestServer(_collector_cfg(port), collector_store,
                       on_alerts=lambda sid, al: dispatched.append((sid, len(al))),
                       now=now)
    assert srv.start(), "collector did not start"

    agent_store, _ = _seed_agent_store(tmp / "agent.sqlite")
    agent_cfg = RelayCfg(
        mode="agent", sensor_id="frigate", key="shared-secret",
        url=f"https://127.0.0.1:{port}/ingest/v1",
        tls_fingerprint=_pin(), batch_seconds=1.0,
    )
    client = RelayClient(agent_cfg, agent_store, now=now)

    try:
        seq = client.enqueue()
        assert seq == 1, seq
        assert client.flush() is True, f"push failed: {client.state.last_error}"

        sensor = collector_store.get_remote_sensor("frigate")
        assert sensor is not None and sensor.last_seq == 1
        flows = collector_store.list_remote_flows()
        alerts = collector_store.list_remote_alerts()
        assert len(flows) == 3, f"expected 3 relayed flows, got {len(flows)}"
        assert len(alerts) == 1 and alerts[0]["sensor_id"] == "frigate"
        assert dispatched == [("frigate", 1)], dispatched
        up = collector_store.remote_uptime_report(now(), 180)
        assert {u["ip"] for u in up} == {"117.111.101.2", "117.111.102.2"}

        # the collector's own tables are untouched
        assert _snapshot_central(collector_store) == before, (
            "relayed data modified the collector's own state"
        )

        # --- link goes down: the agent must spool, not lose data ---
        srv.stop()
        from surveillancehound.store import FlowRow
        for i in range(2):
            agent_store.insert_flow(FlowRow(
                src_ip="117.111.103.2", src_port=554, dst_ip="88.255.5.11",
                dst_port=50000 + i, proto="tcp", first_seen=T0, last_seen=T0 + 20,
                packets=5, bytes=500, bytes_to_camera=50, bytes_from_camera=450,
                tcp_flags_seen="PA", classification="lan_normal"))
        clock["t"] += 30
        client.enqueue()
        assert client.flush() is False, "flush should fail with the link down"
        assert client.spool.stats(now()).pending >= 1, "nothing was spooled"

        # --- link returns, well outside the skew window ---
        clock["t"] += 3600
        srv2 = IngestServer(_collector_cfg(port), collector_store, now=now)
        assert srv2.start(), "collector did not restart"
        try:
            assert client.flush() is True, (
                f"spooled replay failed: {client.state.last_error}"
            )
            assert client.spool.stats(now()).pending == 0, "spool not drained"
            assert len(collector_store.list_remote_flows()) == 5, (
                "replayed flows did not arrive"
            )
            assert _snapshot_central(collector_store) == before
        finally:
            srv2.stop()

        print("  end-to-end: 3 flows + 1 alert relayed over TLS; link drop "
              "spooled and replayed an hour later; collector state untouched")
    finally:
        srv.stop()
        agent_store.close()
        collector_store.close()


def _check_agent_is_silent(tmp: Path) -> None:
    """Agent mode must not notify — the collector is the only notifier."""
    from surveillancehound.config import load_from_dict
    from surveillancehound.daemon import Hound

    cfg = load_from_dict({
        "capture": {"pcap_file": str(tmp / "none.pcap")},
        "network": {"camera_ips": ["117.111.101.2"],
                    "lan_subnets": ["88.255.0.0/16"]},
        "store": {"path": str(tmp / "silent.sqlite")},
        "notify": [{"type": "stdout", "level": "info"}],
        "relay": {"mode": "agent", "sensor_id": "frigate", "key": "k",
                  "url": "https://88.255.5.1:18443/ingest/v1",
                  "tls_fingerprint": ["sha256:abc"]},
    })
    hound = Hound(cfg)
    try:
        assert hound.dispatcher.channels == [], (
            "an agent configured a notify channel — it would page twice"
        )
        assert hound.relay is not None and hound.ingest is None
    finally:
        hound.store.close()
    print("  agent mode: dispatch disabled, relay client constructed")


def _check_resource_bounds(tmp: Path) -> None:
    """Quota, disk guard and VACUUM guard.

    Retention bounds how old relayed rows get. These bound how many, and
    how much damage a write can do when the disk is nearly gone — the two
    cases where a sensor holding a valid key is still a liability.
    """
    import os as _os
    from surveillancehound.ingest import IngestServer
    from surveillancehound.store import HoundStore

    store = HoundStore(path=tmp / "bounds.sqlite")
    T = 1_700_000_000.0

    # --- per-sensor quota: oldest trimmed, newest kept, cap respected
    cap = 10
    for i in range(25):
        recs = V.validate_records(
            {"alerts": [{
                "remote_id": i, "ts": T + i, "device_ip": "10.0.0.5",
                "kind": "new_device", "severity": "low",
                "summary": f"a{i}", "detail": "", "dedup_key": f"k{i}",
            }]}, 100)
        store.ingest_remote_batch("noisy", "inst", i + 1, recs, T + i,
                                  max_rows_per_sensor=cap)
    rows = store._conn.execute(
        "SELECT ts FROM remote_alerts WHERE sensor_id='noisy' ORDER BY ts"
    ).fetchall()
    assert len(rows) == cap, f"quota not enforced: {len(rows)} rows, cap {cap}"
    assert rows[0]["ts"] == T + 15, (
        "quota must evict the OLDEST rows; the recent picture is the one "
        f"worth keeping (kept from ts={rows[0]['ts'] - T})"
    )

    # A hostile sensor must only ever be able to evict ITS OWN history.
    quiet = V.validate_records(
        {"alerts": [{"remote_id": 1, "ts": T, "device_ip": "10.0.0.9",
                     "kind": "new_device", "severity": "low",
                     "summary": "quiet", "detail": "", "dedup_key": "q"}]}, 100)
    store.ingest_remote_batch("quiet", "i2", 1, quiet, T, max_rows_per_sensor=cap)
    for i in range(25, 60):
        recs = V.validate_records(
            {"alerts": [{"remote_id": i, "ts": T + i, "device_ip": "10.0.0.5",
                         "kind": "new_device", "severity": "low",
                         "summary": f"a{i}", "detail": "", "dedup_key": f"k{i}"}]},
            100)
        store.ingest_remote_batch("noisy", "inst", i + 1, recs, T + i,
                                  max_rows_per_sensor=cap)
    assert store._conn.execute(
        "SELECT COUNT(*) c FROM remote_alerts WHERE sensor_id='quiet'"
    ).fetchone()["c"] == 1, (
        "one sensor flooding must never evict another sensor's rows"
    )

    # cap of 0 disables, and must not delete anything
    before = store._conn.execute(
        "SELECT COUNT(*) c FROM remote_alerts").fetchone()["c"]
    recs = V.validate_records(
        {"alerts": [{"remote_id": 999, "ts": T + 999, "device_ip": "10.0.0.5",
                     "kind": "new_device", "severity": "low", "summary": "z",
                     "detail": "", "dedup_key": "z"}]}, 100)
    store.ingest_remote_batch("noisy", "inst", 10_000, recs, T + 999,
                              max_rows_per_sensor=0)
    assert store._conn.execute(
        "SELECT COUNT(*) c FROM remote_alerts").fetchone()["c"] == before + 1, (
        "max_rows_per_sensor=0 must disable trimming entirely"
    )
    print(f"  quota: trims oldest to cap, scoped per sensor, 0 disables")

    # --- VACUUM guard: never run it when free space cannot cover a rewrite
    store._VACUUM_HEADROOM = 1e18          # demand an impossible amount
    assert store._vacuum_is_safe() is False, (
        "VACUUM must be skipped when the disk cannot hold a second copy"
    )
    store._VACUUM_HEADROOM = 2.0
    assert store._vacuum_is_safe() is True, "normal case must still VACUUM"

    # Skipping must still DELETE: data goes, only reclamation waits.
    store._VACUUM_HEADROOM = 1e18
    d = store.prune_remote(T + 10_000)
    assert sum(d.values()) > 0, "prune must delete even when VACUUM is skipped"
    store._VACUUM_HEADROOM = 2.0
    print("  vacuum guard: skipped when space is short, rows still deleted")

    # --- disk guard: fails OPEN when unknowable, CLOSED when genuinely low
    cfg = _collector_cfg(0, min_free_disk_mb=0.0)
    srv = IngestServer(cfg, store, now=lambda: T)
    assert srv._disk_ok() is True, "0 must disable the disk guard"
    srv.cfg = _collector_cfg(0, min_free_disk_mb=1e12)   # a petabyte free
    assert srv._disk_ok() is False, "guard must trip when free space is short"

    real = _os.statvfs
    def _boom(_p):
        raise OSError("statvfs unavailable")
    _os.statvfs = _boom
    try:
        assert srv._disk_ok() is True, (
            "an unreadable filesystem must fail OPEN — refusing every batch "
            "would turn an unknown into a total relay outage"
        )
    finally:
        _os.statvfs = real
    store.close()
    print("  disk guard: trips when low, fails open when unreadable")


def _check_capture_exclusion() -> None:
    """The agent must not capture its own uploads.

    Left in, they aggregate into a flow to an off-network host, classify
    as telemetry, alert, and get relayed — which generates more of the
    same traffic. Filtering in tcpdump keeps it off the parser entirely.
    """
    import shutil
    import subprocess
    from surveillancehound.capture import compose_bpf
    from surveillancehound.relay import exclusion_filter, split_endpoint

    assert split_endpoint("https://88.255.5.1:18443/ingest/v1") == (
        "88.255.5.1", 18443, "/ingest/v1")
    assert split_endpoint("https://[fd00::1]:18443/ingest/v1") == (
        "fd00::1", 18443, "/ingest/v1"), "IPv6 literals must keep their port"

    ex = exclusion_filter("https://88.255.5.1:18443/ingest/v1")
    assert "88.255.5.1" in ex and "18443" in ex, ex
    assert exclusion_filter("") == "", "no url means nothing to exclude"

    # Precedence: a user filter of `a or b` must be parenthesised, or the
    # `or` binds loosely and swallows the exclusion completely.
    combined = compose_bpf("host 10.0.0.1 or host 10.0.0.2", ex)
    assert combined.startswith("(host 10.0.0.1 or host 10.0.0.2)"), (
        f"user filter must be parenthesised against `or` precedence: {combined}"
    )
    assert compose_bpf("port 554", "") == "port 554", "no exclusion, no change"
    assert compose_bpf("", ex) == ex

    # Compile them for real where tcpdump exists. A filter that does not
    # compile takes the capture down on startup, which is the one failure
    # the whole daemon cannot absorb.
    # socketserver dispatches connection errors to the SERVER's
    # handle_error. An override on the handler class silently never fires,
    # which let aborted TLS handshakes print tracebacks to stderr — a peer
    # that can reach the port could fill the log by dropping connections.
    import socketserver
    from surveillancehound.ingest import _Server
    assert _Server.handle_error is not socketserver.BaseServer.handle_error, (
        "_Server must override handle_error; putting it on the request "
        "handler does not work and is how the traceback spam came back"
    )

    if shutil.which("tcpdump"):
        checked = 0
        for expr in (ex, combined, compose_bpf("port 554", ex)):
            r = subprocess.run(
                ["tcpdump", "-d", "-y", "EN10MB", expr],
                capture_output=True, text=True,
            )
            assert r.returncode == 0, (
                f"tcpdump refused the generated filter {expr!r}: "
                f"{r.stderr.strip()}"
            )
            checked += 1
        print(f"  capture exclusion: {checked} generated filter(s) compile "
              f"under real tcpdump; `or` precedence held")
    else:
        print("  capture exclusion: shape correct (tcpdump absent, not "
              "compile-checked)")


def main() -> int:
    import tempfile
    print("=== relay validation ===")
    _check_json_constants()
    _check_scalars()
    _check_records()
    _check_notification_hardening()
    _check_dashboard_numeric_escaping()
    _check_relay_config()
    _check_capture_exclusion()
    _check_key_never_printed()
    print("=== quarantine ===")
    _check_authorizer_actually_catches()
    with tempfile.TemporaryDirectory() as td:
        _check_remote_store(Path(td))
        _check_quarantine(Path(td))
        _check_resource_bounds(Path(td))
    print("=== listener ===")
    with tempfile.TemporaryDirectory() as td:
        _check_listener(Path(td))
        _check_listener_limits(Path(td))
        _check_pinning(Path(td))
    print("=== end to end ===")
    with tempfile.TemporaryDirectory() as td:
        _check_agent_is_silent(Path(td))
        _check_end_to_end(Path(td))
    print("\nRELAY VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
