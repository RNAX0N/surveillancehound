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

    agent = {"mode": "agent", "sensor_id": "frigate", "key": "test-secret-abcdefgh",
             "url": "https://88.255.5.1:18443/ingest/v1",
             "tls_fingerprint": "sha256:" + "ab" * 32}
    cfg = load(agent)
    assert cfg.relay.is_agent and cfg.relay.tls_fingerprint == ["sha256:" + "ab" * 32]

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
            "sensor": [{"id": "frigate", "key": "test-secret-abcdefgh"}]}
    assert load(coll).relay.key_for("frigate") == "test-secret-abcdefgh"
    assert load(coll).relay.key_for("nope") is None
    rejects({**coll, "listen_host": "0.0.0.0"},
            "a collector listening on every interface")
    assert load({**coll, "listen_host": "0.0.0.0",
                 "listen_allow_any": True}).relay.is_collector
    rejects({"mode": "collector", "listen_host": "88.255.5.1"},
            "a collector with no sensors")
    rejects({**coll, "sensor": [{"id": "a", "key": "test-secret-abcdefgh"},
                               {"id": "a", "key": "test-secret-abcdefgh2"}]},
            "duplicate sensor ids")
    # The shared secret is the only thing authenticating a sensor.
    rejects({**agent, "key": "short"}, "a brute-forceable relay key")
    rejects({**coll, "sensor": [{"id": "a", "key": "short"}]},
            "a brute-forceable sensor key")
    rejects({"mode": "sideways"}, "an unknown relay mode")
    # These live in two modules (config must not import relay) and are
    # only correct while they agree: a collector cap below the agent's
    # per-kind batch size rejects and DROPS every batch forever.
    from surveillancehound.config import _AGENT_RECORDS_PER_KIND
    from surveillancehound.relay import _MAX_RECORDS_PER_KIND
    assert _AGENT_RECORDS_PER_KIND == _MAX_RECORDS_PER_KIND, (
        f"config says the agent sends {_AGENT_RECORDS_PER_KIND} records "
        f"per kind, relay sends {_MAX_RECORDS_PER_KIND}. If relay's is "
        f"larger, the collector floor no longer protects anything."
    )
    # 0 means NO CAP, matching remote_retention_days /
    # max_rows_per_sensor / min_free_disk_mb. It used to mean "reject
    # every batch", so an operator following the documented convention
    # got permanent silent loss with a clean config-check.
    assert V.validate_records({"alerts": [{
        "remote_id": 1, "ts": 1.79e9, "device_ip": "10.0.0.1",
        "kind": "new_device", "severity": "low", "summary": "x",
        "detail": "", "dedup_key": "k",
    }]}, 0)["alerts"], "max_records_per_batch=0 must mean unlimited"

    # A LOW cap is allowed: lowering it is the remedy hound.toml.example
    # recommends for bounding per-batch cost, so a hard floor outlawed
    # the documented mitigation. The agent sizes its own batches from
    # its own cap instead, so lowering both ends works.
    low = load({"mode": "collector", "listen_host": "88.255.5.1",
                "max_records_per_batch": 100,
                "sensor": [{"id": "a", "key": "shared-secret-abcdef"}]})
    assert low.relay.max_records_per_batch == 100
    print("  config: 15 relay guards hold; mode defaults to off; 0 means "
          "unlimited")


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
            'tls_fingerprint = ["sha256:' + "ab" * 32 + '"]\n'
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

        # Dedup lookups are scoped to remote_alerts, and report when WE
        # received the alert rather than the ts the sensor claimed —
        # otherwise backdating an alert walks it past the dedup window.
        key = "camera_offline:117.111.101.2:1"
        assert store.remote_alert_last_at("frigate", key) == T0 + 100, (
            "dedup must key on ingested_at (collector time), not the "
            "sensor-supplied ts"
        )
        assert store.remote_alert_last_at("frigate", "nope") is None
        # Excluding the row under consideration is what stops an alert
        # being compared against itself and suppressed forever.
        only_id = store._conn.execute(
            "SELECT remote_id FROM remote_alerts WHERE dedup_key = ?",
            (key,)).fetchone()["remote_id"]
        assert store.remote_alert_last_at(
            "frigate", key, exclude_remote_id=only_id) is None

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
        sensors=[RelaySensorCfg(id="frigate", key="shared-secret-abcdef")],
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
        # *a: track the real signature. A stub pinned to an old one
        # fails inside ingest's catch-all and reads as 'the
        # callback never fired'.
        on_alerts=lambda sid, al, *a: got_alerts.append((sid, len(al))),
        now=lambda: clock["t"],
    )
    assert srv.start(), "listener failed to start"
    url = f"https://127.0.0.1:{port}/ingest/v1"
    pins = _pin()

    def send(seq=1, key="shared-secret-abcdef", sensor="frigate", instance="inst-1",
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
        st, _ = R.post_batch(url, fresh, "shared-secret-abcdef", "frigate", 3, pins)
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
    # Generous budget for the shape checks below: EVERY request now
    # counts against it, including 404/405/413, because a rejection
    # that skipped the budget was the cheapest request a flooder
    # could make. The limiter itself is exercised separately.
    srv = IngestServer(_collector_cfg(port, max_body_bytes=2048,
                                      max_batches_per_minute=100),
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

        # Rate limit is by source address and fires before auth, and
        # counts EVERY request shape — a 404 used to skip it entirely,
        # which made "POST /nope" an unmetered way to burn collector
        # CPU.
        import socket as _bsk2
        lim_port = _free_port()
        lim_store = HoundStore(path=tmp / "lim2.sqlite")
        lim = IngestServer(_collector_cfg(lim_port, max_batches_per_minute=3),
                           lim_store, now=lambda: clock["t"])
        assert lim.start()
        try:
            def hit(path="/ingest/v1", method="POST"):
                c = http.client.HTTPSConnection(
                    "127.0.0.1", lim_port, timeout=10,
                    context=_ssl._create_unverified_context())
                try:
                    c.request(method, path, body=b"{}",
                              headers={"Content-Length": "2"})
                    return c.getresponse().status
                except OSError as e:
                    return type(e).__name__
                finally:
                    c.close()

            codes = [hit(path="/nope") for _ in range(6)]
            assert 429 in codes, (
                f"a 404 path skipped the request budget entirely: {codes}"
            )

            # EVERY method, not just the ones we implement. An unknown
            # verb is dispatched by the stdlib straight to
            # send_error(501) and never reaches do_GET/do_POST, so
            # metering there left PUT/HEAD/OPTIONS unmetered — the same
            # unmetered-request class, through a different shape.
            lim._limiter._hits.clear()
            lim._limiter._cooldown.clear()
            verb_codes = [hit(method="PUT") for _ in range(6)]
            assert 429 in verb_codes, (
                f"an unknown HTTP verb skipped the request budget: "
                f"{verb_codes}"
            )
            # ...and exhausting it arms the accept-time cooldown, so
            # the source is refused where refusing is cheapest rather
            # than served another request cycle.
            assert lim._limiter.in_cooldown("127.0.0.1", clock["t"]), (
                "an unknown verb exhausted the budget without arming "
                "the cooldown"
            )
            # Shapes the STDLIB rejects before parse_request ever
            # runs — an over-long request line, a bad version, a
            # header flood. Metering after super().parse_request()
            # never saw any of them: measured ~1,900 req/s from one
            # address with no key, costing 62-66% of packet-parse
            # throughput, cooldown never arming.
            for label, payload in (
                ("over-long request line",
                 b"GET /" + b"x" * 70000 + b" HTTP/1.1\r\n\r\n"),
                ("bad HTTP version", b"GET / HTTP/9.9\r\n\r\n"),
                ("header flood",
                 b"GET / HTTP/1.1\r\n"
                 + b"".join(b"X-%d: y\r\n" % i for i in range(200))
                 + b"\r\n"),
            ):
                lim._limiter._hits.clear()
                lim._limiter._cooldown.clear()
                for _ in range(6):
                    try:
                        sk = _bsk2.create_connection(
                            ("127.0.0.1", lim_port), timeout=5)
                        tw = _ssl._create_unverified_context().wrap_socket(
                            sk, server_hostname="x")
                        tw.sendall(payload)
                        tw.recv(300)
                        tw.close()
                    except OSError:
                        pass
                assert lim._limiter.in_cooldown("127.0.0.1", clock["t"]), (
                    f"{label} is rejected by the stdlib before "
                    f"parse_request, so it never reached the limiter — "
                    f"an unmetered request shape"
                )

            # Cooldown is armed from the runs above; clear it so this
            # connection is accepted and we are testing the parse
            # path rather than the limiter.
            lim._limiter._cooldown.clear()
            lim._limiter._hits.clear()

            # A malformed request line must still get a status. The
            # drain added to send_error touches self.headers, which
            # parse_request has NOT assigned yet when it rejects a bad
            # request line — the AttributeError was swallowed by the
            # server's handle_error and the client saw a silent close.
            bad = _bsk2.create_connection(("127.0.0.1", lim_port), timeout=10)
            bw = _ssl._create_unverified_context().wrap_socket(
                bad, server_hostname="x")
            try:
                bw.sendall(b"GARBAGE LINE WITH TOO MANY PARTS\r\n\r\n")
                first = bw.recv(200).split(b"\r\n")[0]
                assert first.startswith(b"HTTP/"), (
                    f"a malformed request line got no status line "
                    f"({first!r}); an exception was swallowed and the "
                    f"connection closed silently"
                )
            finally:
                try:
                    bw.close()
                except OSError:
                    pass

            assert all(isinstance(c, int) for c in verb_codes[:3]), (
                f"an unknown verb with a body was reset instead of "
                f"answered: {verb_codes[:3]}"
            )
        finally:
            lim.stop()
            lim_store.close()

        print("  listener: 405/404/413/400-chunked enforced; every request "
              "shape counts against the budget; over-budget sources enter "
              "an accept-time cooldown")
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
        st, _ = R.post_batch(url, body, "shared-secret-abcdef", "frigate", 1, _pin())
        assert st == 200
        try:
            R.post_batch(url, body, "shared-secret-abcdef", "frigate", 2,
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
                       on_alerts=lambda sid, al, *a: dispatched.append((sid, len(al))),
                       now=now)
    assert srv.start(), "collector did not start"

    agent_store, _ = _seed_agent_store(tmp / "agent.sqlite")
    agent_cfg = RelayCfg(
        mode="agent", sensor_id="frigate", key="shared-secret-abcdef",
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
        "relay": {"mode": "agent", "sensor_id": "frigate",
                  "key": "test-secret-abcdefgh",
                  "url": "https://88.255.5.1:18443/ingest/v1",
                  "tls_fingerprint": ["sha256:" + "ab" * 32]},
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
                "remote_id": i + 1, "ts": T + i, "device_ip": "10.0.0.5",
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
            {"alerts": [{"remote_id": i + 1, "ts": T + i, "device_ip": "10.0.0.5",
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
    from surveillancehound.config import load_from_dict
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
    # Fingerprint formats must converge. `hound relay` prints
    # sha256:<lowercase hex>; openssl prints UPPER:CASE:WITH:COLONS. If
    # these do not normalise to the same value, pasting the openssl output
    # produces "not in the pinned set" naming two strings a human reads as
    # identical.
    from surveillancehound.config import normalize_fingerprint as _nf
    canon = "sha256:" + "d42847ed2b32b8533bb1f4b8dda27de41ae291e4d98434a0c6eebd85f008fbb2"
    openssl_form = "D4:28:47:ED:2B:32:B8:53:3B:B1:F4:B8:DD:A2:7D:E4:1A:E2:91:E4:D9:84:34:A0:C6:EE:BD:85:F0:08:FB:B2"
    assert _nf(openssl_form) == _nf(canon) == canon, (
        f"openssl and hound fingerprint formats must converge: "
        f"{_nf(openssl_form)} vs {_nf(canon)}"
    )
    for bad in ("nope", "abcd", "", "sha256:" + "z" * 64):
        assert _nf(bad) == "", f"{bad!r} must not normalise to a pin"

    # And a malformed pin must be REFUSED at load, not carried through:
    # it can never match, so it turns a typo into a permanently failing
    # connection that gets diagnosed as a network fault.
    try:
        load_from_dict({
            "capture": {"interface": "x0"},
            "network": {"camera_ips": ["10.0.0.1"]},
            "relay": {"mode": "agent", "sensor_id": "s",
                      "url": "https://10.0.0.2:18443/ingest/v1",
                      "key": "k" * 20, "tls_fingerprint": ["not-a-digest"]},
        })
        raise AssertionError("a malformed tls_fingerprint must be refused")
    except ValueError as e:
        assert "fingerprint" in str(e).lower(), e

    # Wiring, not just the helper: prove the daemon actually hands the
    # exclusion to the capture layer in agent mode, and hands nothing in
    # the default case. A correct helper nobody calls is still a bug.
    import tempfile
    from surveillancehound import daemon as daemon_mod

    def _seen_exclusion(relay_block: dict) -> str:
        seen: dict = {}

        def _fake_stream(cfg, **kw):
            seen.update(kw)
            raise daemon_mod.CaptureError("stop here; wiring already observed")

        with tempfile.TemporaryDirectory() as td:
            base = {
                "capture": {"interface": "test0"},
                "network": {"camera_ips": ["10.9.0.5"]},
                "store": {"path": f"{td}/wiring.sqlite"},
            }
            base.update(relay_block)
            cfg = load_from_dict(base)
            orig = daemon_mod.stream_packets
            daemon_mod.stream_packets = _fake_stream
            try:
                h = daemon_mod.Hound(cfg)
                h.run()
                h.store.close()
            finally:
                daemon_mod.stream_packets = orig
        return seen.get("exclude_bpf", "<<never passed>>")

    got = _seen_exclusion({"relay": {
        "mode": "agent", "sensor_id": "s1",
        "url": "https://10.9.0.250:18443/ingest/v1",
        "key": "k" * 20,
        "tls_fingerprint": ["sha256:" + "AB:" * 31 + "CD"],
    }})
    assert "10.9.0.250" in got and "18443" in got, (
        f"agent mode must exclude its own relay traffic at capture; "
        f"daemon passed {got!r}"
    )
    assert _seen_exclusion({}) == "", (
        "a non-relay daemon must not have its capture filtered"
    )

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


def _check_relayed_dispatch_is_quarantined(tmp: Path) -> None:
    """Execute the REAL Hound._on_relayed_alerts and prove it stays remote.

    This test exists because of a specific near-miss. Every other relay
    test substitutes a stub for `on_alerts`, so `_on_relayed_alerts` was
    never executed by the suite at all — and the v1 design's three
    breaches all lived in exactly that method. Replacing its body with
    `self._emit(alert)` reintroduces all three at once and every other
    suite still passes. This one must not.

    What `_emit` would do that this path must not:
      * insert into `alerts`          (a remote host authoring local alerts)
      * call `set_alert_channels`     (a second write to that row)
      * write `notifications`         (whose alert_id means alerts.id, so a
                                       relayed row would point at an
                                       unrelated local alert)
      * run the snapshot engine       (letting a remote alert overwrite a
                                       LOCAL alert's forensic pcap)
    """
    from surveillancehound import daemon as daemon_mod
    from surveillancehound.config import load_from_dict

    cfg = load_from_dict({
        "capture": {"interface": "test0"},
        "network": {"camera_ips": ["10.9.0.5"]},
        "store": {"path": str(tmp / "dispatch.sqlite")},
        # A real channel, so dispatch actually runs and returns a delivery.
        "notify": [{"type": "stdout", "level": "info"}],
        # Snapshots ON: if this path ever reaches the snapshot engine we
        # want a row to appear, not a silent no-op that hides the bug.
        "snapshot": {"enabled": True},
        "relay": {
            "mode": "collector", "listen_host": "127.0.0.1",
            "listen_port": 0,
            "cert_file": str(FIXTURES / "ingest-test.crt"),
            "key_file": str(FIXTURES / "ingest-test.key"),
            "sensor": [{"id": "frigate", "key": "shared-secret-abcdef"}],
        },
    })
    hound = daemon_mod.Hound(cfg)
    try:
        store = hound.store
        # A local alert with a snapshot-eligible camera, so there is
        # something for a misrouted relayed alert to collide with.
        recs = V.validate_records({"alerts": [{
            "remote_id": 7, "ts": T0, "device_ip": "10.9.0.5",
            "kind": "camera_offline", "severity": "high",
            "summary": "relayed camera is down", "detail": "",
            "dedup_key": "camera_offline:10.9.0.5",
        }]}, 100)
        store.ingest_remote_batch("frigate", "inst", 1, recs, T0)

        before = _snapshot_central(store)
        for raw in recs["alerts"]:
            hound._dispatch_relayed_alert("frigate", raw)
        after = _snapshot_central(store)

        assert before == after, (
            "dispatching a relayed alert modified central state. Tables "
            "that changed: "
            + ", ".join(t for t in before if before[t] != after[t])
        )

        # Positive side: it must actually have been delivered and audited
        # in the REMOTE audit table, or the quarantine is just "does
        # nothing", which would also pass the comparison above.
        remote_notes = store._conn.execute(
            "SELECT sensor_id, channel_type, ok FROM remote_notifications"
        ).fetchall()
        assert len(remote_notes) == 1, (
            f"relayed dispatch must be audited in remote_notifications; "
            f"got {[tuple(r) for r in remote_notes]}"
        )
        assert remote_notes[0]["sensor_id"] == "frigate"
        assert remote_notes[0]["channel_type"] == "stdout"

        # Named explicitly, because these are the four v1 breaches.
        for table in ("alerts", "notifications", "snapshots"):
            n = store._conn.execute(
                f"SELECT COUNT(*) c FROM {table}").fetchone()["c"]
            assert n == 0, (
                f"{table} must stay empty: a relayed alert reached it "
                f"({n} row(s)). This is the v1 breach rev 2 exists to close."
            )
        # A FAILED relayed delivery must be audited too, with its error.
        # Recording only successes made ok/error unable to say anything
        # else, and a failed relayed alert is the row an operator looks for.
        class _Boom:
            type, level = "webhook", "info"

            def dispatch(self, alert):
                raise OSError("collector-side webhook refused")

        hound.dispatcher.channels = [_Boom()]
        recs2 = V.validate_records({"alerts": [{
            "remote_id": 8, "ts": T0 + 1, "device_ip": "10.9.0.6",
            "kind": "new_device", "severity": "high", "summary": "x",
            "detail": "", "dedup_key": "new_device:10.9.0.6",
        }]}, 100)
        store.ingest_remote_batch("frigate", "inst", 2, recs2, T0 + 1)
        before2 = _snapshot_central(store)
        for raw in recs2["alerts"]:
            hound._dispatch_relayed_alert("frigate", raw)
        assert _snapshot_central(store) == before2, (
            "a FAILING relayed dispatch must still not touch central state"
        )
        failed = store._conn.execute(
            "SELECT ok, error FROM remote_notifications WHERE ok = 0"
        ).fetchall()
        assert len(failed) == 1, (
            f"a failed relayed delivery must be audited; got "
            f"{[tuple(r) for r in failed]}"
        )
        assert "refused" in failed[0]["error"], failed[0]["error"]


        # A FRESH relayed alert MUST be notified. The listener stores the
        # batch before dispatching, so a dedup gate that does not exclude
        # the alert under consideration compares it against itself and
        # suppresses everything. On a collector — the only host that
        # notifies at all — that silently disables relayed alerting while
        # the dashboard still looks correct.
        import time as _time
        class _Count:
            type, level = "stdout", "info"
            n = 0

            def dispatch(self, alert):
                _Count.n += 1

        hound.dispatcher.channels = [_Count()]
        real_now = _time.time()

        def _fresh(rid, ts, key="camera_offline:10.9.0.7"):
            r = V.validate_records({"alerts": [{
                "remote_id": rid, "ts": ts, "device_ip": "10.9.0.7",
                "kind": "camera_offline", "severity": "high",
                "summary": "down", "detail": "", "dedup_key": key,
            }]}, 100)
            store.ingest_remote_batch("frigate", "inst", 50 + rid, r, real_now)
            before_n = _Count.n
            hound._dispatch_relayed_alert("frigate", r["alerts"][0])
            return _Count.n > before_n

        assert _fresh(201, real_now) is True, (
            "a fresh relayed alert must be notified; the collector is the "
            "only host that notifies, so suppressing it pages nobody"
        )
        assert _fresh(202, real_now) is False, (
            "an immediate repeat of the same dedup_key must be suppressed"
        )
        # Dedup must use OUR receipt time, not the sensor-supplied ts, or
        # backdating an alert walks it straight past the window.
        assert _fresh(203, real_now - 108_000) is False, (
            "a backdated duplicate must still be suppressed — dedup keyed "
            "on the sensor-supplied ts is attacker-controlled"
        )
        print("  relayed dispatch: fresh alerts notify, repeats suppress, "
              "backdating cannot bypass the window")

        # A relayed alert's dedup_key must be a STRING, like a local
        # one. The in-memory dedup map is keyed by a tuple, and reusing
        # the same variable name for both put the tuple on the Alert —
        # so jsonlines/webhook/ftp consumers saw a two-element array
        # where every local alert gives them a string. Different schemas
        # on the exact output path this feature exists to feed.
        captured = []

        class _Capture:
            type, level = "jsonlines", "info"

            def dispatch(self, alert):
                captured.append(alert.as_dict())

        hound.dispatcher.channels = [_Capture()]
        shape = {
            "remote_id": 801, "ts": real_now, "device_ip": "10.9.0.9",
            "kind": "new_device", "severity": "high", "summary": "s",
            "detail": "", "dedup_key": "new_device:10.9.0.9",
        }
        store.ingest_remote_batch(
            "frigate", "inst", 801,
            V.validate_records({"alerts": [dict(shape)]}, 10), real_now)
        hound._dispatch_relayed_alert("frigate", dict(shape))
        assert captured, "the capture channel saw nothing"
        emitted = captured[0]["dedup_key"]
        assert isinstance(emitted, str), (
            f"dedup_key reached a notify channel as {type(emitted).__name__} "
            f"({emitted!r}); local alerts emit a string, and a SIEM parsing "
            f"both would see two schemas"
        )
        assert emitted == "frigate/new_device:10.9.0.9", emitted

        # A repeated remote_id must NOT multiply notifications.
        # `remote_id` is chosen by the sensor and the collector stores one
        # row per (sensor_id, remote_id), so N copies sharing an id
        # collapse to one row while still being dispatched N times. That
        # turned the dedup window — the only bound on relayed
        # notification volume — into one integer the attacker picks.
        hound.dispatcher.channels = [_Count()]
        _Count.n = 0
        dup = {
            "remote_id": 900, "ts": real_now, "device_ip": "10.9.0.8",
            "kind": "camera_offline", "severity": "critical",
            "summary": "flood", "detail": "",
            "dedup_key": "camera_offline:10.9.0.8",
        }
        store.ingest_remote_batch(
            "frigate", "inst", 900,
            V.validate_records({"alerts": [dict(dup)]}, 10), real_now)
        for _ in range(100):
            hound._dispatch_relayed_alert("frigate", dict(dup))
        assert _Count.n == 1, (
            f"100 copies of one alert sharing a remote_id produced "
            f"{_Count.n} notifications; the dedup window must not depend "
            f"on a number the sensor chooses"
        )

        # And such a batch is refused outright at validation, since a
        # well-formed agent never emits a duplicate id.
        try:
            V.validate_records({"alerts": [dict(dup), dict(dup)]}, 10)
            raise AssertionError(
                "a batch with a duplicate remote_id must be refused")
        except V.ValidationError as e:
            assert "duplicate remote_id" in str(e), e
        print("  relayed dispatch: a repeated remote_id cannot multiply "
              "notifications, and such a batch is refused")

        # Reusing one remote_id ACROSS batches must not page repeatedly.
        # The collector stores one row per (sensor_id, remote_id), so
        # fifty batches reusing id 1 stored the first and paged all
        # fifty — fifty audit rows citing content that was never sent.
        _Count.n = 0
        for i in range(50):
            a = {
                "remote_id": 1, "ts": real_now + i, "device_ip": "10.9.0.10",
                "kind": "camera_offline", "severity": "critical",
                "summary": f"page #{i}", "detail": "",
                "dedup_key": f"varies-{i}",
            }
            store.ingest_remote_batch(
                "reuser", "inst", i + 1,
                V.validate_records({"alerts": [a]}, 10), real_now + i)
            hound._dispatch_relayed_alert("reuser", a)
        stored = store._conn.execute(
            "SELECT COUNT(*) c FROM remote_alerts WHERE sensor_id='reuser'"
        ).fetchone()["c"]
        assert _Count.n == 1 and stored == 1, (
            f"a reused remote_id paged {_Count.n} time(s) against {stored} "
            f"stored row(s); the record and the page must agree"
        )

        # A per-sensor NOTIFICATION budget, since distinct dedup keys
        # bypass dedup entirely. Storage must be unaffected — only the
        # paging is capped, because that is the part that cannot be
        # taken back.
        hound.cfg.relay.max_notifications_per_minute = 5
        hound._relay_notify_times.clear()
        _Count.n = 0
        burst = []
        for i in range(40):
            a = {
                "remote_id": 2000 + i, "ts": real_now, "device_ip": "10.9.0.11",
                "kind": "bulk_inbound", "severity": "critical",
                "summary": f"burst {i}", "detail": "",
                "dedup_key": f"burst-{i}",
            }
            store.ingest_remote_batch(
                "burst", "inst", i + 1,
                V.validate_records({"alerts": [a]}, 10), real_now)
            burst.append(a)
        # Through the ENQUEUE path: the budget is applied there, because
        # an item that has already taken a queue slot has already denied
        # it to another sensor.
        hound._on_relayed_alerts("burst", burst, "inst")
        import queue as _q
        while True:
            try:
                hound._dispatch_relayed_alert(*hound._relay_alertq.get_nowait())
            except _q.Empty:
                break
        burst_rows = store._conn.execute(
            "SELECT COUNT(*) c FROM remote_alerts WHERE sensor_id='burst'"
        ).fetchone()["c"]
        assert _Count.n == 5, f"budget not enforced: {_Count.n} pages"
        assert burst_rows == 40, (
            f"the budget must cap PAGING only; {burst_rows}/40 alerts "
            f"reached storage, so the dashboard would under-report"
        )
        hound.cfg.relay.max_notifications_per_minute = 60
        print("  relayed dispatch: reused remote_id pages once; per-sensor "
              "notification budget caps paging but not storage")

        # The ingest thread must only ENQUEUE. Dispatching inline would let
        # one authenticated batch hold an ingest thread for as long as its
        # slowest channel takes.
        import queue as _queue
        hound.dispatcher.channels = []
        hound.stats.relayed_dropped_batch = 0
        hound.stats.relayed_dropped_share = 0
        hound.stats.relayed_dropped_queue = 0
        hound.stats.relayed_dropped_budget = 0
        while True:
            try:
                hound._relay_alertq.get_nowait()
            except _queue.Empty:
                break
        # Isolate the per-batch cap from the notification budget, which
        # also admits at enqueue and would otherwise bind first.
        hound.cfg.relay.max_notifications_per_minute = 0
        hound._relay_inflight.clear()
        many = [dict(recs["alerts"][0], remote_id=100 + i, dedup_key=f"k{i}")
                for i in range(500)]
        hound._on_relayed_alerts("frigate", many, "inst")
        queued = hound._relay_alertq.qsize()
        assert queued == 200, (
            f"a single batch must be capped at 200 enqueued alerts so it "
            f"cannot starve other sensors; queued {queued}"
        )
        assert hound.stats.relayed_dropped_batch == 300, (
            f"the overflow must be COUNTED, and attributed to the right "
            f"cause; batch counter says {hound.stats.relayed_dropped_batch}"
        )
        print("  relayed dispatch: ingest thread only enqueues; per-batch "
              "cap holds and overflow is counted")

        print("  relayed dispatch: real dispatch path audited to "
              "remote_notifications (successes AND failures); "
              "alerts/notifications/snapshots untouched")
    finally:
        hound.store.close()


def _check_sensor_offline_alerts(tmp: Path) -> None:
    """A sensor going quiet must ALERT, not just render grey.

    Stopping the agent is the first thing an intruder on the camera
    segment would do. Its cameras correctly degrade to `unknown`, but
    that is silent — visible only to someone already looking at the
    dashboard — and the collector is the only host that notifies.
    """
    from surveillancehound import daemon as daemon_mod
    from surveillancehound.config import load_from_dict

    cfg = load_from_dict({
        "capture": {"interface": "test0"},
        "network": {"camera_ips": ["10.9.0.5"]},
        "store": {"path": str(tmp / "sensorlive.sqlite")},
        "notify": [{"type": "stdout", "level": "info"}],
        "relay": {
            "mode": "collector", "listen_host": "127.0.0.1",
            "listen_port": 0,
            "cert_file": str(FIXTURES / "ingest-test.crt"),
            "key_file": str(FIXTURES / "ingest-test.key"),
            "sensor_timeout_seconds": 180.0,
            "sensor": [{"id": "frigate", "key": "shared-secret-abcdef"}],
        },
    })
    hound = daemon_mod.Hound(cfg)
    hound.ingest = object()          # mark collector mode without binding
    try:
        store = hound.store
        recs = V.validate_records(_good_records(), 100)
        store.ingest_remote_batch("frigate", "inst", 1, recs, T0)

        def kinds():
            return [a.kind for a in store.list_alerts(limit=50)]

        hound._check_sensor_liveness(T0 + 10)
        assert "sensor_offline" not in kinds(), (
            "a sensor that reported 10s ago is not offline"
        )

        hound._check_sensor_liveness(T0 + 1000)
        assert "sensor_offline" in kinds(), (
            "a sensor silent for 1000s with a 180s timeout must alert; "
            "otherwise killing the agent is completely silent"
        )
        n_after_first = kinds().count("sensor_offline")

        hound._check_sensor_liveness(T0 + 2000)
        assert kinds().count("sensor_offline") == n_after_first, (
            "sensor_offline must fire once per outage, not every tick"
        )

        # Recovery: a newer batch arrives, the next check clears it.
        store.ingest_remote_batch("frigate", "inst", 2, recs, T0 + 2100)
        hound._check_sensor_liveness(T0 + 2110)
        assert "sensor_recovered" in kinds(), (
            "the sensor reporting again must be announced, or an operator "
            "cannot tell a resolved outage from an ongoing one"
        )
        print("  sensor liveness: offline alerts once, recovery announced")
    finally:
        hound.store.close()


def _check_parse_amplification_bounded() -> None:
    """A dense body must be refused BEFORE json.loads allocates.

    Authenticating before parsing closed the unauthenticated case, but
    the threat model's premise is a key-holder: an 8 MB body of
    `[],[],[]...` costs ~209 MB resident, and concurrent ones took the
    collector to 1.3 GB — an OOM of the process that is also capturing
    packets. The record cap cannot help; it is applied after the
    allocation it would need to prevent.
    """
    import json as _json

    hostile = b"[" + b"[]," * 700000 + b"[]]"
    try:
        V.check_container_budget(hostile)
        raise AssertionError(
            f"a {len(hostile) // 1000} kB body of empty containers was "
            f"accepted for parsing"
        )
    except V.ValidationError:
        pass

    # A FULL legitimate batch must still pass, or the bound is useless.
    rec = {
        "remote_id": 1, "src_ip": "10.0.0.1", "src_port": 1,
        "dst_ip": "10.0.0.2", "dst_port": 2, "proto": "tcp",
        "first_seen": T0, "last_seen": T0, "packets": 1, "bytes": 1,
        "bytes_to_camera": 0, "bytes_from_camera": 0,
        "tcp_flags_seen": "", "classification": "lan_normal",
    }
    full = _json.dumps({"records": {
        k: [dict(rec, remote_id=i + 1) for i in range(5000)]
        for k in ("flows", "alerts", "devices", "outages", "uptime")
    }}).encode()
    V.check_container_budget(full)

    # Brackets inside a string are data, not structure.
    V.check_container_budget(_json.dumps({"summary": "[{" * 100000}).encode())
    # Deep nesting must be a 4xx, not a 500. The agent retries 500s
    # from the spool forever, so one malformed body wedged the head of
    # the queue permanently.
    try:
        V.loads_strict(b"[" * 140000)
        raise AssertionError("140k nesting levels parsed")
    except V.ValidationError:
        pass
    except RecursionError:
        raise AssertionError(
            "RecursionError escaped loads_strict; it reaches the "
            "handler's catch-all as a 500, and the agent retries 500s "
            "forever"
        ) from None

    # Memory-dense but container-sparse shapes: the budget counts
    # containers, so these are bounded by max_body_bytes and the
    # worker ceiling rather than by the scan. Asserted so the limit of
    # the mechanism is written down rather than assumed away.
    two_containers = b'["' + b'ab","' * 200 + b'ab"]'
    V.check_container_budget(two_containers)

    print(f"  parse budget: dense bodies refused before allocation; deep "
          f"nesting is a 400 not a 500; a full "
          f"{len(full) // 100000 / 10:.1f} MB batch still accepted")


def _check_relayed_api_surface(tmp: Path) -> None:
    """Relayed rows must reach /api/uptime and `hound export` correctly.

    These two are the stale-gating path. Its entire purpose is that a
    dead sensor's cameras do not read `up`, so leaving it unasserted at
    the boundary means the one guarantee it exists to provide is the one
    nobody checks. A reader that silently stops emitting `remote_cameras`
    would turn the collector's dashboard back into a local-only view.
    """
    import json
    import threading
    import time
    import urllib.request
    from http.server import ThreadingHTTPServer

    from surveillancehound.config import load_from_dict
    from surveillancehound.store import HoundStore
    from surveillancehound.web import _Handler

    now = time.time()
    db = tmp / "api.sqlite"
    store = HoundStore(path=db)
    store.upsert_device("10.9.0.5", "camera", now - 5, 10, 1000,
                        first_seen=now - 9000)
    store.start_monitor_session(now - 9000, "live")
    store.set_heartbeat(now - 2, now)

    def _rec(ip, state, avail):
        return {"ip": ip, "role": "camera", "state": state,
                "last_seen": now - 10, "first_seen": now - 9000,
                "down_since": None, "current_downtime": 0.0,
                "outage_count": 0, "downtime_seconds": 0.0,
                "monitored_seconds": 9000.0, "availability": avail}

    store.ingest_remote_batch(
        "live-one", "i1", 1,
        V.validate_records({"uptime": [_rec("10.1.1.2", "up", 1.0)]}, 100),
        now - 20)
    # three hours silent, far past the 180s default timeout
    store.ingest_remote_batch(
        "dead-one", "i2", 1,
        V.validate_records({"uptime": [_rec("10.2.2.2", "up", 1.0)]}, 100),
        now - 10800)
    store.close()

    cfg = load_from_dict({
        "capture": {"interface": "test0"},
        "network": {"camera_ips": ["10.9.0.5"]},
        "store": {"path": str(db)},
        "web": {"enabled": True, "host": "127.0.0.1", "port": 0},
        # Must be a collector: the API withholds relayed rows otherwise,
        # which is correct — a non-collector has no business reporting
        # them — and is itself worth asserting below.
        "relay": {
            "mode": "collector", "listen_host": "127.0.0.1",
            "listen_port": 0,
            "cert_file": str(FIXTURES / "ingest-test.crt"),
            "key_file": str(FIXTURES / "ingest-test.key"),
            "sensor": [{"id": "live-one", "key": "shared-secret-abcdef"},
                       {"id": "dead-one", "key": "shared-secret-abcdef"}],
        },
    })
    _Handler.cfg = cfg
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/api/uptime") as r:
            up = json.loads(r.read())

        for key in ("cameras", "remote_cameras", "sensors"):
            assert key in up, f"/api/uptime must carry {key!r}: {list(up)}"

        by_ip = {c["ip"]: c for c in up["remote_cameras"]}
        assert set(by_ip) == {"10.1.1.2", "10.2.2.2"}, list(by_ip)

        live = by_ip["10.1.1.2"]
        assert live["sensor"] == "live-one" and live["state"] == "up", live
        assert live["stale"] is False, live

        dead = by_ip["10.2.2.2"]
        assert dead["state"] == "unknown", (
            f"a camera behind a sensor that stopped reporting must read "
            f"unknown, not the {dead['state']!r} it last claimed"
        )
        assert dead["stale"] is True, dead
        assert dead["availability"] is None, (
            f"its availability is as stale as its state; got "
            f"{dead['availability']!r}"
        )

        # Local rows must stay distinguishable from relayed ones.
        assert all(c.get("sensor") == "local" for c in up["cameras"]), up["cameras"]

        # Relayed ALERTS must reach the API too. They were stored,
        # notified, quota'd and pruned but rendered by neither dashboard.
        with urllib.request.urlopen(base + "/api/alerts") as r:
            al = json.loads(r.read())
        assert "remote_alerts" in al, list(al)
        assert all(a.get("sensor") == "local" for a in al["alerts"])
        with urllib.request.urlopen(base + "/api/flows") as r:
            fl = json.loads(r.read())
        assert "remote_flows" in fl, list(fl)

        rep = {x["sensor_id"]: x["reporting"] for x in up["sensors"]}
        assert rep == {"live-one": True, "dead-one": False}, rep
    finally:
        srv.shutdown()
        srv.server_close()

    # A NON-collector must report no relayed rows at all, even against a
    # store that has them. Reporting another host's observations when
    # this instance is not configured to receive any would be claiming
    # something it has no basis for.
    plain = load_from_dict({
        "capture": {"interface": "test0"},
        "network": {"camera_ips": ["10.9.0.5"]},
        "store": {"path": str(db)},
        "web": {"enabled": True, "host": "127.0.0.1", "port": 0},
    })
    _Handler.cfg = plain
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/api/uptime") as r:
            off = json.loads(r.read())
        assert off["remote_cameras"] == [] and off["sensors"] == [], (
            "a non-collector reported relayed rows"
        )
        assert rep == {"live-one": True, "dead-one": False}, rep
    finally:
        srv.shutdown()
        srv.server_close()

    # And the same data through `hound export`, which is what the OPNsense
    # plugin dashboard renders — it cannot reach /api/uptime at all.
    import argparse
    import io
    from contextlib import redirect_stdout

    from surveillancehound import cli as cli_mod
    buf = io.StringIO()
    toml = tmp / "api.toml"
    toml.write_text(
        '[capture]\ninterface = "test0"\n'
        '[network]\ncamera_ips = ["10.9.0.5"]\n'
        f'[store]\npath = "{db}"\n'
        # Collector mode: `hound export` withholds relayed rows
        # otherwise, matching the API.
        '[relay]\nmode = "collector"\nlisten_host = "127.0.0.1"\n'
        'listen_port = 18443\n'
        f'cert_file = "{FIXTURES / "ingest-test.crt"}"\n'
        f'key_file = "{FIXTURES / "ingest-test.key"}"\n'
        '[[relay.sensor]]\nid = "live-one"\n'
        'key = "shared-secret-abcdef"\n'
        '[[relay.sensor]]\nid = "dead-one"\n'
        'key = "shared-secret-abcdef"\n'
    )
    with redirect_stdout(buf):
        rc = cli_mod.cmd_export(argparse.Namespace(config=str(toml), limit=100, window=86400.0))
    assert rc == 0, rc
    doc = json.loads(buf.getvalue())
    assert "remote_uptime" in doc and "sensors" in doc, list(doc)
    exported = {c["ip"]: c for c in doc["remote_uptime"]}
    assert exported["10.2.2.2"]["state"] == "unknown", exported["10.2.2.2"]
    assert exported["10.2.2.2"]["availability"] is None
    assert {x["sensor_id"]: x["reporting"] for x in doc["sensors"]} == {
        "live-one": True, "dead-one": False}
    print("  api surface: /api/uptime and `hound export` both carry relayed "
          "rows; a dead sensor reads unknown with no availability")


def _check_replay_opens_no_listener(tmp: Path) -> None:
    """A forensic replay must not open a network port.

    `run()` starts the listener only on the live path, but the rebind
    retry ran from the replay tick too — so analysing a pcap silently
    bound the ingest port and accepted authenticated remote writes into
    the replay store, with no dispatch worker to consume them.
    """
    import socket

    from surveillancehound import daemon as daemon_mod
    from surveillancehound.config import load_from_dict
    from surveillancehound.pcap import write_pcap

    pcap = tmp / "empty.pcap"
    write_pcap(pcap, iter([]))
    port = 18991
    cfg = load_from_dict({
        "capture": {"pcap_file": str(pcap)},
        "network": {"camera_ips": ["10.9.0.5"]},
        "store": {"path": str(tmp / "replay.sqlite")},
        "relay": {
            "mode": "collector", "listen_host": "127.0.0.1",
            "listen_port": port,
            "cert_file": str(FIXTURES / "ingest-test.crt"),
            "key_file": str(FIXTURES / "ingest-test.key"),
            "sensor": [{"id": "frigate", "key": "shared-secret-abcdef"}],
        },
    })
    hound = daemon_mod.Hound(cfg)
    assert hound._replay, "fixture must be a replay"
    hound.run()
    sock = socket.socket()
    try:
        sock.settimeout(2)
        sock.connect(("127.0.0.1", port))
        raise AssertionError(
            "replay opened the ingest port; a pcap analysis must not "
            "start a listener or accept remote writes"
        )
    except OSError:
        pass
    finally:
        sock.close()
    print("  replay: no ingest listener, no sensor alerts from packet time")


def _check_spool_counters(tmp: Path) -> None:
    """`hound relay` must not report numbers it cannot stand behind.

    This is the command specified to work with the link DOWN, which is
    exactly when an operator trusts it. `_enforce_caps` bumps the drop
    counters, and `pending()` runs every push cycle, so without writing
    the filtered list back one expired batch was re-counted as a fresh
    drop forever; `stats()` skipped the age cap entirely and reported a
    backlog that would never be sent.
    """
    from surveillancehound.relay import Spool

    sp = Spool(tmp / "spool", 10 * 1024 * 1024, 10.0)
    sp.append(1, b'{"a":1}', 0.0)
    sp.append(2, b'{"a":2}', 0.0)
    for _ in range(5):
        assert sp.pending(100.0) == [], "expired batches must never be sent"
    st = sp.stats(100.0)
    assert st.pending == 0, (
        f"stats() must report what pending() would actually send; it "
        f"claims {st.pending} batches are spooled"
    )
    assert st.bytes == 0, st.bytes

    # READERS MUST NOT MUTATE. `hound relay` builds its own Spool over the
    # live directory in a DIFFERENT PROCESS from the daemon, and the lock
    # is a thread lock, so a reader that wrote back could erase a batch
    # the daemon appended in between — the diagnostic command for data
    # loss causing it.
    spool_file = (tmp / "spool" / "spool.jsonl")
    on_disk_before = spool_file.read_text()
    sp.pending(100.0)
    sp.stats(100.0)
    assert spool_file.read_text() == on_disk_before, (
        "pending()/stats() rewrote the spool; a concurrent append from "
        "the daemon would be lost"
    )

    # Counting happens on mutation, exactly once, and an entry that aged
    # out UNSENT must still appear in the drop total rather than being
    # swept away as though it had been delivered.
    assert sp.dropped_age == 0, (
        f"reads must not count drops — pending() runs every push cycle, "
        f"so counting there inflates the total forever; got {sp.dropped_age}"
    )
    sp.append(3, b'{"a":3}', 100.0)
    sp.ack(3)
    assert sp.dropped_age == 2, (
        f"two batches aged out unsent and must be counted; got "
        f"{sp.dropped_age}"
    )
    sp.ack(3)
    assert sp.dropped_age == 2, "a second ack must not re-count"

    # Live entries survive, and the byte cap evicts oldest-first.
    sp2 = Spool(tmp / "spool2", 200, 3600.0)
    for i in range(20):
        sp2.append(i, b'{"padpadpadpadpad":%d}' % i, 0.0)
    got = [seq for seq, _ in sp2.pending(1.0)]
    assert got, "the byte cap must not empty the spool"
    assert got == sorted(got) and got[-1] == 19, (
        f"the newest batch must survive and order must hold: {got}"
    )
    assert sp2.dropped_size > 0

    # ack / drop semantics
    sp3 = Spool(tmp / "spool3", 10 * 1024 * 1024, 3600.0)
    for i in (1, 2, 3, 4):
        sp3.append(i, b'{"x":%d}' % i, 0.0)
    sp3.ack(2)
    assert [q for q, _ in sp3.pending(1.0)] == [3, 4], (
        "ack must clear everything up to and including the acked seq — "
        "a batch the collector has is not ours to resend"
    )
    sp3.drop(3, "rejected")
    assert [q for q, _ in sp3.pending(1.0)] == [4]
    assert sp3.dropped_stale == 1

    # Survives a restart: the file IS the state.
    again = Spool(tmp / "spool3", 10 * 1024 * 1024, 3600.0)
    assert [q for q, _ in again.pending(1.0)] == [4], (
        "the spool must survive a restart, or an outage loses exactly the "
        "observations it was buffering"
    )
    # An agent draining a backlog must not trip the collector's
    # request budget and lock ITSELF out. The limiter counts every
    # request, so a tight replay loop earns an accept-time cooldown at
    # exactly the moment the sensor is trying to catch up.
    import surveillancehound.relay as _rl
    assert _rl._REPLAY_PACE_S > 0, (
        "spool replay is unpaced; a backlog drain exceeds the "
        "collector's per-source request budget and the agent locks "
        "itself out while recovering"
    )
    # 60 requests/minute is the collector default; pacing must leave
    # headroom under it.
    assert _rl._REPLAY_PACE_S >= 60.0 / 60, (
        f"replay pace {_rl._REPLAY_PACE_S}s is at or above the default "
        f"budget rate with no margin"
    )

    print("  spool: drop counters count once; stats() matches pending(); "
          "ack/drop/restart hold")


def _check_agent_state(tmp: Path) -> None:
    """Agent identity and progress must survive a restart.

    `instance_id` is how the collector tells a restarted agent from a
    second one claiming the same id, and `next_seq` is what stops a
    restart replaying from 1 and getting 409s forever. A watermark that
    reset would re-send the agent's whole history on every restart.
    """
    from surveillancehound.relay import AgentState

    base = tmp / "agent"
    st = AgentState.load(base)
    first_instance = st.instance_id
    assert first_instance, "an agent must mint an instance id"
    st.next_seq = 42
    st.watermark.flow_id = 7
    st.watermark.alert_id = 9
    st.watermark.outage_id = 3
    st.watermark.reported_at = 1234.5
    st.last_push_ts = 999.0
    st.save()

    back = AgentState.load(base)
    assert back.instance_id == first_instance, (
        "instance_id must be stable across restarts, or the collector "
        "treats every restart as a new agent and resets its sequence"
    )
    assert back.next_seq == 42, back.next_seq
    assert (back.watermark.flow_id, back.watermark.alert_id,
            back.watermark.outage_id) == (7, 9, 3), back.watermark
    assert back.watermark.reported_at == 1234.5

    # Four independent cursors, not one: flows, alerts and outages have
    # separate autoincrement ids.
    assert len({"flow_id", "alert_id", "outage_id", "reported_at"}
               - set(back.watermark.as_dict())) == 0

    # A wiped state directory mints a NEW instance, which is the signal
    # the collector uses to reset its sequence expectations.
    import shutil
    shutil.rmtree(base)
    fresh = AgentState.load(base)
    assert fresh.instance_id != first_instance, (
        "a wiped agent must present a new instance id so the collector "
        "can tell it apart from a sequence replay"
    )
    assert fresh.next_seq == 1, fresh.next_seq
    # `hound relay` is a diagnostic and must not rewrite identity. A
    # normal load mints and SAVES an instance_id when the file is
    # missing or torn, so run as another user — or against a damaged
    # file — the diagnostic silently reset the agent's identity.
    import shutil as _sh
    probe = tmp / "agent-ro"
    ro = AgentState.load(probe, readonly=True)
    assert ro.instance_id == "", "readonly must not mint an identity"
    assert not probe.exists(), "readonly must not create the state directory"
    live = AgentState.load(probe)
    assert live.instance_id, "a normal load still mints"
    assert AgentState.load(probe, readonly=True).instance_id == \
        live.instance_id, "readonly must read an existing identity"
    _sh.rmtree(probe)

    print("  agent state: instance stable across restart, new on wipe; "
          "4 watermark cursors persist; diagnostics do not rewrite it")


def _check_shutdown_and_slot_release(tmp: Path) -> None:
    """Shutdown must not be hostage to a remote-filled queue, and a
    failed worker spawn must not leak a connection slot."""
    import queue as _q
    import time as _t

    from surveillancehound import daemon as daemon_mod
    from surveillancehound.config import load_from_dict

    class _Slow:
        type, level = "stdout", "info"

        def dispatch(self, alert):
            _t.sleep(0.05)

    cfg = load_from_dict({
        "capture": {"interface": "test0"},
        "network": {"camera_ips": ["10.9.0.5"]},
        "store": {"path": str(tmp / "shutdown.sqlite")},
        "notify": [{"type": "stdout", "level": "info"}],
        "relay": {
            "mode": "collector", "listen_host": "127.0.0.1", "listen_port": 0,
            "cert_file": str(FIXTURES / "ingest-test.crt"),
            "key_file": str(FIXTURES / "ingest-test.key"),
            "sensor": [{"id": "frigate", "key": "shared-secret-abcdef"}],
        },
    })
    hound = daemon_mod.Hound(cfg)
    hound.dispatcher.channels = [_Slow()]
    try:
        hound._start_relay_dispatch()
        raw = {"remote_id": 1, "ts": T0, "device_ip": "10.0.0.5",
               "kind": "new_device", "severity": "high", "summary": "s",
               "detail": "", "dedup_key": "k"}
        for i in range(1000):
            try:
                hound._relay_alertq.put_nowait(
                    ("frigate", dict(raw, remote_id=i, dedup_key=f"k{i}")))
            except _q.Full:
                break
        t0 = _t.time()
        hound._stop_relay_dispatch()
        elapsed = _t.time() - t0
        assert elapsed < 3.0, (
            f"shutdown took {elapsed:.1f}s with a full queue. The stop flag "
            f"must be checked every iteration, not only when the queue is "
            f"empty — otherwise a remote sensor decides how long shutdown "
            f"takes, and the worker outlives the store it writes to"
        )
    finally:
        hound.store.close()

    # A failed thread spawn must release both the semaphore and the
    # per-source count, or six failures lock that address out for good —
    # the anti-lockout counter becoming the lockout.
    from surveillancehound.ingest import _Server

    class _Boom(_Server):
        def __init__(self):            # no socket; we only exercise bookkeeping
            self._slots = __import__("threading").BoundedSemaphore(4)
            self._per_source = {}
            self._trusted = {}
            self._deadlines = {}
            self._src_lock = __import__("threading").Lock()
            self.rejected_overload = 0

        def shutdown_request(self, request):
            pass

        def process_request_thread(self, request, client_address):
            raise AssertionError("must not be reached")

    srv = _Boom()
    import socketserver
    orig = socketserver.ThreadingMixIn.process_request

    def _fail(self, request, client_address):
        raise RuntimeError("can't start new thread")

    socketserver.ThreadingMixIn.process_request = _fail
    try:
        for _ in range(8):
            try:
                srv.process_request(None, ("10.0.0.9", 1234))
            except RuntimeError:
                pass
    finally:
        socketserver.ThreadingMixIn.process_request = orig
    assert srv._per_source.get("10.0.0.9", 0) == 0, (
        f"per-source count leaked on spawn failure: {srv._per_source}"
    )
    # And shutdown must not be extended by connections that are not
    # doing work: an idle keep-alive, or a bare TCP SYN from an
    # unauthenticated peer, used to add the full timeout to every
    # restart — a remote host lengthening the blind window on its own
    # schedule.
    import socket as _sock

    from surveillancehound.ingest import IngestServer
    from surveillancehound.store import HoundStore as _HS
    probe_store = _HS(path=tmp / "idleconn.sqlite")
    probe_port = _free_port()
    probe = IngestServer(_collector_cfg(probe_port), probe_store)
    assert probe.start()
    try:
        idle = _sock.create_connection(("127.0.0.1", probe_port), timeout=5)
        _t.sleep(0.3)
        t0 = _t.time()
        probe.stop()
        took = _t.time() - t0
        idle.close()
        assert took < 3.0, (
            f"stop() took {took:.1f}s with one idle connection and no "
            f"batch in flight; shutdown must wait for work, not sockets"
        )
    finally:
        probe_store.close()
    # Round-robin service: one sensor's backlog must not sit in front
    # of another sensor's page. Dropping was fixed earlier; DELAY is
    # the same silencing at a few seconds per channel.
    from surveillancehound.daemon import _FairAlertQueue
    fq = _FairAlertQueue(1000)
    for i in range(500):
        fq.put_nowait(("noisy", {"i": i}, "inst"))
    fq.put_nowait(("quiet", {"i": "critical"}, "inst"))
    served = [fq.get_nowait()[0] for _ in range(6)]
    assert "quiet" in served[:3], (
        f"the quiet sensor waited behind a 500-deep flood: {served}"
    )
    # The sentinel is not an alert and must not be counted as backlog.
    fq2 = _FairAlertQueue(10)
    fq2.put_nowait(None)
    assert fq2.qsize() == 0, "the shutdown sentinel inflated the queue size"
    assert fq2.get_nowait() is None

    # The per-sensor budget must be CHECKED at admission but only SPENT
    # on a successful enqueue, or alerts rejected by a later gate burn
    # an allowance they never used.
    from surveillancehound import daemon as dmod
    from surveillancehound.config import load_from_dict as _lfd
    cfg2 = _lfd({
        "capture": {"interface": "test0"},
        "network": {"camera_ips": ["10.9.0.5"]},
        "store": {"path": str(tmp / "budget.sqlite")},
        "relay": {
            "mode": "collector", "listen_host": "127.0.0.1", "listen_port": 0,
            "cert_file": str(FIXTURES / "ingest-test.crt"),
            "key_file": str(FIXTURES / "ingest-test.key"),
            "max_notifications_per_minute": 10,
            "sensor": [{"id": "s0", "key": "shared-secret-abcdef"}],
        },
    })
    h2 = dmod.Hound(cfg2)
    try:
        h2._relay_queue_share = lambda: 0          # force share rejection
        mk = lambda i: {"remote_id": i, "ts": T0, "device_ip": "10.0.0.5",
                        "kind": "new_device", "severity": "low",
                        "summary": "n", "detail": "", "dedup_key": f"d{i}"}
        h2._on_relayed_alerts("s0", [mk(i + 1) for i in range(10)], "inst")
        spent = len(h2._relay_notify_times.get("s0", []))
        assert spent == 0, (
            f"{spent} budget token(s) spent on alerts that were never "
            f"queued; a burst of rejected noise would then refuse the "
            f"next genuine alert against an empty queue"
        )
        h2._relay_queue_share = lambda: 500
        h2._on_relayed_alerts("s0", [dict(mk(99), severity="critical")], "inst")
        assert h2._relay_alertq.qsize() == 1
    finally:
        h2.store.close()

    # The reaper must actually close the socket, not merely log that
    # it did. `ssl.wrap_socket` DETACHES the raw socket it is given,
    # so the object captured at accept time has fileno == -1: the
    # shutdown raised EBADF, was swallowed, and the collector logged a
    # defence that had never fired. A warning is a claim like any
    # other.
    import socket as _sk
    import ssl as _ssl

    import surveillancehound.ingest as _ing
    from surveillancehound.store import HoundStore as _HS2

    saved_budget = _ing._CONN_BUDGET
    _ing._CONN_BUDGET = 3.0
    reap_store = _HS2(path=tmp / "reaper.sqlite")
    reaper_port = _free_port()
    reaper_srv = IngestServer(_collector_cfg(reaper_port), reap_store)
    assert reaper_srv.start()
    try:
        cctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
        cctx.check_hostname = False
        cctx.verify_mode = _ssl.CERT_NONE
        sock = _sk.create_connection(("127.0.0.1", reaper_port), timeout=30)
        tls = cctx.wrap_socket(sock, server_hostname="x")
        tls.sendall(b"POST /ingest/v1 HTTP/1.1\r\nHost: x\r\n"
                    b"Content-Length: 100000\r\n\r\n")
        cut = None
        start = _t.time()
        for _ in range(20):
            try:
                tls.sendall(b"a")
                _t.sleep(0.5)
            except OSError:
                cut = _t.time() - start
                break
        assert cut is not None and cut < 10, (
            f"a dribbling peer was never disconnected (budget "
            f"{_ing._CONN_BUDGET}s); it holds a worker slot forever "
            f"while the reaper logs that it closed it"
        )
        assert reaper_srv._httpd.active_slots() == 0, (
            "the reaped connection did not release its slot"
        )
        try:
            tls.close()
        except OSError:
            pass
    finally:
        _ing._CONN_BUDGET = saved_budget
        reaper_srv.stop()
        reap_store.close()

    # File descriptors must not leak per connection. Keying the
    # deadline map on the WRAPPED socket meant the handler's cleanup
    # popped the raw one, matched nothing, and left a strong reference
    # to the only object holding the real fd for the whole budget:
    # measured, an unauthenticated peer reached EMFILE in 14s and the
    # accept loop then span at 99.8% of a core in the same process as
    # the pcap parser.
    import os as _os

    def _fd_count() -> int:
        try:
            return len(_os.listdir("/proc/self/fd"))
        except OSError:
            return -1

    if _fd_count() >= 0:
        leak_store = _HS2(path=tmp / "fdleak.sqlite")
        leak_port = _free_port()
        leak_srv = IngestServer(_collector_cfg(leak_port), leak_store)
        assert leak_srv.start()
        try:
            lctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            lctx.check_hostname = False
            lctx.verify_mode = _ssl.CERT_NONE
            before = _fd_count()
            for _ in range(40):
                try:
                    c = _sk.create_connection(("127.0.0.1", leak_port), timeout=5)
                    tw = lctx.wrap_socket(c, server_hostname="x")
                    tw.sendall(b"POST /nope HTTP/1.1\r\nHost: x\r\n"
                               b"Content-Length: 0\r\n\r\n")
                    tw.recv(200)
                    tw.close()
                except OSError:
                    pass
            _t.sleep(0.5)
            grew = _fd_count() - before
            assert grew < 20, (
                f"{grew} file descriptors leaked over 40 completed "
                f"connections. They are pinned for the whole connection "
                f"budget, so a peer needing no key reaches EMFILE and "
                f"the accept loop livelocks against packet capture"
            )
            assert len(leak_srv._httpd._deadlines) < 10, (
                f"{len(leak_srv._httpd._deadlines)} deadline entries "
                f"outlived their handlers; each pins a socket"
            )
        finally:
            leak_srv.stop()
            leak_store.close()
        print("  fd hygiene: 40 completed connections leak no descriptors")

    print("  shutdown: prompt with a full queue; slots released on spawn "
          "failure; round-robin service; budget spent only on enqueue")


def _check_instance_reset(tmp: Path) -> None:
    """An agent that loses its state must not have its records swallowed.

    `remote_id` is the agent's own rowid, so a wiped agent restarts at 1.
    Keyed on (sensor_id, remote_id) alone, every colliding record was
    dropped by ON CONFLICT, acked as accepted, and the agent advanced its
    watermark past it — permanent loss on a documented operation
    (`docker volume rm`), and trivially induced by anyone who can delete
    a file on the camera-segment host the threat model assumes is
    compromised. Outages were worse: DO UPDATE rewrote an unrelated
    camera's outage window.
    """
    from surveillancehound.store import HoundStore

    store = HoundStore(path=tmp / "instance.sqlite")
    try:
        def alert(rid, summary, kind="new_device", sev="low"):
            return V.validate_records({"alerts": [{
                "remote_id": rid, "ts": T0, "device_ip": "10.0.0.5",
                "kind": kind, "severity": sev, "summary": summary,
                "detail": "", "dedup_key": f"dk-{summary}",
            }]}, 10)

        store.ingest_remote_batch("frigate", "INST-A", 1,
                                  alert(1, "benign"), T0)
        counts = store.ingest_remote_batch(
            "frigate", "INST-B", 1,
            alert(1, "firmware push", "bulk_inbound", "critical"), T0 + 10)
        rows = store._conn.execute(
            "SELECT instance_id, summary FROM remote_alerts ORDER BY id"
        ).fetchall()
        assert len(rows) == 2, (
            f"a post-wipe alert was swallowed: {[tuple(r) for r in rows]}"
        )
        assert counts["alerts"] == 1, (
            f"the ack must report rows actually INSERTED, not records "
            f"submitted — the agent advances its watermark on this and "
            f"never resends; got {counts['alerts']}"
        )

        # Outages: a reused id across instances must not rewrite another
        # camera's window.
        def outage(rid, cam, down, up):
            return V.validate_records({"outages": [{
                "remote_id": rid, "camera_ip": cam, "down_since": down,
                "up_at": up, "last_seen_before": 0.0, "cause": "silence",
            }]}, 10)

        store.ingest_remote_batch("frigate", "INST-A", 2,
                                  outage(7, "10.0.0.5", T0, None), T0)
        store.ingest_remote_batch("frigate", "INST-B", 2,
                                  outage(7, "10.0.0.99", T0 + 5000,
                                         T0 + 5100), T0 + 20)
        out = store._conn.execute(
            "SELECT camera_ip, down_since, up_at FROM remote_outages "
            "ORDER BY id").fetchall()
        assert len(out) == 2, (
            f"a reused outage id across instances rewrote the other "
            f"camera's outage instead of inserting: {[tuple(o) for o in out]}"
        )
        first = dict(out[0])
        assert first["camera_ip"] == "10.0.0.5" and first["up_at"] is None, (
            f"the pre-wipe outage was corrupted: {first}"
        )
        # instance_id is now part of the key, so it is as untrusted as
        # any other wire string. An EMPTY one collapses the key straight
        # back to (sensor, remote_id) and reinstates the cross-instance
        # clobbering the key exists to stop.
        for bad, why in (
            ("", "empty"),
            ("x" * 200, "over-long"),
            ("INST\x07\x1b[31m", "control characters"),
            (None, "missing"),
        ):
            try:
                V.clean_instance_id(bad)
                raise AssertionError(
                    f"an {why} instance_id was accepted; it is persisted on "
                    f"every relayed row, echoed by the API and logged"
                )
            except V.ValidationError:
                pass
        assert V.clean_instance_id("a1b2c3d4e5f6a7b8") == "a1b2c3d4e5f6a7b8"

        print("  instance reset: post-wipe records stored, acked honestly, "
              "outage history intact, instance_id validated")
    finally:
        store.close()


def _check_prerelease_schema_upgrade(tmp: Path) -> None:
    """A store from before the instance-scoped key must still work.

    The project forbids ALTER TABLE and uses CREATE TABLE IF NOT EXISTS,
    so an older relay table survives untouched and every INSERT then
    fails with "no column named instance_id". Ingest answers 500, the
    agent treats 500 as retryable, and the collector silently ingests
    NOTHING for the rest of its life while the agent's spool ages out —
    loud in one log, invisible in the other.
    """
    import sqlite3

    from surveillancehound.store import HoundStore

    db = tmp / "prerelease.sqlite"
    con = sqlite3.connect(db)
    con.executescript(
        """CREATE TABLE remote_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL,
            remote_id INTEGER NOT NULL, ts REAL NOT NULL,
            device_ip TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL,
            severity TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '', dedup_key TEXT NOT NULL,
            ingested_at REAL NOT NULL, UNIQUE (sensor_id, remote_id));"""
    )
    con.execute("INSERT INTO remote_alerts VALUES "
                "(1,'s',1,0,'','k','low','old','','d',0)")
    con.commit()
    con.close()

    store = HoundStore(path=db)
    try:
        recs = V.validate_records({"alerts": [{
            "remote_id": 1, "ts": T0, "device_ip": "10.0.0.1",
            "kind": "new_device", "severity": "low", "summary": "new",
            "detail": "", "dedup_key": "k",
        }]}, 10)
        counts = store.ingest_remote_batch("s", "inst-aaaa1111", 1, recs, T0)
        assert counts["alerts"] == 1, (
            f"ingest against a pre-release store inserted nothing "
            f"({counts}); an in-place upgrade would 500 forever"
        )
        cols = {r[1] for r in
                store._conn.execute("PRAGMA table_info(remote_alerts)")}
        assert "instance_id" in cols, cols
        print("  schema: a pre-release relay table is recreated rather than "
              "failing every insert")
    finally:
        store.close()


def _check_outage_close_is_relayed(tmp: Path) -> None:
    """An outage that CLOSES must reach the collector as closed.

    `up_at IS NULL` re-sends an outage only while it is still open, and
    the watermark advances past its id on the first send — so the close
    matched nothing and the collector's copy stayed open forever. The
    (sensor, instance, remote_id) key makes the update idempotent, and
    was correct the whole time; the sender simply never sent the
    update that would use it. Nothing renders remote_outages yet, so
    this was invisible: the first surface to show it would have
    reported every camera as still down.
    """
    from surveillancehound.relay import AgentState, Watermark
    from surveillancehound.store import HoundStore

    agent = HoundStore(path=tmp / "agent-out.sqlite")
    collector = HoundStore(path=tmp / "coll-out.sqlite")
    try:
        with agent._conn:
            agent._conn.execute(
                "INSERT INTO outages (camera_ip, down_since, up_at, "
                "last_seen_before, cause) VALUES ('10.0.0.5',?,NULL,"
                "0.0,'silence')", (T0,))

        # Drive the REAL RelayClient: collect() + _advance(), not a
        # re-implementation of them. A test that reproduces the
        # watermark logic inline passes just as happily when the
        # production code is reverted, which is how this project has
        # twice shipped a "fix" that never landed.
        from surveillancehound.relay import RelayClient
        from surveillancehound.config import load_from_dict as _lfd

        acfg = _lfd({
            "capture": {"interface": "test0"},
            "network": {"camera_ips": ["10.0.0.5"]},
            "store": {"path": str(tmp / "agent-out.sqlite")},
            "relay": {
                "mode": "agent", "sensor_id": "frigate",
                "url": "https://10.0.0.250:18443/ingest/v1",
                "key": "shared-secret-abcdef",
                "tls_fingerprint": ["sha256:" + "ab" * 32],
            },
        })
        client = RelayClient(acfg.relay, agent, now=lambda: T0)
        seq = 0

        def cycle() -> None:
            """One real collect+advance, then hand the records over."""
            nonlocal seq
            seq += 1
            records, new_wm = client.collect()
            outs = records.get("outages", [])
            if outs:
                recs = V.validate_records({"outages": outs}, 100)
                collector.ingest_remote_batch(
                    "frigate", "inst-aaaa1111", seq, recs, T0 + seq)
            client.state.watermark = new_wm

        wm_of = lambda: client.state.watermark

        cycle()
        cycle()
        got = collector._conn.execute(
            "SELECT up_at FROM remote_outages").fetchone()
        assert got is not None and got["up_at"] is None, got

        with agent._conn:
            agent._conn.execute(
                "UPDATE outages SET up_at = ? WHERE id = 1", (T0 + 100,))
        cycle()

        rows = collector._conn.execute(
            "SELECT camera_ip, down_since, up_at FROM remote_outages"
        ).fetchall()
        assert len(rows) == 1, (
            f"the close inserted a second row instead of updating: "
            f"{[tuple(r) for r in rows]}"
        )
        assert rows[0]["up_at"] == T0 + 100, (
            "the outage close was never relayed; the collector still shows "
            "this camera as down, and would keep showing it forever"
        )

        # And the id drains out of the carry-forward list.
        cycle()
        assert wm_of().open_outage_ids == [], (
            f"a closed outage stayed in the re-send list: "
            f"{wm_of().open_outage_ids}"
        )

        # The watermark must survive a restart with the list intact.
        st = AgentState.load(tmp / "agent-wm")
        st.watermark = Watermark(outage_id=7, open_outage_ids=[3, 4])
        st.save()
        back = AgentState.load(tmp / "agent-wm")
        assert back.watermark.open_outage_ids == [3, 4], (
            f"open outage ids did not survive a restart: "
            f"{back.watermark.open_outage_ids} — the closes would be lost"
        )
        print("  outage close: relayed exactly once, upserts in place, and "
              "the re-send list drains and persists")
    finally:
        agent.close()
        collector.close()


def _check_ingest_does_not_stall_capture(tmp: Path) -> None:
    """Relayed ingest must not freeze the collector's packet loop.

    `ingest.py`'s docstring argues this is prevented by never taking
    `_loop_lock`. That is necessary and NOT sufficient: the watchdog
    tick writes the store while holding `_loop_lock`, and the packet
    loop takes `_loop_lock` per packet — so ingest threads queued on
    the STORE lock stall capture just as effectively. Measured at 32
    concurrent writers it was tens of seconds, long enough for
    tcpdump's pipe to fill: the collector going actually blind on its
    own segment, with no alert, at a remote host's choosing.
    """
    import statistics
    import threading
    import time as _t

    from surveillancehound.store import HoundStore

    store = HoundStore(path=tmp / "stall.sqlite")
    try:
        now = _t.time()
        cap = 5000
        batches = [
            V.validate_records({"flows": [{
                "remote_id": b * cap + i + 1, "src_ip": "10.0.0.1",
                "src_port": 1, "dst_ip": "10.0.0.2", "dst_port": 2,
                "proto": "tcp", "first_seen": now, "last_seen": now,
                "packets": 1, "bytes": 1, "bytes_to_camera": 0,
                "bytes_from_camera": 0, "tcp_flags_seen": "",
                "classification": "lan_normal",
            } for i in range(cap)]}, cap)
            for b in range(8)
        ]

        waits: list[float] = []
        pkt_waits: list[float] = []
        stop = threading.Event()
        from surveillancehound.relay import CaptureGate
        gate = CaptureGate()

        # Measure the REAL thing: a tick holding `_loop_lock` and
        # doing store work, which is exactly what the packet loop
        # queues behind. A synthetic set_heartbeat loop reported ~0.3s
        # while an instrumented tick was blocked 3.3s in the same run —
        # the test was 10x off the quantity it claimed to bound.
        loop_lock = threading.RLock()

        def tick() -> None:
            while not stop.is_set():
                t0 = _t.time()
                with loop_lock:                      # as the watchdog does
                    with gate.capture_priority():
                        store.set_heartbeat(_t.time(), _t.time())
                        store.recent_flows(limit=50)
                        store.list_remote_sensors()
                waits.append(_t.time() - t0)
                _t.sleep(0.02)

        def packet_loop() -> None:
            """What actually goes blind: per-packet _loop_lock."""
            while not stop.is_set():
                t0 = _t.time()
                with loop_lock:
                    pass
                pkt_waits.append(_t.time() - t0)
                _t.sleep(0.001)

        # Go through the REAL IngestServer.handle_batch, so the
        # serialisation under test is the production one. Wrapping a
        # locally-made Semaphore around the store call tested the
        # premise and would have passed with `_write_slot` deleted.
        import ssl as _ssl

        from surveillancehound import relay as _R
        from surveillancehound.ingest import IngestServer

        icfg = _collector_cfg(
            0, max_records_per_batch=cap,
            sensors=[__import__(
                "surveillancehound.config", fromlist=["RelaySensorCfg"]
            ).RelaySensorCfg(id=f"s{i}", key="shared-secret-abcdef")
                for i in range(8)],
        )
        server = IngestServer(icfg, store, now=_t.time, gate=gate)

        peak_concurrent = [0]
        live = [0]
        conc_lock = threading.Lock()
        real_ingest = store.ingest_remote_batch

        def _counting(*a, **kw):
            with conc_lock:
                live[0] += 1
                peak_concurrent[0] = max(peak_concurrent[0], live[0])
            try:
                return real_ingest(*a, **kw)
            finally:
                with conc_lock:
                    live[0] -= 1

        store.ingest_remote_batch = _counting

        def write(i: int) -> None:
            body = _R.build_batch(
                f"s{i}", "inst-aaaa1111", 1,
                {"flows": batches[i]["flows"], "alerts": [], "devices": [],
                 "outages": [], "uptime": [], "monitor": None},
                _t.time())
            status, _ = server.handle_batch(
                "10.0.0.9", body,
                {_R.SENSOR_HEADER: f"s{i}",
                 _R.SIG_HEADER: _R.sign("shared-secret-abcdef", body)})
            assert status == 200, status

        t = threading.Thread(target=tick, daemon=True)
        t.start()
        pl = threading.Thread(target=packet_loop, daemon=True)
        pl.start()
        ws = [threading.Thread(target=write, args=(i,)) for i in range(8)]
        for w in ws:
            w.start()
        for w in ws:
            w.join()
        stop.set()
        _t.sleep(0.1)

        # The LOAD-BEARING assertion: at no point were two relayed
        # writes inside the store at once. A timing threshold alone
        # does not catch a regression here — raising the semaphore to
        # 64 leaves the wall-clock numbers on this fixture unchanged,
        # so only the concurrency invariant actually protects the fix.
        assert peak_concurrent[0] == 1, (
            f"{peak_concurrent[0]} relayed writes were inside the store "
            f"simultaneously. They queue on the store lock, the watchdog "
            f"tick waits on it while holding _loop_lock, and the packet "
            f"loop waits on that — so concurrent ingest is measured in "
            f"seconds of blind capture"
        )

        worst_pkt = max(pkt_waits) if pkt_waits else 0.0
        assert worst_pkt < 1.0, (
            f"the packet loop froze for {worst_pkt:.2f}s waiting on "
            f"_loop_lock behind relayed ingest. tcpdump's pipe fills in "
            f"milliseconds, so this is the collector going blind on its "
            f"own segment because a remote host sent data"
        )

        worst = max(waits)
        assert worst < 2.0, (
            f"a tick waited {worst:.1f}s on the store lock behind relayed "
            f"ingest. The packet loop is behind that wait, and tcpdump's "
            f"pipe fills in milliseconds — this is the collector going "
            f"blind because a remote host sent data"
        )
        # A hostile sensor must not lock out a legitimate one. Bounding
        # CPU by shrinking the CONNECTION pool did exactly that: with
        # four slots, six hostile source addresses took every one and a
        # real sensor got 0 of 20 batches in. The two limits are
        # separate for this reason, and both halves need asserting —
        # fixing the stall by denying service is not a fix.
        from surveillancehound.ingest import (
            _CONN_BUDGET, _CPU_SLOTS, _Server)
        assert _Server.max_workers >= 4 * _CPU_SLOTS, (
            f"the connection pool ({_Server.max_workers}) is too close "
            f"to the CPU limit ({_CPU_SLOTS}); a few hostile sources "
            f"will fill it and legitimate sensors get refused at accept"
        )
        assert _Server.max_per_source < _Server.max_workers, (
            "one source may take the entire connection pool"
        )
        # Counting connections cannot separate a hostile peer from a
        # real one at accept time — reserving for "sources holding
        # none" did nothing, because every attacker connection is from
        # a source holding none. The reserve must key on something an
        # attacker cannot forge: having completed a signed request.
        assert _Server.trusted_reserve >= 2, (
            "no slots are held for sources that have proven a key, so "
            "enough unauthenticated addresses lock out a real sensor"
        )
        assert _Server.trusted_reserve < _Server.max_workers, (
            "the reserve leaves no capacity for a sensor's first batch"
        )
        # Generous on purpose: a full batch takes 12s on a 1 Mbit link
        # and 24s on a bad one, and reaping a real agent's upload over
        # a slow tunnel is a worse failure than a peer holding a
        # thread. The reserve above is what protects a working sensor.
        assert _CONN_BUDGET >= 60, (
            f"a {_CONN_BUDGET:.0f}s connection budget reaps legitimate "
            f"agents on slow links mid-upload"
        )
        assert _CONN_BUDGET > 0, (
            "without an absolute per-connection budget, a peer that "
            "dribbles a byte before each socket timeout holds a slot "
            "for as long as it likes"
        )
        assert _CPU_SLOTS <= 4, (
            f"{_CPU_SLOTS} concurrent batches through the pure-Python "
            f"stages takes the GIL away from the pcap parser; this is "
            f"the number that protects capture"
        )

        # The CPU slot must NOT be held across the body read. Holding
        # it there was a slowloris on the CPU limit: two clients that
        # finish the handshake, declare a large Content-Length and
        # then dribble held both slots for the full socket timeout,
        # and a legitimate sensor got 5 of 10 batches in. Asserted
        # structurally because reproducing it needs real sockets and
        # real time; the shape is what matters.
        import inspect

        from surveillancehound import ingest as _ing
        src_do_post = inspect.getsource(_ing._make_handler)
        body_at = src_do_post.index("self.rfile.read(length)")
        slot_at = src_do_post.index("server._cpu_slot")
        assert body_at < slot_at, (
            "the body is read while holding the CPU slot; a slow "
            "sender then occupies one of two slots for the whole "
            "socket timeout and starves every other sensor"
        )

        # The gate itself, asserted directly. The timing loop above
        # exercises the one-writer slot; at this fixture's load the
        # slot alone keeps contention low, so removing the gate does
        # NOT move those numbers. The gate earns its place at the load
        # a reviewer measured (32 posters, 3-4s freezes), which is too
        # slow and too machine-dependent to assert on here — so its
        # contract is tested on its own rather than claimed to be
        # covered by a timing threshold that cannot see it.
        g = CaptureGate()
        entered = threading.Event()
        released = threading.Event()

        def relayed_side() -> None:
            with g.deferred(timeout=5.0):
                entered.set()

        with g.capture_priority():
            th = threading.Thread(target=relayed_side, daemon=True)
            th.start()
            held = entered.wait(0.4)
            assert not held, (
                "relayed store access proceeded while capture held "
                "priority; the tick holds _loop_lock for its whole "
                "duration, so this is the packet loop waiting"
            )
            released.set()
        assert entered.wait(5.0), (
            "relayed access never resumed after capture released "
            "priority — the gate must defer relayed work, not starve it"
        )
        th.join(timeout=5.0)

        # A wedged tick must degrade to "relay is slow", never "relay
        # is dead": the wait is bounded.
        g2 = CaptureGate()
        with g2.capture_priority():
            t0 = _t.time()
            with g2.deferred(timeout=0.2):
                pass
            assert _t.time() - t0 < 2.0, "deferred() did not time out"

        print(f"  capture gate: relayed access defers to the tick and "
              f"resumes, with a bounded wait")
        print(f"  capture coupling: {peak_concurrent[0]} concurrent store "
              f"user(s); worst packet-loop freeze {worst_pkt:.3f}s, worst "
              f"tick {worst:.2f}s, median {statistics.median(waits):.3f}s")
    finally:
        store.close()


def main() -> int:
    import tempfile
    print("=== relay validation ===")
    _check_json_constants()
    _check_scalars()
    _check_records()
    _check_notification_hardening()
    _check_dashboard_numeric_escaping()
    _check_relay_config()
    _check_parse_amplification_bounded()
    _check_capture_exclusion()
    _check_key_never_printed()
    print("=== quarantine ===")
    _check_authorizer_actually_catches()
    with tempfile.TemporaryDirectory() as td:
        _check_remote_store(Path(td))
        _check_quarantine(Path(td))
        _check_resource_bounds(Path(td))
        _check_instance_reset(Path(td))
        _check_prerelease_schema_upgrade(Path(td))
        _check_outage_close_is_relayed(Path(td))
        _check_ingest_does_not_stall_capture(Path(td))
        _check_relayed_dispatch_is_quarantined(Path(td))
        _check_sensor_offline_alerts(Path(td))
        _check_relayed_api_surface(Path(td))
        _check_replay_opens_no_listener(Path(td))
        _check_spool_counters(Path(td))
        _check_agent_state(Path(td))
        _check_shutdown_and_slot_release(Path(td))
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
