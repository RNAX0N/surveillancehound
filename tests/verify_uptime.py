"""End-to-end verification of passive uptime monitoring.

Four sections, all driven by an explicit synthetic clock — never
`time.time()`, so the assertions are deterministic and a slow machine
cannot flake them:

  (1) **store**    — outage + monitor-session lifecycle, the last_seen
                     touch path, and the span-merge math behind availability.
  (2) **config**   — the [uptime] section and the grace-inherits-silence rule.
  (3) **tracker**  — the seven liveness scenarios, including the two
                     regressions this feature exists to fix: a continuously
                     streaming camera must never trip offline, and a camera
                     that was down before the daemon started must still alert.
  (4) **alerts**   — the three new kinds and outage-scoped dedup.

Run: PYTHONPATH=src:tests python tests/verify_uptime.py
"""

from __future__ import annotations

import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from surveillancehound.alerts import AlertEngine  # noqa: E402
from surveillancehound.config import (  # noqa: E402
    AlertsCfg, NetworkCfg, ThresholdCfg, UptimeCfg, load_from_dict,
)
from surveillancehound.pcap import Packet  # noqa: E402
from surveillancehound.store import (  # noqa: E402
    AlertRow, HoundStore, OutageRow,
)
from surveillancehound.uptime import Transition, UptimeTracker  # noqa: E402

T0 = 1_760_000_000.0   # fixed epoch — no wall-clock dependence anywhere

CAM = "10.9.0.5"
CAM2 = "10.9.0.6"
NEVER = "10.9.0.9"


def _store(tmp: Path, name: str) -> HoundStore:
    return HoundStore(path=tmp / name)


# --------------------------------------------------------------------------
# (1) store
# --------------------------------------------------------------------------

def _check_store(tmp: Path) -> None:
    print("=== store ===")
    store = _store(tmp, "store.sqlite")
    try:
        # seed_device marks a configured-but-unobserved camera with
        # last_seen = 0.0, and never overwrites an existing row
        assert store.seed_device(CAM, "camera", T0) is True
        assert store.seed_device(CAM, "camera", T0) is False
        assert store.get_device(CAM).last_seen == 0.0
        print("  seed_device: inserts once, last_seen=0.0 marker")

        # touch_devices_last_seen moves last_seen ONLY
        store.upsert_device(CAM2, "camera", T0, 10, 100)
        store.touch_devices_last_seen({CAM2: T0 + 50})
        d = store.get_device(CAM2)
        assert d.last_seen == T0 + 50, d.last_seen
        assert d.packet_count == 10, d.packet_count
        assert d.role == "camera", d.role
        # ...and never backwards
        store.touch_devices_last_seen({CAM2: T0 + 10})
        assert store.get_device(CAM2).last_seen == T0 + 50
        print("  touch_devices_last_seen: last_seen only, monotonic")

        # outage lifecycle
        oid = store.open_outage(
            OutageRow(None, CAM, T0, None, 0.0, "never_seen", None),
        )
        assert store.open_outage_for(CAM).id == oid
        assert [o.id for o in store.open_outages()] == [oid]
        store.set_outage_alert(oid, 42)
        store.close_outage(oid, T0 + 100)
        assert store.open_outage_for(CAM) is None
        closed = store.list_outages(CAM)[0]
        assert closed.up_at == T0 + 100 and closed.alert_id == 42
        assert closed.duration(T0 + 500) == 100.0, closed.duration(T0 + 500)
        print("  outages: open -> close, duration, alert linkage")

        # monitor sessions: an open session is clipped to `until`
        sid = store.start_monitor_session(T0, "eth0")
        assert store.monitored_spans(T0 - 10, T0 + 60) == [(T0, T0 + 60)]
        store.end_monitor_session(sid, T0 + 30, True)
        assert store.monitored_spans(T0 - 10, T0 + 60) == [(T0, T0 + 30)]
        assert store.current_monitor_session().clean_exit is True
        print("  monitor_sessions: open clipped to now, close recorded")

        # two sessions with a gap stay disjoint; overlapping ones merge
        sid2 = store.start_monitor_session(T0 + 60, "eth0")
        store.end_monitor_session(sid2, T0 + 90, True)
        assert store.monitored_spans(T0, T0 + 120) == [
            (T0, T0 + 30), (T0 + 60, T0 + 90),
        ]
        print("  monitored_spans: disjoint sessions preserved")

        # latest_device_activity tracks the tick-refreshed device clock, not
        # the flows table. Flow rows are only written at eviction —
        # flow_ttl_seconds after the fact — so any freshness check built on
        # them reads as permanently stalled.
        assert store.latest_device_activity() == T0 + 50, (
            store.latest_device_activity()
        )
        print("  latest_device_activity: tracks the tick-refreshed clock")

        # an orphaned session (SIGKILL / power loss) must not be counted as
        # monitored forever — that reports 100% availability for time
        # nothing was watching
        store.start_monitor_session(T0 + 100, "eth0")
        # while it looks open, it reads as monitored right up to `until`
        assert store.monitored_spans(T0 + 100, T0 + 9999)[-1][1] == T0 + 9999
        store.start_monitor_session(T0 + 5000, "eth0")   # next daemon start
        monitored = sum(
            b - a for a, b in store.monitored_spans(T0 + 100, T0 + 5000)
        )
        assert monitored == 0.0, (
            f"orphaned session still counted as monitored: {monitored}s"
        )
        print("  orphaned session: closed on next start, blind time excluded")

        # prune never deletes an OPEN outage or a RUNNING session
        live = store.open_outage(OutageRow(None, CAM2, T0, None, 0.0, "silence", None))
        store.start_monitor_session(T0, "eth0")
        deleted = store.prune(
            outages_older_than=T0 + 10_000, sessions_older_than=T0 + 10_000,
        )
        assert deleted["outages"] == 1, deleted
        # 4: the two early sessions, the orphan closed above, and the one
        # that closed it — only the still-running newest survives
        assert deleted["monitor_sessions"] == 4, deleted
        assert store.open_outage_for(CAM2).id == live
        print("  prune: closed/ended only, live state preserved")
    finally:
        store.close()


# --------------------------------------------------------------------------
# (2) config
# --------------------------------------------------------------------------

def _check_config() -> None:
    print("=== config ===")
    cfg = load_from_dict({
        "capture": {"pcap_file": "x.pcap"},
        "network": {"camera_ips": [CAM]},
        "uptime": {"startup_grace_seconds": 0, "capture_stall_seconds": 45},
    })
    assert cfg.uptime.enabled is True
    assert cfg.uptime.capture_stall_seconds == 45.0
    assert cfg.uptime.recovery_alerts is True
    assert cfg.uptime.report_window_seconds == 86400.0
    # grace of 0 inherits the silence threshold so there is one knob to tune
    assert cfg.uptime.grace_for(cfg.thresholds) == cfg.thresholds.silence_seconds
    # an explicit grace wins
    assert UptimeCfg(startup_grace_seconds=30.0).grace_for(ThresholdCfg()) == 30.0
    print("  [uptime] parsed; grace=0 inherits thresholds.silence_seconds")


# --------------------------------------------------------------------------
# (3) tracker
# --------------------------------------------------------------------------

SILENCE = 60.0
GRACE = 30.0
STALL = 20.0
TICK = 5.0


def _tracker() -> UptimeTracker:
    return UptimeTracker(
        UptimeCfg(
            startup_grace_seconds=GRACE, capture_stall_seconds=STALL,
        ),
        ThresholdCfg(silence_seconds=SILENCE),
        replay=False,
    )


def _kinds(trs: list[Transition]) -> list[str]:
    return [t.kind for t in trs]


def _check_streaming_camera_never_trips(tmp: Path) -> None:
    """Gap-2 regression: the bug this whole feature exists to fix.

    A camera holding one continuous RTSP stream used to never refresh
    devices.last_seen (the flow never went idle, so it never flushed) and
    tripped camera_offline while actively streaming.
    """
    store = _store(tmp, "stream.sqlite")
    try:
        tr = _tracker()
        store.start_monitor_session(T0, "eth0")
        tr.bootstrap(store, NetworkCfg(camera_ips=[CAM]), T0)
        seen: list[str] = []
        for i in range(1, 41):          # 200s of continuous streaming
            t = T0 + i * TICK
            tr.touch(CAM, t)
            seen += _kinds(tr.tick(store, t, saw_packets=True))
        assert seen == [], f"streaming camera tripped: {seen}"
        assert store.get_device(CAM).last_seen == T0 + 200.0
        print("  streaming camera: 200s continuous, zero transitions")
    finally:
        store.close()


def _check_silence_and_recovery(tmp: Path) -> int:
    store = _store(tmp, "silence.sqlite")
    try:
        tr = _tracker()
        store.start_monitor_session(T0, "eth0")
        tr.bootstrap(store, NetworkCfg(camera_ips=[CAM]), T0)
        tr.touch(CAM, T0)
        tr.tick(store, T0, saw_packets=True)

        kinds: list[str] = []
        for i in range(1, 30):          # 145s of camera silence
            t = T0 + i * TICK
            # the sensor itself is healthy — other hosts on the segment are
            # still talking, which is what makes the camera's silence its
            # own fault rather than ours
            tr.observe_packet(t)
            kinds += _kinds(tr.tick(store, t, saw_packets=True))
        assert kinds.count("down") == 1, f"expected one down, got {kinds}"
        out = store.open_outage_for(CAM)
        assert out is not None and out.cause == "silence"
        assert out.last_seen_before == T0, out.last_seen_before
        print("  silent camera: exactly one 'down', one open outage")

        t_back = T0 + 200.0
        tr.touch(CAM, t_back)
        ups = [t for t in tr.tick(store, t_back, saw_packets=True) if t.kind == "up"]
        assert len(ups) == 1, f"expected one up, got {ups}"
        assert ups[0].duration > 0 and ups[0].outage_id == out.id
        assert store.open_outage_for(CAM) is None
        print(f"  recovery: one 'up', outage closed after {ups[0].duration:.0f}s")

        # flap: a second outage must be a DISTINCT row, so it gets its own
        # dedup key and is not silently swallowed by the 1800s window
        kinds = []
        for i in range(1, 30):
            t = t_back + i * TICK
            tr.observe_packet(t)
            kinds += _kinds(tr.tick(store, t, saw_packets=True))
        assert kinds.count("down") == 1, kinds
        ids = {o.id for o in store.list_outages(CAM)}
        assert len(ids) == 2, f"flap did not create a second outage: {ids}"
        print("  flap down->up->down: two distinct outages")
        return len(store.list_outages(CAM))
    finally:
        store.close()


def _check_never_seen(tmp: Path) -> None:
    store = _store(tmp, "never.sqlite")
    try:
        tr = _tracker()
        store.start_monitor_session(T0, "eth0")
        tr.bootstrap(store, NetworkCfg(camera_ips=[NEVER]), T0)
        # before the grace elapses: silence is expected, not alertable
        tr.observe_packet(T0 + 10)
        assert _kinds(tr.tick(store, T0 + 10, saw_packets=True)) == []
        tr.observe_packet(T0 + GRACE + 1)
        assert _kinds(tr.tick(store, T0 + GRACE + 1, saw_packets=True)) == ["never_seen"]
        # and only once
        tr.observe_packet(T0 + 120)
        assert _kinds(tr.tick(store, T0 + 120, saw_packets=True)) == []
        out = store.open_outage_for(NEVER)
        assert out is not None and out.cause == "never_seen"
        assert out.last_seen_before == 0.0
        print("  never-seen camera: fires once after grace, outage opened")

        # it still recovers correctly when the camera finally appears
        tr.touch(NEVER, T0 + 200)
        ups = [t for t in tr.tick(store, T0 + 200, saw_packets=True) if t.kind == "up"]
        assert len(ups) == 1, ups
        assert store.open_outage_for(NEVER) is None
        print("  never-seen camera: recovers when it finally shows up")
    finally:
        store.close()


def _check_stall_suppression(tmp: Path) -> None:
    """The dead-man's-switch: a blind sensor must not blame the cameras."""
    store = _store(tmp, "stall.sqlite")
    try:
        tr = _tracker()
        store.start_monitor_session(T0, "eth0")
        tr.bootstrap(store, NetworkCfg(camera_ips=[CAM, CAM2]), T0)
        tr.touch(CAM, T0)
        tr.touch(CAM2, T0)
        tr.tick(store, T0, saw_packets=True)

        kinds: list[str] = []
        for i in range(1, 30):          # 145s with no packets at all
            kinds += _kinds(tr.tick(store, T0 + i * TICK, saw_packets=False))
        assert kinds.count("stalled") == 1, f"expected one stall, got {kinds}"
        assert "down" not in kinds, f"stall did not suppress per-camera down: {kinds}"
        assert tr.stalled is True
        assert store.open_outage_for(CAM) is None, "outage opened during a stall"
        print("  capture stall: one 'stalled', per-camera 'down' suppressed")

        # when packets return, the stall clears and normal detection resumes
        t = T0 + 200
        tr.touch(CAM, t)
        cleared = _kinds(tr.tick(store, t, saw_packets=True))
        assert "stall_cleared" in cleared, cleared
        assert tr.stalled is False
        # both cameras now go quiet from the recovery point, and BOTH are
        # reported — the suppression is scoped to the blind window, not
        # permanent
        kinds = []
        for i in range(1, 30):
            tt = t + i * TICK
            tr.observe_packet(tt)
            kinds += _kinds(tr.tick(store, tt, saw_packets=True))
        assert kinds.count("down") == 2, f"detection did not resume: {kinds}"
        # neither is charged for the blind window: the silence clock
        # restarted when visibility came back
        for ip in (CAM, CAM2):
            assert store.open_outage_for(ip).down_since >= t, ip
        print("  stall cleared: detection resumes, blind window not charged")
    finally:
        store.close()


def _check_no_blame_without_evidence(tmp: Path) -> None:
    """A camera is not blamed when the sensor has seen nothing since.

    The failure this guards against: an operator sets capture_stall_seconds
    higher than silence_seconds, every camera trips before the stall is ever
    declared, and the alert storm the dead-man's-switch exists to prevent
    happens anyway.
    """
    store = _store(tmp, "evidence.sqlite")
    try:
        tr = UptimeTracker(
            # stall threshold deliberately LONGER than the silence threshold
            UptimeCfg(startup_grace_seconds=GRACE, capture_stall_seconds=600.0),
            ThresholdCfg(silence_seconds=SILENCE),
            replay=False,
        )
        store.start_monitor_session(T0, "eth0")
        tr.bootstrap(store, NetworkCfg(camera_ips=[CAM]), T0)
        tr.touch(CAM, T0)

        # nothing at all observed after T0: no down, despite silence_seconds
        # being long past, because we cannot tell the camera from ourselves
        kinds: list[str] = []
        for i in range(1, 40):
            kinds += _kinds(tr.tick(store, T0 + i * TICK, saw_packets=False))
        assert "down" not in kinds, f"blamed a camera with no evidence: {kinds}"
        assert store.open_outage_for(CAM) is None
        print("  no-blame rule: silent camera + blind sensor -> no camera_offline")

        # the moment other traffic proves the sensor can still see, the
        # camera's silence becomes its own fault and is reported
        t = T0 + 300
        tr.observe_packet(t)
        kinds = _kinds(tr.tick(store, t, saw_packets=True))
        assert kinds.count("down") == 1, f"expected one down, got {kinds}"
        print("  no-blame rule: other traffic seen -> camera_offline fires")
    finally:
        store.close()


def _check_restart_resumes_outage(tmp: Path) -> None:
    store = _store(tmp, "restart.sqlite")
    try:
        tr = _tracker()
        store.start_monitor_session(T0, "eth0")
        net = NetworkCfg(camera_ips=[CAM])
        tr.bootstrap(store, net, T0)
        tr.touch(CAM, T0)
        for i in range(1, 30):
            t = T0 + i * TICK
            tr.observe_packet(t)
            tr.tick(store, t, saw_packets=True)
        before = len(store.list_outages(CAM))
        assert before == 1 and store.open_outage_for(CAM) is not None

        # a fresh process picks the open outage back up instead of
        # re-firing it or double-opening — the no-re-alert-on-restart rule
        tr2 = _tracker()
        tr2.bootstrap(store, net, T0 + 200)
        tr2.observe_packet(T0 + 205)
        assert tr2.tick(store, T0 + 205, saw_packets=True) == []
        assert len(store.list_outages(CAM)) == before
        assert store.open_outage_for(CAM) is not None
        print("  restart mid-outage: resumed, no duplicate, no re-alert")
    finally:
        store.close()


def _check_restart_does_not_fake_recovery(tmp: Path) -> None:
    """A dead camera must not be resurrected by flow-eviction bookkeeping.

    `_check_restart_resumes_outage` drives the tracker directly and so never
    exercises the flow path. This one does: a flow is evicted
    flow_ttl_seconds AFTER its last packet, and the device row is stamped
    then. If that stamp uses the processing time instead of the packet time,
    `devices.last_seen` lands later than the outage's `down_since`, and the
    next restart reads it back as "activity after the outage started" —
    closing the outage and telling the operator a dead camera came back.
    """
    store = _store(tmp, "fake_recovery.sqlite")
    try:
        net = NetworkCfg(camera_ips=[CAM])
        store.start_monitor_session(T0, "eth0")

        # the camera's last real packet is at T0; its flow is evicted 300s
        # later and the device row is written at that point
        store.upsert_device(CAM, "camera", T0, 50, 5000)
        assert store.get_device(CAM).last_seen == T0, store.get_device(CAM).last_seen

        # it then goes quiet and an outage opens with the true down_since
        tr = _tracker()
        tr.bootstrap(store, net, T0)
        tr.touch(CAM, T0)
        for i in range(1, 30):
            t = T0 + i * TICK
            tr.observe_packet(t)
            tr.tick(store, t, saw_packets=True)
        outage = store.open_outage_for(CAM)
        assert outage is not None, "no outage opened"

        # a late flush of an older flow must not drag last_seen forward
        store.upsert_device(CAM, "camera", T0 - 100, 10, 100)
        assert store.get_device(CAM).last_seen == T0, (
            "an older flow moved last_seen forward"
        )

        # Now the hostile case the original bug produced: something stamps
        # the device row AFTER the outage began (the old code did exactly
        # this, using the eviction tick instead of the packet time).
        store.touch_devices_last_seen({CAM: outage.down_since + 200})
        assert store.get_device(CAM).last_seen > outage.down_since

        # restart: the camera is still dead, so nothing should recover
        tr2 = _tracker()
        tr2.bootstrap(store, net, T0 + 400)
        trs = tr2.tick(store, T0 + 405, saw_packets=True)
        assert [t.kind for t in trs] == [], f"faked a recovery: {trs}"
        assert store.open_outage_for(CAM) is not None, (
            "the outage was closed for a camera that never came back"
        )
        print("  restart: a still-dead camera is not reported as recovered, "
              "even when its device row claims later activity")
    finally:
        store.close()


def _check_availability(tmp: Path) -> None:
    store = _store(tmp, "avail.sqlite")
    try:
        now = T0 + 3600.0
        # monitored for the whole hour
        sid = store.start_monitor_session(T0, "eth0")
        store.end_monitor_session(sid, now, True)
        # CAM: one 360s outage inside the window -> 90% available
        store.upsert_device(CAM, "camera", T0, 1, 1)
        oid = store.open_outage(OutageRow(None, CAM, T0 + 600, None, T0, "silence", None))
        store.close_outage(oid, T0 + 960)
        # CAM2: observed, no outages -> 100%
        store.upsert_device(CAM2, "camera", T0, 1, 1)

        rows = {r.ip: r for r in store.uptime_report(3600.0, now)}
        assert abs(rows[CAM].availability - 0.90) < 0.001, rows[CAM].availability
        assert abs(rows[CAM].downtime_seconds - 360.0) < 0.001
        assert rows[CAM].state == "up", rows[CAM].state
        assert rows[CAM2].availability == 1.0
        print(f"  availability: {rows[CAM].availability:.2%} for a 360s/1h outage")

        # an outage that straddles a monitoring gap is only charged for the
        # monitored part — otherwise a stopped daemon reads as camera downtime
        store2 = _store(tmp, "avail2.sqlite")
        try:
            s1 = store2.start_monitor_session(T0, "eth0")
            store2.end_monitor_session(s1, T0 + 1800, True)   # down for 30 min
            s2 = store2.start_monitor_session(T0 + 3600, "eth0")
            store2.end_monitor_session(s2, T0 + 5400, True)
            store2.upsert_device(CAM, "camera", T0, 1, 1)
            o = store2.open_outage(
                OutageRow(None, CAM, T0 + 900, None, T0, "silence", None),
            )
            store2.close_outage(o, T0 + 4500)   # 3600s wall, 1800s monitored
            r = {x.ip: x for x in store2.uptime_report(5400.0, T0 + 5400)}[CAM]
            assert abs(r.monitored_seconds - 3600.0) < 0.001, r.monitored_seconds
            assert abs(r.downtime_seconds - 1800.0) < 0.001, r.downtime_seconds
            assert abs(r.availability - 0.5) < 0.001, r.availability
            print("  availability: unmonitored time excluded, not charged")
        finally:
            store2.close()

        # zero monitored time -> None, rendered as n/a. Never a fake 0%/100%.
        store3 = _store(tmp, "avail3.sqlite")
        try:
            store3.upsert_device(CAM, "camera", T0, 1, 1)
            r = {x.ip: x for x in store3.uptime_report(3600.0, now)}[CAM]
            assert r.availability is None, r.availability
            assert r.monitored_seconds == 0.0
            print("  availability: None when never monitored (renders n/a)")
        finally:
            store3.close()
    finally:
        store.close()


def _check_never_seen_state_in_report(tmp: Path) -> None:
    store = _store(tmp, "report_state.sqlite")
    try:
        now = T0 + 3600.0
        sid = store.start_monitor_session(T0, "eth0")
        store.end_monitor_session(sid, now, True)
        store.seed_device(NEVER, "camera", T0)
        r = {x.ip: x for x in store.uptime_report(3600.0, now)}[NEVER]
        assert r.state == "never_seen", r.state
        assert r.last_seen == 0.0
        print("  report: configured-but-unobserved camera shows 'never_seen'")
    finally:
        store.close()


# --------------------------------------------------------------------------
# (4) alerts
# --------------------------------------------------------------------------

def _check_alerts(tmp: Path) -> None:
    print("=== alerts ===")
    store = _store(tmp, "alerts.sqlite")
    try:
        eng = AlertEngine(cfg=AlertsCfg(dedup_window_seconds=1800.0), store=store)

        def emit(a) -> int:
            """Mirror daemon._emit so dedup (which reads the store) applies."""
            return store.insert_alert(AlertRow(
                id=None, ts=a.ts, device_ip=a.device_ip, kind=a.kind,
                severity=a.severity, summary=a.summary, detail=a.detail,
                dedup_key=a.dedup_key,
            ))

        down = Transition("down", CAM, since=T0, duration=120.0,
                          outage_id=7, last_seen_before=T0)
        a = eng.from_transition(down, T0)
        assert a.kind == "camera_offline" and a.severity == "medium"
        assert a.dedup_key == f"camera_offline:{CAM}:7", a.dedup_key
        assert "inferred" in a.detail.lower(), a.detail
        emit(a)
        # same outage ticking again inside the window -> suppressed
        assert eng.from_transition(down, T0 + 30) is None
        # a DISTINCT outage is not suppressed — the missed-alert bug
        down2 = Transition("down", CAM, since=T0 + 10, duration=120.0,
                           outage_id=8, last_seen_before=T0)
        a2 = eng.from_transition(down2, T0 + 20)
        assert a2 is not None and a2.dedup_key == f"camera_offline:{CAM}:8"
        print("  camera_offline: outage-scoped dedup, flap not swallowed")

        up = Transition("up", CAM, since=T0, duration=200.0,
                        outage_id=7, last_seen_before=T0)
        ar = eng.from_transition(up, T0 + 200)
        assert ar.kind == "camera_recovered" and ar.severity == "info"
        assert ar.dedup_key == f"camera_recovered:{CAM}:7"
        print("  camera_recovered: info severity, outage-scoped")

        # a never-seen camera showing up has not "come back"
        first = Transition("up", NEVER, since=T0, duration=90.0,
                           outage_id=11, last_seen_before=0.0,
                           cause="never_seen")
        af = eng.from_transition(first, T0 + 90)
        assert "first time" in af.summary, af.summary
        assert "is back" not in af.summary, af.summary
        print("  camera_recovered: first sighting worded as such, not 'back'")

        ns = Transition("never_seen", NEVER, since=T0, duration=30.0,
                        outage_id=3, last_seen_before=0.0)
        an = eng.from_transition(ns, T0 + 30)
        assert an.kind == "camera_never_seen" and an.severity == "medium"
        assert an.dedup_key == f"camera_never_seen:{NEVER}"
        print("  camera_never_seen: medium severity")

        st = Transition("stalled", "", since=T0, duration=300.0,
                        outage_id=None, last_seen_before=0.0)
        as_ = eng.from_transition(st, T0 + 300)
        assert as_.kind == "capture_stalled" and as_.severity == "high"
        assert "suppress" in as_.detail.lower(), as_.detail
        print("  capture_stalled: high severity, explains suppression")

        cleared = Transition("stall_cleared", "", since=T0, duration=0.0,
                             outage_id=None, last_seen_before=0.0)
        assert eng.from_transition(cleared, T0) is None
        print("  stall_cleared: logged, never alerted")

        # recovery_alerts = false silences only the recovery
        eng2 = AlertEngine(cfg=AlertsCfg(), store=store, recovery_alerts=False)
        assert eng2.from_transition(up, T0 + 400) is None
        assert eng2.from_transition(down2, T0 + 400) is not None
        print("  recovery_alerts=false: suppresses recovery only")
    finally:
        store.close()


# --------------------------------------------------------------------------
# (5) the watchdog, at the daemon level
# --------------------------------------------------------------------------

def _check_watchdog_fires_when_capture_wedges(tmp: Path) -> None:
    """The dead-man's-switch, exercised through a real Hound instance.

    This is the scenario the watchdog thread exists for and the one a unit
    test of the tracker cannot reach: the capture generator blocks forever
    (tcpdump alive but delivering nothing, NIC down, mirror port pulled).
    A tick driven from inside `for pkt in packets` would never run here, so
    `capture_stalled` would never fire and the daemon would sit silently
    blind — which is the single worst failure mode for a monitor.
    """
    from surveillancehound import daemon as daemon_mod

    wedge = threading.Event()

    class _Handle:
        def close(self) -> None:
            wedge.set()

    def _fake_stream(cfg, *, keep_raw=False, snaplen_override=None):
        def _gen():
            # one real packet so the session starts and a camera is known,
            # then block exactly like a wedged capture
            yield Packet(
                ts=time.time(), src_ip=CAM, dst_ip="10.9.0.1",
                src_port=554, dst_port=51000, proto="tcp",
                length=800, tcp_flags="PA", raw_record=b"",
            )
            wedge.wait(timeout=30)
        return _gen(), None, _Handle()

    orig_stream = daemon_mod.stream_packets
    orig_tick = daemon_mod._TICK_S
    daemon_mod.stream_packets = _fake_stream
    daemon_mod._TICK_S = 0.2        # keep the test fast
    try:
        cfg = load_from_dict({
            "capture": {"interface": "test0"},
            "network": {"camera_ips": [CAM]},
            "store": {"path": str(tmp / "watchdog.sqlite")},
            "thresholds": {"silence_seconds": 0.6},
            "uptime": {
                "capture_stall_seconds": 0.5, "startup_grace_seconds": 30.0,
            },
            "notify": [{"type": "stdout", "level": "critical"}],
        })
        hound = daemon_mod.Hound(cfg)
        runner = threading.Thread(target=hound.run, daemon=True)
        runner.start()

        deadline = time.time() + 15.0
        store = _store(tmp, "watchdog.sqlite")
        try:
            kinds: set[str] = set()
            while time.time() < deadline:
                kinds = {a.kind for a in store.list_alerts(limit=50)}
                if "capture_stalled" in kinds:
                    break
                time.sleep(0.2)
            assert "capture_stalled" in kinds, (
                f"watchdog never fired while the capture was wedged: {kinds}"
            )
            # and the storm is suppressed: no per-camera offline alert even
            # though silence_seconds (0.6s) elapsed long ago
            assert "camera_offline" not in kinds, (
                f"stall did not suppress per-camera offline alerts: {kinds}"
            )
            print("  watchdog: capture_stalled fired on a wedged capture, "
                  "per-camera offline suppressed")

            # the blind window must be carved out of monitored time, or a
            # wedged sensor reports as perfect camera uptime
            sessions = store.monitored_spans(0.0, time.time())
            assert sessions, "no monitored span recorded"
            assert store.current_monitor_session().ended_at is not None, (
                "the stalled session was not closed, so blind time would "
                "still count as monitored"
            )
            print("  watchdog: monitor session closed at the stall, blind "
                  "time excluded from availability")
        finally:
            store.close()
        hound.stop()
        wedge.set()
        runner.join(timeout=10)
    finally:
        daemon_mod.stream_packets = orig_stream
        daemon_mod._TICK_S = orig_tick


def _check_capture_death_is_reported(tmp: Path) -> None:
    """tcpdump exiting must not look like a clean shutdown.

    When the capture process dies its stdout closes and the generator simply
    ends. Reporting that as a clean run means the supervisor sees no reason
    to relaunch and nobody is told the monitor went blind — the quietest
    possible failure for a security sensor.
    """
    from surveillancehound import daemon as daemon_mod

    class _DeadHandle:
        def close(self) -> None:
            pass

        def is_alive(self) -> bool:
            return False

    def _fake_stream(cfg, *, keep_raw=False, snaplen_override=None):
        def _gen():
            yield Packet(
                ts=time.time(), src_ip=CAM, dst_ip="10.9.0.1",
                src_port=554, dst_port=51000, proto="tcp",
                length=800, tcp_flags="PA", raw_record=b"",
            )
            return  # tcpdump exited: stdout closed, generator ends
        return _gen(), None, _DeadHandle()

    orig = daemon_mod.stream_packets
    daemon_mod.stream_packets = _fake_stream
    try:
        cfg = load_from_dict({
            "capture": {"interface": "test0"},
            "network": {"camera_ips": [CAM]},
            "store": {"path": str(tmp / "death.sqlite")},
            "notify": [{"type": "stdout", "level": "critical"}],
        })
        hound = daemon_mod.Hound(cfg)
        ok = hound.run()
        assert ok is False, "a dead capture reported a clean run"

        store = _store(tmp, "death.sqlite")
        try:
            kinds = {a.kind for a in store.list_alerts(limit=50)}
            assert "capture_stalled" in kinds, (
                f"capture death was not announced to the operator: {kinds}"
            )
            session = store.current_monitor_session()
            assert session.ended_at is not None, "session left open"
        finally:
            store.close()
        print("  capture death: run() returns False and capture_stalled fires")
    finally:
        daemon_mod.stream_packets = orig


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        _check_store(tmp)
        _check_config()
        print("=== tracker ===")
        _check_streaming_camera_never_trips(tmp)
        _check_silence_and_recovery(tmp)
        _check_never_seen(tmp)
        _check_stall_suppression(tmp)
        _check_no_blame_without_evidence(tmp)
        _check_restart_resumes_outage(tmp)
        _check_restart_does_not_fake_recovery(tmp)
        _check_availability(tmp)
        _check_never_seen_state_in_report(tmp)
        _check_alerts(tmp)
        print("=== watchdog (daemon-level) ===")
        _check_watchdog_fires_when_capture_wedges(tmp)
        _check_capture_death_is_reported(tmp)
    print("\nUPTIME VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
