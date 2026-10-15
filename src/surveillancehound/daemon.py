"""The always-running event loop.

Pulls packets from `capture.stream_packets`, feeds them to the flow aggregator
and the device classifier, periodically (every TICK seconds) flushes idle
flows + advances the uptime state machine, classifies each flushed flow,
emits + dedups alerts, and dispatches notifications through every configured
channel.

**Two tick drivers, deliberately.** Live capture ticks from a watchdog
thread; replay ticks inline from the packet loop. The reason is the capture
dead-man's-switch: a tick driven from inside `for pkt in packets` cannot fire
when the capture is dead, which is exactly when it needs to. The watchdog
thread keeps ticking while the packet loop is blocked on a read that will
never return, so `capture_stalled` can actually fire. Replay has no such
failure mode and benefits from determinism, so it ticks inline off packet
timestamps.

Because of that thread, `_LOOP_LOCK` guards everything mutable the tick and
the packet path share — `FlowAggregator`, `DeviceClassifier`,
`UptimeTracker`, and the snapshot ring buffer are all single-threaded by
design (`HoundStore` serializes itself, the rest do not).

**Clock.** Live capture uses wall clock; replay uses the maximum packet
timestamp seen so far. Replaying a capture recorded months ago must not
report every camera as offline, and a forensic replay should report cameras
that went silent *inside* the capture.

Graceful shutdown on SIGINT / SIGTERM: a flag is flipped, the current packet
batch finishes, all remaining flows are flushed (so nothing in-RAM is lost),
the capture handle is closed, the store is closed. A failed live capture
(tcpdump dies, NIC goes down) is restarted by the outer supervisor — this
module signals failure by returning False.

The architectural separation here is deliberate: pure aggregation (flows) has
no knowledge of cameras; pure classification (classify) has no knowledge of
the loop; pure dispatch (notify) has no knowledge of either. The daemon is the
only place that sees all three.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

from surveillancehound.alerts import Alert, AlertEngine
from surveillancehound.baseline import BaselineEngine, HSEngine, make_engine
from surveillancehound.capture import CaptureError, stream_packets
from surveillancehound.classify import FlowClassifier
from surveillancehound.config import HoundCfg
from surveillancehound.discover import DeviceClassifier
from surveillancehound.flows import FlowAggregator, LiveFlow
from surveillancehound.notify import Dispatcher, build_channel
from surveillancehound.pcap import Packet
from surveillancehound.snapshot import SnapshotEngine, snapshot_dir_for
from surveillancehound.store import AlertRow, FlowRow, HoundStore, SnapshotRow
from surveillancehound.uptime import Transition, UptimeTracker

log = logging.getLogger(__name__)

# how often (seconds) to evict idle flows + check for silent cameras
_TICK_S = 5.0


@dataclass
class RunStats:
    packets_seen: int = 0
    flows_flushed: int = 0
    alerts_emitted: int = 0
    uptime_transitions: int = 0
    started_at: float = 0.0
    stopped_at: float | None = None


class Hound:
    """Owns the daemon's lifecycle. One instance per process."""

    def __init__(self, cfg: HoundCfg) -> None:
        self.cfg = cfg
        self.store = HoundStore(path=cfg.store.path)
        self.devices = DeviceClassifier(network=cfg.network)
        self.flows = FlowAggregator()
        self.classifier = FlowClassifier(
            network=cfg.network, thresholds=cfg.thresholds, devices=self.devices,
        )
        self.alerts = AlertEngine(
            cfg=cfg.alerts, store=self.store,
            recovery_alerts=cfg.uptime.recovery_alerts,
        )
        self.dispatcher = Dispatcher(
            [build_channel(c) for c in cfg.notify], store=self.store,
        )
        self.baseliner: BaselineEngine | HSEngine | None = None
        if cfg.baseline.enabled:
            self.baseliner = make_engine(cfg.baseline)
            self.baseliner.bootstrap_from(self.store)
            if cfg.baseline.model == "hstree":
                log.info(
                    "baseline: hstree enabled (trees=%d, depth=%d, window=%d, "
                    "score≥%g, min_samples=%d, flush=%gs)",
                    cfg.baseline.hstree_n_trees, cfg.baseline.hstree_depth,
                    cfg.baseline.hstree_window_size,
                    cfg.baseline.hstree_score_threshold,
                    cfg.baseline.min_samples,
                    cfg.baseline.flush_interval_seconds,
                )
            else:
                log.info(
                    "baseline: welford enabled (z=%g, min_samples=%d, flush=%gs)",
                    cfg.baseline.z_threshold, cfg.baseline.min_samples,
                    cfg.baseline.flush_interval_seconds,
                )
        self.snapshotter: SnapshotEngine | None = None
        if cfg.snapshot.enabled:
            snap_dir = snapshot_dir_for(cfg.snapshot, cfg.store.path)
            snap_dir.mkdir(parents=True, exist_ok=True)
            self.snapshotter = SnapshotEngine(cfg.snapshot, snap_dir)
            log.info(
                "snapshot: enabled (window=%gs, min_severity=%s, dir=%s)",
                cfg.snapshot.window_seconds, cfg.snapshot.min_severity,
                snap_dir,
            )
        # replay drives the clock from packet timestamps; live uses wall clock
        self._replay = bool(cfg.capture.pcap_file)
        self._clock_ts = 0.0
        self.uptime: UptimeTracker | None = None
        if cfg.uptime.enabled:
            self.uptime = UptimeTracker(
                cfg.uptime, cfg.thresholds, replay=self._replay,
            )
        self.stats = RunStats()
        self._stop_flag = False
        # guards everything the watchdog tick and the packet path share
        self._loop_lock = threading.RLock()
        self._packets_since_tick = 0
        self._session_id: int | None = None
        self._started = False
        self._watchdog: threading.Thread | None = None
        # cameras seen this run; used to keep new_peer alerts tight
        self._known_peers_per_camera: dict[str, set[str]] = {}
        # bootstrap from the store so a restart doesn't re-alert on every device
        self._seen_ips: set[str] = self.store.device_ips()

    # ----- public lifecycle -----

    def install_signal_handlers(self) -> None:
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def stop(self) -> None:
        self._stop_flag = True

    def run(self) -> bool:
        """Run until stopped or the capture source ends.

        Returns True on clean completion (replay finished or stop requested),
        False if the live capture died unexpectedly. The outer supervisor
        decides whether to relaunch on False.
        """
        self.stats.started_at = time.time()
        keep_raw = self.snapshotter is not None
        snaplen_override = (
            self.cfg.snapshot.snaplen if self.snapshotter is not None else None
        )
        try:
            gen, _stats, handle = stream_packets(
                self.cfg.capture,
                keep_raw=keep_raw, snaplen_override=snaplen_override,
            )
        except CaptureError as e:
            log.error("capture failed to start: %s", e)
            return False
        # Live capture can start its session immediately. Replay cannot: the
        # clock is the packet timestamps, and none have been read yet, so the
        # session would be stamped at epoch 0. It starts on the first packet.
        if not self._replay:
            self._begin_session(time.time())
            self._start_watchdog()
        clean = False
        died = False
        try:
            self._loop(gen)
            # A live capture whose generator simply ENDS has died — tcpdump
            # exited and closed its stdout. Without this the daemon returns
            # True ("clean"), the supervisor sees no reason to relaunch, and
            # monitoring stops silently. The watchdog covers the wedged-but-
            # alive case; this is the died-outright case.
            if not self._replay and not self._stop_flag:
                died = True
                log.error(
                    "capture ended unexpectedly (tcpdump alive=%s) — "
                    "the monitor is blind", handle.is_alive(),
                )
                self._announce_capture_death()
            # drain everything on shutdown so nothing is lost. Sort by
            # last_ts so the baseliner sees flows in time order regardless of
            # dict-iteration order — anomaly detection is order-sensitive.
            with self._loop_lock:
                self._flush(
                    sorted(self.flows.drain(), key=lambda f: f.last_ts),
                    now=self._now(),
                )
                if self.baseliner is not None:
                    self.baseliner.flush(self.store)
                if self.uptime is not None:
                    self.uptime.flush(self.store, self._now())
            clean = not died
            return not died
        finally:
            self._stop_flag = True
            if self._watchdog is not None:
                self._watchdog.join(timeout=_TICK_S * 2)
            if self._session_id is not None:
                self.store.end_monitor_session(
                    self._session_id, self._now() or time.time(), clean,
                )
            handle.close()
            self.store.close()
            self.stats.stopped_at = time.time()
            log.info(
                "hound stopped: packets=%s flows_flushed=%s alerts=%s "
                "uptime_transitions=%s",
                self.stats.packets_seen, self.stats.flows_flushed,
                self.stats.alerts_emitted, self.stats.uptime_transitions,
            )

    # ----- internals -----

    def _handle_signal(self, signum, _frame) -> None:
        log.info("hound: received signal %s — stopping", signum)
        self.stop()

    # ----- clock + session -----

    def _now(self) -> float:
        """Current time on whichever clock this run uses."""
        return self._clock_ts if self._replay else time.time()

    def _begin_session(self, now: float) -> None:
        source = self.cfg.capture.pcap_file or self.cfg.capture.interface
        self._session_id = self.store.start_monitor_session(now, source)
        if self.uptime is not None:
            self.uptime.bootstrap(self.store, self.cfg.network, now)
        self._started = True

    def _start_watchdog(self) -> None:
        """Tick from a thread so a dead capture still gets evaluated.

        Ticking from inside the packet loop means no tick ever happens while
        the capture is wedged — which is precisely the condition
        `capture_stalled` exists to report.
        """
        def _run() -> None:
            while not self._stop_flag:
                time.sleep(_TICK_S)
                if self._stop_flag:
                    return
                try:
                    with self._loop_lock:
                        self._tick(self._now())
                except Exception:  # noqa: BLE001 - a tick must never kill the daemon
                    log.exception("hound: tick failed")

        self._watchdog = threading.Thread(
            target=_run, name="hound-tick", daemon=True,
        )
        self._watchdog.start()

    # ----- the loop -----

    def _loop(self, packets: Iterator[Packet]) -> None:
        next_tick = 0.0
        for pkt in packets:
            if self._stop_flag:
                break
            with self._loop_lock:
                self.stats.packets_seen += 1
                self._packets_since_tick += 1
                self._on_packet(pkt)
                if not self._replay:
                    continue  # the watchdog thread owns ticking when live
                # replay ticks inline, off packet time, so a forensic replay
                # is deterministic rather than dependent on how fast the
                # file happens to be read
                now = self._now()
                if next_tick == 0.0:
                    next_tick = now + _TICK_S
                elif now >= next_tick:
                    self._tick(now)
                    next_tick = now + _TICK_S

    def _on_packet(self, pkt: Packet) -> None:
        if pkt.ts and pkt.ts > self._clock_ts:
            self._clock_ts = pkt.ts
        if not self._started:
            # replay: the first packet is what tells us what time it is
            self._begin_session(self._now())
        self.devices.observe(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
        self.flows.ingest(pkt)
        now = self._now()
        if self.uptime is not None:
            # every packet, camera or not — this is the evidence that the
            # sensor can still see, which is what keeps a blind capture from
            # being reported as a fleet of failed cameras
            self.uptime.observe_packet(pkt.ts or now)
        for ip in (pkt.src_ip, pkt.dst_ip):
            self._maybe_new_device(ip, now)
        # snapshot ring buffer + uptime liveness both key off the endpoint
        # role, so resolve it once per endpoint rather than twice
        for ip in (pkt.src_ip, pkt.dst_ip):
            role = self.devices.role_for(ip)
            if role == "camera" and self.snapshotter is not None:
                # append the raw record under any camera endpoint so the
                # buffer captures the conversation regardless of direction.
                # No-op if snapshots disabled or this is pcapng input.
                self.snapshotter.observe(ip, pkt.ts, pkt.raw_record)
            if role in ("camera", "nvr") and self.uptime is not None:
                self.uptime.touch(ip, pkt.ts or now)

    def _tick(self, now: float) -> None:
        # 1) evict idle flows and process them — sort by last_ts so the
        #    baseliner sees flows in time order across the eviction batch
        evicted = sorted(
            self.flows.evict_idle(now, self.cfg.thresholds.flow_ttl_seconds),
            key=lambda f: f.last_ts,
        )
        if evicted:
            self._flush(evicted, now=now)
        # 2) advance the liveness state machine. `saw_packets` is ANY packet,
        #    not just camera traffic — it is what drives the dead-man's-switch
        saw = self._packets_since_tick > 0
        self._packets_since_tick = 0
        if self.uptime is not None:
            for tr in self.uptime.tick(self.store, now, saw_packets=saw):
                self._on_transition(tr, now)
        # 3) write baselines back to disk on cadence (no-op if disabled)
        if self.baseliner is not None:
            self.baseliner.maybe_flush(self.store, now)

    def _flush(self, flows: list[LiveFlow], *, now: float) -> None:
        for fl in flows:
            fc = self.classifier.classify(fl)
            self.stats.flows_flushed += 1
            row = FlowRow(
                src_ip=fc.src_ip, src_port=fc.src_port, dst_ip=fc.dst_ip,
                dst_port=fc.dst_port, proto=fl.proto,
                first_seen=fl.first_ts, last_seen=fl.last_ts,
                packets=fl.packets, bytes=fl.bytes,
                bytes_to_camera=fc.bytes_to_camera,
                bytes_from_camera=fc.bytes_from_camera,
                tcp_flags_seen="".join(sorted(fl.flags)),
                classification=fc.classification,
            )
            self.store.insert_flow(row)
            # device-count update — first endpoint is the camera side when known
            cam_role = self.devices.role_for(fc.src_ip)
            self.store.upsert_device(
                fc.src_ip, cam_role, now, fl.packets, fl.bytes,
            )
            self.store.upsert_device(
                fc.dst_ip, self.devices.role_for(fc.dst_ip), now, 0, 0,
            )
            # alert from the flow
            alert = self.alerts.from_flow(fc, now)
            if alert is not None:
                self._emit(alert)
            # new-peer alert: a camera contacted a peer it hasn't talked to before
            if cam_role == "camera":
                peers = self._known_peers_per_camera.setdefault(fc.src_ip, set())
                if fc.dst_ip not in peers:
                    peers.add(fc.dst_ip)
                    peer_alert = self.alerts.new_peer(fc.src_ip, fc.dst_ip, now)
                    if peer_alert is not None:
                        self._emit(peer_alert)
            # behavioral baseline (opt-in): score this flow against the
            # camera's learned per-bucket envelope, emit one alert per
            # feature that crossed the z threshold
            if self.baseliner is not None and cam_role == "camera":
                for anom in self.baseliner.observe(fc.src_ip, fl, fc, now):
                    a = self.alerts.behavioral_anomaly(anom, now)
                    if a is not None:
                        self._emit(a)

    def _maybe_new_device(self, ip: str, now: float) -> None:
        if ip in self._seen_ips:
            return
        self._seen_ips.add(ip)
        # the very first observation might be on a router/loopback — only alert
        # for devices that look meaningful (LAN, or already classified)
        role = self.devices.role_for(ip)
        alert = self.alerts.new_device(ip, role, now)
        if alert is not None:
            self._emit(alert)

    def _announce_capture_death(self) -> None:
        """Tell the operator the capture died, through the normal channels.

        Returning False to the supervisor is not enough on its own — if the
        supervisor is a bare `hound run` in a terminal, or restarts into the
        same failure, nobody is told. This routes through the same alert
        path as a stall so it reaches every configured notify channel.
        """
        if self.uptime is None:
            return
        now = self._now()
        last = self.uptime.last_packet_at or now
        with self._loop_lock:
            self._on_transition(Transition(
                kind="stalled", camera_ip="", since=last,
                duration=max(0.0, now - last), outage_id=None,
                last_seen_before=0.0, role="",
            ), now)

    def _on_transition(self, tr: Transition, now: float) -> None:
        """Handle one liveness transition from the uptime tracker."""
        self.stats.uptime_transitions += 1
        # A stall means the sensor is blind, not that the cameras are fine.
        # Splitting the monitor session here is what keeps blind time out of
        # the availability figures — otherwise a wedged capture would be
        # reported as 100% camera uptime, which is worse than no figure.
        if tr.kind == "stalled" and self._session_id is not None:
            self.store.end_monitor_session(self._session_id, tr.since, False)
            self._session_id = None
        elif tr.kind == "stall_cleared":
            source = self.cfg.capture.pcap_file or self.cfg.capture.interface
            self._session_id = self.store.start_monitor_session(now, source)

        alert = self.alerts.from_transition(tr, now)
        if alert is None:
            log.debug("uptime: %s %s (no alert)", tr.kind, tr.camera_ip)
            return
        alert_id = self._emit(alert)
        if tr.outage_id is not None and tr.kind in ("down", "never_seen"):
            self.store.set_outage_alert(tr.outage_id, alert_id)

    def _emit(self, alert: Alert) -> int:
        row = AlertRow(
            id=None, ts=alert.ts, device_ip=alert.device_ip, kind=alert.kind,
            severity=alert.severity, summary=alert.summary, detail=alert.detail,
            dedup_key=alert.dedup_key,
        )
        alert_id = self.store.insert_alert(row)
        delivered = self.dispatcher.dispatch(alert, alert_id)
        if delivered:
            self.store.set_alert_channels(alert_id, ",".join(delivered))
        # dump per-camera ring buffer to a pcap for forensic review
        if self.snapshotter is not None:
            dumped = self.snapshotter.dump_for_alert(
                alert.device_ip, alert.severity, alert_id,
            )
            if dumped is not None:
                path, byte_count, packet_count = dumped
                self.store.insert_snapshot(SnapshotRow(
                    id=None, alert_id=alert_id, camera_ip=alert.device_ip,
                    path=str(path), byte_count=byte_count,
                    packet_count=packet_count, created_at=alert.ts,
                ))
        self.stats.alerts_emitted += 1
        return alert_id
