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
import queue
import sqlite3
import threading
import time
from collections import deque
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
# Retention is housekeeping, not detection. Hourly is frequent enough to
# bound disk and rare enough that it never competes with packet handling.
_REMOTE_PRUNE_EVERY_S = 3600.0

# Relayed alerts are dispatched off the ingest thread. The queue is bounded
# because the alternative to dropping is unbounded memory growth driven by a
# remote host: a channel like ftp or email can take seconds per alert, and a
# single authenticated batch may carry max_records_per_batch of them.
# Dropping and COUNTING the overflow is honest; silently queueing it is not.
_RELAY_ALERT_QUEUE = 1000
# Per batch, independent of the queue: one batch should not be able to
# consume the whole queue and starve every other sensor.
_RELAY_ALERTS_PER_BATCH = 200
# How often to retry a listener that could not bind. The address may come
# up after the daemon does; a first failure is not a permanent one.
_INGEST_REBIND_EVERY_S = 60.0
# Bound on the relayed-alert dedup map. dedup_key is sensor-controlled, so
# the keyspace has to be capped like any other remote-driven structure.
_RELAY_DEDUP_MAX = 4096


@dataclass
class RunStats:
    packets_seen: int = 0
    flows_flushed: int = 0
    alerts_emitted: int = 0
    uptime_transitions: int = 0
    relayed_alerts_dispatched: int = 0  # observed elsewhere, paged by us
    relayed_dropped_batch: int = 0      # over the per-batch cap
    relayed_dropped_budget: int = 0     # over the per-sensor notify budget
    relayed_dropped_share: int = 0      # over this sensor's queue share
    relayed_dropped_queue: int = 0      # queue full outright
    started_at: float = 0.0
    stopped_at: float | None = None


class _FairAlertQueue:
    """Bounded alert queue that serves sensors round-robin.

    A single FIFO closed the "one sensor drops another's alerts" hole
    but not the "one sensor DELAYS another's alerts" one: a legitimate
    sensor's critical page sat behind the flooder's backlog, and at a
    few seconds per channel that is tens of minutes. Silencing by delay
    is still silencing.

    Round-robin means a quiet sensor's alert waits at most one item per
    OTHER sensor, regardless of how much backlog the noisy one has.
    """

    def __init__(self, maxsize: int):
        self.maxsize = maxsize
        self._queues: dict[str, deque] = {}
        self._order: deque[str] = deque()
        self._sentinel = False
        self._n = 0
        self._cv = threading.Condition()

    def qsize(self) -> int:
        with self._cv:
            return self._n

    def put_nowait(self, item) -> None:
        with self._cv:
            if item is None:            # shutdown sentinel, always admitted
                self._sentinel = True
                self._cv.notify()
                return
            if self._n >= self.maxsize:
                raise queue.Full
            sensor = item[0]
            q = self._queues.get(sensor)
            if q is None:
                q = self._queues[sensor] = deque()
                self._order.append(sensor)
            q.append(item)
            self._n += 1
            self._cv.notify()

    def _pop_locked(self):
        if self._sentinel:
            self._sentinel = False
            return None
        for _ in range(len(self._order)):
            sensor = self._order[0]
            self._order.rotate(-1)
            q = self._queues.get(sensor)
            if q:
                self._n -= 1
                return q.popleft()
        raise queue.Empty

    def get_nowait(self):
        with self._cv:
            if not self._n and not self._sentinel:
                raise queue.Empty
            return self._pop_locked()

    def get(self, timeout: float | None = None):
        with self._cv:
            if not self._n and not self._sentinel:
                self._cv.wait(timeout)
            if not self._n and not self._sentinel:
                raise queue.Empty
            return self._pop_locked()


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
        if cfg.relay.is_agent:
            # An agent never notifies. The collector is the only notifier,
            # so configuring channels at both ends would double-page.
            self.dispatcher = Dispatcher([], store=self.store)
            log.info("relay: agent mode — notifications are the collector's "
                     "job, dispatch disabled here")
        else:
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
        self.relay = None
        self.ingest = None
        if cfg.relay.is_agent:
            from surveillancehound.relay import RelayClient
            self.relay = RelayClient(cfg.relay, self.store, now=time.time)
        elif cfg.relay.is_collector:
            from surveillancehound.ingest import IngestServer
            self.ingest = IngestServer(
                cfg.relay, self.store, on_alerts=self._on_relayed_alerts,
                now=time.time,
            )
        # Relayed rows arrive from hosts we do not control, so their volume
        # is not ours to bound at write time. Retention is what keeps a
        # collector's disk finite; without this sweep `remote_retention_days`
        # is a config field that does nothing.
        self._last_remote_prune = 0.0
        self._last_ingest_bind_try = 0.0
        # sensor_id -> last_seen at the moment we declared it down
        self._sensors_down: dict[str, float] = {}
        # (sensor_id, dedup_key) -> when we last DISPATCHED it
        self._relay_last_dispatch: dict[tuple, float] = {}
        self._relay_notify_times: dict[str, deque] = {}
        self._relay_inflight: dict[str, int] = {}
        self._relay_inflight_lock = threading.Lock()
        self._relay_budget_warned: dict[str, bool] = {}
        self._relay_budget_lock = threading.Lock()
        # Bounded hand-off from the ingest threads to one dispatch worker.
        self._relay_alertq: _FairAlertQueue | None = (
            _FairAlertQueue(_RELAY_ALERT_QUEUE)
            if cfg.relay.is_collector else None
        )
        self._relay_worker: threading.Thread | None = None
        self._relay_stop = threading.Event()
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
            # An agent must not capture its own uploads: they would be
            # aggregated, classified as off-network telemetry, alerted on,
            # and relayed — producing more of exactly the traffic that
            # triggered them.
            exclude_bpf = ""
            if self.cfg.relay.is_agent:
                from surveillancehound.relay import exclusion_filter
                exclude_bpf = exclusion_filter(self.cfg.relay.url)
            gen, _stats, handle = stream_packets(
                self.cfg.capture,
                keep_raw=keep_raw, snaplen_override=snaplen_override,
                exclude_bpf=exclude_bpf,
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
            if self.relay is not None:
                self.relay.start()
            if self.ingest is not None:
                self._start_relay_dispatch()
                self.ingest.start()
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
            if self.relay is not None:
                self.relay.final_flush()
            clean = not died
            return not died
        finally:
            self._stop_flag = True
            # Stop the relay threads BEFORE taking the lock and closing the
            # store, or an in-flight ingest resumes against a dead handle.
            if self.relay is not None:
                self.relay.stop()
            if self.ingest is not None:
                # Listener first: stop accepting, then drain what is queued.
                self.ingest.stop()
                self._stop_relay_dispatch()
            if self._watchdog is not None:
                self._watchdog.join(timeout=_TICK_S * 2)
            # Close out under the loop lock so no watchdog tick can be
            # mid-transition against the store while it is being closed.
            with self._loop_lock:
                if self._session_id is not None:
                    self.store.end_monitor_session(
                        self._session_id, self._now() or time.time(), clean,
                    )
                handle.close()
                self.store.close()
            self.stats.stopped_at = time.time()
            # relayed_dispatched is reported separately and ALWAYS, not
            # folded into `alerts`: separating the counter and then not
            # printing it meant a collector that paged 500 relayed
            # alerts reported alerts=0.
            log.info(
                "hound stopped: packets=%s flows_flushed=%s alerts=%s "
                "relayed_dispatched=%s uptime_transitions=%s",
                self.stats.packets_seen, self.stats.flows_flushed,
                self.stats.alerts_emitted,
                self.stats.relayed_alerts_dispatched,
                self.stats.uptime_transitions,
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
                try:
                    with self._loop_lock:
                        # Re-check INSIDE the lock. Shutdown sets the flag
                        # and then closes the store under this same lock, so
                        # checking outside it leaves a window where a tick
                        # starts against a connection that is about to go
                        # away — losing whatever alert it was emitting.
                        if self._stop_flag:
                            return
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
        # 4) age out relayed rows (collector only, hourly)
        self._maybe_prune_remote(now)
        # 5) retry a listener that could not bind at startup
        self._maybe_retry_ingest_bind(now)
        # 6) alert if a relay sensor has gone quiet
        self._check_sensor_liveness(now)

    def _check_sensor_liveness(self, now: float) -> None:
        """Alert when a relay agent stops reporting.

        Its cameras degrade to `unknown`, which is honest but silent —
        and silence is only visible to someone already watching the
        dashboard. The collector cannot see that segment itself, so a
        quiet agent means those cameras are unmonitored, not fine.
        """
        # Replay's clock is packet time, so a months-old capture would
        # compute silence against a months-old `now` and invent outages.
        if self._replay or self.ingest is None:
            return
        timeout = self.cfg.relay.sensor_timeout_seconds
        if timeout <= 0:
            return
        # Reconcile against the CONFIGURED list, not just rows that exist.
        # `remote_sensors` only gains a row after a first successful
        # batch, so a sensor that has never connected — or one whose row
        # was removed with `hound sensors --forget` — produced no row, no
        # alert, and `hound sensors` saying "none have reported yet".
        # That is the same hole `uptime.py` has a `never_seen` transition
        # for: a thing that was dead before we started still has to be
        # reported.
        seen = {x.sensor_id: x.last_seen
                for x in self.store.list_remote_sensors()}
        for cfg_sensor in self.cfg.relay.sensors:
            seen.setdefault(cfg_sensor.id, self.stats.started_at or now)

        for sensor_id, last_seen in sorted(seen.items()):
            silent = now - last_seen
            was_down = sensor_id in self._sensors_down
            if silent > timeout and not was_down:
                self._sensors_down[sensor_id] = last_seen
                alert = self.alerts.sensor_offline(sensor_id, silent, now)
                if alert is not None:
                    self._emit(alert)
            elif silent <= timeout and was_down:
                down_since = self._sensors_down.pop(sensor_id)
                alert = self.alerts.sensor_recovered(
                    sensor_id, max(0.0, now - down_since), now)
                if alert is not None:
                    self._emit(alert)

    def _maybe_retry_ingest_bind(self, now: float) -> None:
        """Retry binding the ingest listener.

        The listen address may legitimately not exist yet when the daemon
        starts — on a firewall the interface can come up after the service
        does. Treating the first failure as final meant the collector
        silently never listened for the life of the process, which is the
        worst outcome: the UI says collector, and nothing arrives.
        """
        # Replay must never open a listener. `run()` starts ingest only on
        # the live path, but this retry ran from the replay tick too, so
        # analysing a pcap silently bound a port and accepted remote
        # writes into the replay store — and with no dispatch worker
        # started, anything received filled the queue and was dropped.
        if self._replay or self.ingest is None or self.ingest.started:
            return
        if (now - self._last_ingest_bind_try) < _INGEST_REBIND_EVERY_S:
            return
        self._last_ingest_bind_try = now
        if self.ingest.start():
            log.info("relay: ingest listener bound on a retry")

    def _maybe_prune_remote(self, now: float) -> None:
        """Age out relayed rows on an hourly cadence.

        Only the collector accumulates these. The sweep is deliberately
        cheap and failure-tolerant: a locked or unwritable database must
        degrade to "disk keeps growing", never to a daemon that stops
        capturing. Retention is the only bound on `remote_*` growth,
        because the rows come from hosts whose volume we do not control.
        """
        if self.ingest is None:
            return
        days = self.cfg.relay.remote_retention_days
        if days <= 0:                      # 0 disables, per config convention
            return
        if (now - self._last_remote_prune) < _REMOTE_PRUNE_EVERY_S:
            return
        self._last_remote_prune = now
        try:
            deleted = self.store.prune_remote(now - days * 86400.0)
        except sqlite3.Error as e:
            log.warning("relay: remote retention sweep failed: %s", e)
            return
        total = sum(deleted.values())
        if total:
            log.info("relay: retention removed %d relayed row(s) older "
                     "than %.1f days: %s", total, days,
                     ", ".join(f"{k}={v}" for k, v in deleted.items() if v))

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
            # device-count update — first endpoint is the camera side when known.
            # Stamp with the flow's OWN last packet time, not the tick clock.
            # A flow is evicted flow_ttl_seconds (default 300) after its last
            # packet, so stamping with `now` claimed we had seen the device
            # five minutes more recently than we had — which, for a camera
            # that had just died, was enough to make a restart think it had
            # recovered and close its outage.
            cam_role = self.devices.role_for(fc.src_ip)
            self.store.upsert_device(
                fc.src_ip, cam_role, fl.last_ts, fl.packets, fl.bytes,
                first_seen=fl.first_ts,
            )
            self.store.upsert_device(
                fc.dst_ip, self.devices.role_for(fc.dst_ip), fl.last_ts, 0, 0,
                first_seen=fl.first_ts,
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

    def _on_relayed_alerts(self, sensor_id: str, alerts: list[dict],
                           instance_id: str = "") -> None:
        """Hand relayed alerts to the dispatch worker. Called ON AN INGEST
        THREAD, so it must not block.

        Dispatching inline would let one authenticated batch hold an
        ingest thread for as long as its slowest channel takes. Three
        admission checks happen HERE rather than downstream, because a
        slot consumed is a slot another sensor cannot have:

        1. a per-batch cap, so one batch cannot fill the queue;
        2. the per-sensor notification budget — checked at enqueue, since
           checking it after the item had already taken a queue slot
           meant an over-budget sensor still denied slots to everyone
           else;
        3. a per-sensor share of the queue. Without it one sensor
           holding a valid key could saturate the shared queue and
           suppress every OTHER sensor's pages indefinitely: ingest
           admits far more per minute than a worker doing multi-second
           channel fan-outs can drain.
        """
        q = self._relay_alertq
        if q is None:
            return
        now = time.time()
        share = self._relay_queue_share()
        over_batch = max(0, len(alerts) - _RELAY_ALERTS_PER_BATCH)

        window = self.cfg.alerts.dedup_window_seconds
        for raw in alerts[:_RELAY_ALERTS_PER_BATCH]:
            # Cheap dedup pre-check BEFORE spending budget. An alert the
            # dispatcher would suppress for free should not consume the
            # sensor's allowance, or a flood of duplicates lets a sensor
            # silence its own real pages.
            seen = self._relay_last_dispatch.get(
                ("k", sensor_id, raw["dedup_key"]))
            if seen is not None and (now - seen) < window:
                continue
            # Budget is CHECKED here but only SPENT once the item is
            # actually queued. Spending it first meant alerts rejected
            # by the later gates — never queued, never dispatched,
            # never paged — still burned the sensor's allowance, so a
            # burst of share-dropped noise could exhaust the budget and
            # the next genuine critical was refused against an empty
            # queue. That is the same defect as budget-dropped alerts
            # poisoning the dedup map, moved one gate downstream.
            # Check and spend are individually atomic but not atomic as
            # a pair, so concurrent ingest threads can over-admit by at
            # most one per thread. Deliberate: holding the budget lock
            # across the enqueue would serialise every sensor behind
            # one mutex, and for a monitor the safe direction to err is
            # paging slightly too much, never suppressing.
            if not self._relay_notify_budget(sensor_id, now, spend=False):
                self.stats.relayed_dropped_budget += 1
                continue
            with self._relay_inflight_lock:
                if self._relay_inflight.get(sensor_id, 0) >= share:
                    self.stats.relayed_dropped_share += 1
                    continue
                self._relay_inflight[sensor_id] = (
                    self._relay_inflight.get(sensor_id, 0) + 1)
            try:
                q.put_nowait((sensor_id, raw, instance_id))
            except queue.Full:
                with self._relay_inflight_lock:
                    n = self._relay_inflight.get(sensor_id, 1) - 1
                    if n > 0:
                        self._relay_inflight[sensor_id] = n
                    else:
                        self._relay_inflight.pop(sensor_id, None)
                self.stats.relayed_dropped_queue += 1
                continue
            self._relay_notify_budget(sensor_id, now, spend=True)

        if over_batch:
            self.stats.relayed_dropped_batch += over_batch
            log.warning(
                "relay: sensor %r sent %d alerts in one batch; dispatching "
                "at most %d and dropping %d. They remain in remote_alerts "
                "and on the dashboard — only the notification is skipped.",
                sensor_id, len(alerts), _RELAY_ALERTS_PER_BATCH, over_batch,
            )

    def _relay_queue_share(self) -> int:
        """How many queue slots any ONE sensor may hold at once.

        An equal split, floored so a single sensor is not throttled on a
        quiet collector. The point is only that no sensor can take the
        whole queue.
        """
        n = max(1, len(self.cfg.relay.sensors))
        return max(50, _RELAY_ALERT_QUEUE // n)

    def _relay_inflight_done(self, sensor_id: str) -> None:
        with self._relay_inflight_lock:
            n = self._relay_inflight.get(sensor_id, 1) - 1
            if n > 0:
                self._relay_inflight[sensor_id] = n
            else:
                self._relay_inflight.pop(sensor_id, None)

    def _start_relay_dispatch(self) -> None:
        if self._relay_alertq is None:
            return

        def _run() -> None:
            while True:
                # Check the flag FIRST, every iteration. Checking it only
                # on an empty queue meant a remote-filled backlog kept
                # the worker dispatching through shutdown: the 10s join
                # expired, the store closed underneath it, and it then
                # logged a ProgrammingError per queued alert — with the
                # sensor choosing how long shutdown took and how much
                # noise it made.
                if self._relay_stop.is_set():
                    return
                try:
                    item = self._relay_alertq.get(timeout=0.5)
                except queue.Empty:
                    continue
                if item is None:
                    return
                try:
                    self._dispatch_relayed_alert(*item)
                except Exception:           # noqa: BLE001
                    log.exception("relay: dispatching a relayed alert failed")
                finally:
                    self._relay_inflight_done(item[0])

        self._relay_worker = threading.Thread(
            target=_run, name="hound-relay-dispatch", daemon=True)
        self._relay_worker.start()

    def _stop_relay_dispatch(self) -> None:
        """Drain before the store closes, or the worker writes to a dead
        handle. Bounded wait: a wedged channel must not block shutdown."""
        if self._relay_alertq is None or self._relay_worker is None:
            return
        # An in-band sentinel is dropped exactly when the queue is full —
        # the hostile case the queue exists for — so the worker would
        # never see it and would still be running when the store closed.
        # The flag is out of band and cannot be crowded out.
        self._relay_stop.set()
        try:
            self._relay_alertq.put_nowait(None)
        except queue.Full:
            pass
        self._relay_worker.join(timeout=10)
        # Whatever was still queued is not dispatched. Counting it keeps
        # the shutdown report honest — and these stay suppressed for the
        # dedup window after a restart, because dedup measures receipt,
        # so an operator needs to know they were skipped.
        # qsize() excludes the sentinel, so this is real work dropped.
        abandoned = self._relay_alertq.qsize()
        if abandoned:
            self.stats.relayed_dropped_queue += abandoned
        self._relay_worker = None
        self._log_relay_drops()

    def _log_relay_drops(self) -> None:
        """Report undispatched relayed alerts BY CAUSE.

        One counter attributing everything to "the queue was full" told
        an operator the wrong thing three times out of four — and a
        collector that has quietly stopped paging looks healthy until
        then, so the causes have to be distinguishable.
        """
        st = self.stats
        causes = [
            (st.relayed_dropped_budget, "over the per-sensor notify budget"),
            (st.relayed_dropped_share, "over that sensor's queue share"),
            (st.relayed_dropped_batch, "over the per-batch cap"),
            (st.relayed_dropped_queue, "dispatch queue full"),
        ]
        total = sum(n for n, _ in causes)
        if not total:
            return
        log.warning(
            "relay: %d relayed alert(s) were stored and shown but NOT "
            "dispatched — %s. Raise the relevant [relay] limit if this is "
            "legitimate traffic.",
            total, "; ".join(f"{n} {why}" for n, why in causes if n),
        )

    def _dispatch_relayed_alert(self, sensor_id: str, raw: dict,
                                instance_id: str = "") -> None:
        """Dispatch one relayed alert.

        Deliberately not `_emit`. That writes `alerts`, updates it again via
        set_alert_channels, records into `notifications` (whose alert_id
        means alerts.id), and can make the snapshot engine overwrite a local
        alert's pcap — four ways for a remote host to reach central state.
        This path touches remote_* only. tests/verify_relay.py executes this
        method directly and fails if it reaches any central table.
        """
        now = time.time()
        window = self.cfg.alerts.dedup_window_seconds
        key = f"{sensor_id}/{raw['dedup_key']}"
        # Two gates, because the first one alone trusted a number the
        # sensor chooses.
        #
        # 1) What we have actually DISPATCHED, held in memory. The stored
        #    row cannot answer this: the listener writes the batch before
        #    dispatch, and several queued copies can map to one row, so a
        #    row-based check either suppresses everything or nothing.
        # Two identities, both of which must be fresh.
        #
        # `dedup_key` is what the alert is ABOUT. `remote_id` is the
        # sensor's own id for the record, and the collector stores one
        # row per (sensor_id, remote_id) — so reusing it across batches
        # with different content stored the FIRST copy and paged every
        # one. Fifty batches reusing id 1 produced fifty pages, one
        # stored row, and fifty audit rows citing content that was never
        # the thing sent. Treating a reused id as the same record is
        # what keeps the record and the page agreeing.
        dkey = ("k", sensor_id, raw["dedup_key"])
        rkey = ("r", sensor_id, instance_id, raw["remote_id"])
        for k in (dkey, rkey):
            seen = self._relay_last_dispatch.get(k)
            if seen is not None and (now - seen) < window:
                return
        sent = self._relay_last_dispatch.get(dkey)
        # 2) What we RECEIVED before this process started, so a restart
        #    does not re-notify the backlog. Measured on ingested_at —
        #    collector time — never the sensor-supplied ts, which would
        #    let a backdated alert walk past the window.
        if sent is None:
            last = self.store.remote_alert_last_at(
                sensor_id, raw["dedup_key"],
                exclude_remote_id=raw["remote_id"],
            )
            if last is not None and (now - last) < window:
                return

        self._relay_last_dispatch[dkey] = now
        self._relay_last_dispatch[rkey] = now
        if len(self._relay_last_dispatch) > _RELAY_DEDUP_MAX:
            # Bounded: the keyspace is sensor-controlled via dedup_key.
            # Dropping the oldest can at worst re-notify something, never
            # suppress something new.
            for k in sorted(self._relay_last_dispatch,
                            key=self._relay_last_dispatch.get,
                            )[:_RELAY_DEDUP_MAX // 2]:
                del self._relay_last_dispatch[k]
        alert = Alert(
            ts=raw["ts"], device_ip=raw["device_ip"], kind=raw["kind"],
            severity=raw["severity"], summary=raw["summary"],
            detail=raw["detail"], dedup_key=key, sensor=sensor_id,
        )
        remote_id = self.store.remote_alert_id_for(
            sensor_id, raw["remote_id"], instance_id)

        # Audit every attempt, not just the successful ones. A relayed
        # alert that failed to deliver is exactly the row an operator
        # goes looking for, and recording only successes made the
        # ok/error columns unable to ever say anything else.
        def _audit(channel: str, ok: bool, err: str,
                   _sid=sensor_id, _rid=remote_id or 0) -> None:
            self.store.record_remote_notification(_sid, _rid, channel, ok, err)

        self.dispatcher.dispatch(alert, None, on_attempt=_audit)
        # Counted separately: mixing relayed dispatches into
        # alerts_emitted made the shutdown line claim this sensor had
        # observed things another host did.
        self.stats.relayed_alerts_dispatched += 1

    def _relay_notify_budget(self, sensor_id: str, now: float,
                             *, spend: bool = True) -> bool:
        """Per-sensor cap on NOTIFICATIONS, not on storage.

        Dedup bounds repeats of one alert; this bounds distinct ones. A
        sensor holding a valid key can otherwise emit alerts with
        distinct dedup keys as fast as it can post, and every one fans
        out to email, webhook and FTP. The alerts themselves are still
        stored and still relayed to the dashboard — only the paging
        stops, which is the part that cannot be undone. There is no
        notification audit row for a budget denial, because nothing was
        attempted; the shutdown report counts it by cause instead.
        """
        cap = self.cfg.relay.max_notifications_per_minute
        if cap <= 0:
            return True
        # Called from up to max_workers ingest threads concurrently.
        with self._relay_budget_lock:
            return self._budget_locked(sensor_id, now, cap, spend)

    def _budget_locked(self, sensor_id: str, now: float, cap: int,
                       spend: bool) -> bool:
        q = self._relay_notify_times.setdefault(sensor_id, deque())
        while q and (now - q[0]) > 60.0:
            q.popleft()
        if len(q) >= cap:
            if not self._relay_budget_warned.get(sensor_id):
                self._relay_budget_warned[sensor_id] = True
                log.warning(
                    "relay: sensor %r hit its notification budget of %d/min; "
                    "further alerts from it are stored and shown but not "
                    "dispatched until it slows down. Raise [relay] "
                    "max_notifications_per_minute if this is legitimate.",
                    sensor_id, cap,
                )
            return False
        self._relay_budget_warned[sensor_id] = False
        if spend:
            q.append(now)
        return True

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
