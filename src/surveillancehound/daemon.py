"""The always-running event loop.

Pulls packets from `capture.stream_packets`, feeds them to the flow aggregator
and the device classifier, periodically (every TICK seconds) flushes idle
flows + checks for silent cameras, classifies each flushed flow, emits + dedups
alerts, and dispatches notifications through every configured channel.

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
import time
from collections.abc import Iterator
from dataclasses import dataclass

from surveillancehound.alerts import Alert, AlertEngine
from surveillancehound.capture import CaptureError, stream_packets
from surveillancehound.classify import FlowClassifier
from surveillancehound.config import HoundCfg
from surveillancehound.discover import DeviceClassifier
from surveillancehound.flows import FlowAggregator, LiveFlow
from surveillancehound.notify import Dispatcher, build_channel
from surveillancehound.pcap import Packet
from surveillancehound.store import AlertRow, FlowRow, HoundStore

log = logging.getLogger(__name__)

# how often (seconds) to evict idle flows + check for silent cameras
_TICK_S = 5.0


@dataclass
class RunStats:
    packets_seen: int = 0
    flows_flushed: int = 0
    alerts_emitted: int = 0
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
        self.alerts = AlertEngine(cfg=cfg.alerts, store=self.store)
        self.dispatcher = Dispatcher(
            [build_channel(c) for c in cfg.notify], store=self.store,
        )
        self.stats = RunStats()
        self._stop_flag = False
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
        try:
            gen, _stats, handle = stream_packets(self.cfg.capture)
        except CaptureError as e:
            log.error("capture failed to start: %s", e)
            return False
        try:
            self._loop(gen)
            # drain everything on shutdown so nothing is lost
            self._flush(list(self.flows.drain()), now=time.time())
            return True
        finally:
            handle.close()
            self.store.close()
            self.stats.stopped_at = time.time()
            log.info(
                "hound stopped: packets=%s flows_flushed=%s alerts=%s",
                self.stats.packets_seen, self.stats.flows_flushed,
                self.stats.alerts_emitted,
            )

    # ----- internals -----

    def _handle_signal(self, signum, _frame) -> None:
        log.info("hound: received signal %s — stopping", signum)
        self.stop()

    def _loop(self, packets: Iterator[Packet]) -> None:
        next_tick = time.time() + _TICK_S
        for pkt in packets:
            if self._stop_flag:
                break
            self.stats.packets_seen += 1
            self._on_packet(pkt)
            now = time.time()
            if now >= next_tick:
                self._tick(now)
                next_tick = now + _TICK_S

    def _on_packet(self, pkt: Packet) -> None:
        self.devices.observe(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
        self.flows.ingest(pkt)
        now = time.time()
        for ip in (pkt.src_ip, pkt.dst_ip):
            self._maybe_new_device(ip, now)

    def _tick(self, now: float) -> None:
        # 1) evict idle flows and process them
        evicted = list(self.flows.evict_idle(now, self.cfg.thresholds.flow_ttl_seconds))
        if evicted:
            self._flush(evicted, now=now)
        # 2) check for silent cameras
        self._check_silence(now)

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

    def _check_silence(self, now: float) -> None:
        ttl = self.cfg.thresholds.silence_seconds
        for d in self.store.list_devices():
            if d.role != "camera":
                continue
            if (now - d.last_seen) >= ttl:
                a = self.alerts.camera_offline(d.ip, now - d.last_seen, now)
                if a is not None:
                    self._emit(a)

    def _emit(self, alert: Alert) -> None:
        row = AlertRow(
            id=None, ts=alert.ts, device_ip=alert.device_ip, kind=alert.kind,
            severity=alert.severity, summary=alert.summary, detail=alert.detail,
            dedup_key=alert.dedup_key,
        )
        alert_id = self.store.insert_alert(row)
        delivered = self.dispatcher.dispatch(alert, alert_id)
        # update the alert row with the delivered channels (audit)
        if delivered:
            with self.store._lock, self.store._conn:  # noqa: SLF001
                self.store._conn.execute(  # noqa: SLF001
                    "UPDATE alerts SET notified_channels = ? WHERE id = ?",
                    (",".join(delivered), alert_id),
                )
        self.stats.alerts_emitted += 1
