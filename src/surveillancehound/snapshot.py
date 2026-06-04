"""Per-camera packet ring buffer + on-alert pcap dump.

When the operator enables `[snapshot]`, the daemon keeps the last
`window_seconds` of raw packet records per camera in RAM. When an alert
fires at severity >= `min_severity`, the matching camera's buffer is
flushed to `<dir>/<alert_id>.pcap` so the operator can open the entire
suspicious window in Wireshark — not just the summary the alert row has.

Memory is bounded two ways: by time-window (entries past `window_seconds`
are evicted on append) AND by per-camera byte cap (`max_buffer_bytes`,
oldest-evicted-first under packet storms). Both bounds are enforced on
every observe call — O(1) amortized.

The writer only works when the source produced classic-pcap raw records
(i.e. live tcpdump or a classic-pcap file). pcapng records don't carry a
classic record header and would mismatch the global header `pcap.write_pcap`
emits; those are skipped silently.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from surveillancehound.config import SnapshotCfg
from surveillancehound.pcap import write_pcap

log = logging.getLogger(__name__)


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class _CameraBuffer:
    """Ring of (ts, raw_record_bytes) entries for one camera."""
    records: deque  # deque[tuple[float, bytes]]
    bytes_held: int = 0


class SnapshotEngine:
    """Owns the per-camera ring buffers + the dump-on-alert path.

    Lifecycle:
      * `observe(camera_ip, pkt_ts, raw_record)` per packet that involves
        a camera. Appends to the buffer and evicts past the time/byte
        bounds.
      * `dump_for_alert(alert, ts) -> (path, byte_count, packet_count) | None`
        Drains the matching camera's buffer to a pcap file. Returns None
        if severity below threshold or buffer empty.
    """

    def __init__(self, cfg: SnapshotCfg, snapshot_dir: Path) -> None:
        self.cfg = cfg
        self.dir = snapshot_dir
        self._bufs: dict[str, _CameraBuffer] = {}
        self._min_sev = _SEVERITY_RANK.get(cfg.min_severity, 2)

    def observe(
        self, camera_ip: str, pkt_ts: float, raw_record: bytes | None,
    ) -> None:
        if raw_record is None:
            return
        buf = self._bufs.get(camera_ip)
        if buf is None:
            buf = _CameraBuffer(records=deque())
            self._bufs[camera_ip] = buf
        buf.records.append((pkt_ts, raw_record))
        buf.bytes_held += len(raw_record)
        self._evict(buf, pkt_ts)

    def _evict(self, buf: _CameraBuffer, now: float) -> None:
        cutoff = now - self.cfg.window_seconds
        while buf.records and buf.records[0][0] < cutoff:
            _, rec = buf.records.popleft()
            buf.bytes_held -= len(rec)
        while buf.bytes_held > self.cfg.max_buffer_bytes and buf.records:
            _, rec = buf.records.popleft()
            buf.bytes_held -= len(rec)

    def dump_for_alert(
        self, camera_ip: str, severity: str, alert_id: int,
    ) -> tuple[Path, int, int] | None:
        if _SEVERITY_RANK.get(severity, 0) < self._min_sev:
            return None
        buf = self._bufs.get(camera_ip)
        if buf is None or not buf.records:
            return None
        path = self.dir / f"{alert_id}.pcap"
        # snapshot a copy so concurrent observes don't mutate mid-write
        records = [rec for _, rec in list(buf.records)]
        byte_count = write_pcap(path, iter(records))
        log.info(
            "snapshot: alert=%d camera=%s wrote=%d bytes (%d packets) → %s",
            alert_id, camera_ip, byte_count, len(records), path,
        )
        return path, byte_count, len(records)


def snapshot_dir_for(cfg: SnapshotCfg, store_path: str) -> Path:
    """Resolve the snapshot dir: explicit cfg.dir if set, else
    <store_dir>/snapshots/. Caller is responsible for creating it."""
    if cfg.dir:
        return Path(cfg.dir)
    return Path(store_path).resolve().parent / "snapshots"
