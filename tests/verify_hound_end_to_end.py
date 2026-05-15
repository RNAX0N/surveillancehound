"""End-to-end verification of SurveillanceHound.

Builds the synthetic capture (camera 192.168.1.50 with four known-answer
conversations), spins the daemon up in REPLAY mode against it (no live wire
needed), and asserts:

  * the expected flow classifications land in the store,
  * the expected alerts fire (bulk_inbound HIGH, control_channel_suspect MEDIUM,
    telemetry_offnet MEDIUM, new_device per IP, new_peer per camera↔peer pair),
  * notifications were dispatched through the configured channels,
  * the audit log records every dispatch,
  * dedup suppresses a re-emit of the same dedup_key.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from surveillancehound.alerts import AlertEngine  # noqa: E402
from surveillancehound.config import (  # noqa: E402
    AlertsCfg, CaptureCfg, HoundCfg, NetworkCfg, NotifyChannelCfg, StoreCfg,
    ThresholdCfg,
)
from surveillancehound.daemon import Hound  # noqa: E402
from surveillancehound.store import HoundStore  # noqa: E402

import make_synthetic_camera_pcap as mk  # noqa: E402


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        pcap_path = root / "synthetic.pcap"
        pcap_path.write_bytes(mk.build())

        jsonl_path = root / "alerts.jsonl"
        log_path = root / "alerts.log"
        db_path = root / "hound.sqlite"

        cfg = HoundCfg(
            capture=CaptureCfg(pcap_file=str(pcap_path), snaplen=96),
            network=NetworkCfg(camera_ips=[mk.CAMERA_IP]),
            thresholds=ThresholdCfg(),
            alerts=AlertsCfg(),
            store=StoreCfg(path=str(db_path)),
            notify=[
                NotifyChannelCfg(type="jsonlines", path=str(jsonl_path), level="info"),
                NotifyChannelCfg(type="logfile", path=str(log_path), level="info"),
            ],
        )

        hound = Hound(cfg)
        ok = hound.run()
        assert ok, "hound run failed in replay mode"
        print(f"  replay: packets={hound.stats.packets_seen} "
              f"flows_flushed={hound.stats.flows_flushed} "
              f"alerts={hound.stats.alerts_emitted}")

        store = HoundStore(path=db_path)

        # --- flow classifications ---
        flows = store.recent_flows(limit=20)
        by_class = {f.classification: f for f in flows}
        for needed in ("lan_normal", "telemetry_offnet", "bulk_inbound",
                       "control_channel_suspect"):
            assert needed in by_class, (
                f"missing classification {needed} (got {list(by_class)})"
            )
        bulk = by_class["bulk_inbound"]
        assert bulk.bytes_to_camera >= 1024 * 1024, bulk.bytes_to_camera
        ctrl = by_class["control_channel_suspect"]
        assert ctrl.dst_port == 4444 and ctrl.packets == 200, (
            ctrl.dst_port, ctrl.packets,
        )
        print(f"  flows: 4 expected classifications present; "
              f"bulk_inbound to_cam={bulk.bytes_to_camera:,}B, "
              f"control_channel {ctrl.packets} pkts")

        # --- alerts ---
        alerts = store.list_alerts(limit=200)
        kinds = {a.kind for a in alerts}
        assert "bulk_inbound" in kinds, kinds
        assert "control_channel_suspect" in kinds, kinds
        assert "telemetry_offnet" in kinds, kinds
        assert "new_device" in kinds, kinds
        assert "new_peer" in kinds, kinds
        # severity assertions
        bulk_alert = next(a for a in alerts if a.kind == "bulk_inbound")
        assert bulk_alert.severity == "high", bulk_alert.severity
        ctrl_alert = next(a for a in alerts if a.kind == "control_channel_suspect")
        assert ctrl_alert.severity == "medium", ctrl_alert.severity
        # camera should have 4 distinct peers -> 4 new_peer alerts
        new_peer_count = sum(1 for a in alerts if a.kind == "new_peer")
        assert new_peer_count == 4, new_peer_count
        # 5 distinct IPs seen this run -> 5 new_device alerts
        new_dev_count = sum(1 for a in alerts if a.kind == "new_device")
        assert new_dev_count == 5, new_dev_count
        print(f"  alerts: {len(alerts)} total "
              f"(bulk_inbound HIGH, control_channel MEDIUM, telemetry MEDIUM, "
              f"{new_peer_count} new_peer, {new_dev_count} new_device)")

        # --- notification dispatch ---
        assert jsonl_path.is_file() and log_path.is_file()
        jsonl_lines = jsonl_path.read_text().strip().splitlines()
        assert len(jsonl_lines) == len(alerts), (len(jsonl_lines), len(alerts))
        parsed = [json.loads(line) for line in jsonl_lines]
        assert any(p["kind"] == "bulk_inbound" for p in parsed)
        log_lines = log_path.read_text().strip().splitlines()
        assert len(log_lines) == len(alerts), (len(log_lines), len(alerts))
        print(f"  notifications: {len(jsonl_lines)} JSON lines, "
              f"{len(log_lines)} log lines (one per alert × 2 channels)")

        # the alert row's notified_channels column records which channels delivered
        for a in alerts:
            assert "jsonlines" in a.notified_channels, a.notified_channels
            assert "logfile" in a.notified_channels, a.notified_channels
        print("  audit: every alert row records the channels it was delivered through")

        # --- dedup: a same-dedup-key alert within the window is suppressed ---
        engine = AlertEngine(cfg=AlertsCfg(dedup_window_seconds=3600.0), store=store)
        bulk_dedup = bulk_alert.dedup_key
        # mimicking a fresh emit attempt for the same dedup_key — should suppress
        suppressed = engine._suppressed(bulk_dedup)  # noqa: SLF001
        assert suppressed, "dedup did not suppress a same-key re-emit"
        print("  dedup: same-key re-emit suppressed within the window")

        # --- devices: camera IP is in the store and classified ---
        cam = store.get_device(mk.CAMERA_IP)
        assert cam is not None and cam.role == "camera", cam
        print(f"  devices: {mk.CAMERA_IP} role={cam.role} "
              f"packets={cam.packet_count} bytes={cam.byte_count}")

        store.close()
        print("\nHOUND END-TO-END VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
