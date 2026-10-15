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


def _check_lan_subnets() -> None:
    """[network].lan_subnets must widen what counts as local.

    Not every deployment numbers its cameras out of RFC-1918. On a network
    using provider-assigned public space, the built-in private ranges call
    every local device foreign, so ordinary camera-to-NVR traffic classifies
    as telemetry_offnet and raises a MEDIUM alert for each flow. That is a
    flood of false positives, and it makes the manufacturer allowlist
    pointless because everything already looks off-network.
    """
    from surveillancehound.classify import FlowClassifier
    from surveillancehound.config import load_from_dict
    from surveillancehound.discover import DeviceClassifier, is_lan
    from surveillancehound.flows import LiveFlow

    def classify_with(lan_subnets):
        cfg = load_from_dict({
            "capture": {"pcap_file": "x.pcap"},
            "network": {
                "camera_ips": ["117.111.101.2"],
                "nvr_ips": ["88.255.5.11"],
                "lan_subnets": lan_subnets,
            },
        })
        devices = DeviceClassifier(network=cfg.network)
        fc = FlowClassifier(
            network=cfg.network, thresholds=cfg.thresholds, devices=devices,
        )
        fl = LiveFlow(
            proto="tcp", ep_a=("117.111.101.2", 554), ep_b=("88.255.5.11", 40000),
            first_ts=1000.0, last_ts=1010.0, packets=50, bytes=50000,
        )
        fl.bytes_a_to_b, fl.bytes_b_to_a = 49000, 1000
        return devices, fc.classify(fl).classification

    devices, cls = classify_with([])
    assert cls == "telemetry_offnet", cls
    assert devices.is_lan("88.255.5.11") is False

    devices, cls = classify_with(["117.111.0.0/16", "88.255.0.0/16"])
    assert cls == "lan_normal", (
        f"camera-to-NVR traffic inside a configured lan_subnet should be "
        f"lan_normal, got {cls}"
    )
    assert devices.is_lan("88.255.5.11") is True
    # a range NOT listed stays foreign
    assert devices.is_lan("203.0.113.9") is False

    # the module-level helper is unchanged — existing callers and the
    # default deployment must behave exactly as before
    assert is_lan("10.0.0.1") is True
    assert is_lan("117.111.101.2") is False
    print("  lan_subnets: widens 'local' without changing the default")


def _check_cooked_capture_linktypes() -> None:
    """`tcpdump -i any` must actually parse.

    An agent watching a host with one VLAN interface per camera is told to
    capture on `any`. Since libpcap 1.10 that device defaults to LINUX_SLL2
    (DLT 276), not SLL. Without SLL2 support every packet is skipped and the
    sensor reports a perfectly healthy, completely empty segment — the worst
    failure mode available to a monitor, because nothing looks wrong.
    """
    import io
    import socket
    import struct

    from surveillancehound.pcap import (
        LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2,
        read_packets_from_stream,
    )

    def ipv4_tcp(src, dst, sport, dport, payload=20):
        ip = struct.pack(
            ">BBHHHBBH4s4s", 0x45, 0, 20 + 20 + payload, 1, 0, 64, 6, 0,
            socket.inet_aton(src), socket.inet_aton(dst),
        )
        tcp = struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x10, 8192, 0, 0)
        return ip + tcp + b"\x00" * payload

    def one_packet_pcap(linktype, frame):
        out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
        return out + struct.pack("<IIII", 1000, 0, len(frame), len(frame)) + frame

    pkt = ipv4_tcp("10.0.0.5", "10.0.0.9", 554, 40000)
    cases = [
        ("SLL2", LINKTYPE_LINUX_SLL2,
         struct.pack(">HHIHBB", 0x0800, 0, 3, 1, 0, 6) + b"\xaa" * 8 + pkt),
        ("SLL2+802.1Q", LINKTYPE_LINUX_SLL2,
         struct.pack(">HHIHBB", 0x8100, 0, 3, 1, 0, 6) + b"\xaa" * 8
         + struct.pack(">HH", 0x0064, 0x0800) + pkt),
        ("SLL", LINKTYPE_LINUX_SLL,
         struct.pack(">HHH", 0, 1, 6) + b"\xaa" * 8 + struct.pack(">H", 0x0800) + pkt),
        ("Ethernet", LINKTYPE_ETHERNET,
         b"\x11" * 6 + b"\x22" * 6 + struct.pack(">H", 0x0800) + pkt),
    ]
    for name, linktype, frame in cases:
        gen, stats = read_packets_from_stream(
            io.BytesIO(one_packet_pcap(linktype, frame)),
        )
        got = list(gen)
        assert len(got) == 1, (
            f"{name}: parsed {len(got)} packets, skipped {stats.packets_skipped} "
            f"— a capture on this link type would see nothing"
        )
        assert got[0].src_ip == "10.0.0.5" and got[0].dst_port == 40000, (
            f"{name}: wrong fields {got[0]}"
        )
    print(f"  link types: {len(cases)} cooked/ethernet encapsulations parse")


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
        # Replay stamps alerts with PACKET time, not wall time, so a forensic
        # replay dates its findings to when the traffic happened. Dedup has to
        # be evaluated on that same clock — asking "is this suppressed right
        # now?" against a capture from months ago is a different question.
        engine = AlertEngine(cfg=AlertsCfg(dedup_window_seconds=3600.0), store=store)
        bulk_dedup = bulk_alert.dedup_key
        suppressed = engine._suppressed(bulk_dedup, bulk_alert.ts + 1.0)  # noqa: SLF001
        assert suppressed, "dedup did not suppress a same-key re-emit"
        # ...and outside the window it is not suppressed
        assert not engine._suppressed(bulk_dedup, bulk_alert.ts + 7200.0)  # noqa: SLF001
        print("  dedup: same-key re-emit suppressed within the window")

        # --- the replay clock: a capture recorded months ago must NOT be
        # reported as a storm of camera outages. This is the regression the
        # packet-timestamp clock exists to prevent.
        kinds = {a.kind for a in alerts}
        for bogus in ("camera_offline", "camera_never_seen", "capture_stalled"):
            assert bogus not in kinds, f"replay emitted bogus {bogus}: {kinds}"
        print("  replay clock: no bogus offline/never-seen/stalled alerts")

        # --- devices: camera IP is in the store and classified ---
        cam = store.get_device(mk.CAMERA_IP)
        assert cam is not None and cam.role == "camera", cam
        print(f"  devices: {mk.CAMERA_IP} role={cam.role} "
              f"packets={cam.packet_count} bytes={cam.byte_count}")

        store.close()
        _check_lan_subnets()
        _check_cooked_capture_linktypes()
        print("\nHOUND END-TO-END VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
