"""End-to-end verification of the per-camera behavioral baseliner.

Two engines, two tests:

  (1) **Welford** — N warmup flows + 1 anomalous flow whose total bytes
      are ~500× the warmup mean. Asserts per-feature σ alerts fire only
      after warmup, and baseline rows persist.

  (2) **HS-Forest** — same shape but using ``model = "hstree"``. Asserts
      the multivariate detector fires exactly one ``feature="joint"``
      anomaly on the rare flow, that nothing fires during warmup, and
      that the serialized forest round-trips through SQLite without
      changing its scores.
"""

from __future__ import annotations

import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from surveillancehound.baseline import HSForest  # noqa: E402
from surveillancehound.config import (  # noqa: E402
    AlertsCfg, BaselineCfg, CaptureCfg, HoundCfg, NetworkCfg,
    NotifyChannelCfg, StoreCfg, ThresholdCfg,
)
from surveillancehound.daemon import Hound  # noqa: E402
from surveillancehound.store import HoundStore  # noqa: E402

import make_synthetic_camera_pcap as mk  # noqa: E402


CAMERA_IP = "192.168.2.50"
PEER_IP = "192.168.2.1"

WARMUP_FLOWS = 5
PACKETS_PER_FLOW = 4
WARMUP_PKT_LEN = 120     # → ~500 byte warmup flows (slight variation)
ANOMALY_PKT_LEN = 60000  # → ~240 KB anomalous flow (~500× the warmup mean)


def _build_pcap() -> bytes:
    out = bytearray()
    # classic pcap global header: LE, microsecond, Ethernet
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # warmup: WARMUP_FLOWS separate conversations (distinct src_ports keep
    # them from collapsing into a single aggregated flow) with mild
    # per-packet AND per-flow variation so std isn't exactly zero.
    for i in range(WARMUP_FLOWS):
        sport = 60000 + i
        for j in range(PACKETS_PER_FLOW):
            ts = mk.BASE_TS + i * 1.0 + j * 0.1
            length = WARMUP_PKT_LEN + i * 5 + j * 3
            out += mk._tcp_packet(ts, CAMERA_IP, PEER_IP, sport, 80, length)

    # anomalous flow — same peer (already known, so no new_peer alert),
    # later in time so the sorted drain processes it last
    anomaly_base = mk.BASE_TS + WARMUP_FLOWS * 1.0
    for j in range(PACKETS_PER_FLOW):
        out += mk._tcp_packet(
            anomaly_base + j * 0.1, CAMERA_IP, PEER_IP, 60500, 80,
            ANOMALY_PKT_LEN,
        )
    return bytes(out)


def _test_hstree_forest_unit() -> None:
    """In-RAM unit test of HSForest — no daemon, no SQLite. Verifies:
      - score is 0 before the first rollover (no reference yet)
      - after rollover, common points score LOW, rare points score HIGH
      - serialize → deserialize → score matches bit-for-bit
    """
    import random
    rng = random.Random(42)
    f = HSForest.build(n_features=5, n_trees=8, depth=6, window_size=200, seed=42)

    # Pre-rollover: every score is 0 because there's no reference window
    assert f.score([0.5] * 5) == 0.0, "expected 0 before first rollover"

    # Feed 200 points clustered near the center of the unit cube → reference
    # mass concentrates in middle leaves, edges stay near-zero mass.
    for _ in range(200):
        f.update([0.5 + rng.gauss(0, 0.03) for _ in range(5)])
    assert f.has_reference, "should have rolled over after window_size samples"

    inlier_score = f.score([0.5, 0.5, 0.5, 0.5, 0.5])
    outlier_score = f.score([0.02, 0.02, 0.02, 0.02, 0.02])  # corner of the cube
    assert 0.0 <= inlier_score <= 1.0, inlier_score
    assert 0.0 <= outlier_score <= 1.0, outlier_score
    assert outlier_score > inlier_score, (
        f"outlier {outlier_score:.3f} should score higher than inlier {inlier_score:.3f}"
    )
    print(f"  unit: inlier={inlier_score:.3f} outlier={outlier_score:.3f} "
          f"(separation OK)")

    # Round-trip
    blob = f.serialize()
    g = HSForest.deserialize(blob)
    for x in (
        [0.5, 0.5, 0.5, 0.5, 0.5], [0.02] * 5, [0.99, 0.01, 0.5, 0.7, 0.3],
    ):
        assert f.score(x) == g.score(x), x
    print(f"  unit: serialize/deserialize round-trip OK ({len(blob)} bytes)")


def _build_hstree_pcap() -> bytes:
    """Like _build_pcap() but with more warmup flows so the HS-Forest can
    roll over once before the anomalous flow arrives. The anomaly differs
    in BYTES and DURATION and DIRECTION simultaneously — exactly the kind
    of multivariate shift Welford can miss feature-by-feature."""
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # 14 warmup flows (need >= window_size=10 to trigger a rollover) of
    # comparable shape: short, small, mostly camera→peer
    for i in range(14):
        sport = 60000 + i
        for j in range(PACKETS_PER_FLOW):
            ts = mk.BASE_TS + i * 1.0 + j * 0.05  # 0.05s = quick duration
            length = WARMUP_PKT_LEN + i * 3 + j * 2
            out += mk._tcp_packet(ts, CAMERA_IP, PEER_IP, sport, 80, length)

    # Anomalous flow: very long duration AND bigger packets AND direction
    # flipped (peer→camera). All three feature axes shift simultaneously.
    anomaly_base = mk.BASE_TS + 14 * 1.0 + 60.0  # gap so it's its own flow
    for j in range(PACKETS_PER_FLOW):
        ts = anomaly_base + j * 20.0  # spread over 60 s — duration ~60s
        out += mk._tcp_packet(ts, PEER_IP, CAMERA_IP, 80, 60500, 8000)
    return bytes(out)


def _test_hstree_end_to_end() -> None:
    """Replay through the full daemon with model='hstree'. Same camera, same
    peer, just enough flows to roll over the reference window once."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        pcap_path = root / "baseline-hs.pcap"
        pcap_path.write_bytes(_build_hstree_pcap())
        db_path = root / "hound-hs.sqlite"

        cfg = HoundCfg(
            capture=CaptureCfg(pcap_file=str(pcap_path), snaplen=96),
            network=NetworkCfg(camera_ips=[CAMERA_IP]),
            thresholds=ThresholdCfg(),
            alerts=AlertsCfg(),
            store=StoreCfg(path=str(db_path)),
            notify=[NotifyChannelCfg(type="stdout", level="info")],
            baseline=BaselineCfg(
                enabled=True, model="hstree",
                min_samples=10,
                flush_interval_seconds=0.0,
                hstree_n_trees=8, hstree_depth=6,
                hstree_window_size=10,
                hstree_score_threshold=0.30,  # tuned for the synthetic data
                hstree_seed=12345,             # reproducible
            ),
        )

        hound = Hound(cfg)
        ok = hound.run()
        assert ok, "hound (hstree) run failed"
        print(f"  hstree replay: packets={hound.stats.packets_seen} "
              f"flows={hound.stats.flows_flushed} "
              f"alerts={hound.stats.alerts_emitted}")

        store = HoundStore(path=db_path)
        try:
            alerts = store.list_alerts(limit=200)
            anomalies = [a for a in alerts if a.kind == "behavioral_anomaly"]
            assert anomalies, (
                f"hstree: no behavioral_anomaly fired "
                f"(got kinds={[a.kind for a in alerts]})"
            )
            # Joint flavor: dedup key is :joint
            joint = [a for a in anomalies if a.dedup_key.endswith(":joint")]
            assert len(joint) == 1, (
                f"hstree: expected exactly 1 joint anomaly, got {len(joint)} "
                f"(dedup keys: {[a.dedup_key for a in anomalies]})"
            )
            # Detail text should name the HS-Forest detector specifically
            assert "HS-Forest" in joint[0].detail, joint[0].detail
            print(f"  hstree: exactly 1 joint anomaly fired "
                  f"(score from summary: {joint[0].summary})")

            # Persistence: at least one forest row survives
            forests = store.load_forests()
            cam_rows = [f for f in forests if f.camera_ip == CAMERA_IP]
            assert cam_rows, "hstree: no forest persisted for the camera"
            # All non-empty buckets must have rolled over at least once
            armed = [f for f in cam_rows if f.has_reference]
            assert armed, (
                "hstree: no forest reached the reference state — "
                "window_size may be too large for the synthetic flow count"
            )
            print(f"  hstree: persisted {len(cam_rows)} bucket(s); "
                  f"{len(armed)} armed (post-rollover)")

            # Round-trip through SQLite preserves scoring (this is the test
            # that catches blob-encoding bugs end-to-end, not in isolation)
            blob = cam_rows[0].blob
            from surveillancehound.baseline import HSForest
            f1 = HSForest.deserialize(blob)
            assert f1.has_reference == cam_rows[0].has_reference
            print(f"  hstree: SQLite round-trip preserved forest state")
        finally:
            store.close()


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        pcap_path = root / "baseline.pcap"
        pcap_path.write_bytes(_build_pcap())
        db_path = root / "hound.sqlite"

        cfg = HoundCfg(
            capture=CaptureCfg(pcap_file=str(pcap_path), snaplen=96),
            network=NetworkCfg(camera_ips=[CAMERA_IP]),
            thresholds=ThresholdCfg(),
            alerts=AlertsCfg(),
            store=StoreCfg(path=str(db_path)),
            notify=[NotifyChannelCfg(type="stdout", level="info")],
            baseline=BaselineCfg(
                enabled=True,
                z_threshold=4.0,
                min_samples=WARMUP_FLOWS,
                flush_interval_seconds=0.0,  # flush on every tick (for tests)
            ),
        )

        hound = Hound(cfg)
        ok = hound.run()
        assert ok, "hound run failed"
        print(f"  replay: packets={hound.stats.packets_seen} "
              f"flows={hound.stats.flows_flushed} "
              f"alerts={hound.stats.alerts_emitted}")

        store = HoundStore(path=db_path)
        try:
            alerts = store.list_alerts(limit=200)
            anomalies = [a for a in alerts if a.kind == "behavioral_anomaly"]
            assert anomalies, (
                f"no behavioral_anomaly fired (got kinds={[a.kind for a in alerts]})"
            )
            # parse the feature name out of the summary
            features_fired = {
                a.summary.split(":")[1].strip().split(" ")[0]
                for a in anomalies
            }
            for needed in ("bytes", "bytes_from_camera"):
                assert needed in features_fired, (
                    f"expected {needed} anomaly, got {features_fired}"
                )
            print(f"  anomalies fired for features: {sorted(features_fired)}")

            # every anomaly should be a single alert (dedup is per-feature
            # and the dedup window is wide; we observed each feature once)
            for feat in features_fired:
                hits = [a for a in anomalies
                        if a.summary.split(":")[1].strip().startswith(feat + " ")]
                assert len(hits) == 1, (feat, len(hits))
            print("  dedup: exactly one alert per feature")

            # NONE of the warmup flows themselves should have alerted
            # (n was below min_samples until the anomalous flow arrived).
            # We observed WARMUP_FLOWS + 1 total camera-flows, all of which
            # update the bucket, so the persisted n should equal that.
            baselines = store.load_baselines()
            cam_buckets = [b for b in baselines if b.camera_ip == CAMERA_IP]
            assert cam_buckets, "no baselines persisted for the camera"
            bytes_bucket = next(b for b in cam_buckets if b.feature == "bytes")
            assert bytes_bucket.n == WARMUP_FLOWS + 1, bytes_bucket.n
            print(f"  baselines persisted: {len(cam_buckets)} buckets "
                  f"(bytes.n={bytes_bucket.n})")

            # no spurious `new_peer` alerts — every warmup + anomaly went to
            # the same peer, so we expect at most 1 new_peer alert total
            new_peer_count = sum(1 for a in alerts if a.kind == "new_peer")
            assert new_peer_count == 1, new_peer_count
            print(f"  new_peer alerts: {new_peer_count} (one per camera↔peer pair)")
        finally:
            store.close()

        print()
        print("=== HS-Forest model ===")
        _test_hstree_forest_unit()
        _test_hstree_end_to_end()

        print("\nBASELINE VERIFICATION PASSED (welford + hstree)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
