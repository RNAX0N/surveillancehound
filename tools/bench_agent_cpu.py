"""Measure the agent's CPU cost on the paths that run continuously.

Run this ON THE BOX you intend to deploy to. The absolute numbers are
meaningless anywhere else — a developer workstation is several times
faster per core than a typical NVR or firewall appliance, and the
question this answers is "what will this cost me on THAT hardware".

    PYTHONPATH=src python3 tools/bench_agent_cpu.py [--tick]

Three measurements, in order of how much they matter:

  1. steady state -- CPU seconds per million packets through the
     per-packet path (parse, flow aggregate, device classify, uptime
     touch). This is the one that runs 24/7, and it is the number to
     care about. The output converts it to "percent of one core" at
     several sustained packet rates.
  2. the spool drain -- 15,427 batches in a full 64 MiB spool, the
     backlog of a long collector outage. This path once cost 682 ms
     of CPU PER ACK because it rewrote the whole file each time;
     the figure is printed alongside for contrast.
  3. --tick -- worst case tick: a completely full 50k flow table
     evicted and classified in one go. Amortised in practice, since
     ticks are 5 seconds apart and evict a fraction of the table.

Estimating your own load: packets/sec is roughly
`total_bitrate_bits / (8 * average_packet_bytes)`. Sixteen cameras at
4 Mbit/s with 1400-byte packets is about 5,700 packets/sec.

If the number is uncomfortable, the lever is `[capture] bpf` — a
Berkeley Packet Filter is applied by tcpdump in the kernel, so
filtered-out traffic never reaches this process at all. Narrowing the
capture to the camera segment is far cheaper than any optimisation
inside the pipeline.

Reports CPU time (time.process_time), not wall clock.
"""
from __future__ import annotations

import os
import struct
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, "tests")

from surveillancehound import pcap
from surveillancehound.config import NetworkCfg, ThresholdCfg, UptimeCfg
from surveillancehound.discover import DeviceClassifier
from surveillancehound.flows import FlowAggregator
from surveillancehound.relay import Spool
from surveillancehound.uptime import UptimeTracker

BASE = datetime(2026, 5, 12, 14, 0, 0, tzinfo=timezone.utc).timestamp()


def _eth():
    return b"\xaa\xbb\xcc\xdd\xee\x01" + b"\xaa\xbb\xcc\xdd\xee\x02" + b"\x08\x00"


def _ip(src, dst, total_len):
    return struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, total_len & 0xFFFF, 0, 0x4000, 64, 6, 0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")))


def _tcp(sp, dp):
    return struct.pack(">HHIIBBHHH", sp, dp, 1, 1, 0x50, 0x10, 0xFFFF, 0, 0)


def _rec(ts, payload):
    sec = int(ts)
    return (struct.pack("<IIII", sec, int((ts - sec) * 1e6),
                        len(payload), len(payload)) + payload)


def make_capture(n_packets: int, n_cameras: int = 16) -> bytes:
    """A realistic surveillance segment: N cameras streaming to one NVR."""
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    ts = BASE
    for i in range(n_packets):
        cam = i % n_cameras
        src = f"192.168.1.{50 + cam}"
        # RTSP stream toward the NVR, with an occasional reverse packet
        if i % 7 == 0:
            body = (_eth() + _ip("192.168.1.10", src, 120)
                    + _tcp(40000 + cam, 554))
        else:
            body = (_eth() + _ip(src, "192.168.1.10", 1400)
                    + _tcp(554, 40000 + cam))
        out.append(_rec(ts, body))
        ts += 0.001
    return b"".join(out)


def bench_steady_state(n_packets=200_000):
    blob = make_capture(n_packets)
    path = Path(tempfile.mkdtemp()) / "bench.pcap"
    path.write_bytes(blob)

    cameras = [f"192.168.1.{50 + i}" for i in range(16)]
    net = NetworkCfg(camera_ips=cameras, nvr_ips=["192.168.1.10"])
    disco = DeviceClassifier(network=net)
    flows = FlowAggregator()
    up = UptimeTracker(UptimeCfg(), ThresholdCfg(), replay=False)

    packets, _stats = pcap.read_packets(path)
    t0 = time.process_time()
    seen = 0
    for pkt in packets:
        disco.observe(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port)
        flows.ingest(pkt)
        up.touch(pkt.src_ip, pkt.ts)
        up.touch(pkt.dst_ip, pkt.ts)
        seen += 1
    cpu = time.process_time() - t0
    return seen, cpu, path.stat().st_size


def bench_spool_drain(n_batches=15_427, body_bytes=4096):
    d = Path(tempfile.mkdtemp())
    sp = Spool(d, 64 * 1024 * 1024, 86400.0)
    body = b'{"x":"' + b"p" * (body_bytes - 10) + b'"}'
    now = BASE
    t0 = time.process_time()
    for i in range(1, n_batches + 1):
        sp.append(i, body, now)
    append_cpu = time.process_time() - t0
    size_before = sp.path.stat().st_size

    t0 = time.process_time()
    drained = 0
    while True:
        p = sp.pending(now)
        if not p:
            break
        for seq, _ in p:
            sp.ack(seq)
            drained += 1
    drain_cpu = time.process_time() - t0
    return drained, append_cpu, drain_cpu, size_before, sp.path.stat().st_size


REPEATS = 5


if __name__ == "__main__":
    import statistics

    print("=== steady state: full packet path ===")
    # REPEAT and report the spread. A single run of this is not worth
    # acting on: measured on an otherwise-busy 28-core box, five
    # consecutive runs gave 7.71, 7.64, 5.67, 3.84 and 3.23 us/packet
    # as the machine's load average fell away under them. The best
    # run is the least contaminated estimate; a wide spread means
    # something else was competing and the box was not idle.
    runs = []
    for _ in range(REPEATS):
        n, cpu, nbytes = bench_steady_state()
        runs.append(cpu / n * 1e6)
    best, med, worst = min(runs), statistics.median(runs), max(runs)
    print(f"  {n:,} packets, {nbytes/1e6:.1f} MB capture, "
          f"{REPEATS} runs")
    print(f"  best {best:.2f} / median {med:.2f} / worst {worst:.2f} "
          f"us/packet")
    if worst > best * 1.25:
        print(f"  !! {worst/best:.1f}x spread — this box was NOT idle. "
              f"Re-run it quiet; use the best figure meanwhile.")
    print(f"  = {best:.2f} CPU-seconds per million packets (best)")
    for pps in (1_000, 5_000, 20_000, 100_000):
        print(f"    at {pps:>7,} packets/sec sustained: "
              f"{best/1e6*pps*100:.1f}% of one core")

    print()
    print("=== spool drain (the old 175 CPU-minute case) ===")
    d, ap, dr, before, after = bench_spool_drain()
    print(f"  {d:,} batches spooled, file {before/1e6:.1f} MB")
    print(f"  append:  {ap:.2f} CPU-seconds")
    print(f"  drain:   {dr:.2f} CPU-seconds  ({dr/d*1e6:.1f} us/ack)")
    print(f"  file after drain: {after/1024:.1f} KB")
    print(f"  old behaviour (measured 682 ms/ack): "
          f"{d*0.682/60:.0f} CPU-minutes")
    print(f"  speedup: {d*0.682/dr:,.0f}x")


def bench_tick():
    """Worst-case tick: a full flow table evicted and classified at once."""
    from surveillancehound.classify import FlowClassifier
    from surveillancehound.config import NetworkCfg, ThresholdCfg
    from surveillancehound.discover import DeviceClassifier
    from surveillancehound.flows import FlowAggregator
    from surveillancehound.pcap import Packet

    ips = [f"192.168.{i // 250}.{i % 250}" for i in range(50_000)]
    net = NetworkCfg(camera_ips=ips[:16], nvr_ips=["10.0.0.10"])
    disco = DeviceClassifier(network=net)
    thr = ThresholdCfg()
    clf = FlowClassifier(network=net, thresholds=thr, devices=disco)
    flows = FlowAggregator()
    ts = BASE
    for i, ip in enumerate(ips):
        flows.ingest(Packet(ts=ts, src_ip=ip, dst_ip="10.0.0.10",
                            proto="tcp", src_port=554,
                            dst_port=40000 + (i % 1000),
                            length=1400, tcp_flags="A"))
    t0 = time.process_time()
    n = 0
    for fl in flows.evict_idle(ts + 10_000, 30.0):
        clf.classify(fl)
        n += 1
    cpu = time.process_time() - t0
    return n, cpu


if __name__ == "__main__" and "--tick" in sys.argv:
    print()
    print("=== worst-case tick: full 50k flow table ===")
    n, cpu = bench_tick()
    print(f"  {n:,} flows evicted + classified in {cpu:.3f} CPU-seconds")
    print(f"  = {cpu/max(n,1)*1e6:.1f} us/flow")
