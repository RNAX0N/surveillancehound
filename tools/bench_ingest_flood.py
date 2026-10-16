#!/usr/bin/env python3
"""Re-derive the capture-loss figures in deploy/agent/README.md.

The README quotes PROPORTIONS of each machine's own unloaded
throughput, not absolute packet rates, and this is the harness that
produced them. Run it on your own hardware before planning from the
table.

    PYTHONPATH=src:tests ./tools/bench_ingest_flood.py [--seconds 6]

Three things about the method matter more than the result, because
each of them produced a wrong number here first:

* The load generators MUST be separate processes. In-process posting
  threads starve the very packet loop being measured, which once
  produced a reported 22s capture freeze that did not exist.
* They must come from DISTINCT source addresses. The collector caps
  concurrent connections per source at four, so same-address
  flooders measure the cap, not the flood.
* Vary ONE policy against a FIXED flood. Comparing a loaded run to an
  unloaded baseline measures the TLS handshake cost, which swamps
  everything else and tells you nothing about the policy you changed.

It also prints the unloaded parse rate. Treat that as a property of
this harness, not of a real deployment: it re-parses one capture
already in memory. Two independent reviewers measured real files on
disk at 193k and 443k pkt/s while this loop reported several million.
"""
from __future__ import annotations

import argparse
import io
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

_FLOODER = r'''
import socket, ssl, sys, time
port, secs, rotate = int(sys.argv[1]), float(sys.argv[2]), int(sys.argv[3])
base = int(sys.argv[4])
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def addr(n):
    return "127.%d.%d.%d" % ((n >> 16) & 0xff, (n >> 8) & 0xff,
                             (n & 0xff) or 1)
n, end = base, time.monotonic() + secs
while time.monotonic() < end:
    try:
        s = socket.socket()
        s.bind((addr(n if rotate else base), 0))
        if rotate:
            n += 1
        s.settimeout(3)
        s.connect(("127.0.0.1", port))
        w = ctx.wrap_socket(s)
        w.sendall(b"POST /ingest/v1 HTTP/1.1\r\nHost: x\r\n"
                  b"Content-Length: 16\r\n\r\n{\"a\":1}")
        w.close()
    except OSError:
        pass
'''


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seconds", type=float, default=6.0)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--flooders", type=int, default=8)
    args = ap.parse_args()

    import make_synthetic_camera_pcap as mk
    import verify_relay as V
    from surveillancehound import pcap
    from surveillancehound.ingest import IngestServer
    from surveillancehound.store import HoundStore

    raw = mk.build()
    try:
        os.sched_setaffinity(0, {0})
        pinned = True
    except (AttributeError, OSError):
        pinned = False

    def parse_for(secs: float) -> float:
        n, end = 0, time.monotonic() + secs
        while time.monotonic() < end:
            for _ in pcap.read_packets_from_stream(io.BytesIO(raw)):
                n += 1
            if time.monotonic() >= end:
                break
        return n / secs

    with tempfile.TemporaryDirectory() as td:
        script = Path(td) / "flood.py"
        script.write_text(_FLOODER)
        store = HoundStore(path=Path(td) / "bench.sqlite")
        parse_for(1.0)                       # warm up
        print(f"collector pinned to one core: {pinned}")
        base = statistics.median(
            [parse_for(args.seconds) for _ in range(args.runs)])
        print(f"unloaded parse rate (THIS HARNESS, in memory): "
              f"{base:,.0f} pkt/s\n")
        print(f"{'flood':44s} {'pkt/s':>12s} {'lost':>7s} {'refused':>9s}")
        for label, meter, rotate in (
                ("8 fixed addresses, metering off", 10_000, 0),
                ("8 fixed addresses, shipped 60/min", 60, 0),
                ("20,000 rotating addresses, shipped 60/min", 60, 1)):
            port = V._free_port()
            srv = IngestServer(
                V._collector_cfg(port, max_batches_per_minute=meter),
                store, now=time.time)
            if not srv.start():
                print(f"{label:44s}  could not start listener")
                continue
            runs = []
            for _ in range(args.runs):
                ps = [subprocess.Popen(
                    ["taskset", "-c", "1", sys.executable, str(script),
                     str(port), str(args.seconds + 1.0), str(rotate),
                     str(i + 2)], stdout=subprocess.DEVNULL)
                    for i in range(args.flooders)]
                time.sleep(0.5)
                runs.append(parse_for(args.seconds))
                for p in ps:
                    try:
                        p.wait(timeout=30)
                    except Exception:        # noqa: BLE001
                        p.kill()
            got = statistics.median(runs)
            refused = srv._httpd.rejected_overload if srv._httpd else -1
            srv.stop()
            print(f"{label:44s} {got:>12,.0f} {1 - got / base:>6.0%} "
                  f"{refused:>9,}")
        store.close()
    print("\nReport the LOST column, not the pkt/s. Absolute rates here "
          "are a property of this loop, not of your capture.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
