"""Run ONLY the collector's ingest listener — no packet capture.

Not the supported deployment path. `hound run` with
`[relay] mode = "collector"` is, and it hosts this listener inside the
daemon alongside the capture it also does.

This exists for the case where a host should collect but cannot
capture: no `CAP_NET_RAW`, no tcpdump, or simply no interface worth
watching. The daemon insists on a capture source, so it cannot be used
that way. It is also what the first real-hardware relay test was run
against, which is why it is in the tree rather than in someone's
scratch directory.

It serves the real `IngestServer` against a real `HoundStore`, so
admission control, signature checking, validation, quotas and the
`remote_*` tables all behave exactly as in the daemon. What you do NOT
get is anything the daemon owns: no local capture, and NO NOTIFICATION
DISPATCH — relayed alerts are stored and visible to `hound alerts` and
the web UI, but nothing is sent anywhere. Do not use this as a
production collector for that reason alone.

    PYTHONPATH=src python3 tools/run_collector.py /path/to/collector.toml
"""
import signal, sys, time
sys.path.insert(0, "src")
from pathlib import Path
from surveillancehound.config import load as load_config
from surveillancehound.ingest import IngestServer
from surveillancehound.store import HoundStore

cfg = load_config(Path(sys.argv[1]))
store = HoundStore(path=cfg.store.path)
srv = IngestServer(cfg.relay, store)
if not srv.start():
    sys.exit("collector failed to start")
print(f"collector listening on {cfg.relay.listen_host}:{cfg.relay.listen_port}",
      flush=True)
stop = {"now": False}
signal.signal(signal.SIGTERM, lambda *a: stop.__setitem__("now", True))
signal.signal(signal.SIGINT, lambda *a: stop.__setitem__("now", True))
while not stop["now"]:
    time.sleep(0.5)
srv.stop(); store.close()
print("collector stopped", flush=True)
