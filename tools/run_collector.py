"""Stand up just the collector's ingest listener, no packet capture.

The daemon normally hosts this, but it needs a capture source and
CAP_NET_RAW. This box is only playing collector for the test, so run
the real IngestServer against a real store and nothing else.
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
