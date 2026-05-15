"""SurveillanceHound CLI — `hound`.

Subcommands:

  hound run <config.toml>
      Start the always-running monitor. Live capture if [capture].interface is
      set; offline replay if [capture].pcap_file is set. SIGINT / SIGTERM stops
      it cleanly (drains and persists all in-RAM flows first).

  hound replay <config.toml>
      Alias for `run` — explicit when the config points at a pcap_file.

  hound alerts <config.toml> [--limit N] [--since SECS]
      Print the most recent alerts from the store.

  hound flows <config.toml> [--limit N] [--class CLASS]
      Print recent flows from the store. --class filters by classification.

  hound devices <config.toml>
      Print every device the daemon has observed.

  hound config-check <config.toml>
      Parse + validate the config, print the resolved settings, and exit.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

from surveillancehound.config import HoundCfg, load
from surveillancehound.daemon import Hound
from surveillancehound.store import HoundStore


def _cfg(path: str) -> HoundCfg:
    p = Path(path)
    if not p.is_file():
        sys.exit(f"config not found: {path}")
    return load(p)


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    hound = Hound(cfg)
    hound.install_signal_handlers()
    ok = hound.run()
    return 0 if ok else 1


def cmd_alerts(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    store = HoundStore(path=cfg.store.path)
    try:
        cutoff = time.time() - args.since if args.since else 0.0
        for a in store.list_alerts(limit=args.limit):
            if a.ts < cutoff:
                continue
            ts = datetime.fromtimestamp(a.ts).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"{ts}  [{a.severity:8s}] {a.kind:24s} {a.device_ip:18s} "
                f"{a.summary}"
            )
            if a.detail and args.verbose:
                print(f"    {a.detail}")
            if a.notified_channels and args.verbose:
                print(f"    notified: {a.notified_channels}")
    finally:
        store.close()
    return 0


def cmd_flows(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    store = HoundStore(path=cfg.store.path)
    try:
        rows = store.recent_flows(limit=args.limit, classification=args.cls)
        if not rows:
            print("no flows yet")
            return 0
        for r in rows:
            ts = datetime.fromtimestamp(r.last_seen).strftime("%H:%M:%S")
            print(
                f"{ts}  {r.src_ip}:{r.src_port} -> {r.dst_ip}:{r.dst_port} "
                f"[{r.proto}]  {r.packets}p {r.bytes}B  "
                f"to_cam={r.bytes_to_camera}B from_cam={r.bytes_from_camera}B  "
                f"<{r.classification}>"
            )
    finally:
        store.close()
    return 0


def cmd_devices(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    store = HoundStore(path=cfg.store.path)
    try:
        rows = store.list_devices()
        if not rows:
            print("no devices observed yet")
            return 0
        print(f"{'IP':18s} {'role':8s} {'first seen':19s} {'last seen':19s} "
              f"{'packets':>10s} {'bytes':>12s}")
        for d in rows:
            print(
                f"{d.ip:18s} {d.role:8s} "
                f"{datetime.fromtimestamp(d.first_seen):%Y-%m-%d %H:%M:%S} "
                f"{datetime.fromtimestamp(d.last_seen):%Y-%m-%d %H:%M:%S} "
                f"{d.packet_count:10d} {d.byte_count:12d}"
            )
    finally:
        store.close()
    return 0


def cmd_config_check(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    print(f"config: {args.config}")
    print(f"  capture: interface={cfg.capture.interface!r} "
          f"pcap_file={cfg.capture.pcap_file!r} bpf={cfg.capture.bpf!r}")
    print(f"  network: cameras={cfg.network.camera_ips} "
          f"subnets={cfg.network.camera_subnets} nvrs={cfg.network.nvr_ips}")
    print(f"  thresholds: bulk_inbound={cfg.thresholds.bulk_inbound_bytes:,} "
          f"long_lived={cfg.thresholds.long_lived_seconds:.0f}s "
          f"silence={cfg.thresholds.silence_seconds:.0f}s "
          f"flow_ttl={cfg.thresholds.flow_ttl_seconds:.0f}s")
    print(f"  store: {cfg.store.path}")
    print(f"  notify ({len(cfg.notify)} channel(s)):")
    for n in cfg.notify:
        extra = ""
        if n.path:
            extra = f" path={n.path}"
        elif n.url:
            extra = f" url={n.url}"
        print(f"    [{n.level:8s}] {n.type}{extra}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hound", description="SurveillanceHound CLI")
    p.add_argument("--verbose", "-v", action="store_true", help="DEBUG logging")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="start the always-running monitor")
    p_run.add_argument("config")
    p_run.set_defaults(func=cmd_run)

    p_replay = sub.add_parser(
        "replay", help="replay a pcap file (alias for `run` with pcap_file set)"
    )
    p_replay.add_argument("config")
    p_replay.set_defaults(func=cmd_run)

    p_a = sub.add_parser("alerts", help="show recent alerts")
    p_a.add_argument("config")
    p_a.add_argument("--limit", type=int, default=50)
    p_a.add_argument("--since", type=float, default=0.0,
                     help="only alerts newer than N seconds ago")
    p_a.set_defaults(func=cmd_alerts)

    p_f = sub.add_parser("flows", help="show recent flows")
    p_f.add_argument("config")
    p_f.add_argument("--limit", type=int, default=50)
    p_f.add_argument("--class", dest="cls", help="filter by classification")
    p_f.set_defaults(func=cmd_flows)

    p_d = sub.add_parser("devices", help="show observed devices")
    p_d.add_argument("config")
    p_d.set_defaults(func=cmd_devices)

    p_cc = sub.add_parser(
        "config-check", help="parse + validate the config and exit"
    )
    p_cc.add_argument("config")
    p_cc.set_defaults(func=cmd_config_check)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
