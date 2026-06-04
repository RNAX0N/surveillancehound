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

  hound baselines <config.toml> [--camera IP | --reset IP | --reset-all]
      Inspect learned per-camera baselines, or wipe them. NOTE: stop the
      daemon before --reset — it holds Welford state in RAM.

  hound snapshots <config.toml> [--limit N]
      List per-alert pcap snapshots saved by the snapshot ring buffer.

  hound prune <config.toml> [--flows-days N] [--alerts-days N]
      Delete old rows + VACUUM. Defaults to flows older than 30 days,
      alerts older than 90 days. Skip whichever you don't want pruned.

  hound web <config.toml> [--host H] [--port P]
      Serve the local dashboard (read-only). Defaults to 127.0.0.1:8080
      or to whatever [web] in the config specifies.

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


def cmd_baselines(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    store = HoundStore(path=cfg.store.path)
    try:
        if args.reset_all or args.reset:
            target = None if args.reset_all else args.reset
            n = store.delete_baselines(camera_ip=target)
            label = "all cameras" if args.reset_all else target
            print(f"deleted {n} baseline buckets for {label}")
            print(
                "NOTE: stop the daemon first — it holds Welford state in RAM "
                "and would re-upsert on the next flush.",
            )
            return 0
        weekday_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        # Welford rows
        rows = store.load_baselines(camera_ip=args.camera)
        from itertools import groupby
        if rows:
            print("=== Welford baselines (per-feature μ/σ) ===")
            for (ip, wd, h), group in groupby(
                rows, key=lambda r: (r.camera_ip, r.weekday, r.hour),
            ):
                print(f"\n{ip}  {weekday_names[wd]} {h:02d}:00")
                for r in group:
                    std = (r.m2 / (r.n - 1)) ** 0.5 if r.n >= 2 else 0.0
                    print(
                        f"  {r.feature:20s}  n={r.n:5d}  "
                        f"μ={r.mean:14.2f}  σ={std:14.2f}",
                    )
        # HS-Forest rows
        forests = store.load_forests(camera_ip=args.camera)
        if forests:
            print("\n=== HS-Forest baselines (joint multivariate model) ===")
            for f in forests:
                ready = "armed" if f.has_reference else f"warming ({f.n_samples_in_window} in current window)"
                print(
                    f"  {f.camera_ip}  {weekday_names[f.weekday]} {f.hour:02d}:00  "
                    f"samples={f.n_samples:5d}  status={ready}  "
                    f"blob={len(f.blob)}B",
                )
        if not rows and not forests:
            print("no baselines yet "
                  "(enable [baseline].enabled and run the daemon for a while)")
            return 0
    finally:
        store.close()
    return 0


def cmd_snapshots(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    store = HoundStore(path=cfg.store.path)
    try:
        rows = store.list_snapshots(limit=args.limit)
        if not rows:
            print("no snapshots yet "
                  "(enable [snapshot].enabled and trigger an alert >= "
                  "[snapshot].min_severity)")
            return 0
        print(f"{'ts':19s} {'alert#':>7s} {'camera':18s} "
              f"{'packets':>8s} {'bytes':>12s}  path")
        for s in rows:
            ts = datetime.fromtimestamp(s.created_at).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"{ts} {s.alert_id:7d} {s.camera_ip:18s} "
                f"{s.packet_count:8d} {s.byte_count:12d}  {s.path}",
            )
    finally:
        store.close()
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    store = HoundStore(path=cfg.store.path)
    try:
        now = time.time()
        kwargs = {}
        if args.flows_days is not None:
            kwargs["flows_older_than"] = now - args.flows_days * 86400.0
        if args.alerts_days is not None:
            kwargs["alerts_older_than"] = now - args.alerts_days * 86400.0
        if args.notifications_days is not None:
            kwargs["notifications_older_than"] = (
                now - args.notifications_days * 86400.0
            )
        if not kwargs:
            sys.exit(
                "no cutoff given. specify --flows-days, --alerts-days, "
                "and/or --notifications-days",
            )
        deleted = store.prune(**kwargs)
        if not any(deleted.values()):
            print("nothing to prune")
        else:
            for table, n in deleted.items():
                print(f"deleted {n:>8d} rows from {table}")
    finally:
        store.close()
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    if args.host:
        cfg.web.host = args.host
    if args.port:
        cfg.web.port = args.port
    # the web server is independent of [web].enabled — running this command
    # IS the explicit operator opt-in. The config flag just controls whether
    # `hound run` should auto-launch one alongside the daemon (future).
    from surveillancehound.web import serve
    serve(cfg)
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
    print(f"  baseline: enabled={cfg.baseline.enabled} "
          f"z={cfg.baseline.z_threshold} "
          f"min_samples={cfg.baseline.min_samples} "
          f"flush_every={cfg.baseline.flush_interval_seconds:.0f}s")
    print(f"  snapshot: enabled={cfg.snapshot.enabled} "
          f"window={cfg.snapshot.window_seconds:.0f}s "
          f"min_severity={cfg.snapshot.min_severity} "
          f"snaplen={cfg.snapshot.snaplen} "
          f"buf={cfg.snapshot.max_buffer_bytes//1024//1024}MiB")
    print(f"  web: enabled={cfg.web.enabled} "
          f"bind={cfg.web.host}:{cfg.web.port} "
          f"poll={cfg.web.poll_interval_seconds:.1f}s")
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

    p_b = sub.add_parser("baselines", help="inspect or reset learned baselines")
    p_b.add_argument("config")
    p_b.add_argument("--camera", help="filter to one camera IP")
    p_b.add_argument("--reset", help="wipe baselines for one camera IP")
    p_b.add_argument("--reset-all", action="store_true",
                     help="wipe ALL baselines (stop the daemon first)")
    p_b.set_defaults(func=cmd_baselines)

    p_s = sub.add_parser("snapshots", help="list pcap snapshots from alerts")
    p_s.add_argument("config")
    p_s.add_argument("--limit", type=int, default=50)
    p_s.set_defaults(func=cmd_snapshots)

    p_p = sub.add_parser("prune", help="delete old rows + VACUUM")
    p_p.add_argument("config")
    p_p.add_argument("--flows-days", type=float,
                     help="delete flow rows older than N days")
    p_p.add_argument("--alerts-days", type=float,
                     help="delete alert rows older than N days")
    p_p.add_argument("--notifications-days", type=float,
                     help="delete notification audit rows older than N days")
    p_p.set_defaults(func=cmd_prune)

    p_w = sub.add_parser("web", help="serve the local dashboard")
    p_w.add_argument("config")
    p_w.add_argument("--host", default=None,
                     help="bind address (default from [web].host, 127.0.0.1)")
    p_w.add_argument("--port", type=int, default=None,
                     help="bind port (default from [web].port, 8080)")
    p_w.set_defaults(func=cmd_web)

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
