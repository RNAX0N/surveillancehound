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

  hound uptime <config.toml> [--window SECONDS] [--outages]
      Per-camera liveness and availability over a window (default
      [uptime].report_window_seconds, 24h). --outages prints the downtime
      history instead of the summary table. Availability is computed over
      time the monitor was actually watching, so a stopped daemon is never
      charged to a camera as downtime.

  hound export <config.toml> [--window SECONDS] [--limit N]
      Dump the dashboard's data as one JSON document on stdout. For
      front-ends that cannot reach the built-in web server — notably the
      OPNsense plugin, whose pages run under a Content-Security-Policy
      that blocks cross-origin iframes.

  hound sensors <config.toml> [--forget ID]
      Relay sensors this collector knows about: whether each is still
      reporting, its clock skew, and how much it has sent.

  hound relay <config.toml>
      Relay health. On an agent: spool depth, last successful push, last
      error — it reads the spool, not the network, so it still answers when
      the link is down. On a collector: the TLS fingerprint to pin.

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
import json
import logging
import sqlite3
import sys
import time
import tomllib
from datetime import datetime
from pathlib import Path

from surveillancehound import config
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
    store = _ro_store(cfg)
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
    store = _ro_store(cfg)
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
    store = _ro_store(cfg)
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


def _dur(seconds: float) -> str:
    """Compact duration for table cells — '3d 4h', '12m', '45s'."""
    s = int(max(0.0, seconds))
    if s == 0:
        # "<1s", not "-". `hound sensors` prints `_dur(age) + " ago"`,
        # so a sensor that reported half a second ago read "- ago",
        # which looks like missing data rather than the freshest
        # possible contact.
        return "<1s" if seconds > 0 else "-"
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{s // 86400}d {(s % 86400) // 3600}h"


_PASSIVE_NOTE = (
    "Uptime is inferred from traffic observed on the monitored interface, "
    "not from active probing.\nA camera that is powered but no longer "
    "visible to this sensor reads the same as one that is off."
)


# The daemon ticks every 5s, so a heartbeat older than this means the
# process is gone, not merely idle. Reader processes cannot contact the
# daemon, so this is the only way to tell.
_DAEMON_ALIVE_WINDOW_S = 30.0


def _monitor_health(store, cfg, now: float) -> tuple[bool, bool, float]:
    """(daemon_alive, capture_blind, last_packet_ts), for readers.

    Liveness comes from the heartbeat's `updated_at`, NOT from whether the
    monitor session is open. A capture stall deliberately CLOSES the
    session so blind time is excluded from availability, which would
    otherwise make a daemon that is very much running — just blind —
    report as "stopped", in precisely the situation where the operator
    most needs to be told the truth.
    """
    hb_packet, hb_updated = store.heartbeat()
    alive = hb_updated > 0.0 and (now - hb_updated) < _DAEMON_ALIVE_WINDOW_S
    last_activity = hb_packet or store.latest_device_activity()
    stall_window = cfg.uptime.capture_stall_seconds
    blind = bool(
        alive and stall_window > 0 and last_activity > 0.0
        and (now - last_activity) > stall_window
    )
    return alive, blind, last_activity


def cmd_uptime(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    # `is not None`, not truthiness — `--window 0` is a real request, not an
    # omitted flag
    window = (
        args.window if args.window is not None
        else cfg.uptime.report_window_seconds
    )
    now = time.time()
    store = _ro_store(cfg)
    try:
        session = store.current_monitor_session()
        if session is None:
            print("no monitor session recorded yet — has the daemon run?")
        else:
            alive, blind, last_activity = _monitor_health(store, cfg, now)
            if not alive:
                state = "NOT RUNNING"
            elif blind:
                state = "RUNNING BUT BLIND (capture stalled)"
            else:
                state = "watching"
            seen = (
                f"last packet {_dur(now - last_activity)} ago"
                if last_activity > 0 else "no packets yet"
            )
            print(
                f"monitor: {state}"
                f"  ·  source {session.source!r}"
                f"  ·  since "
                f"{datetime.fromtimestamp(session.started_at):%Y-%m-%d %H:%M:%S}"
                f"  ·  {seen}"
            )

        if args.outages:
            # Local AND relayed. This read `list_outages` only, so on a
            # collector — whose own [network] often has no cameras at
            # all, because the cameras sit behind the NVR — it printed
            # "no outages" while relayed sensors were reporting a
            # fleet of them. The dashboard showed both; the CLI showed
            # one and said nothing about it.
            local = store.list_outages(since=now - window, limit=500)
            relayed = (store.list_remote_outages(since=now - window,
                                                 limit=500)
                       if cfg.relay.is_collector else [])
            if not local and not relayed:
                print(f"no outages in the last {_dur(window)}")
                return 0
            print(f"\n{'sensor':12s} {'camera':18s} {'from':19s} "
                  f"{'to':19s} {'duration':>10s}  cause")
            rows = [("local", o.camera_ip, o.down_since, o.up_at,
                     o.duration(now), o.cause) for o in local]
            # max(0, ...): `down_since` is sensor-supplied and
            # validated only up to the year 2100, so a future value
            # made this negative and `_dur` printed a bare "-" — a
            # nonsense row rendered as a tidy one.
            rows += [(r["sensor_id"], r["camera_ip"], r["down_since"],
                      r["up_at"],
                      max(0.0, (r["up_at"] or now) - r["down_since"]),
                      r["cause"]) for r in relayed]
            rows.sort(key=lambda r: r[2], reverse=True)
            for sensor, ip, down, up, dur, cause in rows:
                until = (
                    f"{datetime.fromtimestamp(up):%Y-%m-%d %H:%M:%S}"
                    if up is not None else "(ongoing)"
                )
                print(
                    f"{sensor[:12]:12s} {ip:18s} "
                    f"{datetime.fromtimestamp(down):%Y-%m-%d %H:%M:%S} "
                    f"{until:19s} {_dur(dur):>10s}  {cause}"
                )
            print(f"\n{_PASSIVE_NOTE}")
            return 0

        report = store.uptime_report(window, now)
        # Relayed cameras too, with the same stale/blind gating the
        # dashboard applies. On a collector the local report is often
        # EMPTY by design — the cameras sit behind the NVR and never
        # cross the firewall, which is the whole reason relay mode
        # exists — so "check [network] in the config" was advice to
        # fix a correct configuration while hiding the fleet that was
        # actually reporting.
        sensors = (store.list_remote_sensors()
                   if cfg.relay.is_collector else [])
        blind = [x.sensor_id for x in sensors if x.mon_blind]
        relayed = (store.remote_uptime_report(
            now, cfg.relay.sensor_timeout_seconds, blind_sensors=blind)
            if cfg.relay.is_collector else [])
        if not report and not relayed:
            if cfg.relay.is_collector:
                print("no cameras known yet — none in [network] here, and "
                      "no sensor has reported. Check `hound sensors`.")
            else:
                print("no cameras or NVRs known yet — check [network] in "
                      "the config")
            return 0
        print(f"\nwindow: last {_dur(window)}")
        print(f"{'sensor':12s} {'IP':18s} {'role':7s} {'state':11s} "
              f"{'last seen':19s} {'down for':>10s} {'outages':>8s} "
              f"{'avail':>7s}")
        for r in report:
            last = (
                f"{datetime.fromtimestamp(r.last_seen):%Y-%m-%d %H:%M:%S}"
                if r.last_seen > 0 else "never"
            )
            avail = "n/a" if r.availability is None else f"{r.availability:.2%}"
            print(
                f"{'local':12s} {r.ip:18s} {r.role:7s} {r.state:11s} "
                f"{last:19s} {_dur(r.current_downtime):>10s} "
                f"{r.outage_count:8d} {avail:>7s}"
            )
        for d in relayed:
            last = (
                f"{datetime.fromtimestamp(d['last_seen']):%Y-%m-%d %H:%M:%S}"
                if d.get("last_seen", 0) > 0 else "never"
            )
            av = d.get("availability")
            print(
                f"{d['sensor'][:12]:12s} {d['ip']:18s} "
                f"{d.get('role', 'camera'):7s} {d['state']:11s} "
                f"{last:19s} "
                f"{_dur(d.get('current_downtime') or 0.0):>10s} "
                f"{int(d.get('outage_count') or 0):8d} "
                f"{('n/a' if av is None else f'{av:.2%}'):>7s}"
            )
        if any(d.get("stale") for d in relayed):
            print("\nRows marked `unknown` come from a sensor that is not "
                  "reporting, or that says its own capture is blind. That "
                  "is a statement about the SENSOR, not the camera.")
        print(f"\n{_PASSIVE_NOTE}")
    finally:
        store.close()
    return 0


def _printable(text: str, limit: int = 300) -> str:
    """Make remote-supplied text safe to print to a terminal.

    Control characters are replaced rather than dropped so that an
    attempt to inject them is visible instead of silent.
    """
    out = "".join(
        ch if (ch.isprintable() or ch == " ") else f"\\x{ord(ch):02x}"
        for ch in str(text)[:limit]
    )
    return out


def _ro_store(cfg) -> HoundStore:
    """Open the store for a command that only reads it.

    Read-only is not a style choice here. The constructor used to
    create the file, its parent directories, the schema AND run the
    pre-release relay migration — so `hound sensors` against a missing
    path left a 188 KB database behind, and against a pre-release
    database it dropped the relayed rows it had been asked to show. A
    diagnostic must not be able to destroy what it reports on.
    """
    try:
        return HoundStore(path=cfg.store.path, readonly=True)
    except FileNotFoundError as e:
        sys.exit(str(e))
    except (OSError, sqlite3.Error) as e:
        # OSError as well as sqlite3.Error: an unreadable parent
        # directory raises PermissionError, which is neither of the
        # two originally caught, so it still reached the operator as a
        # traceback.
        sys.exit(f"cannot read store {cfg.store.path}: {e}")


def cmd_export(args: argparse.Namespace) -> int:
    """Dump the dashboard's data as one JSON document on stdout.

    This exists for front-ends that cannot reach the built-in web server.
    The OPNsense plugin is the motivating case: its pages are served under a
    Content-Security-Policy of `default-src 'self'`, so an iframe pointed at
    the dashboard's own port is a cross-origin frame and the browser blocks
    it outright. The plugin instead renders natively and asks configd to run
    this command, which keeps everything same-origin and means the UI
    inherits the firewall's own theme.

    One command returning one document, deliberately: each configd round
    trip spawns a process, so five endpoints would be five of them on every
    refresh.

    Failure is reported IN the document (status/message) and the exit code
    stays 0, unlike every other subcommand. A front-end that can only see
    stdout has no other channel: OPNsense's configd runs `script_output`
    actions with `check=True`, so a non-zero exit makes configd discard the
    output entirely and hand the caller an empty string. That is how a fresh
    install — no /usr/local/etc/hound.toml until the first Save — turned into
    "No response from the hound backend" in the dashboard tab instead of
    "save the settings first".
    """
    cfg_path = Path(args.config)
    if not cfg_path.is_file():
        json.dump(
            {
                "status": "failed",
                "message": (
                    f"no configuration at {args.config} — save the settings "
                    f"once to generate it, then start the service"
                ),
                "config_path": str(args.config),
            },
            sys.stdout,
        )
        sys.stdout.write("\n")
        return 0
    cfg = _cfg(args.config)
    window = (
        args.window if args.window is not None
        else cfg.uptime.report_window_seconds
    )
    now = time.time()
    # Read-only, and a store failure is reported IN the document like
    # every other failure here. The in-document guard covered only a
    # missing config file, so a store that was corrupt, a directory, or
    # unreadable exited non-zero with empty stdout — and configd
    # discards the output of a non-zero `script_output` action, which
    # is precisely the "No response from the hound backend" this
    # docstring claims to have fixed.
    try:
        store = HoundStore(path=cfg.store.path, readonly=True)
    except (FileNotFoundError, OSError, sqlite3.Error) as e:
        json.dump(
            {
                "status": "failed",
                "message": f"cannot read the store at {cfg.store.path}: {e}",
                "config_path": str(args.config),
            },
            sys.stdout,
        )
        sys.stdout.write("\n")
        return 0
    try:
        return _export_body(args, cfg, store, window, now)
    except (sqlite3.Error, OSError) as e:
        # IN the document, exit 0. configd discards the output of a
        # non-zero script_output action, so a traceback here reaches
        # the operator as "No response from the hound backend" — the
        # exact failure this command's in-document reporting exists to
        # prevent, and it covered only a missing config file.
        json.dump(
            {
                "status": "failed",
                "message": f"cannot read the store at {cfg.store.path}: {e}",
                "config_path": str(args.config),
            },
            sys.stdout,
        )
        sys.stdout.write("\n")
        return 0
    finally:
        store.close()


def _export_body(args, cfg, store, window, now) -> int:
    try:
        alive, blind, last_activity = _monitor_health(store, cfg, now)
        session = store.current_monitor_session()
        devices = store.list_devices()
        report = store.uptime_report(window, now)
        alerts = store.list_alerts(limit=args.limit)
        flows = store.recent_flows(limit=args.limit)
        sensors = (store.list_remote_sensors()
                   if cfg.relay.is_collector else [])
        # Gated like the API. `hound export` is the ONLY source the
        # OPNsense dashboard reads, so leaving it ungated was the half
        # of the inconsistency that actually reached an operator.
        is_collector = cfg.relay.is_collector
        # Blind sensors' rows are stale for the same reason a
        # non-reporting sensor's are: a figure from a sensor that
        # cannot see is not a current figure.
        # `mon_alive` is deliberately NOT consulted. The column defaults to
        # 0 and `monitor` is optional in a batch, so a sensor that has never
        # sent one is indistinguishable from one reporting its capture is
        # down — and treating 0 as "down" marked healthy sensors blind.
        # `mon_blind` is only ever set by a sensor that actually said so.
        #
        # NAMED `blind_sensor_ids`, not `blind`. This was `blind`, which
        # shadowed the LOCAL monitor's boolean bound from
        # `_monitor_health` twenty lines above — so the document shipped
        # `monitor.blind` as a LIST. `Boolean([])` is true in
        # JavaScript, so the OPNsense dashboard, whose only data source
        # this is, rendered "Capture stalled — the monitor is running
        # but seeing no packets" for every healthy daemon, and the real
        # stall signal could never show. A permanent false alarm and a
        # destroyed real one, from a rebound name.
        blind_sensor_ids = [x.sensor_id for x in sensors if x.mon_blind]
        remote_up = (
            store.remote_uptime_report(now, cfg.relay.sensor_timeout_seconds,
                                       blind_sensors=blind_sensor_ids)
            if is_collector else []
        )
        remote_alerts = (store.list_remote_alerts(limit=args.limit)
                         if is_collector else [])
        doc = {
            "now": now,
            "window_seconds": window,
            "evidence": "passive",
            "monitor": {
                "alive": alive,
                "blind": blind,
                "last_activity_ts": last_activity,
                "source": session.source if session else "",
                "started_at": session.started_at if session else 0.0,
            },
            "counts": {
                "devices": len(devices),
                "cameras": sum(1 for d in devices if d.role == "camera"),
                "nvrs": sum(1 for d in devices if d.role == "nvr"),
                # Counts local AND relayed, because the table below this
                # tile renders both — a count that disagrees with the
                # list under it is worse than no count. Relayed rows are
                # aged on ingested_at, our clock, so a backdated alert
                # cannot hide from the tally or inflate it.
                # A COUNT over the table, not over the page fetched
                # for the list below. Counting the page made this
                # saturate at 2x --limit: 200 of 600 at the default,
                # and the OPNsense dashboard clamps limit to 500, so
                # the "Alerts (24h)" tile under-reported precisely
                # during the flood that makes it worth reading.
                "alerts_24h": (
                    store.count_alerts_since(now - 86400)
                    + (store.count_remote_alerts_since(now - 86400)
                       if is_collector else 0)
                ),
            },
            "uptime": [dict(r.__dict__, sensor="local") for r in report],
            "remote_uptime": remote_up,
            "remote_alerts": remote_alerts,
            "sensors": [
                dict(x.__dict__,
                     reporting=(now - x.last_seen) <= cfg.relay.sensor_timeout_seconds)
                for x in sensors
            ],
            "alerts": [a.__dict__ for a in alerts],
            "devices": [d.__dict__ for d in devices],
            "flows": [dict(f.__dict__, sensor="local") for f in flows],
            # The OPNsense dashboard renders THIS document and cannot
            # reach /api/flows, so omitting relayed flows here made them
            # invisible on the collector's own platform.
            "remote_flows": (store.list_remote_flows(limit=args.limit)
                             if is_collector else []),
        }
    finally:
        # The store is closed by cmd_export's own `finally`, which owns
        # it on both the success and the in-document-failure path.
        pass
    json.dump(doc, sys.stdout, default=str)
    sys.stdout.write("\n")
    return 0


def cmd_sensors(args: argparse.Namespace) -> int:
    """Relay sensors known to this collector."""
    cfg = _cfg(args.config)
    now = time.time()
    # Read-only for the listing; `--forget` deletes a sensor's relayed
    # rows, so that path needs a writable store.
    store = (HoundStore(path=cfg.store.path) if args.forget
             else _ro_store(cfg))
    try:
        if args.forget:
            gone = store.forget_remote_sensor(args.forget)
            total = sum(gone.values())
            if not total:
                print(f"no sensor named {args.forget!r}")
                return 1
            print(f"forgot {args.forget!r}: "
                  + ", ".join(f"{k}={v}" for k, v in gone.items() if v))
            return 0

        rows = store.list_remote_sensors()
        if not rows:
            print("no relay sensors have reported yet")
            return 0
        timeout = cfg.relay.sensor_timeout_seconds
        print(f"{'sensor':16s} {'state':14s} {'last batch':12s} {'skew':>8s} "
              f"{'batches':>8s} {'records':>9s}")
        blind_any = False
        for r in rows:
            age = now - r.last_seen
            # Two independent questions, and only one used to be
            # answered. `reporting` is about the LINK. `mon_blind` is
            # what the sensor says about its OWN capture, and a sensor
            # whose capture is dead but whose link is fine read a clean
            # "reporting" beside camera rows it could no longer see.
            if age > timeout:
                state = "NOT REPORTING"
            elif r.mon_blind:
                state = "BLIND"
                blind_any = True
            else:
                state = "reporting"
            print(f"{r.sensor_id:16s} {state:14s} {_dur(age) + ' ago':12s} "
                  f"{r.clock_skew:+7.1f}s {r.batches:8d} {r.records:9d}")
        print()
        print("A sensor that stops reporting does not mean its cameras are "
              "down — it means this collector cannot see that segment. Its "
              "camera rows read 'unknown' rather than their last state.")
        if blind_any:
            print("BLIND: the link is fine but that sensor "
                  "reports its own capture is not seeing traffic. Its "
                  "camera states and availability are STALE, not current.")
    finally:
        store.close()
    return 0


def cmd_relay(args: argparse.Namespace) -> int:
    """Relay health. Must work with the link down — that is when it is needed."""
    cfg = _cfg(args.config)
    r = cfg.relay
    if r.mode == "off":
        print("relay: off (single sensor). Set [relay].mode to agent or "
              "collector to enable.")
        return 0

    if r.is_collector:
        print(f"relay: collector on {r.listen_host}:{r.listen_port}")
        fp = _cert_fingerprint(r.cert_file)
        if fp:
            print(f"  certificate fingerprint: {fp}")
            print("  paste that into the agent's [relay].tls_fingerprint")
        else:
            print(f"  certificate: NOT READABLE at {r.cert_file!r} — the "
                  f"listener will not start until it exists")
        print(f"  configured sensors: {[x.id for x in r.sensors] or 'none'}")
        return 0

    # agent: read the spool, never the network
    from surveillancehound.relay import AgentState, Spool
    base = Path(cfg.store.path).parent / "relay"
    state = AgentState.load(base, readonly=True)
    spool = Spool(base, r.spool_max_bytes, r.spool_max_age_seconds,
                  readonly=True)
    st = spool.stats(time.time())
    print(f"relay: agent {r.sensor_id!r} -> {r.url}")
    if state.instance_id:
        print(f"  instance      {state.instance_id}")
        print(f"  next sequence {state.next_seq}")
    else:
        # readonly load mints nothing, so an absent id means the agent
        # has never run OR its state file is unreadable. Printing a
        # blank instance and "next sequence 1" as fact would be stating
        # something this command cannot actually see.
        print("  instance      unknown — no readable state file at "
              f"{base / 'state.json'}")
        print("  next sequence unknown (the agent mints state on first run)")
    if state.last_push_ts:
        print(f"  last push     {_dur(time.time() - state.last_push_ts)} ago")
    else:
        print("  last push     never")
    print(f"  spooled       {st.pending} batch(es), {st.bytes / 1024:.1f} KiB, "
          f"oldest {_dur(st.oldest_age)}")
    if st.dropped_size or st.dropped_age or st.dropped_stale:
        print(f"  dropped       {st.dropped_size} over size, "
              f"{st.dropped_age} over age, {st.dropped_stale} rejected")
    if state.last_error:
        # Stripped, not printed raw. This string is built from the
        # collector's response body, and the collector echoes
        # agent-supplied values into its own error text — so a
        # terminal-escape payload had a path to an operator's screen,
        # where it can clear it and print a reassuring lie. The
        # agent->collector direction already strips control
        # characters; this direction had no counterpart.
        print(f"  last error    {_printable(state.last_error)}")
    return 0


def _cert_fingerprint(path: str) -> str:
    """sha256 fingerprint of a PEM certificate, or '' if unreadable."""
    import hashlib
    import ssl as _ssl
    try:
        der = _ssl.PEM_cert_to_DER_cert(Path(path).read_text())
    except (OSError, ValueError):
        return ""
    return "sha256:" + hashlib.sha256(der).hexdigest()


def cmd_baselines(args: argparse.Namespace) -> int:
    cfg = _cfg(args.config)
    # Read-only for the listing, writable only for the reset flags.
    # `--reset`/`--reset-all` genuinely delete rows, so they are the
    # one path here that is not a diagnostic.
    writes = bool(args.reset_all or args.reset)
    store = (HoundStore(path=cfg.store.path) if writes else _ro_store(cfg))
    try:
        if writes:
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
    store = _ro_store(cfg)
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
        if args.outages_days is not None:
            kwargs["outages_older_than"] = now - args.outages_days * 86400.0
        if args.sessions_days is not None:
            kwargs["sessions_older_than"] = now - args.sessions_days * 86400.0
        if args.relay_days is None and not kwargs:
            sys.exit(
                "no cutoff given. specify one or more of --flows-days, "
                "--alerts-days, --notifications-days, --outages-days, "
                "--sessions-days, --relay-days",
            )
        # RELAYED ROWS FIRST, then one reclaim covering everything.
        #
        # `store.prune()` runs its own VACUUM, so doing it first
        # rebuilt the file while the relayed pages were still live and
        # they were never in the rebuild. And `prune_remote` does NOT
        # vacuum — deliberately, because the daemon calls it from the
        # tick — so `--relay-days` returned no bytes at all despite
        # this command's own help saying it would. Measured: 40,000
        # relayed flows deleted, 6,324,224 bytes before and after.
        deleted = {}
        if args.relay_days is not None:
            deleted.update(
                store.prune_remote(now - args.relay_days * 86400.0))
        if kwargs:
            deleted.update(store.prune(**kwargs))
        if args.relay_days is not None and any(deleted.values()):
            before, after = store.vacuum()
            if after < before:
                print(f"reclaimed {(before - after) / 1e6:,.1f} MB "
                      f"({before:,} -> {after:,} bytes)")
            else:
                print(f"store is {before:,} bytes; no space reclaimed "
                      f"(not enough free disk to rebuild it)")
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

    # Surface sections the loader ignores. A mistyped section name is the
    # worst class of config error: everything starts, nothing complains,
    # and the settings simply never take effect.
    try:
        with open(args.config, "rb") as fh:
            unknown = config.unknown_sections(tomllib.load(fh))
    except (OSError, tomllib.TOMLDecodeError):
        unknown = []
    if unknown:
        print(f"  WARNING: ignored unknown section(s): {', '.join(unknown)}")
        print("    These are not read by this version. Anything you set in "
              "them has no effect.")

    print(f"  capture: interface={cfg.capture.interface!r} "
          f"pcap_file={cfg.capture.pcap_file!r} bpf={cfg.capture.bpf!r}")
    print(f"  network: cameras={cfg.network.camera_ips} "
          f"subnets={cfg.network.camera_subnets} nvrs={cfg.network.nvr_ips}")
    broad = config.overbroad_lan_subnets(cfg.network.lan_subnets)
    if broad:
        print(f"    WARNING: lan_subnets treats public range(s) "
              f"{', '.join(broad)} as local.")
        print("      Traffic to anything inside them is no longer scored as "
              "off-network telemetry, and a relay agent will ship to them. "
              "Narrow to the prefix you actually own.")
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
    print(f"  uptime: enabled={cfg.uptime.enabled} "
          f"grace={cfg.uptime.grace_for(cfg.thresholds):.0f}s "
          f"stall={cfg.uptime.capture_stall_seconds:.0f}s "
          f"recovery_alerts={cfg.uptime.recovery_alerts} "
          f"(passive — inferred from observed traffic, not probed)")
    if not cfg.uptime.enabled:
        print("    NOTE: uptime disabled also disables camera_offline.")
    if cfg.uptime.capture_stall_seconds <= 0:
        print("    NOTE: capture stall detection is OFF — a dead capture "
              "will not be reported.")
    r = cfg.relay
    if r.mode != "off":
        masked = f"set ({len(r.key)} chars)" if r.key else "MISSING"
        if r.mode == "agent":
            print(f"  relay: agent sensor_id={r.sensor_id!r} -> {r.url} "
                  f"key={masked} pinned={len(r.tls_fingerprint)} "
                  f"batch={r.batch_seconds:.0f}s")
        else:
            print(f"  relay: collector on {r.listen_host}:{r.listen_port} "
                  f"sensors={[x.id for x in r.sensors]} "
                  f"timeout={r.sensor_timeout_seconds:.0f}s "
                  f"retention={r.remote_retention_days:.0f}d")
    else:
        print("  relay: off (single sensor)")
    if cfg.relay.is_agent:
        # Listing channels here without this would promise notifications
        # that agent mode never sends. An unconfigured [[notify]] is also
        # auto-filled with a stdout channel, so the list is never empty
        # and always looks like it will do something.
        print(f"  notify: DISABLED — agent mode dispatches nothing; the "
              f"collector notifies. {len(cfg.notify)} configured "
              f"channel(s) will be ignored.")
        return 0
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

    p_u = sub.add_parser(
        "uptime", help="per-camera liveness + availability (passive)"
    )
    p_u.add_argument("config")
    p_u.add_argument("--window", type=float, default=None,
                     help="reporting window in seconds "
                          "(default [uptime].report_window_seconds)")
    p_u.add_argument("--outages", action="store_true",
                     help="print the outage history instead of the summary")
    p_u.set_defaults(func=cmd_uptime)

    p_e = sub.add_parser(
        "export", help="dump dashboard data as JSON (for external front-ends)"
    )
    p_e.add_argument("config")
    p_e.add_argument("--window", type=float, default=None,
                     help="uptime window in seconds "
                          "(default [uptime].report_window_seconds)")
    p_e.add_argument("--limit", type=int, default=100,
                     help="max alert and flow rows to include")
    p_e.set_defaults(func=cmd_export)

    p_sn = sub.add_parser("sensors", help="relay sensors known to this collector")
    p_sn.add_argument("config")
    p_sn.add_argument("--forget", metavar="ID",
                      help="delete a sensor and everything it ever sent")
    p_sn.set_defaults(func=cmd_sensors)

    p_rl = sub.add_parser("relay", help="relay health (works with the link down)")
    p_rl.add_argument("config")
    p_rl.set_defaults(func=cmd_relay)

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
    p_p.add_argument("--outages-days", type=float,
                     help="delete CLOSED outage rows older than N days")
    p_p.add_argument("--sessions-days", type=float,
                     help="delete ENDED monitor session rows older than N days")
    p_p.add_argument("--relay-days", type=float,
                     help="delete relayed (remote_*) rows older than N days, "
                          "by when this collector received them, then "
                          "rebuild the store to return the space to the "
                          "filesystem")
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
    try:
        return args.func(args)
    except ValueError as e:
        # Config errors already carry a full explanation and a remedy.
        # Wrapping them in a traceback buries that under a stack an
        # operator cannot act on — and `config-check` is the first
        # command the deployment docs tell them to run.
        print(f"error: {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except sqlite3.Error as e:
        # A damaged or unreadable store surfaces on the first QUERY,
        # not at connect — `mode=ro` opens lazily — so neither the
        # constructor guard nor a per-command try/except catches it.
        # An operator diagnosing a store problem should not have to
        # read a traceback to learn the store is the problem. `export`
        # handles its own, because its contract is a document.
        print(f"error: cannot read the store: {e}. If it is damaged, "
              f"stop the daemon and check it with `sqlite3 <path> "
              f"'PRAGMA integrity_check'`.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
