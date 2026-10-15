# SurveillanceHound

A network monitor for IP cameras and NVRs. You point it at the segment your
cameras live on — the NVR's host, your firewall, or a switch mirror port — and
it watches the traffic for the things that actually matter on a camera network.
It never touches the recordings and it never talks to your cameras.

It reads packet headers only. No payloads, no DNS lookups, no video. That's a
deliberate limit, not a missing feature: the daemon physically cannot leak your
footage or credentials because it never reads them.

Zero runtime dependencies. Python 3.11+ and the standard library, nothing else.
It runs on an NVR box, a Raspberry Pi, or a firewall without pulling in pip.

## What it flags

The interesting ones first:

`bulk_inbound` (high) — somebody pushed a large file *to* a camera from off-net.
That's the shape of a firmware flash or a model-weight drop, and it's the single
most important thing on this list.

`control_channel_suspect` (medium) — a camera is holding a long-lived or chatty
session with a public host on an unusual port. Cameras shouldn't maintain
C2-shaped connections.

`telemetry_offnet` (medium) — a camera is talking to a public host that isn't in
your manufacturer allowlist. Sometimes that's the vendor cloud you forgot to
allowlist. Sometimes it isn't.

`behavioral_anomaly` (medium, opt-in) — this camera's traffic doesn't match what
this camera normally does at this hour on this weekday.

Then the housekeeping ones: `new_device`, `new_peer`, `camera_offline`,
`camera_recovered`, `camera_never_seen`, and `capture_stalled`. The last one
means the sensor itself went blind — see [Uptime](#uptime-monitoring).

## Quick start

```bash
pip install -e .                    # or skip it: PYTHONPATH=src python -m surveillancehound.cli
cp hound.toml.example /etc/hound.toml
$EDITOR /etc/hound.toml             # at minimum: [capture].interface and [network].camera_ips
hound config-check /etc/hound.toml  # catches typos before you rely on it
hound run /etc/hound.toml
```

Live capture needs `tcpdump` and permission to use it. Either run as root or
grant the capability once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

There's a hardened systemd unit in `deploy/hound.service` — it runs as a
DynamicUser with only `CAP_NET_RAW` and `CAP_NET_ADMIN`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute=yes`:

```bash
sudo cp deploy/hound.service /etc/systemd/system/
sudo systemctl enable --now hound
journalctl -u hound -f
```

## Running on a firewall

If your firewall already sees the camera traffic, that's the natural place for
this to live.

**OPNsense** — install it from the plugin catalogue:

```sh
fetch -o /usr/local/etc/pkg/repos/hound-repo.pub \
  https://rnax0n.github.io/surveillancehound/opnsense/hound-repo.pub
fetch -o /usr/local/etc/pkg/repos/hound.conf \
  https://rnax0n.github.io/surveillancehound/opnsense/hound.conf
pkg update && pkg install os-hound
```

Or do it from the GUI: **System → Firmware → Plugins**, tick **Show community
plugins**, find `os-hound`, hit the **+**. (The checkbox is needed because
OPNsense hides third-party plugins by default until they're installed. Your
firmware also has to be current — OPNsense refuses to install any plugin while
core is behind.) Either way you get **Services → SurveillanceHound** in the
menu, with a settings form and the live dashboard embedded in the page.

**pfSense** — `deploy/pfsense/` is a legacy `<packagegui>` package. See the
README in there.

Both plugins write `/usr/local/etc/hound.toml` from the form and restart the
daemon on save.

## CLI

```bash
hound run <config>                 # the daemon
hound replay <config>              # same pipeline against a pcap, for forensics
hound alerts <config> --limit 100
hound flows <config> --class bulk_inbound
hound devices <config>
hound uptime <config> [--outages]
hound baselines <config> [--camera IP | --reset IP | --reset-all]
hound snapshots <config>
hound prune <config> --flows-days 30 --alerts-days 90
hound web <config>
```

## Uptime monitoring

Per-camera liveness, outage history and availability, on by default.

```bash
hound uptime /etc/hound.toml
hound uptime /etc/hound.toml --outages
curl -s localhost:8080/api/uptime | jq .
```

**This is passive.** A camera counts as up because packets from it showed up on
the wire. Nothing is pinged or port-scanned. So a camera that's powered on and
recording happily, but has been moved to a VLAN this sensor can't see, looks
exactly like one that's unplugged. Every screen says so rather than claiming the
camera is "verified up". Active probing is on the roadmap — see `DevNotes.md`.

Three things keep that inference honest enough to page someone about:

Cameras get registered from your config at startup, so one that was already dead
before the daemon booted raises `camera_never_seen` instead of just being absent
from a table that otherwise looks fine.

There's a dead-man's-switch on the capture. If *no* packets arrive at all for
`capture_stall_seconds`, you get one `capture_stalled` (high) and the per-camera
offline alerts are suppressed. A wedged tcpdump and a dead PoE switch look
identical from inside the daemon, and sending you twelve "camera offline" pages
when the real answer is "your sensor is blind" is worse than useless.

Availability only counts time the monitor was actually watching. Outage spans
get intersected with recorded monitor sessions, so a daemon that was stopped
overnight doesn't bill that to your cameras. If there's no observation at all
you get `n/a`, not a made-up 0% or 100%.

Outages live in their own table and an open row *is* the camera's down state, so
restarting the daemon resumes an outage instead of forgetting it or re-alerting.
Dedup keys carry the outage id, so a camera that flaps down/up/down inside the
dedup window reports both outages instead of silently swallowing the second.

## Web dashboard

`hound web <config>` puts a single-page dashboard on `127.0.0.1:8080`. It's
read-only — no write endpoints, no auth, no sessions. If you want it reachable
from elsewhere, put your own reverse proxy and auth in front of it.

You get live counters, a severity-coded alert stream, recent flows with
directional byte counts, the uptime panel, per-camera baseline buckets, and
one-click pcap downloads for saved snapshots. There's a help modal that opens on
first visit and explains every alert kind.

All the CSS and JS is inlined. No CDN, no web fonts, no external requests —
same offline-by-default rule as the daemon.

## Behavioral baselining

Opt in with `[baseline]`. Two models, same lifecycle: learn a per-(camera,
weekday, hour) bucket, hold fire until `min_samples`, persist to SQLite, raise
`behavioral_anomaly`.

`welford` (default) keeps a running mean and variance per feature and fires when
one feature crosses `z_threshold` standard deviations. Deterministic, auditable,
O(1) per bucket, and you can read the state straight out of the database.

`hstree` is a streaming Half-Space Forest (Tan, Ting & Liu, *Fast Anomaly
Detection for Streaming Data*, IJCAI 2011) — an ensemble of random projection
trees scoring each flow against a learned reference window. It catches joint
anomalies that Welford misses by construction: flows where every individual
feature looks normal but the combination is rare. Implemented in pure stdlib
(`random` and `struct`), because pulling in PyTorch would defeat the point.

Tune it with `hstree_n_trees` (8), `hstree_depth` (6), `hstree_window_size`
(250), `hstree_score_threshold` (0.7, higher means fewer alerts).

```bash
hound baselines /etc/hound.toml --camera 10.0.0.5
hound baselines /etc/hound.toml --reset-all     # stop the daemon first
```

## Forensic snapshots

With `[snapshot].enabled = true` the daemon keeps the last `window_seconds` of
raw packets per camera in a RAM ring buffer. When an alert fires at or above
`min_severity`, that camera's buffer gets written to
`<store_dir>/snapshots/<alert_id>.pcap`. Open it in Wireshark and you have the
whole conversation leading up to the alert, not just the summary line.

The dashboard links them for download.

## SIEM

Two ways in, pick whichever matches your setup:

1. `[[notify]] type = "jsonlines"` writes one JSON object per line to a rotating
   file. Point wazuh-agent, filebeat, vector or fluent-bit at it.
2. `[[notify]] type = "syslog"` ships RFC 5424 over UDP or TCP. The
   structured-data block carries `kind`, `severity` and `device_ip` as real
   fields, so decoders don't have to regex the message.

`deploy/wazuh/` has ready-made rules (operator range 100200+, MITRE ATT&CK
tagged, with correlation rules for sustained activity), an RFC 5424 decoder for
the syslog path, and an `ossec.conf` snippet for the jsonlines path.

Other notify channels: `stdout`, `logfile`, `webhook` (Slack, Discord, Teams,
PagerDuty or generic), `email` over SMTP/STARTTLS, and `ftp`/`ftps`. Stack as
many `[[notify]]` blocks as you want, each with its own minimum severity.

## What it deliberately doesn't do

- Record or transcode video. Your NVR already does that.
- Read packet payloads. Headers only — that's the threat model, not a TODO.
- Resolve DNS. Alerts name hosts by IP; correlate with firewall logs if you need
  names.
- Probe your cameras. "Offline" strictly means "not visible to this sensor."
- Check C2PA or cryptographic provenance. That lives in the sibling
  footageanalyzer project.
- Phone home, fetch remote assets, or download models. Everything is local.

## Tests

No pytest. Seven end-to-end scripts, each of which exercises the real pipeline:

```bash
PYTHONPATH=src python tests/verify_hound_end_to_end.py        # core daemon
PYTHONPATH=src:tests python tests/verify_baseline.py          # both baseline models
PYTHONPATH=src:tests python tests/verify_snapshots_and_cli.py # snapshots, web, CLI
PYTHONPATH=src python tests/verify_channels.py                # notify channels + audit log
PYTHONPATH=src:tests python tests/verify_uptime.py            # liveness, outages, availability
PYTHONPATH=src:tests python tests/verify_plugins.py           # opnsense, pfsense, wazuh
PYTHONPATH=src:tests python tests/verify_opnsense_fields.py   # every plugin field round-trips
```

There's also a disposable OPNsense VM rig under `deploy/dev/opnsense-vm/` that
boots real OPNsense in QEMU and validates the plugin against it — `make help` in
that directory. It exists because the Python tests can't cover Phalcon routing,
configd actions, or the handful of FreeBSD packaging details that only show up
on a real box.
