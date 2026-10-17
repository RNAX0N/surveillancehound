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
hound sensors <config> [--forget ID]   # relayed sensors; --forget drops one's rows
hound relay <config>               # relay health; on a collector, prints the cert pin
                                   # on an agent: backlog, delivered watermark,
                                   # duplicates and drops (deploy/agent/README.md)
hound prune <config> --flows-days 30 --alerts-days 90
hound prune <config> --relay-days 7            # expire relayed rows, rebuild in place
hound prune <config> --offline-compact         # STOP THE SERVICE FIRST; see below
hound export <config>              # everything, including relayed rows
hound config-check <config>        # validate, and report settings that do nothing
hound web <config>
```

`config-check` is worth running after any edit: it reports sections this
version ignores, so a mistyped `[storage]` surfaces there rather than as a
daemon that starts, looks healthy, and monitors nothing.

### One daemon per store

The daemon holds an exclusive lock on `<store>.writer`, a zero-byte file
beside the database, for as long as it runs. A second `hound run` or
`hound replay` against the same store is refused rather than quietly
corrupting it.

Everything that only reads — `alerts`, `flows`, `devices`, `uptime`,
`sensors`, `export`, `web` — ignores the lock entirely and works normally
while the daemon runs, as do `prune --flows-days`, `prune --relay-days`,
`sensors --forget` and `baselines --reset`.

Those last two do WRITE, and they take no lock either, deliberately:
locking them would mean refusing them whenever the daemon is up, which
is worse. Do not run one at the same time as `prune --offline-compact`
— see the note in `deploy/agent/README.md` about what that costs.

The exception is `prune --offline-compact`, the only command that REPLACES
the database file. It needs room for the live data rather than roughly the
whole file again, which is why it exists: on a disk too full for the
in-place rebuild it is the way out. It refuses while the daemon holds the
lock, because a file swap is invisible to a process that already has the
old one open — that daemon would go on writing to an unlinked inode, with
no error on either side.

Two things not to do:

- **Do not delete `<store>.writer`,** and treat the store's directory
  as part of the lock's trust boundary. The lock binds the file, not
  the name, and the name is only checked when it is taken — so
  removing or replacing `.writer` while the daemon holds it lets the
  next compaction conclude nothing is running and swap the database
  out from under it. Anything that can write that directory can do
  this; the same thing can already corrupt the store directly.
- **Do not put `[store].path` on NFS.** The lock depends on `flock`, which
  is not guaranteed there; SQLite over NFS is unsupported anyway.

`--offline-compact` has one other refusal: if some other connection is
holding a read snapshot of the store, the write-ahead log cannot be
checkpointed and the rebuild stops rather than discarding what is still
in it. Close whatever else has the database open and re-run. It is safe
and retryable — nothing is deleted and the temporary file is cleaned up.

A restart is unaffected: a starting daemon waits up to 60 seconds for its
predecessor to finish draining.

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

## Multiple sensors

A common and awkward topology: the cameras sit behind the NVR, on switch ports
or VLANs that never cross the firewall. A monitor on the firewall sees the NVR
and nothing else, and a green dashboard then means "I can't see anything
wrong", which is not the same as "nothing is wrong".

Relay mode fixes that by putting a sensor where the traffic actually is. An
**agent** runs the whole pipeline locally — capture, flows, discovery,
classification, uptime, baselining — and ships its results to a **collector**,
which is usually the firewall you already watch.

```
  camera VLANs ──▶ agent on the NVR host ──TLS──▶ collector on the firewall
                   (sees the cameras)             (notifies, and shows both)
```

The agent dispatches **nothing**. Any `[[notify]]` block in its config is
ignored, so one camera outage pages you once rather than once per sensor.

```toml
# on the agent
[relay]
mode            = "agent"
sensor_id       = "frigate"
url             = "https://10.0.0.1:18443/ingest/v1"
key             = "<shared secret>"
tls_fingerprint = ["sha256:..."]      # `hound relay` on the collector prints it

# on the collector
[relay]
mode        = "collector"
listen_host = "10.0.0.1"
listen_port = 18443
cert_file   = "/var/lib/hound/hound-ingest.crt"
key_file    = "/var/lib/hound/hound-ingest.key"

[[relay.sensor]]
id  = "frigate"
key = "<same shared secret>"
```

`hound sensors` lists every sensor and when it last reported. The dashboard
gains a Sensor column, and a camera belonging to a sensor that has gone quiet
reads `UNKNOWN` with no availability figure — not the `up` it last claimed,
because that number is exactly as stale as the contact that produced it.

On OPNsense all of this is in Services → SurveillanceHound; there is no need to
hand-edit `hound.toml`, and in fact hand-edits there are overwritten on save.
`deploy/agent/` has a Docker setup for the NVR side.

### The trust model

The agent runs on a camera-segment host, which is more likely to be compromised
than the firewall. So the collector treats a correctly signed batch as
authenticated, not as trusted:

- Batches are signed with HMAC-SHA256 and the collector pins the agent's view
  of its certificate. There is no CA — the pin *is* the trust decision, so
  verify it out of band the first time.
- Relayed records land in separate `remote_*` tables and **cannot** reach the
  tables holding this box's own observations. That isolation is enforced by a
  SQLite authorizer, not merely intended — see `DevNotes.md`.
- Every relayed value is re-validated on arrival. Nothing from the wire is
  trusted to be the type, range or character set it claims.
- Volume is bounded by age (`remote_retention_days`), by row count
  (`max_rows_per_sensor`) and by free disk (`min_free_disk_mb`), so a sensor
  holding a valid key still cannot fill the disk local capture depends on.
- If the collector is unreachable the agent spools to disk and replays later,
  bounded by both size and age.

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

No pytest. Eight end-to-end scripts, each of which exercises the real pipeline:

```bash
PYTHONPATH=src python tests/verify_hound_end_to_end.py        # core daemon
PYTHONPATH=src:tests python tests/verify_baseline.py          # both baseline models
PYTHONPATH=src:tests python tests/verify_snapshots_and_cli.py # snapshots, web, CLI
PYTHONPATH=src python tests/verify_channels.py                # notify channels + audit log
PYTHONPATH=src:tests python tests/verify_uptime.py            # liveness, outages, availability
PYTHONPATH=src:tests python tests/verify_plugins.py           # opnsense, pfsense, wazuh
PYTHONPATH=src:tests python tests/verify_opnsense_fields.py   # every plugin field round-trips
PYTHONPATH=src:tests python tests/verify_relay.py             # relay: validation, quarantine, TLS
```

There's also a disposable OPNsense VM rig under `deploy/dev/opnsense-vm/` that
boots real OPNsense in QEMU and validates the plugin against it — `make help` in
that directory. It exists because the Python tests can't cover Phalcon routing,
configd actions, or the handful of FreeBSD packaging details that only show up
on a real box.
