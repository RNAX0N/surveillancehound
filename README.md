# SurveillanceHound

Always-running NVR / IP-camera network monitor. Sits on the wire (NVR host,
firewall, or a switch SPAN/mirror port), watches the surveillance segment, and
flags activity the surveillance threat model cares about — without disturbing
the recordings.

**What it watches for**

- **`bulk_inbound`** — a large transfer *toward* a camera (model-weight push,
  firmware update). HIGH.
- **`control_channel_suspect`** — a long-lived / chatty session from a camera
  to a public host on a non-routine port. MEDIUM.
- **`telemetry_offnet`** — a camera talks to a public host that is *not* in the
  manufacturer allowlist. MEDIUM.
- **`behavioral_anomaly`** — *(opt-in `[baseline]`)* a camera's per-flow stats
  drift > N σ from its learned per-(weekday, hour) envelope. MEDIUM.
- **`new_device`** — an IP that has never been observed on the segment shows up.
- **`new_peer`** — a known camera is now talking to a brand-new endpoint.
- **`camera_offline`** — a known camera has been silent for too long.

**How it's built**

- Pure-Python pcap / pcapng parser (no scapy, no dpkt).
- Live capture via `tcpdump` as a subprocess (universal; no libpcap binding).
- SQLite stores devices, flows, alerts, learned baselines, snapshot index,
  and the notification audit log.
- Per-camera Welford baselining (opt-in) — deterministic, auditable, no model
  files.
- Per-camera ring-buffer packet capture (opt-in) — dumps a pcap of the
  suspicious window to disk on alert, openable in Wireshark.
- Notifications: `stdout`, `logfile` (size-rotating), `jsonlines`
  (size-rotating), `webhook` (Slack / Discord / Teams / PagerDuty / generic),
  `syslog` (RFC 5424 UDP/TCP — Security Onion / Graylog / Splunk / pfSense /
  OPNsense / any SIEM), `email` (SMTP/STARTTLS), `ftp` / `ftps` — pick any
  combination per `[[notify]]` block.
- Local read-only web dashboard with a dark futuristic theme — pure stdlib
  HTTP server, no external assets.
- Zero runtime Python dependencies. Python 3.11+ for stdlib `tomllib`.

## Install

```bash
cd SurveillanceHound
pip install -e .            # makes the `hound` CLI available
# or, no install:
PYTHONPATH=src python -m surveillancehound.cli ...
```

Live capture needs `tcpdump` on PATH and the capability to capture — either
run as root, or grant the cap once:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)
```

## Configure

Copy `hound.toml.example` to (say) `/etc/hound.toml` and edit:

- `[capture] interface` — the NIC the surveillance traffic crosses, OR
  `pcap_file = ...` for offline replay.
- `[network] camera_ips / camera_subnets / nvr_ips` — what's what on this LAN.
- `[network] manufacturer_allowlist` — your vendor's cloud CIDRs (so legit
  vendor telemetry doesn't pour out alerts).
- `[[notify]]` blocks — every channel you want to dispatch through.
- `[baseline]` — opt in to per-camera anomaly detection.
- `[snapshot]` — opt in to per-camera pcap snapshots on alert.
- `[web]` — opt in to the local dashboard.

Validate before running:

```bash
hound config-check /etc/hound.toml
```

## Run

```bash
hound run /etc/hound.toml         # always-running daemon (SIGTERM to stop)
hound replay /etc/hound.toml      # same loop against a pcap_file
hound alerts /etc/hound.toml --limit 100 -v
hound flows /etc/hound.toml --class bulk_inbound --limit 20
hound devices /etc/hound.toml
hound baselines /etc/hound.toml [--camera IP | --reset IP | --reset-all]
hound snapshots /etc/hound.toml
hound prune /etc/hound.toml --flows-days 30 --alerts-days 90
hound web /etc/hound.toml [--host 0.0.0.0 --port 8080]
```

A hardened `systemd` unit is included at `deploy/hound.service` (drops to a
DynamicUser with only `CAP_NET_RAW`+`CAP_NET_ADMIN`, ProtectSystem=strict, etc.):

```bash
sudo cp deploy/hound.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hound
journalctl -u hound -f
```

## Firewall plugins

Drop-in plugins for the two most common open-source firewalls:

- **OPNsense** — `deploy/opnsense/` ships a full MVC plugin (model +
  controllers + configd actions + a Python config renderer invoked from
  configd). Adds **Services → SurveillanceHound** with a settings form,
  an embedded live dashboard tab, and start/stop/restart/reload
  controls. See `deploy/opnsense/README.md`.
- **pfSense** — `deploy/pfsense/` is a legacy-style `<packagegui>`
  package: `hound.xml` + `hound.inc` (renderer + install hooks) +
  `hound.php` (the dashboard page). See `deploy/pfsense/README.md`.

Both plugins render `/usr/local/etc/hound.toml` from the form on save
and bounce the daemon. Both have validation tests under
`tests/verify_plugins.py` (XML well-formedness, `sh -n` on rc.d
scripts, PHP structural lint, AND the renderers' outputs are parsed by
`tomllib` and round-tripped through `surveillancehound.config.load_from_dict`
— so the plugins' output is guaranteed to be valid Hound config, not
just syntactically valid PHP/XML).

## SIEM integration (Wazuh, Security Onion, Splunk, Graylog, …)

Two paths work with any modern SIEM; pick whichever fits your topology:

1. **JSON file + agent** — `[[notify]] type = "jsonlines"` writes one
   JSON object per line to a rotating log file. A SIEM agent
   (`wazuh-agent`, `filebeat`, `vector`, `fluent-bit`, …) tails it.
2. **Syslog → manager** — `[[notify]] type = "syslog"` ships RFC 5424
   over UDP or TCP (RFC 6587 octet-counting). Structured-data block
   carries `kind` / `severity` / `device_ip` as parsed fields so SIEM
   decoders extract them without regex.

For Wazuh specifically, `deploy/wazuh/` ships ready-to-install
artifacts:

- `hound-rules.xml` — custom Wazuh rules in the operator-defined
  100200+ range, with MITRE ATT&CK tagging (T1190 / T1071 / T1041 /
  T1095 / T1542 / T1499 / T1078) and sustained-attack correlation rules.
- `hound-decoder.xml` — RFC 5424 sub-decoder for the syslog path (the
  jsonlines path uses Wazuh's built-in `json` decoder, no custom needed).
- `localfile-snippet.xml` — drop into `/var/ossec/etc/ossec.conf` to
  tail Hound's jsonlines as JSON.

See `deploy/wazuh/README.md` for both install paths + a
`wazuh-logtest` snippet for verification.

## Web dashboard

`hound web <config>` serves a single-page dashboard at
`http://127.0.0.1:8080/` (override with `--host`/`--port` or `[web]` config).
It is **read-only** — no write endpoints, no auth, no sessions; bind to
localhost-only by default and front it with your own reverse proxy + auth if
you want it reachable elsewhere.

The dashboard:

- Live counters for cameras / NVRs / 24h alerts / baselines / snapshots
- Color-coded alert stream (severity-tinted left bars + neon glow)
- Recent flows with directional byte counters
- Per-camera baseline buckets, grouped by weekday + hour
- One-click `.pcap` downloads of any saved snapshot
- A built-in help modal (auto-opens on first visit) that explains every
  alert kind, severity, and operator workflow

All CSS and JS is embedded — zero external requests, no CDN fetches, no
fonts pulled from the internet. Stays inside the offline-by-default contract.

## Behavioral baselining

Two models share the same lifecycle (learn per-(camera, weekday, hour)
bucket, gate alerts behind `min_samples`, persist to SQLite, fire
`behavioral_anomaly`). Pick one via `[baseline].model`:

- **`model = "welford"`** (default) — running per-feature `(mean, variance)`
  via Welford's algorithm. Fires when a single feature exceeds
  `z_threshold` standard deviations. Deterministic, auditable, O(1) per
  bucket.
- **`model = "hstree"`** — streaming **Half-Space Forest** (Tan, Ting, Liu —
  *Fast Anomaly Detection for Streaming Data*, IJCAI 2011). A real
  multivariate ML anomaly detector implemented in pure stdlib (just
  `random` + `struct`). An ensemble of random projection trees scores
  each flow against a learned reference window. Catches *joint* anomalies
  Welford misses by construction — flows where every feature is
  individually normal but their combination is rare. Honors the same
  "zero runtime deps, offline-by-default" constraints as the rest of the
  daemon (no PyTorch / onnxruntime / scikit-learn).

Tuning the HS-Forest: `hstree_n_trees` (default 8), `hstree_depth` (6),
`hstree_window_size` (250 — samples before reference rollover), and
`hstree_score_threshold` (0.7 in [0, 1]; higher = fewer alerts).

Inspect or reset learned baselines via the CLI (works for both models):

```bash
hound baselines /etc/hound.toml                  # dumps Welford + HS-Forest
hound baselines /etc/hound.toml --camera 10.0.0.5
hound baselines /etc/hound.toml --reset 10.0.0.5 # stop the daemon first!
hound baselines /etc/hound.toml --reset-all
```

## Forensic snapshots

When `[snapshot].enabled = true`, the daemon keeps the last
`window_seconds` of raw packets per camera in a RAM ring buffer. On any
alert at severity ≥ `min_severity`, the matching camera's buffer is dumped
to `<store_dir>/snapshots/<alert_id>.pcap` — open it in Wireshark for the
full pre-alert context, not just the alert summary.

```bash
hound snapshots /etc/hound.toml --limit 20
```

The dashboard exposes snapshot pcaps as direct download links.

## What it does NOT do

- It does not record or transcode video. The NVR keeps doing that.
- It does not inspect packet payloads. Headers only — that's the threat model.
- It does not perform DNS resolution; alerts identify hosts by IP. Use your
  firewall logs alongside if you need names.
- It does not validate C2PA / cryptographic provenance. That stays offline in
  the sibling footageanalyzer project.
- It does not phone home, fetch external assets, or load remote ML models.
  Everything runs locally with the Python standard library.

## Tests

No pytest harness — five focused end-to-end scripts:

```bash
PYTHONPATH=src python tests/verify_hound_end_to_end.py        # core daemon
PYTHONPATH=src:tests python tests/verify_baseline.py          # baseliner
PYTHONPATH=src:tests python tests/verify_snapshots_and_cli.py # snapshots + web + CLI
PYTHONPATH=src python tests/verify_channels.py                # syslog + email + ftp + audit
PYTHONPATH=src:tests python tests/verify_plugins.py           # opnsense + pfsense + wazuh
```
