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
- **`new_device`** — an IP that has never been observed on the segment shows up.
- **`new_peer`** — a known camera is now talking to a brand-new endpoint.
- **`camera_offline`** — a known camera has been silent for too long.

**How it's built**

- Pure-Python pcap / pcapng parser (no scapy, no dpkt).
- Live capture via `tcpdump` as a subprocess (universal; no libpcap binding).
- SQLite stores devices, flows, alerts, and the notification audit log.
- Notifications: `stdout`, `logfile`, `jsonlines`, `webhook` — pick any
  combination in the TOML config.
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

Validate before running:

```bash
hound config-check /etc/hound.toml
```

## Run

```bash
hound run /etc/hound.toml      # the always-running daemon (Ctrl-C / SIGTERM to stop)
hound replay /etc/hound.toml   # same loop against a pcap_file
hound alerts /etc/hound.toml --limit 100 -v
hound flows /etc/hound.toml --class bulk_inbound --limit 20
hound devices /etc/hound.toml
```

A `systemd` unit (rough):

```ini
[Unit]
Description=SurveillanceHound — NVR / IP-camera network monitor
After=network-online.target

[Service]
ExecStart=/usr/local/bin/hound run /etc/hound.toml
Restart=always
RestartSec=5
StateDirectory=surveillancehound
LogsDirectory=surveillancehound

[Install]
WantedBy=multi-user.target
```

## What it does NOT do

- It does not record or transcode video. The NVR keeps doing that.
- It does not inspect packet payloads. Headers only — that's the threat model.
- It does not perform DNS resolution; alerts identify hosts by IP. Use your
  firewall logs alongside if you need names.
- It does not validate C2PA / cryptographic provenance. That stays offline in
  the sibling footageanalyzer project.

## Tests

```bash
PYTHONPATH=src python tests/verify_hound_end_to_end.py
```
