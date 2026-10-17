# SurveillanceHound relay agent (Docker)

Runs a full SurveillanceHound pipeline on a host that can actually see the
cameras — typically the NVR box itself — and ships the results to a
collector running on your firewall.

This exists because of a common and awkward topology: the cameras sit
behind the NVR and their traffic never crosses the firewall. A monitor on
the firewall sees the NVR and nothing else. Putting a sensor *on* the NVR
host is the only way to see that segment, and relaying is how its findings
reach the place you already watch.

## Setup

```bash
cp hound.toml.example hound.toml
$EDITOR hound.toml            # interface, camera_ips, sensor_id, key, fingerprint
docker compose run --rm hound-agent config-check /etc/hound/hound.toml
docker compose up -d --build
docker compose logs -f
```

Build context is the repository root (the image copies `src/`), which the
compose file handles — run `docker compose` from this directory.

### Get the collector's fingerprint

The collector's certificate is self-signed, so there is no CA to validate
it against. The pinned fingerprint *is* the trust decision, and the agent
refuses to connect without one. On the **collector**:

```bash
hound relay /usr/local/etc/hound.toml
```

It prints a `sha256:…` line. Copy that into `tls_fingerprint` on the
agent. If you have no shell on the collector:

```bash
openssl s_client -connect 88.255.5.1:18443 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

Verify it out of band the first time. Trusting whatever answers on first
connect is exactly the attack pinning exists to prevent.

### Shared secret

Generate one, put the identical string in the agent's `[relay] key` and in
the collector's `[[relay.sensor]]` block for this `sensor_id`:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Every batch is signed with it (HMAC-SHA256 over the raw body). The
collector answers `401` for both an unknown sensor and a bad signature —
deliberately the same response, since telling them apart is a probing
oracle.

## Restrict the ingest port to your agents

The collector reserves capacity for source addresses that have
completed a signed request, so a flood of unauthenticated addresses
cannot starve a sensor that is already reporting. It cannot make the
port free, though: enough unauthenticated connections will still
delay a sensor's **first** batch after an install or an address
change.

Do not read that as harmless. Connections AND requests are metered
per source, and an over-budget source is refused at accept — but a
peer that can reach the port still makes the collector do work, and
the collector is the same process that parses packets. An
unauthenticated TLS handshake flood was measured taking two thirds of
local packet-parse throughput on a single-CPU collector, which is
what a 1-vCPU firewall VM is.

**The metering reduces that; it does not close it.** The budget is
keyed on the source address, so it only bites a source that comes
back.

Measured with the collector pinned to a single core — a 1-vCPU
firewall VM is the case these plugins exist for — against a flood on
the ingest port, three runs each, median, on three different
machines. These are PROPORTIONS of each machine's own unloaded
throughput. The absolute packet rate depends on the capture, the
link and the hardware, so only the spread is worth reading:

| flood | packets lost |
|---|---|
| none | — |
| 8 fixed addresses, metering off | 55-70% |
| 8 fixed addresses, shipped 60/min | **0-20%** |
| 20,000 rotating addresses, shipped 60/min | **19-75%** |

The metering is what turns a 55-70% loss into 0-20%, and it only
bites a source that comes back. Against rotating addresses every
connection is a first offence, nothing is ever in cooldown, and the
loss returns to 19-75%. Plan for the top of each range — slower
storage and a busier core both push it that way.

Re-derive these on your own hardware rather than trusting the
spread: `tools/bench_ingest_flood.py` is the harness that produced
them, and it prints the method it used. An earlier revision of this
section quoted an absolute baseline that was ~10-20x high, because
it came from a loop re-parsing one small capture already in memory;
two independent reviewers measured real files at 193k and 443k
pkt/s. The ratios survived that error. A single number would not
have.

Nothing alerts on this either: packets are still arriving, so
`capture_stalled` cannot fire, and the loss shows up only as flows
that were never recorded.

A firewall rule is not defence in depth here. It is the control.

Put a firewall rule in front of it. The port should be reachable from
your agents and nothing else:

```
# OPNsense: Firewall -> Rules -> (interface facing the agents)
#   pass  proto tcp  from <agent addresses>  to <collector>  port 18443
#   block proto tcp  from any                to <collector>  port 18443
```

The relay is built to survive a hostile agent — that is the threat
model — but it is not a service to expose broadly, and nothing in it
pretends otherwise.

### What the collector does NOT defend against

Written down because finding these in the field is worse than reading
them here.

- **A compromised agent can degrade the relay.** It holds a valid key,
  so it can occupy ingest capacity from several addresses. Each
  connection is time-bounded, each address is capped, and requests are
  metered per source — so a starved sensor raises `sensor_offline`
  after `sensor_timeout_seconds` rather than vanishing.

  Do not read that as contained. It holds an address your firewall
  rule must permit, so that control does not apply to it, and a flood
  from an allowed address costs local capture throughput — which no
  alert reports, because packets are still arriving and
  `capture_stalled` only fires when none are. A compromised agent is a
  reason to remove its key promptly: delete it from
  `[[relay.sensor]]`, restart, then `hound sensors --forget <id>` to
  clear what it sent.
- **Agents behind one NAT share everything keyed on their address:**
  the per-source connection cap, the batches-per-minute bucket, and
  the reserved-capacity credit one of them earns. A hostile host
  behind the same NAT as a real agent can therefore crowd it out
  without holding any key.

  This bites honest agents too, and sooner than "more than a
  couple". A single agent replaying a spool costs 48 of the default
  60 units per minute, so **two agents recovering behind one address
  throttle each other** — 96 against 60. Nothing is lost (a `429`
  ends the cycle with the batch still spooled) but recovery stretches
  out and `hound sensors` may show both as stale meanwhile. Give
  agents distinct addresses, and treat that NAT as part of the
  collector's trust boundary.
- **An attacker on the agent host itself** can read the shared secret
  out of `hound.toml`. Nothing on the collector helps with that; it is
  the agent host's own security boundary. The same access can plant a
  delivered-watermark in the spool's `counters.json` that hides
  everything queued — the agent clamps it to a sequence it actually
  minted and logs loudly, but anything already below that is
  indistinguishable from delivered. Accidental damage to that file
  (truncation, garbage, a value that will not parse) is safe: it
  resets and the batches are re-sent, which the collector answers
  with `409`.
- **`--offline-compact` is not serialised against the other manual
  writing subcommands.** It refuses while the DAEMON holds the store,
  which is the case that matters, but not while `sensors --forget`,
  `baselines --reset` or a plain `prune` is running in another shell.
  Measured, a concurrent writer across a compaction kept 9,652 of
  62,750 rows. Giving those the same lock would mean refusing them
  whenever the daemon is up, which is worse. Both commands are
  manual: do not run two at once.

## One daemon per store

The daemon holds an exclusive `flock` on `<store>.writer`, a
zero-byte file beside the database, for as long as it runs. A second
`hound run` or `hound replay` against the same store is refused
rather than quietly corrupting it, and `hound prune
--offline-compact` — the only command that replaces the database
file — refuses while that lock is held, because `os.replace` is
invisible to a process that already has the old file open.

Three things worth knowing:

- **Do not delete the `.writer` file.** It is how a second process
  can tell a daemon is running. Removing it while the daemon holds
  it makes the next compaction create a fresh one, conclude nothing
  is running, and swap the database out from under the daemon.
- **Keep `[store].path` on local storage.** `flock` over NFS depends
  on `lockd` and is not guaranteed; SQLite over NFS is unsupported
  anyway.
- **A restart is not blocked by it.** A starting daemon waits up to
  60 seconds for its predecessor to finish draining, so
  `service hound restart` behaves normally. Readers (`hound alerts`,
  the dashboard, `hound export`) never take the lock at all.

## Why host networking

`network_mode: host` is required, not a convenience. A bridged container
gets its own network namespace and would see only its own veth pair — none
of the camera VLANs, which is the entire point. There are no published
ports because the agent listens on nothing; it only makes outbound
connections to the collector.

The container holds `CAP_NET_RAW` and, because of `cap_drop: ALL`,
nothing else. That is what `tcpdump` needs to open a capture socket. A
process reading every packet on the camera segment should not be able to
do anything else if it is subverted.

## The `interface = "any"` caveat

`"any"` captures every interface at once and is tempting when you have a
VLAN interface per camera. It has a real cost: **traffic crossing two
monitored interfaces is counted twice.** Routed traffic between two camera
VLANs is seen on both, so byte counts roughly double, which inflates flow
volumes and can trip `bulk_inbound` on transfers that never happened.

Name the interface you mean where you can. If you genuinely need several,
prefer running one agent per segment with distinct `sensor_id`s over
`"any"` — the collector shows them separately and the counts stay honest.

(`"any"` also yields Linux SLL2 cooked headers rather than Ethernet, which
the parser handles, but snapshots are less useful because there are no
real link-layer addresses to inspect.)

## State

`/var/lib/hound` is a **named volume**, not a bind mount, so it survives
`docker compose down` and a re-create. This matters: the daemon bootstraps
its seen-device set from that database, and losing it means `new_device`
fires again for every camera on the next start.

To reset deliberately:

```bash
docker compose down
docker volume rm agent_hound-state
```

## What the agent does and does not do

- It runs the **whole** pipeline locally: capture, flow aggregation,
  device discovery, classification and uptime tracking — plus
  baselining if you turn `[baseline]` on, which is off by default here
  as it is everywhere else.
- It dispatches **nothing**. Any `[[notify]]` block in its config is
  ignored. The collector is the only thing that notifies, so one camera
  outage does not page you once per sensor.
- If the collector is unreachable, observations spool to disk and replay
  when it returns, bounded by both `spool_max_bytes` and
  `spool_max_age_seconds` — whichever is hit first drops the oldest. It
  says so in its own log when the link first drops and hourly after.
- **One push window can arrive as several batches.** If a window's
  records would exceed the collector's body limit, the agent halves how
  many it sends and keeps the rest for the next batch rather than
  building something that gets refused. Lossless, and logged.
- Relayed records land in `remote_*` tables on the collector and can never
  overwrite its own observations. No code on the ingest path writes any
  of the collector's own tables — the isolation is structural, not a
  validation rule that could be bypassed. The test suite proves it with
  a SQLite authorizer that fails the build if an ingest-path write ever
  touches a local table. That is a build-time gate, not a control
  running in your collector.

## Updating

```bash
git pull
docker compose up -d --build
```

The named volume is untouched by a rebuild, so no re-alert storm.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `No such device exists` | `interface` names a container interface, or a host interface that does not exist. Check `ip -br link` **on the host**. |
| Nothing relays, no error | Check `docker compose logs`: a spooling agent logs `collector unreachable ... spooling` when the link first drops and hourly after, with batch count and last error. `hound relay` on the agent config prints the same depth plus the drop totals. |
| `certificate fingerprint mismatch` | The collector's cert was regenerated. Re-read it and update `tls_fingerprint`. Do not disable pinning. |
| `401` from the collector | Key mismatch, or `sensor_id` has no `[[relay.sensor]]` entry on the collector. **Spooled batches are discarded, not held** — a rejection that retrying cannot fix would wedge the spool, so each one is dropped with a `dropping spooled batch` log line. Observations made while the key was wrong are gone. Fix it promptly. |
| `400` or `413`, *too big* | The batch exceeds that collector's limits. The agent adopts them from the rejection, splits the batch and resends, logging `split into N smaller batch(es)`. If it keeps happening, set `max_records_per_batch` and `max_body_bytes` to the same values on BOTH ends. A single record that is still refused is dropped and logged. |
| `400`, *sent_at is ±Ns from collector time* | The two clocks disagree by more than `clock_skew_seconds`. **Nothing is discarded** — the batch stays spooled and goes as soon as the clocks agree, because fixing the clock makes the identical batch valid. Fix NTP on the agent. If you never do, the backlog ages out through `spool_max_age_seconds` and `hound relay` counts it under `dropped age`. |
| `400`, *a record was rejected* | One or more records are malformed. The agent splits the batch and resends, which salvages the good records and narrows the loss to the individual bad one, logged as `dropping spooled batch`. |
| `401`, or a `400` the agent cannot narrow | The key or `sensor_id` is wrong, or a single record is itself unacceptable. Retrying cannot help, so **that batch is discarded** and logged. For a `401`, everything observed while the key was wrong is gone — fix it promptly. |
| `507` from the collector | The collector is low on disk. The agent spools and retries; free space there, and run `hound prune --relay-days <N>` on the collector to expire relayed rows. That is safe with the service up. It rebuilds the store in place, which needs roughly the whole file size free again — if there is not that much it says so, and the freed pages stay reusable in place, so ingest is not blocked by the shortfall. To shrink the file on a genuinely full disk, **stop the service** and re-run with `--offline-compact`; that form needs room only for the live data. It refuses while the daemon holds the store, so stopping the service is not optional. The agent logs `collector unreachable ... spooling` once and hourly. |
| Byte counts look doubled | `interface = "any"` across VLANs. See above. |
