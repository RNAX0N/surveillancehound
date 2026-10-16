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

Do not read that as harmless. Connections AND requests are metered per
source, and an over-budget source is refused at accept — but a peer
that can reach the port still makes the collector do work, and the
collector is the same process that parses packets. Before the
metering that now covers it, a sustained TLS handshake flood was
measured taking two thirds of local packet-parse throughput on a
single-CPU collector, which is what a 1-vCPU firewall VM is. No alert
reports that: packets are still arriving, so `capture_stalled` cannot
fire.

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
  without holding any key. If you run more than a couple of agents
  behind one address, give them distinct addresses, and treat that
  NAT as part of the collector's trust boundary.
- **An attacker on the agent host itself** can read the shared secret
  out of `hound.toml`. Nothing on the collector helps with that; it is
  the agent host's own security boundary.

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
  device discovery, classification, uptime tracking, baselining.
- It dispatches **nothing**. Any `[[notify]]` block in its config is
  ignored. The collector is the only thing that notifies, so one camera
  outage does not page you once per sensor.
- If the collector is unreachable, observations spool to disk and replay
  when it returns, bounded by both `spool_max_bytes` and
  `spool_max_age_seconds` — whichever is hit first drops the oldest.
- Relayed records land in `remote_*` tables on the collector and can never
  overwrite its own observations. That isolation is enforced by a SQLite
  authorizer, not merely intended.

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
| Nothing relays, no error | Check `docker compose logs`. A spooling agent logs the failure each flush; `hound relay` on the agent config prints spool depth. |
| `certificate fingerprint mismatch` | The collector's cert was regenerated. Re-read it and update `tls_fingerprint`. Do not disable pinning. |
| `401` from the collector | Key mismatch, or `sensor_id` has no `[[relay.sensor]]` entry on the collector. |
| `507` from the collector | The collector is low on disk. The agent spools and retries; free space there. |
| Byte counts look doubled | `interface = "any"` across VLANs. See above. |
