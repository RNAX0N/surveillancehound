# Development notes

Design decisions and deferred work, kept here so the reasoning survives
instead of being re-derived every time someone looks at the code.

## Roadmap: verified liveness

Uptime monitoring is **passive**: a camera counts as up because packets from
it were observed on the monitored interface. Two follow-ons that would make it
*verified* rather than *inferred* were considered and deliberately deferred.

### Active probing — ICMP ping + TCP connect

Today a camera that is powered and recording, but no longer visible to this
sensor (moved VLAN, mirror/SPAN port re-patched, uplink moved), is
indistinguishable from one that is powered down. A probe collapses that
ambiguity, and the two probe types answer different questions: ICMP says the
box is powered and on the network, a TCP connect to 554/80/8000 says its
service stack is still alive. Together they separate *powered down* from *up
but hung / rebooting / stream stopped* — a distinction an operator acts on
differently.

Shape it would take: ICMP via the system `ping` binary as a subprocess (works
on Linux and FreeBSD with no extra capability; a raw socket would need
`CAP_NET_RAW` in the daemon itself, which the hardened systemd unit
deliberately scopes to tcpdump). TCP via stdlib `socket` with a short timeout.
Both stay stdlib and LAN-local, so neither breaks the zero-dependency or
offline-by-default constraints.

The cost is the trust boundary. Hound stops being a pure passive sensor and
starts emitting traffic toward the cameras. "It cannot possibly disturb the
recordings" is currently unconditionally true, and that is worth something —
so this should be opt-in, with the probe interval and per-camera port list
configurable.

The groundwork is already in place: `uptime.py`'s `Transition` model and the
`outages` table are probe-agnostic. A prober would feed the same state
machine; the only new surface is an `evidence` field separating
observed-traffic from probe-confirmed.

### Deep packet inspection

Parsing RTSP/ONVIF verbs or TLS SNI would let the daemon confirm a camera is
actually *streaming* rather than merely emitting packets — the strongest form
of "this camera is working" — and would sharpen classification generally.

It also contradicts the headers-only rule, which is a threat-model commitment
rather than an implementation shortcut: the daemon currently cannot leak video
or credentials because it never reads a payload byte. Doing this needs a
deliberate, documented decision to change that, and almost certainly an opt-in
flag that is off by default. Treat the constraint as load-bearing until
someone decides otherwise in writing.

## Where machine learning does and doesn't belong here

Two places it buys something real, as opposed to box-ticking:

1. **Per-camera behavioral baselining inside the daemon** — learn each
   device's normal envelope (bytes/peers/ports per time-of-day bucket) and
   score deviations. This fixes the tool's biggest weakness, which is that
   static thresholds false-positive as soon as they are tuned for one camera.
   Shipped, in `baseline.py`, with two models.
2. **Triage assistance over the alert log** — grouping, summarising and
   prioritising a backlog. This has to be an out-of-band tool the operator
   invokes, never something the daemon runs.

The constraint that decides the shape of both: an always-running monitor that
reaches the internet defeats the point of putting it on the wire. Baselining
is fine because it is local, deterministic and auditable — though it does add
a cold-start window and the occasional "is this an anomaly or is it patch
day?" judgement call. Anything needing a network round-trip has to be a
separate, operator-triggered tool that reads the audit log and takes no
action.

## Known gaps

`deploy/wazuh/hound-decoder.xml` uses patterns containing `\S+?`, `\d+` and
`$`. Lazy quantifiers and `$` are PCRE constructs; Wazuh's default decoder
engine is OS_Regex, which does not support them, and PCRE2 requires an
explicit `type="pcre2"`. The decoder may therefore be matching less than
intended on the syslog ingestion path. Not verified against a live Wazuh
manager — it needs one to settle.
