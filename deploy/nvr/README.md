# NVR host operations

Tools for the box the relay agent runs on. Not part of the daemon.

## `nft-drift`

Answers a question neither `nft -c -f` nor `nft list ruleset` can: **does
the live firewall match the file that claims to define it?**

A firewall has two states that can silently disagree, and both directions
cost you:

- a rule added **live** and never written to the config vanishes at the
  next reload, reboot or `docker restart`
- a rule written to the **config** and never applied means you believe
  you are protected and are not

The second one was already true on the NVR when this was written:
`/etc/sysctl.conf` carried hardening keys that had never been applied, so
`rp_filter` read `0` while the file said otherwise.

`nft -c -f` tells you the file parses. `nft list ruleset` tells you what
is loaded. Nothing compared them.

So this renders the config in a **throwaway network namespace** — which
has its own empty nftables — and diffs it against live. The namespace is
what makes the render free of consequences: no flush, no reload, nothing
on the host is touched. Only tables the config itself defines are
compared, so Docker's iptables-nft tables are ignored instead of being
reported as drift forever.

```
nft-drift [config]     # 0 = in sync, 1 = drift, 2 = error
```

Install with the timer so it actually runs — an unscheduled checker is
itself a config that never executes:

```
install -m 0755 nft-drift /usr/local/sbin/nft-drift
# nft-drift.service (oneshot) + nft-drift.timer (OnBootSec=3min, hourly)
systemctl enable --now nft-drift.timer
```

Non-zero exit marks the unit **failed**, which surfaces in
`systemctl --failed` — a place operators already look. A checker whose
only output is a log line nobody greps has the same defect it exists to
find.

The boot run matters most: a reboot is exactly when live-only rules
disappear.

### Why not `flush ruleset` + `systemctl restart docker`

That was the other candidate for the same problem and it is worse on both
counts. Restarting Docker is disruptive — on this host it restarted
Frigate and cost ~5 minutes of recording — and it only restores *Docker's*
tables. Any rule hand-added to another table is still gone, silently,
which is the failure this tool reports.

## `gsfw-observe` + `gsfw-observe.nft` — the P1 observation window

Before enforcing a firewall lockdown on a host that records twelve
cameras, measure what the lockdown would have broken.

`gsfw-observe.nft` loads a table that **cannot drop a packet**: both
chains are `policy accept` and no rule contains a `drop` or `reject`
verb (the only matches are the words inside counter comments — checked).
Every named counter in it corresponds to exactly one DROP that the P2
forward lockdown or P3 input lockdown will introduce.

```
nft -f gsfw-observe.nft                     # observe only, cannot drop
install -m 0755 gsfw-observe /usr/local/sbin/
systemctl enable --now gsfw-observe.timer   # hourly samples
# ... 24 hours later ...
gsfw-observe summary                        # markdown review + GO/NO-GO
```

The summary is deliberately hard to pass:

- a counter the lockdown is **meant** to stop reads `expected`
- any **other** non-zero counter reads `UNEXPECTED` and forces NO-GO —
  finding the unpredicted flows is the whole point of the window
- a counter that **must** be in use (cameras' NTP) reading zero also
  forces NO-GO: more likely the window did not see it than that nothing
  needs it
- **no samples at all is NO-GO**, not a pass. An empty set is evidence
  nothing was *watched*, not that nothing *happened* — a distinction
  this project has got wrong before
- a window shorter than 23h is NO-GO, because partial observation reads
  as "nothing unexpected" for the hours it did not watch

`snapshot` is append-only and never interprets; `summary` interprets and
never writes to the samples. A summary that could rewrite its own inputs
cannot be audited.
