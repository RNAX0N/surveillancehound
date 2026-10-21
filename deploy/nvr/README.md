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
