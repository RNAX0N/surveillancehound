# Teardown — getting back to a clean slate

The rig is designed to leave no footprint outside `deploy/dev/opnsense-vm/`.
No system services installed, no `sudo` required, no host firewall changes,
no SSH config touched, no `/etc/hosts` entries.

## Stop the VM cleanly

```bash
cd deploy/dev/opnsense-vm
make stop          # ACPI powerdown via QEMU monitor (gives FreeBSD time to fsync)
make status        # confirm "VM: stopped"
```

If `make stop` ever hangs (rare — only if the monitor socket is broken),
fall back to:

```bash
pkill -f "qemu-system-x86_64.*opnsense.qcow2"
rm -f var/qemu.pid var/*.sock
```

## Delete everything

Three levels of cleanup, pick the one that fits:

### 1. Quick reset — keep the downloaded image, rebuild the VM next time

```bash
make teardown
```

- Stops the VM.
- Deletes `var/opnsense.qcow2`, sockets, pidfile, console log.
- **Keeps** `cache/OPNsense-*.img.bz2` so `make disk` + `make boot` skip the
  re-download on the next run (saves 5-10 min on slow connections).

### 2. Full wipe — also reclaim the ~550 MB cache

```bash
make teardown
rm -rf cache/
```

Or in one shot:

```bash
make teardown && rm -rf cache/
```

### 3. Nuke the whole rig directory

If you want it gone entirely (e.g. you decided not to ship the dev rig):

```bash
cd ..                           # one level up, so you don't `rm` your CWD
rm -rf opnsense-vm/
```

The `deploy/dev/` parent stays — other dev-only artifacts can live there.

## What's NOT auto-cleaned (and how to check)

| Thing | Why kept by default | How to remove |
|---|---|---|
| `cache/checksums.sha256` | Re-verifying the image without re-downloading | `rm cache/checksums.sha256` |
| Host SSH `known_hosts` | We pass `UserKnownHostsFile=/dev/null` so there's nothing to clean | n/a |
| Listening ports `127.0.0.1:2222` / `127.0.0.1:8443` | QEMU releases them on shutdown | `ss -ltn \| grep -E ':(2222\|8443)'` should be empty after `make stop` |
| `/tmp` files | None — everything lives under the rig dir | n/a |

## Re-creating the VM from scratch

If you want a *truly* fresh OPNsense (factory-default config), the qcow2 is
all that needs to go — the image is golden:

```bash
make teardown                              # removes the qcow2 only
make disk && make boot && make first-boot  # rebuilds the VM in ~5 min
```

## Verifying nothing leaked

After teardown, this should print nothing:

```bash
ls var/ 2>/dev/null               # gone
ps -ef | grep qemu-system | grep -v grep
ss -ltn '( sport = :2222 or sport = :8443 )'
```

And the rig directory should hold only the scripts you can re-run:

```bash
ls deploy/dev/opnsense-vm/
# README.md  TEARDOWN.md  Makefile  vars.sh  scripts/  (cache/ if you kept it)
```
