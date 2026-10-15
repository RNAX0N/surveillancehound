# OPNsense plugin validation rig

Disposable QEMU/KVM VM that runs real OPNsense for end-to-end validation of
`deploy/opnsense/` — the one validation surface that pure-Python tests can't cover
(Phalcon MVC routing + configd action invocation).

All scripts are pure Bash + stdlib Python + QEMU. No Vagrant, libvirt, Docker,
Ansible — no extra deps beyond what a stock Arch / Debian box already has.

## What's pinned

| | |
|---|---|
| OPNsense version | **26.1.6** by default (`serial-amd64`) — `vars.sh` is the single source of truth. Set `OPNSENSE_VERSION` for another one (26.7 is verified: FreeBSD 15.1, PHP 8.5) |
| Mirror | `mirrors.nycbug.org` (pkgsrc-friendly, https, no auth) |
| Image flavor | nano — pre-installed root FS, boots straight to a login prompt on serial |
| Hypervisor | QEMU `x86_64` + KVM acceleration |
| Memory / CPU | 1 GB / 1 vCPU (enough for `wazuh-logtest`-class workloads; bump in `vars.sh` if you push it) |
| Disk | 8 GB qcow2 (raw image is ~3 GB; the grow gives room for `pkg install python311`) |
| Networking | QEMU user-mode (SLIRP) with three host-side forwards: `2222 → 22` (SSH), `8443 → 443` (UI), `8080 → 8080` (`hound web`). Non-default versions get a version-derived offset — see *Running more than one version* |
| Console | UNIX socket at `<state dir>/console.sock` — attach with `make console` |
| Root password | `hound-dev` (set on first boot; **dev/test only** — never expose this VM beyond localhost) |

## Quick start

```bash
cd deploy/dev/opnsense-vm
make help
make fetch        # download + verify the nano image (one-time, ~300 MB)
make disk         # decompress + convert to qcow2 (one-time)
make boot         # start the VM in the background (writes var/qemu.pid)
make first-boot   # drive the console once to enable SSH (one-time per fresh disk)
make ssh          # interactive shell on the VM (uses var/ssh_key)
make plugin-drop  # scp the plugin tree over
make validate     # run all routing + configd assertions, prints PASS/FAIL summary
make stop         # graceful shutdown
make teardown     # stop + delete the qcow2 (keeps the original .img.bz cache)
```

`make validate` is the only target that returns a non-zero exit on failure; the rest
print human progress.

## Running more than one version

Every target honours `OPNSENSE_VERSION`. The state directory and all three host
port forwards are derived from it, so two versions can be up at once and neither
touches the other's disk, SSH key or API key:

```bash
make status                           # the default instance: var/, ssh 2222
OPNSENSE_VERSION=26.7 make fetch      # cache/ is shared; filenames carry the version
OPNSENSE_VERSION=26.7 make disk       # → var-26.7/opnsense.qcow2
OPNSENSE_VERSION=26.7 make boot       # → ssh 2892, ui 9113, dash 8750
OPNSENSE_VERSION=26.7 make first-boot
OPNSENSE_VERSION=26.7 make status     # prints this instance's ports + paths
```

| | state dir | ssh | ui | dash |
|---|---|---|---|---|
| 26.1.6 (`RIG_BASE_VERSION`) | `var/` | 2222 | 8443 | 8080 |
| 26.7 | `var-26.7/` | 2892 | 9113 | 8750 |

The offset is `(major mod 10) * 100 + minor * 10` (26.7 → 670); override it with
`PORT_OFFSET=<n>`, or pin individual ports with `HOST_SSH_PORT` / `HOST_HTTPS_PORT`
/ `HOST_DASH_PORT`. The base version deliberately keeps the original paths and
ports so an instance built before this existed needs no migration.

Mind two things when adding a version:

- the mirror directory is the release *series*, not always the full version —
  26.7's image is `.../26.7/OPNsense-26.7-serial-amd64.img.bz2` and there is no
  26.7.7 image. Set `OPNSENSE_RELEASE_DIR` if the two ever diverge further.
- a fresh image's **webgui** password is OPNsense's default (`opnsense`);
  `first-boot.sh` only rotates the *system* password that SSH uses. Never reset
  the webgui password with PHP `local_user_set()` — it wipes
  `/root/.ssh/authorized_keys` and locks the rig out of SSH.

**The rig is key-only on purpose.** `ssh-wrap.sh` passes `BatchMode=yes`,
`PreferredAuthentications=publickey` and `NumberOfPasswordPrompts=0`, so a
key failure fails immediately instead of falling back to password auth —
which on a desktop spawns an `ssh-askpass` GUI prompt and hangs the run
forever waiting on a human. If you see "Permission denied (publickey)",
re-run `make first-boot`; do not type a password.

**Do not reset the VM's root webgui password with PHP `local_user_set()`.**
It wipes `/root/.ssh/authorized_keys` and resets root's shell, locking the
rig out of SSH. Recovery is via the serial console
(`socat - UNIX-CONNECT:var/console.sock`).

## Files

```
deploy/dev/opnsense-vm/
├── Makefile                  one entrypoint per phase
├── vars.sh                   pinned versions + paths (sourced by every script)
├── README.md                 this file
├── scripts/
│   ├── fetch-image.sh        curl mirror → cache/, verify size + record SHA
│   ├── prepare-disk.sh       bunzip2 → qemu-img convert → resize to 8 GB
│   ├── boot.sh               qemu-system-x86_64 with KVM + serial socket
│   ├── stop.sh               graceful shutdown via QEMU monitor, kill fallback
│   ├── first-boot.sh         drives console.sock via socat to enable SSH
│   ├── ssh-wrap.sh           ssh/scp helpers wired to the right key + port
│   ├── plugin-drop.sh        scp deploy/opnsense/src + pkg install python311
│   └── validate.sh           runs all Phalcon + configd assertions
├── var/                      runtime state of the base instance (qemu.pid, console.sock, ssh_key, logs)
├── var-<version>/            same, per non-default OPNSENSE_VERSION
├── scripts/status.sh         what `make status` prints
└── cache/                    downloaded image artifacts (gitignored)
```

`var/`, `var-*/` and `cache/` are gitignored — nothing here is checked in beyond the scripts
themselves.

## What's actually being validated

The whole reason this rig exists is the three things the in-repo Python tests
genuinely can't reach:

1. **Phalcon MVC routing** — `validate.sh` issues authenticated `curl` requests
   against `/ui/hound/`, `/api/hound/settings/get`, and `/api/hound/service/status`
   and asserts on the JSON envelope shape. Catches namespace / class-name /
   directory-path mismatches that pass `php -l` but fail to auto-route.
2. **configd action invocation** — exercises `configctl hound {status,reload,restart}`
   and tails `/var/log/configd.log` for the action-exec line. Catches missing
   `actions.d/*.conf` files, wrong `command:` paths, perms on reload.sh.
3. **Model serialization round-trip** — saves a config via the API, reads
   `/conf/config.xml` back, feeds it through `render_config.py`, and confirms the
   result parses with `surveillancehound.config.load_from_dict`. Catches drift
   between what Phalcon stores and what render_config.py expects to read.

## Security notes

This VM exists for plugin validation, **not** for general OPNsense use:

- Root password is a hard-coded dev string in `vars.sh`. Don't reuse it.
- SSH is bound to `127.0.0.1` on the host (port 2222 for the base instance) — never to a routable interface.
- The QEMU NIC is user-mode (SLIRP); the guest can reach the internet but the
  outside world cannot reach the guest except via the explicit `hostfwd` rules.
- `make teardown` deletes the qcow2 but leaves `cache/` so re-creation is fast.

If you want to expose the UI for clicking around, use `ssh -L 8443:localhost:8443`
on the host — don't change the QEMU bind address.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `make boot` hangs / "Could not access KVM kernel module" | `/dev/kvm` not readable — `sudo usermod -aG kvm $USER && newgrp kvm` |
| `make first-boot` times out at console login | Console banner changed between OPNsense versions; attach with `socat - UNIX-CONNECT:var/console.sock`, drive manually, then bump the regexes in `scripts/first-boot.sh` |
| `make ssh` "Connection refused" | First-boot didn't actually enable SSH — re-run `make first-boot`, then check `tail var/console.log` |
| `make validate` 403s on /api/hound/* | ACL pattern off — check `deploy/opnsense/src/opnsense/mvc/app/models/OPNsense/Hound/ACL/ACL.xml`, then `make plugin-drop` again |
| `make validate` 404s on /api/hound/* | Phalcon didn't auto-load the controller — check filename + namespace + `configctl webgui restart` actually ran |
