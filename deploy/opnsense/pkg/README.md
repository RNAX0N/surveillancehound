# os-hound — building & shipping the OPNsense package

This directory turns SurveillanceHound into a real, `pkg`-installable OPNsense
package (`os-hound`). It bundles the Python sources *inside* the package and
declares no hard dependencies — OPNsense already ships python3 (configd is
written in it) and tcpdump (base), and the bundled `/usr/local/bin/hound`
wrapper finds python 3.11+. No pip, no `.pth`, no git checkout. This also lets
`pkg add` the package succeed fully offline.

> Verified on the dev VM (`make package-test`): builds on FreeBSD 14.3,
> `pkg add` installs it, the CLI runs from the bundled sources, post-install
> creates the user + dirs, and `pkg delete` removes it cleanly. ✓

```
deploy/opnsense/pkg/
├── build-pkg.sh        # builds os-hound-X.Y.Z.pkg (+ optional signed repo). FreeBSD only.
├── hound.conf.sample   # /usr/local/etc/pkg/repos/hound.conf for auto-updating installs
└── README.md           # this file
```

The build runs in CI via `.github/workflows/build-opnsense-pkg.yml` (a FreeBSD
VM on a Linux runner — a FreeBSD-ABI package must be built on FreeBSD).

## The three ways to install — and which survives updates

| Tier | Command | Survives firmware upgrades? | Auto-updates? |
|------|---------|------------------------------|---------------|
| **A. Script drop-in** | `sh deploy/opnsense/install.sh` | ❌ (re-run after upgrade) | ❌ |
| **B. `pkg add` a release asset** | `pkg add https://…/os-hound-X.Y.Z.pkg` | ⚠️ minor yes, major may drop it | ❌ |
| **C. Subscribe to the pkg repo** | add `hound.conf`, then `pkg install os-hound` | ✅ | ✅ (`pkg upgrade`) |
| **D. Official `opnsense/plugins`** | ships with OPNsense | ✅✅ | ✅ |

Why B doesn't reliably survive a *major* OPNsense upgrade: the upgrade
reinstalls from OPNsense's configured repositories and treats packages it
doesn't recognize as foreign — it can remove them. A standalone `pkg add` of a
release file is exactly that. **Tier C fixes this**: once the firewall has a
configured, signed repo for `os-hound`, the package is a first-class citizen of
`pkg upgrade` and the update process keeps it.

## Does it show up in System → Firmware → Plugins?

Yes. This was verified on a real OPNsense 26.1.6 box, and the answer matters
because it is the difference between "a package you install over SSH" and "a
plugin". OPNsense's `FirmwareController::infoAction()` filters the plugin list
on nothing but the `os-` name prefix — there is **no repository allowlist**, so
a plugin from a third-party repo is listed like any other.

Two caveats that will otherwise waste your afternoon:

- Repository provenance sets the **tier**. Anything not from `OPNsense` or
  `SunnyValley` is tier 4, and tier-4 rows are hidden until you tick **Show
  community plugins** — unless they are already installed or configured, in
  which case they show unconditionally.
- OPNsense refuses to install *any* plugin while core is behind its repo
  ("Installation out of date..."). Update the firmware first. This is generic
  OPNsense behaviour, nothing to do with this package.

The plugin also has to register itself, or none of the durability below is
real. `firmware/register.php` only records a plugin in `config.xml` when a file
under `/usr/local/opnsense/version/` carries `product_id` equal to the package
name. `build-pkg.sh` stages that file; without it the UI shows the plugin as
"(orphaned)" and `sync.subr.sh` will not reinstall it after a firmware upgrade.

## Tier C — subscribe a firewall to the repo (recommended)

1. The release workflow publishes a **signed pkg repository** to GitHub Pages at
   `https://rnax0n.github.io/surveillancehound/opnsense/` (only if you've set the
   signing-key secret — see below). It publishes the client-side `hound.conf`
   alongside the catalogue, so there is nothing to hand-edit.
2. On the firewall:
   ```sh
   fetch -o /usr/local/etc/pkg/repos/hound-repo.pub \
     https://rnax0n.github.io/surveillancehound/opnsense/hound-repo.pub
   fetch -o /usr/local/etc/pkg/repos/hound.conf \
     https://rnax0n.github.io/surveillancehound/opnsense/hound.conf
   pkg update
   pkg install os-hound
   ```
   Or, once the repo is configured, install it from the GUI: **System →
   Firmware → Plugins**, tick **Show community plugins**, pick `os-hound`.
3. Thereafter `pkg upgrade` updates `os-hound` like any other package.

## One-time signing-key setup (enables Tier C)

The catalog is signed with an RSA key so firewalls can verify it. Generate a
keypair once, keep the private key as a GitHub Actions secret, publish the
public key with the repo:

```sh
openssl genrsa -out hound-repo.key 4096
openssl rsa -in hound-repo.key -pubout -out hound-repo.pub
# add the PRIVATE key as a repository secret named HOUND_REPO_SIGNING_KEY:
gh secret set HOUND_REPO_SIGNING_KEY < hound-repo.key
# keep hound-repo.key OFFLINE and out of git. The workflow derives + publishes
# the matching .pub automatically.
```

Then enable GitHub Pages for the repo (**Settings → Pages → Source: GitHub
Actions**). On the next published release, the `publish-repo` job builds the
signed repo and deploys it. Without the secret, releases still attach the raw
`.pkg` (Tier B) — the repo step is simply skipped.

## Building locally (on FreeBSD / an OPNsense box)

```sh
# unsigned package only:
sh deploy/opnsense/pkg/build-pkg.sh --version 0.1.0
#   → dist/os-hound-0.1.0.pkg   (install with: pkg add dist/os-hound-0.1.0.pkg)

# package + signed repo:
sh deploy/opnsense/pkg/build-pkg.sh --version 0.1.0 --sign /path/to/hound-repo.key
#   → dist/os-hound-0.1.0.pkg and dist/repo/ (meta.conf, packagesite.*, .pub)
```

`build-pkg.sh` must run on FreeBSD because it uses `pkg create` / `pkg repo`.
On Linux, use the CI workflow (or push a tag / cut a release to trigger it).

### What the package contains

| Path | What |
|------|------|
| `/usr/local/bin/hound` | CLI wrapper (`python3 -m surveillancehound.cli`) |
| `/usr/local/share/hound/lib/surveillancehound/` | bundled Python sources |
| `/usr/local/etc/rc.d/hound` | rc.d service |
| `/usr/local/opnsense/mvc/.../OPNsense/Hound/` | the Services → SurveillanceHound UI |
| `/usr/local/opnsense/scripts/OPNsense/Hound/` | config renderer + reload |
| `/usr/local/opnsense/service/conf/actions.d/actions_hound.conf` | configd actions |

The **post-install** script creates the `hound` user + `/var/lib/hound` +
`/var/log/hound` and restarts the webgui; **pre-deinstall** stops and disables
the daemon. `/usr/local/etc/hound.toml` is *not* shipped — it's rendered by the
UI on first **Save & restart**, so `pkg` never clobbers your config on upgrade.

## Matching your OPNsense's FreeBSD base

The package ABI must match the firewall. Set `FREEBSD_VERSION` in the workflow
(and `--abi` locally):

| OPNsense | FreeBSD base | ABI |
|----------|--------------|-----|
| 25.x / 26.x | 14 | `FreeBSD:14:amd64` |
| 24.x | 13 | `FreeBSD:13:amd64` |

(Your dev rig pins OPNsense 26.1.6 → FreeBSD 14, which the workflow defaults to.)

## Tier D — getting it into official `opnsense/plugins`

The most durable outcome is upstreaming. The plugin tree here already follows
OPNsense's `src/` layout and ships a `Makefile` using `plugins.mk`, so the path is:

1. Fork [`opnsense/plugins`](https://github.com/opnsense/plugins), add this under
   `security/hound/` (the `deploy/opnsense/` contents map onto a plugin port).
2. Build with their infra: `make package` from inside the plugins tree on an
   OPNsense build host.
3. Open a PR. Once merged, `os-hound` is installable from **System → Firmware →
   Plugins** and tracked by OPNsense itself — Tier D, no custom repo needed.

Until then, **Tier C is the practical equivalent**: a genuine `pkg install
os-hound` that auto-updates and survives upgrades, hosted by you.
