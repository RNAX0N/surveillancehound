# SurveillanceHound — OPNsense plugin

A native OPNsense plugin that runs SurveillanceHound on your firewall and
adds **Services → SurveillanceHound** to the OPNsense UI.

What this plugin does:

- Installs a model + Volt view + MVC controllers + configd actions for the
  service lifecycle (start / stop / restart / reload / status).
- Renders `/usr/local/etc/hound.toml` from the model on every save.
- Adds a `Services → SurveillanceHound` menu with a settings tab, an embedded
  live-dashboard tab (iframe to `hound web`), and a help tab.
- Ships an rc.d script so the daemon survives reboots once enabled.

It does **not** bundle the Python source — the operator installs Python 3.11+
and `hound` from this repo on the firewall (see [Install](#install)).

## Layout

```
deploy/opnsense/
├── install.sh                      # one-command installer (run this)
├── uninstall.sh                    # mirror of install.sh
├── Makefile                        # FreeBSD ports-style; uses OPNsense plugins.mk
├── pkg-descr                       # pkg description
├── src/
│   ├── usr/local/etc/rc.d/hound    # FreeBSD rc.d service script
│   └── opnsense/                   # → installs to /usr/local/opnsense/
│       ├── mvc/app/
│       │   ├── controllers/OPNsense/Hound/
│       │   │   ├── IndexController.php          # Services > Hound page
│       │   │   ├── forms/general.xml            # settings form
│       │   │   └── Api/{Settings,Service}Controller.php
│       │   ├── models/OPNsense/Hound/
│       │   │   ├── Hound.php                    # BaseModel marker stub
│       │   │   ├── Hound.xml                    # config schema
│       │   │   ├── ACL/ACL.xml                  # auth.x patterns
│       │   │   └── Menu/Menu.xml                # menu placement
│       │   └── views/OPNsense/Hound/index.volt  # Volt template (UI)
│       ├── scripts/OPNsense/Hound/
│       │   ├── render_config.py    # /conf/config.xml → /usr/local/etc/hound.toml
│       │   └── reload.sh           # configd "reload": render + mint cert + bounce
│       └── service/conf/actions.d/actions_hound.conf  # configd actions
└── README.md (this file)
```

## Install

### The one-command way (recommended)

On the firewall, as `root`, from a checkout of this repo:

```sh
sh deploy/opnsense/install.sh
```

That's it. The script is idempotent and dependency-free: it verifies
Python 3.11+ / tcpdump (both ship with OPNsense), installs the `hound`
CLI without pip (a `.pth` + a wrapper — nothing to break on the next
firmware update), creates the `hound` service user + `/var/lib/hound` +
`/var/log/hound`, drops the plugin files into place, and refreshes the
UI. Re-run it any time (e.g. after a major OPNsense upgrade, which can
strip drop-in plugins).

No checkout on the firewall yet? Bootstrap from your fork in one line —
set `HOUND_REPO_URL` to it first (the public repo URL is a placeholder):

```sh
HOUND_REPO_URL=https://github.com/RNAX0N/surveillancehound \
  fetch -o - https://raw.githubusercontent.com/RNAX0N/surveillancehound/main/deploy/opnsense/install.sh | sh
```

When it finishes, open **Services → SurveillanceHound**, pick the listen
interface + camera IPs, tick **Enable**, and hit **Save & restart**.

To remove it: `sh deploy/opnsense/uninstall.sh` (add `HOUND_PURGE=1` to
also drop the user and `/var/lib/hound` data).

### The package way (`pkg install`, survives updates)

For a genuine `pkg`-tracked install that survives firmware upgrades and
auto-updates, use the `os-hound` package. The GitHub Actions workflow
(`.github/workflows/build-opnsense-pkg.yml`) builds a signed `.pkg` on every
release and can publish a pkg repository you subscribe the firewall to:

```sh
# quick: install a release asset directly (one-off; may not survive a major upgrade)
pkg add https://github.com/RNAX0N/surveillancehound/releases/download/v0.1.0/os-hound-0.1.0.pkg

# durable: subscribe to the signed repo, then it upgrades with `pkg upgrade`
fetch -o /usr/local/etc/pkg/repos/hound-repo.pub \
  https://rnax0n.github.io/surveillancehound/opnsense/hound-repo.pub
cp pkg/hound.conf.sample /usr/local/etc/pkg/repos/hound.conf   # edit RNAX0N
pkg update && pkg install os-hound
```

The package bundles the Python sources and declares no hard dependencies
(OPNsense already ships python3 + tcpdump), and its post-install creates the
user/dirs and refreshes the UI. Full details,
the one-time signing-key setup, ABI/FreeBSD-version matching, and the path to
upstreaming into official `opnsense/plugins` are in **[`pkg/README.md`](pkg/README.md)**.

You can also build the legacy ports way (`make package`) on an OPNsense build
host with the `tools/`/`core/` repos checked out — see the Makefile.

### Manual drop-in (what install.sh automates)

If you'd rather do it by hand, these are the exact steps. Note the rc.d
script ships under `src/usr/local/etc/rc.d/`, and the MVC tree lands in
`/usr/local/opnsense/`:

```sh
pkg install -y python311 tcpdump        # usually already present on OPNsense
git clone https://github.com/RNAX0N/surveillancehound /usr/local/src/SurveillanceHound

# install the CLI (zero deps — no pip needed)
PY=/usr/local/bin/python3
SITEPKG=$("$PY" -c 'import site; print(site.getsitepackages()[0])')
echo /usr/local/src/SurveillanceHound/src > "$SITEPKG/surveillancehound.pth"
printf '#!/bin/sh\nexec %s -m surveillancehound.cli "$@"\n' "$PY" > /usr/local/bin/hound
chmod 0555 /usr/local/bin/hound

# create the service user + state/log dirs
pw groupadd hound
pw useradd hound -g hound -s /usr/sbin/nologin -d /var/lib/hound
install -d -o hound -g hound -m 0750 /var/lib/hound
install -d -o hound -g hound -m 0755 /var/log/hound

# drop the plugin files in place
SRC=/usr/local/src/SurveillanceHound/deploy/opnsense/src
install -m 0555 "${SRC}/usr/local/etc/rc.d/hound" /usr/local/etc/rc.d/hound
cp -a "${SRC}/opnsense/." /usr/local/opnsense/
chmod 0755 /usr/local/opnsense/scripts/OPNsense/Hound/*.sh \
           /usr/local/opnsense/scripts/OPNsense/Hound/*.py

# refresh the OPNsense UI so it picks up the new menu / model / view
service configd restart
configctl webgui restart
```

Open **Services → SurveillanceHound** in the OPNsense UI, fill in the
listen interface + camera IPs, tick **Enable**, hit **Save & restart**.

## How it gets permission to capture

The daemon runs as the unprivileged `hound` user, not as root — it parses
untrusted bytes off the wire for a living, so it should not do that with
full privilege. FreeBSD has no `capabilities(7)`, so there is no
equivalent of the Linux `setcap cap_net_raw` on tcpdump. Instead the rc
script grants the service user group access to `/dev/bpf` (normally
`crw------- root:wheel`) at every start, re-applied on each boot by the
service itself rather than by taking over the global devfs ruleset.

Set `hound_grant_bpf=NO` in `/etc/rc.conf` to manage BPF access yourself
(a devfs ruleset of your own, or running as root). The service logs a
warning and keeps going if the grant fails, so you find out from the log
rather than from silence.

The rendered `/usr/local/etc/hound.toml` is written `0640 hound:hound`.
It carries webhook URLs, SMTP passwords and FTP credentials, so it is
deliberately not world-readable — and configd's own `umask 027` would
otherwise leave it root-owned and unreadable by the daemon.

## Interface names

The form stores the OPNsense interface **alias** (`lan`, `opt3`); the
renderer translates it to the real device (`igb1`, `vlan0.20`) by reading
`<interfaces>` from `/conf/config.xml`, because tcpdump only knows device
names. If you type a device name directly into the field it is passed
through unchanged.

## Run the dashboard outside OPNsense

The plugin's UI tab embeds the dashboard via an iframe. If your browser
blocks mixed-content (you're on HTTPS for OPNsense and the dashboard is
HTTP), open the dashboard at `http://<firewall-ip>:8080/` directly — or
front it with an OPNsense **System → Settings → Administration**
reverse-proxy entry.

## Add more notifiers

Edit the rendered `/usr/local/etc/hound.toml` or, more durably,
`/etc/hound.toml.local` (the rc.d script loads it before the rendered
file). Examples for Slack, syslog → Security Onion, SMTP, FTP, etc.
are in `hound.toml.example` at the repo root.

## Uninstall

```sh
sh deploy/opnsense/uninstall.sh              # remove plugin + CLI, keep data
HOUND_PURGE=1 sh deploy/opnsense/uninstall.sh  # also drop user + /var/lib/hound
```

Or by hand:

```sh
service hound onestop
sysrc -x hound_enable
rm -f  /usr/local/etc/rc.d/hound /usr/local/bin/hound
rm -rf /usr/local/opnsense/mvc/app/{controllers,models,views}/OPNsense/Hound \
       /usr/local/opnsense/scripts/OPNsense/Hound
rm -f  /usr/local/opnsense/service/conf/actions.d/actions_hound.conf
rm -f  /usr/local/lib/python3.*/site-packages/surveillancehound.pth
configctl webgui restart
# optionally: rm -rf /var/lib/hound /var/log/hound
```
