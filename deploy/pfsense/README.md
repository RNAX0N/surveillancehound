# SurveillanceHound — pfSense package

A drop-in pfSense package that adds **Services → SurveillanceHound** to the
pfSense UI: settings form (interface, camera IPs, baselining, snapshots,
dashboard bind), service status, an embedded live-dashboard iframe.

pfSense's package system is older and more constrained than OPNsense's,
so this is a single-file `<packagegui>` definition (`hound.xml`) plus a
PHP include with the install/uninstall/resync hooks and the TOML
renderer. The rc.d script is installed by the include on package install.

## Layout

```
deploy/pfsense/
├── usr/local/pkg/
│   ├── hound.xml        # packagegui — menu, settings fields, hooks
│   └── hound.inc        # install / deinstall / resync; TOML renderer
├── usr/local/www/
│   └── hound.php        # Services > SurveillanceHound dashboard page
└── README.md (this file)
```

## Install (drop-in, no package server)

You need shell access to the pfSense box.

```bash
# 1) prerequisites
pkg install -y python311 tcpdump
git clone https://github.com/RNAX0N/surveillancehound /usr/local/src/SurveillanceHound
pip install /usr/local/src/SurveillanceHound      # installs /usr/local/bin/hound

# 2) drop the package files in place
SRC=/usr/local/src/SurveillanceHound/deploy/pfsense
cp -a "${SRC}/usr/local/pkg/" /usr/local/pkg/
cp -a "${SRC}/usr/local/www/" /usr/local/www/

# 3) register the package with pfSense so it appears in the menu
php -r '
require_once("/etc/inc/config.inc");
require_once("/etc/inc/pkg-utils.inc");
$conf = parse_config(true);
if (!isset($conf["installedpackages"])) $conf["installedpackages"] = [];
if (!isset($conf["installedpackages"]["package"])) {
    $conf["installedpackages"]["package"] = [];
}
$conf["installedpackages"]["package"][] = [
    "name" => "SurveillanceHound",
    "internal_name" => "hound",
    "descr" => "IP-camera network monitor",
    "version" => "0.1",
    "configurationfile" => "hound.xml",
];
write_config("Install SurveillanceHound");
'

# 4) run the install hook (creates dirs, rc.d, renders empty toml)
php -r 'require_once("/usr/local/pkg/hound.inc"); hound_install_command();'
```

Now open **Services → SurveillanceHound** in the pfSense UI, click
**Edit settings**, fill in the listen interface and your camera IPs,
tick **Enable**, and save. The package's resync hook will regenerate
`/usr/local/etc/hound.toml` and restart the service.

## Add custom notifiers

Edit `/etc/hound.toml.local` (the rc.d script sources it before the
rendered config). Examples for Slack, syslog → Security Onion, SMTP, FTP,
etc. are in `hound.toml.example` at the repo root.

## Caveats

- The pfSense package GUI does not auto-validate that the interface you
  picked actually exists; double-check with `ifconfig` if the daemon
  refuses to start.
- The embedded dashboard iframe is HTTP. If your pfSense UI is HTTPS,
  mixed-content blocking may prevent it from rendering — use the
  **Open dashboard ↗** link to open it in its own tab, or front
  `hound web` with pfSense's haproxy / nginx package.

## Uninstall

```bash
php -r 'require_once("/usr/local/pkg/hound.inc"); hound_deinstall_command();'
rm -f /usr/local/pkg/hound.xml /usr/local/pkg/hound.inc \
      /usr/local/www/hound.php
# manually remove the entry from /cf/conf/config.xml under
# <installedpackages><package> ... or use the WebGUI Package Manager.
```
