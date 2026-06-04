#!/bin/sh
#
# SurveillanceHound — OPNsense uninstaller. Mirrors install.sh.
#
#     sh deploy/opnsense/uninstall.sh            # remove plugin + CLI
#     HOUND_PURGE=1 sh deploy/opnsense/uninstall.sh   # also drop user + data
#
# By default it KEEPS /var/lib/hound (your SQLite history + snapshots) and the
# hound user. Set HOUND_PURGE=1 to remove those too.

set -eu

say()  { printf '\033[36m▸\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "run as root."

say "stopping + disabling the daemon"
service hound onestop >/dev/null 2>&1 || true
sysrc -x hound_enable >/dev/null 2>&1 || true

say "removing the plugin files"
rm -f  /usr/local/etc/rc.d/hound
rm -rf /usr/local/opnsense/mvc/app/controllers/OPNsense/Hound \
       /usr/local/opnsense/mvc/app/models/OPNsense/Hound \
       /usr/local/opnsense/mvc/app/views/OPNsense/Hound \
       /usr/local/opnsense/scripts/OPNsense/Hound
rm -f  /usr/local/opnsense/service/conf/actions.d/actions_hound.conf
ok "plugin removed"

say "removing the hound CLI"
rm -f /usr/local/bin/hound
for sp in /usr/local/lib/python3.*/site-packages/surveillancehound.pth; do
    [ -e "$sp" ] && rm -f "$sp"
done
ok "CLI removed"

if [ "${HOUND_PURGE:-0}" = "1" ]; then
    say "purging user + data (HOUND_PURGE=1)"
    pw userdel hound  >/dev/null 2>&1 || true
    pw groupdel hound >/dev/null 2>&1 || true
    rm -rf /var/lib/hound /var/log/hound /usr/local/etc/hound.toml /etc/hound.toml.local
    ok "user + data purged"
else
    warn "kept /var/lib/hound, /var/log/hound, and the hound user."
    warn "to remove them too: HOUND_PURGE=1 sh $0"
fi

say "refreshing the OPNsense UI"
command -v configctl >/dev/null 2>&1 && configctl webgui restart >/dev/null 2>&1 || true
ok "done."
