#!/usr/bin/env bash
# Drop deploy/opnsense/src/ onto the running VM and refresh the webgui so
# Phalcon picks up the new controllers/models/views.
#
# Idempotent: re-runs cleanly, overwriting prior copies.
set -euo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

SSH="${RIG_DIR}/scripts/ssh-wrap.sh ssh"
SCP="${RIG_DIR}/scripts/ssh-wrap.sh scp"

if ! ${SSH} 'echo connected' >/dev/null 2>&1; then
    echo "[plugin-drop] FATAL: cannot SSH to VM — is it booted + first-booted?" >&2
    exit 1
fi

echo "[plugin-drop] live image is RO at / — remounting RW"
# OPNsense's serial image has unionfs over /usr/local — writes go to the
# tmpfs upper layer, which is fine for a dev rig. /etc and /var are also
# unionfs (writable). / itself is the only RO mount; we don't write there.
${SSH} 'mount -uw / 2>&1 | head -3 || true'

echo "[plugin-drop] uploading plugin tree (split by pkg convention)"
# An OPNsense plugin's `src/` tree mirrors what `pkg install` would lay down:
#   src/etc/...             → /etc/...                  (base-system paths)
#   src/usr/local/...       → /usr/local/...            (third-party paths, incl. rc.d)
#   src/opnsense/...        → /usr/local/opnsense/...   (mvc, scripts, service/conf)
# A real `pkg install os-hound-*.txz` does that split via plugins.mk; we do
# it manually for the dev drop. Anything else under src/ is treated as relative
# to / (so add new top-level dirs to this loop if you create them).
for d in etc usr; do
    if [[ -d "${PLUGIN_SRC}/${d}" ]]; then
        tar -C "${PLUGIN_SRC}" -cf - "${d}" | ${SSH} "tar -C / -xf - && echo ok-${d}"
    fi
done
if [[ -d "${PLUGIN_SRC}/opnsense" ]]; then
    tar -C "${PLUGIN_SRC}/opnsense" -cf - . | \
        ${SSH} 'mkdir -p /usr/local/opnsense && tar -C /usr/local/opnsense -xf - && echo ok-opnsense'
fi

echo "[plugin-drop] ensuring rc.d script + helpers are executable"
${SSH} 'chmod +x /etc/rc.d/hound /usr/local/opnsense/scripts/OPNsense/Hound/reload.sh 2>&1 | head -3 || true'

echo "[plugin-drop] dropping hound user + state dirs (idempotent)"
${SSH} '
pw groupshow hound >/dev/null 2>&1 || pw groupadd hound
pw usershow  hound >/dev/null 2>&1 || pw useradd hound -g hound -s /usr/sbin/nologin -d /var/lib/hound -m
install -d -o hound -g hound /var/lib/hound /var/log/hound
'

echo "[plugin-drop] uploading SurveillanceHound Python source"
# Skip the venv / git / cache cruft; only the runtime is needed
tar -C "${REPO_ROOT}" --exclude '__pycache__' --exclude '.git' --exclude 'tests' \
    --exclude 'cache' --exclude 'var' --exclude 'deploy/dev' \
    -cf - src pyproject.toml hound.toml.example \
  | ${SSH} 'mkdir -p /usr/local/src/SurveillanceHound && tar -C /usr/local/src/SurveillanceHound -xf -'

# OPNsense 26.1 ships python3 (currently 3.13) at /usr/local/bin/python3.
# We deliberately don't pip-install — the daemon has zero runtime deps anyway,
# so a thin shim is plenty.
echo "[plugin-drop] installing /usr/local/bin/hound shim"
${SSH} 'cat > /usr/local/bin/hound <<"EOF"
#!/bin/sh
export PYTHONPATH=/usr/local/src/SurveillanceHound/src
exec /usr/local/bin/python3 -m surveillancehound.cli "$@"
EOF
chmod +x /usr/local/bin/hound'

echo "[plugin-drop] restarting configd so it parses actions_hound.conf"
# configctl doesn't have a "reload" — full restart is the documented way to
# pick up new actions.d/*.conf files (idempotent, ~2 sec downtime).
${SSH} 'service configd restart 2>&1 | head -3' || true
sleep 2

echo "[plugin-drop] restarting webgui so Phalcon re-scans the controllers"
${SSH} 'configctl webgui restart' || true
sleep 3

echo "[plugin-drop] minting an API key for root (used by validate.sh)"
# OPNsense's UI auth uses CSRF-protected session cookies; for scripted API
# calls the recommended path is per-user API key+secret pairs sent as HTTP
# Basic auth (no CSRF dance). 26.1 dropped `configctl auth user newapikey`,
# so we generate it via PHP using OPNsense's own config helpers and append
# to root's <apikeys> in /conf/config.xml. Idempotent: re-runs append a new
# key (the rig only ever uses the most recent one).
${SSH} 'php -r "
require_once(\"config.inc\");
require_once(\"auth.inc\");
global \$config;
\$key = base64_encode(random_bytes(60));
\$secret_plain = base64_encode(random_bytes(60));
\$secret_hash = password_hash(\$secret_plain, PASSWORD_BCRYPT);
foreach (\$config[\"system\"][\"user\"] as \$idx => \$user) {
    if (\$user[\"name\"] === \"root\") {
        if (!isset(\$config[\"system\"][\"user\"][\$idx][\"apikeys\"]) || !is_array(\$config[\"system\"][\"user\"][\$idx][\"apikeys\"])) {
            \$config[\"system\"][\"user\"][\$idx][\"apikeys\"] = [\"item\" => []];
        }
        \$config[\"system\"][\"user\"][\$idx][\"apikeys\"][\"item\"][] = [\"key\" => \$key, \"secret\" => \$secret_hash];
        break;
    }
}
write_config(\"adding API key for validation rig\", false);
echo \"key=\" . \$key . PHP_EOL;
echo \"secret=\" . \$secret_plain . PHP_EOL;
" 2>&1' > "${VAR_DIR}/apikey.txt"
if grep -q '^key=' "${VAR_DIR}/apikey.txt" && grep -q '^secret=' "${VAR_DIR}/apikey.txt"; then
    echo "[plugin-drop] api key saved to ${VAR_DIR}/apikey.txt"
else
    echo "[plugin-drop] WARN: API key creation may have failed — check ${VAR_DIR}/apikey.txt"
    cat "${VAR_DIR}/apikey.txt"
fi

echo "[plugin-drop] done — try: make validate"
