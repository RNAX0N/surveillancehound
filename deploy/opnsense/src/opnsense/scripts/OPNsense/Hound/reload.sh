#!/bin/sh
# SurveillanceHound — configd "reload" action.
#
# Called from /usr/local/opnsense/service/conf/actions.d/actions_hound.conf
# whenever the operator saves Services > SurveillanceHound:
#
#   1) re-render /usr/local/etc/hound.toml from the live model
#   2) auto-mint a self-signed TLS cert if HTTPS is enabled and no
#      operator-supplied paths are in the model (so the embedded dashboard
#      iframe survives the firewall UI being HTTPS — browsers block HTTP
#      iframes on HTTPS parents)
#   3) bounce the daemon so it picks up the new config
#
# Fails loudly (non-zero exit) so configd surfaces errors in the UI.

set -e

SCRIPT_DIR="$(dirname "$0")"
PY=/usr/local/bin/python3
CERT_DIR=/var/lib/hound
CERT_FILE="${CERT_DIR}/hound-web.crt"
KEY_FILE="${CERT_DIR}/hound-web.key"
INGEST_CERT="${CERT_DIR}/hound-ingest.crt"
INGEST_KEY="${CERT_DIR}/hound-ingest.key"

if [ ! -x "${PY}" ]; then
    echo "python3 not found at ${PY}; install python from pkg first" >&2
    exit 1
fi

"${PY}" "${SCRIPT_DIR}/render_config.py"

# If the rendered TOML asks for the auto-cert paths, materialize them.
# Idempotent — only generates when the files don't already exist (or are
# unreadable). openssl ships with OPNsense base, so no extra pkg dep.
#
# `cn` is cosmetic for both of these: the dashboard cert is trusted by the
# browser only after the operator accepts it, and the ingest cert is pinned
# by fingerprint rather than validated by name.
mint_cert() {
    _cert="$1"; _key="$2"; _cn="$3"; _what="$4"
    grep -q "^[a-z_]* *= *\"${_cert}\"" /usr/local/etc/hound.toml 2>/dev/null || return 0
    [ -s "${_cert}" ] && [ -s "${_key}" ] && return 0
    echo "minting self-signed TLS cert for ${_what} → ${_cert}"
    install -d -m 0750 "${CERT_DIR}"
    _host=$(hostname -s 2>/dev/null || echo opnsense)
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout "${_key}" -out "${_cert}" \
        -subj "/CN=${_cn}/O=SurveillanceHound (auto-generated)" \
        -addext "subjectAltName=DNS:localhost,DNS:${_host},IP:127.0.0.1" \
        2>/dev/null
    chmod 0640 "${_cert}" "${_key}"
    # Best-effort: hand to the hound user if it exists
    chown hound:hound "${_cert}" "${_key}" 2>/dev/null || true
}

mint_cert "${CERT_FILE}" "${KEY_FILE}" "hound-web" "hound web"

# The relay listener needs its own certificate. Without this, selecting
# Collector in the UI produced a daemon that logged "cannot load ingest
# certificate" and simply never listened — nothing in the UI said so.
mint_cert "${INGEST_CERT}" "${INGEST_KEY}" "hound-ingest" "hound relay ingest"

# Put rc.conf in step with the Enable tick-box, then act on it.
#
# This used to read hound_enable and restart only when it was already YES —
# but nothing ever set it. The operator ticked Enable, the config rendered,
# and the daemon was never enabled, never started, and did not come back
# after a reboot either. `service hound status` said "not running" with no
# log file, because it had genuinely never run.
ENABLED=$("${PY}" "${SCRIPT_DIR}/render_config.py" --print-enabled 2>/dev/null || echo NO)

if [ "${ENABLED}" = "YES" ]; then
    sysrc hound_enable=YES >/dev/null 2>&1 || true
    # onerestart rather than restart: rc.subr's restart is a no-op when the
    # service was not already running, which is exactly the first-enable case.
    /usr/local/etc/rc.d/hound onerestart
else
    sysrc hound_enable=NO >/dev/null 2>&1 || true
    /usr/local/etc/rc.d/hound onestop >/dev/null 2>&1 || true
fi
