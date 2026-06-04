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

if [ ! -x "${PY}" ]; then
    echo "python3 not found at ${PY}; install python from pkg first" >&2
    exit 1
fi

"${PY}" "${SCRIPT_DIR}/render_config.py"

# If the rendered TOML asks for the auto-cert paths, materialize them.
# Idempotent — only generates when the files don't already exist (or are
# unreadable). openssl ships with OPNsense base, so no extra pkg dep.
if grep -q "^cert_file *= *\"${CERT_FILE}\"" /usr/local/etc/hound.toml 2>/dev/null; then
    if [ ! -s "${CERT_FILE}" ] || [ ! -s "${KEY_FILE}" ]; then
        echo "minting self-signed TLS cert for hound web → ${CERT_FILE}"
        install -d -m 0750 "${CERT_DIR}"
        # CN matches the bind host the dashboard will be served on; SAN
        # covers loopback + the firewall's primary hostname so the same
        # cert works whether the operator browses via IP or DNS.
        HOSTNAME=$(hostname -s 2>/dev/null || echo opnsense)
        openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
            -keyout "${KEY_FILE}" -out "${CERT_FILE}" \
            -subj "/CN=hound-web/O=SurveillanceHound (auto-generated)" \
            -addext "subjectAltName=DNS:localhost,DNS:${HOSTNAME},IP:127.0.0.1" \
            2>/dev/null
        chmod 0640 "${CERT_FILE}" "${KEY_FILE}"
        # Best-effort: hand to the hound user if it exists
        chown hound:hound "${CERT_FILE}" "${KEY_FILE}" 2>/dev/null || true
    fi
fi

# only restart if currently enabled
if [ "$(sysrc -n hound_enable 2>/dev/null)" = "YES" ]; then
    /usr/local/etc/rc.d/hound onerestart
fi
