#!/usr/bin/env bash
# Thin wrapper around ssh/scp with the rig's key, port, and "yeah I know it's
# a self-signed dev VM" options pre-baked.
#   ssh-wrap.sh ssh [args...]            # opens a session, or runs a command
#   ssh-wrap.sh scp <src> <dst>          # the dst uses 'vm:' as the prefix
#   ssh-wrap.sh curl-ui [curl-args...]   # curl bound to https://127.0.0.1:8443/
set -euo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

if [[ ! -f "${SSH_KEY}" ]]; then
    echo "[ssh] FATAL: ${SSH_KEY} missing — run 'make first-boot' first" >&2
    exit 1
fi

# BatchMode + PreferredAuthentications: this rig is key-only, so a key
# failure must fail FAST and loudly. Without them ssh falls back to
# password auth, and on a desktop that spawns ssh-askpass — a GUI password
# prompt, on a developer's screen, from an automated run that then hangs
# forever waiting on it. That happened: a password reset on the VM wiped
# /root/.ssh/authorized_keys and left a prompt up for 40 minutes.
# Never give an unattended script a path to an interactive credential ask.
SSH_OPTS=(
    -i "${SSH_KEY}"
    -p "${HOST_SSH_PORT}"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR
    -o ConnectTimeout=10
    -o BatchMode=yes
    -o PreferredAuthentications=publickey
    -o NumberOfPasswordPrompts=0
)

cmd="${1:-ssh}"; shift || true
case "${cmd}" in
    ssh)
        exec ssh "${SSH_OPTS[@]}" "root@127.0.0.1" "$@"
        ;;
    scp)
        # scp uses -P (uppercase) for the port, NOT ssh's lowercase -p — so it
        # needs its own option array, otherwise -p is read as "preserve times"
        # and the connection falls back to port 22.
        SCP_OPTS=(
            -i "${SSH_KEY}"
            -P "${HOST_SSH_PORT}"
            -o StrictHostKeyChecking=no
            -o UserKnownHostsFile=/dev/null
            -o LogLevel=ERROR
            -o ConnectTimeout=10
            -o BatchMode=yes
            -o PreferredAuthentications=publickey
            -o NumberOfPasswordPrompts=0
        )
        # Translate "vm:..." → root@127.0.0.1:... for either side
        args=()
        for a in "$@"; do
            args+=("${a/vm:/root@127.0.0.1:}")
        done
        exec scp "${SCP_OPTS[@]}" -r "${args[@]}"
        ;;
    curl-ui)
        # Sensible defaults for the OPNsense UI: ignore self-signed, use basic
        # auth, time out aggressively, follow redirects.
        exec curl -sk \
             --connect-timeout 5 --max-time 30 \
             -u "root:${ROOT_PASSWORD}" \
             "$@"
        ;;
    *)
        echo "usage: $(basename "$0") {ssh|scp|curl-ui} ..." >&2
        exit 2
        ;;
esac
