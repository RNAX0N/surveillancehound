#!/usr/bin/env bash
# Show what the current instance (OPNSENSE_VERSION) has on disk and running.
# Everything printed here is derived from vars.sh, so it always matches what
# boot.sh / ssh-wrap.sh would use.
set -uo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

printf 'instance: OPNsense %s (%s)\n' "${OPNSENSE_VERSION}" "${OPNSENSE_FLAVOR}"
printf 'state:    %s\n' "${VAR_DIR}"
printf 'ports:    ssh %s → 22   ui %s → 443   dash %s → 8080  (offset %s)\n' \
    "${HOST_SSH_PORT}" "${HOST_HTTPS_PORT}" "${HOST_DASH_PORT}" "${PORT_OFFSET}"

if [[ -f "${QEMU_PID}" ]] && kill -0 "$(cat "${QEMU_PID}")" 2>/dev/null; then
    printf 'VM:       running (pid %s)\n' "$(cat "${QEMU_PID}")"
else
    printf 'VM:       stopped\n'
fi

[[ -S "${CONSOLE_SOCK}" ]] && printf 'console:  %s\n' "${CONSOLE_SOCK}"

if [[ -s "${DISK_QCOW2}" ]]; then
    printf 'disk:     %s at %s\n' "$(du -h "${DISK_QCOW2}" | cut -f1)" "${DISK_QCOW2}"
else
    printf 'disk:     not built (make disk)\n'
fi

if [[ -s "${IMAGE_BZ_PATH}" ]]; then
    printf 'image:    %s cached (%s)\n' \
        "$(du -h "${IMAGE_BZ_PATH}" | cut -f1)" "$(basename "${IMAGE_BZ_PATH}")"
else
    printf 'image:    not fetched (make fetch)\n'
fi

if nc -z 127.0.0.1 "${HOST_SSH_PORT}" 2>/dev/null; then
    printf 'ssh:      open on 127.0.0.1:%s\n' "${HOST_SSH_PORT}"
else
    printf 'ssh:      not reachable yet (make boot && make first-boot)\n'
fi

# Other instances present in the rig directory, so `make status` never hides
# a VM that is quietly running under a different version.
shopt -s nullglob
for d in "${RIG_DIR}"/var "${RIG_DIR}"/var-*; do
    [[ "${d}" == "${VAR_DIR}" ]] && continue
    [[ -s "${d}/opnsense.qcow2" ]] || continue
    if [[ -f "${d}/qemu.pid" ]] && kill -0 "$(cat "${d}/qemu.pid")" 2>/dev/null; then
        printf 'other:    %s — VM running (pid %s)\n' "$(basename "${d}")" "$(cat "${d}/qemu.pid")"
    else
        printf 'other:    %s — disk present, VM stopped\n' "$(basename "${d}")"
    fi
done
