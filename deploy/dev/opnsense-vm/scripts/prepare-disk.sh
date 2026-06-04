#!/usr/bin/env bash
# Convert the bz2-compressed raw image into a sparse qcow2 with headroom.
# Idempotent: noop if var/opnsense.qcow2 already exists and is non-empty.
set -euo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

mkdir -p "${VAR_DIR}"

if [[ -s "${DISK_QCOW2}" ]]; then
    echo "[disk] ${DISK_QCOW2} exists — skipping ($(du -h "${DISK_QCOW2}" | cut -f1))"
    echo "[disk] (delete the file or 'make teardown' to rebuild)"
    exit 0
fi

if [[ ! -s "${IMAGE_BZ_PATH}" ]]; then
    echo "[disk] FATAL: ${IMAGE_BZ_PATH} not present — run 'make fetch' first" >&2
    exit 1
fi

echo "[disk] decompressing ${IMAGE_BZ_PATH} → ${IMAGE_RAW_PATH}"
bzip2 -dkc "${IMAGE_BZ_PATH}" > "${IMAGE_RAW_PATH}.part"
mv "${IMAGE_RAW_PATH}.part" "${IMAGE_RAW_PATH}"

echo "[disk] raw image: $(du -h "${IMAGE_RAW_PATH}" | cut -f1)"
echo "[disk] converting raw → qcow2"
qemu-img convert -f raw -O qcow2 -p "${IMAGE_RAW_PATH}" "${DISK_QCOW2}.part"
mv "${DISK_QCOW2}.part" "${DISK_QCOW2}"

echo "[disk] resizing qcow2 to ${VM_DISK_GB}G (sparse — actual size grows on use)"
qemu-img resize "${DISK_QCOW2}" "${VM_DISK_GB}G"

echo "[disk] done"
qemu-img info "${DISK_QCOW2}"

# Free the decompressed raw — qcow2 backs everything from here on
rm -f "${IMAGE_RAW_PATH}"
echo "[disk] removed intermediate raw image"
