#!/usr/bin/env bash
# Download the pinned OPNsense nano image into cache/.
# Idempotent: if the file is already present and non-empty, skips the fetch
# and prints the cached SHA-256.
set -euo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

mkdir -p "${CACHE_DIR}"

if [[ -s "${IMAGE_BZ_PATH}" ]]; then
    echo "[fetch] already cached: ${IMAGE_BZ_PATH} ($(du -h "${IMAGE_BZ_PATH}" | cut -f1))"
    echo "[fetch] sha256: $(sha256sum "${IMAGE_BZ_PATH}" | awk '{print $1}')"
    exit 0
fi

echo "[fetch] downloading ${OPNSENSE_IMAGE_URL}"
echo "[fetch]   → ${IMAGE_BZ_PATH}"
echo "[fetch] this is ~300 MB; ctrl-C aborts cleanly"

# --fail surfaces 404 / 500 as non-zero; --location follows mirror redirects;
# --continue-at resumes a partial download; --progress-bar is human-friendly.
curl --fail --location --continue-at - --progress-bar \
     --output "${IMAGE_BZ_PATH}.part" \
     "${OPNSENSE_IMAGE_URL}"
mv "${IMAGE_BZ_PATH}.part" "${IMAGE_BZ_PATH}"

# Pull the published checksum file and verify (no GPG dance — the mirror is
# https and the checksum file lives alongside the image, so an attacker would
# need to compromise both. Good enough for a dev rig.)
echo "[fetch] verifying against published checksum file"
curl --fail --location --silent \
     --output "${CACHE_DIR}/checksums.sha256" \
     "${OPNSENSE_CHECKSUMS_URL}"
# OPNsense ships checksums in BSD format: "SHA256 (file) = hash"
EXPECTED="$(grep -F "(${OPNSENSE_IMAGE_BZ})" "${CACHE_DIR}/checksums.sha256" | sed -E 's/.* = //')"
ACTUAL="$(sha256sum "${IMAGE_BZ_PATH}" | awk '{print $1}')"
if [[ -z "${EXPECTED}" ]]; then
    echo "[fetch] WARNING: ${OPNSENSE_IMAGE_BZ} not listed in checksums file" >&2
elif [[ "${EXPECTED}" != "${ACTUAL}" ]]; then
    echo "[fetch] FATAL: checksum mismatch" >&2
    echo "[fetch]   expected: ${EXPECTED}" >&2
    echo "[fetch]   actual:   ${ACTUAL}" >&2
    rm -f "${IMAGE_BZ_PATH}"
    exit 1
else
    echo "[fetch] sha256 OK: ${ACTUAL}"
fi
echo "[fetch] done — ${IMAGE_BZ_PATH} ($(du -h "${IMAGE_BZ_PATH}" | cut -f1))"
