# Single source of truth for the OPNsense validation rig.
# Sourced by every script under scripts/. Override by exporting before `make`.

# --- OPNsense image pin ------------------------------------------------------
# Using the "serial" flavor (not "nano") because:
#   - primary console is serial (matches our -serial qemu flag)
#   - filesystem is read-write (lets us pkg install python311 + persist /conf)
#   - smaller than the dvd installer + no installer to script around
: "${OPNSENSE_VERSION:=26.1.6}"
: "${OPNSENSE_FLAVOR:=serial-amd64}"
: "${OPNSENSE_MIRROR:=https://mirrors.nycbug.org/pub/opnsense/releases}"
# The mirror directory is the release series, which is not always the full
# version string (26.7 ships as ".../26.7/OPNsense-26.7-...", there is no
# 26.7.7 image). Override OPNSENSE_RELEASE_DIR if they ever diverge further.
: "${OPNSENSE_RELEASE_DIR:=${OPNSENSE_VERSION}}"
OPNSENSE_IMAGE_BZ="OPNsense-${OPNSENSE_VERSION}-${OPNSENSE_FLAVOR}.img.bz2"
OPNSENSE_IMAGE_URL="${OPNSENSE_MIRROR}/${OPNSENSE_RELEASE_DIR}/${OPNSENSE_IMAGE_BZ}"
OPNSENSE_CHECKSUMS_URL="${OPNSENSE_MIRROR}/${OPNSENSE_RELEASE_DIR}/OPNsense-${OPNSENSE_VERSION}-checksums-amd64.sha256"

# --- Instance scoping --------------------------------------------------------
# One rig directory, many OPNsense versions. Everything that can collide
# between two concurrently-installed versions — the state dir (qcow2, sockets,
# ssh key, api key) and the three host port forwards — is derived from
# OPNSENSE_VERSION.
#
#   OPNSENSE_VERSION=26.1.6  (the original instance)  → var/      , 2222/8443/8080
#   OPNSENSE_VERSION=26.7                             → var-26.7/ , 2892/9113/8750
#
# RIG_BASE_VERSION keeps the first instance on the original paths and ports so
# nothing that was built before versioned instances existed has to move.
: "${RIG_BASE_VERSION:=26.1.6}"

RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${RIG_DIR}/cache"
REPO_ROOT="$(cd -- "${RIG_DIR}/../../.." && pwd)"
PLUGIN_SRC="${REPO_ROOT}/deploy/opnsense/src"

if [[ "${OPNSENSE_VERSION}" == "${RIG_BASE_VERSION}" ]]; then
    : "${VAR_DIR:=${RIG_DIR}/var}"
    : "${PORT_OFFSET:=0}"
else
    : "${VAR_DIR:=${RIG_DIR}/var-${OPNSENSE_VERSION}}"
    # Deterministic, collision-free for the versions we care about, and easy to
    # recompute by hand: (major mod 10) * 100 + minor * 10.
    #   26.7   → 6*100 + 7*10  = 670
    #   27.1   → 7*100 + 1*10  = 710
    _rig_major="${OPNSENSE_VERSION%%.*}"
    _rig_rest="${OPNSENSE_VERSION#*.}"
    _rig_minor="${_rig_rest%%.*}"
    : "${PORT_OFFSET:=$(( (10#${_rig_major} % 10) * 100 + 10#${_rig_minor} * 10 ))}"
    unset _rig_major _rig_rest _rig_minor
fi

IMAGE_BZ_PATH="${CACHE_DIR}/${OPNSENSE_IMAGE_BZ}"
IMAGE_RAW_PATH="${CACHE_DIR}/${OPNSENSE_IMAGE_BZ%.bz2}"
CHECKSUMS_PATH="${CACHE_DIR}/checksums-${OPNSENSE_VERSION}.sha256"
DISK_QCOW2="${VAR_DIR}/opnsense.qcow2"
QEMU_PID="${VAR_DIR}/qemu.pid"
QEMU_MONITOR_SOCK="${VAR_DIR}/monitor.sock"
CONSOLE_SOCK="${VAR_DIR}/console.sock"
CONSOLE_LOG="${VAR_DIR}/console.log"
SSH_KEY="${VAR_DIR}/ssh_key"

# --- VM sizing ---------------------------------------------------------------
: "${VM_MEM_MB:=1024}"
: "${VM_CPUS:=1}"
: "${VM_DISK_GB:=8}"

# --- Networking --------------------------------------------------------------
# host → guest port forwards. PORT_OFFSET (see "Instance scoping") is 0 for
# the base version and version-derived for every other instance.
#   2222+off → 22   : SSH (validation + manual login)
#   8443+off → 443  : OPNsense webgui (browse Services → SurveillanceHound)
#   8080+off → 8080 : `hound web` (on the base instance the host port matches
#                     the guest one, which the old iframe dashboard relied on)
: "${HOST_SSH_PORT:=$(( 2222 + PORT_OFFSET ))}"
: "${HOST_HTTPS_PORT:=$(( 8443 + PORT_OFFSET ))}"
: "${HOST_DASH_PORT:=$(( 8080 + PORT_OFFSET ))}"

# --- Dev-only credentials (DO NOT REUSE) ------------------------------------
# OPNsense ships nano with root:opnsense; first-boot.sh rotates to this:
: "${ROOT_PASSWORD:=hound-dev}"
