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
OPNSENSE_IMAGE_BZ="OPNsense-${OPNSENSE_VERSION}-${OPNSENSE_FLAVOR}.img.bz2"
OPNSENSE_IMAGE_URL="${OPNSENSE_MIRROR}/${OPNSENSE_VERSION}/${OPNSENSE_IMAGE_BZ}"
OPNSENSE_CHECKSUMS_URL="${OPNSENSE_MIRROR}/${OPNSENSE_VERSION}/OPNsense-${OPNSENSE_VERSION}-checksums-amd64.sha256"

# --- Paths -------------------------------------------------------------------
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${RIG_DIR}/cache"
VAR_DIR="${RIG_DIR}/var"
REPO_ROOT="$(cd -- "${RIG_DIR}/../../.." && pwd)"
PLUGIN_SRC="${REPO_ROOT}/deploy/opnsense/src"

IMAGE_BZ_PATH="${CACHE_DIR}/${OPNSENSE_IMAGE_BZ}"
IMAGE_RAW_PATH="${CACHE_DIR}/${OPNSENSE_IMAGE_BZ%.bz2}"
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
# host → guest port forwards.
#   2222 → 22   : SSH (validation + manual login)
#   8443 → 443  : OPNsense webgui (browse Services → SurveillanceHound)
#   8080 → 8080 : embedded dashboard iframe (matches the default web.port,
#                 so window.location.hostname in the Volt iframe lands here)
: "${HOST_SSH_PORT:=2222}"
: "${HOST_HTTPS_PORT:=8443}"
: "${HOST_DASH_PORT:=8080}"

# --- Dev-only credentials (DO NOT REUSE) ------------------------------------
# OPNsense ships nano with root:opnsense; first-boot.sh rotates to this:
: "${ROOT_PASSWORD:=hound-dev}"
