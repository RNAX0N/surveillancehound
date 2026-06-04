#!/usr/bin/env bash
# Boot the OPNsense VM in the background.
#   - KVM acceleration if /dev/kvm is writable
#   - User-mode networking with two hostfwd rules
#   - Serial console exposed as a UNIX socket for scripted + interactive attach
#   - QEMU monitor exposed as a separate UNIX socket for shutdown
set -euo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

mkdir -p "${VAR_DIR}"

if [[ ! -s "${DISK_QCOW2}" ]]; then
    echo "[boot] FATAL: ${DISK_QCOW2} not present — run 'make disk' first" >&2
    exit 1
fi

if [[ -f "${QEMU_PID}" ]] && kill -0 "$(cat "${QEMU_PID}")" 2>/dev/null; then
    echo "[boot] VM already running (pid $(cat "${QEMU_PID}"))"
    exit 0
fi

# Remove any stale sockets — qemu refuses to bind over an existing path
rm -f "${CONSOLE_SOCK}" "${QEMU_MONITOR_SOCK}"

ACCEL_FLAGS=()
if [[ -w /dev/kvm ]]; then
    ACCEL_FLAGS=(-enable-kvm -cpu host)
    echo "[boot] KVM acceleration: on (-cpu host)"
else
    ACCEL_FLAGS=(-cpu qemu64)
    echo "[boot] KVM acceleration: OFF — boot will be ~10x slower"
    echo "[boot]   fix: sudo usermod -aG kvm \$USER && newgrp kvm"
fi

echo "[boot] starting OPNsense ${OPNSENSE_VERSION} (${VM_MEM_MB} MB / ${VM_CPUS} vCPU)"
echo "[boot]   disk:    ${DISK_QCOW2}"
echo "[boot]   console: ${CONSOLE_SOCK}  (attach: socat - UNIX-CONNECT:${CONSOLE_SOCK})"
echo "[boot]   ssh:     127.0.0.1:${HOST_SSH_PORT} → guest:22   (after first-boot)"
echo "[boot]   ui:      127.0.0.1:${HOST_HTTPS_PORT} → guest:443  (after webgui up)"
echo "[boot]   dash:    127.0.0.1:${HOST_DASH_PORT} → guest:8080 (after hound web is started)"

# nohup keeps the qemu process alive after this shell exits;
# stdout/stderr go to the console log for after-the-fact inspection.
# -daemonize is intentionally not used so the pid we capture is qemu itself
# (daemonized qemu forks and the parent exits — the pidfile catches that anyway,
# but doing it this way keeps things simple and works the same on macOS).
nohup qemu-system-x86_64 \
    "${ACCEL_FLAGS[@]}" \
    -m "${VM_MEM_MB}" \
    -smp "${VM_CPUS}" \
    -drive "file=${DISK_QCOW2},if=virtio,format=qcow2" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${HOST_SSH_PORT}-:22,hostfwd=tcp:127.0.0.1:${HOST_HTTPS_PORT}-:443,hostfwd=tcp:127.0.0.1:${HOST_DASH_PORT}-:8080" \
    -device virtio-net-pci,netdev=net0 \
    -nographic \
    -serial "unix:${CONSOLE_SOCK},server,nowait" \
    -monitor "unix:${QEMU_MONITOR_SOCK},server,nowait" \
    -pidfile "${QEMU_PID}" \
    > "${VAR_DIR}/qemu.log" 2>&1 &

# qemu prints "QEMU 8.x.x monitor" on startup; wait briefly for the pidfile
for _ in $(seq 1 20); do
    [[ -f "${QEMU_PID}" ]] && break
    sleep 0.25
done

if [[ ! -f "${QEMU_PID}" ]]; then
    echo "[boot] FATAL: qemu failed to write a pidfile — check ${VAR_DIR}/qemu.log" >&2
    tail -20 "${VAR_DIR}/qemu.log" >&2
    exit 1
fi

PID="$(cat "${QEMU_PID}")"
if ! kill -0 "${PID}" 2>/dev/null; then
    echo "[boot] FATAL: qemu died (pid ${PID}) — check ${VAR_DIR}/qemu.log" >&2
    tail -20 "${VAR_DIR}/qemu.log" >&2
    exit 1
fi

# Start a passive console logger so we can replay what scrolled by during boot
# (socat exits when the qemu socket closes, i.e. on shutdown).
( socat -u "UNIX-CONNECT:${CONSOLE_SOCK}" "OPEN:${CONSOLE_LOG},append,creat" \
  >/dev/null 2>&1 & ) 2>/dev/null || true

echo "[boot] VM up — pid ${PID}, console log → ${CONSOLE_LOG}"
echo "[boot] OPNsense first boot takes 3-5 min on KVM; run 'make first-boot' when ready"
