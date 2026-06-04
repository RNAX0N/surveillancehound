#!/usr/bin/env bash
# Graceful shutdown via QEMU monitor; falls back to SIGTERM, then SIGKILL.
set -euo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

if [[ ! -f "${QEMU_PID}" ]]; then
    echo "[stop] no pidfile — VM not running"
    exit 0
fi

PID="$(cat "${QEMU_PID}")"
if ! kill -0 "${PID}" 2>/dev/null; then
    echo "[stop] pid ${PID} not alive — cleaning up stale pidfile"
    rm -f "${QEMU_PID}" "${CONSOLE_SOCK}" "${QEMU_MONITOR_SOCK}"
    exit 0
fi

# Prefer ACPI powerdown over killing — gives FreeBSD a chance to fsync
if [[ -S "${QEMU_MONITOR_SOCK}" ]]; then
    echo "[stop] sending system_powerdown via monitor"
    echo "system_powerdown" | socat - "UNIX-CONNECT:${QEMU_MONITOR_SOCK}" >/dev/null 2>&1 || true
    for _ in $(seq 1 60); do
        kill -0 "${PID}" 2>/dev/null || break
        sleep 0.5
    done
fi

if kill -0 "${PID}" 2>/dev/null; then
    echo "[stop] still alive after 30s — SIGTERM"
    kill "${PID}" 2>/dev/null || true
    for _ in $(seq 1 10); do
        kill -0 "${PID}" 2>/dev/null || break
        sleep 0.5
    done
fi

if kill -0 "${PID}" 2>/dev/null; then
    echo "[stop] still alive — SIGKILL"
    kill -9 "${PID}" 2>/dev/null || true
fi

rm -f "${QEMU_PID}" "${CONSOLE_SOCK}" "${QEMU_MONITOR_SOCK}"
echo "[stop] done"
