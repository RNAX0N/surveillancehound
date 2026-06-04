#!/usr/bin/env bash
# First-boot bootstrap, driven over the serial console.
#
# OPNsense's serial image boots as a live system with the single virtio NIC
# auto-assigned as LAN @ 192.168.1.1 (static). Under QEMU SLIRP user-mode
# networking that IP is unreachable from the host. We log in over the serial
# console, drop straight to /bin/sh (the menu's "Shell" lands you in
# /usr/local/sbin/opnsense-shell which is restricted and rejects heredocs),
# and from there:
#   - run dhclient on vtnet0 (lands on SLIRP's 10.0.2.15)
#   - install root's authorized_keys + rotate the root password
#   - disable pf so SLIRP can reach :22 and :443
#   - switch root's login shell to /bin/sh (so ssh redirects don't csh-fail)
#
# Why dhclient instead of editing /conf/config.xml: config.xml is consulted
# at *boot* time. Editing it requires a reboot to take effect. dhclient
# punches an IP onto vtnet0 immediately, no reboot. This means the IP doesn't
# survive a reboot — but the rig brings the VM down with `make stop` between
# runs anyway, so the next `make boot && make first-boot` rebuilds it.
set -euo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

if [[ ! -S "${CONSOLE_SOCK}" ]]; then
    echo "[first-boot] FATAL: ${CONSOLE_SOCK} missing — is the VM booted? (make boot)" >&2
    exit 1
fi

if [[ ! -f "${SSH_KEY}" ]]; then
    ssh-keygen -t ed25519 -N "" -C "hound-validation-rig" -f "${SSH_KEY}" >/dev/null
    echo "[first-boot] generated SSH key: ${SSH_KEY}"
fi
PUBKEY="$(cat "${SSH_KEY}.pub")"

# QEMU's UNIX-socket chardev hands data to the FIRST connected client only.
# boot.sh kicked off a passive `socat` logger; evict it so our Python driver
# can drive the console. The driver writes its own log entries back to the
# same console.log, so nothing is lost. We restart the passive logger at
# exit so `tail -F console.log` keeps working.
PASSIVE_PID="$(pgrep -f "socat.*UNIX-CONNECT:${CONSOLE_SOCK}" || true)"
if [[ -n "${PASSIVE_PID}" ]]; then
    echo "[first-boot] evicting passive console logger (pid ${PASSIVE_PID})"
    kill ${PASSIVE_PID} 2>/dev/null || true
    sleep 0.3
fi
restart_passive_logger() {
    ( socat -u "UNIX-CONNECT:${CONSOLE_SOCK}" "OPEN:${CONSOLE_LOG},append,creat" \
      >/dev/null 2>&1 & ) 2>/dev/null || true
}
trap restart_passive_logger EXIT

echo "[first-boot] driving console — takes ~30 sec"
echo "[first-boot] watch live: tail -F ${CONSOLE_LOG}"

exec python3 - \
    "${CONSOLE_SOCK}" "${CONSOLE_LOG}" "${ROOT_PASSWORD}" "${PUBKEY}" \
<<'PYEOF'
import os, re, socket, sys, time

sock_path, log_path, root_pw, pubkey = sys.argv[1:5]

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sock_path)
sock.setblocking(False)
log = open(log_path, "ab", buffering=0)
buf = bytearray()

def strip(s): return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", s.decode("utf-8","replace")).replace("\r","")
def recv(t=1.0):
    end = time.monotonic() + t
    while time.monotonic() < end:
        try:
            d = sock.recv(8192)
            if not d: return
            buf.extend(d); log.write(d)
        except BlockingIOError:
            time.sleep(0.05)
def send(s, settle=0.4):
    sock.sendall(s.encode()); log.write(b"\n>>> "+s.encode()+b"\n"); time.sleep(settle)
def wait(pat, timeout=60, label=""):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        recv(t=0.5)
        if re.search(pat, strip(buf), re.M):
            print(f"  ✓ {label or pat}"); buf.clear(); return True
        time.sleep(0.2)
    print(f"  ✗ TIMEOUT {label or pat}", file=sys.stderr)
    print(f"  last 400B: {strip(buf)[-400:]}", file=sys.stderr)
    return False

print("[first-boot] waiting for login prompt")
send("\n", settle=0.5)
# Detect the prompt WITHOUT clearing the buffer — we need to inspect which
# prompt we landed on (login / password / menu / shell) to pick a branch.
# (wait() clears buf on match, which would leave `state` empty.)
end = time.monotonic() + 300
state = ""
while time.monotonic() < end:
    recv(t=0.5)
    state = strip(buf)
    if re.search(r"(login:\s*$|Password:\s*$|Enter an option:\s*|#\s*$)", state, re.M):
        print("  ✓ prompt")
        break
    time.sleep(0.2)
else:
    print("  ✗ TIMEOUT prompt", file=sys.stderr)
    print(f"  last 400B: {state[-400:]}", file=sys.stderr)
    sys.exit(1)
state = state[-300:]
buf.clear()

# State A: already at sh prompt (rare — only on re-run)
# State B: at OPNsense menu (re-run after partial login)
# State C: at login prompt (fresh boot)
# State D: at password prompt (after sending root\n)
if re.search(r"#\s*$", state) and "login:" not in state:
    print("[first-boot] already at shell")
elif "Enter an option:" in state:
    print("[first-boot] at menu — option 8 (shell)")
    send("8\n", settle=0.7)
    wait(r"#\s*$", timeout=15, label="shell prompt")
elif "login:" in state:
    print("[first-boot] at login — root/opnsense")
    send("root\n", settle=0.5)
    wait(r"Password:\s*", timeout=20)
    send("opnsense\n", settle=0.7)
    if not wait(r"Enter an option:\s*", timeout=30, label="menu"):
        sys.exit(1)
    send("8\n", settle=0.7)
    wait(r"#\s*$", timeout=15, label="shell prompt")
else:
    print(f"[first-boot] unexpected state — last 300B: {state!r}")
    sys.exit(1)

# We're in opnsense-shell (restricted). Drop to /bin/sh so heredocs/redirects
# behave the way scripts expect.
print("[first-boot] switching to /bin/sh")
send("/bin/sh\n", settle=0.8)
wait(r"#\s*$", timeout=10, label="sh prompt")

# Now run the bootstrap. Each command on its own line — serial drops chars
# on large pastes. Sentinel pattern at the end so we know we're done.
SENTINEL = "__HOUND_FIRSTBOOT_DONE_OK__"
bootstrap = f"""
ifconfig vtnet0 0.0.0.0
dhclient vtnet0 2>&1 | tail -3
mkdir -p /root/.ssh
chmod 700 /root/.ssh
printf '%s\\n' '{pubkey}' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
echo '{root_pw}' | pw usermod root -h 0
pw usermod root -s /bin/sh
pfctl -d 2>&1 | head -1
/usr/bin/ssh-keygen -A 2>/dev/null || true
service openssh onestart 2>&1 | tail -2 || true
sockstat -4 -l 2>/dev/null | grep ':22' | head -1 || echo 'sshd-not-listening'
ifconfig vtnet0 | grep 'inet '
echo {SENTINEL}
"""
for line in bootstrap.splitlines():
    if line.strip():
        sock.sendall((line + "\n").encode())
        log.write(b"$ " + line.encode() + b"\n")
        time.sleep(0.06)

print("[first-boot] waiting for bootstrap sentinel")
if not wait(rf"{SENTINEL}", timeout=60, label="bootstrap complete"):
    sys.exit(1)

print("[first-boot] done — try: make ssh   (or just make plugin-drop)")
PYEOF
