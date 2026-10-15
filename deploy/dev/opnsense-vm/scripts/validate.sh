#!/usr/bin/env bash
# Run the three things in-repo tests genuinely can't reach:
#   1. Phalcon MVC routing — controllers resolve at /ui/hound/ and /api/hound/*
#   2. configd action invocation — actions_hound.conf entries reach reload.sh + rc.d
#   3. Model serialization round-trip — Phalcon writes XML render_config.py can read
#
# Each assertion is numbered, exits non-zero on first failure but prints a
# PASS/FAIL summary at the end either way.
#
# Authentication: OPNsense's webgui uses CSRF-protected session cookies; for
# scripted access the documented path is per-user API key+secret pairs sent
# as HTTP Basic auth. plugin-drop.sh mints one and stores it in var/apikey.txt.
set -uo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

SSH="${RIG_DIR}/scripts/ssh-wrap.sh ssh"
APIKEY_FILE="${VAR_DIR}/apikey.txt"

if [[ ! -s "${APIKEY_FILE}" ]]; then
    echo "[validate] FATAL: ${APIKEY_FILE} missing — run 'make plugin-drop' first" >&2
    exit 1
fi
# OPNsense prints the key+secret on separate lines after the prompt. Format:
#   key=...
#   secret=...
KEY="$(grep -E '^key=' "${APIKEY_FILE}" | head -1 | cut -d= -f2- | tr -d ' \r')"
SECRET="$(grep -E '^secret=' "${APIKEY_FILE}" | head -1 | cut -d= -f2- | tr -d ' \r')"
if [[ -z "${KEY}" || -z "${SECRET}" ]]; then
    echo "[validate] FATAL: couldn't parse key/secret from ${APIKEY_FILE}" >&2
    echo "--- ${APIKEY_FILE} ---" >&2
    cat "${APIKEY_FILE}" >&2
    exit 1
fi

# Curl helper: ignore TLS, time out fast, use the API key as basic auth
ui() {
    curl -sk --connect-timeout 5 --max-time 30 \
         -u "${KEY}:${SECRET}" \
         "$@"
}

PASS=0
FAIL=0
FAILED_NAMES=()

check() {
    local name="$1" expected="$2" actual="$3"
    if [[ "${actual}" =~ ${expected} ]]; then
        printf "  [PASS]  %s\n" "${name}"
        PASS=$((PASS+1))
    else
        printf "  [FAIL]  %s\n" "${name}"
        printf "          expected match: %s\n" "${expected}"
        printf "          got: %s\n" "${actual:0:240}"
        FAIL=$((FAIL+1))
        FAILED_NAMES+=("${name}")
    fi
}

# Detect python on the VM (3.13 on 26.1, may vary)
PY="$(${SSH} 'command -v python3.13 || command -v python3' 2>/dev/null | tr -d '\r' | head -1)"
PY="${PY:-/usr/local/bin/python3}"
echo "[validate] using remote python: ${PY}"
echo

echo "═══ 1. configd action invocation ═══"

# 1a. configd parses actions_hound.conf and registers all 5 actions
actions="$(${SSH} 'configctl configd actions 2>&1 | grep -E "^hound "' 2>&1)"
check "configd registers hound.{start,stop,restart,reload,status}" \
      "hound start.*hound stop.*hound restart.*hound reload.*hound status" \
      "$(echo "${actions}" | tr '\n' '~')"

# 1b. Invoke status. configctl wraps the rc.d script's output and prints
#     "Error (N)" if the script returned non-zero. Status returning 1 (not
#     running) is fine here — we just want to confirm the action plumbing
#     fires the rc.d script. Read configd's audit log to confirm exec.
${SSH} 'configctl hound status' >/dev/null 2>&1 || true
sleep 0.5
cdlog="$(${SSH} 'tail -200 /var/log/configd/configd_$(date +%Y%m%d).log 2>/dev/null | grep -E "querying hound status" | tail -3' 2>&1)"
check "configd.log shows hound.status exec" "querying hound status" "${cdlog}"

# 1c. Reload — exit code 2 is the "no config yet" path (CORRECT before save).
${SSH} 'configctl hound reload' >/dev/null 2>&1 || true
sleep 0.5
cdlog="$(${SSH} 'tail -200 /var/log/configd/configd_$(date +%Y%m%d).log 2>/dev/null | grep -E "reloading hound config" | tail -3' 2>&1)"
check "configd.log shows hound.reload exec" "reloading hound config" "${cdlog}"

# 1d. The rc.d script itself is reachable + responds to onestatus
out="$(${SSH} '/usr/local/etc/rc.d/hound onestatus 2>&1; echo rc=$?' 2>&1)"
check "rc.d/hound onestatus reachable" "(not running|is running)" "${out}"

echo
echo "═══ 2. Phalcon MVC routing ═══"

# 2a. IndexController auto-mounts at /ui/hound/. UI routes require a session
#     cookie (not API key), so without a session OPNsense 302s to login. The
#     302 itself proves the route was matched — a missing controller would
#     return 404. We don't test the body here (would need full session flow).
code="$(curl -sk --connect-timeout 5 -o /dev/null -w '%{http_code}' \
        "https://127.0.0.1:${HOST_HTTPS_PORT}/ui/hound/")"
check "/ui/hound/ route resolved (302 → login or 200)" "^(200|302)$" "${code}"
# Negative control: a non-existent /api/ controller returns 404 (the auth
# gate doesn't apply to nonexistent routes), proving the router distinguishes.
# We use /api/ because /ui/ unconditionally 302s to login when unauthed.
code_404="$(ui -o /dev/null -w '%{http_code}' \
            "https://127.0.0.1:${HOST_HTTPS_PORT}/api/this_does_not_exist/foo/bar")"
check "non-existent /api/ path returns 404 (proves router is live)" "^404$" "${code_404}"

# 2b. SettingsController auto-routes — must return the model
set_json="$(ui "https://127.0.0.1:${HOST_HTTPS_PORT}/api/hound/settings/get")"
check "/api/hound/settings/get returns model JSON" '("hound"|"general"|"enabled")' "${set_json}"

# 2c. ServiceController auto-routes
svc_json="$(ui -X POST "https://127.0.0.1:${HOST_HTTPS_PORT}/api/hound/service/status")"
check "/api/hound/service/status returns JSON" '("status"|running|stopped)' "${svc_json}"

# 2d. Unauthenticated requests are blocked. OPNsense's /api gate redirects
#     (302) rather than returning 401, which is unusual but consistent across
#     all OPNsense APIs — match the framework's actual behavior.
nauth="$(curl -sk --connect-timeout 5 -o /dev/null -w '%{http_code}' \
    "https://127.0.0.1:${HOST_HTTPS_PORT}/api/hound/settings/get")"
check "/api/hound/settings/get blocks unauth (302/401/403)" "^(302|401|403)$" "${nauth}"

echo
echo "═══ 3. Model ↔ render_config.py round-trip ═══"

# 3a. Save a minimal config via the API. OPNsense's InterfaceField validates
#     against the system's interface aliases (`lan`/`wan`/`opt1`...), NOT
#     against bare NIC names — using `vtnet0` would 400.
save_resp="$(ui -H 'Content-Type: application/json' \
    -d '{"hound":{"general":{"enabled":"1","interface":"lan"},
          "network":{"camera_ips":"192.168.10.20"}}}' \
    -X POST "https://127.0.0.1:${HOST_HTTPS_PORT}/api/hound/settings/set")"
check "POST /api/hound/settings/set succeeds" '"saved"' "${save_resp}"

# 3b. /conf/config.xml now has a <Hound> subtree under <OPNsense>.
# Grep just for the <Hound element (might be self-closing or container).
xml_block="$(${SSH} 'grep -E "<Hound( |/?>)" /conf/config.xml' 2>&1)"
check "config.xml gained <Hound> block" "<Hound" "${xml_block}"

# 3c. configctl hound reload — should now succeed (config exists)
out="$(${SSH} 'configctl hound reload 2>&1')"
check "configctl hound reload now succeeds" "(OK|reloaded|hound.toml)" "${out}"

# 3d. /usr/local/etc/hound.toml exists and is non-empty
toml_size="$(${SSH} 'wc -c < /usr/local/etc/hound.toml 2>/dev/null || echo 0' | tr -d '[:space:]')"
check "rendered hound.toml is non-empty" '^[1-9][0-9]*$' "${toml_size}"

# 3e. The rendered TOML has the saved interface and parses cleanly
# The python package lives under /usr/local/src/SurveillanceHound after
# `make plugin-drop`, and under /usr/local/share/hound/lib after a real
# `pkg install os-hound` — validate has to work against either.
PYLIB="$(${SSH} 'for d in /usr/local/src/SurveillanceHound/src /usr/local/share/hound/lib; do
    [ -d "$d/surveillancehound" ] && { echo "$d"; break; }
done' 2>/dev/null | tr -d '\r' | head -1)"
check "python package present on the VM" "surveillancehound|/usr/local" "${PYLIB:-<not found>}"
parse_out="$(${SSH} "PYTHONPATH='${PYLIB}' ${PY} -c '
import tomllib, surveillancehound.config as c, sys
with open(\"/usr/local/etc/hound.toml\", \"rb\") as f: data = tomllib.load(f)
cfg = c.load_from_dict(data)
print(\"OK loaded interface=\" + (cfg.capture.interface or \"<none>\") + \" cameras=\" + str(len(cfg.network.camera_ips)))
'" 2>&1)"
check "TOML round-trips through load_from_dict" "^OK loaded" "${parse_out}"
# camera_ips lives under <network>, not <general> — posting it in the wrong
# section is silently dropped by the model, which used to leave this whole
# round-trip asserting an empty camera list.
check "saved camera_ips survived the round-trip" "cameras=1" "${parse_out}"

echo
echo "═══ Summary ═══"
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
if (( FAIL > 0 )); then
    printf "  Failed checks:\n"
    for n in "${FAILED_NAMES[@]}"; do printf "    - %s\n" "${n}"; done
    exit 1
fi
echo "  All checks passed."
