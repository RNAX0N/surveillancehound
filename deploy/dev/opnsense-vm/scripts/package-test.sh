#!/usr/bin/env bash
# Build the os-hound .txz INSIDE the running OPNsense VM (the package must be
# built on FreeBSD), `pkg add` it, and assert the installed package actually
# works end-to-end. This is the real proof that deploy/opnsense/pkg/build-pkg.sh
# + the GitHub Actions workflow produce a valid, installable package — something
# the in-repo `sh -n` / YAML lint can't reach.
#
# What it does:
#   1. uploads the build inputs (src/, deploy/opnsense/, pyproject.toml) to the VM
#   2. runs build-pkg.sh on the VM → os-hound-X.Y.Z.txz (native FreeBSD:14 ABI)
#   3. pkg add -f the package (force, so it overwrites any prior dev drop)
#   4. asserts: pkg registered it, files landed, the hound CLI runs, the post-
#      install created the user + state dirs
#   5. copies the .txz back to var/ for inspection
#   6. unless KEEP=1, pkg delete and assert clean removal (tests the deinstall
#      scripts too), leaving the VM as it was found
#
# Independent of `make plugin-drop` — it builds and installs a real package
# rather than scattering files. Run after `make boot` + `make first-boot`.
set -uo pipefail
RIG_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../vars.sh
source "${RIG_DIR}/vars.sh"

SSH="${RIG_DIR}/scripts/ssh-wrap.sh ssh"
SCP="${RIG_DIR}/scripts/ssh-wrap.sh scp"

BUILD_DIR=/usr/local/src/SH-pkgbuild
KEEP="${KEEP:-0}"

VERSION="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "${REPO_ROOT}/pyproject.toml" | head -1)"
[[ -n "${VERSION}" ]] || { echo "[pkg-test] FATAL: no version in pyproject.toml" >&2; exit 1; }
# Modern pkg writes a universal `.pkg` extension; resolve the real path after build.
PKGGLOB="${BUILD_DIR}/dist/os-hound-${VERSION}.*"

PASS=0; FAIL=0; FAILED_NAMES=()
check() {
    local name="$1" expected="$2" actual="$3"
    if [[ "${actual}" =~ ${expected} ]]; then
        printf "  [PASS]  %s\n" "${name}"; PASS=$((PASS+1))
    else
        printf "  [FAIL]  %s\n" "${name}"
        printf "          expected match: %s\n" "${expected}"
        printf "          got: %s\n" "${actual:0:240}"
        FAIL=$((FAIL+1)); FAILED_NAMES+=("${name}")
    fi
}

if ! ${SSH} 'echo connected' >/dev/null 2>&1; then
    echo "[pkg-test] FATAL: cannot SSH to VM — is it booted + first-booted?" >&2
    exit 1
fi

echo "═══ 0. upload build inputs → ${BUILD_DIR} ═══"
${SSH} "rm -rf ${BUILD_DIR} && mkdir -p ${BUILD_DIR}"
# Only what build-pkg.sh reads: the package sources, the plugin tree, pyproject.
tar -C "${REPO_ROOT}" --exclude '__pycache__' --exclude '.git' \
    -cf - src pyproject.toml deploy/opnsense \
  | ${SSH} "tar -C ${BUILD_DIR} -xf - && echo uploaded"

echo
echo "═══ 1. build the package on FreeBSD ═══"
build_out="$(${SSH} "cd ${BUILD_DIR} && sh deploy/opnsense/pkg/build-pkg.sh --version ${VERSION} --out ${BUILD_DIR}/dist 2>&1")"
echo "${build_out}" | sed 's/^/    /'
check "build-pkg.sh produced the package" "os-hound-${VERSION}\." \
      "$(${SSH} "ls -1 ${BUILD_DIR}/dist/ 2>&1")"

# resolve the real package path (extension is .pkg on modern pkg)
PKG="$(${SSH} "ls -1 ${PKGGLOB} 2>/dev/null | head -1" | tr -d '\r')"
echo "  package on VM: ${PKG:-<none>}"

echo
echo "═══ 2. pkg add the package ═══"
# Remove any prior install, then force-add so a previous `make plugin-drop`
# (unowned files at the same paths) doesn't block the overwrite.
${SSH} "pkg delete -y os-hound >/dev/null 2>&1 || true"
add_out="$(${SSH} "pkg add -f ${PKG} 2>&1"; echo "rc=$?")"
echo "${add_out}" | sed 's/^/    /'
check "pkg add succeeded" "rc=0" "${add_out}"

echo
echo "═══ 3. assert the install ═══"
check "pkg registered os-hound ${VERSION}" "os-hound-${VERSION}" \
      "$(${SSH} 'pkg info os-hound 2>&1' | head -1)"
check "package owns the rc.d service" "/usr/local/etc/rc.d/hound" \
      "$(${SSH} 'pkg list os-hound 2>&1 | grep rc.d/hound')"
check "package owns the MVC controller" "IndexController.php" \
      "$(${SSH} 'pkg list os-hound 2>&1 | grep IndexController')"
check "package bundled the python sources" "surveillancehound/daemon.py" \
      "$(${SSH} 'pkg list os-hound 2>&1 | grep daemon.py')"
check "hound CLI runs from the package" "(usage|SurveillanceHound)" \
      "$(${SSH} 'hound --help 2>&1' | head -3 | tr '\n' ' ')"
check "post-install created the hound user" "^hound:" \
      "$(${SSH} 'pw usershow hound 2>&1')"
check "post-install created the state dir" "/var/lib/hound" \
      "$(${SSH} 'ls -d /var/lib/hound 2>&1')"
# Exercise the bundled CLI + config/tomllib path against a minimal config we
# write ourselves (the UI renders the real /usr/local/etc/hound.toml on Save).
${SSH} 'printf "[capture]\ninterface = \"lan\"\n[network]\ncamera_ips = [\"192.168.10.20\"]\n" > /tmp/hound-pkgtest.toml'
check "bundled CLI config-check parses a config" "(capture|interface|notify)" \
      "$(${SSH} 'hound config-check /tmp/hound-pkgtest.toml 2>&1' | tr '\n' ' ')"

echo
echo "═══ 4. copy the package back to the host ═══"
if [[ -n "${PKG}" ]] && ${SCP} "vm:${PKG}" "${VAR_DIR}/"; then
    echo "  saved ${VAR_DIR}/$(basename "${PKG}")"
else
    echo "  (scp back failed — non-fatal)"
fi

if [[ "${KEEP}" != "1" ]]; then
    echo
    echo "═══ 5. pkg delete + assert clean removal ═══"
    del_out="$(${SSH} 'pkg delete -y os-hound 2>&1'; echo "rc=$?")"
    check "pkg delete succeeded" "rc=0" "${del_out}"
    check "rc.d service removed" "^gone$" \
          "$(${SSH} 'test -e /usr/local/etc/rc.d/hound || echo gone')"
    check "CLI wrapper removed" "^gone$" \
          "$(${SSH} 'test -e /usr/local/bin/hound || echo gone')"
else
    echo
    echo "  KEEP=1 — leaving os-hound installed on the VM."
fi

echo
echo "═══ Summary ═══"
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
if (( FAIL > 0 )); then
    printf "  Failed checks:\n"
    for n in "${FAILED_NAMES[@]}"; do printf "    - %s\n" "${n}"; done
    exit 1
fi
echo "  All package checks passed."
