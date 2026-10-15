#!/bin/sh
#
# Build the os-hound OPNsense package (.txz) — and, optionally, a signed pkg
# repository you can subscribe a firewall to for durable, auto-updating installs.
#
# MUST run on FreeBSD (uses pkg-create/pkg-repo). In CI that's a FreeBSD VM;
# locally it's an OPNsense box or any FreeBSD 14 host. The produced package is
# self-contained — it bundles the SurveillanceHound Python sources and declares
# NO hard deps: OPNsense already ships python3 (configd is written in it) and
# tcpdump (base), and the /usr/local/bin/hound wrapper finds python 3.11+. This
# also lets `pkg add` the .txz succeed offline, with no dependency fetch.
#
# Usage:
#   sh deploy/opnsense/pkg/build-pkg.sh [options]
#     --version X.Y.Z     package version (default: from pyproject.toml / git tag)
#     --out DIR           output dir for the .txz (default: ./dist)
#     --repo              also build a pkg repository under <out>/repo
#                         (override the location with REPO_SUBDIR=...)
#     --sign KEYFILE      RSA private key to sign the repo catalog (implies --repo)
#     --abi ABI           override pkg ABI (default: host, e.g. FreeBSD:14:amd64)
#
# Examples:
#   sh deploy/opnsense/pkg/build-pkg.sh --version 0.1.0
#   sh deploy/opnsense/pkg/build-pkg.sh --version 0.1.0 --repo --sign /tmp/hound-repo.key

set -eu

die() { printf '\033[31mbuild-pkg: %s\033[0m\n' "$*" >&2; exit 1; }
say() { printf '\033[36m▸\033[0m %s\n' "$*"; }

command -v pkg >/dev/null 2>&1 || die "pkg(8) not found — this must run on FreeBSD/OPNsense."

# --- locate the repo --------------------------------------------------------
script_dir=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$script_dir/../../.." && pwd)
[ -f "$REPO_ROOT/pyproject.toml" ] || die "can't find repo root (looked at $REPO_ROOT)"

# --- args -------------------------------------------------------------------
VERSION=""
OUT="$REPO_ROOT/dist"
BUILD_REPO=0
SIGN_KEY=""
ABI_OVERRIDE=""
MAINTAINER="${HOUND_MAINTAINER:-njack2af@proton.me}"
WWW="${HOUND_WWW:-https://github.com/RNAX0N/surveillancehound}"

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --out)     OUT="$2"; shift 2 ;;
        --repo)    BUILD_REPO=1; shift ;;
        --sign)    SIGN_KEY="$2"; BUILD_REPO=1; shift 2 ;;
        --abi)     ABI_OVERRIDE="$2"; shift 2 ;;
        *) die "unknown option: $1" ;;
    esac
done

if [ -z "$VERSION" ]; then
    VERSION=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$REPO_ROOT/pyproject.toml" | head -1)
fi
[ -n "$VERSION" ] || die "could not determine version (pass --version)"
PKGNAME="os-hound"
say "building ${PKGNAME}-${VERSION}"

# --- stage the filesystem ---------------------------------------------------
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM
STAGE="$WORK/stage"
PLUGIN_SRC="$REPO_ROOT/deploy/opnsense/src"

# 1) plugin tree → /usr/local/opnsense, rc.d → /usr/local/etc/rc.d
mkdir -p "$STAGE/usr/local"
cp -a "$PLUGIN_SRC/opnsense" "$STAGE/usr/local/opnsense"
mkdir -p "$STAGE/usr/local/etc/rc.d"
cp -a "$PLUGIN_SRC/usr/local/etc/rc.d/hound" "$STAGE/usr/local/etc/rc.d/hound"

# 2) Python sources → /usr/local/share/hound/lib (version-independent)
mkdir -p "$STAGE/usr/local/share/hound/lib"
cp -a "$REPO_ROOT/src/surveillancehound" "$STAGE/usr/local/share/hound/lib/surveillancehound"

# 3) the hound CLI wrapper → /usr/local/bin/hound
mkdir -p "$STAGE/usr/local/bin"
cat > "$STAGE/usr/local/bin/hound" <<'WRAP'
#!/bin/sh
# SurveillanceHound CLI (packaged). Bundled sources live under /usr/local/share/hound/lib.
# service(8) execs rc scripts with `env -i ... PATH=/sbin:/bin:/usr/sbin:/usr/bin`,
# which omits /usr/local/bin — where FreeBSD/OPNsense installs python3. Without
# this prepend `service hound start` dies in a daemon(8) restart loop logging
# "python 3.11+ not found" even though python3 is installed.
PATH="/usr/local/bin:/usr/local/sbin:$PATH"; export PATH
PY=""
for c in python3.11 python3.12 python3.13 python3; do
    if command -v "$c" >/dev/null 2>&1; then PY=$(command -v "$c"); break; fi
done
[ -n "$PY" ] || { echo "hound: python 3.11+ not found (pkg install python311)" >&2; exit 1; }
exec env PYTHONPATH=/usr/local/share/hound/lib "$PY" -m surveillancehound.cli "$@"
WRAP

# 4) OPNsense plugin metadata → /usr/local/opnsense/version/hound
# Load-bearing, not cosmetic: firmware/register.php's plugins_disk_get() globs
# /usr/local/opnsense/version/* and only registers a plugin in config.xml
# (system/firmware/plugins) when a file there carries product_id == the package
# name. Without it `register.php install os-hound` is a no-op, the plugin never
# becomes "configured", the Plugins UI labels it "(orphaned)", and
# firmware/sync.subr.sh will NOT reinstall it after a firmware upgrade — i.e.
# the whole durability claim of a subscribed repo silently does not apply.
mkdir -p "$STAGE/usr/local/opnsense/version"
PRODUCT_ABI=$(opnsense-version -a 2>/dev/null || echo "")
cat > "$STAGE/usr/local/opnsense/version/hound" <<META
{
    "product_abi": "${PRODUCT_ABI}",
    "product_arch": "$(uname -p)",
    "product_email": "${MAINTAINER}",
    "product_id": "${PKGNAME}",
    "product_name": "hound",
    "product_version": "${VERSION}",
    "product_website": "${WWW}"
}
META

# strip caches + set exec bits (pkg captures on-disk modes)
find "$STAGE" -name '__pycache__' -type d -prune -exec rm -rf {} +
chmod 0555 "$STAGE/usr/local/bin/hound" "$STAGE/usr/local/etc/rc.d/hound"
chmod 0755 "$STAGE"/usr/local/opnsense/scripts/OPNsense/Hound/*.sh \
           "$STAGE"/usr/local/opnsense/scripts/OPNsense/Hound/*.py

# --- plist (absolute paths, files + symlinks) -------------------------------
PLIST="$WORK/plist"
( cd "$STAGE" && find . \( -type f -o -type l \) ) | sed 's#^\.##' | sort > "$PLIST"
say "$(wc -l < "$PLIST" | tr -d ' ') files staged"

# --- lifecycle scripts (single-line; embedded in the manifest) --------------
# post-install: create the service user + state/log dirs, refresh the UI.
#
# The cache_flush() step is not optional garnish — it is what makes the menu
# entry appear. OPNsense merges every plugin's Menu/Menu.xml into
# /var/lib/php/tmp/opnsense_menu_cache.xml and trusts that file for a full
# hour (MenuSystem::$menuCacheTTL = 3600); the ACL and Phalcon template
# caches sit beside it. Neither `service configd restart` nor
# `configctl webgui restart` touches them, so a plugin installed while an
# operator is browsing the UI (i.e. every install via System > Firmware >
# Plugins) lands its Menu.xml on disk and still shows NO Services entry until
# the cache happens to expire. rc.configure_plugins is exactly what the
# official plugin framework runs here (opnsense/plugins Templates/configure);
# it calls system_cache_flush(), which invalidates the menu + ACL + model +
# template caches for whatever OPNsense version is installed. The rm is the
# fallback for a box without that script.
cache_flush() {
    printf '%s' "if [ -f /usr/local/etc/rc.configure_plugins ]; then /usr/local/etc/rc.configure_plugins $1 >/dev/null 2>&1 || true; else rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json >/dev/null 2>&1 || true; fi;"
}
PI="pw groupshow hound >/dev/null 2>&1 || pw groupadd hound; pw usershow hound >/dev/null 2>&1 || pw useradd hound -g hound -s /usr/sbin/nologin -d /var/lib/hound -c SurveillanceHound; install -d -o hound -g hound -m 0750 /var/lib/hound; install -d -o hound -g hound -m 0755 /var/log/hound; if command -v configctl >/dev/null 2>&1; then service configd restart >/dev/null 2>&1 || true; $(cache_flush POST_INSTALL) configctl webgui restart >/dev/null 2>&1 || true; fi; true"
# pre-deinstall: stop + disable the daemon before files vanish.
PRD='service hound onestop >/dev/null 2>&1 || true; sysrc -x hound_enable >/dev/null 2>&1 || true; true'
# post-deinstall: flush the caches + refresh the UI so the menu entry goes
# away. Without the flush a deleted plugin keeps its Services entry (and a
# 404 behind it) for up to an hour — the same cache, the other direction.
POD="$(cache_flush POST_DEINSTALL) command -v configctl >/dev/null 2>&1 && configctl webgui restart >/dev/null 2>&1 || true; true"

# --- manifest (UCL; scripts inlined) ----------------------------------------
MANIFEST="$WORK/+MANIFEST"
cat > "$MANIFEST" <<MANI
name = "${PKGNAME}"
version = "${VERSION}"
origin = "security/${PKGNAME}"
comment = "SurveillanceHound — always-running NVR / IP-camera network monitor"
maintainer = "${MAINTAINER}"
www = "${WWW}"
prefix = "/usr/local"
categories = ["security"]
licenselogic = "single"
licenses = ["PROPRIETARY"]
desc = "SurveillanceHound watches the surveillance segment (camera VLAN / NVR uplink / SPAN port) for bulk transfers toward a camera, control-channel-shaped sessions, off-allowlist telemetry, new devices/peers, and behavioral anomalies. Tracks per-camera uptime passively (offline, recovered, never-seen, plus a capture dead-man's-switch) with outage history and availability. Adds Services > SurveillanceHound to the OPNsense UI. Headers only — no payload, no DNS, no video."
scripts {
  "post-install" = "${PI}"
  "pre-deinstall" = "${PRD}"
  "post-deinstall" = "${POD}"
}
MANI

# --- build ------------------------------------------------------------------
mkdir -p "$OUT"
ABI_ARGS=""
if [ -n "$ABI_OVERRIDE" ]; then
    # OSVERSION must match the ABI major or pkg rejects its own output.
    # Hardcoding 1400000 silently produced FreeBSD:14 packages for every
    # --abi, which is how a FreeBSD:15 box ends up refusing the repo with
    # "wrong architecture: FreeBSD:14:amd64 instead of FreeBSD:15:amd64".
    ABI_MAJOR=$(echo "$ABI_OVERRIDE" | cut -d: -f2)
    case "$ABI_MAJOR" in
        ''|*[!0-9]*) die "cannot parse major version from ABI: $ABI_OVERRIDE" ;;
    esac
    ABI_ARGS="-o ABI=$ABI_OVERRIDE -o OSVERSION=${ABI_MAJOR}00000"
fi
say "pkg create (abi: ${ABI_OVERRIDE:-$(pkg config ABI)})"
# Default format = the universal `.pkg` (zstd) — exactly what OPNsense ships.
# Modern pkg names every package `<name>-<version>.pkg` regardless of the
# internal compression, so don't assume a `.txz` extension.
# shellcheck disable=SC2086
pkg $ABI_ARGS create -o "$OUT" -r "$STAGE" -p "$PLIST" -M "$MANIFEST"

PKG=$(ls -t "$OUT/${PKGNAME}-${VERSION}".* 2>/dev/null | head -1)
[ -n "$PKG" ] && [ -f "$PKG" ] || die "pkg create did not produce a package in $OUT"
say "package: $PKG"
pkg info -F "$PKG" 2>/dev/null | sed 's/^/    /' || true

# --- optional: signed repository --------------------------------------------
if [ "$BUILD_REPO" = "1" ]; then
    REPODIR="${REPO_SUBDIR:-$OUT/repo}"
    say "building pkg repository → $REPODIR"
    rm -rf "$REPODIR"; mkdir -p "$REPODIR"
    cp "$PKG" "$REPODIR/"
    if [ -n "$SIGN_KEY" ]; then
        [ -f "$SIGN_KEY" ] || die "signing key not found: $SIGN_KEY"
        say "signing catalog with $SIGN_KEY"
        pkg repo "$REPODIR" "$SIGN_KEY"
        # publish the matching public key so the firewall can verify
        openssl rsa -in "$SIGN_KEY" -pubout -out "$REPODIR/hound-repo.pub" 2>/dev/null \
            || die "could not derive public key from $SIGN_KEY"
    else
        say "no --sign key — building an UNSIGNED repo (signature_type: none)"
        pkg repo "$REPODIR"
    fi
    say "repo catalog:"; ls -1 "$REPODIR" | sed 's/^/    /'
fi

say "done."
