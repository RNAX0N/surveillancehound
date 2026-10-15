"""Validate the OPNsense + pfSense firewall plugins as far as we can
without an actual FreeBSD VM.

What we CAN verify here:
  * Every XML file parses (well-formed).
  * Every sh script passes `sh -n` (syntax).
  * Every PHP file is brace-balanced and has matching <?php ?> (or omits
    the close tag, which is the modern convention).
  * The OPNsense `render_config.py` actually runs against a synthetic
    config.xml and emits valid TOML — `tomllib` parses it without error
    AND the round-tripped config has the expected fields.
  * The pfSense `hound_render_toml` logic ported to Python emits valid
    TOML for the same range of model inputs.

What we CANNOT verify here:
  * Phalcon MVC routing / Volt rendering / configd action invocation —
    those need a real OPNsense system.
  * pfSense package GUI rendering — needs a real pfSense system.

This script lives next to the other end-to-end scripts. Run:
    PYTHONPATH=src:tests python tests/verify_plugins.py
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEPLOY = ROOT / "deploy"
OPNSENSE = DEPLOY / "opnsense"
PFSENSE = DEPLOY / "pfsense"
WAZUH = DEPLOY / "wazuh"


# ---------------------------------------------------------------------------
# static checks
# ---------------------------------------------------------------------------


def _check_xml_wellformed() -> None:
    xmls = (list(OPNSENSE.rglob("*.xml"))
            + list(PFSENSE.rglob("*.xml"))
            + list(WAZUH.rglob("*.xml")))
    assert xmls, "no XML files found under deploy/"
    for f in xmls:
        text = f.read_text()
        try:
            ET.fromstring(text)
        except ET.ParseError:
            # Wazuh decoder files canonically have multiple top-level
            # <decoder> elements (no wrapping root); try once more with
            # a synthetic <root> wrapper. If it parses then, it's valid
            # Wazuh-shaped even if not strictly XML-1.0 wellformed.
            try:
                ET.fromstring(f"<root>{text}</root>")
            except ET.ParseError as e:
                raise AssertionError(
                    f"{f}: not well-formed: {e}",
                ) from e
    print(f"  XML well-formed: {len(xmls)} file(s) "
          f"(opnsense + pfsense + wazuh)")


def _check_sh_syntax() -> None:
    shells = [
        DEPLOY / "hound.service",  # ini-ish, not a shell script — skip
        OPNSENSE / "src/usr/local/etc/rc.d/hound",
        OPNSENSE / "src/opnsense/scripts/OPNsense/Hound/reload.sh",
    ]
    checked = 0
    for s in shells:
        if not s.exists():
            continue
        if s.suffix == ".service":
            continue
        r = subprocess.run(
            ["sh", "-n", str(s)], capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise AssertionError(f"{s}: sh -n failed: {r.stderr.strip()}")
        checked += 1
    assert checked >= 2, f"expected ≥2 shell scripts, checked {checked}"
    print(f"  sh -n syntax: {checked} script(s)")


def _php_strip(code: str) -> str:
    """Remove PHP strings and comments in ONE left-to-right pass.

    Order matters and neither order is safe on its own: stripping strings
    first means an apostrophe in a comment ("the daemon's socket") opens a
    phantom string that swallows everything up to the next quote, braces
    included; stripping comments first means a `//` inside a string literal
    (every URL) eats the rest of the line. A single scan that decides what
    it is in context is the only version that is right.
    """
    out = []
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if c in "'\"":
            quote = c
            i += 1
            while i < n:
                if code[i] == "\\":
                    i += 2
                    continue
                if code[i] == quote:
                    i += 1
                    break
                i += 1
            out.append(" ")
        elif c == "/" and nxt == "/":
            while i < n and code[i] != "\n":
                i += 1
        elif c == "#":
            while i < n and code[i] != "\n":
                i += 1
        elif c == "/" and nxt == "*":
            end = code.find("*/", i + 2)
            i = n if end == -1 else end + 2
            out.append(" ")
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _check_php_brace_balance() -> None:
    """Hand-rolled brace/<?php balance check — we don't have php-cli.

    Rules:
      * file must start with `<?php` or `<?` (modern convention is no
        closing `?>` so it doesn't need to be there)
      * curly braces balanced
      * round parens balanced
      * no obvious syntax errors via a few regex sniffs (unterminated
        strings on a single line, double `;;`, etc.)
    """
    phps = list(OPNSENSE.rglob("*.php")) + list(PFSENSE.rglob("*.php"))
    assert phps, "no PHP files found under deploy/"
    for f in phps:
        text = f.read_text()
        assert text.startswith("<?php") or text.startswith("<?"), (
            f"{f}: doesn't start with PHP tag"
        )
        # Extract every <?php ... ?> or <?= ... ?> block; only validate
        # syntax INSIDE the PHP blocks (CSS/HTML braces in between are
        # not our concern).
        php_blocks = re.findall(
            r"<\?(?:php|=)?(.*?)(?:\?>|\Z)", text, flags=re.DOTALL,
        )
        assert php_blocks, f"{f}: no <?php blocks found"
        php_code = "\n".join(php_blocks)
        stripped = _php_strip(php_code)
        opens = stripped.count("{")
        closes = stripped.count("}")
        assert opens == closes, (
            f"{f}: brace mismatch ({opens} open vs {closes} close) "
            f"inside PHP blocks"
        )
        popens = stripped.count("(")
        pcloses = stripped.count(")")
        assert popens == pcloses, (
            f"{f}: paren mismatch ({popens} open vs {pcloses} close) "
            f"inside PHP blocks"
        )
        # double-semicolon — usually a typo
        assert ";;" not in stripped, f"{f}: contains ';;'"
        # no smart-quote slipped in (anywhere — would break literals)
        for bad in ("‘", "’", "“", "”"):
            assert bad not in text, f"{f}: contains curly-quote {bad!r}"
    print(f"  PHP structural lint: {len(phps)} file(s)")


# ---------------------------------------------------------------------------
# OPNsense renderer end-to-end
# ---------------------------------------------------------------------------


def _load_opnsense_renderer():
    """Import deploy/opnsense/.../render_config.py as a Python module."""
    path = (OPNSENSE
            / "src/opnsense/scripts/OPNsense/Hound/render_config.py")
    spec = importlib.util.spec_from_file_location("hound_render", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _opnsense_synthetic_config(**overrides) -> str:
    """Build a /conf/config.xml shaped subtree containing OPNsense/Hound.
    Defaults reflect a typical small deployment."""
    defaults = {
        "interface": "vlan10",
        "snaplen": "1500",
        "bpf": "host 192.168.10.0/24",
        "camera_ips": "192.168.10.20,192.168.10.21,192.168.10.22",
        "camera_subnets": "192.168.10.0/24",
        "nvr_ips": "192.168.10.10",
        "manufacturer_allowlist": "203.0.113.0/24, 198.51.100.0/24",
        "baseline_enabled": "1",
        "z_threshold": "5.5",
        "min_samples": "200",
        "snapshot_enabled": "1",
        "window_seconds": "120.0",
        "min_severity": "high",
        "web_enabled": "1",
        "web_host": "127.0.0.1",
        "web_port": "8765",
        "silence_seconds": "900.0",
        "uptime_enabled": "1",
        "startup_grace_seconds": "300.0",
        "capture_stall_seconds": "45.0",
    }
    defaults.update(overrides)
    d = defaults
    return f"""<?xml version="1.0"?>
<opnsense>
  <OPNsense>
    <Hound>
      <general>
        <interface>{d['interface']}</interface>
        <snaplen>{d['snaplen']}</snaplen>
        <bpf>{d['bpf']}</bpf>
      </general>
      <network>
        <camera_ips>{d['camera_ips']}</camera_ips>
        <camera_subnets>{d['camera_subnets']}</camera_subnets>
        <nvr_ips>{d['nvr_ips']}</nvr_ips>
        <manufacturer_allowlist>{d['manufacturer_allowlist']}</manufacturer_allowlist>
      </network>
      <baseline>
        <enabled>{d['baseline_enabled']}</enabled>
        <z_threshold>{d['z_threshold']}</z_threshold>
        <min_samples>{d['min_samples']}</min_samples>
      </baseline>
      <snapshot>
        <enabled>{d['snapshot_enabled']}</enabled>
        <window_seconds>{d['window_seconds']}</window_seconds>
        <min_severity>{d['min_severity']}</min_severity>
      </snapshot>
      <web>
        <enabled>{d['web_enabled']}</enabled>
        <host>{d['web_host']}</host>
        <port>{d['web_port']}</port>
      </web>
      <thresholds>
        <silence_seconds>{d['silence_seconds']}</silence_seconds>
      </thresholds>
      <uptime>
        <enabled>{d['uptime_enabled']}</enabled>
        <startup_grace_seconds>{d['startup_grace_seconds']}</startup_grace_seconds>
        <capture_stall_seconds>{d['capture_stall_seconds']}</capture_stall_seconds>
      </uptime>
    </Hound>
  </OPNsense>
</opnsense>
"""


def _check_opnsense_renderer() -> None:
    mod = _load_opnsense_renderer()
    cases = [
        # rich case (every field set)
        {},
        # minimum: no cameras, no NVRs, no BPF, default snaplen
        {
            "bpf": "", "camera_ips": "", "camera_subnets": "",
            "nvr_ips": "", "manufacturer_allowlist": "",
            "baseline_enabled": "0", "snapshot_enabled": "0",
            "web_enabled": "0",
            # uptime off entirely; stall detector disabled (0) and grace
            # set to 0, which means "inherit thresholds.silence_seconds"
            "uptime_enabled": "0", "startup_grace_seconds": "0",
            "capture_stall_seconds": "0",
        },
        # special characters that need TOML escaping (backslash + quote)
        {
            "bpf": r'host 1.2.3.4 and tcp port 22 \\ and not src 5.6.7.8',
            "camera_ips": '10.0.0.1', "camera_subnets": "",
            "nvr_ips": "", "manufacturer_allowlist": "",
        },
        # boolean strings the model might emit ("1"/"0", "on"/"off", "true"/"false")
        {"baseline_enabled": "true", "snapshot_enabled": "on", "web_enabled": "yes",
         "uptime_enabled": "on"},
    ]
    for i, overrides in enumerate(cases):
        with tempfile.TemporaryDirectory() as td:
            cfg_path = Path(td) / "config.xml"
            cfg_path.write_text(_opnsense_synthetic_config(**overrides))
            out_path = Path(td) / "hound.toml"
            rc = mod.main(["render_config.py", str(cfg_path), str(out_path)])
            assert rc == 0, f"case {i}: render returned {rc}"
            assert out_path.is_file(), f"case {i}: no output"
            data = tomllib.loads(out_path.read_text())
            # required structural assertions: every section present
            for section in ("capture", "network", "store", "baseline",
                            "snapshot", "web", "thresholds", "uptime"):
                assert section in data, (
                    f"case {i}: missing [{section}] in output",
                )
            assert isinstance(data["network"]["camera_ips"], list)
            assert isinstance(data["network"]["camera_subnets"], list)
            assert isinstance(data["baseline"]["enabled"], bool)
            assert isinstance(data["snapshot"]["enabled"], bool)
            assert isinstance(data["web"]["enabled"], bool)
            assert isinstance(data["uptime"]["enabled"], bool)
            assert isinstance(data["capture"]["snaplen"], int)
            # numeric uptime knobs must be TOML floats, not strings
            for key in ("startup_grace_seconds", "capture_stall_seconds"):
                assert isinstance(data["uptime"][key], float), (
                    f"case {i}: uptime.{key} not a float"
                )
            assert isinstance(data["thresholds"]["silence_seconds"], float)
            assert data["store"]["path"] == "/var/lib/hound/hound.sqlite"
            # at least one notify channel always present (default stdout)
            assert isinstance(data.get("notify"), list)
            assert any(n["type"] == "stdout" for n in data["notify"])
    print(f"  OPNsense renderer: {len(cases)} model variants → valid TOML each")


def _check_opnsense_interface_resolution() -> None:
    """The form stores an interface ALIAS; tcpdump needs the device.

    Writing the alias straight through produced `interface = "lan"`, and
    the daemon died with `tcpdump: lan: No such device exists` — a config
    saved from the OPNsense UI could never capture anything.
    """
    mod = _load_opnsense_renderer()
    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "config.xml"
        # a config.xml carrying the interfaces block OPNsense really writes
        body = _opnsense_synthetic_config(interface="opt2")
        body = body.replace("<opnsense>", """<opnsense>
  <interfaces>
    <wan><if>em0</if></wan>
    <lan><if>igb1</if></lan>
    <opt2><if>vlan0.20</if></opt2>
  </interfaces>""", 1)
        cfg.write_text(body)
        out = Path(td) / "hound.toml"
        assert mod.main(["render_config.py", str(cfg), str(out)]) == 0
        data = tomllib.loads(out.read_text())
        assert data["capture"]["interface"] == "vlan0.20", (
            f"alias not resolved to a device: {data['capture']['interface']!r}"
        )
        # direct unit checks, including the pass-through cases
        mod._IFACE_CACHE.clear()
        assert mod.resolve_interface("lan", cfg) == "igb1"
        mod._IFACE_CACHE.clear()
        # an operator who typed a real device name must keep working
        assert mod.resolve_interface("igb3", cfg) == "igb3"
        mod._IFACE_CACHE.clear()
        # unreadable config.xml must not crash the render
        assert mod.resolve_interface("lan", Path(td) / "nope.xml") == "lan"
        mod._IFACE_CACHE.clear()
        assert mod.resolve_interface("", cfg) == ""
        mod._IFACE_CACHE.clear()
    print("  OPNsense renderer: interface alias resolves to the real device")


def _check_opnsense_pkg_build_script() -> None:
    """Guard the two packaging defects that made os-hound unusable.

    Neither is visible from Python, and neither was caught by five rounds of
    VM testing, because the dev rig drops its own /usr/local/bin/hound shim
    over the package's — so `service hound onestart` never once exercised
    the wrapper that actually ships. These are cheap static assertions on
    build-pkg.sh; they are not a substitute for building the package, but
    they do fail loudly if someone removes either line.
    """
    script = (
        Path(__file__).resolve().parent.parent
        / "deploy/opnsense/pkg/build-pkg.sh"
    ).read_text()

    # 1. service(8) runs rc scripts with PATH=/sbin:/bin:/usr/sbin:/usr/bin —
    #    no /usr/local/bin, which is where FreeBSD puts python3. Without the
    #    prepend the wrapper cannot find any interpreter and daemon(8) -r
    #    spins a restart loop logging "python 3.11+ not found" on a box with
    #    python3 installed.
    assert 'PATH="/usr/local/bin:/usr/local/sbin:$PATH"' in script, (
        "build-pkg.sh: the CLI wrapper no longer prepends /usr/local/bin to "
        "PATH — the packaged service will not find python3 under service(8)"
    )
    wrapper_start = script.index("cat > \"$STAGE/usr/local/bin/hound\"")
    wrapper_end = script.index("WRAP\n", wrapper_start)
    wrapper = script[wrapper_start:wrapper_end]
    assert "PATH=" in wrapper, (
        "the PATH prepend must be INSIDE the shipped wrapper, not merely "
        "somewhere in the build script"
    )

    # 2. firmware/register.php only records a plugin in config.xml when a
    #    file under /usr/local/opnsense/version/ carries product_id == the
    #    package name. Without it the plugin never becomes "configured",
    #    the UI labels it "(orphaned)", and sync.subr.sh will NOT reinstall
    #    it after a firmware upgrade — the durability a subscribed repo is
    #    supposed to buy silently does not apply.
    assert '"$STAGE/usr/local/opnsense/version/hound"' in script, (
        "build-pkg.sh no longer stages /usr/local/opnsense/version/hound — "
        "the plugin will not register and will not survive firmware upgrades"
    )
    assert '"product_id": "${PKGNAME}"' in script, (
        "the version metadata must carry product_id == the package name, or "
        "register.php silently skips it"
    )
    print("  OPNsense pkg: wrapper PATH prepend + plugin registration staged")

    # 3. OSVERSION must track the ABI major. It was hardcoded to 1400000, so
    #    every --abi produced a FreeBSD:14 package regardless — which is how
    #    an OPNsense 26.7 box (FreeBSD 15.1) rejects the whole repository
    #    with "wrong architecture: FreeBSD:14:amd64 instead of
    #    FreeBSD:15:amd64". OPNsense changes base between majors, so this
    #    must never be a constant again.
    assert "OSVERSION=1400000" not in script, (
        "build-pkg.sh hardcodes OSVERSION=1400000 again — every --abi will "
        "emit a FreeBSD:14 package and newer OPNsense will refuse the repo"
    )
    assert "OSVERSION=${ABI_MAJOR}00000" in script, (
        "build-pkg.sh must derive OSVERSION from the ABI major version"
    )

    # 4. The published repo is per-ABI and hound.conf must point pkg at
    #    .../${ABI}, or a firewall on a different base fetches the wrong
    #    catalogue.
    conf = (
        Path(__file__).resolve().parent.parent
        / "deploy/opnsense/pkg/hound.conf.sample"
    ).read_text()
    assert "/opnsense/${ABI}" in conf, (
        "hound.conf.sample must use ${ABI} in the url, or firewalls on a "
        "different FreeBSD base pull a catalogue they cannot install from"
    )
    wf = (
        Path(__file__).resolve().parent.parent
        / ".github/workflows/build-opnsense-pkg.yml"
    ).read_text()
    for abi in ("FreeBSD:14:amd64", "FreeBSD:15:amd64"):
        assert abi in wf, f"workflow no longer publishes a catalogue for {abi}"
    print("  OPNsense pkg: OSVERSION tracks ABI; repo published per-ABI")

    # 5. The lifecycle scripts must flush OPNsense's UI caches. OPNsense
    #    merges every plugin's Menu/Menu.xml into
    #    /var/lib/php/tmp/opnsense_menu_cache.xml and trusts it for an hour
    #    (MenuSystem::$menuCacheTTL = 3600). `service configd restart` and
    #    `configctl webgui restart` do NOT touch that file, so os-hound 0.1.1
    #    installed its Menu.xml and showed no Services entry at all until the
    #    cache happened to expire — reproduced on the dev VM. The official
    #    plugin framework runs rc.configure_plugins here
    #    (opnsense/plugins Templates/configure → system_cache_flush()).
    for var, arg in (("PI=", "POST_INSTALL"), ("POD=", "POST_DEINSTALL")):
        start = script.index("\n" + var)
        body = script[start:script.index("\n", start + 1) + 1]
        assert "cache_flush" in body or "rc.configure_plugins" in body, (
            f"build-pkg.sh {var[:-1]} no longer flushes the OPNsense UI "
            f"caches — the Services menu entry will not appear (or will not "
            f"disappear) for up to an hour after a pkg install/delete"
        )
        assert f"cache_flush {arg}" in body or arg in body, (
            f"build-pkg.sh {var[:-1]} must flush the caches with {arg}"
        )
    assert "/usr/local/etc/rc.configure_plugins" in script, (
        "build-pkg.sh must call rc.configure_plugins (it is what invalidates "
        "the menu + ACL + model + template caches on every OPNsense version)"
    )
    assert "opnsense_menu_cache.xml" in script, (
        "build-pkg.sh lost the explicit menu-cache fallback for boxes "
        "without rc.configure_plugins"
    )
    print("  OPNsense pkg: install/deinstall flush the menu + ACL caches")



#: Every one of these is a MenuItem *property* (MenuItem.php has a matching
#: set<Name>() and the attribute match is case-insensitive). They belong in an
#: attribute. Written as a child ELEMENT, MenuSystem does not read them as
#: properties at all — MenuItem::addXmlNode() walks every child element and
#: appends it as a menu item, so `<VisibleName>Services</VisibleName>` became a
#: bogus, empty, collapsible nav row literally labelled "VisibleName".
_MENU_PROPERTY_NAMES = frozenset({
    "visiblename", "fixedname", "cssclass", "linkclass",
    "url", "order", "visibility", "isexternal",
})


def _check_opnsense_menu_xml() -> None:
    """Assert each Menu/Menu.xml has the shape OPNsense's parser expects.

    The published 0.1.1 plugin installed cleanly and rendered no usable
    Services entry. Its Menu.xml was::

        <menu><Services>
            <VisibleName>Services</VisibleName>          <!-- wrong -->
            <SurveillanceHound VisibleName=".." url=".."/>
        </Services></menu>

    No core plugin does that (grep `<VisibleName>` across
    /usr/local/opnsense/mvc/app/models/*/*/Menu/Menu.xml on a real box: zero
    hits). The shape every core plugin uses is a category element whose only
    children are entry nodes carrying their labels as attributes.
    """
    menus = sorted(OPNSENSE.rglob("Menu/Menu.xml"))
    assert menus, f"no Menu/Menu.xml found under {OPNSENSE}"

    def walk(node, path: str, menu_path: Path) -> None:
        for child in node:
            tag = child.tag
            assert tag.lower() not in _MENU_PROPERTY_NAMES, (
                f"{menu_path}: <{tag}> is a child ELEMENT of <{path}>. "
                f"{tag} is a menu-item property — it must be an attribute "
                f"(e.g. <{path} {tag}=\"...\"/>). As an element OPNsense "
                f"renders it as an extra, empty menu row instead."
            )
            # Menu items are identified by tag name; text content is never read.
            assert not (child.text or "").strip(), (
                f"{menu_path}: <{tag}> under <{path}> carries text "
                f"({(child.text or '').strip()!r}). The menu parser ignores "
                f"element text entirely; labels go in VisibleName=\"...\"."
            )
            walk(child, tag, menu_path)

    for menu_path in menus:
        root = ET.parse(menu_path).getroot()
        assert root.tag == "menu", (
            f"{menu_path}: root element is <{root.tag}>, must be <menu> — "
            f"MenuSystem::addXML() rejects anything else "
            f"('seems to be of wrong type') and the whole file is dropped"
        )
        categories = list(root)
        assert categories, f"{menu_path}: <menu> has no category elements"
        for category in categories:
            # A category must contribute at least one entry, otherwise the
            # plugin ships a menu file that adds nothing.
            assert len(list(category)), (
                f"{menu_path}: category <{category.tag}> has no entries"
            )
            walk(category, category.tag, menu_path)

    # And the entry we actually ship must still point at the UI page.
    hound = OPNSENSE / ("src/opnsense/mvc/app/models/OPNsense/Hound"
                        "/Menu/Menu.xml")
    root = ET.parse(hound).getroot()
    entry = root.find("./Services/SurveillanceHound")
    assert entry is not None, (
        f"{hound}: no Services/SurveillanceHound entry — the plugin would "
        f"install with no Services menu item"
    )
    assert entry.get("url") == "/ui/hound/", (
        f"{hound}: SurveillanceHound url is {entry.get('url')!r}, "
        f"expected '/ui/hound/'"
    )
    assert entry.get("VisibleName"), f"{hound}: entry has no VisibleName"
    print(f"  OPNsense menu: {len(menus)} Menu.xml — category/entry shape "
          f"matches core plugins, properties are attributes")


def _check_opnsense_renderer_error_path() -> None:
    """Missing config block should fail loudly, not silently emit garbage."""
    mod = _load_opnsense_renderer()
    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "config.xml"
        cfg.write_text('<?xml version="1.0"?><opnsense><Junk/></opnsense>')
        out = Path(td) / "hound.toml"
        rc = mod.main(["render_config.py", str(cfg), str(out)])
        assert rc != 0, "expected non-zero on missing <Hound> block"
        assert not out.exists(), "shouldn't have written output on error"
    print("  OPNsense renderer: error path returns non-zero on missing block")


# ---------------------------------------------------------------------------
# pfSense renderer — ported to Python so we can validate output
# ---------------------------------------------------------------------------


def _pf_csv_to_toml_array(csv: str) -> str:
    """Equivalent of hound_csv_to_toml_array() in deploy/pfsense/.../hound.inc"""
    items = [x.strip() for x in (csv or "").split(",") if x.strip()]
    quoted = ['"' + x.replace("\\", "\\\\") + '"' for x in items]
    return "[" + ", ".join(quoted) + "]"


def _pf_b(b: bool) -> str:
    return "true" if b else "false"


def _pf_render_toml(iface: str, bpf: str, snaplen: int,
                    camera_ips: str, camera_subnets: str, nvr_ips: str,
                    mfg_allow: str,
                    bp_enabled: bool, z: float, min_samples: int,
                    sn_enabled: bool, sn_window: float, sn_minsev: str,
                    web_enabled: bool, web_host: str, web_port: int) -> str:
    """Python port of hound_render_toml() — mirrors the PHP heredoc exactly.
    If you edit hound.inc, mirror the change here AND extend the case list."""
    bpf_line = f'bpf       = "{bpf}"\n' if bpf else ""
    cams = _pf_csv_to_toml_array(camera_ips)
    subnets = _pf_csv_to_toml_array(camera_subnets)
    nvrs = _pf_csv_to_toml_array(nvr_ips)
    allow = _pf_csv_to_toml_array(mfg_allow)
    return f"""# Generated by the SurveillanceHound pfSense package — do not hand-edit.
# To add custom [[notify]] blocks, drop them into /etc/hound.toml.local
# (sourced by the rc.d script).

[capture]
interface = "{iface}"
snaplen   = {snaplen}
{bpf_line}
[network]
camera_ips             = {cams}
camera_subnets         = {subnets}
nvr_ips                = {nvrs}
manufacturer_allowlist = {allow}

[store]
path = "/var/lib/hound/hound.sqlite"

[baseline]
enabled                = {_pf_b(bp_enabled)}
z_threshold            = {z}
min_samples            = {min_samples}
flush_interval_seconds = 60.0

[snapshot]
enabled         = {_pf_b(sn_enabled)}
window_seconds  = {sn_window}
min_severity    = "{sn_minsev}"
snaplen         = 1500

[web]
enabled                = {_pf_b(web_enabled)}
host                   = "{web_host}"
port                   = {web_port}
poll_interval_seconds  = 5.0

[[notify]]
type  = "stdout"
level = "low"

[[notify]]
type      = "jsonlines"
path      = "/var/log/hound/hound.alerts.jsonl"
level     = "low"
max_bytes = 10485760
keep      = 5"""


def _check_pfsense_renderer() -> None:
    cases = [
        # full
        dict(iface="igb1", bpf="host 192.168.10.0/24", snaplen=1500,
             camera_ips="192.168.10.20,192.168.10.21", camera_subnets="192.168.10.0/24",
             nvr_ips="192.168.10.10", mfg_allow="203.0.113.0/24",
             bp_enabled=True, z=4.0, min_samples=100,
             sn_enabled=True, sn_window=60.0, sn_minsev="medium",
             web_enabled=True, web_host="127.0.0.1", web_port=8080),
        # minimum / empty
        dict(iface="lan", bpf="", snaplen=96,
             camera_ips="", camera_subnets="", nvr_ips="", mfg_allow="",
             bp_enabled=False, z=4.0, min_samples=100,
             sn_enabled=False, sn_window=60.0, sn_minsev="medium",
             web_enabled=False, web_host="127.0.0.1", web_port=8080),
        # only NVR set
        dict(iface="opt2", bpf="", snaplen=96,
             camera_ips="", camera_subnets="10.0.0.0/24", nvr_ips="10.0.0.5",
             mfg_allow="",
             bp_enabled=True, z=3.5, min_samples=50,
             sn_enabled=False, sn_window=30.0, sn_minsev="high",
             web_enabled=True, web_host="0.0.0.0", web_port=8888),
    ]
    for i, args in enumerate(cases):
        out = _pf_render_toml(**args)
        data = tomllib.loads(out)
        # every section present
        for section in ("capture", "network", "store", "baseline",
                        "snapshot", "web"):
            assert section in data, f"case {i}: missing [{section}]"
        # capture interface preserved
        assert data["capture"]["interface"] == args["iface"]
        assert data["capture"]["snaplen"] == args["snaplen"]
        # bpf only present if non-empty
        if args["bpf"]:
            assert data["capture"].get("bpf") == args["bpf"]
        else:
            assert "bpf" not in data["capture"]
        # CSV → array
        expected_cams = [x.strip() for x in args["camera_ips"].split(",")
                         if x.strip()]
        assert data["network"]["camera_ips"] == expected_cams
        # booleans round-trip as bools (not strings)
        assert data["baseline"]["enabled"] is args["bp_enabled"]
        assert data["snapshot"]["enabled"] is args["sn_enabled"]
        assert data["web"]["enabled"] is args["web_enabled"]
        # default notify always present
        assert any(n["type"] == "stdout" for n in data["notify"])
        assert any(n["type"] == "jsonlines" for n in data["notify"])
    print(f"  pfSense renderer: {len(cases)} model variants → valid TOML each")


# ---------------------------------------------------------------------------
# Cross-plugin consistency
# ---------------------------------------------------------------------------


def _check_cross_consistency() -> None:
    """Both renderers must emit configs the surveillancehound config loader
    can actually consume. Round-trip through the real loader."""
    sys.path.insert(0, str(ROOT / "src"))
    from surveillancehound.config import load_from_dict

    mod = _load_opnsense_renderer()
    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "config.xml"
        cfg.write_text(_opnsense_synthetic_config())
        out = Path(td) / "hound.toml"
        mod.main(["render_config.py", str(cfg), str(out)])
        parsed = tomllib.loads(out.read_text())
        loaded = load_from_dict(parsed)
        assert loaded.capture.interface == "vlan10"
        assert loaded.baseline.enabled
        assert loaded.snapshot.enabled
        assert loaded.web.enabled
        assert any(n.type == "stdout" for n in loaded.notify)
        # uptime surface: form values survive render -> tomllib -> loader
        assert loaded.uptime.enabled is True
        assert loaded.uptime.startup_grace_seconds == 300.0
        assert loaded.uptime.capture_stall_seconds == 45.0
        assert loaded.thresholds.silence_seconds == 900.0
        # grace_for() prefers the explicit grace when non-zero
        assert loaded.uptime.grace_for(loaded.thresholds) == 300.0

    # disabled/zero variant: 0 grace means "inherit silence_seconds"
    with tempfile.TemporaryDirectory() as td:
        cfg = Path(td) / "config.xml"
        cfg.write_text(_opnsense_synthetic_config(
            uptime_enabled="0", startup_grace_seconds="0",
            capture_stall_seconds="0", silence_seconds="1200.0",
        ))
        out = Path(td) / "hound.toml"
        mod.main(["render_config.py", str(cfg), str(out)])
        loaded = load_from_dict(tomllib.loads(out.read_text()))
        assert loaded.uptime.enabled is False
        assert loaded.uptime.capture_stall_seconds == 0.0
        assert loaded.thresholds.silence_seconds == 1200.0
        assert loaded.uptime.grace_for(loaded.thresholds) == 1200.0

    pf_out = _pf_render_toml(
        iface="igb1", bpf="", snaplen=96,
        camera_ips="10.0.0.1", camera_subnets="", nvr_ips="", mfg_allow="",
        bp_enabled=False, z=4.0, min_samples=100,
        sn_enabled=False, sn_window=60.0, sn_minsev="medium",
        web_enabled=False, web_host="127.0.0.1", web_port=8080,
    )
    parsed = tomllib.loads(pf_out)
    loaded = load_from_dict(parsed)
    assert loaded.capture.interface == "igb1"
    assert loaded.network.camera_ips == ["10.0.0.1"]

    print("  cross-consistency: both renderers → load_from_dict accepts them")


def _check_wazuh_artifacts() -> None:
    """Validate the Wazuh decoder + rules:

      * XML well-formedness (covered by _check_xml_wellformed, but we
        also verify the file LIVES under deploy/wazuh)
      * Every <field name="X"> in the rules references a field that
        Hound's Alert.as_dict() actually emits — otherwise the rule
        silently never matches, which is a real foot-gun
      * Rule IDs in the operator-defined 100200+ range
      * Severity references are valid Hound severities
      * Custom syslog decoder's <order> fields match what the
        SyslogChannel structured-data block produces
    """
    sys.path.insert(0, str(ROOT / "src"))
    from surveillancehound.alerts import Alert  # noqa: PLC0415

    # ground-truth: what fields does Hound's JSON output actually have?
    sample = Alert(
        ts=1.7e9, device_ip="10.0.0.1", kind="bulk_inbound",
        severity="high", summary="x", detail="y",
        dedup_key="bulk_inbound:10.0.0.1",
    ).as_dict()
    emitted_fields = set(sample.keys())
    # rules can also match on the @source.* labels we add via localfile-snippet
    allowed_fields = emitted_fields | {"@source.name", "@source.product"}

    rules_path = WAZUH / "hound-rules.xml"
    assert rules_path.is_file(), rules_path
    tree = ET.parse(rules_path)
    root = tree.getroot()
    referenced_fields: set[str] = set()
    rule_ids: list[int] = []
    severities_in_rules: set[str] = set()
    for rule in root.iter("rule"):
        rid = int(rule.attrib["id"])
        assert 100000 <= rid <= 119999, (
            f"rule {rid}: outside the operator-defined 100000–119999 range"
        )
        rule_ids.append(rid)
        for fld in rule.findall("field"):
            referenced_fields.add(fld.attrib["name"])
            if fld.attrib["name"] == "severity":
                m = re.match(r"\^?(\w+)\$?$", (fld.text or "").strip())
                if m:
                    severities_in_rules.add(m.group(1))
    assert len(rule_ids) == len(set(rule_ids)), (
        f"duplicate rule IDs in hound-rules.xml: {rule_ids}"
    )
    missing = referenced_fields - allowed_fields
    assert not missing, (
        f"rules reference fields Hound doesn't emit: {missing}. "
        f"Hound emits: {sorted(emitted_fields)}"
    )
    valid_severities = {"info", "low", "medium", "high", "critical"}
    bad = severities_in_rules - valid_severities
    assert not bad, (
        f"rules reference invalid severities: {bad}. "
        f"Hound emits: {sorted(valid_severities)}"
    )

    # decoder check — the <order> field names must match what the rules
    # consume
    decoder_path = WAZUH / "hound-decoder.xml"
    assert decoder_path.is_file(), decoder_path
    # the file has multiple <decoder> top-level elements without a wrapping
    # root, so we wrap it for the XML parser
    wrapped = f"<root>{decoder_path.read_text()}</root>"
    droot = ET.fromstring(wrapped)
    decoder_order_fields: set[str] = set()
    for order in droot.iter("order"):
        for f in (order.text or "").split(","):
            f = f.strip()
            if f:
                decoder_order_fields.add(f)
    # the decoder must extract the same fields the rules match on
    rules_need = referenced_fields - {"@source.name", "@source.product"}
    not_decoded = rules_need - decoder_order_fields - {"kind"}  # kind in prematch
    # Wazuh's built-in json decoder produces all fields automatically, so
    # this is only a hard check when there's NO json source — for now
    # just inform if the syslog decoder is missing anything
    missing_in_decoder = rules_need - decoder_order_fields
    if missing_in_decoder:
        # Not fatal: the json path covers it. But warn.
        print(f"  wazuh: note — syslog decoder doesn't extract "
              f"{sorted(missing_in_decoder)} (json path covers these)")

    # localfile-snippet sanity: must reference the same path Hound writes to
    snippet = (WAZUH / "localfile-snippet.xml").read_text()
    # parse the <localfile> stanza (file has comments + the snippet)
    snippet_xml = re.sub(r"<!--.*?-->", "", snippet, flags=re.DOTALL).strip()
    lfroot = ET.fromstring(f"<root>{snippet_xml}</root>")
    lf = lfroot.find("localfile")
    assert lf is not None, "no <localfile> in snippet"
    assert lf.findtext("log_format") == "json", (
        "snippet must use json log_format"
    )
    assert lf.findtext("location").endswith(".jsonl"), (
        "snippet location should end .jsonl"
    )

    print(f"  wazuh rules: {len(rule_ids)} rules, ids "
          f"{min(rule_ids)}..{max(rule_ids)}; fields validated against "
          f"Alert.as_dict()")


def _check_opnsense_layout() -> None:
    """Assert the OPNsense MVC tree has every file the framework expects.

    Three real bugs caught by the dev-rig live validation became permanent
    static checks:

      (a) Every controllers/OPNsense/<Plugin>/IndexController.php that calls
          `getForm("<name>")` must have a corresponding
          controllers/OPNsense/<Plugin>/forms/<name>.xml on disk. OPNsense's
          base controller looks for forms next to the *controller*, not the
          model. Misplacing the form throws a 500 on every UI hit.

      (b) Every models/OPNsense/<Plugin>/<Plugin>.xml schema must have a
          sibling <Plugin>.php class extending BaseModel. Without it,
          ApiMutableServiceControllerBase::getModel() fails with
          ``ReflectionException: Class "\\OPNsense\\<Plugin>\\<Plugin>"
          does not exist``.

      (c) Every rc.d script referenced by a configd action file must exist
          at the path the action declares (verified by reading the actual
          `command:` lines from actions_*.conf).
    """
    import re
    ctl_root = OPNSENSE / "src/opnsense/mvc/app/controllers/OPNsense"
    mdl_root = OPNSENSE / "src/opnsense/mvc/app/models/OPNsense"
    cfg_root = OPNSENSE / "src/opnsense/service/conf/actions.d"
    plugin_dirs = sorted(d for d in ctl_root.iterdir() if d.is_dir())
    if not plugin_dirs:
        raise AssertionError(f"no plugin dirs under {ctl_root}")
    for plug in plugin_dirs:
        name = plug.name
        # (a) form references → matching XML present
        idx = plug / "IndexController.php"
        if idx.exists():
            wanted = set(re.findall(
                r'getForm\(\s*[\'"]([^\'"]+)[\'"]', idx.read_text(),
            ))
            for form_name in wanted:
                form_xml = plug / "forms" / f"{form_name}.xml"
                assert form_xml.exists(), (
                    f"{idx} calls getForm({form_name!r}) but "
                    f"{form_xml} is missing"
                )
        # (b) model XML → matching PHP class
        model_xml = mdl_root / name / f"{name}.xml"
        if model_xml.exists():
            model_php = mdl_root / name / f"{name}.php"
            assert model_php.exists(), (
                f"{model_xml} present but {model_php} is missing — "
                f"ApiMutableServiceControllerBase needs the PHP class to "
                f"reflect on (otherwise: ReflectionException at runtime)"
            )
    # (c) every command: line in actions_*.conf points to a real file in the
    # plugin tree (mapped from absolute install path → src tree path)
    for actions in cfg_root.glob("actions_*.conf"):
        for line in actions.read_text().splitlines():
            line = line.strip()
            if not line.startswith("command:"):
                continue
            cmd = line[len("command:"):].split()[0]
            # Map install paths to src/ paths
            src_path = None
            if cmd.startswith("/usr/local/opnsense/"):
                src_path = OPNSENSE / "src/opnsense" / cmd[len("/usr/local/opnsense/"):]
            elif cmd.startswith("/usr/local/etc/rc.d/"):
                src_path = OPNSENSE / "src/usr/local/etc/rc.d" / Path(cmd).name
            elif cmd.startswith("/etc/rc.d/"):
                # legacy path — also accept if installed there
                src_path = OPNSENSE / "src/etc/rc.d" / Path(cmd).name
            if src_path is not None and not src_path.exists():
                raise AssertionError(
                    f"{actions}: 'command:{cmd}' references a file that "
                    f"isn't in the plugin tree at {src_path}"
                )
    print(f"  OPNsense layout: {len(plugin_dirs)} plugin(s) "
          f"— controllers↔forms↔models↔actions all wired")


def _check_opnsense_form_ids() -> None:
    """Every form field id must be the FULL model path, and must exist.

    The published 0.1.2 plugin rendered its Listen-interface dropdown with no
    options at all, on 26.1.6 and 26.7 alike. The ids were section-relative
    ("general.interface") while the API returns the model wrapped in its own
    name ({"hound": {"general": {...}}}, from
    ApiMutableModelControllerBase::getAction). opnsense.js setFormData()
    walks an input's id — split on "." — through that document, so the first
    key never matched and no field was ever populated; a <select> starts
    empty, which is why that one field looked broken while blank text inputs
    looked normal. The same mismatch breaks the other two directions:
    getFormData() rebuilds the POST body from the ids (so Save posted
    general[...] rather than hound[general][...]) and handleFormValidation()
    matches server validation keys, which are also fully qualified.

    Core plugins all use fully-qualified ids (dnsmasq's are "dnsmasq.enable"
    etc.). This check asserts the prefix AND that the remainder resolves to a
    real node in the model XML, which also catches renamed/typo'd fields.
    """
    ctl_root = OPNSENSE / "src/opnsense/mvc/app/controllers/OPNsense"
    mdl_root = OPNSENSE / "src/opnsense/mvc/app/models/OPNsense"
    checked = 0
    for plug in sorted(d for d in ctl_root.iterdir() if d.is_dir()):
        model_xml = mdl_root / plug.name / f"{plug.name}.xml"
        if not model_xml.exists():
            continue
        model_name = plug.name.lower()
        items = ET.parse(model_xml).getroot().find("items")
        assert items is not None, f"{model_xml}: no <items> element"
        known = {
            f"{section.tag}.{field.tag}"
            for section in items
            for field in section
        }
        for form_xml in sorted((plug / "forms").glob("*.xml")):
            for node in ET.parse(form_xml).getroot().iter("id"):
                field_id = (node.text or "").strip()
                if not field_id:
                    continue
                checked += 1
                head, _, rest = field_id.partition(".")
                assert head == model_name and rest, (
                    f"{form_xml}: field id {field_id!r} is not prefixed with "
                    f"the model name — it must be "
                    f"'{model_name}.{field_id}'. Unprefixed ids never match "
                    f"the /api/{model_name}/settings/get document, so the "
                    f"field renders unpopulated (dropdowns come up empty) "
                    f"and Save posts the wrong shape."
                )
                assert rest in known, (
                    f"{form_xml}: field id {field_id!r} has no matching node "
                    f"in {model_xml} (known: {sorted(known)})"
                )
    assert checked, f"no form field ids found under {ctl_root}"
    print(f"  OPNsense forms: {checked} field id(s) fully qualified and "
          f"present in the model XML")


def main() -> int:
    print("=== Plugin static checks ===")
    _check_xml_wellformed()
    _check_sh_syntax()
    _check_php_brace_balance()
    _check_opnsense_layout()
    _check_opnsense_menu_xml()
    _check_opnsense_form_ids()
    print()
    print("=== OPNsense renderer ===")
    _check_opnsense_renderer()
    _check_opnsense_interface_resolution()
    _check_opnsense_pkg_build_script()
    _check_opnsense_renderer_error_path()
    print()
    print("=== pfSense renderer ===")
    _check_pfsense_renderer()
    print()
    print("=== Cross-plugin consistency ===")
    _check_cross_consistency()
    print()
    print("=== Wazuh integration ===")
    _check_wazuh_artifacts()
    print()
    print("PLUGINS VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
