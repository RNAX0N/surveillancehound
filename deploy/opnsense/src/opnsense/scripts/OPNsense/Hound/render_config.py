#!/usr/local/bin/python3
"""Render /usr/local/etc/hound.toml from the OPNsense Hound model.

Invoked by the configd `hound reload` action — see
service/conf/actions.d/actions_hound.conf. Reading the live config from
/conf/config.xml keeps us decoupled from Phalcon's runtime; the only
dependency is the stdlib XML parser.

Idempotent — running it twice produces byte-identical output (assuming
the underlying config hasn't changed). Exit 0 on success, non-zero on
any parse / file-write error so configd surfaces the failure.

This is OPNsense-side glue; the actual hound daemon and CLI live in the
SurveillanceHound Python package the operator installed separately.
"""

from __future__ import annotations

import os
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

_CONFIG = Path("/conf/config.xml")
_OUT = Path("/usr/local/etc/hound.toml")
_HOUND_PATH = "OPNsense/Hound"


def _csv_to_array(value: str) -> str:
    """Comma-separated → TOML array literal. Empty → []."""
    if not value:
        return "[]"
    items = [x.strip() for x in value.split(",") if x.strip()]
    if not items:
        return "[]"
    quoted = ", ".join(_toml_quote(x) for x in items)
    return f"[{quoted}]"


def _toml_quote(s: str) -> str:
    """Quote a string for TOML; escape backslash and double-quote."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_bool(v) -> str:
    if isinstance(v, str):
        return "true" if v.strip() in ("1", "true", "on", "yes") else "false"
    return "true" if v else "false"


def _xtext(node: ET.Element, path: str, default: str = "") -> str:
    """ET .findtext but stripped + default for None."""
    val = node.findtext(path)
    return (val or default).strip() if val else default


_WEBGUI_PROTOCOL_CACHE: dict[str, str] = {}


def _webgui_uses_https(config_path: Path | None = None) -> bool:
    """Read OPNsense's own webgui protocol from /conf/config.xml.

    Default in OPNsense is `https`; an operator who switched to `http` in
    System → Settings → Administration almost certainly wants the
    dashboard on HTTP too (otherwise the iframe would be mixed-content
    blocked by the browser). Cache so we don't reparse the file twice
    when render() is called repeatedly in a test.
    """
    p = str(config_path) if config_path else str(_CONFIG)
    if p in _WEBGUI_PROTOCOL_CACHE:
        return _WEBGUI_PROTOCOL_CACHE[p] == "https"
    proto = "https"  # OPNsense default — used if /conf/config.xml is unreadable
    try:
        tree = ET.parse(p)
        node = tree.getroot().find("./system/webgui/protocol")
        if node is not None and (node.text or "").strip():
            proto = node.text.strip().lower()
    except (FileNotFoundError, ET.ParseError):
        pass
    _WEBGUI_PROTOCOL_CACHE[p] = proto
    return proto == "https"


_IFACE_CACHE: dict[str, dict[str, str]] = {}


def _interface_map(config_path: Path | None = None) -> dict[str, str]:
    """Map OPNsense interface aliases to real device names.

    `/conf/config.xml` holds `<interfaces><lan><if>igb1</if></lan>…`. The
    form stores the alias (`lan`, `opt3`), but tcpdump needs the device
    (`igb1`, `vlan0.20`).
    """
    p = str(config_path) if config_path else str(_CONFIG)
    if p in _IFACE_CACHE:
        return _IFACE_CACHE[p]
    mapping: dict[str, str] = {}
    try:
        tree = ET.parse(p)
        node = tree.getroot().find("./interfaces")
        if node is not None:
            for child in node:
                dev = (child.findtext("if") or "").strip()
                if dev:
                    mapping[child.tag] = dev
    except (FileNotFoundError, ET.ParseError):
        pass
    _IFACE_CACHE[p] = mapping
    return mapping


def resolve_interface(alias: str, config_path: Path | None = None) -> str:
    """Translate a form interface value into something tcpdump accepts.

    The OPNsense picker stores an ALIAS (`lan`, `opt3`), but tcpdump only
    knows device names. Writing the alias through verbatim produced
    `interface = "lan"` and the daemon died with `tcpdump: lan: No such
    device exists` — a config saved from the UI could never capture.

    An unknown value is passed through unchanged: an operator who typed a
    real device name (`igb1`, `vlan0.20`) into the field must keep working,
    and so must a box whose config.xml is unreadable from here.
    """
    if not alias:
        return alias
    return _interface_map(config_path).get(alias, alias)


def render(model_root: ET.Element, config_path: Path | None = None) -> str:
    """Render the TOML from the parsed model subtree (the Hound block).

    `config_path` is the /conf/config.xml the model came from; it is read
    again for the interface alias table and the webgui protocol. Defaults
    to the real path so existing callers keep working.
    """
    g = model_root.find("general") or ET.Element("general")
    n = model_root.find("network") or ET.Element("network")
    b = model_root.find("baseline") or ET.Element("baseline")
    s = model_root.find("snapshot") or ET.Element("snapshot")
    w = model_root.find("web") or ET.Element("web")
    t = model_root.find("thresholds") or ET.Element("thresholds")
    u = model_root.find("uptime") or ET.Element("uptime")

    # the picker stores an alias; tcpdump needs the device behind it
    iface = resolve_interface(_xtext(g, "interface"), config_path)
    snaplen = _xtext(g, "snaplen", "96")
    bpf = _xtext(g, "bpf")

    cam_ips = _csv_to_array(_xtext(n, "camera_ips"))
    cam_nets = _csv_to_array(_xtext(n, "camera_subnets"))
    nvr_ips = _csv_to_array(_xtext(n, "nvr_ips"))
    allow = _csv_to_array(_xtext(n, "manufacturer_allowlist"))

    bp_enabled = _toml_bool(_xtext(b, "enabled", "0"))
    bp_z = _xtext(b, "z_threshold", "4.0")
    bp_min = _xtext(b, "min_samples", "100")

    sn_enabled = _toml_bool(_xtext(s, "enabled", "0"))
    sn_window = _xtext(s, "window_seconds", "60.0")
    sn_minsev = _xtext(s, "min_severity", "medium")

    # Silence threshold drives camera_offline; it is also the fallback the
    # uptime tracker inherits when startup_grace_seconds is 0.
    silence_seconds = _xtext(t, "silence_seconds", "600.0")

    up_enabled = _toml_bool(_xtext(u, "enabled", "1"))
    up_grace = _xtext(u, "startup_grace_seconds", "600.0")
    up_stall = _xtext(u, "capture_stall_seconds", "120.0")

    web_enabled = _toml_bool(_xtext(w, "enabled", "1"))
    web_host = _xtext(w, "host", "127.0.0.1")
    web_port = _xtext(w, "port", "8080")
    # If the operator supplied explicit cert/key paths, honor them.
    # Otherwise, match the dashboard's scheme to OPNsense's own webgui
    # protocol (https unless explicitly disabled in System → Settings →
    # Administration). The iframe would be mixed-content blocked anyway
    # if it didn't match, so there's no useful operator choice here.
    web_cert = _xtext(w, "cert_file")
    web_key = _xtext(w, "key_file")
    if not (web_cert and web_key):
        if _webgui_uses_https(config_path):
            web_cert = "/var/lib/hound/hound-web.crt"
            web_key = "/var/lib/hound/hound-web.key"
        else:
            web_cert = ""
            web_key = ""

    parts = [
        "# Auto-generated by /usr/local/opnsense/scripts/OPNsense/Hound/render_config.py",
        "# DO NOT HAND-EDIT — overwritten on every save in Services > SurveillanceHound.",
        "# To add custom [[notify]] blocks, drop them into /etc/hound.toml.local",
        "# which the rc.d wrapper sources before invoking the daemon.",
        "",
        "[capture]",
        f"interface = {_toml_quote(iface)}",
        f"snaplen   = {int(snaplen)}",
    ]
    if bpf:
        parts.append(f"bpf       = {_toml_quote(bpf)}")
    parts += [
        "",
        "[network]",
        f"camera_ips             = {cam_ips}",
        f"camera_subnets         = {cam_nets}",
        f"nvr_ips                = {nvr_ips}",
        f"manufacturer_allowlist = {allow}",
        "",
        "[thresholds]",
        f"silence_seconds = {float(silence_seconds)}",
        "",
        "[store]",
        'path = "/var/lib/hound/hound.sqlite"',
        "",
        "[baseline]",
        f"enabled                = {bp_enabled}",
        f"z_threshold            = {float(bp_z)}",
        f"min_samples            = {int(bp_min)}",
        "flush_interval_seconds = 60.0",
        "",
        "[snapshot]",
        f"enabled         = {sn_enabled}",
        f"window_seconds  = {float(sn_window)}",
        f"min_severity    = {_toml_quote(sn_minsev)}",
        "snaplen         = 1500",
        "",
        "[web]",
        f"enabled                = {web_enabled}",
        f"host                   = {_toml_quote(web_host)}",
        f"port                   = {int(web_port)}",
        "poll_interval_seconds  = 5.0",
        f"cert_file              = {_toml_quote(web_cert)}",
        f"key_file               = {_toml_quote(web_key)}",
        "",
        "# Uptime monitoring is PASSIVE: a camera counts as up because packets",
        "# from it were seen on the monitored interface. Nothing is probed.",
        "[uptime]",
        f"enabled               = {up_enabled}",
        f"startup_grace_seconds = {float(up_grace)}",
        f"capture_stall_seconds = {float(up_stall)}",
        "",
        "# default notifications — extend in /etc/hound.toml.local",
        "[[notify]]",
        'type  = "stdout"',
        'level = "low"',
        "",
        "[[notify]]",
        'type      = "jsonlines"',
        'path      = "/var/log/hound/hound.alerts.jsonl"',
        'level     = "low"',
        "max_bytes = 10485760",
        "keep      = 5",
        "",
    ]
    return "\n".join(parts)


def main(argv: list[str]) -> int:
    # --print-enabled: report whether the operator has ticked Enable, and
    # write nothing. reload.sh uses it to keep rc.conf's hound_enable in
    # step with the model. Without that the tick-box was decorative: it
    # set general.enabled in config.xml, the daemon was never enabled and
    # never started, and nothing said so.
    args = [a for a in argv[1:] if not a.startswith("--")]
    print_enabled = "--print-enabled" in argv[1:]
    config_path = Path(args[0]) if len(args) > 0 else _CONFIG
    out_path = Path(args[1]) if len(args) > 1 else _OUT
    if not config_path.is_file():
        sys.stderr.write(f"config not found: {config_path}\n")
        return 1
    tree = ET.parse(str(config_path))
    root = tree.getroot()
    # OPNsense plugin configs live under OPNsense/Hound in /conf/config.xml
    hound = root.find(_HOUND_PATH)
    if hound is None:
        # second guess — some OPNsense versions namespace plugins differently
        hound = root.find("Hound") or root.find(".//Hound")
    if hound is None:
        sys.stderr.write(
            "no <OPNsense/Hound> block in config.xml — "
            "enable the plugin in Services > SurveillanceHound first\n",
        )
        return 2
    if print_enabled:
        general = hound.find("general")
        raw = _xtext(general, "enabled", "0") if general is not None else "0"
        sys.stdout.write(
            "YES\n" if _toml_bool(raw) == "true" else "NO\n"
        )
        return 0

    rendered = render(hound, config_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # atomic write so a half-rendered file never reaches the daemon
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    tmp.write_text(rendered)
    os.replace(tmp, out_path)
    _secure_output(out_path)
    return 0


def _secure_output(path: Path, owner: str = "hound") -> None:
    """Make the rendered config readable by the service user, and nobody else.

    configd runs its scripts with umask 027, so the file lands 0640 owned
    by root — and the daemon, running as an unprivileged user, crash-looped
    with PermissionError on its own config. `required_files` in the rc
    script does not catch this because rc.subr tests readability as root.

    0640 with group ownership, not 0644: this file carries webhook URLs,
    SMTP passwords and FTP credentials, so world-readable is the wrong
    trade. Failures are non-fatal — on a box without the hound user
    (a packaging dry-run, a test) the render itself still succeeded.
    """
    try:
        os.chmod(path, 0o640)
    except OSError as e:  # pragma: no cover - depends on host permissions
        sys.stderr.write(f"warning: could not chmod {path}: {e}\n")
    try:
        shutil.chown(path, user=owner, group=owner)
    except (OSError, LookupError) as e:
        sys.stderr.write(
            f"warning: could not chown {path} to {owner}: {e}; "
            f"the daemon may not be able to read its own config\n",
        )


if __name__ == "__main__":
    sys.exit(main(sys.argv))
