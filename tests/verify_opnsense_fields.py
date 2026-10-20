"""Every OPNsense form field must survive the whole round trip.

The plugin has four places a setting has to line up, and nothing previously
checked them against each other as a set:

    Hound.xml (model)  ->  general.xml (form)  ->  render_config.py
        ->  /usr/local/etc/hound.toml  ->  surveillancehound.config

A field can be present in all four and still be broken — rendered under the
wrong section, emitted as a string where the daemon wants a float, or
silently dropped because the renderer reads a key the model does not spell
the same way. Those are invisible in the UI: the box accepts your value,
saves it, and the daemon quietly runs on a default.

So this gives every field a distinctive non-default value, renders, and
asserts the value arrives in the parsed config with the right type. It also
checks the inventories match in both directions, which is what catches a
field that was added to the model and never wired up.

Run: PYTHONPATH=src:tests python tests/verify_opnsense_fields.py
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from surveillancehound.config import load_from_dict  # noqa: E402

PLUGIN = ROOT / "deploy/opnsense/src/opnsense/mvc/app"
MODEL_XML = PLUGIN / "models/OPNsense/Hound/Hound.xml"
FORM_XML = PLUGIN / "controllers/OPNsense/Hound/forms/general.xml"
RENDERER = (
    ROOT / "deploy/opnsense/src/opnsense/scripts/OPNsense/Hound/render_config.py"
)

# One distinctive value per field, chosen so a mix-up between two fields is
# visible rather than coincidentally equal. `check` receives the loaded
# HoundCfg and returns the value the daemon actually ended up with.
FIELDS: dict[str, dict] = {
    "general.enabled": {
        "raw": "1", "check": lambda c: True,  # not represented in hound.toml
    },
    "general.interface": {
        "raw": "vlan0.77", "check": lambda c: c.capture.interface,
        "want": "vlan0.77",
    },
    "general.bpf": {
        "raw": "not port 22", "check": lambda c: c.capture.bpf,
        "want": "not port 22",
    },
    "general.snaplen": {
        "raw": "1234", "check": lambda c: c.capture.snaplen, "want": 1234,
    },
    "network.camera_ips": {
        "raw": "10.77.0.1,10.77.0.2", "check": lambda c: c.network.camera_ips,
        "want": ["10.77.0.1", "10.77.0.2"],
    },
    "network.camera_subnets": {
        "raw": "10.77.0.0/24", "check": lambda c: c.network.camera_subnets,
        "want": ["10.77.0.0/24"],
    },
    "network.nvr_ips": {
        "raw": "10.77.9.9", "check": lambda c: c.network.nvr_ips,
        "want": ["10.77.9.9"],
    },
    "network.manufacturer_allowlist": {
        "raw": "198.51.100.0/24",
        "check": lambda c: c.network.manufacturer_allowlist,
        "want": ["198.51.100.0/24"],
    },
    "network.lan_subnets": {
        "raw": "10.77.0.0/16,88.255.5.0/24",
        "check": lambda c: [str(x) for x in c.network.lan_subnets],
        "want": ["10.77.0.0/16", "88.255.5.0/24"],
    },
    # The combined fixture renders ONE config, and a relay is either an
    # agent or a collector, never both. Collector fields assert; the
    # agent-only fields below are coverage-only and are asserted by
    # _check_relay_agent_round_trip against an agent-mode config.
    "relay.mode": {
        "raw": "collector", "check": lambda c: c.relay.mode,
        "want": "collector",
    },
    "relay.listen_host": {
        "raw": "10.77.0.250", "check": lambda c: c.relay.listen_host,
        "want": "10.77.0.250",
    },
    "relay.listen_port": {
        "raw": "19443", "check": lambda c: c.relay.listen_port, "want": 19443,
    },
    "relay.cert_file": {
        "raw": "/var/lib/hound/t.crt", "check": lambda c: c.relay.cert_file,
        "want": "/var/lib/hound/t.crt",
    },
    "relay.key_file": {
        "raw": "/var/lib/hound/t.key", "check": lambda c: c.relay.key_file,
        "want": "/var/lib/hound/t.key",
    },
    "relay.sensors": {
        "raw": "frigate = top-secret-one-abcdefgh-abcdef",
        "check": lambda c: [(x.id, x.key) for x in c.relay.sensors],
        "want": [("frigate", "top-secret-one-abcdefgh-abcdef")],
    },
    "relay.remote_retention_days": {
        "raw": "17.5", "check": lambda c: c.relay.remote_retention_days,
        "want": 17.5,
    },
    "relay.max_rows_per_sensor": {
        "raw": "4242", "check": lambda c: c.relay.max_rows_per_sensor,
        "want": 4242,
    },
    "relay.min_free_disk_mb": {
        "raw": "123.5", "check": lambda c: c.relay.min_free_disk_mb,
        "want": 123.5,
    },
    "relay.sensor_id": {"raw": "edge-box"},
    "relay.url": {"raw": "https://10.77.0.250:19443/ingest/v1"},
    "relay.key": {"raw": "agent-secret-abcdef"},
    "relay.tls_fingerprint": {
        "raw": "sha256:AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD:EE:FF:00:11",
    },
    "thresholds.silence_seconds": {
        "raw": "777", "check": lambda c: c.thresholds.silence_seconds,
        "want": 777.0,
    },
    "uptime.enabled": {
        "raw": "0", "check": lambda c: c.uptime.enabled, "want": False,
    },
    "uptime.startup_grace_seconds": {
        "raw": "321", "check": lambda c: c.uptime.startup_grace_seconds,
        "want": 321.0,
    },
    "uptime.capture_stall_seconds": {
        "raw": "99", "check": lambda c: c.uptime.capture_stall_seconds,
        "want": 99.0,
    },
    "baseline.enabled": {
        "raw": "1", "check": lambda c: c.baseline.enabled, "want": True,
    },
    "baseline.z_threshold": {
        "raw": "6.5", "check": lambda c: c.baseline.z_threshold, "want": 6.5,
    },
    "baseline.min_samples": {
        "raw": "222", "check": lambda c: c.baseline.min_samples, "want": 222,
    },
    "snapshot.enabled": {
        "raw": "1", "check": lambda c: c.snapshot.enabled, "want": True,
    },
    "snapshot.window_seconds": {
        "raw": "45", "check": lambda c: c.snapshot.window_seconds, "want": 45.0,
    },
    "snapshot.min_severity": {
        "raw": "high", "check": lambda c: c.snapshot.min_severity, "want": "high",
    },
    "web.enabled": {
        "raw": "1", "check": lambda c: c.web.enabled, "want": True,
    },
    "web.host": {
        "raw": "10.77.0.254", "check": lambda c: c.web.host, "want": "10.77.0.254",
    },
    "web.port": {
        "raw": "8321", "check": lambda c: c.web.port, "want": 8321,
    },
    # cert/key are a pair: the renderer only emits them together, and the
    # config treats "both set" as the switch to HTTPS.
    "web.cert_file": {
        "raw": "/var/lib/hound/x.crt", "check": lambda c: c.web.cert_file,
        "want": "/var/lib/hound/x.crt",
    },
    "web.key_file": {
        "raw": "/var/lib/hound/x.key", "check": lambda c: c.web.key_file,
        "want": "/var/lib/hound/x.key",
    },
}


def _load_renderer():
    spec = importlib.util.spec_from_file_location("render_config", RENDERER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _model_fields() -> list[tuple[str, str]]:
    root = ET.parse(MODEL_XML).getroot()
    items = root.find(".//items")
    container = items if items is not None else root
    out = []
    for section in container:
        for field in section:
            out.append((f"{section.tag}.{field.tag}", field.get("type", "")))
    return out


def _model_root() -> str:
    """The key `getAction` wraps the model in — the last path element of
    <mount>, lowercased. For //OPNsense/Hound that is `hound`."""
    root = ET.parse(MODEL_XML).getroot()
    mount = (root.findtext("mount") or "").rstrip("/")
    assert mount, "model has no <mount>"
    return mount.rsplit("/", 1)[-1].lower()


def _check_inventories() -> None:
    """Model, form and this test must agree on the field set.

    Form ids must carry the model-root prefix. OPNsense's getAction wraps
    the model, so the payload is {"hound": {"general": ...}} and
    mapDataToFormUI matches ids against that shape. An id of
    `general.interface` matches nothing: the field silently never
    populates, and Save posts the wrong shape. Every field looked present
    in the UI while none of them were actually bound.
    """
    prefix = _model_root() + "."
    model = {name for name, _ in _model_fields()}
    form_raw = set(re.findall(r"<id>([^<]+)</id>", FORM_XML.read_text()))
    covered = set(FIELDS)

    unprefixed = sorted(i for i in form_raw if not i.startswith(prefix))
    assert not unprefixed, (
        f"form id(s) missing the '{prefix}' model-root prefix: {unprefixed} — "
        f"these will never bind to the API payload"
    )
    form = {i[len(prefix):] for i in form_raw}

    assert not (model - form), f"in the model but not the form: {sorted(model - form)}"
    assert not (form - model), f"in the form but not the model: {sorted(form - model)}"
    assert not (model - covered), (
        f"field(s) added to the plugin with no round-trip coverage here: "
        f"{sorted(model - covered)} — add them to FIELDS"
    )
    assert not (covered - model), (
        f"this test covers field(s) the model no longer has: "
        f"{sorted(covered - model)}"
    )
    print(f"  inventory: {len(model)} fields, model/form/test agree; "
          f"all form ids carry the '{prefix}' prefix")


def _build_config_xml() -> str:
    """A /conf/config.xml carrying every field at its distinctive value."""
    sections: dict[str, list[str]] = {}
    for fid, spec in FIELDS.items():
        section, name = fid.split(".", 1)
        sections.setdefault(section, []).append(
            f"        <{name}>{spec['raw']}</{name}>"
        )
    body = "\n".join(
        f"      <{s}>\n" + "\n".join(rows) + f"\n      </{s}>"
        for s, rows in sections.items()
    )
    return (
        '<?xml version="1.0"?>\n<opnsense>\n'
        "  <interfaces>\n    <lan><if>vlan0.77</if></lan>\n  </interfaces>\n"
        "  <OPNsense>\n    <Hound>\n" + body + "\n    </Hound>\n  </OPNsense>\n"
        "</opnsense>\n"
    )


def _check_round_trip() -> None:
    mod = _load_renderer()
    with tempfile.TemporaryDirectory() as td:
        cfg_path = Path(td) / "config.xml"
        out_path = Path(td) / "hound.toml"
        cfg_path.write_text(_build_config_xml())
        rc = mod.main(["render_config.py", str(cfg_path), str(out_path)])
        assert rc == 0, f"renderer returned {rc}"

        toml_text = out_path.read_text()
        data = tomllib.loads(toml_text)
        cfg = load_from_dict(data)

        failures = []
        for fid, spec in FIELDS.items():
            if "want" not in spec:
                continue
            got = spec["check"](cfg)
            want = spec["want"]
            if got != want:
                failures.append(f"    {fid}: want {want!r}, got {got!r}")
            elif type(got) is not type(want) and not (
                isinstance(got, list) and isinstance(want, list)
            ):
                failures.append(
                    f"    {fid}: value matched but type did not — "
                    f"want {type(want).__name__}, got {type(got).__name__}"
                )
        assert not failures, (
            "field(s) did not survive the round trip:\n" + "\n".join(failures)
        )
        print(f"  round trip: all {sum('want' in s for s in FIELDS.values())} "
              f"value-bearing fields arrive intact and correctly typed")


def _check_interface_is_resolved() -> None:
    """The form stores an alias; the daemon needs the device behind it."""
    mod = _load_renderer()
    mod._IFACE_CACHE.clear()
    with tempfile.TemporaryDirectory() as td:
        cfg_path = Path(td) / "config.xml"
        out_path = Path(td) / "hound.toml"
        xml = _build_config_xml().replace(
            "<interface>vlan0.77</interface>", "<interface>lan</interface>"
        )
        cfg_path.write_text(xml)
        assert mod.main(["render_config.py", str(cfg_path), str(out_path)]) == 0
        cfg = load_from_dict(tomllib.loads(out_path.read_text()))
        assert cfg.capture.interface == "vlan0.77", (
            f"interface alias was not resolved to its device: "
            f"{cfg.capture.interface!r} (tcpdump would fail with "
            f"'No such device exists')"
        )
        mod._IFACE_CACHE.clear()
    print("  interface: the alias stored by the form resolves to the device")



def _check_ui_endpoints_exist() -> None:
    """Every /api/hound/... the view calls must resolve to a real action.

    A UI pointed at a nonexistent endpoint fails as "Endpoint not found",
    and when it is a follow-up call the failure is quiet in the worst way:
    Save itself succeeds, config.xml is written, and the operator believes
    the change is live while the daemon keeps running the previously
    rendered file. `reload` was exactly that — the base controller supplies
    start/stop/restart/status/reconfigure and nothing else.
    """
    view = (PLUGIN / "views/OPNsense/Hound/index.volt").read_text()
    called = set(re.findall(r'["\'](/api/hound/([a-z]+)/([a-zA-Z]+))["\']', view))

    # actions defined in our own controllers
    own: dict[str, set[str]] = {}
    for php in (PLUGIN / "controllers/OPNsense/Hound/Api").glob("*.php"):
        ctrl = php.stem.replace("Controller", "").lower()
        own[ctrl] = {
            m.lower() for m in
            re.findall(r"public function ([a-zA-Z]+)Action", php.read_text())
        }

    # actions inherited from the OPNsense base classes we extend
    inherited = {
        "ApiMutableModelControllerBase": {"get", "set"},
        "ApiMutableServiceControllerBase": {
            "start", "stop", "restart", "status", "reconfigure",
        },
        "ApiControllerBase": set(),
    }
    for php in (PLUGIN / "controllers/OPNsense/Hound/Api").glob("*.php"):
        ctrl = php.stem.replace("Controller", "").lower()
        text = php.read_text()
        for base, acts in inherited.items():
            if re.search(rf"extends[ \t]+{base}(?![A-Za-z])", text):
                own[ctrl] |= acts

    missing = []
    for full, ctrl, action in sorted(called):
        if action.lower() not in own.get(ctrl, set()):
            missing.append(f"{full} (controller {ctrl!r} has: "
                           f"{sorted(own.get(ctrl, []))})")
    assert not missing, (
        "the view calls endpoint(s) that do not exist:\n    "
        + "\n    ".join(missing)
    )
    print(f"  endpoints: all {len(called)} /api/hound/* calls in the view resolve")



def _check_enable_is_wired() -> None:
    """Ticking Enable must actually enable and start the service.

    The box set general.enabled in config.xml and rendered hound.toml, but
    nothing ever wrote rc.conf's hound_enable, and reload.sh restarted the
    daemon only when that was already YES. So the tick-box was decorative:
    the service was never enabled, never started, and did not survive a
    reboot. `service hound status` reported "not running" with no log file
    at all, because it had genuinely never run once.
    """
    reload_sh = (
        ROOT / "deploy/opnsense/src/opnsense/scripts/OPNsense/Hound/reload.sh"
    ).read_text()

    assert "--print-enabled" in reload_sh, (
        "reload.sh no longer asks the model whether Enable is ticked"
    )
    assert "sysrc hound_enable=YES" in reload_sh, (
        "reload.sh must set hound_enable=YES, or the service is never "
        "enabled and will not come back after a reboot"
    )
    assert "sysrc hound_enable=NO" in reload_sh, (
        "reload.sh must clear hound_enable when Enable is unticked"
    )
    # rc.subr's `restart` is a no-op on a stopped service, which is exactly
    # the first-enable case this bug lived in.
    assert "onerestart" in reload_sh, (
        "reload.sh must use onerestart; plain restart does nothing when the "
        "service is not already running"
    )

    renderer = (
        ROOT / "deploy/opnsense/src/opnsense/scripts/OPNsense/Hound/render_config.py"
    ).read_text()
    assert "--print-enabled" in renderer, (
        "render_config.py must support --print-enabled for reload.sh"
    )

    # and it must actually report both states
    mod = _load_renderer()
    import io
    import contextlib
    with tempfile.TemporaryDirectory() as td:
        for raw, want in (("1", "YES"), ("0", "NO")):
            cfg = Path(td) / "c.xml"
            cfg.write_text(
                '<?xml version="1.0"?><opnsense>'
                "<interfaces><lan><if>igb9</if></lan></interfaces>"
                "<OPNsense><Hound><general>"
                f"<enabled>{raw}</enabled><interface>lan</interface>"
                "</general></Hound></OPNsense></opnsense>"
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = mod.main([
                    "render_config.py", str(cfg),
                    str(Path(td) / "o.toml"), "--print-enabled",
                ])
            assert rc == 0, f"--print-enabled returned {rc}"
            got = buf.getvalue().strip()
            assert got == want, f"enabled={raw!r} reported {got!r}, want {want!r}"
    print("  enable: ticking Enable sets hound_enable and starts the service")


def _check_relay_agent_round_trip() -> None:
    """Agent mode, and the off case.

    The combined fixture can only render one role at a time, so the
    agent-only fields would otherwise be inventory-covered but never
    actually exercised — which is precisely how a form field ends up
    decorative.
    """
    mod = _load_renderer()
    import xml.etree.ElementTree as ET

    def _render(relay_xml: str) -> str:
        root = ET.fromstring(
            "<Hound><general><interface>vlan0.77</interface>"
            "<snaplen>96</snaplen></general>"
            "<network><camera_ips>10.77.0.1</camera_ips>"
            "<lan_subnets>10.77.0.0/16</lan_subnets></network>"
            "<thresholds><silence_seconds>600.0</silence_seconds></thresholds>"
            "<uptime><enabled>1</enabled></uptime>"
            f"{relay_xml}</Hound>"
        )
        return mod.render(root, config_path=None)

    toml_text = _render(
        "<relay><mode>agent</mode><sensor_id>edge-box</sensor_id>"
        "<url>https://10.77.0.250:19443/ingest/v1</url>"
        "<key>agent-secret-abcdef</key>"
        "<tls_fingerprint>sha256:AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD:EE:FF:00:11:AA:BB:CC:DD:EE:FF:00:11</tls_fingerprint></relay>"
    )
    cfg = load_from_dict(tomllib.loads(toml_text))
    assert cfg.relay.mode == "agent", cfg.relay.mode
    assert cfg.relay.sensor_id == "edge-box", cfg.relay.sensor_id
    assert cfg.relay.url == "https://10.77.0.250:19443/ingest/v1", cfg.relay.url
    assert cfg.relay.key == "agent-secret-abcdef", "the shared secret must survive"
    assert len(cfg.relay.tls_fingerprint) == 1, (
        "the pin is the whole trust decision in agent mode; losing it in "
        "the renderer would leave the agent unable to connect at all"
    )

    # Off must emit no [relay] whatsoever, so a box that never touched the
    # feature renders the same file it rendered before relay existed.
    off = _render("<relay><mode>off</mode></relay>")
    assert "[relay]" not in off, "mode=off must not emit a [relay] table"
    load_from_dict(tomllib.loads(off))

    # Sensor-list parsing: the collector's authorisation list. A line that
    # cannot be parsed must be DROPPED, never guessed at — a half-read
    # secret authenticates nothing and the 401 gets blamed on the agent.
    parsed = mod._parse_sensors(
        "frigate = secret-one-abcdefgh\n"
        "# comment\n"
        "garage : secret-two-abcdefgh\n"
        "frigate = shadowing-duplicate-x\n"
        "no-separator-here\n"
        "   \n"
        "trailing = secret-three-abcdef  "
    )
    assert parsed == [
        ("frigate", "secret-one-abcdefgh"),
        ("garage", "secret-two-abcdefgh"),
        ("trailing", "secret-three-abcdef"),
    ], parsed

    collector = _render(
        "<relay><mode>collector</mode><listen_host>10.77.0.250</listen_host>"
        "<listen_port>19443</listen_port>"
        "<cert_file>/var/lib/hound/t.crt</cert_file>"
        "<key_file>/var/lib/hound/t.key</key_file>"
        "<sensors>a = one-secret-abcdef\nb = two-secret-abcdef</sensors></relay>"
    )
    ccfg = load_from_dict(tomllib.loads(collector))
    assert [(x.id, x.key) for x in ccfg.relay.sensors] == [
        ("a", "one-secret-abcdef"), ("b", "two-secret-abcdef")], ccfg.relay.sensors
    print("  relay: agent/collector/off all render and parse; sensor list "
          "drops malformed and duplicate entries")


def _check_csv_masks_accept_lists() -> None:
    """A CSVListField holds "a,b,c" — its Mask must accept that.

    Every one of these was anchored ^...$ around a SINGLE value, so the
    field accepted one entry and rejected two, showing a
    ValidationMessage that describes exactly what the operator had
    typed. Hit on a real firewall entering two LAN subnets; it only
    surfaced then because clearing Camera IPs left `lan_subnets` as the
    one field with more than a single value.

    The repetition group is correct whether OPNsense applies the mask
    per item or to the joined string, so this does not depend on which.
    """
    import re as _re
    import xml.etree.ElementTree as _ET

    model = (PLUGIN / "models/OPNsense/Hound/Hound.xml").read_text()
    csv_fields = _re.findall(
        r'<(\w+) type="CSVListField">(.*?)</\1>', model, _re.S)
    assert csv_fields, "no CSVListField entries found"

    for name, body in csv_fields:
        mm = _re.search(r"<Mask>/(.*)/u</Mask>", body)
        if not mm:
            continue
        rx = mm.group(1)
        assert "," in rx, (
            f"{name}: CSVListField stores a comma-separated list but its "
            f"Mask has no comma, so a second entry makes the whole value "
            f"fail and the field rejects input its own ValidationMessage "
            f"calls correct")

    def mask_for(field):
        m = _re.search(rf'<{field} type="CSVListField">(.*?)</{field}>',
                       model, _re.S)
        return _re.search(r"<Mask>/(.*)/u</Mask>", m.group(1)).group(1)

    # Concrete, including the exact values that failed on the firewall.
    cases = [
        ("lan_subnets", "88.255.0.0/16", True),
        ("lan_subnets", "88.255.0.0/16,117.111.0.0/16", True),
        ("lan_subnets", "88.255.0.0/16, 117.111.0.0/16", True),
        ("lan_subnets", "88.255.0.0/99", False),
        ("lan_subnets", "nonsense", False),
        ("camera_ips", "117.111.101.2", True),
        ("camera_ips", "117.111.101.2,117.111.102.2", True),
        ("camera_ips", "117.111.101.2,junk", False),
        ("camera_ips", "999.1.1.1", False),
    ]
    for field, value, want in cases:
        got = bool(_re.match(mask_for(field), value))
        assert got == want, (
            f"{field} mask {'rejected' if want else 'accepted'} "
            f"{value!r} and should not have")

    _ET.parse(PLUGIN / "models/OPNsense/Hound/Hound.xml")
    print(f"  csv masks: {len(csv_fields)} CSVListField(s) accept lists, "
          f"single values and still reject malformed entries")


def _check_tokenize_fields_say_how_to_use_them() -> None:
    """Every tokenizer field must tell the operator to press Enter.

    `style: tokenize` means the value only becomes a token on Enter.
    Paste two CIDRs on two lines and you get ONE invalid token, and the
    field rejects input that its own ValidationMessage describes as
    correct — "Enter CIDR ranges such as 192.168.0.0/16" while refusing
    exactly that. An operator hit this on a real firewall and had no
    way to tell the UI apart from a broken validator.

    Only `camera_ips` said it. Five fields did not, including
    `tls_fingerprint`, which takes a long pasted value and is the next
    field anyone wiring up a relay uses.
    """
    import re as _re

    form = (PLUGIN / "controllers/OPNsense/Hound/forms/general.xml").read_text()
    missing = []
    for block in _re.findall(r"<field>(.*?)</field>", form, _re.S):
        if "tokenize" not in block:
            continue
        fid = (_re.search(r"<id>(.*?)</id>", block) or [None, "?"])[1]
        helps = (_re.search(r"<help>(.*?)</help>", block, _re.S)
                 or [None, ""])[1]
        if "press enter" not in helps.lower():
            missing.append(fid)
    assert not missing, (
        f"tokenize field(s) {missing} never say the value must be "
        f"committed with Enter. Pasting a multi-line list into one "
        f"makes a single invalid token and the field then rejects "
        f"input its own help text calls correct")
    print("  tokenize fields: all say how to commit a value")


def _check_volt_renders_relayed_data() -> None:
    """The plugin view must render relayed sensors, not just local rows.

    On OPNsense the plugin page is NOT an iframe of `hound web` — the
    firewall serves its UI under `default-src 'self'`, so a frame on
    another port is cross-origin and blocked. That means this view is the
    only dashboard a collector's operator sees, and if it ignores
    `remote_uptime` the box that IS the collector cannot see the segment
    the relay exists to watch. It would look healthy while showing
    nothing.
    """
    volt = PLUGIN / "views/OPNsense/Hound/index.volt"
    text = volt.read_text()

    for key in ("remote_uptime", "remote_alerts", "remote_flows", "sensors"):
        assert key in text, (
            f"index.volt never reads d.{key}; `hound export` emits it and "
            f"the plugin dashboard is the only view a collector operator "
            f"has, so relayed data would be invisible on its own platform"
        )
    assert "c.sensor" in text, (
        "relayed rows must show which sensor reported them, or a local "
        "camera and a relayed one are indistinguishable"
    )
    assert "c.stale" in text, (
        "a stale sensor's availability must render n/a, not the figure it "
        "last claimed"
    )

    # The alerts table must line up too, now that it carries a Sensor
    # column. Relayed alerts were stored, notified, quota'd and pruned
    # but rendered by neither dashboard.
    ahead = text[text.index('id="tbl-alerts"'):]
    ahead = ahead[:ahead.index("</thead>")]
    a_head = ahead.count("<th>")
    abody = text[text.index("$.each(alerts"):]
    abody = abody[:abody.index('$("#tbl-alerts')]
    a_body = abody.count("'<td>")       # also matches the <code> cell
    assert a_head == a_body, (
        f"alerts table has {a_head} header cells but rows emit {a_body}"
    )
    assert f'colspan="{a_head}"' in text

    # Column counts must agree, or the table silently misaligns.
    head = text[text.index('id="tbl-uptime"'):]
    head = head[:head.index("</thead>")]
    n_head = head.count("<th>")
    body = text[text.index("$.each(cams"):]
    body = body[:body.index("$(\"#tbl-uptime")]
    n_body = body.count("'<td>")
    assert n_head == n_body, (
        f"uptime table has {n_head} header cells but rows emit {n_body} "
        f"cells — the columns would not line up"
    )
    assert f'colspan="{n_head}"' in text, (
        f"the empty-table placeholder must span all {n_head} columns"
    )
    # The flows table too.
    fhead = text[text.index('id="tbl-flows"'):]
    fhead = fhead[:fhead.index("</thead>")]
    f_head = fhead.count("<th>")
    # The flow table groups repeated conversations, so the row-emitting
    # loop iterates the grouped list, not the raw one.
    fbody = text[text.index("$.each(order"):]
    fbody = fbody[:fbody.index('$("#tbl-flows')]
    f_body = fbody.count("'<td>")
    assert f_head == f_body, (
        f"flows table has {f_head} header cells but rows emit {f_body}"
    )
    assert f'colspan="{f_head}"' in text

    # Merged lists must sort on OUR clock. `ts`/`last_seen` come from the
    # sensor, so sorting on them re-opens the pinning the server-side
    # ORDER BY ingested_at was changed to close.
    assert "ingested_at" in text, (
        "merged alert/flow lists must sort on ingested_at; sorting on the "
        "sensor-supplied ts lets one future-dated row pin itself to the "
        "top of the dashboard forever"
    )
    assert "num(y.ts) - num(x.ts)" not in text, (
        "a merged list still sorts on the sensor-supplied ts"
    )

    # Numerics interpolated into innerHTML must be coerced. This view
    # renders rows produced on another host now, and the spec names
    # outage_count/packets as the stored-XSS vector precisely because
    # validation alone is one layer. web.py has a num() helper; this
    # view must too.
    assert "function num(" in text, (
        "index.volt renders relayed rows but has no numeric coercion "
        "helper; web.py was hardened and this view was not"
    )
    import re
    raw = re.findall(r"'<td>' \+ ([a-z]\.[a-z_]+)", text)
    assert not raw, (
        f"raw field(s) interpolated into innerHTML: {raw}. Wrap numbers "
        f"in num() and strings in esc()."
    )
    print(f"  volt: renders relayed rows + sensor health; "
          f"{n_head} columns line up; numerics coerced")


def main() -> int:
    print("=== OPNsense field wiring ===")
    _check_inventories()
    _check_round_trip()
    _check_relay_agent_round_trip()
    _check_interface_is_resolved()
    _check_ui_endpoints_exist()
    _check_csv_masks_accept_lists()
    _check_tokenize_fields_say_how_to_use_them()
    _check_volt_renders_relayed_data()
    _check_enable_is_wired()
    print("\nOPNSENSE FIELD VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
