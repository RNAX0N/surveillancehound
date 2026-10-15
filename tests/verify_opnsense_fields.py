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


def main() -> int:
    print("=== OPNsense field wiring ===")
    _check_inventories()
    _check_round_trip()
    _check_interface_is_resolved()
    _check_ui_endpoints_exist()
    _check_enable_is_wired()
    print("\nOPNSENSE FIELD VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
