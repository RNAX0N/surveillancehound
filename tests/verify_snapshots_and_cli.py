"""End-to-end verification of: snapshot ring buffer, log rotation,
prune, baselines CLI, snapshots CLI, web JSON endpoints.

Uses the existing make_synthetic_camera_pcap (which already produces a
classic-pcap stream — required for snapshot raw-record capture). With
[snapshot].enabled = true, a `bulk_inbound` alert (HIGH) should produce
exactly one snapshot pcap on disk + one snapshots row.

We don't spin up the web server in a subprocess; we directly call the
request handler against an in-process server bound to a random port and
exercise every /api/* path. This keeps the test stdlib-only.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from surveillancehound.config import (  # noqa: E402
    AlertsCfg, BaselineCfg, CaptureCfg, HoundCfg, NetworkCfg,
    NotifyChannelCfg, SnapshotCfg, StoreCfg, ThresholdCfg, WebCfg,
)
from surveillancehound.daemon import Hound  # noqa: E402
from surveillancehound.notify import _maybe_rotate  # noqa: E402
from surveillancehound.pcap import read_packets  # noqa: E402
from surveillancehound.store import HoundStore, OutageRow  # noqa: E402
from surveillancehound.web import _Handler  # noqa: E402

import make_synthetic_camera_pcap as mk  # noqa: E402

from http.server import ThreadingHTTPServer  # noqa: E402


def _run_hound_with_snapshots(td: Path) -> tuple[HoundCfg, Path]:
    pcap_path = td / "synthetic.pcap"
    pcap_path.write_bytes(mk.build())
    db_path = td / "hound.sqlite"
    snap_dir = td / "snapshots"
    log_path = td / "alerts.log"

    cfg = HoundCfg(
        capture=CaptureCfg(pcap_file=str(pcap_path), snaplen=1500),
        network=NetworkCfg(camera_ips=[mk.CAMERA_IP]),
        thresholds=ThresholdCfg(),
        alerts=AlertsCfg(),
        store=StoreCfg(path=str(db_path)),
        notify=[
            NotifyChannelCfg(
                type="logfile", path=str(log_path), level="info",
                max_bytes=200, keep=3,  # tiny so we exercise rotation
            ),
        ],
        baseline=BaselineCfg(enabled=False),
        snapshot=SnapshotCfg(
            enabled=True, window_seconds=600.0, min_severity="medium",
            dir=str(snap_dir), snaplen=1500,
        ),
        web=WebCfg(),
    )
    hound = Hound(cfg)
    ok = hound.run()
    assert ok
    return cfg, snap_dir


def _check_snapshots(cfg: HoundCfg, snap_dir: Path) -> int:
    store = HoundStore(path=cfg.store.path)
    try:
        snaps = store.list_snapshots(limit=50)
    finally:
        store.close()
    assert snaps, "no snapshots saved"
    # at least one snapshot should exist on disk and be a readable pcap
    for s in snaps:
        path = Path(s.path)
        assert path.is_file(), path
        assert path.parent == snap_dir, (path, snap_dir)
        # parse it back — must be a valid classic pcap
        gen, stats = read_packets(path)
        n = sum(1 for _ in gen)
        assert n == s.packet_count, (s.path, n, s.packet_count)
    print(f"  snapshots: {len(snaps)} pcaps on disk, all parse cleanly")
    return len(snaps)


def _check_log_rotation(log_path: Path) -> None:
    # the bulk_inbound + several other alerts pushed past max_bytes=200, so
    # the rotated files .1, .2, .3 should exist (or .1 at minimum)
    rotated = [p for p in log_path.parent.glob(log_path.name + ".*")]
    assert rotated, f"no rotated log files alongside {log_path}"
    # also make sure rotation is bounded — never more than `keep` rotated files
    assert len(rotated) <= 3, len(rotated)
    print(f"  log rotation: {len(rotated)} rotated file(s) alongside live log")


def _check_prune(cfg: HoundCfg) -> None:
    store = HoundStore(path=cfg.store.path)
    try:
        before = len(store.recent_flows(limit=1000))
        # one closed + one OPEN outage, one ended + one RUNNING session.
        # Pruning must take the finished rows and leave the live ones — a
        # deleted open outage would strand the tracker's state.
        now = time.time()
        closed = store.open_outage(
            OutageRow(None, "10.9.9.1", now - 500, None, now - 600, "silence", None),
        )
        store.close_outage(closed, now - 400)
        live_outage = store.open_outage(
            OutageRow(None, "10.9.9.2", now - 100, None, now - 200, "silence", None),
        )
        ended = store.start_monitor_session(now - 500, "test0")
        store.end_monitor_session(ended, now - 400, True)
        store.start_monitor_session(now - 100, "test0")

        # prune everything (cutoff in the far future)
        deleted = store.prune(
            flows_older_than=time.time() + 1.0,
            alerts_older_than=time.time() + 1.0,
            outages_older_than=time.time() + 1.0,
            sessions_older_than=time.time() + 1.0,
        )
        assert deleted["flows"] == before, (deleted, before)
        assert deleted["alerts"] > 0, deleted
        assert deleted["outages"] == 1, deleted
        # >= 1 because the replay run earlier in this suite also recorded and
        # ended a session of its own; what matters is that only ENDED ones go
        assert deleted["monitor_sessions"] >= 1, deleted
        assert store.open_outage_for("10.9.9.2").id == live_outage
        assert store.current_monitor_session().ended_at is None
        # second prune is a no-op
        deleted2 = store.prune(flows_older_than=time.time() + 1.0)
        assert deleted2["flows"] == 0, deleted2
    finally:
        store.close()
    print(f"  prune: removed {deleted['flows']} flow rows + "
          f"{deleted['alerts']} alerts + {deleted['outages']} closed outage(s); "
          f"open outage and running session preserved")


def _check_uptime_cli(cfg_path: Path) -> None:
    env = {"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"}
    out = subprocess.run(
        [sys.executable, "-m", "surveillancehound.cli", "uptime", str(cfg_path)],
        capture_output=True, text=True, check=True, env=env,
    )
    assert "not from active probing" in out.stdout, out.stdout
    assert "avail" in out.stdout or "no cameras" in out.stdout, out.stdout
    out = subprocess.run(
        [sys.executable, "-m", "surveillancehound.cli",
         "uptime", str(cfg_path), "--outages", "--window", "3600"],
        capture_output=True, text=True, check=True, env=env,
    )
    assert "cause" in out.stdout or "no outages" in out.stdout, out.stdout
    print("  CLI: hound uptime (summary + --outages) renders and exits 0")


def _check_baselines_cli(cfg_path: Path) -> None:
    # baselines list — should report "no baselines yet"
    out = subprocess.run(
        [sys.executable, "-m", "surveillancehound.cli", "baselines", str(cfg_path)],
        capture_output=True, text=True, check=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
    )
    assert "no baselines yet" in out.stdout, out.stdout
    # reset-all (also reports zero deletions when there's nothing there)
    out = subprocess.run(
        [sys.executable, "-m", "surveillancehound.cli",
         "baselines", str(cfg_path), "--reset-all"],
        capture_output=True, text=True, check=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
    )
    assert "deleted 0" in out.stdout, out.stdout
    print("  CLI: hound baselines + --reset-all both behave")


def _check_snapshots_cli(cfg_path: Path) -> None:
    out = subprocess.run(
        [sys.executable, "-m", "surveillancehound.cli",
         "snapshots", str(cfg_path)],
        capture_output=True, text=True, check=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin"},
    )
    # header + at least one snapshot row
    assert "packets" in out.stdout, out.stdout
    print("  CLI: hound snapshots renders rows")


def _check_web(cfg: HoundCfg) -> None:
    _Handler.cfg = cfg
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{port}"
        # HTML page renders + contains the brand string
        with urllib.request.urlopen(base + "/") as resp:
            html = resp.read().decode()
        assert resp.status == 200
        assert "SurveillanceHound" in html, "HTML missing brand"
        assert "<style>" in html and "<script>" in html, "HTML missing CSS/JS"

        # Each API endpoint returns JSON of the expected shape
        for path, key in [
            ("/api/status", "alive"),
            ("/api/devices", "devices"),
            ("/api/alerts", "alerts"),
            ("/api/flows", "flows"),
            ("/api/baselines", "baselines"),
            ("/api/snapshots", "snapshots"),
            ("/api/uptime", "cameras"),
            ("/api/help", "intro"),
        ]:
            with urllib.request.urlopen(base + path) as resp:
                body = json.loads(resp.read())
            assert key in body, (path, body)

        # /api/uptime: the documented shape, and the honesty contract — the
        # evidence must always declare itself passive, because nothing here
        # probes anything
        with urllib.request.urlopen(base + "/api/uptime?window=3600") as resp:
            up = json.loads(resp.read())
        assert up["evidence"] == "passive", up.get("evidence")
        assert up["window_seconds"] == 3600.0, up["window_seconds"]
        assert isinstance(up["cameras"], list) and isinstance(up["outages"], list)
        mon = up["monitor"]
        for field in ("source", "running", "stalled", "last_flow_ts"):
            assert field in mon, (field, mon)
        if up["cameras"]:
            cam = up["cameras"][0]
            for field in (
                "ip", "role", "state", "last_seen", "current_downtime",
                "outage_count", "downtime_seconds", "monitored_seconds",
                "availability",
            ):
                assert field in cam, (field, cam)
            assert cam["state"] in ("up", "down", "never_seen"), cam["state"]
        # a non-numeric window is rejected rather than silently defaulted
        try:
            urllib.request.urlopen(base + "/api/uptime?window=soon")
            raise AssertionError("expected 400 on a non-numeric window")
        except urllib.error.HTTPError as e:
            assert e.code == 400, e.code
        print(f"  web: /api/uptime shape + passive evidence flag "
              f"({len(up['cameras'])} camera rows)")

        # the dashboard has to actually render the panel, not just serve the API
        assert "Camera uptime" in html, "uptime panel missing from the dashboard"
        assert "renderUptime" in html, "uptime renderer missing from the dashboard"
        assert "not from" in html and "active probing" in html, (
            "dashboard must state that liveness is passive inference"
        )

        # 404 for unknown
        try:
            urllib.request.urlopen(base + "/nope")
            raise AssertionError("expected 404 on /nope")
        except urllib.error.HTTPError as e:
            assert e.code == 404

        # download a snapshot pcap
        store = HoundStore(path=cfg.store.path)
        try:
            snaps = store.list_snapshots(limit=1)
        finally:
            store.close()
        if snaps:
            with urllib.request.urlopen(
                f"{base}/api/snapshots/{snaps[0].id}.pcap"
            ) as resp:
                pcap_bytes = resp.read()
            assert resp.headers["Content-Type"] == "application/vnd.tcpdump.pcap"
            assert pcap_bytes[:4] in (
                b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",
            ), pcap_bytes[:4]
            print(f"  web: served snapshot #{snaps[0].id} "
                  f"({len(pcap_bytes)} bytes)")
        print(f"  web: HTML + 7 JSON endpoints all return correctly "
              f"(:{port})")
    finally:
        server.shutdown()
        server.server_close()


def _check_web_https(cfg: HoundCfg, td: Path) -> None:
    """Mint a self-signed cert with openssl, run `serve()` with cert/key in
    cfg, and confirm an HTTPS GET returns the dashboard. Exercises the
    `ssl.SSLContext.wrap_socket` branch in web.serve()."""
    import shutil
    if not shutil.which("openssl"):
        print("  web HTTPS: skipped (openssl not on PATH)")
        return
    cert = td / "hound-web.crt"
    key = td / "hound-web.key"
    rc = subprocess.run(
        ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
         "-days", "1", "-keyout", str(key), "-out", str(cert),
         "-subj", "/CN=localhost"],
        capture_output=True,
    )
    assert rc.returncode == 0, rc.stderr.decode()
    import ssl
    import socket
    import dataclasses
    https_cfg = dataclasses.replace(
        cfg, web=dataclasses.replace(
            cfg.web, enabled=True, host="127.0.0.1", port=0,
            cert_file=str(cert), key_file=str(key),
        ),
    )
    # `serve()` blocks; we run it in a thread but it picks the port itself,
    # so we drive the SSL wrap path by hand to keep this test self-contained.
    from surveillancehound.web import _Handler
    _Handler.cfg = https_cfg
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(
            f"https://127.0.0.1:{port}/api/status", context=client_ctx,
        ) as resp:
            body = json.loads(resp.read())
        assert "alive" in body, body
        # Verify the listening socket is actually wrapped (raw connect → SSL handshake)
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            wrapped = client_ctx.wrap_socket(s, server_hostname="localhost")
            wrapped.close()
        finally:
            s.close()
        print(f"  web HTTPS: TLS handshake + JSON GET OK (:{port})")
    finally:
        server.shutdown()
        server.server_close()


def _check_web_cfg_validation() -> None:
    """[web] cert_file and key_file must be set together — XOR is rejected."""
    from surveillancehound.config import load_from_dict
    base = {
        "capture": {"pcap_file": "/tmp/nope.pcap"},
        "network": {"camera_ips": ["10.0.0.1"]},
    }
    # Both set → OK
    cfg = load_from_dict({**base, "web": {
        "enabled": True, "cert_file": "/a.crt", "key_file": "/a.key",
    }})
    assert cfg.web.scheme == "https", cfg.web.scheme
    # Neither set → OK, scheme = http
    cfg = load_from_dict({**base, "web": {"enabled": True}})
    assert cfg.web.scheme == "http", cfg.web.scheme
    # Only one set → ValueError
    for partial in ({"cert_file": "/a.crt"}, {"key_file": "/a.key"}):
        try:
            load_from_dict({**base, "web": {"enabled": True, **partial}})
        except ValueError as e:
            assert "cert_file and key_file" in str(e), e
        else:
            raise AssertionError(f"expected ValueError for partial {partial}")
    print("  web cfg: cert/key XOR rejected; scheme switches on both-set")


def _check_rotate_helper(td: Path) -> None:
    # standalone test for _maybe_rotate: 4 writes of 100 bytes should
    # produce path + path.1 + path.2 etc, never exceeding keep
    p = td / "rotate.log"
    for i in range(5):
        # write enough to exceed 100-byte threshold each time
        _maybe_rotate(p, max_bytes=100, keep=2)
        p.write_text("x" * 200)
    files = sorted(td.glob("rotate.log*"))
    # current + .1 + .2 = 3 files max
    assert len(files) <= 3, files
    print(f"  rotation helper: cap respected ({len(files)} files)")


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cfg, snap_dir = _run_hound_with_snapshots(root)
        cfg_path = root / "hound.toml"
        cfg_path.write_text(
            f"[capture]\npcap_file = {str(root/'synthetic.pcap')!r}\n"
            f"snaplen = 1500\n[network]\ncamera_ips = ['{mk.CAMERA_IP}']\n"
            f"[store]\npath = {str(root/'hound.sqlite')!r}\n"
            f"[[notify]]\ntype = 'stdout'\nlevel = 'info'\n"
            f"[snapshot]\nenabled = true\nwindow_seconds = 600.0\n"
            f"min_severity = 'medium'\ndir = {str(snap_dir)!r}\nsnaplen = 1500\n",
        )

        n_snaps = _check_snapshots(cfg, snap_dir)
        assert n_snaps >= 1
        _check_log_rotation(root / "alerts.log")
        _check_baselines_cli(cfg_path)
        _check_snapshots_cli(cfg_path)
        _check_uptime_cli(cfg_path)
        _check_web(cfg)
        _check_web_https(cfg, root)
        _check_web_cfg_validation()
        _check_prune(cfg)
        _check_rotate_helper(root)

        print("\nSNAPSHOTS + CLI + WEB VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
