"""Local web dashboard — pure-stdlib HTTP server, no external assets.

The dashboard is a separate process from the daemon: it reads the same
SQLite the daemon writes (WAL mode lets one writer and many readers
coexist). It is READ-ONLY — there are no write endpoints, no auth, no
session state. By default it binds to 127.0.0.1, so it is only reachable
from the host running it; expose it elsewhere by changing `[web].host`,
ideally behind your own reverse proxy + auth.

Every CSS/JS asset is embedded in the served HTML — zero external
requests, zero CDN fetches. The "futuristic" look is hand-rolled CSS
(dark base, neon cyan/magenta accents, monospace data, subtle glow).

Endpoints:
  GET /                  — the dashboard HTML (cache-controlled to no-store)
  GET /api/status        — daemon liveness + counters
  GET /api/devices       — observed devices, sorted by recency
  GET /api/uptime        — per-camera liveness + availability (passive).
                           ?window=<seconds>, ?outages=1 to include history
                           (omitted by default — the dashboard polls this
                           endpoint and does not render the outage list)
  GET /api/alerts        — recent alerts (limit param)
  GET /api/flows         — recent flows (limit, classification params)
  GET /api/baselines     — Welford buckets (camera param)
  GET /api/snapshots     — pcap snapshots saved on alert
  GET /api/snapshots/<id>.pcap — serves the pcap binary (if file still on disk)
  GET /api/help          — operator documentation (rendered in the UI)
"""

from __future__ import annotations

import json
import logging
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from surveillancehound.config import HoundCfg
from surveillancehound.store import HoundStore

log = logging.getLogger(__name__)


# Daemon-liveness heuristic: if any flow row has last_seen within this
# many seconds, consider the daemon alive. Approximation — the web server
# can't actually contact the daemon process. Tunable via [web] in future.
_LIVENESS_WINDOW_SECONDS = 600.0

# The daemon rewrites monitor_heartbeat every tick (5s), so a heartbeat
# older than this means the process is gone rather than merely idle. This
# server cannot contact the daemon, so the heartbeat is the only evidence.
_DAEMON_ALIVE_WINDOW_S = 30.0


def _json(handler: BaseHTTPRequestHandler, status: int, payload) -> None:
    body = json.dumps(payload, default=_jsonable).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _jsonable(obj):
    """Render dataclasses + Paths as plain dicts/strings."""
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    if isinstance(obj, Path):
        return str(obj)
    raise TypeError(f"can't json-serialize {type(obj).__name__}")


class _Handler(BaseHTTPRequestHandler):
    cfg: HoundCfg = None  # type: ignore[assignment]

    def log_message(self, fmt, *args):  # quiet the default access log
        log.debug("web: " + fmt, *args)

    def do_GET(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        params = {k: v[0] for k, v in parse_qs(url.query).items()}
        try:
            if url.path == "/":
                return self._serve_html()
            if url.path == "/api/status":
                return self._api_status()
            if url.path == "/api/devices":
                return self._api_devices()
            if url.path == "/api/uptime":
                return self._api_uptime(
                    params.get("window"),
                    params.get("outages", "") in ("1", "true", "yes"),
                )
            if url.path == "/api/alerts":
                return self._api_alerts(int(params.get("limit", 100)))
            if url.path == "/api/flows":
                return self._api_flows(
                    int(params.get("limit", 100)),
                    params.get("classification"),
                )
            if url.path == "/api/baselines":
                return self._api_baselines(params.get("camera"))
            if url.path == "/api/snapshots":
                return self._api_snapshots(int(params.get("limit", 100)))
            if url.path.startswith("/api/snapshots/") and url.path.endswith(".pcap"):
                snap_id = url.path[len("/api/snapshots/"):-len(".pcap")]
                return self._serve_snapshot(int(snap_id))
            if url.path == "/api/help":
                return self._api_help()
            _json(self, HTTPStatus.NOT_FOUND, {"error": "not found"})
        except Exception as e:  # noqa: BLE001
            log.exception("web: request failed")
            _json(self, HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})

    # --- handlers --------------------------------------------------------

    def _store(self) -> HoundStore:
        return HoundStore(path=self.cfg.store.path)

    def _serve_html(self) -> None:
        html = _render_dashboard(self.cfg)
        body = html.encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _api_status(self) -> None:
        store = self._store()
        try:
            recent = store.recent_flows(limit=1)
            last_flow_ts = recent[0].last_seen if recent else 0.0
            alive = (time.time() - last_flow_ts) < _LIVENESS_WINDOW_SECONDS
            alerts = store.list_alerts(limit=1)
            devices = store.list_devices()
            baselines = store.load_baselines()
            snapshots = store.list_snapshots(limit=1)
        finally:
            store.close()
        _json(self, HTTPStatus.OK, {
            "alive": alive,
            "last_flow_ts": last_flow_ts,
            "now": time.time(),
            "last_alert_ts": alerts[0].ts if alerts else 0.0,
            "device_count": len(devices),
            "camera_count": sum(1 for d in devices if d.role == "camera"),
            "nvr_count": sum(1 for d in devices if d.role == "nvr"),
            "baseline_bucket_count": len(baselines),
            "snapshot_count": len(snapshots),
            "baseline_enabled": self.cfg.baseline.enabled,
            "snapshot_enabled": self.cfg.snapshot.enabled,
            "poll_interval_seconds": self.cfg.web.poll_interval_seconds,
        })

    def _api_devices(self) -> None:
        store = self._store()
        try:
            rows = store.list_devices()
        finally:
            store.close()
        _json(self, HTTPStatus.OK, {"devices": [r.__dict__ for r in rows]})

    def _api_uptime(self, window: str | None, want_outages: bool = False) -> None:
        """Per-camera liveness + availability.

        `evidence` is always "passive" and clients are expected to surface
        that: a camera counts as up because packets from it were observed,
        not because anything probed it.

        `monitor.stalled` is a reader-side heuristic for the same reason
        `status.alive` is — this process cannot contact the daemon, it can
        only notice that no flow row has landed recently.
        """
        seconds = self.cfg.uptime.report_window_seconds
        if window:
            try:
                seconds = max(60.0, float(window))
            except ValueError:
                _json(self, HTTPStatus.BAD_REQUEST,
                      {"error": f"window must be a number, got {window!r}"})
                return
        now = time.time()
        store = self._store()
        try:
            cameras = store.uptime_report(seconds, now)
            session = store.current_monitor_session()
            # The daemon's heartbeat, not the flows table and not
            # devices.last_seen: flow rows are only written at eviction
            # (flow_ttl_seconds late) and device rows only tick for
            # camera/NVR roles, so both are stale by design precisely when
            # every camera is dead — the case this indicator is for.
            hb_packet, hb_updated = store.heartbeat()
            last_activity = hb_packet or store.latest_device_activity()
            outages = (
                store.list_outages(since=now - seconds, limit=200)
                if want_outages else []
            )
            # Relayed rows are kept separate all the way to the client, so
            # the Sensor column is always truthful about provenance.
            remote_cameras = store.remote_uptime_report(
                now, self.cfg.relay.sensor_timeout_seconds)
            sensors = [
                dict(x.__dict__,
                     reporting=(now - x.last_seen)
                     <= self.cfg.relay.sensor_timeout_seconds)
                for x in store.list_remote_sensors()
            ]
        finally:
            store.close()
        stall_window = self.cfg.uptime.capture_stall_seconds
        # Liveness comes from the heartbeat, NOT from whether the session is
        # open: a stall deliberately closes the session so blind time is
        # excluded from availability, which would otherwise make a running
        # but blind daemon report as stopped — exactly backwards, in exactly
        # the situation the operator needs the truth.
        running = hb_updated > 0.0 and (now - hb_updated) < _DAEMON_ALIVE_WINDOW_S
        stalled = bool(
            running and stall_window > 0 and last_activity > 0.0
            and (now - last_activity) > stall_window
        )
        _json(self, HTTPStatus.OK, {
            "window_seconds": seconds,
            "now": now,
            "evidence": "passive",
            "cameras": [dict(c.__dict__, sensor="local") for c in cameras],
            "remote_cameras": remote_cameras,
            "sensors": sensors,
            "outages": [o.__dict__ for o in outages],
            "monitor": {
                "source": session.source if session else "",
                "started_at": session.started_at if session else 0.0,
                "ended_at": session.ended_at if session else 0.0,
                "running": running,
                "stalled": stalled,
                "last_activity_ts": last_activity,
                "heartbeat_ts": hb_updated,
                "stall_window_seconds": stall_window,
            },
        })

    def _api_alerts(self, limit: int) -> None:
        store = self._store()
        try:
            rows = store.list_alerts(limit=limit)
        finally:
            store.close()
        _json(self, HTTPStatus.OK, {"alerts": [r.__dict__ for r in rows]})

    def _api_flows(self, limit: int, classification: str | None) -> None:
        store = self._store()
        try:
            rows = store.recent_flows(limit=limit, classification=classification)
        finally:
            store.close()
        _json(self, HTTPStatus.OK, {"flows": [r.__dict__ for r in rows]})

    def _api_baselines(self, camera: str | None) -> None:
        store = self._store()
        try:
            rows = store.load_baselines(camera_ip=camera)
        finally:
            store.close()
        _json(self, HTTPStatus.OK, {"baselines": [r.__dict__ for r in rows]})

    def _api_snapshots(self, limit: int) -> None:
        store = self._store()
        try:
            rows = store.list_snapshots(limit=limit)
        finally:
            store.close()
        _json(self, HTTPStatus.OK, {"snapshots": [r.__dict__ for r in rows]})

    def _serve_snapshot(self, snap_id: int) -> None:
        store = self._store()
        try:
            row = store.get_snapshot(snap_id)
        finally:
            store.close()
        if row is None:
            _json(self, HTTPStatus.NOT_FOUND, {"error": "no such snapshot"})
            return
        path = Path(row.path)
        if not path.is_file():
            _json(self, HTTPStatus.GONE, {
                "error": f"snapshot file missing on disk: {path}",
            })
            return
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
        self.send_header(
            "Content-Disposition",
            f'attachment; filename="alert-{row.alert_id}.pcap"',
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _api_help(self) -> None:
        _json(self, HTTPStatus.OK, _HELP_TEXT)


# Operator-facing documentation. The dashboard JS renders this in a modal
# so new users can learn what each alert kind / severity means without
# leaving the page. Keep it concise; defer to the README for depth.
_HELP_TEXT: dict = {
    "intro": (
        "SurveillanceHound watches your camera/NVR segment for activity the "
        "surveillance threat model cares about — headers only, no payload "
        "inspection, no video. This dashboard is read-only and refreshes "
        "every few seconds; everything you see is also queryable via the "
        "`hound` CLI."
    ),
    "severity": [
        {"level": "info", "meaning": "noise floor; routine traffic notes"},
        {"level": "low", "meaning": "worth knowing about; a new peer or device"},
        {"level": "medium", "meaning": "actionable; investigate when you have time"},
        {"level": "high", "meaning": "stop what you're doing and look"},
        {"level": "critical", "meaning": "reserved for catastrophic events"},
    ],
    "alert_kinds": [
        {"kind": "bulk_inbound",
         "what": "Large transfer TOWARD a camera — the model-weight / firmware push range. "
                 "Identify the source host and what was delivered."},
        {"kind": "control_channel_suspect",
         "what": "Camera holds a long-lived / chatty session with a public host on a "
                 "non-routine port. Cameras should not be holding C2-shaped sessions."},
        {"kind": "telemetry_offnet",
         "what": "Camera is talking to a public host that is NOT in the manufacturer "
                 "allowlist. Either add the host to the allowlist or investigate."},
        {"kind": "new_device",
         "what": "A previously-unseen IP has shown up on the segment. Medium severity "
                 "for camera/NVR roles, info otherwise."},
        {"kind": "new_peer",
         "what": "A known camera has begun contacting a brand-new endpoint. Low "
                 "severity — useful pattern signal, not a high-priority alert."},
        {"kind": "camera_offline",
         "what": "A known camera has been silent for `silence_seconds` (default 600). "
                 "Check that the camera is online and recording. Detection is "
                 "PASSIVE — a camera that is powered but no longer visible to this "
                 "sensor reads the same as one that is powered down."},
        {"kind": "camera_recovered",
         "what": "A camera that was offline is sending traffic again. Info-grade; "
                 "the outage duration is in the summary and the downtime is "
                 "recorded in the uptime history."},
        {"kind": "camera_never_seen",
         "what": "A camera listed in [network] has NEVER been observed, and the "
                 "startup grace period has elapsed. Either it was already powered "
                 "down before the monitor started, the configured IP is wrong, or "
                 "it sits on a segment this sensor cannot see."},
        {"kind": "capture_stalled",
         "what": "ZERO packets of any kind for `capture_stall_seconds` (default 120) "
                 "— the sensor itself is blind, so no other detection is running "
                 "either. Likely the capture process died, the interface went down, "
                 "or the mirror/SPAN port was reconfigured. Per-camera offline "
                 "alerts are suppressed while stalled, because a blind sensor "
                 "cannot tell which cameras are actually up."},
        {"kind": "behavioral_anomaly",
         "what": "When [baseline] is enabled: this camera's flow is >= z_threshold "
                 "standard deviations from its learned per-(weekday, hour) envelope. "
                 "The summary names the feature (bytes, packets, etc.) that drifted."},
    ],
    "tips": [
        "If a camera is supposed to talk to a vendor cloud, add the cloud's CIDR to "
        "[network].manufacturer_allowlist so legitimate telemetry stops firing alerts.",
        "Stop the daemon before running `hound baselines --reset` — the daemon holds "
        "Welford state in RAM and would re-upsert it on the next flush.",
        "Snapshots are stored at <store_dir>/snapshots/<alert_id>.pcap and can be "
        "downloaded from this dashboard. Open them in Wireshark.",
        "Live capture requires tcpdump and CAP_NET_RAW — run as root or "
        "`setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`.",
        "A `capture_stalled` alert means THIS sensor stopped seeing traffic. Fix "
        "the capture before chasing cameras — while stalled, per-camera offline "
        "alerts are suppressed and the blind window is excluded from availability.",
        "Availability shows n/a rather than 0% or 100% when the monitor was not "
        "running during the window. Uptime is only computed over time the sensor "
        "was actually watching, so a stopped daemon is never charged to a camera.",
    ],
}


def serve(cfg: HoundCfg) -> None:
    """Block forever serving the dashboard. SIGINT stops the loop.

    HTTPS is enabled when both `web.cert_file` and `web.key_file` point to
    PEM files. Required when the dashboard is embedded via iframe under an
    HTTPS parent (the iframe's protocol must match the parent's, or
    browsers block it as mixed content).
    """
    _Handler.cfg = cfg
    addr = (cfg.web.host, cfg.web.port)
    server = ThreadingHTTPServer(addr, _Handler)
    scheme = cfg.web.scheme
    if scheme == "https":
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cfg.web.cert_file, keyfile=cfg.web.key_file)
        # Local-only self-signed cert is the normal case here; don't force
        # client auth or hostname-verify the server-side context.
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    log.info("web: dashboard on %s://%s:%d", scheme, *addr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("web: stopping")
    finally:
        server.server_close()


# --- HTML / CSS / JS payload -------------------------------------------------


def _render_dashboard(cfg: HoundCfg) -> str:
    return _DASHBOARD_HTML.replace(
        "__POLL_INTERVAL_MS__", str(int(cfg.web.poll_interval_seconds * 1000)),
    )


_DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SurveillanceHound — NVR network monitor</title>
<style>
:root {
  --bg-0: #03060d;
  --bg-1: #07101c;
  --bg-2: #0c1a2b;
  --line: rgba(0, 212, 255, 0.16);
  --line-soft: rgba(0, 212, 255, 0.08);
  --fg: #d8eaff;
  --fg-dim: #7a93b0;
  --fg-mute: #4d6580;
  --accent: #00d4ff;
  --accent-2: #ff00aa;
  --ok: #2bf3a3;
  --warn: #ffaa00;
  --bad: #ff5a3c;
  --crit: #ff00aa;
  --mono: ui-monospace, "JetBrains Mono", "Fira Code", "Cascadia Mono",
          Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; min-height: 100%; }
body {
  background:
    radial-gradient(ellipse at 20% 0%, rgba(0,212,255,0.10), transparent 55%),
    radial-gradient(ellipse at 90% 100%, rgba(255,0,170,0.07), transparent 55%),
    linear-gradient(180deg, var(--bg-1) 0%, var(--bg-0) 100%);
  background-attachment: fixed;
  color: var(--fg);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  letter-spacing: 0.01em;
}
/* faint grid overlay — gives the dashboard a mission-control vibe */
body::before {
  content: "";
  position: fixed; inset: 0;
  background:
    linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px) 0 0/40px 40px,
    linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px) 0 0/40px 40px;
  pointer-events: none;
  z-index: 0;
}
header {
  position: relative; z-index: 1;
  display: flex; align-items: center; gap: 24px;
  padding: 18px 28px;
  border-bottom: 1px solid var(--line);
  background: rgba(3, 6, 13, 0.7);
  backdrop-filter: blur(8px);
}
.brand {
  display: flex; align-items: center; gap: 12px;
  font-family: var(--mono);
  font-size: 18px; font-weight: 600;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--fg);
}
.brand .logo {
  width: 28px; height: 28px;
  border: 1.5px solid var(--accent);
  border-radius: 4px;
  display: grid; place-items: center;
  font-size: 16px;
  color: var(--accent);
  box-shadow: 0 0 12px rgba(0,212,255,0.45), inset 0 0 12px rgba(0,212,255,0.15);
}
.brand .sub {
  color: var(--fg-mute);
  font-weight: 400; letter-spacing: 0.12em;
  margin-left: 6px;
}
.status-pill {
  margin-left: auto;
  display: flex; align-items: center; gap: 10px;
  padding: 6px 14px;
  border: 1px solid var(--line);
  background: rgba(7, 16, 28, 0.6);
  font-family: var(--mono); font-size: 12px;
  text-transform: uppercase; letter-spacing: 0.14em;
  color: var(--fg-dim);
}
.dot {
  width: 9px; height: 9px; border-radius: 50%;
  background: var(--fg-mute);
  box-shadow: 0 0 0 0 rgba(0,0,0,0);
  transition: background 200ms;
}
.dot.alive {
  background: var(--ok);
  box-shadow: 0 0 14px var(--ok);
  animation: pulse 2s infinite;
}
.dot.dead { background: var(--bad); box-shadow: 0 0 14px var(--bad); }
@keyframes pulse {
  0% { box-shadow: 0 0 0 0 rgba(43,243,163,0.55); }
  70% { box-shadow: 0 0 0 10px rgba(43,243,163,0); }
  100% { box-shadow: 0 0 0 0 rgba(43,243,163,0); }
}
.help-btn {
  border: 1px solid var(--line);
  background: rgba(7, 16, 28, 0.6);
  color: var(--fg-dim);
  font: 600 12px var(--mono);
  letter-spacing: 0.18em; text-transform: uppercase;
  padding: 6px 14px; cursor: pointer;
  transition: color 150ms, border-color 150ms, background 150ms;
}
.help-btn:hover {
  color: var(--accent); border-color: var(--accent);
  background: rgba(0,212,255,0.08);
}
main {
  position: relative; z-index: 1;
  padding: 24px 28px 80px;
  display: grid; gap: 24px;
}
.stats {
  display: grid; gap: 16px;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
}
.card {
  position: relative;
  border: 1px solid var(--line);
  background: linear-gradient(180deg, rgba(12,26,43,0.45), rgba(7,16,28,0.35));
  backdrop-filter: blur(6px);
  padding: 16px 18px;
}
.card::before {
  content: "";
  position: absolute; top: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg,
    transparent, rgba(0,212,255,0.5), transparent);
}
.stat .label {
  font: 600 10px var(--mono);
  text-transform: uppercase; letter-spacing: 0.22em;
  color: var(--fg-mute);
}
.stat .value {
  margin-top: 6px;
  font: 700 28px var(--mono);
  color: var(--fg);
  text-shadow: 0 0 10px rgba(0,212,255,0.35);
}
.stat .sub {
  margin-top: 2px;
  font: 500 11px var(--mono);
  color: var(--fg-dim);
}
.grid {
  display: grid; gap: 24px;
  grid-template-columns: 1.4fr 1fr 1.4fr;
}
@media (max-width: 1200px) {
  .grid { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 800px) {
  .grid { grid-template-columns: 1fr; }
}
.panel { padding: 0; overflow: hidden; }
.panel h2 {
  margin: 0;
  padding: 14px 18px;
  font: 600 12px var(--mono);
  text-transform: uppercase; letter-spacing: 0.22em;
  color: var(--fg-dim);
  border-bottom: 1px solid var(--line-soft);
  display: flex; align-items: center; gap: 10px;
}
.panel h2 .count {
  margin-left: auto;
  color: var(--fg-mute); font-weight: 500;
}
.panel .body {
  max-height: 540px;
  overflow-y: auto;
}
.row {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 10px 18px;
  border-bottom: 1px solid var(--line-soft);
  font-family: var(--mono);
  font-size: 12px;
}
.row:last-child { border-bottom: 0; }
.row:hover { background: rgba(0,212,255,0.04); }
.sev-bar { width: 3px; align-self: stretch; background: var(--fg-mute); }
.sev-info { background: var(--fg-mute); }
.sev-low { background: var(--accent); box-shadow: 0 0 8px var(--accent); }
.sev-medium { background: var(--warn); box-shadow: 0 0 8px var(--warn); }
.sev-high { background: var(--bad); box-shadow: 0 0 10px var(--bad); }
.sev-critical { background: var(--crit); box-shadow: 0 0 12px var(--crit); }
.row-main { flex: 1; min-width: 0; }
.row-top {
  display: flex; gap: 10px; align-items: center;
  color: var(--fg-dim);
  font-size: 11px;
}
.row-top .ts { color: var(--fg-mute); }
.row-top .kind {
  color: var(--accent);
  text-transform: uppercase; letter-spacing: 0.12em;
}
.row-summary {
  margin-top: 4px; color: var(--fg);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.row-detail {
  margin-top: 4px; color: var(--fg-dim);
  font-size: 11px; line-height: 1.4;
}
.badge {
  display: inline-block;
  padding: 1px 8px;
  font: 600 10px var(--mono);
  text-transform: uppercase; letter-spacing: 0.16em;
  border: 1px solid currentColor;
  color: var(--fg-dim);
}
.badge.camera { color: var(--accent); }
.badge.nvr { color: var(--accent-2); }
.badge.other { color: var(--fg-mute); }
.empty {
  padding: 30px 18px;
  text-align: center;
  color: var(--fg-mute); font-family: var(--mono); font-size: 12px;
  text-transform: uppercase; letter-spacing: 0.18em;
}
.device {
  display: flex; gap: 12px; align-items: center;
  padding: 10px 18px;
  border-bottom: 1px solid var(--line-soft);
  font-family: var(--mono); font-size: 12px;
}
.device .ip { color: var(--fg); flex: 1; }
.device .seen { color: var(--fg-mute); font-size: 11px; }
/* Uptime panel */
.monitor-line {
  display: flex; flex-wrap: wrap; gap: 8px 18px; align-items: center;
  padding: 11px 18px;
  border-bottom: 1px solid var(--line-soft);
  font-family: var(--mono); font-size: 11px; color: var(--fg-dim);
}
.monitor-line .mon-state {
  font-weight: 600; letter-spacing: 0.16em; text-transform: uppercase;
}
.monitor-line .mon-state.ok { color: var(--ok); }
.monitor-line .mon-state.bad { color: var(--bad); }
.uptime-grid {
  display: grid;
  grid-template-columns: auto auto 1fr auto auto auto;
  gap: 0 14px; align-items: center;
  padding: 4px 18px 12px;
  font-family: var(--mono); font-size: 12px;
}
.uptime-grid .head {
  font: 600 10px var(--mono);
  text-transform: uppercase; letter-spacing: 0.16em;
  color: var(--fg-mute);
  padding: 10px 0 8px;
  border-bottom: 1px solid var(--line-soft);
}
.uptime-grid .cell {
  padding: 9px 0;
  border-bottom: 1px solid var(--line-soft);
  white-space: nowrap;
}
.uptime-grid .cell.ip { color: var(--fg); }
.uptime-grid .cell.dim { color: var(--fg-mute); font-size: 11px; }
.uptime-grid .cell.num { text-align: right; }
.pill {
  display: inline-block; padding: 1px 8px;
  font: 600 10px var(--mono);
  text-transform: uppercase; letter-spacing: 0.16em;
  border: 1px solid currentColor;
}
.pill.up { color: var(--ok); }
.pill.down { color: var(--bad); }
.pill.never_seen { color: var(--warn); }
.pill.unknown { color: var(--fg-mute); }
.panel-note {
  padding: 10px 18px 14px;
  font-family: var(--mono); font-size: 10.5px; line-height: 1.5;
  color: var(--fg-mute);
  border-top: 1px solid var(--line-soft);
}
/* Narrow: drop the role and last-seen columns. The count of hidden cells
   must match the columns removed here, or every row shifts out of line. */
@media (max-width: 900px) {
  .uptime-grid { grid-template-columns: auto 1fr auto auto; }
  .uptime-grid .opt { display: none; }
}
.snapshot-link {
  color: var(--accent); text-decoration: none;
  border-bottom: 1px dashed var(--accent);
}
.snapshot-link:hover { color: #7fefff; }
/* Help modal */
.modal-bg {
  position: fixed; inset: 0;
  background: rgba(3, 6, 13, 0.82);
  backdrop-filter: blur(6px);
  display: none; place-items: center;
  z-index: 100;
}
.modal-bg.open { display: grid; }
.modal {
  width: min(820px, calc(100% - 40px));
  max-height: calc(100% - 80px);
  overflow-y: auto;
  border: 1px solid var(--accent);
  background: linear-gradient(180deg, rgba(12,26,43,0.95), rgba(3,6,13,0.95));
  padding: 30px 36px;
  position: relative;
  box-shadow: 0 0 60px rgba(0,212,255,0.25);
}
.modal h1 {
  margin: 0 0 6px;
  font: 600 16px var(--mono);
  text-transform: uppercase; letter-spacing: 0.22em;
  color: var(--accent);
}
.modal h2 {
  margin: 28px 0 10px;
  font: 600 11px var(--mono);
  text-transform: uppercase; letter-spacing: 0.22em;
  color: var(--fg-dim);
  border: 0; padding: 0;
}
.modal p { color: var(--fg); margin: 0 0 12px; }
.modal ul { margin: 0; padding: 0; list-style: none; }
.modal li {
  padding: 10px 0;
  border-bottom: 1px solid var(--line-soft);
  font-size: 13px;
  display: grid;
  grid-template-columns: 200px 1fr;
  gap: 16px;
}
.modal li:last-child { border-bottom: 0; }
.modal li .k {
  font-family: var(--mono); font-size: 12px;
  color: var(--accent);
  text-transform: uppercase; letter-spacing: 0.14em;
}
.modal li .v { color: var(--fg-dim); line-height: 1.5; }
.modal .close {
  position: absolute; top: 16px; right: 18px;
  background: transparent; border: 0;
  color: var(--fg-dim); cursor: pointer;
  font: 600 18px var(--mono);
}
.modal .close:hover { color: var(--accent); }
.tabs {
  display: flex; gap: 0;
  border-bottom: 1px solid var(--line-soft);
}
.tab {
  flex: 1;
  padding: 10px 14px;
  font: 600 11px var(--mono);
  text-transform: uppercase; letter-spacing: 0.18em;
  background: transparent; border: 0; color: var(--fg-mute);
  cursor: pointer;
  border-bottom: 2px solid transparent;
}
.tab.active {
  color: var(--accent);
  border-bottom-color: var(--accent);
  background: rgba(0,212,255,0.05);
}
.tab:hover:not(.active) { color: var(--fg-dim); }
.tab-body { display: none; }
.tab-body.active { display: block; }
footer {
  position: relative; z-index: 1;
  padding: 18px 28px;
  border-top: 1px solid var(--line);
  font: 500 11px var(--mono);
  color: var(--fg-mute);
  text-transform: uppercase; letter-spacing: 0.18em;
  text-align: center;
}
footer a { color: var(--fg-dim); text-decoration: none; }
footer a:hover { color: var(--accent); }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo">◇</div>
    <span>SurveillanceHound</span>
    <span class="sub">NVR&nbsp;Monitor</span>
  </div>
  <div class="status-pill"><div id="dot" class="dot"></div><span id="status-text">connecting…</span></div>
  <button class="help-btn" id="help-btn">? Help</button>
</header>

<main>
  <!-- top stat strip -->
  <div class="stats">
    <div class="card stat">
      <div class="label">Cameras</div>
      <div class="value" id="s-cameras">—</div>
      <div class="sub" id="s-nvrs">— NVR · — other</div>
    </div>
    <div class="card stat">
      <div class="label">Alerts (24h)</div>
      <div class="value" id="s-alerts">—</div>
      <div class="sub" id="s-alerts-sub">last: —</div>
    </div>
    <div class="card stat">
      <div class="label">Baseline buckets</div>
      <div class="value" id="s-baselines">—</div>
      <div class="sub" id="s-baselines-sub">—</div>
    </div>
    <div class="card stat">
      <div class="label">Snapshots</div>
      <div class="value" id="s-snapshots">—</div>
      <div class="sub" id="s-snapshots-sub">—</div>
    </div>
  </div>

  <!-- uptime: liveness + availability (passive inference) -->
  <div class="card panel">
    <h2>Camera uptime <span class="count" id="c-uptime"></span></h2>
    <div class="monitor-line" id="monitor-line"></div>
    <div id="uptime"></div>
    <div class="panel-note">
      Inferred from traffic observed on the monitored interface, not from
      active probing — a camera that is powered but no longer visible to this
      sensor reads the same as one that is off. Availability covers only time
      the monitor was actually running; it shows n/a rather than a figure
      invented from no observation.
    </div>
  </div>

  <!-- main 3-column grid -->
  <div class="grid">
    <div class="card panel">
      <h2>Alerts <span class="count" id="c-alerts"></span></h2>
      <div class="body" id="alerts"></div>
    </div>
    <div class="card panel">
      <h2>Devices <span class="count" id="c-devices"></span></h2>
      <div class="body" id="devices"></div>
    </div>
    <div class="card panel">
      <h2>Recent flows <span class="count" id="c-flows"></span></h2>
      <div class="body" id="flows"></div>
    </div>
  </div>

  <!-- secondary tabs -->
  <div class="card panel">
    <div class="tabs">
      <button class="tab active" data-tab="baselines-tab">Behavioral baselines</button>
      <button class="tab" data-tab="snapshots-tab">Forensic snapshots</button>
    </div>
    <div class="tab-body active" id="baselines-tab"></div>
    <div class="tab-body" id="snapshots-tab"></div>
  </div>
</main>

<footer>
  read-only dashboard · refresh every <span id="poll-rate"></span>s ·
  bind to non-localhost only behind your own reverse proxy + auth
</footer>

<div class="modal-bg" id="modal-bg">
  <div class="modal" role="dialog" aria-modal="true">
    <button class="close" id="modal-close" aria-label="close">×</button>
    <h1>Operator quickstart</h1>
    <p id="m-intro"></p>
    <h2>Severity levels</h2>
    <ul id="m-sev"></ul>
    <h2>Alert kinds</h2>
    <ul id="m-kinds"></ul>
    <h2>Tips</h2>
    <ul id="m-tips"></ul>
  </div>
</div>

<script>
"use strict";

const POLL_MS = __POLL_INTERVAL_MS__;

const $ = (id) => document.getElementById(id);
const escapeHTML = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;",
  '"': "&quot;", "'": "&#39;",
}[c]));
const fmtBytes = (n) => {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KiB";
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(2) + " MiB";
  return (n / 1024 / 1024 / 1024).toFixed(2) + " GiB";
};
const fmtAgo = (ts) => {
  if (!ts) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
};
const fmtTs = (ts) => {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleString();
};
const fmtHM = (ts) => {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
};

async function fetchJSON(path) {
  const r = await fetch(path, { cache: "no-store" });
  if (!r.ok) throw new Error(path + " → " + r.status);
  return await r.json();
}

async function refresh() {
  try {
    const [status, alerts, devices, flows, snapshots, baselines, uptime] =
      await Promise.all([
        fetchJSON("/api/status"),
        fetchJSON("/api/alerts?limit=100"),
        fetchJSON("/api/devices"),
        fetchJSON("/api/flows?limit=100"),
        fetchJSON("/api/snapshots?limit=50"),
        fetchJSON("/api/baselines"),
        fetchJSON("/api/uptime"),
      ]);
    renderStatus(status, alerts.alerts, snapshots.snapshots);
    renderUptime(uptime);
    renderAlerts(alerts.alerts);
    renderDevices(devices.devices);
    renderFlows(flows.flows);
    renderBaselines(baselines.baselines);
    renderSnapshots(snapshots.snapshots);
  } catch (e) {
    setStatus(false, "fetch error: " + e.message);
  }
}

function setStatus(alive, text) {
  const dot = $("dot");
  dot.classList.remove("alive", "dead");
  dot.classList.add(alive ? "alive" : "dead");
  $("status-text").textContent = text;
}

function renderStatus(s, alerts, snapshots) {
  setStatus(s.alive, s.alive ? "daemon live" : "no recent traffic");
  $("s-cameras").textContent = s.camera_count;
  $("s-nvrs").textContent = `${num(s.nvr_count)} NVR · ${num(s.device_count) - num(s.camera_count) - num(s.nvr_count)} other`;
  const dayAgo = Date.now() / 1000 - 86400;
  const last24 = alerts.filter(a => a.ts >= dayAgo).length;
  $("s-alerts").textContent = last24;
  $("s-alerts-sub").textContent = alerts[0]
    ? `last: ${fmtAgo(alerts[0].ts)}` : "no alerts yet";
  $("s-baselines").textContent = s.baseline_bucket_count;
  $("s-baselines-sub").textContent = s.baseline_enabled
    ? "engine: enabled" : "engine: disabled";
  $("s-snapshots").textContent = s.snapshot_count;
  $("s-snapshots-sub").textContent = s.snapshot_enabled
    ? (snapshots[0] ? `last: ${fmtAgo(snapshots[0].created_at)}` : "engine: enabled")
    : "engine: disabled";
}

/* Coerce anything interpolated as a number to an actual number before it
   reaches innerHTML. These columns come from INTEGER/REAL SQLite columns
   today, but SQLite is dynamically typed and relayed rows originate on
   another host — a string here would be markup in the operator's browser. */
const num = (v) => { const n = Number(v); return Number.isFinite(n) ? n : 0; };

const fmtDur = (s) => {
  s = Math.max(0, Math.floor(s || 0));
  if (!s) return "—";
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m " + (s % 60) + "s";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86400) + "d " + Math.floor((s % 86400) / 3600) + "h";
};

function renderUptime(u) {
  const m = u.monitor;
  // The monitor's own health comes first: if the sensor is blind, every
  // per-camera figure below it is stale, and saying so beats a green row.
  let mon = "";
  if (!m.source) {
    mon = '<span class="mon-state bad">no session</span>'
        + '<span>the daemon has not run yet</span>';
  } else if (m.stalled) {
    mon = '<span class="mon-state bad">capture stalled</span>'
        + `<span>source ${escapeHTML(m.source)}</span>`
        + `<span>last packet ${m.last_activity_ts ? fmtAgo(m.last_activity_ts) : "never"}</span>`
        + '<span>per-camera offline alerts suppressed</span>';
  } else if (m.running) {
    mon = '<span class="mon-state ok">watching</span>'
        + `<span>source ${escapeHTML(m.source)}</span>`
        + `<span>since ${fmtTs(m.started_at)}</span>`
        + `<span>last packet ${m.last_activity_ts ? fmtAgo(m.last_activity_ts) : "never"}</span>`;
  } else {
    // "not running", not "stopped": the daemon may have crashed rather
    // than been stopped, and the heartbeat cannot tell us which
    mon = '<span class="mon-state bad">not running</span>'
        + `<span>source ${escapeHTML(m.source)}</span>`
        + `<span>last heartbeat ${m.heartbeat_ts ? fmtAgo(m.heartbeat_ts) : "never"}</span>`;
  }
  mon += `<span>window ${fmtDur(u.window_seconds)}</span>`;
  (u.sensors || []).forEach(sx => {
    const cls = sx.reporting ? "ok" : "bad";
    const label = sx.reporting ? "reporting" : "NOT REPORTING";
    mon += `<span class="mon-state ${cls}">${escapeHTML(sx.sensor_id)}: ${label}</span>`;
  });
  $("monitor-line").innerHTML = mon;

  // local rows first, then each relay sensor's. They are kept distinct
  // rather than merged by address: the NVR is visible to both sensors and
  // their availability is computed over different monitored windows, so
  // collapsing them would invent a number neither sensor reported.
  const cams = (u.cameras || []).concat(u.remote_cameras || []);
  const down = cams.filter(c => c.state !== "up").length;
  $("c-uptime").textContent = down
    ? `${down} of ${cams.length} not up` : `${cams.length} up`;
  if (!cams.length) {
    $("uptime").innerHTML =
      '<div class="empty">no cameras known — check [network] in the config</div>';
    return;
  }
  // The two `opt` cells are dropped together with their columns at the
  // narrow breakpoint; keep the counts in step or rows shift out of line.
  const head = ['state', 'ip', 'sensor', 'last seen', 'down for', 'avail']
    .map((h, i) => `<div class="head${i === 2 || i === 3 ? ' opt' : ''}">${h}</div>`)
    .join("");
  $("uptime").innerHTML = '<div class="uptime-grid">' + head + cams.map(c => `
    <div class="cell"><span class="pill ${escapeHTML(c.state)}">${escapeHTML(c.state.replace("_", " "))}</span></div>
    <div class="cell ip">${escapeHTML(c.ip)}</div>
    <div class="cell dim opt">${escapeHTML(c.sensor || c.sensor_id || "local")}${num(c.outage_count) ? " · " + num(c.outage_count) + " outage" + (num(c.outage_count) === 1 ? "" : "s") : ""}</div>
    <div class="cell dim opt">${c.last_seen ? fmtAgo(c.last_seen) : "never"}</div>
    <div class="cell num">${fmtDur(c.current_downtime)}</div>
    <div class="cell num">${(c.stale || c.availability === null) ? "n/a" : (num(c.availability) * 100).toFixed(2) + "%"}</div>
  `).join("") + '</div>';
}

function renderAlerts(alerts) {
  $("c-alerts").textContent = alerts.length + " shown";
  if (!alerts.length) {
    $("alerts").innerHTML = '<div class="empty">no alerts yet</div>';
    return;
  }
  $("alerts").innerHTML = alerts.map(a => `
    <div class="row">
      <div class="sev-bar sev-${escapeHTML(a.severity)}"></div>
      <div class="row-main">
        <div class="row-top">
          <span class="ts">${fmtHM(a.ts)}</span>
          <span class="kind">${escapeHTML(a.kind)}</span>
          <span style="color:var(--fg-mute)">${escapeHTML(a.device_ip)}</span>
        </div>
        <div class="row-summary">${escapeHTML(a.summary)}</div>
        <div class="row-detail">${escapeHTML(a.detail)}</div>
      </div>
    </div>
  `).join("");
}

function renderDevices(devices) {
  $("c-devices").textContent = devices.length + " seen";
  if (!devices.length) {
    $("devices").innerHTML = '<div class="empty">no devices observed yet</div>';
    return;
  }
  $("devices").innerHTML = devices.map(d => `
    <div class="device">
      <span class="badge ${escapeHTML(d.role)}">${escapeHTML(d.role)}</span>
      <span class="ip">${escapeHTML(d.ip)}</span>
      <span class="seen">${fmtAgo(d.last_seen)}</span>
    </div>
  `).join("");
}

function renderFlows(flows) {
  $("c-flows").textContent = flows.length + " shown";
  if (!flows.length) {
    $("flows").innerHTML = '<div class="empty">no flows yet</div>';
    return;
  }
  $("flows").innerHTML = flows.map(f => `
    <div class="row">
      <div class="sev-bar sev-info"></div>
      <div class="row-main">
        <div class="row-top">
          <span class="ts">${fmtHM(f.last_seen)}</span>
          <span class="kind">${escapeHTML(f.classification)}</span>
        </div>
        <div class="row-summary">
          ${escapeHTML(f.src_ip)}:${escapeHTML(f.src_port ?? "")}
          → ${escapeHTML(f.dst_ip)}:${escapeHTML(f.dst_port ?? "")}
          <span style="color:var(--fg-mute)">[${escapeHTML(f.proto)}]</span>
        </div>
        <div class="row-detail">
          ${num(f.packets)} packets · ${fmtBytes(num(f.bytes))}
          ${num(f.bytes_to_camera) ? "· →cam " + fmtBytes(num(f.bytes_to_camera)) : ""}
          ${num(f.bytes_from_camera) ? "· cam→ " + fmtBytes(num(f.bytes_from_camera)) : ""}
        </div>
      </div>
    </div>
  `).join("");
}

const WEEKDAYS = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];

function renderBaselines(baselines) {
  if (!baselines.length) {
    $("baselines-tab").innerHTML = `
      <div class="empty">
        baseliner is off (or no buckets warmed yet) —
        enable [baseline] in your hound.toml to turn on per-camera anomaly detection
      </div>`;
    return;
  }
  // group by (camera, weekday, hour)
  const groups = new Map();
  for (const b of baselines) {
    const k = `${b.camera_ip}|${b.weekday}|${b.hour}`;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(b);
  }
  const parts = [];
  for (const [k, list] of groups) {
    const [ip, wd, h] = k.split("|");
    parts.push(`<div class="row"><div class="sev-bar sev-low"></div>
      <div class="row-main">
        <div class="row-top">
          <span class="kind">${escapeHTML(ip)}</span>
          <span class="ts">${WEEKDAYS[wd]} ${String(h).padStart(2,"0")}:00</span>
        </div>
        <div class="row-detail">
          ${list.map(b => {
            const std = b.n >= 2 ? Math.sqrt(b.m2 / (b.n - 1)) : 0;
            return `<span style="margin-right:18px">
              <span style="color:var(--accent)">${escapeHTML(b.feature)}</span>
              n=${num(b.n)} μ=${num(b.mean).toFixed(1)} σ=${num(std).toFixed(1)}
            </span>`;
          }).join("")}
        </div>
      </div></div>`);
  }
  $("baselines-tab").innerHTML = parts.join("");
}

function renderSnapshots(snaps) {
  if (!snaps.length) {
    $("snapshots-tab").innerHTML = `
      <div class="empty">
        no snapshots yet — enable [snapshot] to capture pcaps of the
        traffic window around each alert
      </div>`;
    return;
  }
  $("snapshots-tab").innerHTML = snaps.map(s => `
    <div class="row">
      <div class="sev-bar sev-medium"></div>
      <div class="row-main">
        <div class="row-top">
          <span class="ts">${fmtTs(s.created_at)}</span>
          <span class="kind">alert #${num(s.alert_id)}</span>
          <span style="color:var(--fg-mute)">${escapeHTML(s.camera_ip)}</span>
        </div>
        <div class="row-summary">
          ${num(s.packet_count)} packets · ${fmtBytes(num(s.byte_count))} ·
          <a class="snapshot-link" href="/api/snapshots/${num(s.id)}.pcap">
            download .pcap
          </a>
        </div>
        <div class="row-detail">${escapeHTML(s.path)}</div>
      </div>
    </div>
  `).join("");
}

// tabs
document.querySelectorAll(".tab").forEach(t => {
  t.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".tab-body").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    $(t.dataset.tab).classList.add("active");
  });
});

// help modal
async function loadHelp() {
  const h = await fetchJSON("/api/help");
  $("m-intro").textContent = h.intro;
  $("m-sev").innerHTML = h.severity.map(s => `
    <li><div class="k">${escapeHTML(s.level)}</div>
        <div class="v">${escapeHTML(s.meaning)}</div></li>
  `).join("");
  $("m-kinds").innerHTML = h.alert_kinds.map(k => `
    <li><div class="k">${escapeHTML(k.kind)}</div>
        <div class="v">${escapeHTML(k.what)}</div></li>
  `).join("");
  $("m-tips").innerHTML = h.tips.map(t => `
    <li><div class="k">→</div><div class="v">${escapeHTML(t)}</div></li>
  `).join("");
}
$("help-btn").addEventListener("click", () => $("modal-bg").classList.add("open"));
$("modal-close").addEventListener("click",
  () => $("modal-bg").classList.remove("open"));
$("modal-bg").addEventListener("click", (e) => {
  if (e.target.id === "modal-bg") $("modal-bg").classList.remove("open");
});

// first-time auto-open
if (!localStorage.getItem("hound-seen-help")) {
  $("modal-bg").classList.add("open");
  localStorage.setItem("hound-seen-help", "1");
}

$("poll-rate").textContent = (POLL_MS / 1000).toFixed(1);
loadHelp().catch(() => {});
refresh();
setInterval(refresh, POLL_MS);
</script>
</body>
</html>
"""
