"""Alert generation + de-duplication.

Take in classified flows, learned-device events, and silence events; emit Alert
objects worthy of a notification. Alerts that repeat within the
`dedup_window_seconds` window are not re-notified — the operator gets one
notification per ongoing event, not one per packet.

The dedup key combines the event kind and the device(s) involved, so the same
flagged conversation does not re-alert every TTL flush; but a *new* off-network
host the camera contacts produces a fresh alert (different dedup key).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime

from surveillancehound.baseline import Anomaly
from surveillancehound.classify import FlowClassification
from surveillancehound.config import AlertsCfg
from surveillancehound.store import HoundStore

# kinds (event-types). Per-flow classifications above that are info/normal map
# to no alert; the rest map to one of these kinds.
KIND_BULK_INBOUND = "bulk_inbound"
KIND_CONTROL_CHANNEL = "control_channel_suspect"
KIND_TELEMETRY_OFFNET = "telemetry_offnet"
KIND_CAMERA_TO_CAMERA = "camera_to_camera"
# Broadcast / multicast from a camera. Its own kind at INFO because it
# cannot leave the segment: it used to land in telemetry_offnet at
# medium, where one camera's 30-minute beacon produced forty unactionable
# medium alerts a day and taught the operator to ignore that severity.
KIND_BROADCAST_BEACON = "broadcast_beacon"
KIND_NEW_DEVICE = "new_device"
KIND_NEW_PEER = "new_peer"
KIND_CAMERA_OFFLINE = "camera_offline"
KIND_CAMERA_RECOVERED = "camera_recovered"
KIND_CAMERA_NEVER_SEEN = "camera_never_seen"
KIND_CAPTURE_STALLED = "capture_stalled"
KIND_BEHAVIORAL_ANOMALY = "behavioral_anomaly"
KIND_SENSOR_OFFLINE = "sensor_offline"
KIND_SENSOR_RECOVERED = "sensor_recovered"

# Appended to every liveness alert. Detection is passive — a camera that is
# powered but no longer visible to this sensor is indistinguishable from one
# that is powered down, and the operator must never be told otherwise.
_PASSIVE_CAVEAT = (
    "Liveness is inferred from traffic observed on the monitored interface, "
    "not from active probing — a camera that is powered but no longer "
    "visible to this sensor (moved VLAN, mirror/SPAN port reconfigured) "
    "looks identical to one that is powered down."
)


_REPORTABLE_FLOW = {
    "bulk_inbound": (KIND_BULK_INBOUND, "high"),
    "control_channel_suspect": (KIND_CONTROL_CHANNEL, "medium"),
    "telemetry_offnet": (KIND_TELEMETRY_OFFNET, "medium"),
    "camera_to_camera": (KIND_CAMERA_TO_CAMERA, "low"),
    "broadcast_beacon": (KIND_BROADCAST_BEACON, "info"),
}


def _stamp(ts: float) -> str:
    """Human-readable timestamp; 0.0 means the device was never observed."""
    if ts <= 0.0:
        return "never"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _dur(seconds: float) -> str:
    """Compact duration — '3d 4h', '12m 30s'. Alert text, not log text."""
    s = int(max(0.0, seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    if s < 86400:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{s // 86400}d {(s % 86400) // 3600}h"


@dataclass
class Alert:
    ts: float
    device_ip: str
    kind: str
    severity: str  # info | low | medium | high | critical
    summary: str
    detail: str
    dedup_key: str
    # Which sensor observed this. "local" for anything this daemon saw
    # itself; a relay sensor id for anything that arrived over the wire.
    # Without it a relayed alert is byte-identical to a local one in every
    # notification channel, and an operator cannot tell which segment a
    # camera_offline came from.
    sensor: str = "local"

    def as_dict(self) -> dict:
        return {
            "ts": self.ts, "device_ip": self.device_ip, "kind": self.kind,
            "severity": self.severity, "summary": self.summary,
            "detail": self.detail, "dedup_key": self.dedup_key,
            "sensor": self.sensor,
        }


class AlertEngine:
    """Decides which classifications / events become Alerts. Handles dedup."""

    def __init__(
        self, *, cfg: AlertsCfg, store: HoundStore,
        recovery_alerts: bool = True,
    ) -> None:
        self.cfg = cfg
        self.store = store
        self.recovery_alerts = recovery_alerts

    # ----- liveness transitions -> alert -----

    def from_transition(self, tr, now: float) -> Alert | None:
        """Turn an `uptime.Transition` into an Alert, or None.

        Dedup keys for down/up include the outage id, so each distinct
        outage notifies exactly once while repeated ticks inside one outage
        stay quiet. With a plain per-camera key, a camera that flapped
        down -> up -> down inside `dedup_window_seconds` had its second
        outage silently swallowed.
        """
        if tr.kind == "stall_cleared":
            return None  # logged by the daemon; not worth waking anyone
        if tr.kind == "up" and not self.recovery_alerts:
            return None

        what = "NVR" if tr.role == "nvr" else "camera"
        if tr.kind == "down":
            return self._mk(
                f"camera_offline:{tr.camera_ip}:{tr.outage_id}", now,
                device_ip=tr.camera_ip, kind=KIND_CAMERA_OFFLINE,
                severity="medium",
                summary=(
                    f"{what} {tr.camera_ip} has been silent for "
                    f"{tr.duration:.0f}s — possibly offline."
                ),
                detail=(
                    f"No traffic involving {tr.camera_ip} has been observed "
                    f"for {tr.duration:.0f} seconds (last seen "
                    f"{_stamp(tr.last_seen_before)}). Check that the {what} "
                    f"is powered, cabled, and still recording. "
                    f"{_PASSIVE_CAVEAT}"
                ),
            )
        if tr.kind == "up":
            # A camera appearing for the first time has not "come back" —
            # saying so would misdescribe a camera that was never there.
            first_time = tr.cause == "never_seen"
            summary = (
                f"configured {what} {tr.camera_ip} has appeared for the "
                f"first time, {_dur(tr.duration)} after the monitor started."
                if first_time else
                f"{what} {tr.camera_ip} is back after "
                f"{_dur(tr.duration)} of silence."
            )
            detail = (
                f"{tr.camera_ip} was configured but had never been observed; "
                f"traffic from it has now been seen, "
                f"{_dur(tr.duration)} ({tr.duration:.0f}s) after startup. "
                if first_time else
                f"Traffic from {tr.camera_ip} resumed after "
                f"{_dur(tr.duration)} ({tr.duration:.0f}s) with no "
                f"observed activity. "
            ) + f"The outage is recorded in the uptime history. {_PASSIVE_CAVEAT}"
            return self._mk(
                f"camera_recovered:{tr.camera_ip}:{tr.outage_id}", now,
                device_ip=tr.camera_ip, kind=KIND_CAMERA_RECOVERED,
                severity="info", summary=summary, detail=detail,
            )
        if tr.kind == "never_seen":
            return self._mk(
                f"camera_never_seen:{tr.camera_ip}", now,
                device_ip=tr.camera_ip, kind=KIND_CAMERA_NEVER_SEEN,
                severity="medium",
                summary=(
                    f"configured {what} {tr.camera_ip} has never been "
                    f"observed on the segment."
                ),
                detail=(
                    f"{tr.camera_ip} is listed in [network] but no traffic "
                    f"from it has been seen in the {tr.duration:.0f}s since "
                    f"the monitor started. Either it is powered down / "
                    f"disconnected, it sits on a segment this sensor cannot "
                    f"see, or the configured address is wrong. "
                    f"{_PASSIVE_CAVEAT}"
                ),
            )
        if tr.kind == "stalled":
            return self._mk(
                "capture_stalled", now,
                device_ip="", kind=KIND_CAPTURE_STALLED, severity="high",
                summary=(
                    f"no packets captured for {tr.duration:.0f}s — the "
                    f"monitor is blind."
                ),
                detail=(
                    f"Zero packets of any kind have been captured for "
                    f"{tr.duration:.0f} seconds. Likely causes: the capture "
                    f"process died, the monitored interface went down, or "
                    f"the mirror/SPAN port was reconfigured. Per-camera "
                    f"offline alerts are suppressed while stalled, because "
                    f"a blind sensor cannot tell which cameras are up — "
                    f"fix the capture first, then re-check the cameras."
                ),
            )
        return None

    def sensor_offline(self, sensor_id: str, silent_for: float,
                       now: float, *, since: float | None = None) -> Alert | None:
        """A relay agent has stopped reporting.

        This is not a camera alert and must not be mistaken for one. The
        collector cannot see that segment itself — that is the entire
        reason the agent exists — so when the agent goes quiet the
        collector knows nothing about those cameras at all. Their rows go
        to `unknown`, which is honest but silent, and silence is only
        visible to someone already looking at the dashboard.

        It is also the first thing an intruder on the camera segment
        would do, so it is treated as high severity rather than as
        routine housekeeping.
        """
        return self._mk(
            # `since` is the incident anchor — the last time this sensor
            # reported — and the caller already holds it. Without it in
            # the key, a sensor that went down -> up -> down inside
            # `dedup_window_seconds` had its SECOND outage swallowed, and
            # a flapping relay link is exactly when you want to hear
            # about it twice. The camera path fixed this with the outage
            # id; this is the same fix with the anchor the daemon has.
            f"sensor_offline:{sensor_id}"
            + (f":{int(since)}" if since is not None else ""), now,
            device_ip="", kind=KIND_SENSOR_OFFLINE, severity="high",
            summary=(
                f"relay sensor {sensor_id!r} has not reported for "
                f"{silent_for:.0f}s."
            ),
            detail=(
                f"No batch has arrived from sensor {sensor_id!r} in "
                f"{silent_for:.0f} seconds. Everything it watches is now "
                f"UNMONITORED, and its cameras are reported as unknown "
                f"rather than up — their last known state is no longer "
                f"evidence of anything. Causes range from the agent host "
                f"being down or the link failing, to someone on that "
                f"segment stopping the agent. Check the agent host before "
                f"assuming the cameras are fine."
            ),
        )

    def sensor_recovered(self, sensor_id: str, down_for: float,
                         now: float) -> Alert | None:
        return self._mk(
            f"sensor_recovered:{sensor_id}", now,
            device_ip="", kind=KIND_SENSOR_RECOVERED, severity="info",
            summary=(
                f"relay sensor {sensor_id!r} is reporting again after "
                f"{down_for:.0f}s."
            ),
            detail=(
                f"Batches from {sensor_id!r} have resumed. Its segment was "
                f"unmonitored for {down_for:.0f} seconds; that gap is "
                f"excluded from availability rather than counted as uptime."
            ),
        )

    def _mk(
        self, dedup_key: str, now: float, *, device_ip: str, kind: str,
        severity: str, summary: str, detail: str,
    ) -> Alert | None:
        if self._suppressed(dedup_key, now):
            return None
        return Alert(
            ts=now, device_ip=device_ip, kind=kind, severity=severity,
            summary=summary, detail=detail, dedup_key=dedup_key,
        )

    # ----- flow -> alert -----

    def from_flow(self, fc: FlowClassification, now: float) -> Alert | None:
        mapped = _REPORTABLE_FLOW.get(fc.classification)
        if mapped is None:
            return None
        kind, severity = mapped
        dedup_key = f"{kind}:{fc.src_ip}->{fc.dst_ip}:{fc.dst_port}"
        if self._suppressed(dedup_key, now):
            return None
        summary = (
            f"{kind}: {fc.src_ip}:{fc.src_port} -> {fc.dst_ip}:{fc.dst_port}"
        )
        return Alert(
            ts=now, device_ip=fc.src_ip, kind=kind, severity=severity,
            summary=summary, detail=fc.detail, dedup_key=dedup_key,
        )

    # ----- device events -> alert -----

    def new_device(self, ip: str, role: str, now: float) -> Alert | None:
        dedup_key = f"new_device:{ip}"
        if self._suppressed(dedup_key, now):
            return None
        # a brand-new device on the camera segment is medium; everything else
        # is info-grade (LAN devices come and go in normal life)
        severity = "medium" if role in ("camera", "nvr") else "info"
        summary = f"new device on the segment: {ip} (role={role})"
        return Alert(
            ts=now, device_ip=ip, kind=KIND_NEW_DEVICE, severity=severity,
            summary=summary,
            detail=f"this is the first time {ip} has been seen by the daemon.",
            dedup_key=dedup_key,
        )

    def new_peer(self, camera_ip: str, peer_ip: str, now: float) -> Alert | None:
        dedup_key = f"new_peer:{camera_ip}->{peer_ip}"
        if self._suppressed(dedup_key, now):
            return None
        return Alert(
            ts=now, device_ip=camera_ip, kind=KIND_NEW_PEER, severity="low",
            summary=f"camera {camera_ip} contacted a new peer: {peer_ip}",
            detail=(
                f"the camera {camera_ip} began communicating with {peer_ip} for "
                "the first time."
            ),
            dedup_key=dedup_key,
        )

    def behavioral_anomaly(self, anom: Anomaly, now: float) -> Alert | None:
        """A camera-flow is outside its learned per-bucket baseline.

        Two flavors of anomaly come through here:
          * Welford anomalies (anom.model == "welford") — one feature
            crossed a σ threshold. anom.z is a real standard-deviation
            count; mean/std are populated.
          * HS-Forest anomalies (anom.model == "hstree") — joint shape
            score crossed [0,1] threshold. anom.feature == "joint",
            anom.z is the score (NOT a σ count), mean/std are 0.0.

        Same alert kind for both — operator's mental model is "the camera
        is behaving weirdly" either way — but the detail text says which
        model fired so they can investigate appropriately.
        """
        dedup_key = f"behavioral_anomaly:{anom.camera_ip}:{anom.feature}"
        if self._suppressed(dedup_key, now):
            return None
        if anom.model == "hstree":
            summary = (
                f"camera {anom.camera_ip}: joint behavior anomaly "
                f"(score={anom.z:.2f})"
            )
            detail = (
                f"the HS-Forest baseline for camera {anom.camera_ip} "
                f"scored this flow at {anom.z:.2f} (≥ threshold) for "
                f"weekday={anom.weekday} hour={anom.hour:02d}. Score is "
                f"in [0,1] across the ensemble; higher = rarer. This "
                f"detector flags multivariate shape — bytes, packets, "
                f"duration, and direction taken jointly — not any single "
                f"feature in isolation."
            )
        else:
            summary = (
                f"camera {anom.camera_ip}: {anom.feature} anomaly "
                f"(observed={anom.value:.0f}, z={anom.z:+.1f})"
            )
            detail = (
                f"feature {anom.feature!r} for camera {anom.camera_ip} is "
                f"{anom.z:+.1f}σ from the learned baseline for "
                f"weekday={anom.weekday} hour={anom.hour:02d} "
                f"(μ={anom.baseline_mean:.2f}, σ={anom.baseline_std:.2f}, "
                f"observed={anom.value:.2f})."
            )
        return Alert(
            ts=now, device_ip=anom.camera_ip, kind=KIND_BEHAVIORAL_ANOMALY,
            severity="medium",
            summary=summary, detail=detail, dedup_key=dedup_key,
        )

    # `camera_offline` is emitted by `from_transition` above, driven by
    # uptime.UptimeTracker. The old standalone method that the daemon's
    # deleted `_check_silence` called has been removed rather than left as
    # dead code — its per-camera dedup key was the bug that swallowed a
    # second outage inside the dedup window.

    # ----- dedup -----

    def _suppressed(self, dedup_key: str, now: float | None = None) -> bool:
        now = now or time.time()
        last = self.store.last_alert_at(dedup_key)
        if last is None:
            return False
        return (now - last) < self.cfg.dedup_window_seconds
