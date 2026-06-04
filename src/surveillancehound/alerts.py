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
KIND_NEW_DEVICE = "new_device"
KIND_NEW_PEER = "new_peer"
KIND_CAMERA_OFFLINE = "camera_offline"
KIND_BEHAVIORAL_ANOMALY = "behavioral_anomaly"


_REPORTABLE_FLOW = {
    "bulk_inbound": (KIND_BULK_INBOUND, "high"),
    "control_channel_suspect": (KIND_CONTROL_CHANNEL, "medium"),
    "telemetry_offnet": (KIND_TELEMETRY_OFFNET, "medium"),
    "camera_to_camera": (KIND_CAMERA_TO_CAMERA, "low"),
}


@dataclass
class Alert:
    ts: float
    device_ip: str
    kind: str
    severity: str  # info | low | medium | high | critical
    summary: str
    detail: str
    dedup_key: str

    def as_dict(self) -> dict:
        return {
            "ts": self.ts, "device_ip": self.device_ip, "kind": self.kind,
            "severity": self.severity, "summary": self.summary,
            "detail": self.detail, "dedup_key": self.dedup_key,
        }


class AlertEngine:
    """Decides which classifications / events become Alerts. Handles dedup."""

    def __init__(self, *, cfg: AlertsCfg, store: HoundStore) -> None:
        self.cfg = cfg
        self.store = store

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

    def camera_offline(self, ip: str, silent_for: float, now: float) -> Alert | None:
        dedup_key = f"camera_offline:{ip}"
        if self._suppressed(dedup_key, now):
            return None
        return Alert(
            ts=now, device_ip=ip, kind=KIND_CAMERA_OFFLINE, severity="medium",
            summary=(
                f"camera {ip} has been silent for {silent_for:.0f}s — "
                "possibly offline."
            ),
            detail=(
                f"no flows involving {ip} have been observed for {silent_for:.0f} "
                "seconds. Check that the camera is online and recording."
            ),
            dedup_key=dedup_key,
        )

    # ----- dedup -----

    def _suppressed(self, dedup_key: str, now: float | None = None) -> bool:
        now = now or time.time()
        last = self.store.last_alert_at(dedup_key)
        if last is None:
            return False
        return (now - last) < self.cfg.dedup_window_seconds
