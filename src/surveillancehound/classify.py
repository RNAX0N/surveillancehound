"""Classify a flow + derive device/silence events.

Specialized for NVR / IP-camera traffic. The classifications below are the
ones an operator actually wants alerts on:

  * bulk_inbound            — a large transfer TOWARD a camera (HIGH).
                              The size range of a model-weight push or a
                              firmware update — exactly the manipulation
                              install vector the surveillance threat model
                              cares about.
  * control_channel_suspect — long-lived / chatty connection from a camera
                              to a public host on a non-routine port (MEDIUM).
                              Cameras should not be holding C2-shaped sessions.
  * telemetry_offnet        — a camera talks to a public host that is NOT in
                              the manufacturer allowlist (MEDIUM).
  * manufacturer            — peer is on the manufacturer allowlist (info).
  * lan_normal              — LAN-only traffic (info).
  * external_other          — neither endpoint is a known camera but at least
                              one is off-LAN (low — review the device).
  * camera_to_camera        — direct camera-to-camera (unusual; LOW info).

Device events (emitted by the periodic tick, not by per-flow classification):

  * NEW_DEVICE   — a previously-unseen IP has shown up.
  * NEW_PEER     — a known camera is talking to a NEW external endpoint.
  * CAMERA_OFFLINE — a known camera has been silent for `silence_seconds`.
"""

from __future__ import annotations

from dataclasses import dataclass

from surveillancehound.config import NetworkCfg, ThresholdCfg
from surveillancehound.discover import DeviceClassifier
from surveillancehound.flows import LiveFlow


@dataclass(frozen=True)
class FlowClassification:
    classification: str
    severity: str  # info | low | medium | high | critical
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    bytes_to_camera: int
    bytes_from_camera: int
    detail: str


class FlowClassifier:
    """Maps a flushed flow to (classification, severity, detail)."""

    def __init__(
        self, *, network: NetworkCfg, thresholds: ThresholdCfg,
        devices: DeviceClassifier,
    ) -> None:
        self.network = network
        self.t = thresholds
        self.devices = devices
        self._routine_ports = frozenset(thresholds.routine_ports)

    def classify(self, fl: LiveFlow) -> FlowClassification:
        # orient: camera side first if we know which endpoint is the camera
        role_a = self.devices.role_for(fl.ep_a[0])
        role_b = self.devices.role_for(fl.ep_b[0])

        if role_a == "camera" and role_b != "camera":
            cam_ep, peer_ep = fl.ep_a, fl.ep_b
            bytes_to_camera = fl.bytes_b_to_a
            bytes_from_camera = fl.bytes_a_to_b
            camera_role = "camera"
        elif role_b == "camera" and role_a != "camera":
            cam_ep, peer_ep = fl.ep_b, fl.ep_a
            bytes_to_camera = fl.bytes_a_to_b
            bytes_from_camera = fl.bytes_b_to_a
            camera_role = "camera"
        else:
            # both same role (camera-to-camera, or both 'other'/'nvr')
            cam_ep, peer_ep = fl.ep_a, fl.ep_b
            bytes_to_camera = bytes_from_camera = 0
            camera_role = role_a if role_a == role_b else "mixed"

        peer_ip, peer_port = peer_ep
        peer_on_lan = self.devices.is_lan(peer_ip)
        peer_allowlisted = self.devices.is_on_manufacturer_allowlist(peer_ip)

        if role_a == "camera" and role_b == "camera":
            return self._mk("camera_to_camera", "low", cam_ep, peer_ep,
                            bytes_to_camera, bytes_from_camera,
                            "direct camera-to-camera traffic — unusual for most "
                            "deployments; investigate.")

        if camera_role == "camera":
            if peer_allowlisted:
                return self._mk("manufacturer", "info", cam_ep, peer_ep,
                                bytes_to_camera, bytes_from_camera,
                                f"peer {peer_ip} is in the manufacturer allowlist.")
            if peer_on_lan:
                return self._mk("lan_normal", "info", cam_ep, peer_ep,
                                bytes_to_camera, bytes_from_camera,
                                f"LAN traffic between camera {cam_ep[0]} and {peer_ip}.")
            # peer is off-LAN, not allowlisted — the interesting cases
            if bytes_to_camera >= self.t.bulk_inbound_bytes:
                return self._mk(
                    "bulk_inbound", "high", cam_ep, peer_ep,
                    bytes_to_camera, bytes_from_camera,
                    f"{bytes_to_camera:,} bytes transferred TOWARD the camera from "
                    f"public host {peer_ip}:{peer_port} — model-weight / firmware "
                    "push range. Identify the host and what was delivered.",
                )
            duration = fl.duration
            if (
                (duration >= self.t.long_lived_seconds
                 or fl.packets >= self.t.many_packets)
                and peer_port not in self._routine_ports
            ):
                return self._mk(
                    "control_channel_suspect", "medium", cam_ep, peer_ep,
                    bytes_to_camera, bytes_from_camera,
                    f"camera {cam_ep[0]} holds a long-lived / chatty session with "
                    f"public {peer_ip}:{peer_port} ({fl.packets} packets over "
                    f"{duration:.0f}s) on a non-routine port — control-channel-shaped.",
                )
            return self._mk(
                "telemetry_offnet", "medium", cam_ep, peer_ep,
                bytes_to_camera, bytes_from_camera,
                f"camera {cam_ep[0]} is communicating with public {peer_ip}:{peer_port}, "
                "which is not in the manufacturer allowlist — possible off-network "
                "telemetry.",
            )

        # neither endpoint is a camera
        if peer_on_lan and self.devices.is_lan(cam_ep[0]):
            return self._mk("lan_normal", "info", cam_ep, peer_ep,
                            bytes_to_camera, bytes_from_camera,
                            "LAN-only traffic between non-camera devices.")
        return self._mk(
            "external_other", "low", cam_ep, peer_ep,
            bytes_to_camera, bytes_from_camera,
            f"external traffic involving {cam_ep[0]} <-> {peer_ip}; "
            "neither endpoint is a known camera.",
        )

    def _mk(
        self, cls: str, sev: str, cam_ep: tuple, peer_ep: tuple,
        to_cam: int, from_cam: int, detail: str,
    ) -> FlowClassification:
        return FlowClassification(
            classification=cls, severity=sev,
            src_ip=cam_ep[0], src_port=cam_ep[1],
            dst_ip=peer_ep[0], dst_port=peer_ep[1],
            bytes_to_camera=to_cam, bytes_from_camera=from_cam,
            detail=detail,
        )
