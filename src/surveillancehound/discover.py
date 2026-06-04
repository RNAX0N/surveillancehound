"""Device discovery — who on the wire is a camera, an NVR, or 'other'.

The config can name cameras and NVRs explicitly (the trustworthy path on a
real deployment), but on an unknown segment the daemon should still classify
what it sees. The rules here are simple, transparent, and conservative; an
operator can override any one of them by listing the IP in the config.

Heuristics, in priority order:

  1. Explicit config — `camera_ips` / `nvr_ips` win unconditionally.
  2. Subnet match — an IP inside a configured `camera_subnets` entry is a
     camera unless it is also in `nvr_ips`.
  3. Port-based — listening on RTSP (554) / 8554 / 8000 (Hikvision) / 37777-37778
     (Dahua) / 9000 looks like a camera; persistent inbound aggregation from
     multiple cameras looks like an NVR.

A device starts as 'other'; the first heuristic that fires upgrades the role.
Roles never downgrade — once flagged a camera, always a camera (config
override remains the truth).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from surveillancehound.config import NetworkCfg

# Ports the camera vendor side distinctively listens on. NOT here on purpose:
# 80 / 443 (too generic — a camera's web UI uses them, but so does everything
# else), 8080 (same). The list below is "if you see a device serving on this
# port, it is almost certainly a camera or its kit": RTSP, Hikvision ISAPI,
# Dahua, ONVIF, the common alt-RTSP / alt-camera-mgmt ports.
_CAMERA_PORTS = frozenset({554, 8554, 8000, 8001, 37777, 37778, 9000, 322})

# Cap on the per-source peer set used for the NVR heuristic. We only need
# enough peers to ask "are ≥3 of them cameras?" — past that, accumulating
# more entries just bloats memory on a long-running daemon.
_MAX_PEER_HINT_SIZE = 64


@dataclass
class DeviceClassifier:
    """Decides 'camera' / 'nvr' / 'other' for an IP. Stateful across the run."""

    network: NetworkCfg
    _camera_set: set[str] = field(default_factory=set)
    _nvr_set: set[str] = field(default_factory=set)
    _camera_nets: list = field(default_factory=list)
    _allow_nets: list = field(default_factory=list)
    # learned roles persist for the lifetime of the daemon (and SQLite holds
    # the across-restart memory).
    _learned: dict[str, str] = field(default_factory=dict)
    # for the NVR heuristic: who has each device been talking to?
    _peers_per_ip: dict[str, set[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._camera_set = set(self.network.camera_ips)
        self._nvr_set = set(self.network.nvr_ips)
        self._camera_nets = [
            ipaddress.ip_network(c, strict=False)
            for c in self.network.camera_subnets
        ]
        self._allow_nets = [
            ipaddress.ip_network(c, strict=False)
            for c in self.network.manufacturer_allowlist
        ]

    def role_for(self, ip: str) -> str:
        # 1) explicit config wins
        if ip in self._nvr_set:
            return "nvr"
        if ip in self._camera_set:
            return "camera"
        # 2) prior learning persists for this run
        learned = self._learned.get(ip)
        if learned is not None:
            return learned
        # 3) subnet match
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return "other"
        for net in self._camera_nets:
            if addr in net:
                self._learned[ip] = "camera"
                return "camera"
        return "other"

    def observe(
        self, src_ip: str, dst_ip: str, src_port: int | None, dst_port: int | None
    ) -> None:
        """Update heuristics from one packet. Cheap; called per packet."""
        # port-based camera hint: if a device serves on a camera-ish port,
        # mark it a camera. 'serves' = it is the dst_ip and the dst_port is
        # camera-ish (a client connecting INTO that port).
        if dst_port in _CAMERA_PORTS and self._learned.get(dst_ip, "other") == "other":
            if dst_ip not in self._nvr_set and dst_ip not in self._camera_set:
                self._learned[dst_ip] = "camera"
                self._peers_per_ip.pop(dst_ip, None)
        # NVR hint: a LAN device that talks to many camera-classified peers.
        # Skip once src is classified (no further hint to gather) and cap the
        # per-src peer set — keeps `_peers_per_ip` bounded on a busy segment.
        if (
            src_ip in self._learned
            or src_ip in self._camera_set
            or src_ip in self._nvr_set
        ):
            return
        peers = self._peers_per_ip.setdefault(src_ip, set())
        if dst_ip in peers or len(peers) >= _MAX_PEER_HINT_SIZE:
            return
        peers.add(dst_ip)
        if len(peers) >= 3:
            cams = sum(1 for p in peers if self.role_for(p) == "camera")
            if cams >= 3:
                self._learned[src_ip] = "nvr"
                self._peers_per_ip.pop(src_ip, None)

    def is_on_manufacturer_allowlist(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self._allow_nets)


# What counts as "on the local network" — see footageanalyzer's network module
# for the same reasoning. ipaddress.is_private also includes RFC-5737
# documentation ranges, which is wrong for forensic / network-egress purposes.
_LAN_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]


def is_lan(ip: str) -> bool:
    """True if `ip` is on the local network (RFC-1918 + loopback + link-local + ULA)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in _LAN_NETWORKS)
