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
import socket
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
    _lan_nets: list = field(default_factory=list)
    # learned roles persist for the lifetime of the daemon (and SQLite holds
    # the across-restart memory).
    _learned: dict[str, str] = field(default_factory=dict)
    # for the NVR heuristic: who has each device been talking to?
    _peers_per_ip: dict[str, set[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._camera_set = set(self.network.camera_ips)
        # ip -> is it one of this machine's own addresses. Asked once
        # per address, never per packet.
        self._own_cache: dict[str, bool] = {}
        self._nvr_set = set(self.network.nvr_ips)
        self._camera_nets = [
            ipaddress.ip_network(c, strict=False)
            for c in self.network.camera_subnets
        ]
        self._allow_nets = [
            ipaddress.ip_network(c, strict=False)
            for c in self.network.manufacturer_allowlist
        ]
        self._lan_nets = list(_LAN_NETWORKS) + [
            ipaddress.ip_network(c, strict=False)
            for c in self.network.lan_subnets
        ]

    def is_lan(self, ip: str) -> bool:
        """True if `ip` is local for THIS deployment.

        The built-in private ranges plus whatever `[network].lan_subnets`
        adds. Prefer this over the module-level `is_lan()` anywhere a
        classification decision is being made — the module function cannot
        see the operator's configuration, so on a network numbered out of
        public space it calls every local device foreign.
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self._lan_nets)

    def is_own_address(self, ip: str) -> bool:
        """Is this an address of the machine this sensor runs on?

        A sensor cannot observe itself. Liveness here is inferred from
        traffic on the monitored interface, and this host's own
        addresses do not appear there as a peer, so anything of ours
        that gets a camera or nvr role goes "down" and stays down while
        the report saying so proves otherwise.

        Worse than a wrong row: the NVR's VLAN gateway addresses carry
        Frigate's MASQUERADED RTSP, so the port heuristic sees
        117.111.10N.1 connecting to a camera's 554 and concludes the
        gateway is a camera. Camera-to-camera traffic is then alerted as
        "unusual; investigate" — on the recorder doing its job. That is
        exactly what happened once the explicit nvr_ips entries for
        those addresses were removed.

        Binding a UDP socket to an address succeeds only if the kernel
        has it on some interface, and fails with EADDRNOTAVAIL
        otherwise. Port 0, so nothing is reserved and no packet is sent;
        this is a question, not a connection. Pure stdlib, and it
        behaves the same on Linux and FreeBSD, which matters because the
        agent and the collector do not run the same OS.

        Cached per address: the question is asked once per device, not
        once per packet.
        """
        cached = self._own_cache.get(ip)
        if cached is not None:
            return cached
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        try:
            with socket.socket(fam, socket.SOCK_DGRAM) as sk:
                sk.bind((ip, 0))
            own = True
        except OSError:
            own = False
        self._own_cache[ip] = own
        return own

    def role_for(self, ip: str) -> str:
        # 0) never a camera or an NVR if it is one of OUR addresses --
        #    ahead of explicit config, because a configured own-address
        #    cannot work either and `hound config-check` says so.
        if self.is_own_address(ip):
            return "other"
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
            if (dst_ip not in self._nvr_set and dst_ip not in self._camera_set
                    and not self.is_own_address(dst_ip)):
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
        if self.is_own_address(src_ip):
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
