"""Hound config — TOML schema and loader.

The config is a single TOML file. Stdlib `tomllib` (Python 3.11+) reads it; no
extra dependency. Every section has documented defaults so a minimal config
('listen on this interface, here's my camera list') just works.

Schema (see hound.toml.example):

  [capture]
  interface = "eth0"      # device to listen on; mutually exclusive with `pcap_file`
  pcap_file = "..."       # offline replay of a saved capture (testing / forensics)
  bpf       = "..."       # optional Berkeley Packet Filter expression
  snaplen   = 96          # bytes captured per packet — we only need headers

  [network]
  camera_ips      = ["192.168.10.20", "192.168.10.21"]   # known cameras
  camera_subnets  = ["192.168.10.0/24"]                  # cameras live here
  nvr_ips         = ["192.168.10.10"]                    # known NVR(s)
  manufacturer_allowlist = ["203.0.113.0/24"]            # vendor cloud CIDRs

  [thresholds]
  bulk_inbound_bytes      = 1_048_576    # toward-camera total to flag bulk-inbound
  long_lived_seconds      = 120          # flow age to flag control-channel
  many_packets            = 200          # alt control-channel trigger
  silence_seconds         = 600          # camera silent that long -> CAMERA_OFFLINE
  flow_ttl_seconds        = 300          # idle flows flushed + dropped from RAM
  routine_ports           = [80, 443, 53, 123, 554, 322, 8000, 8554, 37777, 34567]

  [alerts]
  dedup_window_seconds = 1800   # don't re-notify on the same alert within this window

  [store]
  path = "/var/lib/surveillancehound/hound.sqlite"   # or relative

  [[notify]]
  type   = "stdout"             # always-on default; remove to silence
  level  = "low"                # min severity to dispatch

  [[notify]]
  type   = "logfile"
  path   = "/var/log/hound.log"
  level  = "info"

  [[notify]]
  type   = "jsonlines"          # one alert per line, easy to tail / pipe
  path   = "/var/log/hound.alerts.jsonl"
  level  = "low"

  [[notify]]
  type   = "webhook"
  url    = "https://example.com/hook"
  level  = "medium"
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CaptureCfg:
    interface: str = ""
    pcap_file: str = ""
    bpf: str = ""
    snaplen: int = 96


@dataclass
class NetworkCfg:
    camera_ips: list[str] = field(default_factory=list)
    camera_subnets: list[str] = field(default_factory=list)
    nvr_ips: list[str] = field(default_factory=list)
    manufacturer_allowlist: list[str] = field(default_factory=list)


@dataclass
class ThresholdCfg:
    bulk_inbound_bytes: int = 1 * 1024 * 1024
    long_lived_seconds: float = 120.0
    many_packets: int = 200
    silence_seconds: float = 600.0
    flow_ttl_seconds: float = 300.0
    routine_ports: list[int] = field(default_factory=lambda: [
        80, 443, 53, 123, 554, 322, 8000, 8554, 37777, 34567,
    ])


@dataclass
class AlertsCfg:
    dedup_window_seconds: float = 1800.0


@dataclass
class StoreCfg:
    path: str = "hound.sqlite"


@dataclass
class NotifyChannelCfg:
    type: str  # stdout | logfile | jsonlines | webhook
    level: str = "low"  # min severity: info | low | medium | high | critical
    path: str = ""  # logfile / jsonlines
    url: str = ""   # webhook
    headers: dict[str, str] = field(default_factory=dict)  # webhook
    timeout: float = 5.0


@dataclass
class HoundCfg:
    capture: CaptureCfg
    network: NetworkCfg
    thresholds: ThresholdCfg
    alerts: AlertsCfg
    store: StoreCfg
    notify: list[NotifyChannelCfg]


def load(path: Path) -> HoundCfg:
    """Load and validate a TOML config. Missing sections fall back to defaults."""
    data = tomllib.loads(Path(path).read_text())
    return _from_dict(data)


def load_from_dict(data: dict) -> HoundCfg:
    """Build a HoundCfg from a parsed-dict (useful for tests)."""
    return _from_dict(data)


def _from_dict(data: dict) -> HoundCfg:
    cap = data.get("capture", {})
    net = data.get("network", {})
    th = data.get("thresholds", {})
    al = data.get("alerts", {})
    st = data.get("store", {})
    notify_raw = data.get("notify", [])
    if isinstance(notify_raw, dict):
        notify_raw = [notify_raw]

    capture = CaptureCfg(
        interface=cap.get("interface", ""),
        pcap_file=cap.get("pcap_file", ""),
        bpf=cap.get("bpf", ""),
        snaplen=int(cap.get("snaplen", 96)),
    )
    if capture.interface and capture.pcap_file:
        raise ValueError(
            "config: [capture] may set either `interface` or `pcap_file`, not both"
        )
    if not capture.interface and not capture.pcap_file:
        raise ValueError(
            "config: [capture] requires either `interface` (live) or `pcap_file` (replay)"
        )

    network = NetworkCfg(
        camera_ips=list(net.get("camera_ips", [])),
        camera_subnets=list(net.get("camera_subnets", [])),
        nvr_ips=list(net.get("nvr_ips", [])),
        manufacturer_allowlist=list(net.get("manufacturer_allowlist", [])),
    )
    thresholds = ThresholdCfg(
        bulk_inbound_bytes=int(th.get("bulk_inbound_bytes", 1_048_576)),
        long_lived_seconds=float(th.get("long_lived_seconds", 120.0)),
        many_packets=int(th.get("many_packets", 200)),
        silence_seconds=float(th.get("silence_seconds", 600.0)),
        flow_ttl_seconds=float(th.get("flow_ttl_seconds", 300.0)),
        routine_ports=list(th.get("routine_ports", ThresholdCfg().routine_ports)),
    )
    alerts = AlertsCfg(dedup_window_seconds=float(al.get("dedup_window_seconds", 1800.0)))
    store = StoreCfg(path=st.get("path", "hound.sqlite"))

    notify: list[NotifyChannelCfg] = []
    for n in notify_raw:
        if "type" not in n:
            raise ValueError(f"config: notify entry missing 'type': {n}")
        notify.append(NotifyChannelCfg(
            type=n["type"], level=n.get("level", "low"),
            path=n.get("path", ""), url=n.get("url", ""),
            headers=dict(n.get("headers", {})),
            timeout=float(n.get("timeout", 5.0)),
        ))
    if not notify:
        # an unconfigured config is a silent daemon — make stdout the default so
        # a misconfigured deployment still surfaces alerts to the operator
        notify.append(NotifyChannelCfg(type="stdout", level="low"))

    return HoundCfg(
        capture=capture, network=network, thresholds=thresholds,
        alerts=alerts, store=store, notify=notify,
    )
