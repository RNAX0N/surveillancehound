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

  [uptime]
  enabled               = true     # per-camera liveness + outage history;
                                   # false also disables camera_offline
  startup_grace_seconds = 600.0    # 0 -> inherit thresholds.silence_seconds
  capture_stall_seconds = 120.0    # no packets at all for this long -> CAPTURE_STALLED; 0 disables
  recovery_alerts       = true     # emit camera_recovered when a camera comes back
  report_window_seconds = 86400.0  # default availability window for `hound uptime` + /api/uptime

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

import ipaddress
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
class SnapshotCfg:
    """Per-camera packet ring buffer + on-alert pcap dump (opt-in).

    When `enabled`, the daemon keeps the last `window_seconds` of raw
    packet records per camera in RAM. On any alert at severity >=
    `min_severity`, the matching camera's buffer is dumped to
    `<dir>/<alert_id>.pcap` so an operator can open it in Wireshark.
    `dir` defaults to `<store_dir>/snapshots/`.
    Snaplen for raw-record capture is independent of the analysis snaplen;
    you typically want it larger (e.g. 1500) for useful forensics.
    """
    enabled: bool = False
    window_seconds: float = 60.0
    min_severity: str = "medium"
    dir: str = ""  # empty → derived from [store].path
    snaplen: int = 1500
    max_buffer_bytes: int = 32 * 1024 * 1024  # per camera; oldest evicted


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
class UptimeCfg:
    """Per-camera liveness tracking, outage history, and availability.

    Detection is PASSIVE: a camera is considered up because packets from it
    were observed on the monitored interface. It is not probed. A camera that
    is powered and recording but no longer visible to this sensor (moved
    VLAN, mirror port reconfigured) is indistinguishable from one that is
    powered down. Active probing is deliberately out of scope — see
    DevNotes.md.

    `capture_stall_seconds` is the dead-man's-switch: when NO packets at all
    arrive for that long, the sensor is blind, so a single `capture_stalled`
    alert fires and per-camera offline alerts are suppressed. Without it, a
    dead tcpdump looks exactly like every camera failing at once.

    NOTE: `enabled = false` turns off ALL liveness alerting, including
    `camera_offline` — this engine is the only thing that emits it. Disable
    only if you genuinely do not want to be told when a camera goes dark.
    """
    enabled: bool = True
    startup_grace_seconds: float = 600.0   # 0 -> inherit silence_seconds
    capture_stall_seconds: float = 120.0   # 0 -> disable the dead-man's-switch
    recovery_alerts: bool = True
    report_window_seconds: float = 86400.0

    def grace_for(self, thresholds: "ThresholdCfg") -> float:
        """How long after startup before an unobserved camera alerts.

        0 means 'inherit the silence threshold' so an operator only has to
        tune one number in the common case.
        """
        if self.startup_grace_seconds > 0:
            return self.startup_grace_seconds
        return thresholds.silence_seconds


@dataclass
class BaselineCfg:
    """Per-camera behavioral baselining (opt-in).

    Two models, both bucketed by (camera_ip, weekday, hour):

      model = "welford" (default) — running per-feature (mean, variance) via
        Welford's algorithm. Fires when a single feature crosses `z_threshold`
        standard deviations. Deterministic, auditable, O(1) memory per bucket.

      model = "hstree" — streaming Half-Space Forest (Tan, Ting, Liu 2011),
        a real ML anomaly detector. Catches *joint* multivariate anomalies
        Welford misses by construction (each feature normal in isolation but
        their combination rare). Pure stdlib, online, O(log depth) per flow.

    Both gate alerts behind `min_samples` per bucket, both persist learned
    state to SQLite so restarts resume rather than retrain, and both fire
    `behavioral_anomaly` alerts. Pick one — running both at once is wasteful.
    """
    enabled: bool = False
    model: str = "welford"               # "welford" | "hstree"
    min_samples: int = 100               # both models — gate before alerts arm
    flush_interval_seconds: float = 60.0 # disk write cadence (both models)

    # --- welford-only knobs ---
    z_threshold: float = 4.0             # σ above which a feature alerts

    # --- hstree-only knobs ---
    hstree_n_trees: int = 8              # ensemble size; 8-25 is the typical band
    hstree_depth: int = 6                # tree depth; mass space = 2**depth leaves
    hstree_window_size: int = 250        # samples per "reference / latest" rollover
    hstree_score_threshold: float = 0.7  # [0,1] — higher fires less, 0.7 ≈ rare
    hstree_seed: int = 0                 # 0 = clock-seeded; non-zero = reproducible


@dataclass
class StoreCfg:
    path: str = "hound.sqlite"


@dataclass
class NotifyChannelCfg:
    """One configured notification channel. Many fields are channel-specific;
    only the ones a given `type` consumes are honored, the rest default."""
    type: str  # stdout|logfile|jsonlines|webhook|syslog|email|ftp
    level: str = "low"  # min severity: info | low | medium | high | critical
    # --- logfile / jsonlines ---
    path: str = ""
    max_bytes: int = 10 * 1024 * 1024  # rotation threshold; 0 disables
    keep: int = 5                      # rotated files kept (path.1..path.N)
    # --- webhook ---
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 5.0
    # --- syslog ---
    host: str = ""              # also used by ftp
    port: int = 0               # 514 for syslog, 21 for ftp if unset
    proto: str = "udp"          # udp | tcp (syslog)
    facility: int = 16          # local0
    app_name: str = "hound"
    # --- email (SMTP) ---
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True   # STARTTLS
    smtp_from: str = ""
    smtp_to: list[str] = field(default_factory=list)
    smtp_subject_prefix: str = "[SurveillanceHound]"
    # --- ftp / ftps ---
    ftp_user: str = "anonymous"
    ftp_password: str = "hound@localhost"
    ftp_dir: str = "/"
    ftp_use_tls: bool = False   # explicit FTPS (AUTH TLS) when True


@dataclass
class HoundCfg:
    capture: CaptureCfg
    network: NetworkCfg
    thresholds: ThresholdCfg
    alerts: AlertsCfg
    store: StoreCfg
    notify: list[NotifyChannelCfg]
    baseline: BaselineCfg = field(default_factory=BaselineCfg)
    snapshot: SnapshotCfg = field(default_factory=SnapshotCfg)
    web: "WebCfg" = field(default_factory=lambda: WebCfg())
    uptime: UptimeCfg = field(default_factory=UptimeCfg)


@dataclass
class WebCfg:
    """Local web dashboard (opt-in). Binds to localhost by default; only
    listens on a routable interface if the operator changes `host`.
    The dashboard is read-only (no write endpoints) — it reads the same
    SQLite the daemon writes.

    HTTPS is opt-in: set both `cert_file` and `key_file` to PEM-encoded
    files and the server wraps the socket with stdlib ssl. Required when
    embedding the dashboard via iframe inside an HTTPS UI (browsers block
    HTTP iframes on HTTPS parent pages). The OPNsense plugin auto-mints
    a self-signed pair on first save when HTTPS is selected.
    """
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8080
    poll_interval_seconds: float = 5.0  # client-side refresh cadence
    cert_file: str = ""                 # PEM cert; if both set → HTTPS
    key_file: str = ""                  # PEM private key

    @property
    def scheme(self) -> str:
        return "https" if (self.cert_file and self.key_file) else "http"


def load(path: Path) -> HoundCfg:
    """Load and validate a TOML config. Missing sections fall back to defaults."""
    data = tomllib.loads(Path(path).read_text())
    return _from_dict(data)


def load_from_dict(data: dict) -> HoundCfg:
    """Build a HoundCfg from a parsed-dict (useful for tests)."""
    return _from_dict(data)


def _addresses(section: dict, key: str) -> list[str]:
    """Validate a list of bare IP addresses.

    The daemon never resolves DNS — it only ever sees addresses on the
    wire — so a hostname here matches nothing. Left unvalidated that fails
    *silently*: the device is never classified as a camera, so it gets no
    uptime tracking and no camera alerts, and the config looks perfectly
    reasonable. Refusing it at load time is the only honest option.
    """
    out = []
    for raw in section.get(key, []):
        value = str(raw).strip()
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            hint = (
                f"config: [network].{key} entry {value!r} is not an IP address. "
            )
            if "/" in value:
                hint += (
                    f"It looks like a CIDR — put ranges in "
                    f"[network].{key.replace('_ips', '_subnets')} instead."
                )
            else:
                hint += (
                    "Hostnames are not supported: the daemon does no DNS "
                    "resolution and only ever sees addresses on the wire. "
                    "Use the address, or cover the whole range with "
                    "[network].camera_subnets."
                )
            raise ValueError(hint) from None
        out.append(value)
    return out


def _networks(section: dict, key: str) -> list[str]:
    """Validate a list of CIDRs (a bare address is accepted as a /32)."""
    out = []
    for raw in section.get(key, []):
        value = str(raw).strip()
        if not value:
            continue
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(
                f"config: [network].{key} entry {value!r} is not a network. "
                f"Use CIDR notation such as 192.168.10.0/24. Hostnames are "
                f"not supported — the daemon does no DNS resolution and only "
                f"ever sees addresses on the wire."
            ) from None
        out.append(value)
    return out


def _from_dict(data: dict) -> HoundCfg:
    cap = data.get("capture", {})
    net = data.get("network", {})
    th = data.get("thresholds", {})
    al = data.get("alerts", {})
    st = data.get("store", {})
    bl = data.get("baseline", {})
    sn = data.get("snapshot", {})
    wb = data.get("web", {})
    up = data.get("uptime", {})
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
        camera_ips=_addresses(net, "camera_ips"),
        camera_subnets=_networks(net, "camera_subnets"),
        nvr_ips=_addresses(net, "nvr_ips"),
        manufacturer_allowlist=_networks(net, "manufacturer_allowlist"),
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
    baseline = BaselineCfg(
        enabled=bool(bl.get("enabled", False)),
        model=str(bl.get("model", "welford")),
        min_samples=int(bl.get("min_samples", 100)),
        flush_interval_seconds=float(bl.get("flush_interval_seconds", 60.0)),
        z_threshold=float(bl.get("z_threshold", 4.0)),
        hstree_n_trees=int(bl.get("hstree_n_trees", 8)),
        hstree_depth=int(bl.get("hstree_depth", 6)),
        hstree_window_size=int(bl.get("hstree_window_size", 250)),
        hstree_score_threshold=float(bl.get("hstree_score_threshold", 0.7)),
        hstree_seed=int(bl.get("hstree_seed", 0)),
    )
    if baseline.model not in ("welford", "hstree"):
        raise ValueError(
            f"config: [baseline].model must be 'welford' or 'hstree', "
            f"got {baseline.model!r}",
        )
    snapshot = SnapshotCfg(
        enabled=bool(sn.get("enabled", False)),
        window_seconds=float(sn.get("window_seconds", 60.0)),
        min_severity=str(sn.get("min_severity", "medium")),
        dir=str(sn.get("dir", "")),
        snaplen=int(sn.get("snaplen", 1500)),
        max_buffer_bytes=int(sn.get("max_buffer_bytes", 32 * 1024 * 1024)),
    )
    web = WebCfg(
        enabled=bool(wb.get("enabled", False)),
        host=str(wb.get("host", "127.0.0.1")),
        port=int(wb.get("port", 8080)),
        poll_interval_seconds=float(wb.get("poll_interval_seconds", 5.0)),
        cert_file=str(wb.get("cert_file", "")),
        key_file=str(wb.get("key_file", "")),
    )
    if bool(web.cert_file) != bool(web.key_file):
        raise ValueError(
            "config: [web] cert_file and key_file must be set together "
            "(or both left empty for HTTP)",
        )

    notify: list[NotifyChannelCfg] = []
    for n in notify_raw:
        if "type" not in n:
            raise ValueError(f"config: notify entry missing 'type': {n}")
        notify.append(NotifyChannelCfg(
            type=n["type"], level=n.get("level", "low"),
            path=n.get("path", ""), url=n.get("url", ""),
            headers=dict(n.get("headers", {})),
            timeout=float(n.get("timeout", 5.0)),
            max_bytes=int(n.get("max_bytes", 10 * 1024 * 1024)),
            keep=int(n.get("keep", 5)),
            # syslog
            host=n.get("host", ""),
            port=int(n.get("port", 0)),
            proto=n.get("proto", "udp"),
            facility=int(n.get("facility", 16)),
            app_name=n.get("app_name", "hound"),
            # email
            smtp_host=n.get("smtp_host", ""),
            smtp_port=int(n.get("smtp_port", 587)),
            smtp_user=n.get("smtp_user", ""),
            smtp_password=n.get("smtp_password", ""),
            smtp_use_tls=bool(n.get("smtp_use_tls", True)),
            smtp_from=n.get("smtp_from", ""),
            smtp_to=list(n.get("smtp_to", [])),
            smtp_subject_prefix=n.get(
                "smtp_subject_prefix", "[SurveillanceHound]",
            ),
            # ftp
            ftp_user=n.get("ftp_user", "anonymous"),
            ftp_password=n.get("ftp_password", "hound@localhost"),
            ftp_dir=n.get("ftp_dir", "/"),
            ftp_use_tls=bool(n.get("ftp_use_tls", False)),
        ))
    if not notify:
        # an unconfigured config is a silent daemon — make stdout the default so
        # a misconfigured deployment still surfaces alerts to the operator
        notify.append(NotifyChannelCfg(type="stdout", level="low"))

    uptime = UptimeCfg(
        enabled=bool(up.get("enabled", True)),
        startup_grace_seconds=float(up.get("startup_grace_seconds", 600.0)),
        capture_stall_seconds=float(up.get("capture_stall_seconds", 120.0)),
        recovery_alerts=bool(up.get("recovery_alerts", True)),
        report_window_seconds=float(up.get("report_window_seconds", 86400.0)),
    )

    return HoundCfg(
        capture=capture, network=network, thresholds=thresholds,
        alerts=alerts, store=store, notify=notify, baseline=baseline,
        snapshot=snapshot, web=web, uptime=uptime,
    )
