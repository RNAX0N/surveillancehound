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
  lan_subnets     = ["100.64.0.0/10"]                    # extra ranges to treat as local

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
    # Extra ranges to treat as local, ON TOP OF the built-in private ones.
    # Not every deployment numbers its cameras out of RFC-1918 — an operator
    # using provider-assigned public space internally would otherwise have
    # every camera classified as off-network, which turns ordinary traffic
    # into telemetry_offnet noise and makes the allowlist meaningless.
    lan_subnets: list[str] = field(default_factory=list)


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
class RelaySensorCfg:
    """One agent the collector will accept batches from."""
    id: str = ""
    key: str = ""


@dataclass
class RelayCfg:
    """Multi-sensor relay. Off by default; this is the only thing in the
    daemon that talks to another host on its own initiative.

    `agent` runs the full pipeline locally, dispatches nothing, and pushes
    records to a collector. `collector` additionally accepts those pushes.
    Relayed data is quarantined in remote_* tables and can never overwrite
    this instance's own state.
    """
    mode: str = "off"                      # off | agent | collector

    # --- agent ---
    sensor_id: str = ""
    url: str = ""
    key: str = ""
    tls_fingerprint: list[str] = field(default_factory=list)
    batch_seconds: float = 30.0
    spool_max_bytes: int = 64 * 1024 * 1024
    spool_max_age_seconds: float = 86400.0
    allow_any_destination: bool = False

    # --- collector ---
    listen_host: str = ""
    listen_port: int = 18443
    listen_allow_any: bool = False
    cert_file: str = ""
    key_file: str = ""
    sensor_timeout_seconds: float = 180.0
    max_body_bytes: int = 8 * 1024 * 1024
    # Per KIND, and there are five kinds — so this bounds one batch at
    # 5x this many row operations inside a single store transaction,
    # which is time the collector's packet loop can be waiting. Lowered
    # from 20000 (100k rows, ~0.4s of store lock) because a bigger
    # batch buys an agent nothing it cannot get from two batches.
    max_records_per_batch: int = 5000
    max_batches_per_minute: int = 60
    clock_skew_seconds: float = 300.0
    remote_retention_days: float = 30.0
    # Retention bounds how OLD relayed rows get; this bounds how MANY. A
    # sensor holding a valid key can otherwise outrun a 30-day window by
    # orders of magnitude, so the cap is what makes collector disk usage a
    # function of sensor COUNT rather than of sensor BEHAVIOUR. 0 disables.
    max_rows_per_sensor: int = 250_000
    # Refuse to ingest when the filesystem holding the store is nearly
    # full. A wedged SQLite write is a far worse failure than a rejected
    # batch the agent will spool and resend. 0 disables.
    min_free_disk_mb: float = 256.0
    # Dedup bounds repeats of the SAME alert. This bounds distinct ones:
    # an authenticated sensor can otherwise drive 200 alerts per batch
    # into email, webhook and FTP at the batch rate. The alerts are still
    # stored and still on the dashboard; only the paging is capped.
    max_notifications_per_minute: int = 60
    sensors: list[RelaySensorCfg] = field(default_factory=list)

    @property
    def is_agent(self) -> bool:
        return self.mode == "agent"

    @property
    def is_collector(self) -> bool:
        return self.mode == "collector"

    def key_for(self, sensor_id: str) -> str | None:
        for s in self.sensors:
            if s.id == sensor_id:
                return s.key
        return None


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
    relay: RelayCfg = field(default_factory=RelayCfg)


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


# Every section `_from_dict` reads. A key outside this set is accepted but
# does nothing, which is the worst way for a config to be wrong: the
# daemon starts, reports healthy, and silently omits whatever that section
# was supposed to configure. `hound config-check` reports these.
KNOWN_SECTIONS = frozenset({
    "capture", "network", "thresholds", "alerts", "uptime", "store",
    "baseline", "snapshot", "web", "notify", "relay",
})


def normalize_fingerprint(raw: str) -> str:
    """Canonicalise a certificate fingerprint to `sha256:<64 lowercase hex>`.

    Operators get this value from one of two places, and they disagree on
    formatting: `hound relay` prints `sha256:ab12...`, while
    `openssl x509 -fingerprint -sha256` prints `AB:12:...` uppercase with
    colons. Comparing the raw strings means the openssl form never matches
    and the agent refuses to connect with "not in the pinned set", naming
    two values that look the same to a human reading them. Normalising both
    ends is the only way that error message is ever truthful.

    Returns "" for anything that is not a 64-hex-digit SHA-256 digest, so
    the caller can reject it rather than pin something unmatchable.
    """
    v = raw.strip().lower()
    for prefix in ("sha256:", "sha-256:", "sha256 fingerprint="):
        if v.startswith(prefix):
            v = v[len(prefix):]
            break
    v = v.replace(":", "").replace(" ", "")
    if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
        return ""
    return "sha256:" + v


def overbroad_lan_subnets(nets: list[str]) -> list[str]:
    """Public prefixes declared local that cover more than a /24.

    Declaring a range local suppresses off-network telemetry scoring for
    everything inside it and widens where a relay agent is willing to
    ship a whole flow table. Private ranges are exempt — 10.0.0.0/8 is an
    ordinary LAN and warning about it would just train operators to
    ignore the warning. A broad PUBLIC range is the one that silently
    turns a detection off.
    """
    out = []
    for raw in nets:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.is_private or net.is_loopback or net.is_link_local:
            continue
        limit = 24 if net.version == 4 else 48
        if net.prefixlen < limit:
            out.append(str(net))
    return out


def unknown_sections(data: dict) -> list[str]:
    """Top-level keys the loader will ignore. Typos, or settings for a
    version that is not this one. Either way the operator should hear it."""
    return sorted(k for k in data if k not in KNOWN_SECTIONS)


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


# The shared secret is the only thing standing between a host that can
# reach the ingest port and the ability to author alerts on the collector.
# A short one is brute-forceable offline against a single captured batch.
_MIN_KEY_LEN = 16


def _require_strong_key(key: str, where: str) -> None:
    if len(key) < _MIN_KEY_LEN:
        raise ValueError(
            f"config: {where} is {len(key)} characters; at least "
            f"{_MIN_KEY_LEN} are required. This secret is the only thing "
            f"authenticating a relay sensor, and a short one can be "
            f"brute-forced offline from one captured batch. Generate one "
            f'with: python3 -c "import secrets; '
            f'print(secrets.token_urlsafe(32))"'
        )


def _pins(raw) -> list[str]:
    """Normalise and validate pinned fingerprints.

    A malformed pin is refused rather than carried through: it can never
    match a real certificate, so keeping it would turn a typo into a
    permanently failing connection diagnosed as a network problem.
    """
    out = []
    for f in raw:
        text = str(f).strip()
        if not text:
            continue
        norm = normalize_fingerprint(text)
        if not norm:
            raise ValueError(
                f"config: [relay].tls_fingerprint entry {text!r} is not a "
                f"SHA-256 certificate fingerprint. Expected 64 hex digits, "
                f"optionally prefixed 'sha256:' and optionally "
                f"colon-separated. Run `hound relay <config>` on the "
                f"collector to print the right value."
            )
        out.append(norm)
    return out


def _relay_from(data: dict, network: "NetworkCfg") -> RelayCfg:
    """Parse and validate [relay].

    The validation here is the difference between a relay and an
    exfiltration channel, so it refuses rather than warns.
    """
    rl = data.get("relay", {})
    sensors_raw = rl.get("sensor", [])
    if isinstance(sensors_raw, dict):
        sensors_raw = [sensors_raw]

    fp = rl.get("tls_fingerprint", [])
    if isinstance(fp, str):
        fp = [fp] if fp else []

    cfg = RelayCfg(
        mode=str(rl.get("mode", "off")).strip().lower(),
        sensor_id=str(rl.get("sensor_id", "")).strip(),
        url=str(rl.get("url", "")).strip(),
        key=str(rl.get("key", "")),
        tls_fingerprint=_pins(fp),
        batch_seconds=float(rl.get("batch_seconds", 30.0)),
        spool_max_bytes=int(rl.get("spool_max_bytes", 64 * 1024 * 1024)),
        spool_max_age_seconds=float(rl.get("spool_max_age_seconds", 86400.0)),
        allow_any_destination=bool(rl.get("allow_any_destination", False)),
        listen_host=str(rl.get("listen_host", "")).strip(),
        listen_port=int(rl.get("listen_port", 18443)),
        listen_allow_any=bool(rl.get("listen_allow_any", False)),
        cert_file=str(rl.get("cert_file", "")).strip(),
        key_file=str(rl.get("key_file", "")).strip(),
        sensor_timeout_seconds=float(rl.get("sensor_timeout_seconds", 180.0)),
        max_body_bytes=int(rl.get("max_body_bytes", 8 * 1024 * 1024)),
        max_records_per_batch=int(rl.get("max_records_per_batch", 5000)),
        max_batches_per_minute=int(rl.get("max_batches_per_minute", 60)),
        clock_skew_seconds=float(rl.get("clock_skew_seconds", 300.0)),
        remote_retention_days=float(rl.get("remote_retention_days", 30.0)),
        max_rows_per_sensor=int(rl.get("max_rows_per_sensor", 250_000)),
        min_free_disk_mb=float(rl.get("min_free_disk_mb", 256.0)),
        max_notifications_per_minute=int(
            rl.get("max_notifications_per_minute", 60)),
        sensors=[
            RelaySensorCfg(id=str(x.get("id", "")).strip(),
                           key=str(x.get("key", "")))
            for x in sensors_raw
        ],
    )

    if cfg.mode not in ("off", "agent", "collector"):
        raise ValueError(
            f"config: [relay].mode must be off, agent or collector, "
            f"got {cfg.mode!r}"
        )
    if cfg.mode == "off":
        return cfg

    if cfg.mode == "agent":
        if not cfg.sensor_id:
            raise ValueError("config: [relay].sensor_id is required in agent mode")
        if not cfg.key:
            raise ValueError("config: [relay].key is required in agent mode")
        _require_strong_key(cfg.key, "[relay].key")
        if not cfg.url:
            raise ValueError("config: [relay].url is required in agent mode")
        host = _relay_url_host(cfg.url)
        try:
            dest = ipaddress.ip_address(host)
        except ValueError:
            # The daemon does no DNS anywhere else; a name here would also
            # make the destination depend on whatever resolves it.
            raise ValueError(
                f"config: [relay].url host {host!r} must be an IP address. "
                f"Hostnames are not supported — the daemon does no DNS "
                f"resolution."
            ) from None
        if not cfg.allow_any_destination and not _is_local_dest(dest, network):
            raise ValueError(
                f"config: [relay].url points at {host}, which is outside "
                f"private address space and [network].lan_subnets. A relay "
                f"ships this segment's whole flow table, so an off-network "
                f"destination is refused. Set "
                f"[relay].allow_any_destination = true if that is genuinely "
                f"what you want."
            )
        if not cfg.tls_fingerprint:
            raise ValueError(
                "config: [relay].tls_fingerprint is required in agent mode. "
                "Without it the agent cannot tell the collector from anything "
                "else answering on that address. Run `hound relay` on the "
                "collector to print it."
            )

    if cfg.mode == "collector":
        if not cfg.listen_host:
            raise ValueError(
                "config: [relay].listen_host is required in collector mode — "
                "name the address to listen on rather than defaulting to all "
                "of them."
            )
        if cfg.listen_host in ("0.0.0.0", "::") and not cfg.listen_allow_any:
            raise ValueError(
                f"config: [relay].listen_host = {cfg.listen_host!r} would "
                f"accept ingest on every interface, including WAN. Name a "
                f"single address, or set [relay].listen_allow_any = true if "
                f"you really mean it."
            )
        if not cfg.sensors:
            raise ValueError(
                "config: collector mode needs at least one [[relay.sensor]] "
                "with an id and a key"
            )
        seen = set()
        for sensor in cfg.sensors:
            if not sensor.id or not sensor.key:
                raise ValueError(
                    "config: every [[relay.sensor]] needs both id and key"
                )
            if sensor.id in seen:
                raise ValueError(
                    f"config: duplicate [[relay.sensor]] id {sensor.id!r}"
                )
            _require_strong_key(sensor.key, f"[[relay.sensor]] {sensor.id!r} key")
            seen.add(sensor.id)
    return cfg


def _relay_url_host(url: str) -> str:
    """Host portion of a relay URL, without importing urllib for one parse."""
    rest = url.split("://", 1)[-1]
    rest = rest.split("/", 1)[0]
    if rest.startswith("["):                      # bracketed IPv6
        return rest[1:].split("]", 1)[0]
    return rest.rsplit(":", 1)[0] if ":" in rest else rest


def _is_local_dest(dest, network: "NetworkCfg") -> bool:
    from surveillancehound.discover import _LAN_NETWORKS
    nets = list(_LAN_NETWORKS) + [
        ipaddress.ip_network(c, strict=False) for c in network.lan_subnets
    ]
    return any(dest in n for n in nets)


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
        lan_subnets=_networks(net, "lan_subnets"),
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
        relay=_relay_from(data, network),
    )
