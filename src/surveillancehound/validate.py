"""Validation for records arriving from a relay agent.

Everything the daemon normally stores is produced by its own code: `kind`
comes from a closed set of constants, severities from another, addresses from
the packet parser, counters from Python integers. Every consumer downstream
quietly relies on that. Relayed records come from a different host — one that
sits on the camera segment and runs third-party software — so none of it
holds any more, and this module is where it is re-established.

Why that matters more than it sounds:

  * SQLite is dynamically typed and will happily store a string in an
    INTEGER column. The dashboard interpolates fields it believes are
    numeric straight into innerHTML, so a flow whose `packets` is
    `<img src=x onerror=...>` is stored XSS in the firewall administrator's
    browser.
  * `kind` reaches an FTP filename, a syslog MSGID and an email header. A
    `../` in it is path traversal on the FTP server.
  * `summary` is written raw into a newline-delimited log that SIEMs tail. A
    newline in it forges security events.
  * `json.loads` accepts NaN and Infinity by default, which then propagate
    into availability arithmetic and comparisons that silently stop working.

So: closed sets stay closed, numbers are finite and bounded, strings are
capped and stripped of control characters, unknown keys are dropped, and
anything that does not fit rejects the whole batch rather than being coerced
into something plausible. Partial acceptance would mean an attacker choosing
which half of a record survives.
"""

from __future__ import annotations

import ipaddress
import json
import math
from typing import Any

from surveillancehound.alerts import (
    KIND_BEHAVIORAL_ANOMALY, KIND_BULK_INBOUND, KIND_CAMERA_NEVER_SEEN,
    KIND_CAMERA_OFFLINE, KIND_CAMERA_RECOVERED, KIND_CAMERA_TO_CAMERA,
    KIND_CAPTURE_STALLED, KIND_CONTROL_CHANNEL, KIND_NEW_DEVICE,
    KIND_NEW_PEER, KIND_TELEMETRY_OFFNET,
)
from surveillancehound.notify import _SEVERITY_RANK

# Imported rather than re-listed so they cannot drift apart from the code
# that produces them.
ALERT_KINDS = frozenset({
    KIND_BULK_INBOUND, KIND_CONTROL_CHANNEL, KIND_TELEMETRY_OFFNET,
    KIND_CAMERA_TO_CAMERA, KIND_NEW_DEVICE, KIND_NEW_PEER,
    KIND_CAMERA_OFFLINE, KIND_CAMERA_RECOVERED, KIND_CAMERA_NEVER_SEEN,
    KIND_CAPTURE_STALLED, KIND_BEHAVIORAL_ANOMALY,
})
SEVERITIES = frozenset(_SEVERITY_RANK)
ROLES = frozenset({"camera", "nvr", "other"})
STATES = frozenset({"up", "down", "never_seen", "unknown"})
PROTOS = frozenset({"tcp", "udp", "icmp", "icmpv6", "other"})
CLASSIFICATIONS = frozenset({
    "bulk_inbound", "control_channel_suspect", "telemetry_offnet",
    "manufacturer", "lan_normal", "external_other", "camera_to_camera",
    "normal",
})
OUTAGE_CAUSES = frozenset({"silence", "never_seen"})

MAX_STR = 1024
MAX_SUMMARY = 4096
# Generous but finite. A counter past this is a bug or an attack, and either
# way storing it helps nobody.
MAX_COUNT = 10**12
# Seconds. Rejects both epoch-0 nonsense and far-future timestamps that would
# poison availability windows.
MIN_TS = 946_684_800.0        # 2000-01-01
MAX_TS = 4_102_444_800.0      # 2100-01-01


class ValidationError(ValueError):
    """A relayed record was not acceptable. Rejects the whole batch."""


def loads_strict(body: bytes) -> Any:
    """json.loads that refuses NaN and Infinity.

    The default accepts them, and they survive all the way into availability
    arithmetic where every comparison against them is silently False.
    """
    def _reject(value: str):
        raise ValidationError(f"non-finite JSON constant: {value}")

    try:
        return json.loads(body.decode("utf-8"), parse_constant=_reject)
    except UnicodeDecodeError as e:
        raise ValidationError(f"body is not valid UTF-8: {e}") from None
    except json.JSONDecodeError as e:
        raise ValidationError(f"malformed JSON: {e}") from None


def clean_str(value: Any, field: str, max_len: int = MAX_STR) -> str:
    """A bounded, control-character-free string."""
    if not isinstance(value, str):
        raise ValidationError(f"{field}: expected a string, got {type(value).__name__}")
    if len(value) > max_len:
        raise ValidationError(f"{field}: longer than {max_len} characters")
    # Strip rather than reject: a control character is never meaningful here,
    # and the damage (log injection, header splitting) is in the character
    # surviving, not in the record existing.
    cleaned = "".join(ch for ch in value if ch >= " " and ch != "\x7f")
    return cleaned


def clean_choice(value: Any, allowed: frozenset[str], field: str) -> str:
    v = clean_str(value, field, 64)
    if v not in allowed:
        raise ValidationError(
            f"{field}: {v!r} is not one of {sorted(allowed)}"
        )
    return v


def clean_ip(value: Any, field: str, allow_empty: bool = False) -> str:
    v = clean_str(value, field, 64)
    if not v:
        if allow_empty:
            return ""
        raise ValidationError(f"{field}: empty address")
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise ValidationError(f"{field}: {v!r} is not an IP address") from None
    return v


def clean_int(value: Any, field: str, lo: int = 0, hi: int = MAX_COUNT) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field}: expected a number, got {type(value).__name__}")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValidationError(f"{field}: not finite")
    v = int(value)
    if not (lo <= v <= hi):
        raise ValidationError(f"{field}: {v} outside [{lo}, {hi}]")
    return v


def clean_float(value: Any, field: str, lo: float = 0.0,
                hi: float = float(MAX_COUNT)) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{field}: expected a number, got {type(value).__name__}")
    v = float(value)
    if not math.isfinite(v):
        raise ValidationError(f"{field}: not finite")
    if not (lo <= v <= hi):
        raise ValidationError(f"{field}: {v} outside [{lo}, {hi}]")
    return v


def clean_ts(value: Any, field: str, allow_zero: bool = False) -> float:
    v = clean_float(value, field, lo=0.0, hi=MAX_TS)
    if v == 0.0:
        if allow_zero:
            return 0.0
        raise ValidationError(f"{field}: zero timestamp")
    if v < MIN_TS:
        raise ValidationError(f"{field}: {v} is implausibly early")
    return v


def clean_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{field}: expected a boolean")
    return value


def clean_port(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return clean_int(value, field, lo=0, hi=65535)


def _require(raw: Any, field: str) -> dict:
    if not isinstance(raw, dict):
        raise ValidationError(f"{field}: expected an object")
    return raw


def validate_device(raw: Any) -> dict:
    r = _require(raw, "device")
    return {
        "ip": clean_ip(r.get("ip"), "device.ip"),
        "role": clean_choice(r.get("role", "other"), ROLES, "device.role"),
        "first_seen": clean_ts(r.get("first_seen", 0.0), "device.first_seen", True),
        "last_seen": clean_ts(r.get("last_seen", 0.0), "device.last_seen", True),
        "packet_count": clean_int(r.get("packet_count", 0), "device.packet_count"),
        "byte_count": clean_int(r.get("byte_count", 0), "device.byte_count"),
    }


def validate_flow(raw: Any) -> dict:
    r = _require(raw, "flow")
    return {
        "remote_id": clean_remote_id(r.get("remote_id"), "flow.remote_id"),
        "src_ip": clean_ip(r.get("src_ip"), "flow.src_ip"),
        "src_port": clean_port(r.get("src_port"), "flow.src_port"),
        "dst_ip": clean_ip(r.get("dst_ip"), "flow.dst_ip"),
        "dst_port": clean_port(r.get("dst_port"), "flow.dst_port"),
        "proto": clean_choice(r.get("proto", "other"), PROTOS, "flow.proto"),
        "first_seen": clean_ts(r.get("first_seen", 0.0), "flow.first_seen", True),
        "last_seen": clean_ts(r.get("last_seen", 0.0), "flow.last_seen", True),
        "packets": clean_int(r.get("packets", 0), "flow.packets"),
        "bytes": clean_int(r.get("bytes", 0), "flow.bytes"),
        "bytes_to_camera": clean_int(r.get("bytes_to_camera", 0), "flow.bytes_to_camera"),
        "bytes_from_camera": clean_int(r.get("bytes_from_camera", 0), "flow.bytes_from_camera"),
        "tcp_flags_seen": clean_str(r.get("tcp_flags_seen", ""), "flow.tcp_flags_seen", 16),
        "classification": clean_choice(
            r.get("classification", "normal"), CLASSIFICATIONS, "flow.classification"),
    }


def validate_alert(raw: Any) -> dict:
    r = _require(raw, "alert")
    return {
        "remote_id": clean_remote_id(r.get("remote_id"), "alert.remote_id"),
        "ts": clean_ts(r.get("ts"), "alert.ts"),
        # capture_stalled legitimately carries no device
        "device_ip": clean_ip(r.get("device_ip", ""), "alert.device_ip", True),
        "kind": clean_choice(r.get("kind"), ALERT_KINDS, "alert.kind"),
        "severity": clean_choice(r.get("severity"), SEVERITIES, "alert.severity"),
        "summary": clean_str(r.get("summary", ""), "alert.summary", MAX_SUMMARY),
        "detail": clean_str(r.get("detail", ""), "alert.detail", MAX_SUMMARY),
        "dedup_key": clean_str(r.get("dedup_key", ""), "alert.dedup_key", 256),
    }


def validate_outage(raw: Any) -> dict:
    r = _require(raw, "outage")
    up_at = r.get("up_at")
    return {
        "remote_id": clean_remote_id(r.get("remote_id"), "outage.remote_id"),
        "camera_ip": clean_ip(r.get("camera_ip"), "outage.camera_ip"),
        "down_since": clean_ts(r.get("down_since"), "outage.down_since"),
        "up_at": None if up_at is None else clean_ts(up_at, "outage.up_at"),
        "last_seen_before": clean_ts(
            r.get("last_seen_before", 0.0), "outage.last_seen_before", True),
        "cause": clean_choice(r.get("cause", "silence"), OUTAGE_CAUSES, "outage.cause"),
    }


def validate_uptime(raw: Any) -> dict:
    r = _require(raw, "uptime")
    availability = r.get("availability")
    down_since = r.get("down_since")
    return {
        "ip": clean_ip(r.get("ip"), "uptime.ip"),
        "role": clean_choice(r.get("role", "camera"), ROLES, "uptime.role"),
        "state": clean_choice(r.get("state"), STATES, "uptime.state"),
        "last_seen": clean_ts(r.get("last_seen", 0.0), "uptime.last_seen", True),
        "first_seen": clean_ts(r.get("first_seen", 0.0), "uptime.first_seen", True),
        "down_since": None if down_since is None else clean_ts(down_since, "uptime.down_since"),
        "current_downtime": clean_float(r.get("current_downtime", 0.0), "uptime.current_downtime"),
        "outage_count": clean_int(r.get("outage_count", 0), "uptime.outage_count"),
        "downtime_seconds": clean_float(r.get("downtime_seconds", 0.0), "uptime.downtime_seconds"),
        "monitored_seconds": clean_float(r.get("monitored_seconds", 0.0), "uptime.monitored_seconds"),
        "availability": (
            None if availability is None
            else clean_float(availability, "uptime.availability", 0.0, 1.0)
        ),
    }


def validate_monitor(raw: Any) -> dict:
    r = _require(raw, "monitor")
    return {
        "alive": clean_bool(r.get("alive", False), "monitor.alive"),
        "blind": clean_bool(r.get("blind", False), "monitor.blind"),
        "last_activity_ts": clean_ts(
            r.get("last_activity_ts", 0.0), "monitor.last_activity_ts", True),
    }


_KINDS = {
    "devices": validate_device,
    "flows": validate_flow,
    "alerts": validate_alert,
    "outages": validate_outage,
    "uptime": validate_uptime,
}


# Kinds whose records carry the sensor's own row id. The collector keys
# storage on (sensor_id, remote_id), so these must be unique per batch.
_ID_KINDS = ("flows", "alerts", "outages")


# The agent's identity for one run. It is now part of the primary key of
# every relayed row, so it has to be as strictly handled as any other wire
# string — and strictly non-empty, because an empty value collapses the
# (sensor, instance, row) key back to (sensor, row) and reinstates the
# cross-instance clobbering that key exists to prevent.
_INSTANCE_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)
MAX_INSTANCE_LEN = 64


def clean_remote_id(value: Any, field: str) -> int:
    """The sensor's own row id for a record. Required, and >= 1.

    Defaulting it to 0 meant an agent that omitted the field had every
    record collide on id 0: the collector stores one row per (sensor,
    instance, remote_id), so exactly ONE flow, ONE alert and ONE outage
    were ever kept for that sensor, while the agent advanced its
    watermark on the 200 and never resent. Silent, permanent, and
    indistinguishable from a quiet segment.
    """
    if value is None:
        raise ValidationError(
            f"{field} is required: without it every record collides on a "
            f"single id and all but the first are silently discarded"
        )
    return clean_int(value, field, lo=1)


def clean_instance_id(value: Any, field: str = "instance_id") -> str:
    """Validate an agent instance id.

    Restricted to an opaque token charset rather than merely stripped:
    this value is persisted on every relayed row, echoed by the API, and
    interpolated into log lines, and the agent only ever generates
    `secrets.token_hex(8)`. Nothing legitimate needs anything else.
    """
    v = clean_str(value, field, MAX_INSTANCE_LEN)
    if not v:
        raise ValidationError(
            f"{field} must not be empty: an empty instance id collapses "
            f"the per-record key and lets one run's records overwrite "
            f"another's"
        )
    bad = sorted(set(v) - _INSTANCE_CHARS)
    if bad:
        raise ValidationError(
            f"{field}: unexpected character(s) {bad!r}; expected an opaque "
            f"token of letters, digits, dash, dot or underscore"
        )
    return v


def validate_records(raw: Any, max_per_kind: int) -> dict:
    """Validate a whole `records` object. Raises on the first bad record.

    All-or-nothing on purpose: accepting the valid half of a batch would let
    an attacker choose which half of a record set survives.
    """
    r = _require(raw, "records")
    unknown = set(r) - set(_KINDS) - {"monitor"}
    if unknown:
        raise ValidationError(f"records: unknown kinds {sorted(unknown)}")

    out: dict = {}
    for kind, validator in _KINDS.items():
        items = r.get(kind, [])
        if not isinstance(items, list):
            raise ValidationError(f"records.{kind}: expected a list")
        if len(items) > max_per_kind:
            raise ValidationError(
                f"records.{kind}: {len(items)} records exceeds the "
                f"per-kind cap of {max_per_kind}"
            )
        out[kind] = [validator(item) for item in items]

        # `remote_id` is the sensor's own primary key for the record, and
        # the collector stores one row per (sensor_id, remote_id). Repeats
        # within a batch therefore collapse to a single stored row while
        # still being processed individually downstream — which defeated
        # relayed-alert dedup entirely: 200 copies of one alert sharing a
        # remote_id produced 200 notifications from one stored row. A
        # well-formed agent never emits a duplicate, so refuse the batch
        # rather than silently keeping whichever copy happens to win.
        if kind in _ID_KINDS:
            seen: set[int] = set()
            for item in out[kind]:
                rid = item["remote_id"]
                if rid in seen:
                    raise ValidationError(
                        f"records.{kind}: duplicate remote_id {rid} in one "
                        f"batch; each record needs its own id"
                    )
                seen.add(rid)

    monitor = r.get("monitor")
    out["monitor"] = validate_monitor(monitor) if monitor is not None else None
    return out
