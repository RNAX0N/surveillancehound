"""SQLite persistence — devices, flows, alerts, notifications.

A long-running daemon needs to remember what it has seen, so a restart does
not amnesiacally re-alert on every camera as 'newly discovered'. SQLite is
the right call: zero ops, file-based, atomic enough for one writer (the
daemon) + occasional readers (`hound alerts`).

Schema:

  devices       — one row per observed IP. role = camera | nvr | other.
                  first_seen, last_seen, packet_count, byte_count.
  flows         — one row per (src, sport, dst, dport, proto). aggregated.
                  first_seen, last_seen, packets, bytes, bytes_to_camera,
                  bytes_from_camera, tcp_flags_seen, classification.
  alerts        — one row per generated alert.
                  device_ip, kind, severity, summary, detail, ts,
                  notified_channels (csv), notified_at, dedup_key.
  notifications — one row per dispatch attempt (audit log).
                  alert_id, channel_type, attempted_at, ok, error.
  outages       — one row per camera downtime window. An OPEN row (up_at
                  IS NULL) *is* the camera's current down-state, so a daemon
                  restart resumes mid-outage instead of forgetting it.
  monitor_sessions — one row per daemon run. Availability is only honest when
                  computed over time the monitor was actually watching; this
                  table is what makes that subtraction possible.

Writes happen at flow-flush time (TTL eviction) and alert time. Reads are
served by the CLI. WAL mode + a 30s busy timeout make this safe under the
daemon's continuous write load.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class DeviceRow:
    ip: str
    role: str  # camera | nvr | other
    first_seen: float
    last_seen: float
    packet_count: int
    byte_count: int


@dataclass
class FlowRow:
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    proto: str
    first_seen: float
    last_seen: float
    packets: int
    bytes: int
    bytes_to_camera: int
    bytes_from_camera: int
    tcp_flags_seen: str
    classification: str


@dataclass
class AlertRow:
    id: int | None
    ts: float
    device_ip: str
    kind: str
    severity: str
    summary: str
    detail: str
    dedup_key: str
    notified_channels: str = ""


@dataclass
class SnapshotRow:
    """One pcap snapshot dumped on alert. `path` is on the local fs."""
    id: int | None
    alert_id: int
    camera_ip: str
    path: str
    byte_count: int
    packet_count: int
    created_at: float


@dataclass
class OutageRow:
    """One camera downtime window.

    `up_at is None` means the outage is still open — that open row IS the
    camera's down-state, which is why there is no separate state table and
    why a restart resumes an outage rather than re-firing it.

    `last_seen_before` is the camera's last activity before it went quiet
    (0.0 when the camera has never been observed at all). `cause` is
    'silence' or 'never_seen'.
    """
    id: int | None
    camera_ip: str
    down_since: float
    up_at: float | None
    last_seen_before: float
    cause: str
    alert_id: int | None = None

    @property
    def is_open(self) -> bool:
        return self.up_at is None

    def duration(self, now: float) -> float:
        return max(0.0, (self.up_at if self.up_at is not None else now) - self.down_since)


@dataclass
class MonitorSessionRow:
    """One daemon run. `ended_at is None` while it is still running.

    `clean_exit` is False when the capture died (daemon.run() returned
    False), which is how an operator tells a deliberate stop from a crash.
    """
    id: int | None
    started_at: float
    ended_at: float | None
    source: str          # interface name or pcap path
    clean_exit: bool = False


@dataclass
class CameraUptimeRow:
    """Derived per-camera availability over a reporting window.

    `availability` is None when the monitor was not watching at all during
    the window. That renders as 'n/a' — reporting 0% or 100% from zero
    observation would be a fabrication.
    """
    ip: str
    role: str
    state: str                   # up | down | never_seen
    last_seen: float             # 0.0 == never observed
    first_seen: float
    down_since: float | None     # start of the current open outage, if any
    current_downtime: float
    outage_count: int
    downtime_seconds: float
    monitored_seconds: float
    availability: float | None   # 0.0..1.0, or None


@dataclass
class RemoteSensorRow:
    sensor_id: str
    instance_id: str
    first_seen: float
    last_seen: float
    last_seq: int
    clock_skew: float
    batches: int
    records: int
    bytes: int
    mon_alive: bool
    mon_blind: bool
    mon_last_activity_ts: float


@dataclass
class BaselineRow:
    """One Welford bucket — per (camera_ip, weekday, hour, feature)."""
    camera_ip: str
    weekday: int   # 0..6 (Monday..Sunday, per datetime.weekday())
    hour: int      # 0..23 (local time)
    feature: str
    n: int
    mean: float
    m2: float
    last_updated: float


@dataclass
class BaselineForestRow:
    """One Half-Space Forest serialized to a blob — per (camera_ip, weekday, hour).

    The whole forest is one row per bucket (versus Welford's per-feature
    rows) because the trees score features jointly and the leaf-mass arrays
    don't decompose. ``blob`` is whatever ``HSForest.serialize()`` returned.
    """
    camera_ip: str
    weekday: int
    hour: int
    n_samples: int
    n_samples_in_window: int
    has_reference: bool
    blob: bytes
    last_updated: float


_DDL = """
CREATE TABLE IF NOT EXISTS devices (
    ip            TEXT PRIMARY KEY,
    role          TEXT NOT NULL DEFAULT 'other',
    first_seen    REAL NOT NULL,
    last_seen     REAL NOT NULL,
    packet_count  INTEGER NOT NULL DEFAULT 0,
    byte_count    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_devices_role ON devices(role);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);

CREATE TABLE IF NOT EXISTS flows (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip              TEXT NOT NULL,
    src_port            INTEGER,
    dst_ip              TEXT NOT NULL,
    dst_port            INTEGER,
    proto               TEXT NOT NULL,
    first_seen          REAL NOT NULL,
    last_seen           REAL NOT NULL,
    packets             INTEGER NOT NULL,
    bytes               INTEGER NOT NULL,
    bytes_to_camera     INTEGER NOT NULL DEFAULT 0,
    bytes_from_camera   INTEGER NOT NULL DEFAULT 0,
    tcp_flags_seen      TEXT NOT NULL DEFAULT '',
    classification      TEXT NOT NULL DEFAULT 'normal'
);
CREATE INDEX IF NOT EXISTS idx_flows_classification ON flows(classification);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen);

CREATE TABLE IF NOT EXISTS alerts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                  REAL NOT NULL,
    device_ip           TEXT NOT NULL,
    kind                TEXT NOT NULL,
    severity            TEXT NOT NULL,
    summary             TEXT NOT NULL,
    detail              TEXT NOT NULL,
    dedup_key           TEXT NOT NULL,
    notified_channels   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(dedup_key, ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id        INTEGER NOT NULL,
    channel_type    TEXT NOT NULL,
    attempted_at    REAL NOT NULL,
    ok              INTEGER NOT NULL,
    error           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_notifications_alert ON notifications(alert_id);

CREATE TABLE IF NOT EXISTS baselines (
    camera_ip      TEXT NOT NULL,
    weekday        INTEGER NOT NULL,
    hour           INTEGER NOT NULL,
    feature        TEXT NOT NULL,
    n              INTEGER NOT NULL,
    mean           REAL NOT NULL,
    m2             REAL NOT NULL,
    last_updated   REAL NOT NULL,
    PRIMARY KEY (camera_ip, weekday, hour, feature)
);

CREATE TABLE IF NOT EXISTS baseline_forests (
    camera_ip            TEXT NOT NULL,
    weekday              INTEGER NOT NULL,
    hour                 INTEGER NOT NULL,
    n_samples            INTEGER NOT NULL,    -- cumulative samples ever seen
    n_samples_in_window  INTEGER NOT NULL,    -- progress toward next rollover
    has_reference        INTEGER NOT NULL,    -- 0|1, true after first rollover
    blob                 BLOB NOT NULL,       -- compact serialized forest
    last_updated         REAL NOT NULL,
    PRIMARY KEY (camera_ip, weekday, hour)
);

CREATE TABLE IF NOT EXISTS snapshots (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id      INTEGER NOT NULL,
    camera_ip     TEXT NOT NULL,
    path          TEXT NOT NULL,
    byte_count    INTEGER NOT NULL,
    packet_count  INTEGER NOT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_alert ON snapshots(alert_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_camera ON snapshots(camera_ip);

CREATE TABLE IF NOT EXISTS outages (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    camera_ip         TEXT NOT NULL,
    down_since        REAL NOT NULL,
    up_at             REAL,              -- NULL while the outage is open
    last_seen_before  REAL NOT NULL,     -- 0.0 when never observed
    cause             TEXT NOT NULL,     -- 'silence' | 'never_seen'
    alert_id          INTEGER            -- the camera_offline alert, if any
);
CREATE INDEX IF NOT EXISTS idx_outages_camera ON outages(camera_ip, down_since);
CREATE INDEX IF NOT EXISTS idx_outages_open ON outages(up_at);

CREATE TABLE IF NOT EXISTS monitor_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  REAL NOT NULL,
    ended_at    REAL,                    -- NULL while running
    source      TEXT NOT NULL,           -- interface name or pcap path
    clean_exit  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_monitor_sessions_started ON monitor_sessions(started_at);

-- Single-row heartbeat: when the daemon last saw a packet of ANY kind.
-- Reader processes (web, CLI) cannot contact the daemon, so this is how
-- they tell "the sensor is watching" from "the sensor is blind". It has to
-- be its own signal: devices.last_seen only ticks for camera/NVR roles,
-- and the flows table only gains rows at eviction, so both are stale by
-- design exactly when every camera is dead — which is the case the stall
-- indicator exists for.
CREATE TABLE IF NOT EXISTS monitor_heartbeat (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    last_packet_at  REAL NOT NULL,
    updated_at      REAL NOT NULL
);

-- ---------------------------------------------------------------- relay --
-- Records relayed from another sensor live ONLY in these tables. No code on
-- the ingest path writes any of the nine tables above, which is what makes
-- "a compromised agent cannot corrupt this instance's state" a structural
-- property rather than a validation rule that could be bypassed. The test
-- suite enforces it with a sqlite authorizer, not by assertion.
CREATE TABLE IF NOT EXISTS remote_sensors (
    sensor_id            TEXT PRIMARY KEY,
    instance_id          TEXT NOT NULL DEFAULT '',
    first_seen           REAL NOT NULL,
    last_seen            REAL NOT NULL,
    last_seq             INTEGER NOT NULL DEFAULT 0,
    clock_skew           REAL NOT NULL DEFAULT 0.0,
    batches              INTEGER NOT NULL DEFAULT 0,
    records              INTEGER NOT NULL DEFAULT 0,
    bytes                INTEGER NOT NULL DEFAULT 0,
    mon_alive            INTEGER NOT NULL DEFAULT 0,
    mon_blind            INTEGER NOT NULL DEFAULT 0,
    mon_last_activity_ts REAL NOT NULL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS remote_devices (
    sensor_id    TEXT NOT NULL,
    ip           TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'other',
    first_seen   REAL NOT NULL,
    last_seen    REAL NOT NULL,
    packet_count INTEGER NOT NULL DEFAULT 0,
    byte_count   INTEGER NOT NULL DEFAULT 0,
    ingested_at  REAL NOT NULL,
    PRIMARY KEY (sensor_id, ip)
);

CREATE TABLE IF NOT EXISTS remote_flows (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id         TEXT NOT NULL,
    remote_id         INTEGER NOT NULL,
    src_ip            TEXT NOT NULL,
    src_port          INTEGER,
    dst_ip            TEXT NOT NULL,
    dst_port          INTEGER,
    proto             TEXT NOT NULL,
    first_seen        REAL NOT NULL,
    last_seen         REAL NOT NULL,
    packets           INTEGER NOT NULL,
    bytes             INTEGER NOT NULL,
    bytes_to_camera   INTEGER NOT NULL DEFAULT 0,
    bytes_from_camera INTEGER NOT NULL DEFAULT 0,
    tcp_flags_seen    TEXT NOT NULL DEFAULT '',
    classification    TEXT NOT NULL DEFAULT 'normal',
    ingested_at       REAL NOT NULL,
    UNIQUE (sensor_id, remote_id)
);
CREATE INDEX IF NOT EXISTS idx_remote_flows_seen ON remote_flows(last_seen);

CREATE TABLE IF NOT EXISTS remote_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id   TEXT NOT NULL,
    remote_id   INTEGER NOT NULL,
    ts          REAL NOT NULL,
    device_ip   TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    summary     TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    dedup_key   TEXT NOT NULL,
    ingested_at REAL NOT NULL,
    UNIQUE (sensor_id, remote_id)
);
CREATE INDEX IF NOT EXISTS idx_remote_alerts_dedup ON remote_alerts(dedup_key, ts);
CREATE INDEX IF NOT EXISTS idx_remote_alerts_ts ON remote_alerts(ts);

-- Keyed on the agent's own row id so a close UPDATES its open row. Without
-- that key a recovery either inserts a duplicate (double-counting the
-- outage) or is dropped, leaving an outage open forever while the uptime
-- snapshot says the camera is up.
CREATE TABLE IF NOT EXISTS remote_outages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id        TEXT NOT NULL,
    remote_id        INTEGER NOT NULL,
    camera_ip        TEXT NOT NULL,
    down_since       REAL NOT NULL,
    up_at            REAL,
    last_seen_before REAL NOT NULL DEFAULT 0.0,
    cause            TEXT NOT NULL DEFAULT 'silence',
    ingested_at      REAL NOT NULL,
    UNIQUE (sensor_id, remote_id)
);

CREATE TABLE IF NOT EXISTS remote_uptime (
    sensor_id         TEXT NOT NULL,
    ip                TEXT NOT NULL,
    role              TEXT NOT NULL DEFAULT 'camera',
    state             TEXT NOT NULL,
    last_seen         REAL NOT NULL DEFAULT 0.0,
    first_seen        REAL NOT NULL DEFAULT 0.0,
    down_since        REAL,
    current_downtime  REAL NOT NULL DEFAULT 0.0,
    outage_count      INTEGER NOT NULL DEFAULT 0,
    downtime_seconds  REAL NOT NULL DEFAULT 0.0,
    monitored_seconds REAL NOT NULL DEFAULT 0.0,
    availability      REAL,
    reported_at       REAL NOT NULL,
    PRIMARY KEY (sensor_id, ip)
);

-- Relayed dispatch must not write `notifications`, whose alert_id
-- implicitly means alerts.id — relayed ids collide with local ones and
-- would make the audit trail ambiguous and attacker-writable.
CREATE TABLE IF NOT EXISTS remote_notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id       TEXT NOT NULL,
    remote_alert_id INTEGER NOT NULL,
    channel_type    TEXT NOT NULL,
    attempted_at    REAL NOT NULL,
    ok              INTEGER NOT NULL,
    error           TEXT NOT NULL DEFAULT ''
);
"""


def _remote_sensor_row(r) -> RemoteSensorRow:
    return RemoteSensorRow(
        sensor_id=r["sensor_id"], instance_id=r["instance_id"],
        first_seen=r["first_seen"], last_seen=r["last_seen"],
        last_seq=r["last_seq"], clock_skew=r["clock_skew"],
        batches=r["batches"], records=r["records"], bytes=r["bytes"],
        mon_alive=bool(r["mon_alive"]), mon_blind=bool(r["mon_blind"]),
        mon_last_activity_ts=r["mon_last_activity_ts"],
    )


def _outage_row(r) -> OutageRow:
    return OutageRow(
        id=r["id"], camera_ip=r["camera_ip"], down_since=r["down_since"],
        up_at=r["up_at"], last_seen_before=r["last_seen_before"],
        cause=r["cause"], alert_id=r["alert_id"],
    )


def _merge_spans(spans) -> list[tuple[float, float]]:
    """Sort and union a sequence of (start, end) intervals.

    Zero-length and inverted intervals are dropped — they contribute no
    time and would otherwise corrupt the merge.
    """
    ordered = sorted((a, b) for a, b in spans if b > a)
    merged: list[tuple[float, float]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _overlap_seconds(
    a: list[tuple[float, float]], b: list[tuple[float, float]],
) -> float:
    """Total length of the intersection of two merged, sorted span lists."""
    total = 0.0
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if hi > lo:
            total += hi - lo
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return total


class HoundStore:
    """Thread-safe wrapper over a SQLite connection. One process, one writer.

    Methods that read may be called from any thread; the internal lock
    serializes both reads and writes — simple, correct, plenty fast for this
    workload (camera traffic is hundreds of packets/sec, not millions)."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.executescript(_DDL)
        self._lock = threading.RLock()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ----- devices -----

    def upsert_device(
        self, ip: str, role: str, ts: float, packets: int, bytes_: int,
        *, first_seen: float | None = None,
    ) -> None:
        """Record observed activity for a device.

        `ts` must be when the traffic was SEEN, not when it was processed.
        `last_seen` only ever moves forward and `first_seen` only ever moves
        backward: flows are flushed out of time order relative to each other
        (eviction batches, shutdown drain), and a device's clock must not
        jitter backwards just because an older flow was processed last.
        A seeded-but-unobserved device carries `last_seen = 0.0`, and the
        MAX() keeps that marker from being resurrected as a real sighting.
        """
        fs = first_seen if first_seen is not None else ts
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO devices (ip, role, first_seen, last_seen,
                                        packet_count, byte_count)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                       last_seen = MAX(devices.last_seen, excluded.last_seen),
                       first_seen = CASE
                           WHEN devices.first_seen <= 0.0 THEN excluded.first_seen
                           ELSE MIN(devices.first_seen, excluded.first_seen)
                       END,
                       packet_count = packet_count + excluded.packet_count,
                       byte_count = byte_count + excluded.byte_count,
                       role = CASE
                           WHEN devices.role = 'other' THEN excluded.role
                           ELSE devices.role
                       END
                """,
                (ip, role, fs, ts, packets, bytes_),
            )

    def get_device(self, ip: str) -> DeviceRow | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM devices WHERE ip = ?", (ip,)
            ).fetchone()
        if r is None:
            return None
        return DeviceRow(
            ip=r["ip"], role=r["role"], first_seen=r["first_seen"],
            last_seen=r["last_seen"], packet_count=r["packet_count"],
            byte_count=r["byte_count"],
        )

    def list_devices(self) -> list[DeviceRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM devices ORDER BY last_seen DESC"
            ).fetchall()
        return [
            DeviceRow(
                ip=r["ip"], role=r["role"], first_seen=r["first_seen"],
                last_seen=r["last_seen"], packet_count=r["packet_count"],
                byte_count=r["byte_count"],
            )
            for r in rows
        ]

    def set_heartbeat(self, last_packet_at: float, now: float) -> None:
        """Record when the daemon last saw any packet. Called each tick."""
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO monitor_heartbeat (id, last_packet_at, updated_at)
                   VALUES (1, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       last_packet_at = excluded.last_packet_at,
                       updated_at = excluded.updated_at""",
                (last_packet_at, now),
            )

    def heartbeat(self) -> tuple[float, float]:
        """(last_packet_at, updated_at); (0.0, 0.0) if never written."""
        with self._lock:
            r = self._conn.execute(
                "SELECT last_packet_at, updated_at FROM monitor_heartbeat WHERE id = 1"
            ).fetchone()
        if r is None:
            return (0.0, 0.0)
        return (float(r["last_packet_at"]), float(r["updated_at"]))

    def latest_device_activity(self) -> float:
        """Newest observed activity across all devices, or 0.0 if none.

        Reader processes use this to judge whether the daemon is still
        seeing traffic. Do NOT use the flows table for that: a flow row is
        only written when the flow is EVICTED, which is `flow_ttl_seconds`
        (default 300) after its last packet, so the newest flow row is
        structurally always several minutes old and any freshness threshold
        below the TTL reads as permanently stalled. `devices.last_seen` is
        refreshed every tick by `touch_devices_last_seen`, so it tracks
        reality.
        """
        with self._lock:
            r = self._conn.execute(
                "SELECT MAX(last_seen) AS t FROM devices"
            ).fetchone()
        return float(r["t"]) if r is not None and r["t"] is not None else 0.0

    def device_ips(self) -> set[str]:
        with self._lock:
            return {r["ip"] for r in self._conn.execute("SELECT ip FROM devices")}

    def touch_devices_last_seen(self, mapping: dict[str, float]) -> None:
        """Bulk-refresh `last_seen` ONLY — no counters, no role change.

        The flow path (`upsert_device`) owns packet/byte counters and role
        promotion. This exists because `last_seen` used to advance only when
        a flow was evicted, which meant a camera holding one continuous RTSP
        stream never refreshed it and tripped `camera_offline` while healthy.

        The `last_seen < ?` guard keeps a late or out-of-order tick from
        moving a device's clock backwards.
        """
        if not mapping:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                "UPDATE devices SET last_seen = ? WHERE ip = ? AND last_seen < ?",
                [(ts, ip, ts) for ip, ts in mapping.items()],
            )

    def seed_device(self, ip: str, role: str, now: float) -> bool:
        """Register a configured camera that has never been observed.

        `last_seen = 0.0` is the 'never seen' marker — it is what makes a
        camera that was powered down before the daemon ever started visible
        to the uptime tracker. Returns True if a row was inserted; an
        existing row is never overwritten.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT OR IGNORE INTO devices
                       (ip, role, first_seen, last_seen, packet_count, byte_count)
                   VALUES (?, ?, ?, 0.0, 0, 0)""",
                (ip, role, now),
            )
            return cur.rowcount == 1

    # ----- outages -----

    def open_outage(self, o: OutageRow) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO outages (camera_ip, down_since, up_at,
                                        last_seen_before, cause, alert_id)
                   VALUES (?, ?, NULL, ?, ?, ?)""",
                (o.camera_ip, o.down_since, o.last_seen_before, o.cause, o.alert_id),
            )
            return cur.lastrowid

    def close_outage(self, outage_id: int, up_at: float) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE outages SET up_at = ? WHERE id = ? AND up_at IS NULL",
                (up_at, outage_id),
            )

    def set_outage_alert(self, outage_id: int, alert_id: int) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE outages SET alert_id = ? WHERE id = ?",
                (alert_id, outage_id),
            )

    def open_outage_for(self, camera_ip: str) -> OutageRow | None:
        with self._lock:
            r = self._conn.execute(
                """SELECT * FROM outages
                   WHERE camera_ip = ? AND up_at IS NULL
                   ORDER BY down_since DESC LIMIT 1""",
                (camera_ip,),
            ).fetchone()
        return _outage_row(r) if r is not None else None

    def open_outages(self) -> list[OutageRow]:
        """Every outage still open — used to resume state after a restart."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM outages WHERE up_at IS NULL ORDER BY down_since"
            ).fetchall()
        return [_outage_row(r) for r in rows]

    def list_outages(
        self, camera_ip: str | None = None, *,
        since: float | None = None, limit: int = 100,
    ) -> list[OutageRow]:
        q = "SELECT * FROM outages WHERE 1=1"
        params: list = []
        if camera_ip:
            q += " AND camera_ip = ?"
            params.append(camera_ip)
        if since is not None:
            q += " AND (up_at IS NULL OR up_at >= ?)"
            params.append(since)
        q += " ORDER BY down_since DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(q, params).fetchall()
        return [_outage_row(r) for r in rows]

    # ----- monitor sessions -----

    def start_monitor_session(self, now: float, source: str) -> int:
        """Open a session, closing any that were orphaned by a hard kill.

        A SIGKILL or power loss leaves `ended_at` NULL forever, and
        `monitored_spans` reads an open session as "running until now". That
        would count the entire dead period as monitored, and since no
        outages were recorded while nothing was running, every camera would
        report 100% availability for time nothing was watched — the exact
        fabricated figure this schema exists to prevent.

        An orphan is closed at the last moment we have evidence the monitor
        was alive: the newest device activity it recorded, floored at its
        own start and capped at now. `clean_exit` stays 0, which is how an
        operator tells a crash from a deliberate stop.
        """
        with self._lock, self._conn:
            evidence = self._conn.execute(
                "SELECT MAX(last_seen) AS t FROM devices"
            ).fetchone()
            last_activity = float(evidence["t"] or 0.0)
            orphans = self._conn.execute(
                "SELECT id, started_at FROM monitor_sessions WHERE ended_at IS NULL"
            ).fetchall()
            for o in orphans:
                ended = min(now, max(float(o["started_at"]), last_activity))
                self._conn.execute(
                    """UPDATE monitor_sessions
                       SET ended_at = ?, clean_exit = 0 WHERE id = ?""",
                    (ended, o["id"]),
                )
            if orphans:
                log.warning(
                    "store: closed %d monitor session(s) left open by an "
                    "unclean shutdown; their blind time is excluded from "
                    "availability", len(orphans),
                )
            cur = self._conn.execute(
                """INSERT INTO monitor_sessions (started_at, ended_at, source, clean_exit)
                   VALUES (?, NULL, ?, 0)""",
                (now, source),
            )
            return cur.lastrowid

    def end_monitor_session(self, session_id: int, now: float, clean: bool) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE monitor_sessions SET ended_at = ?, clean_exit = ? WHERE id = ?",
                (now, 1 if clean else 0, session_id),
            )

    def current_monitor_session(self) -> MonitorSessionRow | None:
        with self._lock:
            r = self._conn.execute(
                """SELECT * FROM monitor_sessions
                   ORDER BY started_at DESC LIMIT 1"""
            ).fetchone()
        if r is None:
            return None
        return MonitorSessionRow(
            id=r["id"], started_at=r["started_at"], ended_at=r["ended_at"],
            source=r["source"], clean_exit=bool(r["clean_exit"]),
        )

    def monitored_spans(self, since: float, until: float) -> list[tuple[float, float]]:
        """Disjoint, merged intervals during which the monitor was running.

        Each session is clipped to [since, until]; an open session (ended_at
        IS NULL) is treated as running right up to `until`. Availability is
        computed against these spans so time the daemon was stopped is never
        charged to a camera as downtime.
        """
        if until <= since:
            return []
        with self._lock:
            rows = self._conn.execute(
                """SELECT started_at, ended_at FROM monitor_sessions
                   WHERE started_at < ? AND (ended_at IS NULL OR ended_at > ?)
                   ORDER BY started_at""",
                (until, since),
            ).fetchall()
        return _merge_spans(
            (max(since, r["started_at"]),
             min(until, r["ended_at"] if r["ended_at"] is not None else until))
            for r in rows
        )

    def uptime_report(
        self, window_seconds: float, now: float,
    ) -> list[CameraUptimeRow]:
        """Per-camera availability over [now - window_seconds, now].

        Downtime is the overlap of the camera's outage spans with the spans
        during which the monitor was actually watching. A camera whose outage
        straddled a daemon restart is charged only for the monitored part.
        """
        since = now - max(0.0, window_seconds)
        monitored = self.monitored_spans(since, now)
        monitored_seconds = sum(b - a for a, b in monitored)
        with self._lock:
            devs = self._conn.execute(
                """SELECT * FROM devices WHERE role IN ('camera', 'nvr')
                   ORDER BY ip"""
            ).fetchall()
            outs = self._conn.execute(
                """SELECT * FROM outages
                   WHERE up_at IS NULL OR up_at >= ?""",
                (since,),
            ).fetchall()
        by_cam: dict[str, list[OutageRow]] = {}
        for r in outs:
            by_cam.setdefault(r["camera_ip"], []).append(_outage_row(r))

        report: list[CameraUptimeRow] = []
        for d in devs:
            cam_outs = by_cam.get(d["ip"], [])
            open_out = next((o for o in cam_outs if o.is_open), None)
            down_spans = _merge_spans(
                (max(since, o.down_since),
                 min(now, o.up_at if o.up_at is not None else now))
                for o in cam_outs
            )
            downtime = _overlap_seconds(down_spans, monitored)
            if monitored_seconds > 0:
                availability = max(
                    0.0, min(1.0, (monitored_seconds - downtime) / monitored_seconds),
                )
            else:
                availability = None
            if d["last_seen"] <= 0.0:
                state = "never_seen"
            elif open_out is not None:
                state = "down"
            else:
                state = "up"
            report.append(CameraUptimeRow(
                ip=d["ip"], role=d["role"], state=state,
                last_seen=d["last_seen"], first_seen=d["first_seen"],
                down_since=open_out.down_since if open_out else None,
                current_downtime=open_out.duration(now) if open_out else 0.0,
                outage_count=len(cam_outs),
                downtime_seconds=downtime,
                monitored_seconds=monitored_seconds,
                availability=availability,
            ))
        return report



    # ----- relay: incremental readers for the agent -----

    def flows_since(self, after_id: int, limit: int = 5000) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM flows WHERE id > ? ORDER BY id LIMIT ?",
                (int(after_id), int(limit)),
            ).fetchall()
        return [dict(r) for r in rows]

    def alerts_since(self, after_id: int, limit: int = 5000) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts WHERE id > ? ORDER BY id LIMIT ?",
                (int(after_id), int(limit)),
            ).fetchall()
        return [dict(r) for r in rows]

    def outages_changed_since(self, after_id: int, limit: int = 5000) -> list[dict]:
        """New outages, plus any still open.

        An open outage is re-sent each cycle so its eventual close lands as
        an update on the collector; the (sensor_id, remote_id) key makes
        that idempotent.
        """
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM outages
                   WHERE id > ? OR up_at IS NULL
                   ORDER BY id LIMIT ?""",
                (int(after_id), int(limit)),
            ).fetchall()
        return [dict(r) for r in rows]

    def devices_changed_since(self, since: float, limit: int = 5000) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM devices WHERE last_seen >= ? ORDER BY ip LIMIT ?",
                (float(since), int(limit)),
            ).fetchall()
        return [dict(r) for r in rows]

    # ----- relay: quarantined remote data -----
    #
    # Everything below writes ONLY remote_* tables. That is the whole
    # security property of relay mode, and it is enforced in the test suite
    # by a sqlite authorizer rather than trusted here.

    def get_remote_sensor(self, sensor_id: str) -> RemoteSensorRow | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM remote_sensors WHERE sensor_id = ?", (sensor_id,)
            ).fetchone()
        return _remote_sensor_row(r) if r is not None else None

    def list_remote_sensors(self) -> list[RemoteSensorRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM remote_sensors ORDER BY sensor_id"
            ).fetchall()
        return [_remote_sensor_row(r) for r in rows]

    def forget_remote_sensor(self, sensor_id: str) -> dict[str, int]:
        """Drop a sensor and everything it ever sent.

        A renamed or retired sensor would otherwise sit there forever as
        'not reporting', with a frozen set of camera rows beside it.
        """
        deleted: dict[str, int] = {}
        with self._lock, self._conn:
            for table in ("remote_notifications", "remote_uptime",
                          "remote_outages", "remote_alerts", "remote_flows",
                          "remote_devices", "remote_sensors"):
                cur = self._conn.execute(
                    f"DELETE FROM {table} WHERE sensor_id = ?", (sensor_id,)
                )
                deleted[table] = cur.rowcount
        return deleted

    # Append-only relayed tables and the column that orders them oldest-first.
    # Upsert-keyed tables are capped too: a sensor can claim an unbounded
    # number of distinct IPs, so "one row per IP" is not a bound.
    _QUOTA_TABLES = (
        ("remote_flows", "last_seen"),
        ("remote_alerts", "ts"),
        ("remote_outages", "down_since"),
        ("remote_devices", "last_seen"),
        ("remote_uptime", "reported_at"),
    )

    def _enforce_sensor_quota(self, sensor_id: str, cap: int) -> int:
        """Trim this sensor's rows to the `cap` newest in each table.

        Called inside the ingest transaction so a batch can never leave the
        store over quota, even briefly. Trimming the OLDEST is deliberate:
        under a flood the recent picture is the one worth keeping, and it
        also means a hostile sensor can only ever evict its own history,
        never another sensor's and never any locally-observed row.
        """
        if cap <= 0:
            return 0
        trimmed = 0
        for table, order_col in self._QUOTA_TABLES:
            n = self._conn.execute(
                f"SELECT COUNT(*) FROM {table} WHERE sensor_id = ?",
                (sensor_id,),
            ).fetchone()[0]
            if n <= cap:
                continue
            trimmed += self._conn.execute(
                f"""DELETE FROM {table}
                     WHERE rowid IN (
                         SELECT rowid FROM {table}
                          WHERE sensor_id = ?
                          ORDER BY {order_col} ASC, rowid ASC
                          LIMIT ?)""",
                (sensor_id, n - cap),
            ).rowcount
        return trimmed

    def ingest_remote_batch(
        self, sensor_id: str, instance_id: str, seq: int, records: dict,
        now: float, skew: float = 0.0, body_bytes: int = 0,
        max_rows_per_sensor: int = 0,
    ) -> dict[str, int]:
        """Write one validated batch. Atomic, including the seq bump.

        Bumping the sequence separately from the rows would either lose a
        batch permanently (bump, fail, agent retries, gets 409, drops it) or
        double-insert on replay. One transaction avoids both.
        """
        counts: dict[str, int] = {}
        with self._lock, self._conn:
            for d in records.get("devices", []):
                self._conn.execute(
                    """INSERT INTO remote_devices
                           (sensor_id, ip, role, first_seen, last_seen,
                            packet_count, byte_count, ingested_at)
                       VALUES (?,?,?,?,?,?,?,?)
                       ON CONFLICT(sensor_id, ip) DO UPDATE SET
                           role = excluded.role,
                           last_seen = MAX(remote_devices.last_seen,
                                           excluded.last_seen),
                           packet_count = excluded.packet_count,
                           byte_count = excluded.byte_count,
                           ingested_at = excluded.ingested_at""",
                    (sensor_id, d["ip"], d["role"], d["first_seen"],
                     d["last_seen"], d["packet_count"], d["byte_count"], now),
                )
            counts["devices"] = len(records.get("devices", []))

            for f in records.get("flows", []):
                self._conn.execute(
                    """INSERT INTO remote_flows
                           (sensor_id, remote_id, src_ip, src_port, dst_ip,
                            dst_port, proto, first_seen, last_seen, packets,
                            bytes, bytes_to_camera, bytes_from_camera,
                            tcp_flags_seen, classification, ingested_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(sensor_id, remote_id) DO NOTHING""",
                    (sensor_id, f["remote_id"], f["src_ip"], f["src_port"],
                     f["dst_ip"], f["dst_port"], f["proto"], f["first_seen"],
                     f["last_seen"], f["packets"], f["bytes"],
                     f["bytes_to_camera"], f["bytes_from_camera"],
                     f["tcp_flags_seen"], f["classification"], now),
                )
            counts["flows"] = len(records.get("flows", []))

            for a in records.get("alerts", []):
                self._conn.execute(
                    """INSERT INTO remote_alerts
                           (sensor_id, remote_id, ts, device_ip, kind,
                            severity, summary, detail, dedup_key, ingested_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(sensor_id, remote_id) DO NOTHING""",
                    (sensor_id, a["remote_id"], a["ts"], a["device_ip"],
                     a["kind"], a["severity"], a["summary"], a["detail"],
                     a["dedup_key"], now),
                )
            counts["alerts"] = len(records.get("alerts", []))

            for o in records.get("outages", []):
                # upsert, so a recovery closes the open row instead of
                # inserting a second one
                self._conn.execute(
                    """INSERT INTO remote_outages
                           (sensor_id, remote_id, camera_ip, down_since,
                            up_at, last_seen_before, cause, ingested_at)
                       VALUES (?,?,?,?,?,?,?,?)
                       ON CONFLICT(sensor_id, remote_id) DO UPDATE SET
                           up_at = excluded.up_at,
                           ingested_at = excluded.ingested_at""",
                    (sensor_id, o["remote_id"], o["camera_ip"],
                     o["down_since"], o["up_at"], o["last_seen_before"],
                     o["cause"], now),
                )
            counts["outages"] = len(records.get("outages", []))

            for u in records.get("uptime", []):
                self._conn.execute(
                    """INSERT INTO remote_uptime
                           (sensor_id, ip, role, state, last_seen, first_seen,
                            down_since, current_downtime, outage_count,
                            downtime_seconds, monitored_seconds, availability,
                            reported_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(sensor_id, ip) DO UPDATE SET
                           role = excluded.role,
                           state = excluded.state,
                           last_seen = excluded.last_seen,
                           first_seen = excluded.first_seen,
                           down_since = excluded.down_since,
                           current_downtime = excluded.current_downtime,
                           outage_count = excluded.outage_count,
                           downtime_seconds = excluded.downtime_seconds,
                           monitored_seconds = excluded.monitored_seconds,
                           availability = excluded.availability,
                           reported_at = excluded.reported_at""",
                    (sensor_id, u["ip"], u["role"], u["state"], u["last_seen"],
                     u["first_seen"], u["down_since"], u["current_downtime"],
                     u["outage_count"], u["downtime_seconds"],
                     u["monitored_seconds"], u["availability"], now),
                )
            counts["uptime"] = len(records.get("uptime", []))

            mon = records.get("monitor") or {}
            total = sum(counts.values())
            self._conn.execute(
                """INSERT INTO remote_sensors
                       (sensor_id, instance_id, first_seen, last_seen,
                        last_seq, clock_skew, batches, records, bytes,
                        mon_alive, mon_blind, mon_last_activity_ts)
                   VALUES (?,?,?,?,?,?,1,?,?,?,?,?)
                   ON CONFLICT(sensor_id) DO UPDATE SET
                       instance_id = excluded.instance_id,
                       last_seen = excluded.last_seen,
                       last_seq = excluded.last_seq,
                       clock_skew = excluded.clock_skew,
                       batches = remote_sensors.batches + 1,
                       records = remote_sensors.records + excluded.records,
                       bytes = remote_sensors.bytes + excluded.bytes,
                       mon_alive = excluded.mon_alive,
                       mon_blind = excluded.mon_blind,
                       mon_last_activity_ts = excluded.mon_last_activity_ts""",
                (sensor_id, instance_id, now, now, seq, skew, total,
                 body_bytes, 1 if mon.get("alive") else 0,
                 1 if mon.get("blind") else 0,
                 float(mon.get("last_activity_ts", 0.0))),
            )

            # Inside the same transaction: a batch must never leave this
            # sensor over quota, not even between statements.
            trimmed = self._enforce_sensor_quota(sensor_id, max_rows_per_sensor)
        if trimmed:
            log.warning(
                "relay: sensor %r is over its %d-row quota; trimmed %d of "
                "its oldest row(s). Raise [relay] max_rows_per_sensor if "
                "this sensor is legitimately this busy.",
                sensor_id, max_rows_per_sensor, trimmed,
            )
        counts["total"] = total
        counts["trimmed"] = trimmed
        return counts

    def remote_alert_last_at(self, sensor_id: str, dedup_key: str,
                             exclude_remote_id: int | None = None) -> float | None:
        """Dedup lookup for relayed alerts — against remote_alerts only.

        Evaluating a relayed alert against the local `alerts` table would let
        a relayed alert suppress a local one.

        Two things here are deliberate and were both bugs before:

        `exclude_remote_id` omits the alert being considered. The listener
        writes the batch BEFORE handing it to dispatch, so without this the
        alert is compared against itself, is always "a duplicate of
        something seen just now", and is never notified. On a collector —
        the only host that notifies at all — that silently disables
        notification for every relayed alert.

        The comparison is on `ingested_at`, not `ts`. `ts` is supplied by
        the sensor, so dedup keyed on it is attacker-controlled: backdating
        an alert walks it straight past a window measured against the
        collector's clock. `ingested_at` is when WE received it.
        """
        sql = """SELECT MAX(ingested_at) AS t FROM remote_alerts
                  WHERE sensor_id = ? AND dedup_key = ?"""
        args: list = [sensor_id, dedup_key]
        if exclude_remote_id is not None:
            sql += " AND remote_id != ?"
            args.append(int(exclude_remote_id))
        with self._lock:
            r = self._conn.execute(sql, tuple(args)).fetchone()
        return r["t"] if r is not None and r["t"] is not None else None

    def record_remote_notification(
        self, sensor_id: str, remote_alert_id: int, channel_type: str,
        ok: bool, error: str = "",
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO remote_notifications
                       (sensor_id, remote_alert_id, channel_type,
                        attempted_at, ok, error)
                   VALUES (?,?,?,?,?,?)""",
                (sensor_id, remote_alert_id, channel_type, time.time(),
                 1 if ok else 0, error),
            )

    def remote_alert_id_for(self, sensor_id: str, remote_id: int) -> int | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT id FROM remote_alerts WHERE sensor_id = ? AND remote_id = ?",
                (sensor_id, remote_id),
            ).fetchone()
        return r["id"] if r is not None else None

    def list_remote_alerts(self, *, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM remote_alerts ORDER BY ts DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    def list_remote_flows(self, *, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM remote_flows ORDER BY last_seen DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    def remote_uptime_report(self, now: float, stale_after: float) -> list[dict]:
        """Relayed camera state, stale-gated.

        A sensor that stopped reporting leaves its last snapshot behind. The
        honest rendering of that is `unknown` — NOT the `up` it last claimed,
        which would show a dead segment as healthy.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM remote_uptime ORDER BY sensor_id, ip"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            # Local rows are tagged `sensor="local"`; relayed rows carry
            # `sensor_id`. Consumers that read only one of those names
            # silently mislabel the other set — the OPNsense view did
            # exactly that and showed every relayed camera as "local".
            # One key, set here, so every reader agrees.
            d["sensor"] = d["sensor_id"]
            if (now - d["reported_at"]) > stale_after:
                d["state"] = "unknown"
                d["stale"] = True
                # Its availability is as stale as its state. Reporting the
                # last figure as though it were current is the same
                # fabrication as inventing one from no observation.
                d["availability"] = None
            else:
                d["stale"] = False
            out.append(d)
        return out

    def remote_quota_usage(self, sensor_id: str) -> dict[str, int]:
        with self._lock:
            rows = {}
            for table in ("remote_flows", "remote_alerts", "remote_outages"):
                rows[table] = self._conn.execute(
                    f"SELECT COUNT(*) AS n FROM {table} WHERE sensor_id = ?",
                    (sensor_id,),
                ).fetchone()["n"]
        return rows

    def prune_remote(self, older_than: float) -> dict[str, int]:
        """Age out relayed rows.

        Every cutoff is on `ingested_at` — when WE received the row —
        never on the sensor-supplied `ts`/`last_seen`. A sensor that
        stamps its alerts for the year 2099 would otherwise never be
        pruned at all, and those rows also sort to the top of
        `list_remote_alerts ORDER BY ts DESC`, pushing real alerts off
        the dashboard. Retention has to be measured on a clock the
        sender does not control.
        """
        deleted: dict[str, int] = {}
        with self._lock, self._conn:
            deleted["remote_flows"] = self._conn.execute(
                "DELETE FROM remote_flows WHERE ingested_at < ?", (older_than,)
            ).rowcount
            deleted["remote_alerts"] = self._conn.execute(
                "DELETE FROM remote_alerts WHERE ingested_at < ?", (older_than,)
            ).rowcount
            deleted["remote_outages"] = self._conn.execute(
                """DELETE FROM remote_outages
                   WHERE up_at IS NOT NULL AND ingested_at < ?""", (older_than,)
            ).rowcount
            deleted["remote_notifications"] = self._conn.execute(
                "DELETE FROM remote_notifications WHERE attempted_at < ?",
                (older_than,),
            ).rowcount
            # These two were never pruned at all. They are upserts keyed
            # by (sensor_id, ip), so they do not grow per batch — but a
            # sensor that cycles through addresses still accumulates, and
            # a retired sensor left rows behind forever.
            deleted["remote_devices"] = self._conn.execute(
                "DELETE FROM remote_devices WHERE ingested_at < ?", (older_than,)
            ).rowcount
            deleted["remote_uptime"] = self._conn.execute(
                "DELETE FROM remote_uptime WHERE reported_at < ?", (older_than,)
            ).rowcount
        return deleted

    # ----- flows -----

    def insert_flow(self, fl: FlowRow) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO flows (src_ip, src_port, dst_ip, dst_port, proto,
                                      first_seen, last_seen, packets, bytes,
                                      bytes_to_camera, bytes_from_camera,
                                      tcp_flags_seen, classification)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fl.src_ip, fl.src_port, fl.dst_ip, fl.dst_port, fl.proto,
                    fl.first_seen, fl.last_seen, fl.packets, fl.bytes,
                    fl.bytes_to_camera, fl.bytes_from_camera,
                    fl.tcp_flags_seen, fl.classification,
                ),
            )
            return cur.lastrowid

    def recent_flows(
        self, *, limit: int = 100, classification: str | None = None
    ) -> list[FlowRow]:
        q = "SELECT * FROM flows"
        args: tuple = ()
        if classification:
            q += " WHERE classification = ?"
            args = (classification,)
        q += " ORDER BY last_seen DESC LIMIT ?"
        args = args + (int(limit),)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [
            FlowRow(
                src_ip=r["src_ip"], src_port=r["src_port"], dst_ip=r["dst_ip"],
                dst_port=r["dst_port"], proto=r["proto"],
                first_seen=r["first_seen"], last_seen=r["last_seen"],
                packets=r["packets"], bytes=r["bytes"],
                bytes_to_camera=r["bytes_to_camera"],
                bytes_from_camera=r["bytes_from_camera"],
                tcp_flags_seen=r["tcp_flags_seen"],
                classification=r["classification"],
            )
            for r in rows
        ]

    # ----- alerts -----

    def last_alert_at(self, dedup_key: str) -> float | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT MAX(ts) AS t FROM alerts WHERE dedup_key = ?",
                (dedup_key,),
            ).fetchone()
        return r["t"] if r and r["t"] is not None else None

    def insert_alert(self, a: AlertRow) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO alerts (ts, device_ip, kind, severity, summary,
                                       detail, dedup_key, notified_channels)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    a.ts, a.device_ip, a.kind, a.severity, a.summary, a.detail,
                    a.dedup_key, a.notified_channels,
                ),
            )
            return cur.lastrowid

    def set_alert_channels(self, alert_id: int, channels: str) -> None:
        """Record which channel types actually delivered an alert (audit trail)."""
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE alerts SET notified_channels = ? WHERE id = ?",
                (channels, alert_id),
            )

    def list_alerts(self, *, limit: int = 50) -> list[AlertRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (int(limit),)
            ).fetchall()
        return [
            AlertRow(
                id=r["id"], ts=r["ts"], device_ip=r["device_ip"], kind=r["kind"],
                severity=r["severity"], summary=r["summary"], detail=r["detail"],
                dedup_key=r["dedup_key"],
                notified_channels=r["notified_channels"],
            )
            for r in rows
        ]

    # ----- baselines -----

    def load_baselines(
        self, *, camera_ip: str | None = None
    ) -> list[BaselineRow]:
        """Return persisted Welford buckets. Filter by camera if given.
        Sorted (camera, weekday, hour, feature) for stable display in the CLI."""
        q = "SELECT * FROM baselines"
        args: tuple = ()
        if camera_ip:
            q += " WHERE camera_ip = ?"
            args = (camera_ip,)
        q += " ORDER BY camera_ip, weekday, hour, feature"
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [
            BaselineRow(
                camera_ip=r["camera_ip"], weekday=r["weekday"], hour=r["hour"],
                feature=r["feature"], n=r["n"], mean=r["mean"], m2=r["m2"],
                last_updated=r["last_updated"],
            )
            for r in rows
        ]

    def delete_baselines(self, *, camera_ip: str | None = None) -> int:
        """Wipe persisted buckets. Returns the rowcount. NOTE: a running
        daemon still holds learned state in RAM and will re-upsert on the
        next flush — stop the daemon first if you want a true reset.

        Also wipes the HS-Forest rows for the same scope so a model switch
        doesn't leave half-stale state behind."""
        n = 0
        args: tuple = ()
        if camera_ip:
            where = " WHERE camera_ip = ?"
            args = (camera_ip,)
        else:
            where = ""
        with self._lock, self._conn:
            for table in ("baselines", "baseline_forests"):
                cur = self._conn.execute(f"DELETE FROM {table}" + where, args)
                n += cur.rowcount
            return n

    # ----- baseline forests (HS-Tree engine) -----

    def load_forests(
        self, *, camera_ip: str | None = None,
    ) -> list[BaselineForestRow]:
        """Return persisted HS-Forest rows, optionally filtered to one camera."""
        q = "SELECT * FROM baseline_forests"
        args: tuple = ()
        if camera_ip:
            q += " WHERE camera_ip = ?"
            args = (camera_ip,)
        q += " ORDER BY camera_ip, weekday, hour"
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [
            BaselineForestRow(
                camera_ip=r["camera_ip"], weekday=r["weekday"], hour=r["hour"],
                n_samples=r["n_samples"],
                n_samples_in_window=r["n_samples_in_window"],
                has_reference=bool(r["has_reference"]),
                blob=bytes(r["blob"]),
                last_updated=r["last_updated"],
            )
            for r in rows
        ]

    def delete_forests(
        self, *, camera_ip: str | None = None,
        weekday: int | None = None, hour: int | None = None,
    ) -> int:
        """Wipe HS-Forest rows. Filter is conjunctive (all `not None` clauses
        must match). Used both by the CLI reset path and by HSEngine to drop
        rows that fail to deserialize (schema drift)."""
        clauses: list[str] = []
        args: list = []
        if camera_ip is not None:
            clauses.append("camera_ip = ?"); args.append(camera_ip)
        if weekday is not None:
            clauses.append("weekday = ?"); args.append(int(weekday))
        if hour is not None:
            clauses.append("hour = ?"); args.append(int(hour))
        q = "DELETE FROM baseline_forests"
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        with self._lock, self._conn:
            cur = self._conn.execute(q, tuple(args))
            return cur.rowcount

    def upsert_forests_batch(self, rows: list[BaselineForestRow]) -> None:
        """Insert-or-replace every passed forest row in one transaction."""
        if not rows:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                """INSERT INTO baseline_forests (
                    camera_ip, weekday, hour, n_samples,
                    n_samples_in_window, has_reference, blob, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(camera_ip, weekday, hour) DO UPDATE SET
                    n_samples = excluded.n_samples,
                    n_samples_in_window = excluded.n_samples_in_window,
                    has_reference = excluded.has_reference,
                    blob = excluded.blob,
                    last_updated = excluded.last_updated
                """,
                [
                    (
                        r.camera_ip, r.weekday, r.hour, r.n_samples,
                        r.n_samples_in_window, 1 if r.has_reference else 0,
                        r.blob, r.last_updated,
                    )
                    for r in rows
                ],
            )

    def prune(
        self, *, flows_older_than: float | None = None,
        alerts_older_than: float | None = None,
        notifications_older_than: float | None = None,
        outages_older_than: float | None = None,
        sessions_older_than: float | None = None,
    ) -> dict[str, int]:
        """Delete old rows. Each cutoff is an epoch ts; rows with
        last_seen/ts < cutoff are removed. Returns per-table rowcounts.

        Outages and monitor sessions are only pruned once CLOSED / ENDED —
        deleting an open row would strand live state the tracker is using.
        """
        deleted: dict[str, int] = {}
        with self._lock, self._conn:
            if outages_older_than is not None:
                cur = self._conn.execute(
                    "DELETE FROM outages WHERE up_at IS NOT NULL AND up_at < ?",
                    (outages_older_than,),
                )
                deleted["outages"] = cur.rowcount
            if sessions_older_than is not None:
                cur = self._conn.execute(
                    """DELETE FROM monitor_sessions
                       WHERE ended_at IS NOT NULL AND ended_at < ?""",
                    (sessions_older_than,),
                )
                deleted["monitor_sessions"] = cur.rowcount
            if flows_older_than is not None:
                cur = self._conn.execute(
                    "DELETE FROM flows WHERE last_seen < ?", (flows_older_than,)
                )
                deleted["flows"] = cur.rowcount
            if alerts_older_than is not None:
                cur = self._conn.execute(
                    "DELETE FROM alerts WHERE ts < ?", (alerts_older_than,)
                )
                deleted["alerts"] = cur.rowcount
            if notifications_older_than is not None:
                cur = self._conn.execute(
                    "DELETE FROM notifications WHERE attempted_at < ?",
                    (notifications_older_than,),
                )
                deleted["notifications"] = cur.rowcount
        # VACUUM must run outside a transaction
        if any(deleted.values()) and self._vacuum_is_safe():
            with self._lock:
                self._conn.execute("VACUUM")
        return deleted

    # VACUUM builds a complete second copy of the database before swapping
    # it in, so it needs free space of at least the file's own size. Headroom
    # above that covers WAL growth from the daemon still writing underneath.
    _VACUUM_HEADROOM = 2.0

    def _vacuum_is_safe(self) -> bool:
        """Skip the VACUUM rather than risk filling the disk reclaiming space.

        Running out of space mid-VACUUM on an appliance leaves no room for
        the thing the daemon actually exists to do. A skipped VACUUM only
        means the file stays sparse until the next prune; rows are already
        deleted either way. Fail OPEN when the free space cannot be read,
        matching the pre-existing behaviour.
        """
        try:
            need = self.path.stat().st_size * self._VACUUM_HEADROOM
            st = os.statvfs(self.path.parent)
        except (OSError, AttributeError):
            return True
        free = st.f_bavail * st.f_frsize
        if free >= need:
            return True
        log.warning(
            "store: skipping VACUUM — it needs about %.0f MB free and only "
            "%.0f MB is available. Rows were still deleted; the file will "
            "stay sparse and be reused. Free disk to reclaim it.",
            need / 1e6, free / 1e6,
        )
        return False

    def upsert_baselines_batch(self, rows: list[BaselineRow]) -> None:
        """Write back N dirty buckets in a single transaction. Called on the
        baseliner's flush cadence — NOT per packet, NOT per flow."""
        if not rows:
            return
        with self._lock, self._conn:
            self._conn.executemany(
                """INSERT INTO baselines (camera_ip, weekday, hour, feature,
                                          n, mean, m2, last_updated)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(camera_ip, weekday, hour, feature) DO UPDATE SET
                       n = excluded.n,
                       mean = excluded.mean,
                       m2 = excluded.m2,
                       last_updated = excluded.last_updated
                """,
                [
                    (r.camera_ip, r.weekday, r.hour, r.feature,
                     r.n, r.mean, r.m2, r.last_updated)
                    for r in rows
                ],
            )

    # ----- snapshots -----

    def insert_snapshot(self, s: SnapshotRow) -> int:
        with self._lock, self._conn:
            cur = self._conn.execute(
                """INSERT INTO snapshots (alert_id, camera_ip, path,
                                          byte_count, packet_count, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (s.alert_id, s.camera_ip, s.path,
                 s.byte_count, s.packet_count, s.created_at),
            )
            return cur.lastrowid

    def list_snapshots(self, *, limit: int = 50) -> list[SnapshotRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM snapshots ORDER BY created_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [
            SnapshotRow(
                id=r["id"], alert_id=r["alert_id"], camera_ip=r["camera_ip"],
                path=r["path"], byte_count=r["byte_count"],
                packet_count=r["packet_count"], created_at=r["created_at"],
            )
            for r in rows
        ]

    def get_snapshot(self, snapshot_id: int) -> SnapshotRow | None:
        with self._lock:
            r = self._conn.execute(
                "SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)
            ).fetchone()
        if r is None:
            return None
        return SnapshotRow(
            id=r["id"], alert_id=r["alert_id"], camera_ip=r["camera_ip"],
            path=r["path"], byte_count=r["byte_count"],
            packet_count=r["packet_count"], created_at=r["created_at"],
        )

    # ----- notifications -----

    def record_notification(
        self, alert_id: int, channel_type: str, ok: bool, error: str = ""
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO notifications (alert_id, channel_type, attempted_at,
                                              ok, error)
                   VALUES (?, ?, ?, ?, ?)""",
                (alert_id, channel_type, time.time(), 1 if ok else 0, error),
            )
