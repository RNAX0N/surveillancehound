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

try:
    import fcntl
except ImportError:                      # pragma: no cover - not on Linux/BSD
    fcntl = None
import threading
import time
from dataclasses import dataclass
from collections.abc import Sequence
from pathlib import Path

log = logging.getLogger(__name__)

# A heartbeat newer than this means the daemon is running. A SECOND
# opinion only — the writer lock is the guard; see
# `_require_no_writer`. It used to be the ONLY check, and it was
# written solely from `UptimeTracker.tick`, so with
# `[uptime] enabled = false` it was never written and "no heartbeat"
# read as "no daemon". `daemon._tick` writes it unconditionally now,
# but a heartbeat still cannot prove absence: a daemon that started
# a moment ago has not written one yet.
_DAEMON_ALIVE_S = 120.0
# How long a starting daemon waits for a predecessor to let go of the
# writer lock. Longer than a clean shutdown's drain, so a restart is
# a restart and not an outage.
_WRITER_LOCK_WAIT_S = 60.0


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
    instance_id TEXT NOT NULL DEFAULT '',
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
    UNIQUE (sensor_id, instance_id, remote_id)
);
CREATE INDEX IF NOT EXISTS idx_remote_flows_seen ON remote_flows(last_seen);

CREATE TABLE IF NOT EXISTS remote_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id   TEXT NOT NULL,
    remote_id   INTEGER NOT NULL,
    instance_id TEXT NOT NULL DEFAULT '',
    ts          REAL NOT NULL,
    device_ip   TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    summary     TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    dedup_key   TEXT NOT NULL,
    ingested_at REAL NOT NULL,
    UNIQUE (sensor_id, instance_id, remote_id)
);
CREATE INDEX IF NOT EXISTS idx_remote_alerts_dedup ON remote_alerts(dedup_key, ts);
CREATE INDEX IF NOT EXISTS idx_remote_alerts_ts ON remote_alerts(ts);

-- Keyed on (sensor, INSTANCE, agent row id). The instance matters: an
-- agent whose state is lost restarts its row ids at 1, and keying on the
-- id alone made every colliding record silently vanish — not stored, not
-- paged, and acked as accepted, so the agent advanced its watermark and
-- never resent. Permanent loss on a documented operation (`docker volume
-- rm`), triggerable by anyone who can delete a file on the agent host.
-- Keyed on the agent's own row id so a close UPDATES its open row. Without
-- that key a recovery either inserts a duplicate (double-counting the
-- outage) or is dropped, leaving an outage open forever while the uptime
-- snapshot says the camera is up.
CREATE TABLE IF NOT EXISTS remote_outages (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id        TEXT NOT NULL,
    remote_id        INTEGER NOT NULL,
    instance_id TEXT NOT NULL DEFAULT '',
    camera_ip        TEXT NOT NULL,
    down_since       REAL NOT NULL,
    up_at            REAL,
    last_seen_before REAL NOT NULL DEFAULT 0.0,
    cause            TEXT NOT NULL DEFAULT 'silence',
    ingested_at      REAL NOT NULL,
    UNIQUE (sensor_id, instance_id, remote_id)
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
-- Relay indices on the COLLECTOR-TIME columns.
--
-- Rounds 19-20 moved every relay read, the retention sweep and the
-- per-batch quota trim onto `ingested_at`/`reported_at`/`attempted_at`
-- and left the indices on `ts`/`last_seen`, which none of those paths
-- use. Measured at 250k rows: `_enforce_sensor_quota` cost 80ms per
-- batch INSIDE the ingest transaction (15ms even with nothing to
-- trim), and `prune_remote` 0.65s from the watchdog tick, which holds
-- `_loop_lock` and therefore the packet path. The VACUUM was taken
-- off that tick for exactly this reason; unindexed scans put a
-- smaller version of it back.
CREATE INDEX IF NOT EXISTS idx_rflows_sensor_ing
    ON remote_flows (sensor_id, ingested_at);
CREATE INDEX IF NOT EXISTS idx_rflows_ing   ON remote_flows (ingested_at);
CREATE INDEX IF NOT EXISTS idx_ralerts_sensor_ing
    ON remote_alerts (sensor_id, ingested_at);
CREATE INDEX IF NOT EXISTS idx_ralerts_ing  ON remote_alerts (ingested_at);
CREATE INDEX IF NOT EXISTS idx_routages_sensor_ing
    ON remote_outages (sensor_id, ingested_at);
CREATE INDEX IF NOT EXISTS idx_routages_ing ON remote_outages (ingested_at);
CREATE INDEX IF NOT EXISTS idx_rdevices_sensor_ing
    ON remote_devices (sensor_id, ingested_at);
CREATE INDEX IF NOT EXISTS idx_rdevices_ing ON remote_devices (ingested_at);
CREATE INDEX IF NOT EXISTS idx_ruptime_sensor_rep
    ON remote_uptime (sensor_id, reported_at);
CREATE INDEX IF NOT EXISTS idx_ruptime_rep  ON remote_uptime (reported_at);

CREATE TABLE IF NOT EXISTS remote_notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id       TEXT NOT NULL,
    remote_alert_id INTEGER NOT NULL,
    channel_type    TEXT NOT NULL,
    attempted_at    REAL NOT NULL,
    ok              INTEGER NOT NULL,
    error           TEXT NOT NULL DEFAULT ''
);
-- remote_notifications is the sixth relay table and was missed when
-- the other five were indexed, while being in both `_QUOTA_TABLES`
-- and `prune_remote` on `attempted_at`. Measured at 250k rows:
-- quota COUNT 12.0ms, quota TRIM 18.2ms, prune 8.7ms; with these
-- indices 7.6 / 1.7 / 0.7ms. The first two are inside the ingest
-- transaction, under the lock the capture tick contends for.
CREATE INDEX IF NOT EXISTS idx_rnotif_sensor_att
    ON remote_notifications (sensor_id, attempted_at);
CREATE INDEX IF NOT EXISTS idx_rnotif_att
    ON remote_notifications (attempted_at);
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

    def __init__(self, path: Path, readonly: bool = False,
                 exclusive: bool = False,
                 lock_wait: float | None = None) -> None:
        """`readonly=True` for diagnostics and the dashboard.

        A reader has no business creating the store, creating its parent
        directories, running the schema, or running a MIGRATION — and
        this constructor did all four. So `hound sensors` against a
        path that did not exist produced a 188 KB database and a tree
        of directories, and against a pre-release database it silently
        dropped the relayed rows it had been asked to display. A
        diagnostic must not be able to destroy the thing it reports on.
        It also failed outright on a read-only store directory, which
        is a reasonable way to run a reader.

        `AgentState.load(readonly=…)` and `Spool(readonly=…)` already
        work this way; the store did not.
        """
        self.path = Path(path)
        self.readonly = bool(readonly)
        self._writer_fh = None
        if self.readonly:
            if not self.path.is_file():
                raise FileNotFoundError(
                    f"store {self.path} does not exist. A read-only "
                    f"command will not create it — start the daemon "
                    f"first, or check [store].path."
                )
            # mode=ro refuses to create anything, including the schema.
            self._conn = sqlite3.connect(
                f"file:{self.path.as_posix()}?mode=ro",
                uri=True, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            # No journal_mode here: it is a property of the database,
            # the writer already set it, and setting it needs write
            # access. busy_timeout is per connection and still wanted,
            # since the daemon is writing while we read.
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._lock = threading.RLock()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # The daemon passes exclusive=True. CLI subcommands and the
        # dashboard do not: they are short-lived and must not lock the
        # daemon out of its own store.
        if exclusive:
            self._take_writer_lock(lock_wait)
        self._connect()
        with self._conn:
            self._drop_prerelease_relay_tables()
            self._conn.executescript(_DDL)
        self._lock = threading.RLock()

    def _connect(self) -> None:
        """Open the writable connection and set its PRAGMAs.

        Extracted so `vacuum()` can reopen after swapping the file in.
        Does NOT run the schema or the migration: callers that need
        those do them once, and a reopen after a rebuild must not
        re-run a destructive migration.
        """
        self._conn = sqlite3.connect(str(self.path),
                                     check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=30000")

    # Relay tables created before the instance_id key existed. They are
    # not upgradable in place: the project forbids ALTER TABLE, and
    # CREATE TABLE IF NOT EXISTS leaves the old definition alone — so
    # every relayed INSERT fails with "no column named instance_id",
    # ingest answers 500, the agent treats that as retryable, and the
    # collector silently ingests nothing for the rest of its life while
    # the agent's spool ages out. Loud in one log, invisible in the other.
    _RELAY_TABLES_V2 = ("remote_flows", "remote_alerts", "remote_outages")

    def _drop_prerelease_relay_tables(self) -> None:
        """Recreate pre-release relay tables rather than fail every insert.

        This is a one-time discard of RELAYED rows only — another host's
        observations, which that host still holds and will resend what it
        has spooled. Nothing this sensor observed is touched. It is safe
        precisely because the relay has never shipped; if it had, this
        would need a real migration instead.
        """
        for table in self._RELAY_TABLES_V2:
            row = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if row is None:
                continue
            cols = {r[1] for r in
                    self._conn.execute(f"PRAGMA table_info({table})")}
            if "instance_id" in cols:
                continue
            n = self._conn.execute(
                f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            log.warning(
                "store: %s predates the instance-scoped relay key and "
                "cannot be upgraded in place; dropping it and its %d "
                "relayed row(s). Only data relayed FROM OTHER SENSORS is "
                "affected — nothing this sensor observed. Agents resend "
                "what they still have spooled.",
                table, n,
            )
            self._conn.execute(f"DROP TABLE {table}")

    def close(self) -> None:
        with self._lock:
            self._conn.close()
            # Release the writer lock too. Closing only the sqlite
            # connection left the lock fd open, so `hound prune
            # --offline-compact` kept refusing after the daemon had
            # stopped — the guard would have become a permanent
            # refusal rather than a check.
            fh, self._writer_fh = self._writer_fh, None
            if fh is not None:
                try:
                    fh.close()
                except OSError:
                    pass

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

    def forget_device(self, ip: str) -> dict[str, int]:
        """Delete a device and the liveness history attached to it.

        For an address the configuration no longer claims. Removing an
        IP from `camera_ips` does NOT currently change anything an
        operator can see, for two compounding reasons:

        * `uptime_report` lists `devices WHERE role IN ('camera','nvr')`
          — the stored role, never the live config.
        * `upsert_device` ratchets the role: `other` may become
          something, but nothing ever becomes `other` again. A device
          classified once stays classified forever.

        The ratchet is deliberate — a camera that goes quiet must not
        silently lose its monitoring — but it also means an EXPLICIT
        operator decision is silently ignored, and the row cannot be
        removed by any other means: `prune()` only deletes CLOSED
        outages, and a camera nothing will ever observe again keeps its
        outage open forever. Those rows are therefore permanent, and
        read as real cameras that are really down.

        Returns the row counts removed, so the caller can say what it
        did rather than claiming success blindly.
        """
        out: dict[str, int] = {}
        with self._lock, self._conn:
            for table, col in (("outages", "camera_ip"),
                               ("devices", "ip")):
                cur = self._conn.execute(
                    f"DELETE FROM {table} WHERE {col} = ?", (ip,))
                out[table] = cur.rowcount
        return out


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

    def count_alerts_since(self, since: float) -> int:
        """How many local alerts since `since`. A COUNT, not a page.

        `hound export` derived this by counting the rows it had already
        fetched for the table, so the tile labelled "Alerts (24h)"
        saturated at twice `--limit` — measured 200 of 600 at the
        default, and the OPNsense dashboard clamps the limit to 500, so
        the number an operator reads under-reports exactly when a flood
        makes it matter.
        """
        with self._lock:
            return int(self._conn.execute(
                "SELECT COUNT(*) AS c FROM alerts WHERE ts >= ?",
                (float(since),),
            ).fetchone()["c"])

    def count_remote_alerts_since(self, since: float) -> int:
        """The same for relayed alerts, aged on OUR clock.

        `ingested_at`, never the sensor-supplied `ts`: a backdated
        alert must not be able to hide from the tally, and a
        future-dated one must not inflate it.
        """
        with self._lock:
            return int(self._conn.execute(
                "SELECT COUNT(*) AS c FROM remote_alerts "
                "WHERE ingested_at >= ?",
                (float(since),),
            ).fetchone()["c"])

    def outages_changed_since(self, after_id: int,
                              open_ids: "Sequence[int]" = (),
                              limit: int = 5000) -> list[dict]:
        """New outages, any still open, and any we last reported as open.

        That third term is load-bearing. `up_at IS NULL` re-sends an
        outage only while it is STILL open; the moment it closes it
        stops matching, and by then the watermark has already advanced
        past its id — so the close was never transmitted and the
        collector's copy stayed open forever. That is precisely the
        failure the (sensor, instance, remote_id) key exists to make
        fixable, and the key was correct while the sender never sent
        the update that would use it.

        `open_ids` is what the caller last saw open, so a close is
        guaranteed exactly one more send. The upsert on the collector
        makes the repeat idempotent.
        """
        # Take the carry-forward ids AS GIVEN, already ordered by the
        # caller, and keep well under SQLite's bind-parameter limit.
        #
        # This used to sort them and take the lowest `limit`. Oldest
        # first sounded right and made the window FIXED: with more
        # outages open than fit in a batch, only the lowest ids were
        # ever re-queried, so a close was returned on no cycle at all
        # while any lower-id outage stayed open. Measured: with 1,020
        # open and a limit of 1,000, the close of id 1020 was not
        # delivered in 2,000 push cycles — about 17 hours at the 30s
        # default, and permanent rather than slow, because the window
        # only slides when a lower-id outage closes. The caller rotates
        # instead; see `RelayClient._rotate_open`.
        #
        # 900, not `limit`: older SQLite builds cap bind parameters at
        # 999 and the relay's default limit is 1000, which would sit
        # right on the edge on whatever the OPNsense Python links.
        ids = [int(i) for i in open_ids][:min(limit, 900)]
        extra = ""
        if ids:
            extra = " OR id IN (%s)" % ",".join("?" * len(ids))
        with self._lock:
            rows = self._conn.execute(
                # Three priorities, and the middle one is the fix.
                #
                # NEW outages first (`id > ?`): that term strictly
                # progresses, so the caller's cursor always advances.
                # Plain `ORDER BY id LIMIT` made this a fixed prefix —
                # with `limit` or more outages open at once, the
                # lowest-id open rows filled every batch and a
                # newly-opened outage was returned on no cycle at all.
                #
                # Then CLOSES WE OWE (`up_at IS NOT NULL` among the
                # carry-forward ids). A close is terminal: it clears
                # the camera and drops the id from the carry-forward
                # set. Still-open rows are mere repeats of what the
                # collector already has, and they were sorting AHEAD
                # of closes purely by id — so with more outages open
                # than fit in a batch, the close of a high-id camera
                # was crowded out by low-id open rows forever and that
                # camera showed down on the collector permanently.
                # Rotating the carry-forward list did not help,
                # because the `up_at IS NULL` term matches every open
                # row regardless of that list.
                #
                # Open re-sends last, as filler.
                #
                # Plain `ORDER BY id LIMIT` made this a fixed prefix:
                # with `limit` or more outages open at once, the
                # lowest-id open rows filled every batch, the caller's
                # cursor never moved past them, and a newly-opened
                # outage was returned on no cycle at all — a camera
                # going down was simply never relayed. Sorting the
                # strictly-progressing term first means the cursor
                # always advances, and the re-sends fill whatever is
                # left and resume once it has.
                """SELECT * FROM outages
                   WHERE id > ? OR up_at IS NULL""" + extra + """
                   ORDER BY (id > ?) DESC,
                            (up_at IS NOT NULL) DESC,
                            id LIMIT ?""",
                (int(after_id), *ids, int(after_id), int(limit)),
            ).fetchall()
        return [dict(r) for r in rows]

    def devices_changed_since(self, since: float, limit: int = 5000) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                # ORDER BY last_seen, not ip. The relay truncates this
                # at its batch limit and resumes from the newest
                # `last_seen` it actually sent, so the ordering has to
                # match the cursor. Ordering by ip made the LIMIT a
                # permanent prefix: the same high-sorted addresses were
                # cut on every cycle and never relayed at all. `ip`
                # breaks ties so the order is total.
                "SELECT * FROM devices WHERE last_seen >= ? "
                "ORDER BY last_seen, ip LIMIT ?",
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
    # Ordered by COLLECTOR time in every case. Trimming on a
    # sensor-supplied column lets a sensor stamp its rows far in the
    # future so they sort newest and survive, pushing its own real
    # history — and, within its own quota, nothing else — out first.
    # `prune_remote` was already corrected this way; the trim was not.
    _QUOTA_TABLES = (
        ("remote_flows", "ingested_at"),
        ("remote_alerts", "ingested_at"),
        ("remote_outages", "ingested_at"),
        ("remote_devices", "ingested_at"),
        ("remote_uptime", "reported_at"),
        # Was retention-only, so rows outlived the alerts they cite
        # and no per-sensor cap applied to them at all.
        ("remote_notifications", "attempted_at"),
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
            _before_devices = self._conn.total_changes
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
            counts["devices"] = self._conn.total_changes - _before_devices

            _before_flows = self._conn.total_changes
            for f in records.get("flows", []):
                self._conn.execute(
                    """INSERT INTO remote_flows
                           (sensor_id, instance_id, remote_id, src_ip,
                            src_port, dst_ip,
                            dst_port, proto, first_seen, last_seen, packets,
                            bytes, bytes_to_camera, bytes_from_camera,
                            tcp_flags_seen, classification, ingested_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(sensor_id, instance_id, remote_id)
                       DO NOTHING""",
                    (sensor_id, instance_id,
                     f["remote_id"], f["src_ip"], f["src_port"],
                     f["dst_ip"], f["dst_port"], f["proto"], f["first_seen"],
                     f["last_seen"], f["packets"], f["bytes"],
                     f["bytes_to_camera"], f["bytes_from_camera"],
                     f["tcp_flags_seen"], f["classification"], now),
                )
            counts["flows"] = self._conn.total_changes - _before_flows

            _before_alerts = self._conn.total_changes
            for a in records.get("alerts", []):
                self._conn.execute(
                    """INSERT INTO remote_alerts
                           (sensor_id, instance_id, remote_id, ts, device_ip,
                            kind, severity, summary, detail, dedup_key,
                            ingested_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(sensor_id, instance_id, remote_id)
                       DO NOTHING""",
                    (sensor_id, instance_id,
                     a["remote_id"], a["ts"], a["device_ip"],
                     a["kind"], a["severity"], a["summary"], a["detail"],
                     a["dedup_key"], now),
                )
            counts["alerts"] = self._conn.total_changes - _before_alerts

            _before_outages = self._conn.total_changes
            for o in records.get("outages", []):
                # upsert, so a recovery closes the open row instead of
                # inserting a second one
                self._conn.execute(
                    """INSERT INTO remote_outages
                           (sensor_id, instance_id, remote_id, camera_ip,
                            down_since,
                            up_at, last_seen_before, cause, ingested_at)
                       VALUES (?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(sensor_id, instance_id, remote_id)
                       DO UPDATE SET
                           up_at = excluded.up_at,
                           ingested_at = excluded.ingested_at""",
                    (sensor_id, instance_id, o["remote_id"], o["camera_ip"],
                     o["down_since"], o["up_at"], o["last_seen_before"],
                     o["cause"], now),
                )
            counts["outages"] = self._conn.total_changes - _before_outages

            _before_uptime = self._conn.total_changes
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
            counts["uptime"] = self._conn.total_changes - _before_uptime

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
                       -- Rows WRITTEN, the same quantity the ack
                       -- reports. The comment here used to claim this
                       -- was a submitted count; it never was. Worth
                       -- knowing when reading `hound sensors`: a sensor
                       -- resending the same remote_ids shows batches
                       -- climbing while records stays flat, which is
                       -- the honest reading of "it sent nothing new".
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
        # `total` is already the sum of per-kind CHANGE counts, i.e.
        # rows this batch actually wrote. Subtracting `trimmed` was
        # wrong in both directions: the trim removes rows from EARLIER
        # batches, so a sensor sitting at its quota was told
        # `accepted=0` while everything it sent was stored, and there
        # is no arithmetic relationship between the two numbers at all.
        # They are reported side by side instead, each meaning one
        # thing: what this batch wrote, and what housekeeping removed.
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

    def remote_alert_id_for(self, sensor_id: str, remote_id: int,
                            instance_id: str = "") -> int | None:
        """The stored row id for an audit record.

        `instance_id` disambiguates: an agent that lost its state
        restarts its row ids at 1, so without it the audit row for a new
        alert attaches to a pre-wipe row with entirely different content
        — a notification record citing something that was never sent.
        """
        sql = "SELECT id FROM remote_alerts WHERE sensor_id = ? AND remote_id = ?"
        args: list = [sensor_id, remote_id]
        if instance_id:
            sql += " AND instance_id = ?"
            args.append(instance_id)
        sql += " ORDER BY id DESC"
        with self._lock:
            r = self._conn.execute(sql, tuple(args)).fetchone()
        return r["id"] if r is not None else None

    def list_remote_alerts(self, *, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                # ORDER BY ingested_at, not ts: `ts` is supplied by the
                # sensor, so ordering on it lets one future-dated alert
                # pin itself to the top of every dashboard and push real
                # ones off the end of the limit.
                "SELECT * FROM remote_alerts ORDER BY ingested_at DESC, id DESC "
                "LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    def list_remote_flows(self, *, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM remote_flows ORDER BY ingested_at DESC, id DESC "
                "LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [dict(r) for r in rows]

    def remote_uptime_report(self, now: float, stale_after: float,
                             blind_sensors: "Sequence[str]" = (),
                             limit: int = 5000) -> list[dict]:
        """Relayed camera state, stale-gated.

        A sensor that stopped reporting leaves its last snapshot behind. The
        honest rendering of that is `unknown` — NOT the `up` it last claimed,
        which would show a dead segment as healthy.

        `blind_sensors` names sensors that are still reporting but have
        told us their own capture is not seeing traffic. Their rows get
        the same treatment, for the same reason: a figure from a blind
        sensor is not a current figure.
        """
        # BOUNDED, and fairly. This was the only relay reader with no
        # limit at all, over a table capped only by
        # `max_rows_per_sensor` — 250,000 by default, and the store's
        # own comment notes a sensor can claim an unbounded number of
        # distinct IPs. Measured with one sensor at its stock quota:
        # `hound export` took 4.29s of CPU and 300 MB of RSS to emit an
        # 86.8 MB document, and the OPNsense dashboard runs it through
        # configd every 10 seconds on a 1-vCPU box.
        with self._lock:
            sensors = [r["sensor_id"] for r in self._conn.execute(
                "SELECT DISTINCT sensor_id FROM remote_uptime").fetchall()]
            if not sensors:
                return []
            # `max(1, ...)` means the true ceiling is
            # max(limit, len(sensors)) — safe only because a sensor_id
            # must match a configured [[relay.sensor]], so the sensor
            # count is bounded by the operator's config and not by
            # anything a peer can mint. `list_remote_outages` has the
            # same floor for the same reason.
            share = max(1, int(limit) // len(sensors))
            rows = []
            truncated = 0
            for sid in sensors:
                rows.extend(self._conn.execute(
                    "SELECT * FROM remote_uptime WHERE sensor_id = ? "
                    "ORDER BY ip LIMIT ?", (sid, share)).fetchall())
                total = self._conn.execute(
                    "SELECT COUNT(*) c FROM remote_uptime "
                    "WHERE sensor_id = ?", (sid,)).fetchone()["c"]
                if total > share:
                    truncated += total - share
            if truncated:
                # Say so. A silently short list is the project's
                # cardinal sin: the operator cannot tell "this camera
                # is fine" from "this camera is not on the page".
                log.warning(
                    "store: %d relayed camera row(s) omitted from this "
                    "view (limit %d across %d sensor(s), lowest "
                    "addresses first). Raise the limit or reduce "
                    "[relay] max_rows_per_sensor.",
                    truncated, limit, len(sensors))
        out = []
        for r in rows:
            d = dict(r)
            # Local rows are tagged `sensor="local"`; relayed rows carry
            # `sensor_id`. Consumers that read only one of those names
            # silently mislabel the other set — the OPNsense view did
            # exactly that and showed every relayed camera as "local".
            # One key, set here, so every reader agrees.
            d["sensor"] = d["sensor_id"]
            # Stale for EITHER reason: the link went quiet, or the
            # sensor told us its own capture is blind.
            #
            # Gating on report age alone meant a sensor whose capture
            # had stalled but whose link was fine kept rendering its
            # last snapshot as current — `up`, 100% availability — on
            # both dashboards. That is the same fabrication as
            # inventing a figure from no observation, which is what
            # `uptime.py`'s stall suppression exists to prevent
            # locally; the relayed path had no equivalent.
            blind = bool(blind_sensors and d["sensor_id"] in blind_sensors)
            if blind or (now - d["reported_at"]) > stale_after:
                d["state"] = "unknown"
                d["stale"] = True
                d["stale_reason"] = ("sensor capture blind" if blind
                                     else "sensor not reporting")
                # Its availability is as stale as its state. Reporting the
                # last figure as though it were current is the same
                # fabrication as inventing one from no observation.
                d["availability"] = None
            else:
                d["stale"] = False
            out.append(d)
        # Stable order regardless of the per-sensor fetch above.
        out.sort(key=lambda d: (d["sensor_id"], d["ip"]))
        return out

    def list_remote_outages(self, since: float,
                            limit: int = 500) -> list[dict]:
        """Outage windows relayed by sensors.

        `remote_outages` had no reader at all: rows were written,
        quota-trimmed, pruned and forgotten, and nothing displayed
        them. So the agent spent batch budget relaying them, the
        carry-forward and close-detection machinery ran, and the
        result went nowhere — while `hound uptime --outages` on a
        collector printed "no outages" with a fleet of relayed cameras
        reporting. For a project whose stated cardinal sin is a
        surface reporting something it cannot back, a view that omits
        the only data a collector HAS is the sin in its purest form.

        Two things keep one sensor from owning this view, and the
        first revision had neither despite its docstring claiming
        both.

        ORDERED ON `ingested_at`, our clock, never the sensor-supplied
        `down_since`. `validate_outage` accepts `down_since` up to the
        year 2100, so ordering by it let one key holder put 500
        future-dated rows at the top of every query.

        FAIR SHARE per sensor. Even ordered honestly, a sensor inside
        its `max_rows_per_sensor` quota can fill any flat limit.
        Measured on the first revision: 600 hostile rows left 0 of 5
        honest rows visible, and this is the ONLY reader of relayed
        outages, so that blinded the operator to every other sensor.
        Same reasoning as the daemon's round-robin alert queue.
        """
        with self._lock:
            sensors = [r["sensor_id"] for r in self._conn.execute(
                "SELECT DISTINCT sensor_id FROM remote_outages"
            ).fetchall()]
            if not sensors:
                return []
            share = max(1, int(limit) // len(sensors))
            out: list[dict] = []
            for sid in sensors:
                rows = self._conn.execute(
                    """SELECT * FROM remote_outages
                       WHERE sensor_id = ?
                         AND (down_since >= ? OR up_at IS NULL)
                       ORDER BY ingested_at DESC, id DESC
                       LIMIT ?""",
                    (sid, float(since), share),
                ).fetchall()
                out.extend(dict(r) for r in rows)
        out.sort(key=lambda r: r["ingested_at"], reverse=True)
        return out[:int(limit)]

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
            # NOT gated on `up_at IS NOT NULL`, unlike the local
            # `prune`. Locally an open outage is this daemon's own live
            # state and deleting it would lose the down-state that a
            # restart resumes from. A RELAYED open outage is not live
            # state — it is a copy, and `validate` accepts
            # `up_at: null`, so a key-holding sensor could send a
            # thousand never-closed outages per batch and every one was
            # permanently immune to retention. Retention is documented
            # as the only bound on remote_* growth, so "immune to
            # retention" meant unbounded.
            #
            # Safe because the agent re-sends it: `_advance` carries
            # every still-open outage id forward in
            # `open_outage_ids`, so `outages_changed_since` returns it
            # on EVERY cycle. A genuinely-open outage pruned here
            # reappears on the next batch from a live sensor; one that
            # does not reappear had no sensor behind it.
            deleted["remote_outages"] = self._conn.execute(
                "DELETE FROM remote_outages WHERE ingested_at < ?",
                (older_than,)
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
        # NO VACUUM HERE. Read this before adding one back.
        #
        # A previous revision did, to make retention free bytes and not
        # just rows. It was a worse bug than the one it fixed, twice
        # over:
        #
        # 1. `prune_remote` is called from the daemon tick, which holds
        #    `_loop_lock` — the lock the packet path takes per packet.
        #    VACUUM costs time proportional to LIVE data, not to the
        #    rows deleted, so the hourly sweep rewrote the whole
        #    database while the capture loop waited. Measured on NVMe:
        #    1.4s at 30k live relayed alerts, 6.1s at 120k, and 28.1s
        #    at 250k — which is exactly `max_rows_per_sensor`, i.e. one
        #    sensor's stock quota. Packet-loop lock acquisitions went
        #    from 4.0M/s to zero for the whole hold, and nothing
        #    alerted: the watchdog thread is the one inside the VACUUM,
        #    so no tick can fire `capture_stalled`.
        # 2. It did not even reclaim. The store is WAL, so VACUUM
        #    writes the rebuilt database into `-wal` and the main file
        #    only shrinks at a checkpoint. Measured: db 1053 MB -> 53 MB
        #    with wal 0 -> 1006 MB, TOTAL unchanged, and still unchanged
        #    after 6,000 further writes. A sweep that expired little was
        #    a net increase (526 MB -> 1002 MB total). It also zeroed
        #    the freelist, removing the `reusable_bytes` credit that
        #    `ingest._disk_ok` counts — so the collector was strictly
        #    worse off for the guard after the sweep than before it.
        #
        # Reclamation belongs in `vacuum()`, called only from
        # `hound prune --relay-days`: a separate short-lived process,
        # not holding `_loop_lock`, whose exit checkpoints the WAL away.
        # The daemon's job here is to delete rows; the pages it frees
        # are reusable in place, which is what the disk guard counts.
        return deleted

    def vacuum(self, offline: bool = False) -> tuple[int, int]:
        """Rebuild the database to return free pages to the filesystem.

        NOT for the daemon. See the note in `prune_remote`: this holds
        the store lock for as long as it takes to rewrite every live
        page, and in WAL mode the bytes only come back when the
        connection closes and the WAL is checkpointed away. Both are
        fine in a one-shot CLI process and unacceptable inside the
        packet loop.

        PLAIN `VACUUM` BY DEFAULT, because it is the only variant that
        is safe while the daemon is running.

        A previous revision preferred `VACUUM INTO` plus `os.replace`,
        to avoid the plain form's need for roughly twice the file size
        free. That was a worse bug than the one it solved. `vacuum()`
        is only ever reached from `hound prune`, a SEPARATE PROCESS,
        and the daemon is another process holding the old inode open.
        `os.replace` is invisible to it: it goes on writing to an
        unlinked file forever, with no error on either side. Measured
        through the documented command with a daemon-like writer
        running: 777 of 1363 writes (57%) silently discarded, and
        `monitor_heartbeat` frozen at the swap instant so every reader
        renders a healthy collector as stalled. The replacement file
        also took the pruning process's umask and ownership — root on
        OPNsense, where the daemon runs as `hound`, so the breakage
        survives the restart that would otherwise have ended it.

        SQLite's own locking coordinates two processes through a plain
        VACUUM. It does not know about `os.replace`.

        `offline=True` opts into the compacting form for the case the
        plain one cannot serve — a disk too full to hold a second copy
        — and refuses unless the heartbeat shows no daemon running.
        The CLI only passes it when the operator asks explicitly.

        Returns (before, after) file sizes.
        """
        before = self.path.stat().st_size
        if self.readonly:
            return before, before
        if offline:
            return before, self._compact_offline(before)
        if not self._vacuum_is_safe():
            return before, before
        with self._lock:
            self._conn.execute("VACUUM")
            # Checkpoint, or the rebuild sits in -wal and the file on
            # disk is unchanged — so this returned before == after and
            # the CLI told the operator the reclaim had failed for
            # lack of disk, which `_vacuum_is_safe` had just ruled out.
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return before, self.path.stat().st_size

    def _compact_offline(self, before: int) -> int:
        """`VACUUM INTO` + swap. ONLY safe with the daemon stopped.

        Needs room for the live data rather than roughly the whole
        file, which is why it exists at all; see `vacuum()` for why it
        is not the default. Measured: a plain VACUUM of a 631 MB store
        with 85 MB live peaked at 552 MB of extra space, because in WAL
        mode it rewrites every page through the WAL. So on the full
        disk this command is the documented recovery for, the plain
        form cannot run and this one can.

        THE GUARD IS THE WRITER LOCK, HELD THROUGHOUT. Two earlier
        versions of this guard were defeated in two different ways,
        and both lost every write a concurrent daemon made:

        * A heartbeat check. `set_heartbeat` was called only from
          `UptimeTracker.tick`, which the daemon builds only when
          `[uptime] enabled` — so with uptime off the row was never
          written, `heartbeat()` returned (0.0, 0.0) and the check
          was skipped entirely. Measured 46,444 of 287,586 rows (16%)
          written to an unlinked inode in one run and 74% in another;
          the fraction is only how much of the run falls after the
          swap, and all of it does.
        * Taking the lock and releasing it again. That proves "no
          daemon at this instant" and then does the slow part —
          `VACUUM INTO` over the live dataset, the WAL teardown,
          `os.replace` — unprotected. Measured 9,680 of 9,680 rows
          lost through a 1.1s window on a 400 MB store; on a 1-vCPU
          appliance that window is minutes. On OPNsense any GUI save
          runs `hound onerestart`, so a second admin on the settings
          page walks straight into it.

        So the lock is taken by the CALLER, for the whole operation:
        `cmd_prune` opens the store `exclusive=True` when compacting.
        `flock` needs no config, and the kernel releases it when the
        process dies, so a crash cannot wedge this command.
        """
        self._require_no_writer()
        tmp = self.path.with_name(self.path.name + ".vacuum.tmp")
        # Clear any leftover BEFORE the free-space check below, or it
        # is counted against the very space it is deciding about.
        # This sat fourteen lines further down, after the check, while
        # its comment claimed otherwise — so a partial rebuild left by
        # a kill made the next attempt refuse for lack of room it was
        # itself occupying, on exactly the full disk this command is
        # the recovery for. Measured: 9,076,736 stale bytes turned
        # "13.1 MB free, needs 10.8" into "4.3 MB free, needs 10.4",
        # and the refusal never mentioned the file.
        tmp.unlink(missing_ok=True)
        try:
            mode = self.path.stat().st_mode & 0o7777
            st = self.path.stat()
        except OSError:
            mode, st = 0o600, None
        # Normalise the sidecar HERE, before the early return below.
        # `_take_writer_lock` has just created `<store>.writer` under
        # this process's umask, and the low-disk refusal used to
        # return without touching it — in the full-disk case this
        # command exists for. Under root's default umask that leaves
        # 0644 root:root, which the read-only fallback survives; under
        # the umask 027 configd uses it leaves 0640 root:root, which
        # the daemon cannot even read, and it will not start.
        self._match_store_ownership(self._writer_lock_path(), mode, st)
        live = self._live_bytes()
        free = self._fs_free()
        if live and free is not None and free < live * 1.15:
            log.warning(
                "store: not compacting — needs about %.0f MB free and "
                "only %.0f MB is available.", live * 1.15 / 1e6,
                free / 1e6)
            return before
        try:
            return self._compact_into(tmp, mode, st)
        except Exception:
            # Never leave a partial rebuild behind: it is dead weight
            # on the disk this command exists to free.
            tmp.unlink(missing_ok=True)
            try:
                self._conn.execute("SELECT 1")
            except sqlite3.Error:
                self._connect()
            raise

    def _compact_into(self, tmp: Path, mode: int, st) -> int:
        with self._lock:
            self._conn.execute("VACUUM INTO ?", (str(tmp),))
            # Mode and owner come from the pruning process's umask
            # otherwise: measured 0600 -> 0644, and on OPNsense a root
            # prune would leave the store root-owned under a daemon
            # running as `hound`.
            os.chmod(tmp, mode)
            if st is not None and hasattr(os, "chown"):
                try:
                    os.chown(tmp, st.st_uid, st.st_gid)
                except (OSError, AttributeError):
                    pass
            # The lock sidecar too. Round 21 taught this method to
            # carry the store's mode and owner across the swap and
            # left the file it creates beside it untreated — so the
            # same root-run prune that no longer breaks the store
            # could still leave a `.writer` the daemon cannot use.
            self._match_store_ownership(self._writer_lock_path(), mode, st)
            # Checkpoint EXPLICITLY before closing. `close()` alone
            # cannot checkpoint while another process still has the
            # database open — a reader keeps the WAL alive — so the
            # unlink below then discarded committed transactions that
            # had never reached the main file. Measured with a reader
            # attached and a SIGKILL between the unlink and the
            # replace: 6,889 of 7,000 rows, three runs, and
            # `integrity_check` said `ok` every time. Silent loss that
            # passes its own audit is the worst shape this project
            # has. After a successful TRUNCATE the unlink is a no-op.
            #
            # Do NOT reorder the unlink after the replace instead:
            # that turns silent loss into a stale journal beside a
            # different database, which is a corrupt store.
            # CHECK THE ROW, not just for an exception.
            #
            # `PRAGMA wal_checkpoint` returns (busy, log_frames,
            # checkpointed_frames) and SQLITE_OK even when it did
            # nothing — it does NOT raise when a reader's snapshot
            # blocks it. The first version of this guard caught
            # `sqlite3.Error` only, so the branch never ran for the
            # one case its own comment named, and the unlink below
            # then discarded every frame the checkpoint had failed to
            # write. Measured with a reader holding a pre-WAL
            # snapshot: `(1, 18, 0)`, no exception, 0 of 7000 rows
            # surviving the swap, and `integrity_check` still `ok`.
            try:
                row = self._conn.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                err = None if (row and row[0] == 0) else (
                    f"blocked (busy={row[0] if row else '?'}, "
                    f"{row[2] if row else '?'} of "
                    f"{row[1] if row else '?'} frames written)")
            except sqlite3.Error as e:
                err = str(e)
            if err:
                raise RuntimeError(
                    f"cannot checkpoint the write-ahead log before "
                    f"swapping {self.path}: {err}. Something else "
                    f"still has the store open; close it and re-run."
                ) from None
            self._conn.close()
            for suffix in ("-wal", "-shm"):
                Path(str(self.path) + suffix).unlink(missing_ok=True)
            os.replace(tmp, self.path)
            self._connect()
        return self.path.stat().st_size

    def _writer_lock_path(self) -> Path:
        return Path(str(self.path) + ".writer")

    def _open_lock_file(self):
        lock = self._writer_lock_path()
        try:
            return open(lock, "a+b")
        except PermissionError:
            # `flock` needs no write access, so a lock file we may
            # only READ is still perfectly usable. This matters
            # because the documented recovery is "stop the service,
            # run prune as root, start it again" — and under
            # `DynamicUser=yes` that root run creates
            # `<store>.writer` as root:root in the dynamic user's
            # state directory. The daemon then could not open it and
            # `Restart=always` looped, with its actual database
            # perfectly writable. OPNsense is immune only because its
            # rc script chowns the whole state dir on every start.
            try:
                return open(lock, "rb")
            except OSError as inner:
                raise RuntimeError(
                    f"cannot open the writer lock {lock}: {inner}. It "
                    f"must be readable by the user running the "
                    f"daemon, in a directory that user can reach; the "
                    f"store itself is fine."
                ) from None
        except OSError as e:
            # A `.writer` the daemon cannot open — wrong owner or
            # mode — raised a bare PermissionError out of the
            # constructor, which is a new way for an otherwise
            # healthy daemon to refuse to start while its actual
            # database is perfectly writable.
            raise RuntimeError(
                f"cannot open the writer lock {self._writer_lock_path()}: "
                f"{e}. It must be writable by the user running the "
                f"daemon; the store itself is fine."
            ) from None

    @staticmethod
    def _match_store_ownership(target: Path, mode: int, st) -> None:
        """Give `target` the store's mode and owner. Best effort."""
        try:
            if not target.exists():
                return
            os.chmod(target, mode)
            if st is not None and hasattr(os, "chown"):
                os.chown(target, st.st_uid, st.st_gid)
        except (OSError, AttributeError):
            pass

    def _lock_inode_matches(self, fh) -> bool:
        try:
            return (os.fstat(fh.fileno()).st_ino
                    == os.stat(self._writer_lock_path()).st_ino)
        except OSError:
            return False

    def _take_writer_lock(self, wait: float | None = None) -> None:
        """Claim this store as THE writer. Raises if another holds it.

        The project's invariant is already one writer per store
        ("One process, one writer" — see this class's docstring). This
        makes it checkable from another process, which is what the
        offline compaction needs: it swaps the database file, and
        `os.replace` is invisible to a daemon holding the old inode.

        A no-op where `fcntl` is unavailable; the platforms this
        deploys on (Linux, FreeBSD) have it.
        """
        if fcntl is None:
            return
        fh = self._open_lock_file()
        # Brief retry, because the common case for contention is a
        # RESTART, not a second daemon. `service hound restart` can
        # start the new process while the old one is still draining —
        # a clean shutdown flushes in-RAM flows and the relay spool
        # and is allowed tens of seconds — and failing instantly there
        # would turn a restart into an outage. FreeBSD's `daemon -r -R
        # 5` would eventually retry, but only after logging a failure
        # that looks like a real fault.
        # The DAEMON waits: its usual competitor is its own
        # predecessor still draining, and failing instantly there
        # turns every restart into an outage. A one-shot command
        # passes 0 — it has an operator in front of it who would
        # rather be told to stop the service now than watch a cursor
        # blink for a minute first.
        budget = _WRITER_LOCK_WAIT_S if wait is None else max(0.0, wait)
        deadline = time.monotonic() + budget
        while True:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                # `flock` is on the open file, not the name. If the
                # lock file was replaced or removed between our open
                # and our lock, we are holding an inode nobody else
                # will consult — and a second process would create a
                # fresh one and conclude no daemon is running.
                if self._lock_inode_matches(fh):
                    break
                # Someone replaced the lock file under us. Re-open and
                # try again — but on the SAME deadline, and with the
                # same backoff. `continue` straight to the top skipped
                # both, so a pathological lock file spun a core for as
                # long as the daemon lived.
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                fh.close()
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"the writer lock {self._writer_lock_path()} "
                        f"keeps being replaced underneath this "
                        f"process; giving up after {budget:.0f}s."
                    ) from None
                time.sleep(0.05)
                fh = self._open_lock_file()
                continue
            except OSError:
                if time.monotonic() >= deadline:
                    fh.close()
                    waited = (f", and still had it after {budget:.0f}s"
                              if budget else "")
                    raise RuntimeError(
                        f"another process already has {self.path} open "
                        f"as a writer{waited}. Only one process may "
                        f"write a store — stop the daemon "
                        f"(`service hound stop`, `systemctl stop "
                        f"hound`) and re-run."
                    ) from None
                time.sleep(0.25)
        self._writer_fh = fh

    def _require_no_writer(self) -> None:
        """Refuse unless no daemon holds this store — AND KEEP IT THAT WAY.

        The first version took the lock and dropped it again in a
        `finally`, proving only "no daemon at this instant". Every
        expensive step then ran unprotected: `VACUUM INTO` over the
        whole live dataset, the WAL teardown, `os.replace`. A daemon
        starting inside that window took the lock unopposed and wrote
        to the inode we were about to unlink. Measured on a 400 MB
        store with a 1.1s window: 9,680 of 9,680 rows lost, silently,
        on both sides — and on a 1-vCPU appliance with slow storage
        that window is tens of seconds to minutes, during which the
        command prints nothing.

        It is not only operator impatience: on OPNsense ANY save in
        the Hound GUI runs configd -> reload.sh -> `hound onerestart`,
        so a second admin touching the settings page restarts the
        daemon straight into it.

        So the caller must already HOLD the lock for the whole
        operation. `cmd_prune` opens the store with
        `exclusive=True` when compacting, and this returns
        immediately in that case — re-opening the path here would
        self-deadlock, because flock is per open file description,
        not per process.
        """
        if self._writer_fh is not None:
            return                 # we hold it, for the whole swap
        if fcntl is not None:
            # No lock of our own: refuse rather than guess. The only
            # way to reach this is a caller that did not open the
            # store exclusive, and proving "nobody right now" is not
            # the property this needs.
            raise RuntimeError(
                "internal: the store must be opened with "
                "exclusive=True before compacting, so the writer lock "
                "is held for the whole swap"
            )
        # FALLBACK FOR PLATFORMS WITHOUT flock, and nothing else.
        # The branch above returns or raises whenever `fcntl` is
        # importable, so on Linux and FreeBSD — the only platforms
        # this deploys on — nothing below ever runs. It is kept for a
        # hypothetical port, not as a live guard, and it could never
        # be one: a heartbeat cannot prove ABSENCE. A daemon that started a moment ago has not
        # written one yet, and before `daemon._tick` wrote it
        # unconditionally a daemon with `[uptime] enabled = false`
        # never wrote one at all.
        _, updated = self.heartbeat()
        # abs(): a heartbeat AHEAD of the clock — a backwards clock
        # step, or a replay of a future-dated capture, which sets the
        # daemon's clock from packet timestamps — made this difference
        # negative, so the check fired forever and the message's
        # "allow up to 120s after stopping" could never be satisfied.
        # A future heartbeat is still a reason to be careful, so it
        # refuses rather than being ignored; the writer lock above has
        # already given the real answer in either case.
        if updated and abs(time.time() - updated) < _DAEMON_ALIVE_S:
            raise RuntimeError(
                f"the daemon wrote its heartbeat "
                f"{time.time() - updated:.0f}s ago, so it is running. "
                f"Stop the service, then re-run. (The heartbeat is "
                f"written every few seconds; allow up to "
                f"{_DAEMON_ALIVE_S:.0f}s after stopping.)"
            )

    def _live_bytes(self) -> int:
        """Bytes of pages actually in use. 0 if it cannot be read."""
        try:
            with self._lock:
                pages = self._conn.execute(
                    "PRAGMA page_count").fetchone()[0]
                free = self._conn.execute(
                    "PRAGMA freelist_count").fetchone()[0]
                size = self._conn.execute(
                    "PRAGMA page_size").fetchone()[0]
            return max(0, (int(pages) - int(free))) * int(size)
        except (sqlite3.Error, TypeError, IndexError):
            return 0

    def _fs_free(self) -> "int | None":
        try:
            st = os.statvfs(self.path.parent)
        except (OSError, AttributeError):
            return None
        return st.f_bavail * st.f_frsize

    def reusable_bytes(self) -> int:
        """Free pages inside the store, in bytes.

        SQLite reuses these without growing the file, so for "is there
        room to write" they are as good as filesystem free space. The
        ingest disk guard counts them because retention can free pages
        without shrinking the file, and gating on the filesystem alone
        made a one-off flood a permanent 507 for every sensor.
        """
        try:
            with self._lock:
                free = self._conn.execute(
                    "PRAGMA freelist_count").fetchone()[0]
                page = self._conn.execute(
                    "PRAGMA page_size").fetchone()[0]
            return int(free) * int(page)
        except (sqlite3.Error, TypeError, IndexError):
            return 0

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
