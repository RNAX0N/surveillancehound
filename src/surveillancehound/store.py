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

Writes happen at flow-flush time (TTL eviction) and alert time. Reads are
served by the CLI. WAL mode + a 30s busy timeout make this safe under the
daemon's continuous write load.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path


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
"""


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
        self, ip: str, role: str, ts: float, packets: int, bytes_: int
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO devices (ip, role, first_seen, last_seen,
                                        packet_count, byte_count)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(ip) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       packet_count = packet_count + excluded.packet_count,
                       byte_count = byte_count + excluded.byte_count,
                       role = CASE
                           WHEN devices.role = 'other' THEN excluded.role
                           ELSE devices.role
                       END
                """,
                (ip, role, ts, ts, packets, bytes_),
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

    def device_ips(self) -> set[str]:
        with self._lock:
            return {r["ip"] for r in self._conn.execute("SELECT ip FROM devices")}

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
    ) -> dict[str, int]:
        """Delete old rows. Each cutoff is an epoch ts; rows with
        last_seen/ts < cutoff are removed. Returns per-table rowcounts."""
        deleted: dict[str, int] = {}
        with self._lock, self._conn:
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
        if any(deleted.values()):
            with self._lock:
                self._conn.execute("VACUUM")
        return deleted

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
