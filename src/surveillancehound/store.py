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
