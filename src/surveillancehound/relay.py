"""Relay wire format, spool, and agent-side client.

Three pieces, all stdlib:

  * the batch format and its HMAC, shared by both ends
  * a disk spool so a link outage does not lose the segment's history
  * the agent client that pushes batches and pins the collector's cert

The collector side lives in `ingest.py`.

Two decisions here exist because the obvious version is broken:

`sent_at` is stamped at transmission, not when the records were produced,
and a replayed batch is re-serialised and re-signed. The skew window exists
to bound replay of a captured batch; applying it to a production timestamp
would reject every spooled batch, since a spooled batch is by definition
older than the outage that spooled it. It would also break replay mode
outright, where the daemon's clock is packet time months in the past.

Pinning uses `http.client` rather than `urllib.request`. urllib never
exposes the connection, so there is no point at which the peer certificate
can be inspected before the body is sent — and `ssl` has no verify callback
to do it from. The sequence here is connect, hash the peer cert, compare,
and only then transmit.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import logging
import os
import secrets
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
SIG_HEADER = "X-Hound-Signature"
SENSOR_HEADER = "X-Hound-Sensor"
SEQ_HEADER = "X-Hound-Seq"


class RelayError(Exception):
    """Something went wrong talking to the collector."""


# --------------------------------------------------------------------------
# wire format
# --------------------------------------------------------------------------

def build_batch(
    sensor_id: str, instance_id: str, seq: int, records: dict, sent_at: float,
) -> bytes:
    """Serialise one batch. `sent_at` is transmission time, not capture time."""
    return json.dumps(
        {
            "schema": SCHEMA_VERSION,
            "sensor_id": sensor_id,
            "instance_id": instance_id,
            "seq": int(seq),
            "sent_at": float(sent_at),
            "records": records,
        },
        separators=(",", ":"), default=str, allow_nan=False,
    ).encode("utf-8")


def restamp(body: bytes, sent_at: float) -> bytes:
    """Re-stamp a spooled batch for a fresh transmission attempt.

    The records keep their original timestamps; only `sent_at` moves, which
    is what lets a day-old spooled batch pass a five-minute skew window.
    """
    doc = json.loads(body.decode("utf-8"))
    doc["sent_at"] = float(sent_at)
    return json.dumps(doc, separators=(",", ":"), default=str,
                      allow_nan=False).encode("utf-8")


def sign(key: str, body: bytes) -> str:
    """HMAC-SHA256 over the raw body.

    The raw bytes, not a re-serialised canonical form — canonicalisation is
    a reliable source of signature-bypass bugs.
    """
    mac = hmac.new(key.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def verify(key: str, body: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(key, body), signature or "")


# --------------------------------------------------------------------------
# spool + agent state
# --------------------------------------------------------------------------

@dataclass
class SpoolStats:
    pending: int = 0
    bytes: int = 0
    oldest_age: float = 0.0
    dropped_size: int = 0
    dropped_age: int = 0
    dropped_stale: int = 0


class Spool:
    """Append-only batch spool bounded by BOTH size and age.

    Two caps rather than one because they fail differently: a byte cap alone
    lets a slow trickle sit for a month and replay something useless, and an
    age cap alone lets a busy segment fill the disk inside an hour.
    """

    def __init__(self, directory: Path, max_bytes: int, max_age_seconds: float,
                 *, readonly: bool = False):
        self.dir = Path(directory)
        # `hound relay` constructs a Spool purely to read it. Creating
        # the directory there means a diagnostic run as the wrong user
        # leaves a root-owned path the daemon then cannot write.
        # AgentState.load was fixed for this; the spool was not.
        if not readonly:
            self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "spool.jsonl"
        self.max_bytes = int(max_bytes)
        self.max_age = float(max_age_seconds)
        self.dropped_size = 0
        self.dropped_age = 0
        self.dropped_stale = 0
        # append/ack/drop are each a read-modify-write of one file. Two
        # of them interleaving loses whichever batch the loser read
        # before the winner wrote — the exact data loss the spool exists
        # to prevent. The pusher thread and a shutdown flush can both be
        # in here at once, so the serialisation has to live in the spool
        # rather than in its callers.
        self._lock = threading.RLock()
        # ack()/drop() are called from the push loop and have no `now` of
        # their own; this tracks the most recent one a caller supplied so
        # their compaction uses a real clock rather than wall time, which
        # keeps replay deterministic.
        self._now_hint = 0.0

    def _read(self) -> list[dict]:
        if not self.path.is_file():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue          # a torn tail line; drop it rather than die
        return out

    def _write(self, entries: list[dict]) -> None:
        # Unique per writer, for the same reason AgentState.save is: the
        # daemon and `hound relay` are different processes sharing this
        # directory, and a fixed name lets one truncate the other's
        # half-written file.
        tmp = self.path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(
            "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)

    def append(self, seq: int, body: bytes, now: float) -> None:
        """Append one batch, compacting only when a cap is actually at risk.

        This used to read and rewrite the whole spool on every enqueue.
        With a 64 MB cap and a 30 s cadence that is O(n^2) disk churn on
        an NVR, for a file that is append-only in the normal case. The
        file is JSON-lines precisely so a new batch is one write.
        """
        line = json.dumps(
            {"seq": int(seq), "at": float(now), "body": body.decode("utf-8")},
            separators=(",", ":"),
        ) + "\n"
        with self._lock:
            self._now_hint = max(self._now_hint, now)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
            # Compact only when the file has actually grown past the byte
            # cap. The age cap is applied on read (`pending`), so a stale
            # entry is never replayed even between compactions.
            try:
                oversized = self.path.stat().st_size > self.max_bytes
            except OSError:
                oversized = True
            if oversized:
                self._write(self._enforce_caps(self._read(), now))

    def _deliverable(self, entries: list[dict], now: float) -> list[dict]:
        """What is still within both caps. PURE — no counters, no writes.

        Readers use this. They must not mutate: `hound relay` builds its
        own Spool over the live directory in a DIFFERENT PROCESS from the
        daemon, and `_lock` is a thread lock, so a reader that wrote back
        could clobber a batch the daemon appended in between. That is the
        data loss the spool exists to prevent, caused by the diagnostic
        command for it.
        """
        kept = [e for e in entries if (now - e["at"]) <= self.max_age]
        total = sum(len(e["body"]) for e in kept)
        i = 0
        while i < len(kept) and total > self.max_bytes:
            total -= len(kept[i]["body"])        # oldest first
            i += 1
        return kept[i:]

    def _enforce_caps(self, entries: list[dict], now: float) -> list[dict]:
        """`_deliverable`, plus the drop counters. MUTATING PATHS ONLY.

        Counting here rather than in the reader is what keeps the totals
        honest: `pending()` runs every push cycle, so counting on read
        made one expired batch register a fresh drop forever.
        """
        kept = self._deliverable(entries, now)
        if len(kept) != len(entries):
            dropped = entries[:len(entries) - len(kept)]
            aged = sum(1 for e in dropped if (now - e["at"]) > self.max_age)
            self.dropped_age += aged
            self.dropped_size += len(dropped) - aged
        return kept

    def pending(self, now: float) -> list[tuple[int, bytes]]:
        with self._lock:
            self._now_hint = max(self._now_hint, now)
            entries = self._deliverable(self._read(), now)
            return [(e["seq"], e["body"].encode("utf-8")) for e in entries]

    def ack(self, seq: int) -> None:
        """Drop everything up to and including `seq` — it is now durable.

        Also compacts, since this already rewrites the file. That is
        where aged-out batches get counted: readers must not count (they
        run every cycle and would re-count forever) and appends only
        compact when oversized, so without this `dropped_age` would stay
        at zero while batches silently expired.
        """
        with self._lock:
            # Count expiries BEFORE removing the acked range, or a batch
            # that aged out unsent is swept away as though it had been
            # delivered and never appears in the drop total.
            live = self._enforce_caps(self._read(), self._now_hint)
            self._write([e for e in live if e["seq"] > seq])

    def drop(self, seq: int, reason: str) -> None:
        """Discard one batch the collector will never accept."""
        with self._lock:
            self.dropped_stale += 1
            log.warning("relay: dropping spooled batch seq=%s (%s)", seq, reason)
            live = self._enforce_caps(self._read(), self._now_hint)
            self._write([e for e in live if e["seq"] != seq])

    def stats(self, now: float) -> SpoolStats:
        # The same view `pending()` would send, not the raw file. These
        # numbers are what `hound relay` shows an operator diagnosing a
        # dead link, and reporting a backlog that will never be
        # delivered is the project's own cardinal sin.
        with self._lock:
            entries = self._deliverable(self._read(), now)
            return SpoolStats(
                pending=len(entries),
                bytes=sum(len(e["body"]) for e in entries),
                oldest_age=(now - min(e["at"] for e in entries)) if entries else 0.0,
                dropped_size=self.dropped_size,
                dropped_age=self.dropped_age,
                dropped_stale=self.dropped_stale,
            )


@dataclass
class Watermark:
    """How far the agent has already collected from its own store.

    Four cursors, not one: flows, alerts and outages have independent
    autoincrement ids, and devices/uptime are snapshots keyed by time.
    """
    flow_id: int = 0
    alert_id: int = 0
    outage_id: int = 0
    reported_at: float = 0.0

    def as_dict(self) -> dict:
        return {"flow_id": self.flow_id, "alert_id": self.alert_id,
                "outage_id": self.outage_id, "reported_at": self.reported_at}

    @classmethod
    def from_dict(cls, d: dict) -> "Watermark":
        return cls(
            flow_id=int(d.get("flow_id", 0)),
            alert_id=int(d.get("alert_id", 0)),
            outage_id=int(d.get("outage_id", 0)),
            reported_at=float(d.get("reported_at", 0.0)),
        )


@dataclass
class AgentState:
    """Persistent agent identity and progress.

    `instance_id` is minted once. It is what makes a wiped volume
    recoverable instead of permanently 409'd, and what makes two agents
    accidentally sharing a sensor_id visible rather than silently
    clobbering each other.
    """
    path: Path
    instance_id: str = ""
    next_seq: int = 1
    watermark: Watermark = field(default_factory=Watermark)
    last_push_ts: float = 0.0
    last_error: str = ""

    @classmethod
    def load(cls, directory: Path, *, readonly: bool = False) -> "AgentState":
        """Load agent identity and progress.

        `readonly=True` is for diagnostics (`hound relay`). Without it a
        read-only-looking command mkdirs the state directory and mints
        AND SAVES a new instance_id whenever the file is missing or
        torn — so running it as a different user, or against a damaged
        file, silently rewrites the agent's identity and resets the
        collector's sequence expectations.
        """
        directory = Path(directory)
        if not readonly:
            directory.mkdir(parents=True, exist_ok=True)
        path = directory / "state.json"
        st = cls(path=path)
        if path.is_file():
            try:
                d = json.loads(path.read_text(encoding="utf-8"))
                st.instance_id = str(d.get("instance_id", ""))
                st.next_seq = int(d.get("next_seq", 1))
                st.watermark = Watermark.from_dict(d.get("watermark", {}))
                st.last_push_ts = float(d.get("last_push_ts", 0.0))
                st.last_error = str(d.get("last_error", ""))
            except (json.JSONDecodeError, ValueError, TypeError):
                log.warning("relay: unreadable state file, starting fresh")
        if not st.instance_id and not readonly:
            st.instance_id = secrets.token_hex(8)
            st.save()
        return st

    def save(self) -> None:
        # Unique temp name: the pusher thread and the shutdown path both
        # save, and a shared "state.json.tmp" lets one truncate the other
        # mid-write. A torn state file loses next_seq and the agent mints
        # a fresh instance_id, which resets the collector's sequence.
        tmp = self.path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps({
            "instance_id": self.instance_id,
            "next_seq": self.next_seq,
            "watermark": self.watermark.as_dict(),
            "last_push_ts": self.last_push_ts,
            "last_error": self.last_error,
        }, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)


# --------------------------------------------------------------------------
# pinned HTTPS client
# --------------------------------------------------------------------------

def fingerprint_of(der: bytes) -> str:
    return "sha256:" + hashlib.sha256(der).hexdigest()


def split_endpoint(url: str) -> tuple[str, int, str]:
    """Split a collector URL into (host, port, path).

    Shared by the poster and by the capture filter that excludes this
    agent's own relay traffic, so the two can never disagree about which
    endpoint is the collector.
    """
    _scheme, _, rest = url.partition("://")
    hostport, _, path = rest.partition("/")
    path = "/" + path
    if hostport.startswith("["):                    # [v6]:port
        host, _, port_s = hostport[1:].partition("]")
        port = int(port_s.lstrip(":") or 443)
    elif ":" in hostport:
        host, _, port_s = hostport.rpartition(":")
        port = int(port_s)
    else:
        host, port = hostport, 443
    return host, port, path


def exclusion_filter(url: str) -> str:
    """A BPF expression excluding this agent's own traffic to the collector.

    Without it the agent captures its own uploads, aggregates them into
    flows, and classifies them — an outbound session to an off-network
    host, which is the shape `telemetry_offnet` exists to flag. It would
    then report that as an alert, relay the alert, and generate more
    traffic doing so. Filtering in tcpdump rather than after parsing also
    keeps the volume off the parser entirely.

    Returns "" when there is nothing to exclude, so callers can treat the
    empty string as "no change".
    """
    if not url:
        return ""
    try:
        host, port, _ = split_endpoint(url)
    except ValueError:
        return ""
    if not host:
        return ""
    return f"not (host {host} and tcp port {port})"


def post_batch(
    url: str, body: bytes, key: str, sensor_id: str, seq: int,
    fingerprints: list[str], timeout: float = 10.0,
) -> tuple[int, dict]:
    """POST one batch, pinning the collector's certificate.

    Connect, hash the peer certificate, compare against the pinned set, and
    only then send. `urllib.request` cannot do this — it never hands back
    the connection — and `ssl` has no verify callback, so the check has to
    happen between connect and request.
    """
    host, port, path = split_endpoint(url)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The pin IS the trust decision; a self-signed collector cert has no
    # chain to validate and its CN is an address, not a name.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    try:
        conn.connect()
        der = conn.sock.getpeercert(binary_form=True)
        got = fingerprint_of(der or b"")
        if got not in fingerprints:
            raise RelayError(
                f"collector certificate {got} is not in the pinned set "
                f"{fingerprints} — refusing to send"
            )
        conn.request("POST", path, body=body, headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            SIG_HEADER: sign(key, body),
            SENSOR_HEADER: sensor_id,
            SEQ_HEADER: str(seq),
        })
        resp = conn.getresponse()
        raw = resp.read(1024 * 64)
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {}
        return resp.status, payload
    finally:
        conn.close()


# --------------------------------------------------------------------------
# agent client
# --------------------------------------------------------------------------

class RelayClient:
    """Collects this sensor's new records and pushes them to the collector.

    Pushing happens on its own thread with the spool as the hand-off. Doing
    it from the daemon tick would hold `_loop_lock` across a network call,
    so a dead collector with a ten-second timeout would stall packet
    processing for ten seconds out of every tick.
    """

    def __init__(self, cfg, store, now=time.time):
        self.cfg = cfg
        self.store = store
        self.now = now
        base = Path(store.path).parent / "relay"
        self.state = AgentState.load(base)
        self.spool = Spool(base, cfg.spool_max_bytes, cfg.spool_max_age_seconds)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ----- collection -----

    def collect(self) -> tuple:
        """Everything new since the last successful push."""
        wm = self.state.watermark
        flows = self.store.flows_since(wm.flow_id)
        alerts = self.store.alerts_since(wm.alert_id)
        outages = self.store.outages_changed_since(wm.outage_id)
        devices = self.store.devices_changed_since(wm.reported_at)
        uptime = self.store.uptime_report(
            self.cfg_report_window(), self.now(),
        )
        return {
            "devices": [
                {"ip": d["ip"], "role": d["role"], "first_seen": d["first_seen"],
                 "last_seen": d["last_seen"], "packet_count": d["packet_count"],
                 "byte_count": d["byte_count"]}
                for d in devices
            ],
            "flows": [
                {"remote_id": f["id"], "src_ip": f["src_ip"],
                 "src_port": f["src_port"], "dst_ip": f["dst_ip"],
                 "dst_port": f["dst_port"], "proto": f["proto"],
                 "first_seen": f["first_seen"], "last_seen": f["last_seen"],
                 "packets": f["packets"], "bytes": f["bytes"],
                 "bytes_to_camera": f["bytes_to_camera"],
                 "bytes_from_camera": f["bytes_from_camera"],
                 "tcp_flags_seen": f["tcp_flags_seen"],
                 "classification": f["classification"]}
                for f in flows
            ],
            "alerts": [
                {"remote_id": a["id"], "ts": a["ts"], "device_ip": a["device_ip"],
                 "kind": a["kind"], "severity": a["severity"],
                 "summary": a["summary"], "detail": a["detail"],
                 "dedup_key": a["dedup_key"]}
                for a in alerts
            ],
            "outages": [
                {"remote_id": o["id"], "camera_ip": o["camera_ip"],
                 "down_since": o["down_since"], "up_at": o["up_at"],
                 "last_seen_before": o["last_seen_before"], "cause": o["cause"]}
                for o in outages
            ],
            "uptime": [
                {"ip": u.ip, "role": u.role, "state": u.state,
                 "last_seen": u.last_seen, "first_seen": u.first_seen,
                 "down_since": u.down_since,
                 "current_downtime": u.current_downtime,
                 "outage_count": u.outage_count,
                 "downtime_seconds": u.downtime_seconds,
                 "monitored_seconds": u.monitored_seconds,
                 "availability": u.availability}
                for u in uptime
            ],
            "monitor": self._monitor(),
        }, _advance(wm, flows, alerts, outages, self.now())

    def cfg_report_window(self) -> float:
        return 86400.0

    def _monitor(self) -> dict:
        last_packet, updated = self.store.heartbeat()
        now = self.now()
        return {
            "alive": (now - updated) < 30.0 if updated else False,
            "blind": bool(last_packet and (now - last_packet) > 120.0),
            "last_activity_ts": last_packet,
        }

    # ----- pushing -----

    def enqueue(self) -> int:
        """Snapshot new records into the spool. Cheap; no network."""
        with self._lock:
            records, new_wm = self.collect()
            if not any(records.get(k) for k in
                       ("devices", "flows", "alerts", "outages", "uptime")):
                return 0
            seq = self.state.next_seq
            body = build_batch(self.cfg.sensor_id, self.state.instance_id,
                               seq, records, self.now())
            self.spool.append(seq, body, self.now())
            self.state.next_seq = seq + 1
            self.state.watermark = new_wm
            self.state.save()
            return seq

    def flush(self) -> bool:
        """Try to deliver everything spooled. Returns True if the spool emptied."""
        with self._lock:
            pending = self.spool.pending(self.now())
        ok = True
        for seq, body in pending:
            try:
                # Re-stamp: a batch spooled during an outage is older than
                # the collector's skew window allows.
                fresh = restamp(body, self.now())
                status, payload = post_batch(
                    self.cfg.url, fresh, self.cfg.key, self.cfg.sensor_id,
                    seq, self.cfg.tls_fingerprint,
                )
            except (RelayError, OSError, ssl.SSLError) as e:
                self.state.last_error = str(e)[:300]
                self.state.save()
                return False
            if status == 200:
                self.spool.ack(seq)
                self.state.last_push_ts = self.now()
                self.state.last_error = ""
                self.state.save()
            elif status == 409:
                # The collector is ahead of us — a wiped volume, or a
                # duplicate. Fast-forward rather than retrying forever.
                last = int(payload.get("last_seq", seq))
                self.spool.drop(seq, f"collector already has seq {last}")
                with self._lock:
                    if self.state.next_seq <= last:
                        self.state.next_seq = last + 1
                        self.state.save()
            elif status in (400, 401):
                # Malformed or unauthorised: retrying cannot help.
                self.spool.drop(seq, f"rejected with {status}: "
                                     f"{payload.get('error', '')[:120]}")
                self.state.last_error = f"{status}: {payload.get('error','')}"[:300]
                self.state.save()
            else:
                self.state.last_error = f"{status}: {payload.get('error','')}"[:300]
                self.state.save()
                ok = False
                break
        return ok

    # ----- thread -----

    def start(self) -> None:
        def _run():
            while not self._stop.wait(self.cfg.batch_seconds):
                try:
                    self.enqueue()
                    self.flush()
                except Exception:       # noqa: BLE001 - never kill the agent
                    log.exception("relay: push cycle failed")
        self._thread = threading.Thread(target=_run, name="hound-relay",
                                        daemon=True)
        self._thread.start()
        log.info("relay: agent %r pushing to %s every %gs",
                 self.cfg.sensor_id, self.cfg.url, self.cfg.batch_seconds)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=15)
            self._thread = None

    def final_flush(self) -> None:
        """Last attempt on clean shutdown so the tail is not lost.

        Quiesces the pusher thread FIRST. The spool serialises its own
        read-modify-write, but two concurrent flushes can still each post
        the same batch, and the shutdown path has no reason to race the
        periodic one. `stop()` is idempotent, so the caller stopping us
        again afterwards is fine.
        """
        self.stop()
        try:
            self.enqueue()
            self.flush()
        except Exception:               # noqa: BLE001
            log.exception("relay: final flush failed")


def _advance(wm: Watermark, flows, alerts, outages, now: float) -> Watermark:
    return Watermark(
        flow_id=max([wm.flow_id] + [f["id"] for f in flows]),
        alert_id=max([wm.alert_id] + [a["id"] for a in alerts]),
        outage_id=max([wm.outage_id] + [o["id"] for o in outages]),
        reported_at=now,
    )
