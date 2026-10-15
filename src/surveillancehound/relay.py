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

    def __init__(self, directory: Path, max_bytes: int, max_age_seconds: float):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "spool.jsonl"
        self.max_bytes = int(max_bytes)
        self.max_age = float(max_age_seconds)
        self.dropped_size = 0
        self.dropped_age = 0
        self.dropped_stale = 0

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
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            "".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries),
            encoding="utf-8",
        )
        os.replace(tmp, self.path)

    def append(self, seq: int, body: bytes, now: float) -> None:
        entries = self._read()
        entries.append({"seq": int(seq), "at": float(now),
                        "body": body.decode("utf-8")})
        entries = self._enforce_caps(entries, now)
        self._write(entries)

    def _enforce_caps(self, entries: list[dict], now: float) -> list[dict]:
        before = len(entries)
        entries = [e for e in entries if (now - e["at"]) <= self.max_age]
        self.dropped_age += before - len(entries)

        def size(es):
            return sum(len(e["body"]) for e in es)

        while entries and size(entries) > self.max_bytes:
            entries.pop(0)        # oldest first
            self.dropped_size += 1
        return entries

    def pending(self, now: float) -> list[tuple[int, bytes]]:
        entries = self._enforce_caps(self._read(), now)
        return [(e["seq"], e["body"].encode("utf-8")) for e in entries]

    def ack(self, seq: int) -> None:
        """Drop everything up to and including `seq` — it is now durable."""
        self._write([e for e in self._read() if e["seq"] > seq])

    def drop(self, seq: int, reason: str) -> None:
        """Discard one batch the collector will never accept."""
        self.dropped_stale += 1
        log.warning("relay: dropping spooled batch seq=%s (%s)", seq, reason)
        self._write([e for e in self._read() if e["seq"] != seq])

    def stats(self, now: float) -> SpoolStats:
        entries = self._read()
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
    def load(cls, directory: Path) -> "AgentState":
        directory = Path(directory)
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
        if not st.instance_id:
            st.instance_id = secrets.token_hex(8)
            st.save()
        return st

    def save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
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
    scheme, _, rest = url.partition("://")
    hostport, _, path = rest.partition("/")
    path = "/" + path
    if hostport.startswith("["):
        host, _, port_s = hostport[1:].partition("]")
        port = int(port_s.lstrip(":") or 443)
    elif ":" in hostport:
        host, _, port_s = hostport.rpartition(":")
        port = int(port_s)
    else:
        host, port = hostport, 443

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
