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
from contextlib import contextmanager
import time
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

# Matches the collector's default [relay].max_records_per_batch. The
# agent cannot see the collector's config, so it self-limits to the
# documented default rather than discovering the cap by rejection.
_MAX_RECORDS_PER_KIND = 1000
# Seconds between spooled batches when replaying a backlog. Chosen to
# sit under the collector's DEFAULT request budget (60/min) with room
# to spare, since the agent cannot see that setting.
#
# A replaying agent costs 2 units every 2.5s = 48 units/minute
# against the default 60. If an operator lowers max_batches_per_minute
# below 48 the agent will out-pace it and self-throttle on 429s:
# lossless, because a 429 ends the flush cycle without acking, but
# slower than it looks. That is the same both-ends coupling as
# max_records_per_batch, and the honest fix is to configure the pair
# together rather than to guess here.
#
# 48 of 60 is not much headroom, and it is per SOURCE ADDRESS, not
# per sensor. Two agents replaying behind one NAT present as one
# source at 96 units/minute and throttle each other; see the NAT
# paragraph in deploy/agent/README.md. Distinct addresses are the
# answer — the collector has no way to tell them apart.
# 2.5s, not 1.2s. Each spooled batch costs the collector TWO metered
# units, not one: it opens a connection (metered at accept, because an
# unmetered TLS handshake was itself a capture-starvation vector) and
# then makes a request on it. At 1.2s that was 100 units/minute
# against a 60/minute budget — the agent locking itself out while
# recovering, which is the exact defect this pacing was added to
# prevent, reintroduced by making connections cost something.
_REPLAY_PACE_S = 2.5
# Budget for draining the spool on a clean shutdown. NOT a hard
# bound on elapsed time: the deadline is checked BETWEEN batches, so
# a post that starts just under it can still run on.
#
# `post_batch` uses a 10s socket timeout (`_POST_TIMEOUT_S`), and a
# socket timeout is PER OPERATION — connect, handshake, write, each
# read — so even 10s is not a bound on one post, only on one of its
# steps. Typical measured shutdown is 25.6s against this 20s budget;
# the realistic worst case is this budget plus one wedged post plus
# one 2.5s pace. `stop()` adds a 15s join before any of it.
#
# What actually has to hold is that nothing OBSERVED is lost, and
# that does not depend on finishing: `daemon.run()` drains and writes
# in-RAM flows BEFORE calling `final_flush`, and whatever does not
# get sent stays spooled for the next run. Both supervisors give more
# room than the worst case (systemd 90s by default; the Docker agent
# sets stop_grace_period: 90s for this reason).
_FINAL_FLUSH_BUDGET_S = 20.0
# How often a persistently unreachable collector is re-reported.
_LINK_LOG_EVERY_S = 3600.0
# Socket timeout for one post. Named so the shutdown-budget comment
# above can refer to the real number — it used to quote "~20s", which
# was not this value or any other in the file.
_POST_TIMEOUT_S = 10.0
# How many carry-forward outage ids `store.outages_changed_since` will
# bind. Mirrored here so the rotation step matches the window; they
# disagreed and left ids permanently unexamined.
_OUTAGE_ID_BINDS = 900
# Delivered batches to accumulate before rewriting the spool file.
#
# The rewrite is O(spool), so doing it per ack cost 682 ms and 63 MB
# on a full 64 MiB spool. Waiting for a FIXED count is better but
# still quadratic overall — a 15,000-batch drain compacts 15,000/N
# times over a file that is only slowly getting smaller.
#
# So the threshold is proportional to what is actually live: compact
# once a quarter of the spool is dead weight. Draining then costs a
# geometric series rather than a product, and the file never carries
# more than ~25% delivered entries. The floor stops a nearly-empty
# spool compacting on every other ack.
_ACK_COMPACT_MIN = 64
_ACK_COMPACT_FRACTION = 4
# "No batch has been confirmed yet". Below any sequence a Spool can
# legally hold, so it cannot be mistaken for one.
_NOTHING_ACKED = -1
# Largest sequence number the agent will adopt from a collector's
# 409. Mirrors the collector's own `_MAX_SEQ`; a value beyond it
# could not have come from a sane peer and gets ignored rather than
# written into state.json.
_MAX_SAFE_SEQ = 2**63 - 1
# Longest a deadline-bearing flush will wait for the lock.
_FLUSH_LOCK_WAIT_S = 5.0
# Body-size self-limit. Mirrors the collector's documented
# [relay].max_body_bytes default; the margin leaves room for
# `restamp`, which rewrites the timestamp after the size is measured.
_DEFAULT_BODY_LIMIT = 2 * 1024 * 1024
_BODY_MARGIN = 0.95
# Floor, so a misconfigured tiny cap cannot stop the agent relaying
# anything at all.
_MIN_BODY_LIMIT = 64 * 1024

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
    """Constant-time signature check.

    `hmac.compare_digest` raises TypeError on non-ASCII str operands,
    and HTTP headers are decoded latin-1 — so one byte >= 0x80 in the
    signature header turned an unauthenticated request into a 500 with
    a full traceback at ERROR level. Measured: 1,102 log lines and 58
    tracebacks in 20s from a single address, and a 500 is the status
    the agent retries forever. A signature that cannot be ASCII cannot
    be valid, so reject it as unauthorised.
    """
    if not signature.isascii():
        return False
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
    # Batches the collector turned out to ALREADY HAVE. Delivery, not
    # loss, and counted apart from `dropped_stale` for that reason —
    # see `Spool.already_delivered`.
    duplicates: int = 0


class CaptureGate:
    """Lets packet capture preempt relayed store access.

    Serialising relayed writes bounded how many threads hold the store
    lock at once, but not how long the capture tick waits for it:
    `HoundStore._lock` is an unfair RLock, so with a queue of ingest
    threads the tick loses the race over and over. Measured, that was
    still 3-4 second freezes of the packet loop — remote-triggered
    blindness, just less of it.

    This makes the ordering explicit rather than leaving it to luck.
    The tick raises a flag; relayed store access waits for it to drop
    before starting a new operation. The tick therefore waits for at
    most ONE in-flight operation instead of an arbitrary run of them.

    Relayed work is strictly less important than seeing packets. If
    the two contend, capture wins — that is the whole premise of the
    daemon.
    """

    def __init__(self) -> None:
        self._open = threading.Event()
        self._open.set()
        self._lock = threading.Lock()
        self._holders = 0

    @contextmanager
    def capture_priority(self):
        """Held by the tick around its store work."""
        with self._lock:
            self._holders += 1
            self._open.clear()
        try:
            yield
        finally:
            with self._lock:
                self._holders -= 1
                if self._holders == 0:
                    self._open.set()

    @contextmanager
    def deferred(self, timeout: float = 10.0):
        """Held by relayed paths around theirs.

        The timeout is a safety valve: a wedged tick must degrade to
        "relay is slow", never to "relay is dead".
        """
        self._open.wait(timeout)
        yield


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
        self.readonly = readonly
        if not readonly:
            self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "spool.jsonl"
        self.max_bytes = int(max_bytes)
        self.max_age = float(max_age_seconds)
        # Persisted beside the spool. These are the numbers `hound
        # relay` exists to show, and it runs in a DIFFERENT PROCESS from
        # the daemon — so in-RAM counters meant the "dropped" line could
        # never print, no matter how much had been dropped.
        self.counters_path = self.dir / "counters.json"
        self.dropped_size = 0
        self.dropped_age = 0
        self.dropped_stale = 0
        self.duplicates = 0
        # Highest sequence the collector has confirmed. Entries at or
        # below it are delivered: never sent again, never counted as
        # a drop, and removed from the file on the next compaction
        # rather than on every ack. See `ack`.
        #
        # -1, not 0, for "nothing acked". Production sequences start
        # at 1, but 0 is a perfectly legal int for a Spool to hold and
        # a 0 sentinel silently swallowed it — a structure should not
        # depend on an invariant that lives in another module.
        self._acked_through = _NOTHING_ACKED
        self._acks_since_compact = 0
        # Undelivered entries present at the last compaction, so the
        # next one triggers proportionally. 0 means "unknown", which
        # the floor covers.
        self._live_at_compact = 0
        self._load_counters()
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
        # Timestamp of the oldest entry the last read/write saw, or
        # None if unknown. It exists so `append` can tell that
        # something has aged out without re-reading the whole spool
        # every cycle — see the age check there.
        self._oldest_at: float | None = None

    def _load_counters(self) -> None:
        """Best effort. These are diagnostics; a damaged file must never
        stop the monitor from starting, which is what a bare int() on a
        hostile or truncated value did."""
        if not self.counters_path.exists():
            # A fresh agent has no counters file. Warning "unreadable"
            # here cried corruption on every first boot, which is how a
            # security tool teaches its operator to ignore warnings.
            return
        try:
            d = json.loads(self.counters_path.read_text(encoding="utf-8"))
            if not isinstance(d, dict):
                return
            self.dropped_size = int(d.get("dropped_size", 0))
            self.dropped_age = int(d.get("dropped_age", 0))
            self.dropped_stale = int(d.get("dropped_stale", 0))
            self.duplicates = int(d.get("duplicates", 0))
            # Persisted so a restart does not re-send what the
            # collector already confirmed. Losing it is survivable —
            # the collector answers 409 and `already_delivered`
            # records that as delivery — but re-sending a day of
            # spool for nothing is worth avoiding.
            # Type-checked like the 409 path checks `last_seq`: a
            # string "9999999" coerced to 9999999, and `true` to 1,
            # which swallows the seq-0 entry the -1 sentinel exists
            # to protect. The two paths read the same class of value
            # off disk or the wire and should agree.
            raw_ack = d.get("acked_through", _NOTHING_ACKED)
            self._acked_through = (
                raw_ack if isinstance(raw_ack, int)
                and not isinstance(raw_ack, bool)
                and raw_ack >= _NOTHING_ACKED else _NOTHING_ACKED)
        except (OSError, ValueError, TypeError, ArithmeticError,
                AttributeError, json.JSONDecodeError):
            # ArithmeticError covers OverflowError, which int() raises on
            # a JSON `1e400` (parsed as inf) and which is NOT a
            # ValueError — the gap that let a diagnostic file stop the
            # monitor even after this was supposedly made best-effort.
            log.warning("relay: unreadable spool counters at %s; the "
                        "drop totals restart from zero", self.counters_path)
            self.dropped_size = self.dropped_age = self.dropped_stale = 0
            self.duplicates = 0

    def _save_counters(self) -> None:
        """Best effort: a diagnostic counter is never worth failing a push."""
        if self.readonly:
            return
        try:
            tmp = self.counters_path.with_suffix(
                f".{os.getpid()}.{threading.get_ident()}.tmp")
            tmp.write_text(json.dumps({
                "dropped_size": self.dropped_size,
                "dropped_age": self.dropped_age,
                "dropped_stale": self.dropped_stale,
                "duplicates": self.duplicates,
                "acked_through": self._acked_through,
            }), encoding="utf-8")
            os.replace(tmp, self.counters_path)
        except OSError:
            pass

    def _read(self) -> list[dict]:
        if not self.path.is_file():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue          # a torn tail line; drop it rather than die
            # Shape, not just syntax. A line that parses but is not a
            # batch — `5`, or a dict missing "at" — used to reach
            # `e["at"]` and `e.get()` downstream and raise
            # TypeError/KeyError/AttributeError. `hound relay` is the
            # command specified to work when things are broken, and it
            # exited 1 with no output at all; the same two functions
            # are on the daemon's append/pending/ack path. The
            # counters file was already defended against exactly this
            # and the spool was not.
            if (not isinstance(rec, dict)
                    or not isinstance(rec.get("at"), (int, float))
                    or not isinstance(rec.get("body"), str)
                    or not isinstance(rec.get("seq"), int)):
                continue
            out.append(rec)
        self._note_oldest(out)
        return out

    def _note_oldest(self, entries: list[dict]) -> None:
        ats = [e["at"] for e in entries if isinstance(e.get("at"), (int, float))]
        self._oldest_at = min(ats) if ats else None

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
        self._note_oldest(entries)

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
            # Compact on expiry too, not only on size.
            #
            # The age cap being enforced on read is enough to stop a
            # stale batch being SENT, but counting only happens on a
            # mutating path — and during an outage there are no acks
            # and no drops, which is exactly when batches expire. A
            # day of observations aged out of a spool that had never
            # grown past its byte cap, and `hound relay` reported
            # `dropped_age 0` throughout: the operator saw a shrinking
            # backlog and no indication anything had been lost.
            #
            # `_oldest_at` is a hint maintained by the last read or
            # write, so the usual cycle costs one float compare rather
            # than re-reading a 64 MB file.
            #
            # When it is UNKNOWN — a fresh process, so every restart —
            # establish it by reading, do not stamp `now`. Stamping
            # claimed the oldest entry had just arrived, so a spool
            # that had been sitting through an outage longer than the
            # age cap never tripped the sweep and its expiries were
            # never counted. Over 150 randomised append/ack/restart
            # sequences that silently under-reported real loss on 6 of
            # them. One read per process start is the right price for
            # a number the drop accounting depends on.
            if self._oldest_at is None:
                self._note_oldest(self._read())
            expired = (self._oldest_at is not None
                       and (now - self._oldest_at) > self.max_age)
            if oversized or expired:
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
        # Delivered entries are not pending and are not loss. They sit
        # in the file until the next compaction, so every reader has to
        # look past them — and `_enforce_caps` must not count them when
        # they age out, or a long outage would report a day of
        # "dropped" data the collector had already acknowledged.
        entries = [e for e in entries if e["seq"] > self._acked_through]
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
        # Count against the UNDELIVERED set only, for the same reason.
        entries = [e for e in entries if e["seq"] > self._acked_through]
        kept = self._deliverable(entries, now)
        if len(kept) != len(entries):
            # Identify the dropped set by IDENTITY, not by position and
            # not by sequence.
            #
            # Not by position: `entries[:n]` assumed file order is age
            # order, and `replace()` deliberately breaks that — a split
            # batch's parts inherit the original's timestamp and land at
            # the tail. So an age expiry could be attributed to the size
            # cap. The total stayed exact, but it pointed the operator
            # at `spool_max_bytes` when the age cap was what discarded
            # their data.
            #
            # Not by sequence either: sequences are not unique in the
            # file. `enqueue` appends to the spool BEFORE it saves the
            # advanced `next_seq`, so a kill between those two writes
            # leaves a sequence spooled that the next run mints again.
            # With a set of sequences, evicting one of a duplicated pair
            # while keeping the other found the survivor's seq in
            # `kept_seqs` and counted NOTHING — the entry was removed
            # from the file and no counter moved. That hides loss, which
            # is the failure this whole accounting exists to prevent;
            # the positional form it replaced at least got the total
            # right. `_deliverable` returns the same dict objects, so
            # identity is exact.
            kept_ids = {id(e) for e in kept}
            dropped = [e for e in entries if id(e) not in kept_ids]
            aged = sum(1 for e in dropped if (now - e["at"]) > self.max_age)
            self.dropped_age += aged
            self.dropped_size += len(dropped) - aged
            self._save_counters()
        return kept

    def pending(self, now: float) -> list[tuple[int, bytes]]:
        # `_now_hint` only ever advances here, and `_flush_locked`
        # calls this ONCE per cycle — so the clock is frozen for the
        # whole drain. That is load-bearing, not incidental: the
        # sweep in `ack` uses `_now_hint`, so a clock that advanced
        # mid-drain could count a batch as aged out between being
        # handed to the poster and being acknowledged, reporting a
        # DELIVERED batch as expired. `stats()` deliberately does not
        # bump it either.
        with self._lock:
            self._now_hint = max(self._now_hint, now)
            entries = self._deliverable(self._read(), now)
            return [(e["seq"], e["body"].encode("utf-8")) for e in entries]

    def ack(self, seq: int) -> None:
        """Everything up to and including `seq` is durable on the collector.

        O(1) in the size of the spool. It used to read and rewrite the
        WHOLE file on every delivered batch, which is the same O(n^2)
        churn `append` documents and avoids for enqueue. Measured on a
        full 64 MiB spool of 15,427 batches: 682 ms of CPU and 63 MB
        rewritten PER ACK — about 175 CPU-minutes and 971 GB to drain
        one long outage. The agent runs the whole capture pipeline
        beside this and has no `CaptureGate`, so that CPU competes
        with its own packet loop, and on an SD- or eMMC-booted NVR the
        writes are the thing that kills the card.

        So the ack moves a watermark and the file is compacted on a
        cadence. Three things have to hold for that to be safe, and
        each is load-bearing:

        * The watermark is PERSISTED (`counters.json`), so a restart
          does not re-send what was already confirmed.
        * Every reader filters on it, so a delivered entry is never
          sent twice even before it is physically removed.
        * `_enforce_caps` counts only UNDELIVERED entries, so a
          delivered one ageing out before compaction is not reported
          as lost data.
        """
        with self._lock:
            if seq <= self._acked_through:
                return
            # Count expiries BEFORE the watermark moves past them.
            #
            # This guard existed, and making `ack` O(1) deleted it
            # along with the full rewrite it was attached to. The
            # delivered-filter runs ahead of the drop counters, so a
            # batch that aged out UNSENT and then falls below an
            # advancing watermark is removed as though it had been
            # delivered and never reaches `dropped_age`. Measured
            # over 100 randomised append/ack/409/drop/restart
            # sequences: 100 of 100 under-reported real loss, by up
            # to 36 batches of 99.
            #
            # Trigger at stock settings: an outage longer than
            # `spool_max_age_seconds`, then a restart — on a fresh
            # Spool `_oldest_at` is None, so the first append skips
            # its own sweep and stamps a false "oldest" — then the
            # collector returns and the fresh tail is acked. Restarts
            # are routine: upgrades, config changes, and the
            # `daemon -r` respawn CLAUDE.md requires.
            #
            # Hiding loss that happened is the same sin as reporting
            # loss that did not, which is what this whole change set
            # was for.
            self._sweep_expiries_locked()
            self._acked_through = int(seq)
            self._acks_since_compact += 1
            self._save_counters()
            self._maybe_compact()

    def already_delivered(self, seq: int, last_seq: int) -> None:
        """The collector says it already has this batch. NOT a loss.

        A 409 means the records are on the collector — a duplicate, or
        a watermark we lost. Routing it through `drop()` counted it in
        `dropped_stale`, so `hound relay` reported discarded
        observations for data that had in fact arrived. Reporting loss
        that did not happen is the same class of error as hiding loss
        that did.
        """
        with self._lock:
            self.duplicates += 1
            log.info("relay: batch seq=%s was already on the collector "
                     "(it is at seq %s); treating as delivered",
                     seq, last_seq)
            if seq > self._acked_through:
                # Same reason as `ack`: expiries are counted before
                # the watermark can hide them.
                self._sweep_expiries_locked()
                self._acked_through = int(seq)
            self._acks_since_compact += 1
            self._save_counters()
            self._maybe_compact()

    @property
    def acked_through(self) -> int:
        """Highest sequence the collector has confirmed. -1 if none.

        Exposed because `hound relay` is the command an operator runs
        when the agent looks stuck, and a watermark is the one piece
        of spool state that can make a healthy-looking spool empty.
        """
        return self._acked_through

    def highest_spooled_seq(self) -> int | None:
        """The largest sequence still in the file, or None if empty.

        For the one caller that cannot clamp — `hound relay` with an
        unreadable state file — and needs to say whether the
        watermark it is choosing to trust is possible at all. A
        watermark ABOVE every spooled sequence cannot have come from
        an ack for anything in the file.
        """
        with self._lock:
            seqs = [e["seq"] for e in self._read()]
        return max(seqs) if seqs else None

    def reconcile_watermark(self, highest_minted: int, now: float) -> None:
        """Clamp an impossible delivered-watermark back below the spool.

        `counters.json` is best-effort and lives on disk beside the
        spool. A corrupt or truncated value — or a hostile one, on a
        host where the threat model is already lost — made every
        entry compare as delivered, so the agent discarded its whole
        spool and reported `pending 0` with every drop counter at
        zero. Silent loss that passes its own audit is the worst
        shape this project has, and the watermark introduced it.

        The bound is exact rather than a heuristic: `AgentState`
        mints every sequence, so one above the highest ever minted
        cannot have been acknowledged by anybody.

        `now` is only used to report accurately how many of the
        re-exposed batches are still within the caps, and is
        REQUIRED. It defaulted to `_now_hint`, which is 0.0 before
        the first push cycle — so the default read every entry as
        fresh and produced the one thing this method exists to
        avoid, a count that is not true.
        """
        with self._lock:
            if self._acked_through <= highest_minted:
                return
            # Clamp BELOW the lowest sequence still in the file, not
            # merely to the highest ever minted.
            #
            # Every spooled entry was minted by `AgentState`, so every
            # entry is at or below `highest_minted` — clamping only to
            # that left them all hidden, every drop counter at zero,
            # and removed silently at the next compaction, while this
            # very message promised they would be "re-sent rather
            # than discarded". A log line that states something the
            # code does not do is the same failure as a dashboard
            # that does.
            #
            # Safe because this branch is only reached when the
            # watermark is IMPOSSIBLE — above anything ever created.
            # Nothing here can be trusted to mean "delivered", so
            # re-sending is the only honest reading, and the
            # collector answers 409 for whatever it already holds.
            entries = self._read()
            floor = highest_minted
            if entries:
                floor = min(floor, min(e["seq"] for e in entries) - 1)
            claimed = self._acked_through
            self._acked_through = max(_NOTHING_ACKED, int(floor))
            # Report what the clamp ACTUALLY re-exposes. Re-exposing is
            # not the same as re-sending: an entry past
            # `spool_max_age_seconds`, or squeezed out of
            # `spool_max_bytes` now that the delivered ones are visible
            # again, is dropped on the next sweep. Saying "re-sent" of
            # those is the same class of untrue statement this clamp
            # was written to fix.
            resent = len(self._deliverable(entries, now))
            stale = len(entries) - resent
            if not entries:
                # Nothing to re-send and nothing lost: the agent had
                # delivered everything and the spool was compacted.
                # This is the ORDINARY damaged-counters case, and the
                # loss branch below reported "0 spooled batch(es) ...
                # those observations are lost" for it — a false loss
                # report standing in for the false delivery report
                # this clamp was written to remove.
                log.warning(
                    "relay: spool watermark claims batch %s was "
                    "delivered but this agent has only ever created "
                    "%s; the counters file is damaged. Clamping to "
                    "%s. The spool is empty, so nothing was hidden "
                    "and nothing is lost.",
                    claimed, highest_minted, self._acked_through)
            elif resent:
                log.warning(
                    "relay: spool watermark claims batch %s was "
                    "delivered but this agent has only ever created "
                    "%s; the counters file is damaged. Clamping to "
                    "%s, so %d spooled batch(es) are re-sent — the "
                    "collector answers 409 for any it already holds%s.",
                    claimed, highest_minted, self._acked_through, resent,
                    f". The other {stale} cannot be sent — past a "
                    f"spool cap, or below even the clamped watermark — "
                    f"and are counted as dropped on the next sweep"
                    if stale else "")
            else:
                # Deliberately not "every one is past a cap": when the
                # floor bottoms out at the sentinel because a planted
                # sequence is negative, the survivors are below the
                # watermark rather than expired. Say what is certain —
                # they will not be sent — and not a reason that may
                # not be the true one.
                log.warning(
                    "relay: spool watermark claims batch %s was "
                    "delivered but this agent has only ever created "
                    "%s; the counters file is damaged. Clamping to "
                    "%s. None of the %d spooled batch(es) can be "
                    "re-sent — they are past a spool cap, or below "
                    "even the clamped watermark — and are counted as "
                    "dropped on the next sweep. Those observations "
                    "are lost.",
                    claimed, highest_minted, self._acked_through,
                    len(entries))
            self._save_counters()

    def _sweep_expiries_locked(self) -> None:
        """Compact if anything has aged out, so it is COUNTED.

        O(1) in the common case — one float compare against the
        `_oldest_at` hint — and only reads the file when something
        has actually expired, so it does not reintroduce the
        per-ack rewrite. Caller holds `_lock`.
        """
        if (self._oldest_at is not None
                and (self._now_hint - self._oldest_at) > self.max_age):
            self._compact_locked()

    def _maybe_compact(self) -> None:
        """Rewrite once a quarter of the spool is delivered. Holds `_lock`."""
        threshold = max(_ACK_COMPACT_MIN,
                        self._live_at_compact // _ACK_COMPACT_FRACTION)
        if self._acks_since_compact >= threshold:
            self._compact_locked()

    def _compact_locked(self) -> None:
        """Physically remove delivered and expired entries. Caller holds
        `_lock`."""
        self._acks_since_compact = 0
        kept = self._enforce_caps(self._read(), self._now_hint)
        self._live_at_compact = len(kept)
        self._write(kept)

    def replace(self, seq: int, parts: list[tuple[int, bytes]]) -> None:
        """Swap one batch for smaller ones. NOT a drop.

        Deliberately does not touch `dropped_stale`: nothing is being
        discarded, so counting it would make `hound relay` report data
        loss that did not happen — the opposite of the reporting sin
        this spool exists to avoid.

        THE REPLACEMENTS INHERIT THE ORIGINAL'S TIMESTAMP. Stamping
        them `now` reset `oldest_age` on every replacement, so
        `spool_max_age_seconds` could never expire an entry that kept
        being re-split — removing the one bound that would have ended
        such a loop, and making `hound relay` report a backlog as
        freshly arrived when it was a day old. These records were
        observed when the original said they were.
        """
        with self._lock:
            live = self._read()
            at = next((e["at"] for e in live if e["seq"] == seq),
                      self._now_hint)
            kept = [e for e in live if e["seq"] != seq]
            for new_seq, body in parts:
                kept.append({"seq": int(new_seq), "at": float(at),
                             "body": body.decode("utf-8")})
            self._write(self._enforce_caps(kept, self._now_hint))

    def drop(self, seq: int, reason: str) -> None:
        """Discard one batch the collector will never accept.

        Counts ENTRIES removed, not calls. A sequence is not unique in
        the file — `enqueue` appends before it saves the advanced
        `next_seq`, so a kill between those two writes leaves a
        sequence the next run mints again — and `+= 1` then discarded
        two observations while reporting one. Same defect as the
        eviction counter had, on the other removal path.

        Removing BOTH entries of a re-minted pair is itself coarse:
        only the posted one was rejected, and the other is unrelated
        data carrying the same number. Nothing in the file can tell
        them apart, so the honest thing is to count what actually
        went, which is what the operator needs to know.
        """
        with self._lock:
            log.warning("relay: dropping spooled batch seq=%s (%s)", seq, reason)
            live = self._enforce_caps(self._read(), self._now_hint)
            kept = [e for e in live if e["seq"] != seq]
            self.dropped_stale += len(live) - len(kept)
            self._save_counters()
            self._write(kept)

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
                duplicates=self.duplicates,
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
    # Outage ids we last sent while they were still OPEN. Re-queried
    # next cycle so their close is transmitted exactly once; without it
    # the watermark advances past an open outage and its eventual close
    # never matches the query again.
    open_outage_ids: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"flow_id": self.flow_id, "alert_id": self.alert_id,
                "outage_id": self.outage_id, "reported_at": self.reported_at,
                "open_outage_ids": list(self.open_outage_ids)}

    @classmethod
    def from_dict(cls, d: dict) -> "Watermark":
        return cls(
            flow_id=int(d.get("flow_id", 0)),
            alert_id=int(d.get("alert_id", 0)),
            outage_id=int(d.get("outage_id", 0)),
            open_outage_ids=[int(x) for x in d.get("open_outage_ids", [])
                             if isinstance(x, (int, float))][:10000],
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
    #: True only when an existing state file parsed COMPLETELY. Not
    #: persisted — it describes this load, not the agent. Callers that
    #: compare the spool against `next_seq` must gate on this and not
    #: on `instance_id`: a partial parse can leave a plausible id
    #: beside a defaulted `next_seq`, and `highest_minted = 0` then
    #: blames an intact counters file for the agent's whole backlog.
    loaded: bool = False
    #: True when a state file was PRESENT and failed to parse. Distinct
    #: from `not loaded`, which is also the ordinary first run: `load`
    #: mints an identity and saves it, so by the time a caller looks,
    #: the file exists and "exists but did not load" would be true of
    #: a perfectly healthy new agent.
    parse_failed: bool = False

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
                if not isinstance(d, dict):
                    raise TypeError("state file is not an object")
                # Parse into locals and commit together. Assigning as we
                # went left a half-loaded state behind on a mid-parse
                # failure: `instance_id` is the FIRST field read, so a
                # file whose `next_seq` was garbage produced a state
                # that looked loaded and claimed the agent had never
                # minted a sequence.
                # STRICT on both identity fields, for the same reason
                # `_load_counters` is strict about `acked_through`: a
                # bare `int()`/`str()` does not fail on a wrong value,
                # it invents a plausible one, and "did the conversion
                # raise" is therefore not the same question as "is
                # this a sequence".
                #
                # `next_seq` decides `highest_minted`, so every value
                # that silently became 1 — `true`, `"1"`, `1.9`, a
                # negative, a missing key — re-entered the bug the
                # `loaded` flag was added to close: the clamp blames
                # an intact counters file and reports the whole spool
                # as backlog. A sequence is a positive int and nothing
                # else; anything else is a damaged file.
                raw_seq = d.get("next_seq")
                if (not isinstance(raw_seq, int)
                        or isinstance(raw_seq, bool) or raw_seq < 1):
                    raise ValueError(f"next_seq is not a sequence: {raw_seq!r}")
                next_seq = raw_seq
                # `str()` of `None` is "None", which is non-empty, so
                # the re-mint guard below never fired and the agent
                # ran permanently as instance "None". A dict or list
                # became its repr.
                raw_id = d.get("instance_id", "")
                if not isinstance(raw_id, str):
                    raise ValueError(f"instance_id is not a string: {raw_id!r}")
                instance_id = raw_id
                watermark = Watermark.from_dict(d.get("watermark", {}))
                last_push_ts = float(d.get("last_push_ts", 0.0))
                last_error = str(d.get("last_error", ""))
            except (OSError, json.JSONDecodeError, ValueError, TypeError,
                    ArithmeticError, AttributeError):
                log.warning("relay: unreadable state file, starting fresh")
                st.parse_failed = True
            else:
                st.instance_id = instance_id
                st.next_seq = next_seq
                st.watermark = watermark
                st.last_push_ts = last_push_ts
                st.last_error = last_error
                st.loaded = True
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
    fingerprints: list[str], timeout: float = _POST_TIMEOUT_S,
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
            if not isinstance(payload, dict):
                # A top-level array, string or number is valid JSON
                # and not a response. Every caller does
                # `payload.get(...)`, so anything else became an
                # AttributeError out of the flush — the batch neither
                # acked nor dropped, the same response next cycle,
                # forever. The collector never sends these; a buggy
                # proxy or a hostile pinned collector could.
                payload = {}
        except Exception:                    # noqa: BLE001
            # Not just JSONDecodeError/UnicodeDecodeError: a body of
            # 65,536 open brackets — inside the read cap — raises
            # RecursionError out of `json.loads`, which escaped
            # `_flush_locked`'s (RelayError, OSError, SSLError)
            # envelope entirely. The batch was then neither acked nor
            # dropped, `last_error` never set and `_note_link` never
            # called: the identical response every cycle forever,
            # with `hound relay` reporting health. A response we
            # cannot parse is simply a response we cannot parse.
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
        # The two files are written independently and either can be
        # damaged on its own. A delivered-watermark above the highest
        # sequence this agent ever minted is impossible, and taking it
        # at face value silently discards the spool.
        #
        # The daemon reconciles even when the state file did not load,
        # unlike `hound relay`: here a fresh `next_seq` is REAL — this
        # process will mint from 1 — so the spool genuinely must be
        # re-exposed rather than left behind a watermark no future ack
        # can ever reach. Say which file is actually suspect, though,
        # or the clamp blames the counters for the state file's fault.
        if self.state.parse_failed:
            # NOT "re-sent under it": `enqueue` bakes the identity into
            # the body at spool time and `restamp` rewrites only
            # `sent_at`, so spooled batches go under the OLD identity —
            # which is exactly why the collector can still 409 them,
            # since it matches on (sensor, instance, seq).
            #
            # The watermark reset is the big one and was missing: the
            # per-kind positions go back to 0, so this run re-collects
            # and re-relays the whole local store, not just the spool.
            log.warning(
                "relay: state file at %s did not parse. This run mints "
                "a new identity and starts from sequence 1; the "
                "per-kind watermarks reset too, so it re-relays this "
                "sensor's whole store rather than only what is new. "
                "Spooled batches still carry their original identity, "
                "so the collector answers 409 for the ones it already "
                "holds.", self.state.path)
        self.spool.reconcile_watermark(self.state.next_seq - 1,
                                       self.now())
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        # Link-health logging state. See `_note_link`.
        #   _link_down_since: start of the CURRENT outage, or None
        #   _link_logged_at:  last time we said anything — NEVER reset
        #                     by a recovery, or a flap defeats the rate
        #                     limit entirely
        #   _link_warned:     did we report the current outage
        #   _link_flaps:      outages since the last report
        self._link_down_since: float | None = None
        self._link_logged_at = 0.0
        self._link_warned = False
        self._link_flaps = 0
        # Limits learned from a collector rejection. See `_learn_limits`.
        self._learned_records = 0
        self._learned_body = 0
        # Where the open-outage re-send sweep is up to. See
        # `_rotate_open`.
        self._open_cursor = 0
        # Limit pairs already reported, so a collector cannot buy a
        # log line per batch by alternating them.
        self._limits_logged: set[tuple[int, int]] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ----- collection -----

    def _rotate_open(self, open_ids) -> list[int]:
        """Rotate the open-outage carry-forward list.

        Secondary to the fix in `outages_changed_since`, which sorts
        closes ahead of still-open repeats — that is what stops a
        recovery being crowded out. This only matters when more
        CLOSES are owed at once than fit in one batch, which needs a
        mass recovery on a large fleet.

        Still worth having: the store can only bind as many ids as fit
        in a batch, so a fixed slice would leave the surplus
        permanently unexamined. Rotating gives each a turn within
        ceil(n / limit) cycles. The cursor is in RAM only — the SET is
        persisted in the watermark, and a restart that begins the
        sweep from the top again costs nothing.
        """
        ids = sorted(int(i) for i in open_ids)
        if not ids:
            return []
        n = len(ids)
        off = self._open_cursor % n
        # Step by the window the STORE will bind, not by `_per_kind()`.
        # `outages_changed_since` clamps to 900 binds, and `enqueue`'s
        # halving loop can lower `_per_kind` below that — so the two
        # disagreed, and when the step exceeded the window the ids in
        # between were never examined. Measured: 2,000 carry-forward
        # ids with a step of 1,000 reached 2 of 2,000 offsets in 400
        # cycles. Stepping by exactly the window tiles the list.
        window = max(1, min(self._per_kind(), _OUTAGE_ID_BINDS))
        self._open_cursor = (off + window) % n
        return ids[off:] + ids[:off]

    def _per_kind(self) -> int:
        """Records per kind this agent will send.

        Taken from its OWN config so that lowering the limit on both
        ends actually works. A collector cap below this rejects 400,
        which the agent treats as terminal — permanent silent loss —
        so the two must be configured together.
        """
        cap = getattr(self.cfg, "max_records_per_batch", 0) or 0
        own = min(cap, _MAX_RECORDS_PER_KIND) if cap > 0 \
            else _MAX_RECORDS_PER_KIND
        # A collector that refused a batch tells us its real cap in the
        # rejection. Honour the lower of the two from then on, so the
        # mismatch costs one rejected batch rather than every batch.
        learned = self._learned_records
        return max(1, min(own, learned)) if learned else own

    def collect(self, per_kind: int | None = None) -> tuple:
        """Everything new since the last successful push.

        `per_kind` overrides the configured cap. `enqueue` lowers it
        when the record cap alone produces a body the collector would
        refuse — see `_body_limit`.
        """
        wm = self.state.watermark
        # EVERY kind honours the configured cap, not just uptime. It
        # was applied to uptime alone while the comment claimed
        # "lowering it on both ends works" — so a collector configured
        # below 5000 rejected 400 on the other four kinds, the agent
        # treated that as terminal and dropped the batch, and the
        # watermark had already advanced at enqueue. Permanent, silent,
        # total loss, with flush() returning success.
        per_kind = self._per_kind() if per_kind is None else max(1, per_kind)
        flows = self.store.flows_since(wm.flow_id, limit=per_kind)
        alerts = self.store.alerts_since(wm.alert_id, limit=per_kind)
        outages = self.store.outages_changed_since(
            wm.outage_id, open_ids=self._rotate_open(wm.open_outage_ids),
            limit=per_kind)
        devices = self.store.devices_changed_since(
            wm.reported_at, limit=per_kind)
        if len(devices) >= per_kind:
            # Deferred, not dropped — see `_advance`, which holds the
            # devices cursor at the newest `last_seen` actually sent so
            # the remainder arrives next cycle. Said out loud anyway,
            # because until it drains the collector's device list is
            # incomplete and an operator comparing the two will notice.
            log.info(
                "relay: device list hit the %d-record batch limit; the "
                "remainder follows in the next batch. Raise [relay] "
                "max_records_per_batch on both ends if this is "
                "routine.", per_kind)
        # Capped like every other collector here. uptime_report returns
        # one row per camera with no limit, so a sensor with more
        # cameras than the collector's max_records_per_batch had EVERY
        # batch rejected 400 and dropped — permanent, silent, total
        # loss with no backpressure signal. Truncating degrades to
        # "some cameras reported" instead.
        all_uptime = self.store.uptime_report(
            self.cfg_report_window(), self.now(),
        )
        uptime = all_uptime[:per_kind]
        if len(all_uptime) > per_kind:
            # `uptime_report` is ORDER BY ip, so a plain prefix hides
            # the SAME high-sorted cameras on every cycle — they would
            # be permanently invisible on the collector, which gets no
            # signal at all because this warning is agent-side. Say how
            # many are missing rather than implying a clean truncation.
            log.warning(
                "relay: %d cameras to report but only %d fit in a batch; "
                "%d are NOT being relayed and will not appear on the "
                "collector. Raise [relay] max_records_per_batch on both "
                "ends.", len(all_uptime), per_kind,
                len(all_uptime) - per_kind)
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
        }, _advance(wm, flows, alerts, outages, self.now(),
                    devices=devices,
                    devices_truncated=len(devices) >= per_kind)

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

    def _body_limit(self) -> int:
        """Largest body this agent will build, in bytes.

        The record cap alone is not enough to stay under the
        collector's body cap, and the two are reached by different
        arithmetic. At STOCK DEFAULTS — 1000 records per kind, 1024
        characters per string, 2 MiB body cap — a batch of 1000
        maximal alerts serialises to 2.24 MB and is refused 413. That
        needs no hostile input and no unusual configuration: a camera
        segment that generates a thousand alerts between pushes is a
        bad afternoon, not an attack.

        A 413 is TERMINAL on the agent side (retrying a body that
        will be exactly as large next time wedges the spool), so the
        batch is dropped. Discovering the cap by having observations
        destroyed is the wrong way round; this keeps the agent inside
        it instead.

        Taken from the agent's own config for the same reason
        `_per_kind` is: the agent cannot see the collector's setting,
        so it honours the documented default and the pair has to be
        configured together. The margin covers `restamp`, which
        rewrites the timestamp after the size is known.
        """
        cap = getattr(self.cfg, "max_body_bytes", 0) or 0
        if cap <= 0:
            cap = _DEFAULT_BODY_LIMIT
        if self._learned_body:
            # The floor is NOT applied to a cap the collector actually
            # enforces. The floor exists so a misconfigured LOCAL cap
            # cannot stop the agent relaying anything at all; raising a
            # learned cap back up to it would mean knowingly building
            # bodies we have been told will be refused.
            return max(1, int(min(cap, self._learned_body) * _BODY_MARGIN))
        return max(_MIN_BODY_LIMIT, int(cap * _BODY_MARGIN))

    def enqueue(self) -> int:
        """Snapshot new records into the spool. Cheap; no network."""
        with self._lock:
            limit = self._body_limit()
            per_kind = self._per_kind()
            while True:
                records, new_wm = self.collect(per_kind=per_kind)
                if not any(records.get(k) for k in
                           ("devices", "flows", "alerts", "outages",
                            "uptime")):
                    return 0
                seq = self.state.next_seq
                body = build_batch(self.cfg.sensor_id,
                                   self.state.instance_id, seq, records,
                                   self.now())
                if len(body) <= limit or per_kind <= 1:
                    break
                # Halve and re-collect. The watermark comes from the
                # records actually included, so the remainder is not
                # lost — it goes in the next batch. Flows and alerts
                # are id-watermarked and strictly resume; devices and
                # uptime are snapshots keyed on time, so a narrower
                # batch reports fewer of them this cycle and the rest
                # on the next change or tick.
                per_kind = max(1, per_kind // 2)
                log.warning(
                    "relay: batch of %d bytes exceeds the %d-byte body "
                    "limit; retrying with %d records per kind. The "
                    "remainder follows in the next batch. Raise [relay] "
                    "max_body_bytes on BOTH ends if this is routine.",
                    len(body), limit, per_kind)
            if len(body) > limit:
                log.warning(
                    "relay: a single-record batch is %d bytes, over the "
                    "%d-byte limit; sending it anyway — the collector "
                    "will refuse it and it will be dropped.",
                    len(body), limit)
            self.spool.append(seq, body, self.now())
            self.state.next_seq = seq + 1
            self.state.watermark = new_wm
            self.state.save()
            return seq

    def _learn_limits(self, payload: dict) -> bool:
        """Adopt the limits a collector reported. True if either moved."""
        lim = payload.get("limits")
        if not isinstance(lim, dict):
            return False
        moved = False
        recs = lim.get("max_records_per_batch")
        if isinstance(recs, int) and not isinstance(recs, bool) and recs > 0:
            if self._learned_records != recs:
                self._learned_records = recs
                moved = True
        body = lim.get("max_body_bytes")
        if isinstance(body, int) and not isinstance(body, bool) and body > 0:
            if self._learned_body != body:
                self._learned_body = body
                moved = True
        if moved:
            # Throttled on the pair of values, not on each change. A
            # collector alternating two settings would otherwise buy
            # one WARNING per batch — the same remote-controlled log
            # flood the collector's own instance-reset branch is
            # throttled for.
            seen = (self._learned_records, self._learned_body)
            if seen in self._limits_logged:
                return moved
            self._limits_logged.add(seen)
            if len(self._limits_logged) > 32:
                self._limits_logged.clear()
                self._limits_logged.add(seen)
            log.warning(
                "relay: collector enforces max_records_per_batch=%s "
                "max_body_bytes=%s, lower than this agent was using. "
                "Adopting them. Set the same values in the agent's "
                "[relay] section so the first batch after a restart is "
                "not rejected too.",
                self._learned_records or "unchanged",
                self._learned_body or "unchanged")
        return moved

    def _resplit(self, seq: int, body: bytes, payload: dict,
                 status: int) -> bool:
        """Halve a rejected batch and re-spool it. True if re-spooled.

        400 and 413 are permanent for the batch AS SENT — the body will
        be exactly as large and hold exactly as many records next time
        — so the old code dropped it. But the watermark advanced at
        enqueue, so dropping meant the observations were gone: measured,
        a collector lowered to 500 records while the agent stayed at the
        default destroyed 1000 of 1200 alerts, with `flush()` returning
        True and the spool reporting empty.

        Permanent for the batch as sent is not the same as permanent
        for its CONTENTS. Splitting it makes the mismatch cost a cycle
        instead of a day of observations.

        THREE THINGS GUARD AGAINST AN IMMORTAL BATCH, and the first
        version of this had none of them.

        1. It only runs for a rejection the collector answered with
           `limits` — the 413 and every `validate_records` 400. A 400
           for clock skew, a bad instance id, a header mismatch or an
           implausible sequence carries none, and no amount of
           splitting will ever help those; splitting them anyway
           re-posted the same batch forever.

           Note that a `validate_records` 400 is not only the
           per-kind cap: a single malformed record lands here too.
           Splitting is still the right response — it terminates in
           about log2(N) rounds and SALVAGES the good records,
           dropping only the single one that is actually bad, where
           the old behaviour discarded the whole batch.
        2. It requires PROGRESS. Halving each kind at
           `(len+1)//2` moves nothing when every kind already holds a
           single record: the first half takes them all, the second is
           empty, and the replacement is byte-identical to what was
           just refused. Measured on the most ordinary batch a
           one-camera agent sends — one device plus one uptime row —
           that looped every cycle forever. So a batch whose kinds
           cannot be halved is split ACROSS kinds instead, and if even
           that cannot reduce it, this returns False and the caller
           drops it.
        3. The replacement keeps the ORIGINAL spool timestamp. Stamping
           it `now` reset `oldest_age` every cycle, so
           `spool_max_age_seconds` could never expire it and the one
           bound that would have ended the loop was defeated.
        """
        self._learn_limits(payload)
        if not isinstance(payload.get("limits"), dict):
            # Not a size rejection. See guard 1 above.
            return False
        try:
            doc = json.loads(body)
            records = doc["records"]
            if not isinstance(records, dict):
                return False
        except (ValueError, KeyError, TypeError):
            return False
        lists = {k: v for k, v in records.items() if isinstance(v, list)}
        scalars = {k: v for k, v in records.items()
                   if not isinstance(v, list)}
        total = sum(len(v) for v in lists.values())
        if total < 2:
            return False          # one record; nothing to divide
        halves: list[dict] = [{}, {}]
        if any(len(v) > 1 for v in lists.values()):
            for kind, items in lists.items():
                mid = (len(items) + 1) // 2
                halves[0][kind] = items[:mid]
                halves[1][kind] = items[mid:]
        else:
            # Every kind holds exactly one record, so halving within a
            # kind cannot move anything. Deal the kinds out instead.
            for i, (kind, items) in enumerate(sorted(lists.items())):
                halves[i % 2][kind] = items
        # `monitor` goes in EVERY part, and is REBUILT, not copied.
        #
        # It is a snapshot upserted onto the sensor row, not a counted
        # record, so repeating it is idempotent. Sending it with only
        # the first half meant the second half arrived with no monitor
        # block — and the collector writes `mon_blind` unconditionally
        # from `records.get("monitor") or {}`, so that CLEARED it.
        #
        # Copying the ORIGINAL block into both parts fixed that and
        # created a subtler version of the same fabrication. The parts
        # get new, highest sequence numbers and go to the TAIL of the
        # spool, so they are posted after batches enqueued later that
        # carry a newer monitor — and `build_batch` re-stamps
        # `sent_at`, so the stale snapshot looks freshest to the
        # collector and its upsert takes it. A sensor that had gone
        # blind rendered as seeing again. Measured: posting order
        # (2, blind=True), (3, blind=False), (4, blind=False), ending
        # at mon_blind = 0.
        #
        # These parts are being sent NOW, so they carry what is true
        # NOW. There is no ordering guarantee to repair; there is just
        # no reason to ship a snapshot we know is out of date.
        fresh = dict(scalars)
        if "monitor" in fresh:
            fresh["monitor"] = self._monitor()
        for half in halves:
            if any(half.get(k) for k in half):
                half.update(fresh)
        shaped = [h for h in halves
                  if any(isinstance(v, list) and v for v in h.values())]
        if len(shaped) < 2:
            # No progress: one part holding everything is the batch we
            # were just refused. Let the caller drop it rather than
            # re-posting it forever.
            #
            # DEFENSIVE, and currently unreachable — no mutation test
            # can cover it, which is why this says so. Above, the
            # halving branch runs only when some kind holds 2+ records
            # (so the second half is always non-empty), and the
            # cross-kind branch runs only when every kind holds 1 and
            # `total >= 2` guarantees at least two kinds. A future
            # record shape that breaks both assumptions lands here
            # instead of looping forever, which is the whole point.
            return False
        parts = []
        with self._lock:
            for half in shaped:
                new_seq = self.state.next_seq
                self.state.next_seq = new_seq + 1
                parts.append((new_seq, build_batch(
                    self.cfg.sensor_id, self.state.instance_id, new_seq,
                    half, self.now())))
            self.state.save()
        # Original timestamp, not now. See guard 3.
        self.spool.replace(seq, parts)
        log.warning(
            "relay: collector refused batch seq=%s with %s; split into "
            "%d smaller batch(es) and requeued rather than discarding "
            "%d record(s).", seq, status, len(parts), total)
        return True

    def _note_link(self, ok: bool, detail: str = "") -> None:
        """Say out loud that the agent is spooling, and say it once.

        `docker compose logs` is the first thing the troubleshooting
        table sends an operator to, and an agent whose collector was
        unreachable printed NOTHING there: the failure went to
        `state.last_error`, which only `hound relay` reads. "Nothing
        relays, no error" was a literal description of the symptom.

        Rate-limited rather than per-cycle. At the 30s default a
        per-cycle warning is 2,880 identical lines a day, which is how
        an operator learns to filter the channel alerts arrive on.

        THE LIMITER MUST SURVIVE A RECOVERY. Clearing it on success
        made every outage "the first", so a link failing on alternate
        cycles logged a warning AND a recovery every time: measured 39
        warnings and 38 infos in 40 cycles, about 5,544 lines a day —
        roughly twice the volume the limiter was added to prevent, and
        each warning also re-parses the whole spool for its figures.
        So `_link_logged_at` is never reset; a flap is reported as a
        count inside the next due message instead.
        """
        now = self.now()
        if ok:
            if self._link_down_since is not None:
                if self._link_warned:
                    log.info("relay: collector reachable again after "
                             "%.0fs; %d spooled batch(es) remain",
                             now - self._link_down_since,
                             self.spool.stats(now).pending)
                    self._link_warned = False
                self._link_down_since = None
            return
        if self._link_down_since is None:
            self._link_down_since = now
            self._link_flaps += 1
        if (now - self._link_logged_at) >= _LINK_LOG_EVERY_S:
            self._link_logged_at = now
            self._link_warned = True
            st = self.spool.stats(now)
            flaps = (f" {self._link_flaps} separate outage(s) since the "
                     f"last report." if self._link_flaps > 1 else "")
            self._link_flaps = 0
            log.warning(
                "relay: collector unreachable for %.0fs — spooling "
                "(%d batch(es), %d bytes, oldest %.0fs; dropped "
                "age=%d size=%d).%s Last error: %s",
                now - self._link_down_since, st.pending, st.bytes,
                st.oldest_age, st.dropped_age, st.dropped_size, flaps,
                detail or self.state.last_error or "unknown")

    def flush(self, deadline: float | None = None,
              ignore_stop: bool = False) -> bool:
        """Try to deliver everything spooled. True if the spool emptied.

        Serialised. `stop()` clears `_thread` even when its join times
        out — a post can sit in a socket timeout, which is per
        operation and so not a bound on the post as a whole — so the
        pusher could still be inside `post_batch` when `final_flush`
        began. Both then posted the same batch, the loser took the
        409, and `spool.drop()` recorded a DELIVERED batch as
        discarded. A lock is the only thing that makes that
        impossible, rather than unlikely.
        """
        # Bounded on the shutdown path. The lock itself has no
        # timeout, and a socket timeout is per operation rather than
        # per post, so `final_flush` could wait here behind a wedged
        # post with no bound at all — on the one path where a
        # supervisor is already counting down to SIGKILL. Nothing
        # observed is lost either way (the daemon drains and writes
        # in-RAM flows BEFORE calling this, and whatever is unsent
        # stays spooled), but blocking achieves nothing: the pusher
        # holding the lock is posting the same spool we would.
        if deadline is None:
            with self._flush_lock:
                return self._flush_locked(deadline, ignore_stop)
        wait = max(0.0, min(_FLUSH_LOCK_WAIT_S, deadline - self.now()))
        if not self._flush_lock.acquire(timeout=wait):
            log.info("relay: another flush is still in progress at "
                     "shutdown; the spool stays for the next run")
            return False
        try:
            return self._flush_locked(deadline, ignore_stop)
        finally:
            self._flush_lock.release()

    def _flush_locked(self, deadline: float | None,
                      ignore_stop: bool) -> bool:
        with self._lock:
            pending = self.spool.pending(self.now())
        ok = True
        for i, (seq, body) in enumerate(pending):
            # Stop promptly when asked. The pacing sleep below had no
            # stop check, so a backlog drain ran on for its full
            # duration after stop() was called: the 15s join expired,
            # `stop()` cleared the thread anyway, and `final_flush()`
            # then ran a SECOND flush concurrently with the pusher it
            # was supposed to have quiesced. Both posted the same
            # batches; the loser got 409s and recorded them as drops,
            # so `hound relay` reported batches discarded that had in
            # fact been delivered.
            if self._stop.is_set() and not ignore_stop:
                return False
            if deadline is not None and self.now() >= deadline:
                log.info("relay: shutdown flush budget reached; %d batch(es) "
                         "stay spooled for the next run", len(pending) - i)
                return False
            # Pace a backlog. The collector meters REQUESTS per source,
            # so an agent draining a day of spool in a tight loop trips
            # that limit and earns itself an accept-time cooldown — a
            # legitimate sensor locking itself out precisely when it is
            # trying to catch up. Nothing is lost (a 429 ends the cycle
            # and the batch stays spooled), but the recovery is slower
            # and noisier than just going at a sustainable rate.
            if i:
                if ignore_stop:
                    # `_stop` is set during a final flush, so waiting
                    # on it returns instantly and the pacing vanishes
                    # — which would let a shutdown drain outrun the
                    # collector's request budget and earn 429s on the
                    # way out. Pace on the clock instead.
                    time.sleep(_REPLAY_PACE_S)
                elif self._stop.wait(_REPLAY_PACE_S):
                    return False
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
                self._note_link(False, str(e)[:200])
                return False
            if status == 200:
                self.spool.ack(seq)
                self.state.last_push_ts = self.now()
                self.state.last_error = ""
                self.state.save()
                self._note_link(True)
            elif status == 409:
                # The collector is ahead of us — a wiped volume, or a
                # duplicate. Fast-forward rather than retrying forever.
                # Type-checked, like `_learn_limits` does for the
                # same class of value. A bare int() on untrusted JSON
                # raises out of the flush, and this one is persisted
                # into state.json where it decides what gets sent
                # next.
                raw_last = payload.get("last_seq", seq)
                # STRICTLY below the ceiling: accepting the maximum
                # sets next_seq one past it, which the collector then
                # rejects 400 forever.
                last = (raw_last if isinstance(raw_last, int)
                        and not isinstance(raw_last, bool)
                        and 0 < raw_last < _MAX_SAFE_SEQ else seq)
                # NOT `drop()`. A 409 means the collector HAS these
                # records; calling it a drop put them in
                # `dropped_stale`, so `hound relay` reported discarded
                # observations for data that had arrived.
                self.spool.already_delivered(seq, last)
                with self._lock:
                    if self.state.next_seq <= last:
                        self.state.next_seq = last + 1
                        self.state.save()
            elif status in (400, 413) and self._resplit(seq, body, payload,
                                                        status):
                # Re-spooled smaller rather than discarded. Keep going;
                # the replacements are at the tail of the spool.
                #
                # The collector ANSWERED, so the link is up: record
                # that, or `_link_down_since` is never cleared and the
                # agent keeps logging "collector unreachable" hourly
                # while every request is being served. And keep the
                # reason in `last_error`, which `hound relay` prints —
                # skipping it left the operator with "nothing relays,
                # no error", the symptom `_note_link` was added to
                # remove.
                self.state.last_error = (
                    f"{status}: {str(payload.get('error', ''))[:160]} "
                    f"(batch split and requeued)")[:300]
                self.state.save()
                self._note_link(True)
                continue
            elif status == 400 and payload.get("retryable"):
                # The collector says this one may succeed unchanged —
                # only the clock-skew refusal does. Keep the batch
                # spooled and stop the cycle, exactly as a transport
                # failure would. Dropping it would make a missing NTP
                # server into permanent data loss.
                err = f"400: {str(payload.get('error', ''))[:200]}"
                self.state.last_error = err[:300]
                self.state.save()
                self._note_link(False, err)
                ok = False
                break
            elif status in (400, 401, 413):
                # 413 belongs here, not in the retry branch. It is
                # permanent — the body is too large and will be exactly
                # as large next cycle — so retrying wedges the head of
                # the spool forever and nothing behind it moves until
                # the age cap discards a day of data. Reachable without
                # malice: max_body_bytes and max_records_per_batch are
                # independent, so 5000 alerts with long summaries can
                # exceed 8 MB.
                # Malformed or unauthorised: retrying cannot help.
                # str() BEFORE slicing, like its two neighbours. A
                # collector answering `{"error": null}` or
                # `{"error": 123}` raised TypeError out of the flush,
                # so the batch was neither acked nor dropped and the
                # identical response fired every cycle forever — a
                # permanent stall with no warning, which is the exact
                # failure shape this file names three times.
                self.spool.drop(seq, f"rejected with {status}: "
                                     f"{str(payload.get('error', ''))[:120]}")
                self.state.last_error = f"{status}: {payload.get('error','')}"[:300]
                self.state.save()
            else:
                # 500/502/503/507 and anything else unforeseen: the
                # collector ANSWERED, so no exception was raised and the
                # link-down log never fired. The agent spooled in total
                # silence while the README's troubleshooting table told
                # the operator to look for exactly that line — and 507
                # (collector out of disk) is documented there as a
                # normal transient, so this was the likeliest refusal of
                # the set to be hit and the one least likely to be seen.
                err = f"{status}: {payload.get('error','')}"[:300]
                self.state.last_error = err
                self.state.save()
                self._note_link(False, err)
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
        # Bounded. With pacing, a day's spool is thousands of batches
        # and a full drain would hold shutdown for the best part of an
        # hour — supervisors SIGKILL well before that (systemd 90s by
        # default, and the Docker agent sets stop_grace_period: 90s),
        # so "finish the backlog" was never going to happen anyway. Send what fits;
        # the rest stays spooled for the next run, which is what the
        # spool is for.
        # Deliberately NOT self._stop.clear(). If the pusher's join
        # timed out — a post can sit in a socket timeout — clearing
        # the shared event would un-stop a thread we believe is gone,
        # and the two would flush concurrently again. The flag below
        # lets THIS call proceed without touching shared state.
        deadline = self.now() + _FINAL_FLUSH_BUDGET_S
        try:
            self.enqueue()
            self.flush(deadline=deadline, ignore_stop=True)
        except Exception:               # noqa: BLE001
            log.exception("relay: final flush failed")


def _advance(wm: Watermark, flows, alerts, outages, now: float,
             devices=(), devices_truncated: bool = False) -> Watermark:
    """The cursor for the records ACTUALLY INCLUDED in this batch.

    `reported_at` is the devices cursor, and advancing it to `now`
    unconditionally is what made device truncation permanent loss
    rather than deferral: `devices_changed_since` is
    `WHERE last_seen >= ? LIMIT ?`, so anything past the limit was
    skipped and then fell behind the cursor. Measured at stock
    defaults with 600 devices and a batch that needed halving, 100
    devices were never relayed on any cycle. `uptime` recovers
    because it is recomputed from scratch each cycle; a device whose
    `last_seen` never moves again does not — and a camera that has
    just gone silent is exactly that device.

    So when the device list was cut off, resume from the newest
    `last_seen` we did send instead of from now.
    """
    reported_at = now
    if devices_truncated and devices:
        high = max(d["last_seen"] for d in devices)
        if high > wm.reported_at:
            reported_at = high
        else:
            # More devices share one `last_seen` than fit in a batch,
            # so there is no cursor that makes progress. Advancing is
            # the lesser evil — holding it would re-send the same
            # prefix forever and relay nothing new at all.
            log.warning(
                "relay: %d devices share the same last_seen and do not "
                "fit in one batch; the remainder cannot be relayed. "
                "Raise [relay] max_body_bytes and max_records_per_batch "
                "on both ends.", len(devices))
    return Watermark(
        flow_id=max([wm.flow_id] + [f["id"] for f in flows]),
        alert_id=max([wm.alert_id] + [a["id"] for a in alerts]),
        outage_id=max([wm.outage_id] + [o["id"] for o in outages]),
        # Carry forward every id we have not yet seen closed, not just
        # the ones in THIS batch. An open outage crowded out of a
        # cycle used to drop off the list, and if it closed while
        # absent it matched none of the query's three terms ever again
        # — id below the cursor, `up_at` no longer null, not in the
        # carry-forward list — so the close was never transmitted and
        # the collector showed that camera down forever. That is the
        # exact failure this list exists to prevent, reachable by
        # truncation rather than by logic.
        open_outage_ids=sorted(
            (set(wm.open_outage_ids)
             | {o["id"] for o in outages if o.get("up_at") is None})
            - {o["id"] for o in outages if o.get("up_at") is not None}
        ),
        reported_at=reported_at,
    )
