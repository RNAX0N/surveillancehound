"""Collector-side ingest listener.

Runs inside the daemon because `HoundStore` is single-writer and the daemon
owns it. It deliberately does **not** take the daemon's `_loop_lock`: that
lock guards in-RAM state (the flow aggregator, device classifier, uptime
tracker, snapshot ring) which ingest never touches, and `HoundStore`
serialises itself. Taking it would let one large authenticated batch stall
packet capture long enough for the watchdog to declare the capture stalled —
a remote host making the firewall fabricate an alert about its own
blindness.

Everything here assumes the peer is hostile even when the signature checks
out, because the agent runs on a camera-segment host that is more likely to
be compromised than this one.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import threading
import time
from collections import defaultdict, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from surveillancehound import relay, validate
from surveillancehound.config import RelayCfg
from surveillancehound.store import HoundStore

log = logging.getLogger(__name__)

INGEST_PATH = "/ingest/v1"

# Concurrent batches allowed through the expensive pure-Python stages.
# This is the number that protects packet capture: everything before
# the store — hmac, container scan, json.loads, validate_records — is
# GIL-bound work competing with the pcap parser. Two is enough to keep
# the store busy while one batch parses.
_CPU_SLOTS = 2
# Seconds a peer gets to complete the TLS handshake. Short, because
# until it completes the peer has proven nothing and is holding a
# worker slot.
_HANDSHAKE_TIMEOUT = 5.0
# How long a source that exhausted its request budget is refused at
# accept. Long enough that flooding is not free, short enough that a
# misconfigured agent recovers on its own.
_REJECT_COOLDOWN = 30.0
# Total wall-clock for draining an unread body before closing. A
# deadline, not a socket timeout: the latter resets on every byte.
# Filesystem bytes that must be free regardless of how much space is
# reusable inside the store. The WAL needs real space for every write;
# see `_disk_ok`.
_ABSOLUTE_DISK_FLOOR = 32 * 1024 * 1024
# How often a sensor that keeps resetting its instance id earns
# another WARNING. The first always does; see the branch in
# `_handle_batch`.
_INSTANCE_RESET_EVERY = 100
# How often a sensor whose batches keep failing validation earns
# another WARNING. The first always does.
_REJECT_LOG_EVERY = 100
_DRAIN_LIMIT = 65536      # default lingering-close absorption
# Ceiling for the one refusal that MUST be understood exactly.
#
# `max_body_bytes` is the wrong ceiling here and was the round-17 bug
# surviving its own fix: the 413 fires if and only if the declared
# length EXCEEDS that cap, so draining up to the cap always left
# `length - cap` bytes unread and the reply's survival came down to
# socket-buffer slack. Measured, delivery went from 30/30 on loopback
# to 0/20 with a 8 KiB client send buffer.
#
# This has to cover a body an honest agent can build, and the agent
# sizes batches from ITS OWN max_body_bytes — which it cannot know
# differs from the collector's. The documented default on both ends
# is 2 MiB, so 8 MiB covers a four-fold asymmetry, and the local cap
# doubled covers an operator who raised both ends well past the
# default and then lowered only this one. Beyond that a peer gets a
# reset, which is correct: at those sizes it is not an honest agent,
# and every other status on these paths is retryable anyway.
#
# The real bound on cost is `_DRAIN_BUDGET_S`, not this number. Read
# and discard is cheap: measured absorbing 576 MB across a sustained
# 413 flood cost no measurable local packet-parse throughput.
_DRAIN_MAX = 8 * 1024 * 1024
#
# A note on what this costs, because it looks alarming and is not.
#
# The drain reads through the TLS layer, so every absorbed byte is
# decrypted on the same CPU that parses packets off the wire. That
# reads like a capture-starvation vector, and a first measurement
# seemed to confirm it: collector pinned to one core, 8
# unauthenticated addresses flooding the 413 path, local packet
# parsing down to 29.9% of its unloaded baseline. (That baseline was
# a tight loop re-parsing one small synthetic capture already in
# memory, so its absolute pkt/s is far above anything a real capture
# reaches — an independent run against a 34 MB file on disk measured
# 443k pkt/s. Only the RATIOS below are meaningful; do not quote the
# absolute figure, which is why it is no longer written down.)
#
# Two things were wrong with reading it that way.
#
# It is not the drain. Holding the flood fixed and varying ONLY the
# drain policy: shipped 8 MiB vs effectively unbounded came out
# identical in two independent runs (29.2% vs 30.3% here; 85% vs 85%
# on a second machine). A shared token bucket for drain bytes was
# written, measured and deleted — it bought nothing, and it gave a
# flood a way to starve an honest agent's 413 of its drain at exactly
# the wrong moment. `_DRAIN_BUDGET_S` is the bound that matters.
#
# One caveat on that run, found by an independent reviewer who could
# not reproduce it: "drain off" is NOT reliably equal to the other
# two. Here it measured 29.2%, within noise of the rest; there it
# measured 42% against 85% — markedly WORSE than draining, because
# clamping the drain makes the collector RST early and the client
# reconnects immediately, buying more RSA handshakes per second. So
# the conclusion holds and is stronger than first stated (the
# handshake is the cost, not the drain) but do not restate the
# specific "all three within noise" triple as a general result.
#
# And that run had `max_batches_per_minute = 10000`, which disables
# the metering in `process_request`. At the SHIPPED default of 60 the
# same flood from the same 8 addresses retains 80.4% of baseline
# (53,017 connections refused at accept); the
# independent run measured 100% at the shipped default. The ~70% loss
# is what an UNMETERED collector costs — which is what the metering
# was added for. It is not what this drain costs, and not what an
# operator running defaults sees.
#
# Measure this the same way or not at all: vary one policy against a
# fixed flood, state the metering setting, and never read an unloaded
# baseline alone — the handshake cost swamps everything else.
_DRAIN_BUDGET_S = 2.0
# How often the listener summarises refused connections.
_OVERLOAD_REPORT_S = 60.0
# Absolute wall-clock a connection may hold a worker slot, from accept
# to done. This is the bound that was missing: the handshake deadline
# only covers a peer that sends nothing, and the socket timeout is
# PER-RECV, so a peer dribbling one byte before each timeout holds a
# slot for as long as it likes. Caps and counters bound how many
# REQUESTS a peer may make; this bounds how much TIME it may buy, which
# is the resource a slow-loris actually spends.
#
# Generous on purpose. The reserve for proven sources is what protects
# a working sensor; this is only a backstop against a connection held
# indefinitely. Set tight it would reap REAL agents: a full 1.5 MB
# batch takes 12s on a 1 Mbit link and 24s on a bad one, and a relay
# that drops its own agent's upload over a slow tunnel is a worse
# failure than a peer holding a thread.
_CONN_BUDGET = 120.0
# How long a source stays "proven" after a signed request. Long enough
# to span an agent's batch interval many times over, short enough that
# a decommissioned address does not hold its reservation forever.
_TRUSTED_TTL = 3600.0
# A forged seq must not be able to poison the counter so the real agent can
# never catch up.
MAX_SEQ_ADVANCE = 1_000_000
# SQLite stores signed 64-bit integers; anything larger raises in the
# driver rather than being rejected as bad input.
_MAX_SEQ = 2**63 - 1


class _RateLimiter:
    """Token bucket keyed by SOURCE ADDRESS, applied before authentication.

    Keying on the sensor id would mean keying on an unsigned header, so
    anyone who could reach the port could exhaust the real agent's budget
    just by naming it.
    """

    def __init__(self, per_minute: int):
        self.per_minute = max(1, int(per_minute))
        self._hits: dict[str, deque] = defaultdict(deque)
        self._cooldown: dict[str, float] = {}
        self._lock = threading.Lock()

    def allow(self, source: str, now: float) -> bool:
        with self._lock:
            q = self._hits[source]
            while q and (now - q[0]) > 60.0:
                q.popleft()
            if len(q) >= self.per_minute:
                # Over budget: refuse at accept for a while, so the
                # next attempt costs this peer a handshake it does not
                # get to complete rather than costing us a request.
                self._cooldown[source] = now + _REJECT_COOLDOWN
                if len(self._cooldown) > 4096:
                    # Keyed on peer-controlled addresses, so bound it
                    # directly rather than relying on the _hits sweep.
                    for k in [k for k, v in self._cooldown.items()
                              if v <= now]:
                        del self._cooldown[k]
                return False
            q.append(now)
            if len(self._hits) > 1024:
                self._sweep(now)
            return True

    def in_cooldown(self, source: str, now: float) -> bool:
        """Is this source serving a penalty? Checked at accept time."""
        with self._lock:
            until = self._cooldown.get(source)
            if until is None:
                return False
            if until <= now:
                del self._cooldown[source]
                return False
            return True

    def _sweep(self, now: float) -> None:
        """Drop keys whose window has fully expired.

        Sweeping only EMPTY deques was not a bound: a deque is only
        emptied when that same source is seen again, so a one-shot source
        leaves a permanently non-empty entry. Anyone with a large address
        range — a /64 of IPv6 is free — grows the dict without limit by
        sending one request per address. Expiry has to be judged by the
        timestamps, not by emptiness.
        """
        stale = [k for k, v in self._hits.items()
                 if not v or (now - v[-1]) > 60.0]
        for k in stale:
            del self._hits[k]
        for k in [k for k, v in self._cooldown.items() if v <= now]:
            del self._cooldown[k]
        if len(self._hits) > 4096:
            # Still oversized: a genuine flood from many live sources.
            # Keep the most recent and let the rest re-register; the
            # alternative is unbounded growth driven by a remote peer.
            for k in sorted(self._hits, key=lambda k: self._hits[k][-1])[:2048]:
                del self._hits[k]


class IngestServer:
    """HTTPS listener accepting exactly one route."""

    def __init__(self, cfg: RelayCfg, store: HoundStore, on_alerts=None,
                 now=time.time, gate=None):
        self.cfg = cfg
        self.store = store
        self.on_alerts = on_alerts
        self.now = now
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._limiter = _RateLimiter(cfg.max_batches_per_minute)
        # One relayed store user at a time. Named for what it guards:
        # access to HoundStore, not just writes.
        self._write_slot = threading.Semaphore(1)
        self._cpu_slot = threading.Semaphore(_CPU_SLOTS)
        # In-flight BATCHES, not open connections. Counting connections
        # meant one idle keep-alive — or a bare TCP SYN from an
        # unauthenticated peer — added the full shutdown timeout to
        # every restart, and warned about a "current batch" that did
        # not exist. Only work that could be mid-write matters here,
        # because that is all a store close can damage.
        self._inflight = 0
        self._inflight_lock = threading.Lock()
        # Per-sensor count of instance-id resets, for log throttling.
        # Bounded by the configured sensor list — a batch cannot reach
        # here without a valid key for a configured sensor_id — so this
        # is not an unbounded-growth vector the way a source-address
        # key would be.
        self._instance_resets: dict[str, int] = {}
        # Per-sensor count of validation rejections, for log
        # throttling. Bounded by the configured sensor list, like
        # `_instance_resets`.
        self._reject_log: dict[str, int] = {}
        self._reset_lock = threading.Lock()
        # Capture outranks relayed work; see relay.CaptureGate.
        self.gate = gate or relay.CaptureGate()
        self.started = False

    # ----- lifecycle -----

    def start(self) -> bool:
        """Bind and serve. Never fatal — a failure here must not kill capture."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.cfg.cert_file, self.cfg.key_file)
        except (OSError, ssl.SSLError) as e:
            log.error(
                "relay: cannot load ingest certificate (%s / %s): %s — "
                "listener not started; the rest of the daemon is unaffected",
                self.cfg.cert_file, self.cfg.key_file, e,
            )
            return False

        server = self
        handler = _make_handler(server, ctx)
        try:
            httpd = _Server((self.cfg.listen_host, self.cfg.listen_port), handler)
            # The accept path needs the limiter: a source that burned
            # its budget is refused there, where refusing is cheapest.
            httpd.limiter = self._limiter
            httpd.now_fn = self.now
        except OSError as e:
            log.error(
                "relay: cannot bind %s:%s: %s — listener not started. The "
                "address may not be up yet; capture continues regardless.",
                self.cfg.listen_host, self.cfg.listen_port, e,
            )
            return False

        self._httpd = httpd
        self._thread = threading.Thread(
            target=httpd.serve_forever, name="hound-ingest", daemon=True,
        )
        self._thread.start()
        self.started = True
        log.info(
            "relay: ingest listening on https://%s:%d%s for sensor(s) %s",
            self.cfg.listen_host, self.cfg.listen_port, INGEST_PATH,
            ", ".join(s.id for s in self.cfg.sensors),
        )
        return True

    def stop(self) -> None:
        """Stop before the store closes, or in-flight writes hit a dead
        handle.

        `daemon_threads = True` means `server_close()` joins nothing, so
        this used to return while a handler was mid-write: the store
        then closed under it and it raised ProgrammingError with a full
        traceback — a remote host choosing when the daemon logs a crash.
        Waiting is bounded, because a wedged handler must not be able to
        hold shutdown open either.
        """
        if self._httpd is not None:
            self._httpd.shutdown()
            deadline = time.time() + 10.0
            while self.in_flight() > 0 and time.time() < deadline:
                time.sleep(0.02)
            left = self.in_flight()
            if left:
                log.warning(
                    "relay: %d ingest handler(s) still running after 10s; "
                    "closing the store anyway. They will fail their "
                    "current batch and the agent will resend it.", left)
            self._httpd._reaper_stop.set()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None
        self.started = False

    # ----- request handling -----

    def _disk_ok(self) -> bool:
        """Is there room to write? Fail OPEN if we cannot tell.

        If `statvfs` is unavailable or errors, refusing every batch would
        turn an unknown into an outage of the whole relay. The store's own
        write errors remain the backstop in that case.
        """
        limit = self.cfg.min_free_disk_mb
        if limit <= 0:
            return True
        try:
            st = os.statvfs(self.store.path.parent)
        except (OSError, AttributeError):
            return True
        fs_free = st.f_bavail * st.f_frsize
        want = limit * 1024 * 1024
        # A HARD filesystem floor, independent of the freelist credit
        # below. Free pages inside the store are reusable for ROW data,
        # but the store is WAL: every write still appends to `-wal`,
        # which is real filesystem space (~4 MB steady at the default
        # autocheckpoint). Counting only the credit let the guard pass
        # with literally zero bytes free — measured True at 0 MB, 1 MB
        # and 255 MB against a 256 MB floor on a store with a 351 MB
        # freelist. Below the WAL's working set the next write raises
        # SQLITE_FULL, the handler answers 500 with a traceback, and
        # the agent retries a 500 forever. That is the "a full
        # filesystem is the one failure that can damage the store"
        # case this guard exists for, reached through the guard.
        if fs_free < min(want, _ABSOLUTE_DISK_FLOOR):
            return False
        # Within that, pages already free inside the store count toward
        # the configured floor: SQLite reuses them without growing the
        # file, and retention frees pages without shrinking it (the
        # daemon deliberately does not VACUUM — see store.prune_remote).
        # Without this credit, one sensor that had inflated the store
        # to the floor kept the collector refusing every sensor
        # permanently, with retention running and unable to lift it.
        reusable = 0
        if fs_free < want:
            try:
                with self.gate.deferred():
                    reusable = self.store.reusable_bytes()
            except Exception:           # noqa: BLE001 - a guard, not a feature
                reusable = 0
        return (fs_free + reusable) >= want

    def in_flight(self) -> int:
        with self._inflight_lock:
            return self._inflight

    def handle_batch(self, source: str, body: bytes, headers) -> tuple[int, dict]:
        with self._inflight_lock:
            self._inflight += 1
        try:
            status, payload = self._handle_batch(source, body, headers)
            # Reserved slots are bought by a COMPLETED batch, not by a
            # signature alone. Marking on verification meant a peer
            # whose every batch was rejected 409 still earned the
            # reservation — true of a replaying agent, and of anyone
            # holding a key who wants the reserve without doing work.
            if status == HTTPStatus.OK and self._httpd is not None:
                self._httpd.mark_trusted(source)
            return status, payload
        finally:
            with self._inflight_lock:
                self._inflight -= 1

    def _handle_batch(self, source: str, body: bytes, headers) -> tuple[int, dict]:
        return self._handle_batch_cpu(source, body, headers)

    def _handle_batch_cpu(self, source: str, body: bytes,
                          headers) -> tuple[int, dict]:
        now = self.now()

        sensor_hint = str(headers.get(relay.SENSOR_HEADER, ""))[:128]
        signature = headers.get(relay.SIG_HEADER, "")

        # AUTHENTICATE BEFORE PARSING.
        #
        # json.loads on an 8 MB body can allocate a couple of hundred MB —
        # `[[],[],...]` is ~24x amplification — and this process is also
        # doing packet capture, so an OOM kill stops the monitor. Parsing
        # first meant any peer who could reach the port could do that
        # without holding a key at all. The HMAC is over the raw bytes, so
        # it does not need the parse; the header only selects which key to
        # try, and the signed body is still checked against it below.
        key = self.cfg.key_for(sensor_hint)
        if key is None:
            # Burn a comparable HMAC anyway. Returning early on an unknown
            # id makes "unknown sensor" measurably faster than "bad
            # signature", which is the oracle the shared 401 exists to
            # avoid.
            relay.verify("\x00" * 32, body, signature)
            ok = False
        else:
            ok = relay.verify(key, body, signature)
        if not ok:
            # debug: a peer chooses how often this fires, and the
            # periodic refusal summary already tells an operator the
            # port is busy. A line per rejected batch is a log flood
            # with a remote throttle.
            log.debug("relay: rejected batch from %s (sensor=%r)",
                      source, sensor_hint[:64])
            return HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"}



        try:
            # Before json.loads allocates: see validate.MAX_CONTAINERS.
            validate.check_container_budget(body)
            doc = validate.loads_strict(body)
        except validate.ValidationError as e:
            return HTTPStatus.BAD_REQUEST, {"error": str(e)}
        if not isinstance(doc, dict):
            return HTTPStatus.BAD_REQUEST, {"error": "body must be an object"}

        if doc.get("schema") != relay.SCHEMA_VERSION:
            return HTTPStatus.BAD_REQUEST, {
                "error": f"unsupported schema {doc.get('schema')!r}, "
                         f"expected {relay.SCHEMA_VERSION}",
            }

        sensor_id = str(doc.get("sensor_id", ""))
        # The signed body remains authoritative. Without this a holder of
        # one sensor's key could put their own id in the header (so their
        # key verifies) and another sensor's id in the body.
        if sensor_id != sensor_hint:
            return HTTPStatus.BAD_REQUEST, {
                "error": "sensor id in the header does not match the signed body",
            }

        sent_at = doc.get("sent_at")
        if not isinstance(sent_at, (int, float)):
            return HTTPStatus.BAD_REQUEST, {"error": "sent_at must be a number"}
        skew = float(sent_at) - now
        if abs(skew) > self.cfg.clock_skew_seconds:
            return HTTPStatus.BAD_REQUEST, {
                "error": f"sent_at is {skew:+.0f}s from collector time, "
                         f"outside the +/-{self.cfg.clock_skew_seconds:.0f}s window",
                "server_time": now,
                # TRANSIENT, unlike every other 400 here. The agent
                # treats 400 as permanent and discards the batch,
                # which for a clock problem means an NVR with no NTP
                # destroys everything it observes until someone
                # notices. Fixing the clock makes the identical batch
                # acceptable, so tell the agent to keep it: it spools,
                # and if the clock is never fixed the data ages out
                # through the normal cap where it is COUNTED and
                # logged rather than silently dropped.
                "retryable": True,
            }

        try:
            instance_id = validate.clean_instance_id(doc.get("instance_id"))
        except validate.ValidationError as e:
            return HTTPStatus.BAD_REQUEST, {"error": str(e)}
        seq = doc.get("seq")
        if (not isinstance(seq, int) or isinstance(seq, bool)
                or not (1 <= seq <= _MAX_SEQ)):
            # Bounded, because an int above SQLite's 64-bit range reaches
            # the driver and raises OverflowError — which the catch-all
            # turns into a 500, and the agent treats 500 as retryable, so
            # a buggy agent would loop on it forever. A 400 tells it to
            # stop.
            return HTTPStatus.BAD_REQUEST, {
                "error": f"seq must be an integer in [1, {_MAX_SEQ}]"}

        # Slot first, then the gate, so the gate is checked as close to
        # the store access as possible. Measured, the order makes no
        # difference today — the slot already admits one thread at a
        # time, so only one is ever past the gate either way — but it
        # is the order that stays correct if the slot is ever widened.
        # The bound on the tick's wait comes from the SLOT; the gate
        # adds protection against losing an unfair-RLock race
        # repeatedly rather than once.
        #
        # Under the slot: this is a store read, and 32 threads doing it
        # concurrently contend with the watchdog tick for
        # HoundStore._lock exactly as a write does. Serialising only
        # the write left the collector's packet loop freezing for
        # seconds — a 5x improvement that was still remote-triggered
        # blindness. Every relayed store access belongs here.
        with self._write_slot, self.gate.deferred():
            known = self.store.get_remote_sensor(sensor_id)
        if known is not None and known.instance_id == instance_id:
            if seq <= known.last_seq:
                # Tell the agent where we are so it can fast-forward instead
                # of discarding everything it has.
                return HTTPStatus.CONFLICT, {
                    "error": "stale sequence",
                    "last_seq": known.last_seq,
                    "instance_id": known.instance_id,
                }
            if seq - known.last_seq > MAX_SEQ_ADVANCE:
                return HTTPStatus.BAD_REQUEST, {
                    "error": "implausible sequence advance",
                    "last_seq": known.last_seq,
                }
        elif known is not None:
            # Throttled per sensor. A VALID key holder chooses how
            # often this fires: 40 batches with a rotating instance_id
            # produced 39 WARNING lines, at 60 requests/minute per
            # source address and no limit on addresses. This module
            # already reasons about exactly that for the 401 ("a peer
            # chooses how often this fires ... a line per rejected
            # batch is a log flood with a remote throttle") and the
            # reasoning was not carried here. The FIRST reset is worth
            # a warning — it is how a wiped agent volume looks — and
            # the hundredth is not.
            with self._reset_lock:
                self._instance_resets[sensor_id] = n = (
                    self._instance_resets.get(sensor_id, 0) + 1)
            if n == 1 or n % _INSTANCE_RESET_EVERY == 0:
                log.warning(
                    "relay: sensor %r presented a new instance id "
                    "(%r -> %r); accepting and resetting its sequence. "
                    "If two agents share this sensor_id, give them "
                    "separate ids. (%d reset(s) from this sensor)",
                    sensor_id, known.instance_id, instance_id, n,
                )
            else:
                log.debug(
                    "relay: sensor %r reset its instance id again "
                    "(%r -> %r, %d total)",
                    sensor_id, known.instance_id, instance_id, n)

        try:
            records = validate.validate_records(
                doc.get("records", {}), self.cfg.max_records_per_batch,
            )
        except validate.ValidationError as e:
            # Throttled per sensor, like the instance-reset branch and
            # for the same reason: a VALID key holder sets the rate
            # here, at 60 requests/minute per source address with no
            # limit on addresses. The neighbouring 401 is already
            # `log.debug` on this reasoning; this one was missed.
            with self._reset_lock:
                self._reject_log[sensor_id] = n = (
                    self._reject_log.get(sensor_id, 0) + 1)
            if n == 1 or n % _REJECT_LOG_EVERY == 0:
                log.warning("relay: rejected batch from %s: %s "
                            "(%d rejection(s) from this sensor)",
                            sensor_id, e, n)
            else:
                log.debug("relay: rejected batch from %s: %s",
                          sensor_id, e)
            # Advertise the limits. The agent sizes batches from its OWN
            # config because it cannot see this one, so a collector
            # configured lower refused every batch — and 400 is terminal
            # on the agent side, so the batch was DISCARDED after its
            # watermark had advanced. Permanent silent loss, reachable by
            # following the documented "lower the cap" remedy on one end
            # only. Telling it the real numbers lets it re-split and
            # resend instead of destroying what it saw.
            return HTTPStatus.BAD_REQUEST, {
                "error": str(e),
                "limits": {
                    "max_records_per_batch": self.cfg.max_records_per_batch,
                    "max_body_bytes": self.cfg.max_body_bytes,
                },
            }

        # Last gate before writing. A full filesystem is the one failure
        # that can damage the store rather than merely lose a batch, and
        # the agent spools a rejection and resends it, so refusing here
        # costs nothing a retry does not recover.
        if not self._disk_ok():
            log.error(
                "relay: refusing ingest from %s — under %.0f MB free on the "
                "store filesystem. Relayed data is being dropped until space "
                "is freed; local capture is unaffected.",
                sensor_id, self.cfg.min_free_disk_mb,
            )
            return HTTPStatus.INSUFFICIENT_STORAGE, {
                "error": "collector is low on disk; retry later",
                "retry_after": 300,
            }

        # ONE relayed writer at a time.
        #
        # SQLite is single-writer anyway, so concurrency here buys no
        # throughput — only contention. And the contention is not local
        # to the relay: the watchdog tick writes the store while holding
        # `_loop_lock`, and the packet loop takes `_loop_lock` per
        # packet, so N ingest threads queued on the store lock stall
        # PACKET CAPTURE for the sum of their holds. Measured at 32
        # workers that was tens of seconds, long enough for tcpdump's
        # pipe to fill — the collector going actually blind on its own
        # segment, which is the failure this module's docstring claims
        # to prevent by avoiding `_loop_lock`. Avoiding that lock was
        # necessary and not sufficient; the store lock is the other
        # half of the same path.
        with self._write_slot, self.gate.deferred():
            counts = self.store.ingest_remote_batch(
                sensor_id, instance_id, seq, records, now,
                skew=skew, body_bytes=len(body),
                max_rows_per_sensor=self.cfg.max_rows_per_sensor,
            )

        if self.on_alerts and records.get("alerts"):
            try:
                self.on_alerts(sensor_id, records["alerts"], instance_id)
            except Exception:   # noqa: BLE001 - never fail ingest on dispatch
                # The batch is already stored, so the ingest itself
                # succeeded; say plainly that the NOTIFICATION did not,
                # because the previous wording ("queuing failed") read
                # as a transient and hid a hook that never fired at all.
                log.exception(
                    "relay: relayed alerts from %r were stored but NOT "
                    "dispatched — the on_alerts hook raised", sensor_id)

        return HTTPStatus.OK, {
            "status": "ok", "ack_seq": seq,
            "accepted": counts.get("total", 0),
            # Housekeeping that ran in the same transaction. Separate
            # from `accepted` because they measure different things,
            # and on the wire because an agent that only sees
            # `accepted` cannot tell a quota from a quiet collector.
            "trimmed": counts.get("trimmed", 0),
            "server_time": now,
        }


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """Swallow per-connection errors.

        socketserver calls this on the SERVER, not on the handler — an
        override on the handler class never fires, which is how aborted
        handshakes were printing tracebacks to stderr. A peer that can
        reach the port must not be able to fill the log by dropping
        connections mid-handshake.
        """
        log.debug("ingest: connection from %s failed", client_address,
                  exc_info=True)

    # The LISTEN backlog — how many connections the kernel queues before
    # we accept them. It is NOT a bound on worker threads; see max_workers.
    request_queue_size = 16
    allow_reuse_address = True

    # ThreadingHTTPServer spawns one thread per connection with no ceiling,
    # so anyone who can reach the port can exhaust threads and memory
    # without ever authenticating. This daemon is also doing packet
    # capture, so the ceiling keeps that failure on the relay.
    # Two SEPARATE limits, because they bound different things.
    #
    # `max_workers` bounds concurrent CONNECTIONS. Making it small
    # looked like the fix for the capture stall and was a denial of
    # service against legitimate sensors instead: with a 4-slot pool,
    # six hostile source addresses took every slot and a real sensor
    # got 0 of 20 batches in. A connection costs a thread and a buffer;
    # it is cheap, and refusing one is the thing that hurts.
    #
    # `_CPU_SLOTS` below bounds concurrent CPU, which is what actually
    # starves capture: hmac, the container scan, json.loads and
    # validate_records are ~0.3s of pure Python per batch, and under
    # the GIL thirty-two of those take the processor away from the pcap
    # parser and the tick. Threads waiting on that semaphore are
    # parked, not burning anything.
    max_workers = 16

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self._deadlines: dict = {}
        # source -> monotonic time of its last successful signature
        self._trusted: dict[str, float] = {}
        self._reaper_stop = threading.Event()
        self._slots = threading.BoundedSemaphore(self.max_workers)
        self._per_source: dict[str, int] = {}
        self._src_lock = threading.Lock()
        self.rejected_overload = 0
        # Started LAST: it touches _src_lock, and starting it before
        # that existed left it one scheduling accident away from dying
        # on an AttributeError with no restart and no health signal.
        self._reaper = threading.Thread(
            target=self._reap, name="hound-ingest-reaper", daemon=True)
        self._reaper.start()

    # Per-source ceiling, enforced at ACCEPT time, so one address
    # cannot take the whole pool. The token-bucket rate
    # limiter lives inside do_POST, which a peer only reaches after a
    # completed TLS handshake — so a single address could hold every
    # worker slot indefinitely by connecting and never finishing, and
    # legitimate sensors were refused ~90% of the time. The global
    # ceiling bounds resources; this one keeps one host from owning them.
    max_per_source = 4

    # Slots reserved for sources that have PROVEN a key.
    #
    # Reserving for "sources holding no connection" did nothing: every
    # attacker connection is from a source holding none, so the branch
    # never fired and sixteen single-connection addresses still took
    # the pool. Counting connections cannot separate a hostile peer
    # from a real one, because at accept time nothing about the peer
    # is known.
    #
    # Something IS known by then, though: whether this address has
    # ever completed a signed request. An attacker without a key can
    # never enter that set, and a real agent enters it on its first
    # successful batch and posts from the same address every
    # batch_seconds after. So the last few slots are held for proven
    # sources, and a flood of unauthenticated addresses can delay a
    # sensor's first-ever batch but not starve it thereafter.
    trusted_reserve = 6

    def process_request(self, request, client_address):
        source = client_address[0] if client_address else "?"
        # The server's clock, not time.time(): `allow()` arms the
        # cooldown using it, so checking against a different clock
        # makes every cooldown look already-expired. Identical in
        # production, where both are wall time — which is exactly why
        # it would never have shown up there.
        limiter = getattr(self, "limiter", None)
        now_fn = getattr(self, "now_fn", time.time)
        if limiter is not None:
            now = now_fn()
            # Charge the CONNECTION, not just the requests on it.
            #
            # Metering started at the request line, and the TLS
            # handshake happens before there is one — so a peer doing
            # nothing but connect, handshake, disconnect was never
            # charged at all. That is the most expensive pre-request
            # unit in the stack: an RSA sign per handshake, measured
            # at 33-66% of packet-parse throughput on a single-CPU
            # collector, with the cooldown never arming. A 1-vCPU
            # firewall VM is exactly what this project ships plugins
            # for.
            #
            # A real agent opens one connection per batch and makes
            # one request on it, so a batch costs TWO units of a
            # 60/minute budget, not one — the connection here and the
            # request in `parse_request`. At the 30s default cadence
            # that is 4 units/minute, but a spool replay runs at
            # `relay._REPLAY_PACE_S`, and that constant is sized
            # against this one. Change either and check the pair.
            if limiter.in_cooldown(source, now) or not limiter.allow(
                    source, now):
                self.rejected_overload += 1
                self.shutdown_request(request)
                return
        with self._src_lock:
            in_use = sum(self._per_source.values())
            free = self.max_workers - in_use
            proven = self.is_proven(source)
            if not proven and free <= self.trusted_reserve:
                self.rejected_overload += 1
                log.debug(
                    "relay: refusing %s — the last %d slots are held for "
                    "sources that have completed a signed request",
                    source, self.trusted_reserve)
                self.shutdown_request(request)
                return
            if self._per_source.get(source, 0) >= self.max_per_source:
                self.rejected_overload += 1
                log.debug(
                    "relay: refusing a connection from %s — it already "
                    "holds %d of %d ingest workers.",
                    source, self.max_per_source, self.max_workers,
                )
                self.shutdown_request(request)
                return
        if not self._slots.acquire(blocking=False):
            self.rejected_overload += 1
            log.debug(
                "relay: refusing a connection from %s — all %d ingest "
                "workers are busy. Agents retry from their spool, so this "
                "costs a delay, not data.",
                client_address[0] if client_address else "?", self.max_workers,
            )
            self.shutdown_request(request)
            return
        with self._src_lock:
            self._per_source[source] = self._per_source.get(source, 0) + 1
            # The key is the raw socket for the connection's whole
            # life so cleanup can always find it; the socket in the
            # value is swapped for the wrapped one after the handshake.
            # [deadline, socket-to-shut-down, requests-completed]
            self._deadlines[request] = [time.monotonic() + _CONN_BUDGET,
                                        request, 0]
        try:
            super().process_request(request, client_address)
        except BaseException:
            # The slot and the counter are released in the worker's
            # `finally` — which never runs if the thread fails to spawn
            # (MemoryError, "can't start new thread"), i.e. exactly under
            # the resource pressure an attacker is pushing toward. Six
            # leaks from one address would lock that address out for the
            # life of the process, turning the anti-lockout counter into
            # the lockout.
            with self._src_lock:
                self._deadlines.pop(request, None)
            self._release(source)
            raise

    # Hard ceiling on the proven-source table. A TTL-only prune is not
    # a bound: a key holder posting from many addresses keeps every
    # entry inside the TTL and the dict grows without limit, and the
    # scan runs under the lock the ACCEPT path takes. `_RateLimiter`
    # already learned this; the lesson did not get carried across.
    max_trusted = 512

    #: How long a completed signed request keeps a source "proven".
    #: A CLASS attribute rather than a `getattr` default, so both
    #: readers below see the same value and a misspelled override
    #: fails loudly instead of silently doing nothing. Overridden
    #: per instance by tests that need to age the window out without
    #: mutating a module global every other thread shares.
    _trusted_ttl = _TRUSTED_TTL

    def active_slots(self) -> int:
        """Worker slots currently held, by source accounting."""
        with self._src_lock:
            return sum(self._per_source.values())

    def is_proven(self, source: str) -> bool:
        """Has this address completed a signed request recently?

        ABSENCE IS NOT A TIMESTAMP. This was
        `self._trusted.get(source, 0.0) > time.monotonic() - _TRUSTED_TTL`,
        and `time.monotonic()` counts from boot — so for the first
        hour of uptime the right-hand side is NEGATIVE and the 0.0
        default for an unknown source compares as proven. Every
        source read as trusted and the reserve did not exist.

        That is the window where it matters most: a firewall that has
        just rebooted, with no sensor having reported yet, is exactly
        when a flood of fresh addresses can take every worker. Four
        review rounds missed it because every reviewer's machine had
        been up for more than an hour; it surfaced on a box 31
        minutes from boot.

        Not a monotonic-clock quirk to code around — a sentinel that
        collides with real data. `None` cannot be mistaken for a
        time.
        """
        last = self._trusted.get(source)
        return last is not None and (
            time.monotonic() - last) < self._trusted_ttl

    def mark_trusted(self, source: str) -> None:
        now = time.monotonic()
        with self._src_lock:
            self._trusted[source] = now
            if len(self._trusted) <= self.max_trusted:
                return
            # Same TTL the proven check uses. Reading the module
            # global here while `is_proven` read the override meant a
            # shortened window pruned on the long one.
            cutoff = now - self._trusted_ttl
            for k in [k for k, v in self._trusted.items() if v < cutoff]:
                del self._trusted[k]
            # Still over: evict oldest. Losing a reservation costs a
            # sensor one contested connection, never its data.
            if len(self._trusted) > self.max_trusted:
                excess = len(self._trusted) - self.max_trusted
                for k in sorted(self._trusted, key=self._trusted.get)[:excess]:
                    del self._trusted[k]

    def note_served(self, key) -> None:
        """Record that this connection completed a request."""
        with self._src_lock:
            entry = self._deadlines.get(key)
            if entry is not None:
                entry[2] += 1

    def rebind_conn(self, old, new) -> None:
        """Record the LIVE socket for a connection, keeping its key.

        `ssl.wrap_socket` builds the SSLSocket from the raw socket's
        fileno and then DETACHES it, so the object stored at accept
        time has fileno == -1 and shutting it down raises EBADF. The
        reaper therefore needs the wrapped socket.

        It must NOT become the dict key, though. Rebinding the key
        meant the handler's cleanup — which pops by the raw socket it
        was given — silently matched nothing, so every connection left
        a live entry for the whole budget. That entry is a strong
        reference to the SSLSocket, which after the detach is the only
        object holding the real fd, so fds leaked at one per
        connection: measured, an unauthenticated peer reached EMFILE in
        14 seconds and the accept loop then span at 99.8% of a core in
        the same process as the pcap parser. The key stays the raw
        socket; only the value changes.
        """
        with self._src_lock:
            entry = self._deadlines.get(old)
            if entry is not None:
                entry[1] = new

    def _reap(self) -> None:
        """Close connections that have outstayed their budget.

        A reaper rather than a timeout because the handler can be
        blocked anywhere — mid-handshake, mid-header, mid-body — and
        only an external close reliably unblocks it. Shutting the
        socket down makes the blocked recv raise, the handler unwind,
        and the slot return.
        """
        last_report = time.monotonic()
        last_count = 0
        while not self._reaper_stop.wait(1.0):
            now = time.monotonic()
            # Report refusals periodically. This counter was
            # incremented in five places and read in none — the one
            # number that would tell an operator the port is being
            # flooded, never shown anywhere.
            if now - last_report >= _OVERLOAD_REPORT_S:
                refused = self.rejected_overload - last_count
                if refused:
                    log.warning(
                        "relay: refused %d connection(s) in the last %.0fs "
                        "— the ingest port is being flooded, or an agent is "
                        "misconfigured. Relayed data may be delayed, and a "
                        "sustained flood costs local capture throughput "
                        "even when every connection is refused. Restrict "
                        "the port to your agents.",
                        refused, _OVERLOAD_REPORT_S)
                last_count = self.rejected_overload
                last_report = now
            with self._src_lock:
                stale = [(k, v[1], v[2]) for k, v in self._deadlines.items()
                         if v[0] < now]
            for key, conn, served in stale:
                # Attempt FIRST, then report what actually happened. The
                # previous version logged the close before trying it, so
                # when the shutdown failed — which it always did — the
                # collector told its operator a defence had fired that
                # had not. A log line is a claim like any other.
                closed = False
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                    closed = True
                except OSError:
                    pass
                if closed:
                    with self._src_lock:
                        self._deadlines.pop(key, None)
                else:
                    # Leave it registered: a connection we could not
                    # close must stay budgeted, or a single failure
                    # exempts it forever.
                    with self._src_lock:
                        entry = self._deadlines.get(key)
                        if entry is not None:
                            entry[0] = now + _CONN_BUDGET
                if not closed:
                    log.debug("relay: budgeted connection was already gone")
                elif served:
                    # It did work and then lingered on a keep-alive
                    # socket. Reaping is still right — it was holding a
                    # worker slot — but calling that "without
                    # completing a request" was simply untrue, and an
                    # operator who cannot tell a real slot-hogger from
                    # a polite client learns to ignore both.
                    log.info(
                        "relay: closed a connection after its %.0fs "
                        "budget; it had completed %d request(s) and was "
                        "holding a worker slot", _CONN_BUDGET, served)
                else:
                    log.warning(
                        "relay: closed a connection that held an ingest "
                        "slot for over %.0fs without ever completing a "
                        "request", _CONN_BUDGET)

    def _release(self, source: str) -> None:
        self._slots.release()
        with self._src_lock:
            n = self._per_source.get(source, 1) - 1
            if n > 0:
                self._per_source[source] = n
            else:
                self._per_source.pop(source, None)

    def process_request_thread(self, request, client_address):
        source = client_address[0] if client_address else "?"
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._src_lock:
                self._deadlines.pop(request, None)
            self._release(source)


def _make_handler(server: IngestServer, ctx: ssl.SSLContext):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # Do not advertise the Python version on an open port.
        server_version = "hound"
        sys_version = ""
        timeout = 15

        def setup(self):
            # Wrap per connection, not on the listening socket: wrapping the
            # listener runs the handshake on the accept thread, so one
            # dribbled ClientHello blocks every other sensor.
            #
            # The timeout goes on BEFORE the handshake. wrap_socket() on a
            # blocking socket blocks indefinitely, so setting it afterwards
            # bounds only the request — a peer that opens a connection,
            # sends one byte and stops would pin a worker thread forever
            # without ever authenticating or reaching the rate limiter.
            # A short deadline for the HANDSHAKE specifically. The
            # request timeout is for a peer that has proven something;
            # a peer that has not should not be able to hold a worker
            # slot for the full window just by opening a socket.
            raw = self.request
            self._budget_key = raw
            self.request.settimeout(_HANDSHAKE_TIMEOUT)
            self.connection = ctx.wrap_socket(self.request, server_side=True)
            self.request = self.connection
            self.connection.settimeout(self.timeout)
            if server._httpd is not None:
                server._httpd.rebind_conn(raw, self.connection)
            super().setup()

        def finish(self):
            # Close the WRAPPED socket explicitly. socketserver's
            # close_request acts on the raw socket, which wrap_socket
            # already detached, so it closes nothing — teardown was
            # relying entirely on refcounting, and anything that kept a
            # reference (a deadline entry, a traceback) kept the fd
            # open with it. Explicit beats incidental for a resource a
            # remote peer can consume.
            try:
                super().finish()
            finally:
                try:
                    self.connection.close()
                except OSError:
                    pass

        def log_message(self, fmt, *args):
            log.debug("ingest: " + fmt, *args)

        def _reply_and_end(self, status, payload, drain_limit=_DRAIN_LIMIT):
            """Reply to a request whose body we will not read.

            Closing with unread incoming data makes the kernel RST,
            which DISCARDS the reply — measured, a 2.05 MB batch
            against the 2 MB cap never saw its 413 at all. The agent
            then took the reset as a transient network error instead
            of the permanent rejection it is, retried the same batch
            forever, wedged everything behind it, and at the age cap
            discarded the lot while `flush()` returned success and
            `hound relay` showed an empty spool with zero drops.

            Write the reply BEFORE lingering, not after. `wfile` is
            unbuffered, so this puts the status on the wire while the
            peer is still sending; the drain that follows is only
            there to keep the final close from resetting a connection
            whose receive queue still holds body bytes.

            `drain_limit` is how much of that body we are willing to
            absorb. Callers that must be understood exactly — 413
            above all, since the agent treats it as terminal and
            anything else as retryable — pass the whole body cap. A
            refusal aimed at a source already over budget keeps the
            small default and accepts that it may reset: every status
            on that path is retryable, so a reset costs the peer
            nothing it did not already have coming.
            """
            # Flag first so `_reply` can emit `Connection: close`;
            # the drain still runs after the reply is on the wire.
            self.close_connection = True
            self._reply(status, payload)
            self._drain_unread_body(limit=drain_limit)

        def _reply(self, status, payload):
            raw = json.dumps(payload).encode()
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            if self.close_connection:
                # Say so in the response rather than only in the
                # socket. A reusing client otherwise sees a silent
                # close where a signalled one would have told it to
                # open a fresh connection.
                self.send_header("Connection", "close")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _drain_unread_body(self, limit: int = _DRAIN_LIMIT) -> None:
            """Discard a bounded amount of an unread request body.

            Closing a socket that still holds unread incoming data
            makes the kernel send RST, which discards the response we
            just wrote — so a client refused before its body was read
            would never see the status explaining why.

            Bounded by a TOTAL deadline, not a per-recv timeout. A
            socket timeout resets on every byte, so a peer dribbling
            one byte per second held the handler here indefinitely —
            measured 21s on 20 of 65,536 bytes — and the real bound
            was the 120s connection reaper. It runs from the
            rate-limited path AND from `send_error`, so "only on the
            metered path" was never true either.
            """
            # `self.headers` may not exist yet: parse_request calls
            # send_error for a malformed request line BEFORE assigning
            # it, and this runs from that path. Without the guard the
            # AttributeError was swallowed by the server's
            # handle_error and the client got a silent close instead
            # of its 400.
            headers = getattr(self, "headers", None)
            if headers is None:
                return
            if getattr(self, "_body_read", False):
                # The body was already consumed (or the peer stopped
                # short of what it declared). Content-Length still
                # names the full size, so draining again would just
                # sit on the deadline for nothing.
                return
            if headers.get("Transfer-Encoding", "").lower() == "chunked":
                # No Content-Length to go on, and the handler refuses
                # chunked outright. Absorb best-effort up to the same
                # ceiling and stop at EOF: without this the refusal
                # closed on an unread chunked body and the 400 was
                # lost to an RST, which is the same silent-retry trap
                # the 413 had.
                remaining = limit
            else:
                try:
                    remaining = min(int(headers.get("Content-Length") or 0),
                                    limit)
                except (TypeError, ValueError, AttributeError):
                    return
            if remaining <= 0:
                return
            give_up_at = time.monotonic() + _DRAIN_BUDGET_S
            try:
                self.connection.settimeout(_DRAIN_BUDGET_S)
            except OSError:
                return
            try:
                while remaining > 0:
                    if time.monotonic() >= give_up_at:
                        return
                    # Per-iteration timeout from the REMAINING budget.
                    # Checking the deadline and then handing read1 the
                    # full budget meant one more whole budget could
                    # elapse inside the call: measured 3.84s against a
                    # docstring promising 2s, for a peer sending one
                    # byte every 1.9s.
                    left = give_up_at - time.monotonic()
                    if left <= 0:
                        return
                    try:
                        self.connection.settimeout(left)
                    except OSError:
                        return
                    try:
                        # read1, not read: `read(n)` on a buffered
                        # reader loops internally until it HAS n
                        # bytes, so the deadline above was only
                        # consulted between 8 KB blocks — a peer
                        # dribbling under the socket timeout was
                        # measured holding this for 122s on 79 of
                        # 65,536 bytes, 61x the stated bound. read1
                        # returns whatever has arrived, so the
                        # deadline is checked per arrival.
                        chunk = self.rfile.read1(min(remaining, 8192))
                    except (OSError, ValueError):
                        return
                    if not chunk:
                        return
                    remaining -= len(chunk)
            finally:
                try:
                    self.connection.settimeout(self.timeout)
                except OSError:
                    pass

        def handle_one_request(self):
            # One request, one meter. `handle_one_request` rejects an
            # over-long request line (414) ITSELF, before
            # parse_request runs, so that shape slipped past metering
            # even after it moved earlier. The flag lets send_error
            # meter whatever the stdlib rejected without
            # double-counting anything parse_request already saw.
            self._metered = False
            # Reset per REQUEST, not per connection. The handler
            # instance is reused for every request on a keep-alive
            # socket, and only the refusal paths set
            # `close_connection` — so after one request with a body,
            # every later refusal on that socket took the
            # "already consumed" early return in `_drain_unread_body`,
            # drained nothing, and reset the client. The oversize-body
            # 413 was delivered as the first request on a connection
            # and lost as the second.
            self._body_read = False
            super().handle_one_request()

        def _meter_once(self) -> bool:
            """Charge this request to its source, at most once.

            Returns False if the source is over budget.
            """
            if getattr(self, "_metered", False):
                return True
            self._metered = True
            source = self.client_address[0] if self.client_address else "?"
            now = server.now()
            if server._limiter.in_cooldown(source, now):
                return False
            return server._limiter.allow(source, now)

        def send_error(self, code, message=None, explain=None):
            # Catches every stdlib rejection that never reached
            # parse_request — 414 above all.
            self._meter_once()
            # The stdlib error path (501 for an unknown verb, 414, …)
            # sets close_connection and writes its reply. If the peer
            # sent a body we never read, closing makes the kernel RST
            # and the client sees a connection reset instead of the
            # status telling it what was wrong. Drain first.
            self._drain_unread_body()
            super().send_error(code, message, explain)

        def parse_request(self):
            """Meter every request, whatever its method.

            Metering inside do_GET/do_POST missed every OTHER verb:
            BaseHTTPRequestHandler dispatches an unknown method
            straight to send_error(501) without ever reaching them, so
            a PUT flood was unmetered — the exact class the previous
            commit claimed to have closed, through a different shape.
            parse_request runs after the request line is read and
            before dispatch, which is the one place that sees all of
            them.

            It also closes the connection for a source in cooldown. The
            cooldown was only consulted at accept, so a peer holding
            ONE keep-alive socket never re-entered that path and kept
            being served cheap 429s indefinitely — the bound there was
            TCP backpressure, not the mechanism this comment describes.
            """
            # BEFORE super(), not after.
            #
            # Metering after it only saw requests the stdlib had
            # already accepted. Everything it rejects earlier — a
            # 70 kB request line (414), a bad version (505), a header
            # flood (431), a malformed line (400) — never reached the
            # limiter at all. Measured: ~1,900 req/s from ONE address
            # with no key, costing 62-66% of packet-parse throughput,
            # with the cooldown never arming and nothing logged above
            # DEBUG. That is two thirds of the way back to the
            # pre-metering regime, through the shapes the stdlib
            # handles for us.
            #
            # Safe to meter here: handle_one_request only calls
            # parse_request once it has actually read a request line,
            # so this cannot count a connection that is merely idle.
            # Meter FIRST so every shape is charged, but reply AFTER
            # the stdlib parse: before it, `request_version` is still
            # HTTP/0.9 and send_response suppresses the status line
            # entirely, so the peer saw a reset instead of its 429.
            over_budget = not self._meter_once()
            if not super().parse_request():
                return False          # the stdlib already answered
            if over_budget:
                # Same ordering trap as the 413: this drained and THEN
                # replied, so the reply went out immediately before the
                # close and anything still unread reset it away. 429 is
                # retryable, so losing it costs a cycle rather than
                # data — but it is the signal that tells a replaying
                # agent to back off instead of digging in.
                self._reply_and_end(HTTPStatus.TOO_MANY_REQUESTS,
                                    {"error": "slow down"})
                return False
            return True

        def do_GET(self):          # noqa: N802
            self._reply_and_end(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "POST only"})

        def do_POST(self):         # noqa: N802
            source = self.client_address[0] if self.client_address else "?"

            # Metering happens in parse_request, which sees every
            # method and runs before dispatch.
            if self.path != INGEST_PATH:
                self._reply_and_end(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return

            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                # BaseHTTPRequestHandler cannot read a chunked body, and
                # silently treating it as empty would be worse.
                self._reply_and_end(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "chunked encoding not supported"})
                return

            # Duplicated, not just misspelled. `headers.get` returns
            # the FIRST of a repeated header, so two different lengths
            # parsed here as whichever came first — the same
            # smuggling differential the strict spelling check below
            # addresses, through a different door. No proxy is the
            # documented topology; neither of these matters until
            # someone puts one in front, and then both do.
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) > 1:
                self._reply_and_end(
                    HTTPStatus.BAD_REQUEST,
                    {"error": "duplicate Content-Length"})
                return
            raw_len = self.headers.get("Content-Length")
            if raw_len is None:
                self._reply_and_end(HTTPStatus.LENGTH_REQUIRED,
                            {"error": "Content-Length required"})
                return
            # Strict: bare ASCII digits only. `int()` also accepts
            # "_" separators, surrounding whitespace, a sign, and
            # non-ASCII decimal digits (int("\u0665") == 5), so three
            # spellings of one length parsed here and would not
            # survive a proxy in front. No proxy is the documented
            # topology; this keeps it from becoming a smuggling
            # differential if one is ever added.
            if not raw_len.isascii() or not raw_len.isdigit():
                self._reply_and_end(HTTPStatus.BAD_REQUEST,
                                    {"error": "bad Content-Length"})
                return
            try:
                length = int(raw_len)
            except ValueError:
                self._reply_and_end(HTTPStatus.BAD_REQUEST,
                                    {"error": "bad Content-Length"})
                return
            # Check the declared size before reading a single byte.
            if length > server.cfg.max_body_bytes:
                # The agent treats 413 as terminal and a reset as
                # retryable, so this is the one status that must not
                # be lost to an RST. See `_DRAIN_MAX`: the ceiling has
                # to EXCEED the cap, because exceeding the cap is what
                # got us here.
                self._reply_and_end(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                    {"error": f"body over {server.cfg.max_body_bytes} bytes",
                     # Same reason as the 400 above: let the agent
                     # re-split to a size this collector will take
                     # rather than discard the batch.
                     "limits": {
                         "max_records_per_batch":
                             server.cfg.max_records_per_batch,
                         "max_body_bytes": server.cfg.max_body_bytes,
                     }},
                    drain_limit=max(_DRAIN_MAX,
                                    2 * server.cfg.max_body_bytes))
                return

            # Read the body OUTSIDE the CPU slot.
            #
            # Holding the slot across the read was a slowloris on the
            # CPU limit: two clients that complete the handshake,
            # declare a large Content-Length and then dribble bytes
            # held both slots for the full socket timeout, and a
            # legitimate sensor got 5 of 10 batches in. A slow reader
            # must cost a thread, which is plentiful, not a CPU slot,
            # of which there are two.
            #
            # The memory that motivated moving it inside is handled by
            # max_body_bytes instead: at the 2 MB default, all 16
            # connections buffering at once is 32 MB.
            try:
                body = self.rfile.read(length)
                self._body_read = True
            except (TimeoutError, socket.timeout, OSError):
                self._body_read = True
                return
            if len(body) != length:
                self._reply_and_end(HTTPStatus.BAD_REQUEST,
                                    {"error": "short body"})
                return
            # Deliberately NO deadline refresh here.
            #
            # It looked harmless — "the peer did real work, give it
            # more time" — but keep-alive is on, and the refresh fires
            # after ANY body is read, including one that goes on to be
            # rejected 401. An unauthenticated peer could hold a slot
            # forever by sending a small request before each timeout.
            # It also buys nothing: the worst legitimate connection is
            # a 2 MB upload on a 512 kbit link plus a handshake plus a
            # CPU-slot queue, about 42s against a 120s budget.
            try:
                with server._cpu_slot:
                    status, payload = server.handle_batch(
                        source, body, self.headers)
            except Exception:       # noqa: BLE001
                log.exception("relay: ingest failed")
                self._reply(HTTPStatus.INTERNAL_SERVER_ERROR,
                            {"error": "internal error"})
                return
            self._reply(status, payload)
            # Only a SUCCESSFUL batch counts. Counting rejections let a
            # peer downgrade its own reap log from WARNING to INFO by
            # sending one junk POST first.
            if (int(status) == int(HTTPStatus.OK)
                    and server._httpd is not None):
                server._httpd.note_served(self._budget_key)
            return

    return Handler
