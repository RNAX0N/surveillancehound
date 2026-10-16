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
        return (st.f_bavail * st.f_frsize) >= (limit * 1024 * 1024)

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
            log.warning("relay: rejected batch from %s (sensor=%r)",
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
            log.warning(
                "relay: sensor %r presented a new instance id (%r -> %r); "
                "accepting and resetting its sequence. If two agents share "
                "this sensor_id, give them separate ids.",
                sensor_id, known.instance_id, instance_id,
            )

        try:
            records = validate.validate_records(
                doc.get("records", {}), self.cfg.max_records_per_batch,
            )
        except validate.ValidationError as e:
            log.warning("relay: rejected batch from %s: %s", sensor_id, e)
            return HTTPStatus.BAD_REQUEST, {"error": str(e)}

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
        limiter = getattr(self, "limiter", None)
        if limiter is not None and limiter.in_cooldown(source, time.time()):
            self.rejected_overload += 1
            self.shutdown_request(request)
            return
        with self._src_lock:
            in_use = sum(self._per_source.values())
            free = self.max_workers - in_use
            proven = self._trusted.get(source, 0.0) > (
                time.monotonic() - _TRUSTED_TTL)
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
                log.warning(
                    "relay: refusing a connection from %s — it already "
                    "holds %d of %d ingest workers. One host must not be "
                    "able to lock out the others.",
                    source, self.max_per_source, self.max_workers,
                )
                self.shutdown_request(request)
                return
        if not self._slots.acquire(blocking=False):
            self.rejected_overload += 1
            log.warning(
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

    def active_slots(self) -> int:
        """Worker slots currently held, by source accounting."""
        with self._src_lock:
            return sum(self._per_source.values())

    def mark_trusted(self, source: str) -> None:
        now = time.monotonic()
        with self._src_lock:
            self._trusted[source] = now
            if len(self._trusted) <= self.max_trusted:
                return
            cutoff = now - _TRUSTED_TTL
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
        while not self._reaper_stop.wait(1.0):
            now = time.monotonic()
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

        def _reply(self, status, payload):
            raw = json.dumps(payload).encode()
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _drain_unread_body(self) -> None:
            """Discard a bounded amount of an unread request body.

            Closing a socket that still holds unread incoming data
            makes the kernel send RST, which discards the response we
            just wrote — so a client refused before its body was read
            would never see the 429 explaining why. Bounded in size
            and in time: this runs only on the rate-limited path, so
            it cannot be used to hold a connection open.
            """
            try:
                remaining = min(int(self.headers.get("Content-Length") or 0),
                                65536)
            except (TypeError, ValueError):
                return
            if remaining <= 0:
                return
            try:
                self.connection.settimeout(2.0)
            except OSError:
                return
            try:
                while remaining > 0:
                    try:
                        chunk = self.rfile.read(min(remaining, 8192))
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

        def send_error(self, code, message=None, explain=None):
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
            if not super().parse_request():
                return False
            source = self.client_address[0] if self.client_address else "?"
            now = server.now()
            if server._limiter.in_cooldown(source, now):
                self.close_connection = True
                self._drain_unread_body()
                self._reply(HTTPStatus.TOO_MANY_REQUESTS,
                            {"error": "cooling down"})
                return False
            if not server._limiter.allow(source, now):
                self.close_connection = True
                self._drain_unread_body()
                self._reply(HTTPStatus.TOO_MANY_REQUESTS,
                            {"error": "slow down"})
                return False
            return True

        def do_GET(self):          # noqa: N802
            self._reply(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "POST only"})

        def do_POST(self):         # noqa: N802
            source = self.client_address[0] if self.client_address else "?"

            # Metering happens in parse_request, which sees every
            # method and runs before dispatch.
            if self.path != INGEST_PATH:
                self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return

            if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                # BaseHTTPRequestHandler cannot read a chunked body, and
                # silently treating it as empty would be worse.
                self._reply(HTTPStatus.BAD_REQUEST,
                            {"error": "chunked encoding not supported"})
                return

            raw_len = self.headers.get("Content-Length")
            if raw_len is None:
                self._reply(HTTPStatus.LENGTH_REQUIRED,
                            {"error": "Content-Length required"})
                return
            try:
                length = int(raw_len)
            except ValueError:
                self._reply(HTTPStatus.BAD_REQUEST, {"error": "bad Content-Length"})
                return
            # Check the declared size before reading a single byte.
            if length < 0 or length > server.cfg.max_body_bytes:
                self._reply(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                            {"error": f"body over {server.cfg.max_body_bytes} bytes"})
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
            except (TimeoutError, socket.timeout, OSError):
                return
            if len(body) != length:
                self._reply(HTTPStatus.BAD_REQUEST, {"error": "short body"})
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
