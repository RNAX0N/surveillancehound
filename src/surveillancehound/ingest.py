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
        self._lock = threading.Lock()

    def allow(self, source: str, now: float) -> bool:
        with self._lock:
            q = self._hits[source]
            while q and (now - q[0]) > 60.0:
                q.popleft()
            if len(q) >= self.per_minute:
                return False
            q.append(now)
            if len(self._hits) > 1024:
                self._sweep(now)
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
            return self._handle_batch(source, body, headers)
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
        self._slots = threading.BoundedSemaphore(self.max_workers)
        self._per_source: dict[str, int] = {}
        self._src_lock = threading.Lock()
        self.rejected_overload = 0

    # Per-source ceiling, enforced at ACCEPT time, so one address
    # cannot take the whole pool. The token-bucket rate
    # limiter lives inside do_POST, which a peer only reaches after a
    # completed TLS handshake — so a single address could hold every
    # worker slot indefinitely by connecting and never finishing, and
    # legitimate sensors were refused ~90% of the time. The global
    # ceiling bounds resources; this one keeps one host from owning them.
    max_per_source = 4

    # Slots held back for sources that currently hold NONE. A flat
    # per-source cap only raises the number of addresses an attacker
    # needs to own the pool, to exactly max_workers/max_per_source —
    # four, which on a camera segment or any IPv6 range is not a
    # defence. Measured, four hosts holding half-open sockets took a
    # legitimate sensor from 45/45 to 2/45. Reserving capacity for
    # first-connection sources means a sensor that is not already
    # hogging can always get in, however many addresses are flooding.
    newcomer_reserve = 4

    def process_request(self, request, client_address):
        source = client_address[0] if client_address else "?"
        with self._src_lock:
            held = self._per_source.get(source, 0)
            in_use = sum(self._per_source.values())
            if held and (self.max_workers - in_use) <= self.newcomer_reserve:
                self.rejected_overload += 1
                log.debug(
                    "relay: %s already holds %d connection(s); the last "
                    "%d slots are reserved for sensors holding none",
                    source, held, self.newcomer_reserve)
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
            self._release(source)
            raise

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
            self.request.settimeout(_HANDSHAKE_TIMEOUT)
            self.connection = ctx.wrap_socket(self.request, server_side=True)
            self.request = self.connection
            self.connection.settimeout(self.timeout)
            super().setup()

        def log_message(self, fmt, *args):
            log.debug("ingest: " + fmt, *args)

        def _reply(self, status, payload):
            raw = json.dumps(payload).encode()
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):          # noqa: N802
            self._reply(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "POST only"})

        def do_POST(self):         # noqa: N802
            source = self.client_address[0] if self.client_address else "?"

            if self.path != INGEST_PATH:
                self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return

            # Rate limit BEFORE reading the body or authenticating.
            if not server._limiter.allow(source, server.now()):
                self._reply(HTTPStatus.TOO_MANY_REQUESTS, {"error": "slow down"})
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

            # The CPU slot is taken BEFORE the body is read, not
            # after. Reading first meant every accepted connection
            # buffered up to max_body_bytes while parked waiting for
            # the slot — sixteen of those is 128 MB of bodies resident
            # on top of the parses, and it was the larger half of a
            # measured 591 MB peak. Now only the batches that are
            # actually being worked on are in memory; the rest are a
            # thread and a socket.
            with server._cpu_slot:
                try:
                    body = self.rfile.read(length)
                except (TimeoutError, socket.timeout, OSError):
                    return
                if len(body) != length:
                    self._reply(HTTPStatus.BAD_REQUEST,
                                {"error": "short body"})
                    return
                try:
                    status, payload = server.handle_batch(
                        source, body, self.headers)
                except Exception:       # noqa: BLE001
                    log.exception("relay: ingest failed")
                    self._reply(HTTPStatus.INTERNAL_SERVER_ERROR,
                                {"error": "internal error"})
                    return
            self._reply(status, payload)
            return

    return Handler
