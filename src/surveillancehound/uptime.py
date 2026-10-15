"""Per-camera liveness state machine — passive uptime monitoring.

**Detection is passive.** A camera counts as up because packets from it were
observed on the monitored interface. Nothing here probes anything: no ICMP,
no TCP connect, no ONVIF keepalive. A camera that is powered and recording
but no longer visible to this sensor — moved VLAN, mirror/SPAN port
reconfigured, uplink re-patched — is indistinguishable from one that is
powered down. Active probing would close that gap and is deliberately out of
scope; see DevNotes.md. Never let a surface built on this module claim
liveness is *verified*.

Three things make the inference trustworthy enough to alert on:

  * **An open row in `outages` IS the down-state.** There is no separate
    state table, so a daemon restart resumes an outage mid-flight instead of
    forgetting it (and re-alerting) or double-opening it.
  * **The silence floor.** Silence only counts from the moment this sensor
    gained continuous visibility — daemon start, or recovery from a capture
    stall. Without it, every camera would alert the instant the daemon came
    back from a blind window, purely because the last packet we happen to
    hold predates the gap.
  * **No blame without evidence.** A camera is only declared down if some
    packet — from anything, not just that camera — has been observed more
    recently than the camera's own last packet. If nothing newer exists, the
    sensor has seen nothing since the camera went quiet, so "the camera
    died" and "we went blind" are the same observation and there is no
    honest basis for picking one. This also neutralizes the config
    foot-gun where `capture_stall_seconds >= silence_seconds`, which would
    otherwise trip every camera before the stall was ever declared.
  * **Stall suppression.** When NO packets at all arrive for
    `capture_stall_seconds`, the sensor is blind: tcpdump died, the NIC went
    down, the mirror port changed. In that state exactly one `stalled`
    transition is emitted and every per-camera `down` is suppressed —
    otherwise a dead capture presents as every camera failing at once, and
    the operator chases cameras instead of the sensor.

This module knows nothing about alerts or notification. It returns
`Transition` objects; `daemon.Hound` turns them into alerts, and is also
what splits the monitor session on a stall so blind time is excluded from
availability.

The clock is always passed in — this module never calls `time.time()`. Live
capture passes wall clock, replay passes the maximum packet timestamp seen,
which is what keeps `hound replay` from reporting a storm of fake outages
against a capture recorded months ago.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from surveillancehound.config import NetworkCfg, ThresholdCfg, UptimeCfg
from surveillancehound.store import HoundStore, OutageRow

log = logging.getLogger(__name__)

# transition kinds
DOWN = "down"
UP = "up"
NEVER_SEEN = "never_seen"
STALLED = "stalled"
STALL_CLEARED = "stall_cleared"


@dataclass(frozen=True)
class Transition:
    """One liveness state change. `camera_ip` is "" for stall transitions."""

    kind: str
    camera_ip: str
    since: float             # when the state being reported began
    duration: float          # how long it has been in that state
    outage_id: int | None
    last_seen_before: float  # 0.0 when the camera has never been observed
    role: str = "camera"     # camera | nvr — for human-readable alert text


class UptimeTracker:
    """Tracks per-camera liveness. One instance per daemon process.

    Hot path is `touch()`: one dict write per packet, no SQLite. All
    persistence happens on `tick()`, which the daemon calls every few
    seconds.
    """

    def __init__(
        self, cfg: UptimeCfg, thresholds: ThresholdCfg, *, replay: bool,
    ) -> None:
        self.cfg = cfg
        self.thresholds = thresholds
        self.replay = replay
        self._grace = cfg.grace_for(thresholds)

        # last observed activity per camera/nvr IP (in RAM, authoritative)
        self._last_activity: dict[str, float] = {}
        # IPs touched since the last tick, flushed to devices.last_seen
        self._pending_touch: dict[str, float] = {}
        # camera_ip -> open outage id
        self._open: dict[str, int] = {}
        # roles we were told about, so alert text can say camera vs NVR
        self._roles: dict[str, str] = {}
        # configured cameras that have never been observed at all
        self._never_seen: set[str] = set()
        # never_seen fires once per process, not once per tick
        self._never_seen_alerted: set[str] = set()

        self._started_at = 0.0
        # silence only counts from here — see the module docstring
        self._silence_floor = 0.0
        # timestamp of the most recent packet from ANY source (not just
        # cameras). This is evidence that the sensor can still see, which is
        # what separates "that camera died" from "we went blind".
        self._last_packet_at = 0.0
        self._stalled = False
        self._stalled_since = 0.0

    @property
    def stalled(self) -> bool:
        return self._stalled

    # ----- lifecycle -----

    def bootstrap(
        self, store: HoundStore, network: NetworkCfg, now: float,
    ) -> None:
        """Seed configured cameras, hydrate prior state, start the clock.

        Seeding is gap #3: a camera that was powered down before the daemon
        ever started has no device row and no traffic, so without this it is
        invisible rather than alertable.
        """
        self._started_at = now
        self._silence_floor = now
        self._last_packet_at = now

        for ip in network.camera_ips:
            self._roles[ip] = "camera"
            store.seed_device(ip, "camera", now)
        for ip in network.nvr_ips:
            self._roles[ip] = "nvr"
            store.seed_device(ip, "nvr", now)

        for d in store.list_devices():
            if d.role not in ("camera", "nvr"):
                continue
            self._roles.setdefault(d.ip, d.role)
            if d.last_seen > 0.0:
                # restore prior observation so a restart does not re-alert
                self._last_activity[d.ip] = d.last_seen
            else:
                self._never_seen.add(d.ip)

        for o in store.open_outages():
            self._open[o.camera_ip] = o.id
            # an already-announced outage must not re-announce on restart
            if o.cause == NEVER_SEEN:
                self._never_seen_alerted.add(o.camera_ip)

        if self._open:
            log.info(
                "uptime: resumed %d open outage(s): %s",
                len(self._open), ", ".join(sorted(self._open)),
            )
        log.info(
            "uptime: tracking %d device(s), %d never observed "
            "(silence=%gs, grace=%gs, stall=%gs)",
            len(self._roles), len(self._never_seen),
            self.thresholds.silence_seconds, self._grace,
            self.cfg.capture_stall_seconds,
        )

    def observe_packet(self, ts: float) -> None:
        """Record that SOME packet was seen. Called for every packet.

        Separate from `touch` on purpose: `touch` records which camera is
        alive, this records that the sensor itself is still receiving. A
        camera is only blamed for silence when something newer than its own
        last packet has been observed — otherwise the two explanations
        (camera down / sensor blind) are indistinguishable from here.
        """
        if ts > self._last_packet_at:
            self._last_packet_at = ts

    def touch(self, ip: str, now: float) -> None:
        """Record activity for a camera/NVR IP. Called per packet."""
        prev = self._last_activity.get(ip, 0.0)
        if now <= prev:
            return  # out-of-order packet — never move a clock backwards
        self._last_activity[ip] = now
        self._pending_touch[ip] = now
        self._never_seen.discard(ip)
        self.observe_packet(now)

    def flush(self, store: HoundStore, now: float) -> None:
        """Persist pending last_seen updates. Called on shutdown."""
        if self._pending_touch:
            store.touch_devices_last_seen(self._pending_touch)
            self._pending_touch.clear()

    # ----- the tick -----

    def tick(
        self, store: HoundStore, now: float, *, saw_packets: bool,
    ) -> list[Transition]:
        """Advance the state machine. Returns transitions for the daemon.

        `saw_packets` is whether ANY packet arrived since the previous tick
        — not just camera traffic. It drives the dead-man's-switch.
        """
        out: list[Transition] = []

        # (a) persist what we observed. This is the fix for a streaming
        #     camera false-tripping: last_seen used to advance only when a
        #     flow was evicted, and a 24/7 RTSP stream never goes idle.
        self.flush(store, now)

        # (b) capture stall — evaluate before anything per-camera
        stall = self._tick_stall(now, saw_packets)
        if stall is not None:
            out.append(stall)
            if stall.kind == STALLED:
                # blind: say so once and suppress the per-camera storm
                return out
        elif self._stalled:
            return out  # still blind, already reported

        # (c) per-camera evaluation
        out.extend(self._tick_cameras(store, now))
        return out

    def _tick_stall(self, now: float, saw_packets: bool) -> Transition | None:
        """The dead-man's-switch. Zero packets at all means we are blind."""
        window = self.cfg.capture_stall_seconds
        if window <= 0:
            return None  # disabled by config
        if saw_packets:
            if not self._stalled:
                return None
            self._stalled = False
            stall_began = self._stalled_since
            # visibility regained: restart every camera's silence clock, or
            # each one alerts purely because its last packet predates the gap
            self._silence_floor = now
            log.info("uptime: capture recovered after %.0fs blind",
                     now - stall_began)
            return Transition(
                kind=STALL_CLEARED, camera_ip="", since=stall_began,
                duration=max(0.0, now - stall_began), outage_id=None,
                last_seen_before=0.0, role="",
            )
        silent_for = now - self._last_packet_at
        if not self._stalled and silent_for >= window:
            self._stalled = True
            self._stalled_since = self._last_packet_at
            log.warning(
                "uptime: no packets for %.0fs — capture stalled, per-camera "
                "offline alerts suppressed", silent_for,
            )
            return Transition(
                kind=STALLED, camera_ip="", since=self._last_packet_at,
                duration=silent_for, outage_id=None, last_seen_before=0.0,
                role="",
            )
        return None

    def _tick_cameras(
        self, store: HoundStore, now: float,
    ) -> list[Transition]:
        out: list[Transition] = []
        silence = self.thresholds.silence_seconds

        # recoveries first, so a camera that came back in the same tick it
        # would have tripped is reported as up rather than down
        for ip, outage_id in list(self._open.items()):
            last = self._last_activity.get(ip, 0.0)
            row = store.open_outage_for(ip)
            if row is None:
                # closed out from under us (e.g. prune); forget it
                del self._open[ip]
                continue
            if last > row.down_since:
                store.close_outage(outage_id, last)
                del self._open[ip]
                self._never_seen_alerted.discard(ip)
                out.append(Transition(
                    kind=UP, camera_ip=ip, since=row.down_since,
                    duration=max(0.0, last - row.down_since),
                    outage_id=outage_id, last_seen_before=row.last_seen_before,
                    role=self._roles.get(ip, "camera"),
                ))

        # a camera in config that has never been observed at all
        for ip in sorted(self._never_seen):
            if ip in self._open or ip in self._never_seen_alerted:
                continue
            if (now - self._started_at) < self._grace:
                continue  # still inside the startup grace window
            self._never_seen_alerted.add(ip)
            outage_id = store.open_outage(OutageRow(
                id=None, camera_ip=ip, down_since=self._started_at,
                up_at=None, last_seen_before=0.0, cause=NEVER_SEEN,
                alert_id=None,
            ))
            self._open[ip] = outage_id
            out.append(Transition(
                kind=NEVER_SEEN, camera_ip=ip, since=self._started_at,
                duration=now - self._started_at, outage_id=outage_id,
                last_seen_before=0.0, role=self._roles.get(ip, "camera"),
            ))

        # cameras that have gone quiet
        stall_enabled = self.cfg.capture_stall_seconds > 0
        for ip, last in sorted(self._last_activity.items()):
            if ip in self._open:
                continue
            # silence is only counted from when this sensor could actually see
            effective_last = max(last, self._silence_floor)
            silent_for = now - effective_last
            if silent_for < silence:
                continue
            if stall_enabled and self._last_packet_at <= effective_last:
                # The newest packet seen from ANY source is no newer than
                # this camera's own last packet. So the sensor has observed
                # nothing at all since this camera went quiet, and "the
                # camera died" and "the sensor went blind" are the same
                # observation — there is no evidence that distinguishes
                # them. Stay quiet and let the stall detector speak.
                #
                # This also covers the config foot-gun where
                # capture_stall_seconds >= silence_seconds: without it, every
                # camera would trip before the stall was ever declared, which
                # is precisely the storm the stall detector exists to prevent.
                continue
            outage_id = store.open_outage(OutageRow(
                id=None, camera_ip=ip, down_since=effective_last,
                up_at=None, last_seen_before=last, cause="silence",
                alert_id=None,
            ))
            self._open[ip] = outage_id
            out.append(Transition(
                kind=DOWN, camera_ip=ip, since=effective_last,
                duration=silent_for, outage_id=outage_id,
                last_seen_before=last, role=self._roles.get(ip, "camera"),
            ))
        return out
