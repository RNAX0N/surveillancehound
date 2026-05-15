"""Live flow aggregator — bidirectional 5-tuple aggregation with TTL eviction.

Packets stream in; the aggregator builds one mutable accumulator per
conversation (`proto + endpoint-pair`, order-normalized so request and
response collapse into one flow). The daemon periodically calls
`evict_idle(now, ttl)`, which returns flows whose `last_seen + ttl < now`,
removing them from the active table — that is what keeps RAM flat on a host
that runs for weeks. A hard cap on the active table evicts the oldest flow
when exceeded, so a packet storm cannot run us out of memory.

This module has NO knowledge of cameras / classifications / alerts. It just
aggregates. Downstream modules (classify, alerts) decide what to do with the
evicted flows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator

from surveillancehound.pcap import Packet


@dataclass
class LiveFlow:
    """Mutable accumulator for one bidirectional conversation."""

    proto: str
    ep_a: tuple        # (ip, port|None) — the stable-sorted lower endpoint
    ep_b: tuple        # (ip, port|None) — the stable-sorted higher endpoint
    first_ts: float
    last_ts: float
    packets: int = 0
    bytes: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    flags: set[str] = field(default_factory=set)
    # one-shot edge tracking — has this flow been emitted as a NEW_PEER yet?
    new_peer_emitted: bool = False

    def add(self, pkt: Packet) -> None:
        if pkt.ts:
            if not self.first_ts or pkt.ts < self.first_ts:
                self.first_ts = pkt.ts
            self.last_ts = max(self.last_ts, pkt.ts)
        self.packets += 1
        self.bytes += pkt.length
        src_ep = (pkt.src_ip, pkt.src_port)
        if src_ep == self.ep_a:
            self.bytes_a_to_b += pkt.length
        else:
            self.bytes_b_to_a += pkt.length
        for ch in pkt.tcp_flags:
            self.flags.add(ch)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


def flow_key(pkt: Packet) -> tuple:
    """Bidirectional 5-tuple key (proto, lo, hi). Lo/hi sorted by (ip, port)."""
    a = (pkt.src_ip, pkt.src_port)
    b = (pkt.dst_ip, pkt.dst_port)
    lo, hi = (a, b) if a <= b else (b, a)
    return (pkt.proto, lo, hi)


class FlowAggregator:
    """Holds active flows. Memory-bounded by TTL eviction + a hard cap."""

    def __init__(self, *, max_active_flows: int = 50_000) -> None:
        self.flows: dict[tuple, LiveFlow] = {}
        self.max_active_flows = max_active_flows

    def ingest(self, pkt: Packet) -> LiveFlow:
        """Update the matching flow (creating it if new). Returns the flow."""
        key = _, lo, hi = flow_key(pkt)
        fl = self.flows.get(key)
        if fl is None:
            fl = LiveFlow(
                proto=pkt.proto, ep_a=lo, ep_b=hi,
                first_ts=pkt.ts or 0.0, last_ts=pkt.ts or 0.0,
            )
            self.flows[key] = fl
            # honor the hard cap by evicting the oldest flow first
            if len(self.flows) > self.max_active_flows:
                self._evict_oldest()
        fl.add(pkt)
        return fl

    def evict_idle(self, now: float, ttl: float) -> Iterator[LiveFlow]:
        """Yield + remove every flow whose last_seen + ttl < now."""
        cutoff = now - ttl
        to_remove = [k for k, fl in self.flows.items() if fl.last_ts < cutoff]
        for k in to_remove:
            yield self.flows.pop(k)

    def drain(self) -> Iterator[LiveFlow]:
        """Yield + remove every active flow (used on shutdown)."""
        while self.flows:
            _, fl = self.flows.popitem()
            yield fl

    def _evict_oldest(self) -> None:
        """Remove the single oldest flow — keep memory bounded under packet storms."""
        if not self.flows:
            return
        oldest_key = min(self.flows, key=lambda k: self.flows[k].last_ts)
        del self.flows[oldest_key]

    def __len__(self) -> int:
        return len(self.flows)
