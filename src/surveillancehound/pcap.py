"""Pure-Python pcap / pcapng reader — file *and* live-stream.

Originally extracted from the footageanalyzer project; SurveillanceHound owns
this parser now. No scapy, no dpkt — the daemon depends only on the Python
standard library so it deploys cleanly on an NVR / firewall / switch host
where bringing in a heavy capture library is friction.

Supported:
  * classic pcap — little- and big-endian, microsecond and nanosecond stamps
  * pcapng — Section Header + Interface Description + Enhanced/Simple Packet
    blocks (the blocks tcpdump / Wireshark actually emit)
  * link types: Ethernet (with one level of 802.1Q VLAN), raw IPv4/IPv6,
    BSD/null loopback, Linux SLL ("any" interface)
  * IPv4 and IPv6, TCP and UDP (other IP protocols are reported as "other")

The two entry points are file-based (`read_packets(path)`) and stream-based
(`read_packets_from_stream(fh)`). The stream form is what the live-capture
wrapper feeds with tcpdump's stdout — tcpdump emits classic pcap, so the same
parser handles offline replay and live monitoring.

Not supported (a packet hitting one of these is skipped, counted, and the
count surfaced — never silently dropped): IPv6 extension-header chains beyond
the first next-header, SLL2, exotic link types, truncated records.
"""

from __future__ import annotations

import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# Link-layer types (pcap LINKTYPE_*).
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

_IPPROTO = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}
_TCP_FLAG_BITS = [
    (0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
    (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C"),
]


@dataclass(frozen=True)
class Packet:
    """One parsed packet — just the fields flow analysis needs."""

    ts: float  # epoch seconds (float)
    src_ip: str
    dst_ip: str
    proto: str  # tcp | udp | icmp | icmpv6 | other
    src_port: int | None
    dst_port: int | None
    length: int  # original on-wire length in bytes
    tcp_flags: str  # e.g. "S", "SA", "" — empty for non-TCP


@dataclass
class CaptureStats:
    """Counters the reader fills in as it goes — surfaced so nothing is hidden."""

    file_format: str = ""  # "pcap" | "pcapng"
    packets_total: int = 0
    packets_parsed: int = 0
    packets_skipped: int = 0
    link_types: set[int] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.link_types is None:
            self.link_types = set()


class PcapError(Exception):
    """The input is not a capture we can read."""


# --- public entry points -----------------------------------------------------


def read_packets(path: Path) -> tuple[Iterator[Packet], CaptureStats]:
    """Open a capture FILE and return (packet generator, stats)."""
    fh = path.open("rb")
    return _read_from(fh, stream=False)


def read_packets_from_stream(
    fh: BinaryIO,
) -> tuple[Iterator[Packet], CaptureStats]:
    """Read packets from a binary STREAM (e.g. tcpdump stdout).

    The stream must begin at the pcap / pcapng global header. The generator
    runs as long as the stream yields bytes — perfect for a live capture
    pipeline. The stream is NOT closed by the generator; the caller owns it.
    """
    return _read_from(fh, stream=True)


def _read_from(fh: BinaryIO, *, stream: bool) -> tuple[Iterator[Packet], CaptureStats]:
    magic = fh.read(4)
    stats = CaptureStats()
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                 b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        stats.file_format = "pcap"
        return _iter_pcap_after_magic(fh, magic, stats, close_fh=not stream), stats
    if magic == b"\x0a\x0d\x0d\x0a":
        stats.file_format = "pcapng"
        return _iter_pcapng_after_magic(fh, stats, close_fh=not stream), stats
    if not stream:
        fh.close()
    raise PcapError(
        f"not a pcap or pcapng input (leading bytes {magic!r}) — only classic "
        "pcap and pcapng are supported"
    )


# --- classic pcap ------------------------------------------------------------


def _iter_pcap_after_magic(
    fh: BinaryIO, magic: bytes, stats: CaptureStats, *, close_fh: bool
) -> Iterator[Packet]:
    try:
        rest = fh.read(20)
        if len(rest) < 20:
            raise PcapError("truncated pcap global header")
        endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        linktype = struct.unpack(endian + "I", rest[16:20])[0]
        stats.link_types.add(linktype)
        ts_div = 1e9 if nano else 1e6

        rec_hdr = struct.Struct(endian + "IIII")
        while True:
            raw = _read_exact(fh, 16)
            if not raw:
                break
            ts_sec, ts_frac, incl_len, _orig = rec_hdr.unpack(raw)
            data = _read_exact(fh, incl_len)
            if data is None:
                stats.packets_skipped += 1
                stats.packets_total += 1
                break
            stats.packets_total += 1
            ts = ts_sec + ts_frac / ts_div
            pkt = _parse_link(linktype, data, ts)
            if pkt is None:
                stats.packets_skipped += 1
            else:
                stats.packets_parsed += 1
                yield pkt
    finally:
        if close_fh:
            fh.close()


# --- pcapng ------------------------------------------------------------------


def _iter_pcapng_after_magic(
    fh: BinaryIO, stats: CaptureStats, *, close_fh: bool
) -> Iterator[Packet]:
    try:
        interfaces: list[tuple[int, float]] = []
        endian = "<"  # refined by the Section Header Block's byte-order magic
        # we already consumed the 4-byte block_type of the SHB; read the rest:
        rest = _read_exact(fh, 4)
        if rest is None:
            return
        block_len = struct.unpack("<I", rest)[0]
        if not (12 <= block_len <= 64 * 1024 * 1024):
            return
        body = _read_exact(fh, block_len - 12) or b""
        _read_exact(fh, 4)  # trailing block_total_length
        bom = body[:4]
        endian = "<" if bom == b"\x1a\x2b\x3c\x4d" else ">"

        while True:
            head = _read_exact(fh, 8)
            if head is None:
                break
            block_type = struct.unpack(endian + "I", head[:4])[0]
            block_len = struct.unpack(endian + "I", head[4:8])[0]
            if not (12 <= block_len <= 64 * 1024 * 1024):
                break
            body = _read_exact(fh, block_len - 12)
            if body is None:
                break
            _read_exact(fh, 4)  # trailing block_total_length

            if block_type == 0x00000001:  # IDB
                linktype = struct.unpack(endian + "H", body[:2])[0]
                stats.link_types.add(linktype)
                ts_div = _pcapng_tsresol(body[8:], endian)
                interfaces.append((linktype, ts_div))
            elif block_type == 0x00000006:  # EPB
                stats.packets_total += 1
                pkt = _pcapng_epb(body, endian, interfaces)
                if pkt is None:
                    stats.packets_skipped += 1
                else:
                    stats.packets_parsed += 1
                    yield pkt
            elif block_type == 0x00000003:  # SPB
                stats.packets_total += 1
                pkt = _pcapng_spb(body, endian, interfaces)
                if pkt is None:
                    stats.packets_skipped += 1
                else:
                    stats.packets_parsed += 1
                    yield pkt
            elif block_type == 0x0A0D0D0A:  # new SHB
                bom = body[:4]
                endian = "<" if bom == b"\x1a\x2b\x3c\x4d" else ">"
                interfaces = []
    finally:
        if close_fh:
            fh.close()


def _pcapng_tsresol(options: bytes, endian: str) -> float:
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[pos : pos + 4])
        pos += 4
        val = options[pos : pos + length]
        pos += length + ((4 - length % 4) % 4)
        if code == 0:
            break
        if code == 9 and val:
            raw = val[0]
            if raw & 0x80:
                return float(2 ** (raw & 0x7F))
            return float(10 ** raw)
    return 1e6


def _pcapng_epb(body: bytes, endian: str, interfaces) -> Packet | None:
    if len(body) < 20:
        return None
    iface_id, ts_hi, ts_lo, cap_len, _orig = struct.unpack(
        endian + "IIIII", body[:20]
    )
    data = body[20 : 20 + cap_len]
    if len(data) < cap_len or iface_id >= len(interfaces):
        return None
    linktype, ts_div = interfaces[iface_id]
    ts = ((ts_hi << 32) | ts_lo) / ts_div
    return _parse_link(linktype, data, ts)


def _pcapng_spb(body: bytes, endian: str, interfaces) -> Packet | None:
    if len(body) < 4 or len(interfaces) != 1:
        return None
    linktype, _ = interfaces[0]
    return _parse_link(linktype, body[4:], 0.0)


# --- link / network / transport parsing -------------------------------------


def _parse_link(linktype: int, data: bytes, ts: float) -> Packet | None:
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype = struct.unpack(">H", data[12:14])[0]
        off = 14
        if ethertype == 0x8100:  # one level of 802.1Q VLAN
            if len(data) < 18:
                return None
            ethertype = struct.unpack(">H", data[16:18])[0]
            off = 18
        if ethertype == 0x0800:
            return _parse_ipv4(data[off:], ts)
        if ethertype == 0x86DD:
            return _parse_ipv6(data[off:], ts)
        return None
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return _parse_ip_autodetect(data, ts)
    if linktype == LINKTYPE_NULL:
        if len(data) < 4:
            return None
        fam = struct.unpack("<I", data[:4])[0]
        if fam in (24, 28, 30):
            return _parse_ipv6(data[4:], ts)
        return _parse_ipv4(data[4:], ts)
    if linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        ethertype = struct.unpack(">H", data[14:16])[0]
        if ethertype == 0x0800:
            return _parse_ipv4(data[16:], ts)
        if ethertype == 0x86DD:
            return _parse_ipv6(data[16:], ts)
        return None
    return None


def _parse_ip_autodetect(data: bytes, ts: float) -> Packet | None:
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        return _parse_ipv4(data, ts)
    if version == 6:
        return _parse_ipv6(data, ts)
    return None


def _parse_ipv4(data: bytes, ts: float) -> Packet | None:
    if len(data) < 20:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack(">H", data[2:4])[0]
    proto_num = data[9]
    src = socket.inet_ntop(socket.AF_INET, data[12:16])
    dst = socket.inet_ntop(socket.AF_INET, data[16:20])
    return _with_transport(ts, src, dst, proto_num, data[ihl:], total_len or len(data))


def _parse_ipv6(data: bytes, ts: float) -> Packet | None:
    if len(data) < 40:
        return None
    payload_len = struct.unpack(">H", data[4:6])[0]
    next_header = data[6]
    src = socket.inet_ntop(socket.AF_INET6, data[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
    return _with_transport(ts, src, dst, next_header, data[40:], 40 + payload_len)


def _with_transport(
    ts: float, src: str, dst: str, proto_num: int, payload: bytes, length: int
) -> Packet:
    proto = _IPPROTO.get(proto_num, "other")
    src_port = dst_port = None
    tcp_flags = ""
    if proto == "tcp" and len(payload) >= 14:
        src_port, dst_port = struct.unpack(">HH", payload[:4])
        flag_byte = payload[13]
        tcp_flags = "".join(ch for bit, ch in _TCP_FLAG_BITS if flag_byte & bit)
    elif proto == "udp" and len(payload) >= 4:
        src_port, dst_port = struct.unpack(">HH", payload[:4])
    return Packet(
        ts=ts, src_ip=src, dst_ip=dst, proto=proto,
        src_port=src_port, dst_port=dst_port, length=length, tcp_flags=tcp_flags,
    )


def _read_exact(fh: BinaryIO, n: int) -> bytes | None:
    """Read exactly `n` bytes, blocking as needed. Returns None on clean EOF."""
    if n <= 0:
        return b""
    buf = bytearray()
    while len(buf) < n:
        chunk = fh.read(n - len(buf))
        if not chunk:
            return None if not buf else None  # short read = treat as EOF
        buf.extend(chunk)
    return bytes(buf)
