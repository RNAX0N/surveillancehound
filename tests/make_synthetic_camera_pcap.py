"""Generate a synthetic classic-pcap capture for end-to-end Hound testing.

Camera IP is 192.168.1.50. Four conversations with a known-answer classification:

  base+0s    192.168.1.50 <-> 192.168.1.1   small      -> lan_normal
  base+10s   192.168.1.50 <-> 203.0.113.10:443  small  -> telemetry_offnet
  base+30s   198.51.100.5:80 -> 192.168.1.50  ~1.3 MiB -> bulk_inbound
  base+50s   192.168.1.50 <-> 192.0.2.7:4444  210 s    -> control_channel_suspect

The IPv4 total-length field drives Hound's per-packet byte count, so the bulk
transfer is simulated with a handful of large-total-length packets rather than
by writing megabytes of pcap.
"""

from __future__ import annotations

import argparse
import struct
from datetime import datetime, timezone
from pathlib import Path

BASE_TS = datetime(2026, 5, 12, 14, 0, 0, tzinfo=timezone.utc).timestamp()
CAMERA_IP = "192.168.1.50"


def _ip_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def _eth() -> bytes:
    return b"\xaa\xbb\xcc\xdd\xee\x01" + b"\xaa\xbb\xcc\xdd\xee\x02" + b"\x08\x00"


def _ipv4(src: str, dst: str, proto: int, total_len: int) -> bytes:
    return struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0x00, total_len & 0xFFFF, 0x0000, 0x4000, 64, proto, 0x0000,
        _ip_bytes(src), _ip_bytes(dst),
    )


def _tcp(sport: int, dport: int, flags: int) -> bytes:
    return struct.pack(
        ">HHIIBBHHH", sport, dport, 1, 1, 0x50, flags, 0xFFFF, 0x0000, 0x0000
    )


def _record(ts: float, payload: bytes) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, len(payload), len(payload)) + payload


def _tcp_packet(ts, src, dst, sport, dport, total_len, flags=0x10):
    body = _eth() + _ipv4(src, dst, 6, total_len) + _tcp(sport, dport, flags)
    return _record(ts, body)


def build() -> bytes:
    out = bytearray()
    # classic pcap global header: LE, microsecond, Ethernet
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # 1) LAN conversation
    for i in range(4):
        ts = BASE_TS + i * 0.5
        out += _tcp_packet(ts, CAMERA_IP, "192.168.1.1", 50000, 80, 120)
        out += _tcp_packet(ts + 0.1, "192.168.1.1", CAMERA_IP, 80, 50000, 200)

    # 2) telemetry to an off-network public host (small volume)
    for i in range(6):
        ts = BASE_TS + 10 + i * 0.3
        out += _tcp_packet(ts, CAMERA_IP, "203.0.113.10", 51000, 443, 180)
        out += _tcp_packet(ts + 0.05, "203.0.113.10", CAMERA_IP, 443, 51000, 160)

    # 3) bulk transfer TOWARD the camera (~1.3 MiB) from a public host
    for i in range(22):
        ts = BASE_TS + 30 + i * 0.2
        out += _tcp_packet(ts, "198.51.100.5", CAMERA_IP, 80, 52000, 64000)

    # 4) long-lived control channel to a public host on an odd port
    for i in range(200):
        ts = BASE_TS + 50 + i * 1.05  # spans ~210 s
        out += _tcp_packet(ts, CAMERA_IP, "192.0.2.7", 53000, 4444, 96)

    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/hound-synthetic.pcap")
    args = ap.parse_args()
    Path(args.out).write_bytes(build())
    print(f"wrote synthetic pcap: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
