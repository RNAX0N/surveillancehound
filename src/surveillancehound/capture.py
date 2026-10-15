"""Packet capture — live (tcpdump subprocess) or replay (a pcap file).

Live capture launches tcpdump as a subprocess with `-w -` (write pcap to
stdout), `-U` (packet-buffered — flush every packet, the line tcpdump's docs
prescribe for live pipelines), and a snaplen + optional BPF filter. The
pcap.read_packets_from_stream parser reads its stdout. Restart-on-failure is
handled by the caller (daemon.py); this module just produces the stream.

Why tcpdump-as-subprocess instead of a libpcap binding: it ships on every
Linux distro and every BSD, it is the most-audited capture tool in existence,
it does not require pulling a C library into the Python process, and it
honors AF_PACKET / BPF without our code needing CAP_NET_RAW directly (tcpdump
does, and drops privileges with `-Z` if asked — out of scope for v1).

Replay (`pcap_file`) reads a saved capture file. Useful for: testing the
classifier against a known-answer capture; running the daemon offline against
a stored capture for forensic analysis without touching the wire.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from surveillancehound.config import CaptureCfg
from surveillancehound.pcap import (
    CaptureStats,
    Packet,
    PcapError,
    read_packets,
    read_packets_from_stream,
)

log = logging.getLogger(__name__)


class CaptureError(RuntimeError):
    """A live capture subprocess could not start, or died."""


def compose_bpf(user_bpf: str, exclude: str) -> str:
    """Combine the operator's filter with a mandatory exclusion.

    Both are ANDed and each is parenthesised: `a or b` as the user filter
    would otherwise bind loosely and swallow the exclusion entirely.
    """
    user_bpf, exclude = (user_bpf or "").strip(), (exclude or "").strip()
    if not exclude:
        return user_bpf
    if not user_bpf:
        return exclude
    return f"({user_bpf}) and ({exclude})"


def stream_packets(
    cfg: CaptureCfg, *, keep_raw: bool = False, snaplen_override: int | None = None,
    exclude_bpf: str = "",
) -> tuple[Iterator[Packet], CaptureStats, "CaptureHandle"]:
    """Open a packet source (live or file) and yield Packets.

    Returns (generator, stats, handle). `handle.close()` releases the
    subprocess / file. Stats fill in as the generator is consumed.

    `keep_raw=True` makes the parser preserve the original classic-pcap
    record bytes on each Packet (used by the snapshot ring buffer).
    `snaplen_override` bumps the capture snaplen — typically the snapshot
    feature wants 1500 instead of the 96 bytes flow analysis needs.
    """
    if cfg.pcap_file:
        path = Path(cfg.pcap_file)
        if not path.is_file():
            raise CaptureError(f"pcap_file not found: {path}")
        gen, stats = read_packets(path, keep_raw=keep_raw)
        return gen, stats, _FileHandle()

    if not cfg.interface:
        raise CaptureError("config: no interface and no pcap_file")
    if shutil.which("tcpdump") is None:
        raise CaptureError(
            "live capture requires `tcpdump` on PATH (apt install tcpdump / "
            "the BSD ships it)."
        )

    effective_snaplen = max(64, snaplen_override or cfg.snaplen)
    argv = [
        "tcpdump",
        "-i", cfg.interface,
        "-U",                                  # packet-buffered output
        "-s", str(effective_snaplen),          # snaplen
        "-n",                                  # no DNS
        "-w", "-",                             # pcap to stdout
    ]
    bpf = compose_bpf(cfg.bpf, exclude_bpf)
    if bpf:
        argv.append(bpf)
    log.info("starting live capture: %s", " ".join(argv))
    proc = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
        start_new_session=True,
    )
    if proc.stdout is None:
        proc.kill()
        raise CaptureError("tcpdump subprocess produced no stdout")
    try:
        gen, stats = read_packets_from_stream(proc.stdout, keep_raw=keep_raw)
    except PcapError as e:
        err = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
        proc.kill()
        proc.wait()
        raise CaptureError(
            f"tcpdump did not produce a valid pcap stream: {e}\nstderr:\n{err}"
        ) from e
    # Validation passed — now drain stderr on a daemon thread. A full PIPE
    # buffer (~64KB) would block tcpdump's next stderr write and stall the
    # whole daemon. Forwarding to the log keeps diagnostics visible.
    if proc.stderr is not None:
        threading.Thread(
            target=_forward_stderr, args=(proc.stderr,),
            name="tcpdump-stderr", daemon=True,
        ).start()
    return gen, stats, _ProcHandle(proc)


def _forward_stderr(stream: BinaryIO) -> None:
    try:
        for raw in iter(stream.readline, b""):
            line = raw.decode(errors="replace").rstrip()
            if line:
                log.info("tcpdump: %s", line)
    except (OSError, ValueError):
        return  # pipe closed under us — the subprocess is going away


# --- handles -----------------------------------------------------------------


class CaptureHandle:
    """Lets the daemon close (or terminate) the underlying source."""

    def close(self) -> None:
        raise NotImplementedError

    def is_alive(self) -> bool:
        return False  # files are always 'done' once iterated


class _FileHandle(CaptureHandle):
    def close(self) -> None:  # the generator closes its own file handle
        pass

    def is_alive(self) -> bool:
        return False


class _ProcHandle(CaptureHandle):
    def __init__(self, proc: subprocess.Popen) -> None:
        self.proc = proc

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def is_alive(self) -> bool:
        return self.proc.poll() is None
