#!/usr/bin/env python3
"""Verify gsfw-observe's P1 verdict logic against synthetic windows.

`deploy/nvr/gsfw-observe` decides whether the NVR firewall lockdown (P2
and P3) is safe to enforce. Getting that wrong in the permissive
direction takes the cameras off the network; getting it wrong in the
strict direction stalls the hardening on a camera that was fine. Neither
can be checked by running it on the live NVR, because the live NVR has
exactly one window's worth of data and no failures in it.

So the checks below construct windows with known answers. The sampler is
never run; samples are built directly, which is also what lets a 24-hour
window be tested in milliseconds.

Run: python3 tests/verify_observe.py
"""
from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import sys
import tempfile
import time
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "deploy" / "nvr" / "gsfw-observe"


def load_tool():
    """Import the tool, which has no .py suffix because it is installed
    as a command. Nothing here executes `main`; the dispatch is guarded
    by `if __name__ == "__main__"`."""
    spec = importlib.util.spec_from_loader(
        "gsfw_observe",
        importlib.machinery.SourceFileLoader("gsfw_observe", str(TOOL)))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


G = load_tool()

FAILURES: list[str] = []
CHECKS = 0

T0 = 1_760_000_000.0          # a fixed epoch; never time.time()
STEP = 900.0                  # the 15-minute sampler cadence
DAY = 96                      # samples in 24h at that cadence


def check(label: str, cond: bool, detail: str = "") -> None:
    global CHECKS
    CHECKS += 1
    if cond:
        print(f"  ok   {label}")
    else:
        print(f"  FAIL {label}" + (f" — {detail}" if detail else ""))
        FAILURES.append(label)


# --------------------------------------------------------------------
# window construction
# --------------------------------------------------------------------
def build(n_samples: int, series: dict[str, list[int]]) -> list[dict]:
    """A sample list from per-counter cumulative value series."""
    out = []
    for i in range(n_samples):
        counters = {}
        for name, vals in series.items():
            v = vals[i] if i < len(vals) else vals[-1]
            if v is None:          # counter absent from this sample
                continue
            counters[name] = {"packets": v, "bytes": v * 90, "comment": ""}
        out.append({"ts": T0 + i * STEP, "counters": counters})
    return out


def steady(n: int, per: int = 1, start: int = 0) -> list[int]:
    """A counter that advances every single sample."""
    return [start + i * per for i in range(n)]


def backed_off(n: int, every: int) -> list[int]:
    """BusyBox ntpd at MAXPOLL: one poll every `every` samples."""
    return [i // every for i in range(n)]


def flatline(n: int, at: int, value: int) -> list[int]:
    """Advances, then stops dead at sample `at`."""
    return [min(i, at) * 1 + value for i in range(n)]


# --------------------------------------------------------------------
# 1. silence_spans — the measurement everything else rests on
# --------------------------------------------------------------------
print("\nsilence_spans")

s = build(10, {"in_ntp_101": steady(10)})
spans, resets, unknown = G.silence_spans(s, "in_ntp_101")
check("a counter advancing every sample has no silence", spans == [])
check("...and no resets or unknowns", (resets, unknown) == (0, 0))

# Held for samples 3..6 inclusive, i.e. intervals (3,4),(4,5),(5,6).
vals = [0, 1, 2, 3, 3, 3, 3, 4, 5, 6]
spans, _, _ = G.silence_spans(build(10, {"c": vals}), "c")
gap, worst = G.longest_span(spans)
check("a held run is measured from the last move to the next",
      gap == 3 * STEP, f"got {gap}")
check("...and bounded by the right sample times",
      worst == (T0 + 3 * STEP, T0 + 6 * STEP), f"got {worst}")

# Three runs of 1, 4 and 1 intervals: the longest wins. Note the run
# spans the INTERVALS between equal readings, so five equal samples are
# four intervals of proven silence — never five.
vals = [0, 0, 1, 1, 1, 1, 1, 2, 2, 3]
spans, _, _ = G.silence_spans(build(10, {"c": vals}), "c")
gap, _ = G.longest_span(spans)
check("the longest of several runs is reported", gap == 4 * STEP, f"got {gap}")
check("...and the shorter runs are kept too", len(spans) == 3, str(spans))

# A reset must not be read as a continuing silence, and must not be
# read as activity either.
vals = [10, 10, 10, 0, 0, 0, 1, 2, 3, 4]
spans, resets, _ = G.silence_spans(build(10, {"c": vals}), "c")
gap, _ = G.longest_span(spans)
check("a counter reset is counted", resets == 1, f"got {resets}")
check("a reset splits the silence rather than spanning it",
      gap == 2 * STEP, f"got {gap}")

# A counter that only appears partway through.
vals = [None, None, 0, 0, 0, 1, 2, 3, 4, 5]
spans, _, unknown = G.silence_spans(build(10, {"c": vals}), "c")
check("intervals with no reading are counted, not assumed quiet",
      unknown == 2, f"got {unknown}")

check("resolution is the widest sample gap",
      G.sample_resolution(build(5, {"c": steady(5)})) == STEP)


# --------------------------------------------------------------------
# 2. the backoff case — the regression this change exists for
# --------------------------------------------------------------------
print("\nBusyBox backoff vs. a dead camera")


def judge(vals: list[int], events=None, egress=None, name="in_ntp_106"):
    s = build(len(vals), {name: vals})
    blockers: list[str] = []
    confirm: list[str] = []
    tot = next((v for v in reversed(vals) if v is not None), 0)
    cell, detail = G.judge_ntp(name, G.camera_of(name), tot, s,
                               events or [], egress or {},
                               blockers, confirm)
    return cell, blockers, confirm, detail


# One poll per ~64 min: 4 samples + a bit. Healthy on our firmware.
cell, blockers, confirm, _ = judge(backed_off(DAY, 4))
check("a camera at MAXPOLL passes", cell == "in use", cell)
check("...with no blocker", not blockers, str(blockers))
check("...and nothing to confirm", not confirm, str(confirm))

# A vendor camera polling every 23s advances every sample.
cell, blockers, _, _ = judge(steady(DAY, per=39))
check("a vendor camera at 23s intervals passes", cell == "in use", cell)
check("...with no blocker", not blockers)

# The case the OLD logic got wrong: one poll, then nothing for 24h.
# Total is non-zero, so a count test calls it healthy.
vals = [0] + [1] * (DAY - 1)
cell, blockers, confirm, _ = judge(vals)
check("one poll then silence is a blocker, not 'in use'",
      "UNEXPECTED" in cell, cell)
check("...and says the camera stopped asking",
      any("stopped asking" in b for b in blockers), str(blockers))

# Dead from the start.
cell, blockers, _, _ = judge([0] * DAY)
check("a wholly silent camera is a blocker", "silent" in cell, cell)
check("...and rules out backoff explicitly",
      any("backoff" in b for b in blockers), str(blockers))

# Zero is judged on the same clock as a gap. Forty-six minutes of zero
# is not evidence of anything — a backed-off camera would not have
# spoken yet — and blocking on it is the easier mistake to make,
# because zero looks damning.
cell, blockers, confirm, _ = judge([0] * 4)       # 45 min of samples
check("a short run of zeros is not a finding", not blockers, str(blockers))
check("...and says so rather than passing it", cell == "no verdict yet", cell)
check("...naming the backoff it cannot yet rule out",
      any("backoff" in c for c in confirm), str(confirm))

# A counter added partway through has been watched for less time than
# the window has run, and must not borrow the window's evidence.
late = [None] * (DAY - 3) + [0, 0, 0]
cell, blockers, confirm, detail = judge(late)
check("a counter added late does not block on the window's length",
      not blockers, str(blockers))
check("...and reports what it was actually watched for",
      "**30 min** watched" in detail, detail)

# Just past MAXPOLL but under 2h: ask, do not block.
vals = backed_off(DAY, 4)
for i in range(20, 25):            # freeze 5 samples = 75 min
    vals[i] = vals[20]
for i in range(25, DAY):
    vals[i] = vals[i] - 1
cell, blockers, confirm, _ = judge(vals)
check("a 70–120 min gap warns rather than blocks", not blockers, str(blockers))
check("...and asks for a glance", len(confirm) == 1, str(confirm))
check("...and shows the gap in the table cell", "min gap" in cell, cell)


# --------------------------------------------------------------------
# 3. maintenance events
# --------------------------------------------------------------------
print("\nmaintenance events")

# A 3h hole in the middle of the window.
vals = backed_off(DAY, 4)
hole_from, hole_to = 40, 52
for i in range(hole_from, hole_to):
    vals[i] = vals[hole_from]
for i in range(hole_to, DAY):
    vals[i] = vals[i] - (vals[hole_to] - vals[hole_from])

cell, blockers, confirm, _ = judge(vals)
check("an unexplained 3h hole blocks", bool(blockers), cell)

during = [{"ts": T0 + (hole_from + 1) * STEP, "text": "C6 down for reflash"}]
cell, blockers, confirm, _ = judge(vals, events=during)
check("an event inside the hole downgrades it to confirm", not blockers)
check("...and quotes it back", any("reflash" in c for c in confirm))

# The one that matters: an event with the right name at the WRONG time
# must not excuse the hole. Every camera gets touched during a firmware
# campaign, so name-only matching eventually excuses everything.
elsewhere = [{"ts": T0 + 2 * STEP, "text": "C6 down for reflash"}]
cell, blockers, confirm, _ = judge(vals, events=elsewhere)
check("an event far from the hole does NOT excuse it", bool(blockers),
      f"cell={cell} confirm={confirm}")

just_before = [{"ts": T0 + hole_from * STEP - 600, "text": "taking cam 6 down"}]
_, blockers, confirm, _ = judge(vals, events=just_before)
check("an event just before the hole does excuse it", not blockers)

other_cam = [{"ts": T0 + (hole_from + 1) * STEP, "text": "C7 down for reflash"}]
_, blockers, _, _ = judge(vals, events=other_cam)
check("another camera's event does not excuse this one", bool(blockers))

check("loose name matching finds a bare VLAN number",
      len(G.events_mentioning([{"ts": T0, "text": "117.111.106.2 rebooted"}],
                              "106")) == 1)
check("loose name matching finds 'camera 6'",
      len(G.events_mentioning([{"ts": T0, "text": "Camera 6 back up"}],
                              "106")) == 1)


# --------------------------------------------------------------------
# 4. known-absent cameras, and the egress correlation
# --------------------------------------------------------------------
print("\nknown-absent, and off-segment time sync")

cell, blockers, confirm, _ = judge([0] * DAY, name="in_ntp_112")
check("a known-absent camera does not block", not blockers, str(blockers))
check("...but still asks for confirmation", len(confirm) == 1, str(confirm))
check("...and gives the reason on record",
      any("not deployed" in c for c in confirm))

cell, blockers, _, _ = judge([0] * DAY, egress={"106": 412})
check("a silent camera that IS leaving the segment still blocks",
      bool(blockers))
check("...and names P2 as what would cut it",
      any("off-segment" in b and "P2" in b for b in blockers), str(blockers))


# --------------------------------------------------------------------
# 5. end to end: the three exit codes
# --------------------------------------------------------------------
print("\nwhole-summary outcomes")


def run_summary(series: dict[str, list[int]], events: list[dict],
                n: int = DAY) -> tuple[int, str]:
    """cmd_summary against temp files, with the clock and the journal
    stubbed. Patched at module scope and restored, so one case cannot
    leak into the next."""
    d = tempfile.mkdtemp(prefix="gsfw-observe-test.")
    samples_p = os.path.join(d, "samples.jsonl")
    events_p = os.path.join(d, "events.jsonl")
    import json
    with open(samples_p, "w") as fh:
        for row in build(n, series):
            fh.write(json.dumps(row) + "\n")
    with open(events_p, "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")

    old = (G.SAMPLES, G.EVENTS, G.journal_lines, G._JOURNAL)
    G.SAMPLES, G.EVENTS = samples_p, events_p
    G.journal_lines = lambda: []
    G._JOURNAL = []
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = G.cmd_summary()
        return rc, buf.getvalue()
    finally:
        G.SAMPLES, G.EVENTS, G.journal_lines, G._JOURNAL = old


healthy = {f"in_ntp_{c}": backed_off(DAY, 4) for c in range(101, 112)}
healthy["in_ntp_112"] = [0] * DAY          # known absent
healthy["fwd_cam_egress"] = steady(DAY, per=7)
healthy["fwd_other"] = [0] * DAY

rc, out = run_summary(healthy, [])
check("a clean window with only a known-absent camera is HOLD",
      rc == 2, f"rc={rc}")
check("...and the known absence is the thing to confirm",
      "not deployed" in out)

# Drop the known-absent camera entirely: that is a GO.
clean = {k: v for k, v in healthy.items() if k != "in_ntp_112"}
rc, out = run_summary(clean, [])
check("an otherwise clean window is GO", rc == 0, f"rc={rc}\n{out[-700:]}")
check("...and still reports the expected-block finding",
      "fwd_cam_egress" in out)
check("...and prints the continuity detail", "proven silence" in out)

# One camera stops dead halfway, nobody logged anything.
broken = dict(clean)
stop = DAY // 2
v = backed_off(DAY, 4)
broken["in_ntp_103"] = [min(x, v[stop]) for x in v]
rc, out = run_summary(broken, [])
check("a camera that stops dead is NO-GO", rc == 1, f"rc={rc}")
check("...named in the blockers", "in_ntp_103" in out)

# Same window, with the maintenance logged.
rc, out = run_summary(
    broken, [{"ts": T0 + stop * STEP, "text": "C3 down, MAC change"}])
check("the same window with the event logged is HOLD", rc == 2, f"rc={rc}")
check("...and quotes the event", "MAC change" in out)

# An unexpected class is still a hard NO-GO.
surprise = dict(clean)
surprise["in_cam_other"] = steady(DAY, per=3)
rc, out = run_summary(surprise, [])
check("an unpredicted class is NO-GO", rc == 1, f"rc={rc}")

# A short window cannot pass, however clean.
rc, out = run_summary({k: v[:8] for k, v in clean.items()}, [], n=8)
check("a 2h window is NO-GO on length", rc == 1, f"rc={rc}")
check("...and says so", "too short" in out)

rc, out = run_summary({}, [], n=0)
check("no samples at all is NO-GO", rc == 1, f"rc={rc}")
check("...and refuses to read silence as a pass", "nothing was watched" in out)


# --------------------------------------------------------------------
print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
if FAILURES:
    print("\nFAILED:")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print("gsfw-observe verdict logic OK")
