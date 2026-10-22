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


def judge(vals: list[int], events=None, egress=None, name="in_ntp_106",
          chrony: list[dict] | None = None):
    s = build(len(vals), {name: vals})
    if chrony is not None:
        cam = G.camera_of(name)
        for row, c in zip(s, chrony):
            row["chrony"] = {cam: c} if c else {}
    blockers: list[str] = []
    confirm: list[str] = []
    tot = next((v for v in reversed(vals) if v is not None), 0)
    cell, detail = G.judge_ntp(name, G.camera_of(name), tot, s,
                               events or [], egress or {},
                               blockers, confirm)
    # Blockers carry the counter they belong to, so a waiver can be
    # matched to one. The checks below read the message text.
    for b in blockers:
        assert isinstance(b, tuple) and b[0] == name, b
    return cell, [b[1] for b in blockers], confirm, detail


def chrony_series(n: int, ntp_start: int, ntp_end: int,
                  drop: int = 0, last_s: float = 120.0) -> list[dict]:
    """A chrony reading per sample, counts rising linearly."""
    out = []
    for i in range(n):
        frac = i / max(1, n - 1)
        out.append({"ntp": int(ntp_start + (ntp_end - ntp_start) * frac),
                    "drop": drop if i else 0,
                    "interval": "12", "last_s": last_s})
    return out


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
# 4b. chrony as the independent witness
# --------------------------------------------------------------------
print("\nchrony cross-check")

# The counter says nothing; chrony says it served 21 requests. The
# camera is fine and the COUNTER RULE is wrong — a tool reading only
# its own counters cannot reach that conclusion about itself.
cell, blockers, _, _ = judge([0] * DAY, chrony=chrony_series(DAY, 100, 121))
check("counter silent but chrony served it blocks on the RULE",
      "RULE WRONG" in cell, cell)
check("...and says the window's other readings are suspect too",
      any("every other silent reading" in b for b in blockers), str(blockers))

# chrony refusing is the opposite fault with the opposite fix.
cell, blockers, _, _ = judge(backed_off(DAY, 4),
                             chrony=chrony_series(DAY, 100, 121, drop=9))
check("chrony dropping requests blocks, even with the counter healthy",
      "refusing" in cell, cell)
check("...and says it is not a firewall problem",
      any("not a firewall problem" in b for b in blockers), str(blockers))

# Both agree the camera is silent: a stronger statement than either.
cell, blockers, _, _ = judge([0] * DAY, chrony=chrony_series(DAY, 100, 100))
check("both silent blocks on the camera", "UNEXPECTED — silent" in cell, cell)
check("...and says so is corroborated",
      any("chrony independently served it nothing" in b for b in blockers),
      str(blockers))

# No chrony data at all: the verdict must say what it is resting on.
cell, blockers, _, _ = judge([0] * DAY)
check("with no chrony data the blocker admits it stands alone",
      any("rests on the counter alone" in b for b in blockers), str(blockers))

# chronyd restarting resets its tallies; a negative delta must not be
# read as a count, in either direction.
restart = chrony_series(DAY, 500, 520)
for i in range(DAY // 2, DAY):
    restart[i] = dict(restart[i], ntp=restart[i]["ntp"] - 500)
cell, blockers, _, detail = judge([0] * DAY, chrony=restart)
check("a chronyd restart is not read as a request count",
      "RULE WRONG" not in cell, cell)
check("...and is called out in the detail",
      "restarted" in detail, detail)
check("...leaving the corroboration unclaimed",
      not any("independently served it nothing" in b for b in blockers))

# Parsed against REAL `chronyc -n clients` output from the NVR, because
# a column index guessed from the man page is the kind of thing that
# reads plausibly and is silently off by one.
REAL_CHRONYC = """Hostname                      NTP   Drop Int IntL Last     Cmd   Drop Int  Last
===============================================================================
117.111.108.2                 753      0   6   -    57       0      0   -     -
117.111.106.2                  23      0  12   -   65m       0      0   -     -
172.19.0.2                      4      0   6   -    12       0      0   -     -
"""


class _FakeRun:
    def __init__(self, text, rc=0):
        self.stdout, self.returncode, self.stderr = text, rc, ""


_real_run = G.subprocess.run
G.subprocess.run = lambda *a, **k: _FakeRun(REAL_CHRONYC)
parsed = G.read_chrony()
G.subprocess.run = lambda *a, **k: _FakeRun("", rc=1)
absent = G.read_chrony()
G.subprocess.run = _real_run

check("real chronyc output parses", set(parsed) == {"108", "106"}, str(parsed))
check("...request counts land in the right column",
      parsed["108"]["ntp"] == 753 and parsed["106"]["ntp"] == 23, str(parsed))
check("...drops land in the right column",
      parsed["106"]["drop"] == 0 and parsed["106"]["interval"] == "12")
check("...and the age is converted", parsed["106"]["last_s"] == 3900)
check("non-camera clients are ignored", "19" not in parsed)
check("chrony being unavailable is empty, not an error", absent == {})

# A chrony delta covering one minute cannot speak for a day of silence.
# The cross-check was installed mid-window, so this is the live case,
# not a hypothetical.
short = [None] * (DAY - 3) + [{"ntp": 500, "drop": 0, "interval": "12",
                               "last_s": 60.0}] * 3
cell, blockers, _, detail = judge([0] * DAY, chrony=short)
check("a chrony delta shorter than the silence does not corroborate",
      not any("independently served it nothing" in b for b in blockers),
      str(blockers))
check("...and says how little it watched",
      any("cannot corroborate this yet" in b for b in blockers), str(blockers))
check("...and shows the span beside the count",
      "in 30 min watched" in detail, detail)

# One chrony reading is not a delta. Reading it as "0 requests" would
# have chrony corroborate a silent counter on no evidence at all.
one = [None] * (DAY - 1) + [{"ntp": 500, "drop": 0,
                             "interval": "12", "last_s": 60.0}]
cell, blockers, _, detail = judge([0] * DAY, chrony=one)
check("a single chrony reading does not corroborate anything",
      not any("independently served it nothing" in b for b in blockers),
      str(blockers))
check("...and says why", "no delta yet" in detail, detail)

check("chrony ages parse bare seconds", G._chrony_age("57") == 57)
check("chrony ages parse minutes", G._chrony_age("65m") == 3900)
check("chrony ages parse hours", G._chrony_age("3h") == 10800)
check("chrony ages tolerate '-'", G._chrony_age("-") is None)


# --------------------------------------------------------------------
# 5. end to end: the three exit codes
# --------------------------------------------------------------------
print("\nwhole-summary outcomes")


def run_summary(series: dict[str, list[int]], events: list[dict],
                n: int = DAY, acks: list[dict] | None = None
                ) -> tuple[int, str]:
    """cmd_summary against temp files, with the clock and the journal
    stubbed. Patched at module scope and restored, so one case cannot
    leak into the next."""
    d = tempfile.mkdtemp(prefix="gsfw-observe-test.")
    samples_p = os.path.join(d, "samples.jsonl")
    events_p = os.path.join(d, "events.jsonl")
    acks_p = os.path.join(d, "acks.jsonl")
    import json
    with open(samples_p, "w") as fh:
        for row in build(n, series):
            fh.write(json.dumps(row) + "\n")
    with open(events_p, "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")
    with open(acks_p, "w") as fh:
        for a in (acks or []):
            fh.write(json.dumps(a) + "\n")

    old = (G.SAMPLES, G.EVENTS, G.ACKS, G.journal_lines, G._JOURNAL)
    G.SAMPLES, G.EVENTS, G.ACKS = samples_p, events_p, acks_p
    G.journal_lines = lambda: []
    G._JOURNAL = []
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = G.cmd_summary()
        return rc, buf.getvalue()
    finally:
        G.SAMPLES, G.EVENTS, G.ACKS, G.journal_lines, G._JOURNAL = old


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
check("...and says maintenance explains it", "Logged maintenance explains" in out)

# An event in the log that excused nothing must not make the verdict
# claim maintenance explains anything — the window-open marker is one.
marker = [{"ts": T0, "text": "P1 window opened; operator may reflash"}]
rc, out = run_summary({**clean, "in_ntp_112": [0] * DAY}, marker)
check("a hold on a known-absent camera is still HOLD", rc == 2, f"rc={rc}")
check("...and does NOT blame maintenance for it",
      "Logged maintenance explains" not in out, out[-600:])
check("...and names how many readings are unsettled",
      "1 reading observation cannot settle" in out, out[-400:])

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
# 5b. cumulative totals, and counters the table no longer defines
# --------------------------------------------------------------------
print("\ntotals across resets, and retired counters")

check("a total is cumulative, not the last reading",
      G.counted_total(build(6, {"c": [0, 5, 9, 9, 14, 20]}), "c") == 20)
check("...and survives a reset",
      G.counted_total(build(6, {"c": [10, 10, 0, 1, 2, 4]}), "c") == 14,
      str(G.counted_total(build(6, {"c": [10, 10, 0, 1, 2, 4]}), "c")))
check("...counting a pre-existing first reading",
      G.counted_total(build(3, {"c": [7, 7, 8]}), "c") == 8)

# The regression this found on the live box: a table replace zeroed the
# counters, so the old last-reading total reported a real finding as 0.
reset_mid = dict(clean)
reset_mid["fwd_cam_egress"] = [i for i in range(DAY // 2)] + [0] * (DAY // 2)
rc, out = run_summary(reset_mid, [])
check("a finding before a counter reset is still reported",
      f"| `fwd_cam_egress` | {DAY // 2 - 1} |" in out, out[:1200])

# A counter the current table does not define belongs to an earlier
# ruleset; today's classifier has nothing to say about its name.
orphan = {k: v for k, v in clean.items()}
orphan["in_cam_ntp"] = [i * 4 for i in range(DAY // 2)] + [None] * (DAY // 2)
rc, out = run_summary(orphan, [])
check("a retired counter does not block", rc == 0, f"rc={rc}\n{out[-400:]}")
check("...is labelled as retired", "retired — earlier ruleset" in out)
check("...and its traffic is still shown",
      "under an earlier ruleset" in out and "Retired counters" in out)


# --------------------------------------------------------------------
# 6. the operator's answer resolves a HOLD, and cannot waive a blocker
# --------------------------------------------------------------------
print("\noperator acks")

held = {**clean, "in_ntp_112": [0] * DAY}
rc, out = run_summary(held, [])
check("unanswered, a known-absent camera holds", rc == 2, f"rc={rc}")

ack_now = [{"ts": T0 + DAY * STEP, "counter": "in_ntp_112",
            "reason": "yes, camera 12 is still undeployed"}]
rc, out = run_summary(held, [], acks=ack_now)
check("answered, the same window is GO", rc == 0, f"rc={rc}\n{out[-500:]}")
check("...and the answer is printed, not swallowed",
      "Answered by the operator" in out and "still undeployed" in out)
check("...quoting when it was given", "operator confirmed on" in out)

stale = [{"ts": T0 - 86400, "counter": "in_ntp_112", "reason": "fine"}]
rc, out = run_summary(held, [], acks=stale)
check("an ack from before the window does not carry over", rc == 2, f"rc={rc}")

# An ack CAN clear a blocker — a finding stays in the samples forever,
# so once it is genuinely fixed the tool would otherwise say NO-GO
# permanently and the only way forward would be to stop believing it.
# What must never happen is a waiver that is silent or that reads as a
# clean window.
surprise2 = {**clean, "in_cam_other": steady(DAY, per=3)}
rc, out = run_summary(surprise2, [], acks=[
    {"ts": T0 + DAY * STEP, "counter": "in_cam_other",
     "reason": "added to the P2 allowlist"}])
check("an acked blocker becomes a waiver, not a blocker", rc == 0, f"rc={rc}")
check("...printed in full with its reason",
      "Waived by the operator" in out and "P2 allowlist" in out)
check("...and the verdict says it is not a clean window",
      "with 1 waived finding" in out and "Not a clean window" in out,
      out[-500:])
check("...and is NOT reported as a plain GO",
      "\n## GO for P2\n" not in out)

rc, out = run_summary(surprise2, [], acks=[
    {"ts": T0 - 86400, "counter": "in_cam_other", "reason": "old"}])
check("a pre-window ack does not waive a blocker", rc == 1, f"rc={rc}")

rc, out = run_summary(surprise2, [])
check("an unwaived blocker is still NO-GO", rc == 1, f"rc={rc}")

rc, out = run_summary(held, [], acks=[
    {"ts": T0 + DAY * STEP, "counter": "in_ntp_111", "reason": "wrong one"}])
check("an ack for a different counter does not apply", rc == 2, f"rc={rc}")

rc, out = run_summary(held, [], acks=[{"ts": "bad", "counter": 7}])
check("a malformed ack line is ignored, not fatal", rc == 2, f"rc={rc}")


# --------------------------------------------------------------------
print(f"\n{CHECKS - len(FAILURES)}/{CHECKS} checks passed")
if FAILURES:
    print("\nFAILED:")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print("gsfw-observe verdict logic OK")
