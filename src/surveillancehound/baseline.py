"""Per-camera behavioral baselining — two model choices, both stdlib-only.

The daemon's job is to learn what each camera's traffic *normally* looks like
at every (weekday, hour) so it can shout when reality drifts. Two models with
the same observe()/flush() lifecycle live here:

* **Welford** (default, ``model = "welford"``) — running per-feature
  (mean, variance) via Welford's algorithm. Fires when a *single* feature
  exceeds ``z_threshold`` standard deviations. Deterministic, auditable,
  O(1) memory per (camera, weekday, hour, feature).

* **Half-Space Forest** (``model = "hstree"``) — a real streaming ML
  anomaly detector (Tan, Ting, Liu — *Fast Anomaly Detection for Streaming
  Data*, IJCAI 2011). An ensemble of random projection trees scores each
  flow against a learned ``reference`` window. Catches *joint* anomalies
  by construction — e.g. a flow whose bytes AND duration are individually
  normal but whose combination is rare. Pure stdlib (just ``random`` +
  ``struct``), O(log depth) per flow.

Why these two: Welford is the safe baseline (no hyper-params besides the
threshold, easy to reason about), HS-Forest is the upgrade when you want
multivariate sensitivity without pulling in numpy / scikit-learn / onnx.
Running both at once is wasteful — pick one per camera fleet.

Both gate alerts behind ``min_samples`` per bucket, both persist learned
state to SQLite (``baselines`` table for Welford, ``baseline_forests`` for
HS-Trees), and both emit ``behavioral_anomaly`` alerts via ``alerts.py``.

The classes that touch the daemon hot path are ``BaselineEngine``
(Welford) and ``HSEngine`` (HS-Forest). Both expose:

  - ``bootstrap_from(store)``      — load persisted state once on startup
  - ``observe(camera_ip, fl, fc, now)`` — score, update, return Anomaly list
  - ``maybe_flush(store, now)``    — periodic disk write
  - ``flush(store, now=...)``      — final write on shutdown

so ``daemon.py`` can hold them through a single ``Baseliner`` protocol-y
attribute and call them the same way.
"""

from __future__ import annotations

import logging
import math
import random
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime

from surveillancehound.classify import FlowClassification
from surveillancehound.config import BaselineCfg
from surveillancehound.flows import LiveFlow
from surveillancehound.store import BaselineForestRow, BaselineRow, HoundStore

log = logging.getLogger(__name__)

# Per-flow features. The same five for both models — Welford scores them
# independently, HS-Trees score them jointly. If you add or reorder, also
# bump _FOREST_SCHEMA_VERSION below and any persisted state needs to be
# wiped (or migrated) because the feature-index is baked into the tree.
_FEATURES: tuple[str, ...] = (
    "bytes",             # total flow bytes
    "packets",           # total flow packets
    "duration",          # seconds first_ts → last_ts
    "bytes_to_camera",   # directional, toward the camera
    "bytes_from_camera", # directional, from the camera (exfil-shaped)
)


def _extract(fl: LiveFlow, fc: FlowClassification) -> dict[str, float]:
    return {
        "bytes": float(fl.bytes),
        "packets": float(fl.packets),
        "duration": float(fl.duration),
        "bytes_to_camera": float(fc.bytes_to_camera),
        "bytes_from_camera": float(fc.bytes_from_camera),
    }


def _vec(fl: LiveFlow, fc: FlowClassification) -> list[float]:
    """HS-Tree-shaped input: normalize counts into [0,1] via log1p.

    HS-Trees split a unit hypercube; everything fed in must live in [0,1].
    Raw byte counts span 0 → ~1e10 (a full RSTP recording session) so we
    use log1p then scale by 25 (since log1p(2^32) ≈ 22, log1p(86400s) ≈
    11). The scaling is constant so the model is identifying *relative*
    rarity within the (camera, weekday, hour) bucket — exactly what we
    want for "this camera does X at 3am".
    """
    raw = _extract(fl, fc)
    return [min(1.0, math.log1p(max(0.0, raw[k])) / 25.0) for k in _FEATURES]


# =============================================================================
# Welford engine (the default, unchanged from the original baseline.py)
# =============================================================================


@dataclass
class Welford:
    """Online mean+variance via Welford. Numerically stable, mergeable."""

    n: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += delta * delta2

    @property
    def variance(self) -> float:
        return self.m2 / (self.n - 1) if self.n >= 2 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def z(self, x: float) -> float:
        # Floor std using a coefficient-of-variation rule: prevents both
        # division-by-zero on a near-constant baseline AND firing on a
        # sub-byte excursion when the baseline value is small.
        floor = abs(self.mean) * 0.05 + 1.0
        s = max(self.std, floor)
        return (x - self.mean) / s


@dataclass(frozen=True)
class Anomaly:
    """One feature outside its bucket's learned distribution.

    Both engines emit Anomaly objects so alerts.py can stay one
    factory method. For Welford, ``feature`` is one of _FEATURES and
    ``z`` is the standard-deviation distance. For HS-Forest, ``feature``
    is the literal string ``"joint"``, ``z`` is the forest's [0,1]
    anomaly score (NOT a σ count), and ``baseline_mean`` / ``baseline_std``
    are 0.0 (we don't compute them — joint distributions don't have a
    single mean). Consumers should check ``model`` before treating ``z``
    as a σ count.
    """
    camera_ip: str
    feature: str
    value: float
    z: float
    baseline_mean: float
    baseline_std: float
    weekday: int
    hour: int
    model: str = "welford"


class BaselineEngine:
    """Welford engine. Holds per-feature buckets keyed by
    (camera_ip, weekday, hour, feature).

    Lifecycle:
      * ``bootstrap_from(store)`` once on startup — loads every persisted bucket
      * ``observe(...)`` per flushed camera-flow — scores first then updates;
        returns 0+ Anomaly objects
      * ``maybe_flush(store, now)`` from the daemon's periodic tick — writes
        dirty buckets to disk no more often than ``flush_interval_seconds``
      * ``flush(store)`` on shutdown — final write-back
    """

    def __init__(self, cfg: BaselineCfg) -> None:
        self.cfg = cfg
        self._buckets: dict[tuple[str, int, int, str], Welford] = {}
        self._dirty: set[tuple[str, int, int, str]] = set()
        self._last_flush_at: float = 0.0

    # --- bootstrap / persistence -----------------------------------------

    def bootstrap_from(self, store: HoundStore) -> None:
        for r in store.load_baselines():
            self._buckets[(r.camera_ip, r.weekday, r.hour, r.feature)] = (
                Welford(n=r.n, mean=r.mean, m2=r.m2)
            )
        log.info("baseline (welford): loaded %d buckets from store",
                 len(self._buckets))

    def maybe_flush(self, store: HoundStore, now: float) -> None:
        if not self._dirty:
            return
        if (now - self._last_flush_at) < self.cfg.flush_interval_seconds:
            return
        self.flush(store, now=now)

    def flush(self, store: HoundStore, *, now: float | None = None) -> None:
        if not self._dirty:
            return
        when = now if now is not None else time.time()
        rows: list[BaselineRow] = []
        for key in self._dirty:
            w = self._buckets[key]
            camera_ip, weekday, hour, feature = key
            rows.append(BaselineRow(
                camera_ip=camera_ip, weekday=weekday, hour=hour,
                feature=feature, n=w.n, mean=w.mean, m2=w.m2,
                last_updated=when,
            ))
        store.upsert_baselines_batch(rows)
        self._dirty.clear()
        self._last_flush_at = when

    # --- per-flow hot path -----------------------------------------------

    def observe(
        self, camera_ip: str, fl: LiveFlow, fc: FlowClassification, now: float,
    ) -> list[Anomaly]:
        ts = fl.last_ts or now
        dt = datetime.fromtimestamp(ts)
        weekday = dt.weekday()
        hour = dt.hour
        values = _extract(fl, fc)
        anomalies: list[Anomaly] = []
        for feature, value in values.items():
            key = (camera_ip, weekday, hour, feature)
            w = self._buckets.get(key)
            if w is None:
                w = Welford()
                self._buckets[key] = w
            if w.n >= self.cfg.min_samples:
                z = w.z(value)
                if abs(z) >= self.cfg.z_threshold:
                    anomalies.append(Anomaly(
                        camera_ip=camera_ip, feature=feature, value=value,
                        z=z, baseline_mean=w.mean, baseline_std=w.std,
                        weekday=weekday, hour=hour, model="welford",
                    ))
            w.update(value)
            self._dirty.add(key)
        return anomalies


# =============================================================================
# Half-Space Forest — streaming ML anomaly detection
# =============================================================================
#
# References:
#   Tan, S.C., Ting, K.M., Liu, T.F. (2011). "Fast Anomaly Detection for
#   Streaming Data." IJCAI 2011, 1511-1516.
#
# Algorithm sketch:
#   1. Build T balanced binary trees of depth h. At each internal node, pick
#      a random feature and split that feature's *current range* exactly in
#      half (a "half-space"). The whole tree partitions the unit hypercube
#      into 2**h equal-volume cells.
#   2. Stream samples. Each sample drops down each tree to one leaf (its
#      cell). Per tree, increment that leaf's mass counter (`latest`).
#   3. After window_size samples, "roll over": copy `latest` → `reference`,
#      zero `latest`. The reference is the model; `latest` is the next one.
#   4. Score a sample by averaging across trees: rarer cells (low reference
#      mass) ⇒ higher anomaly score. We return 1 / (1 + mass) ∈ (0, 1].
#
# The math is identical to scikit-multiflow.HalfSpaceTrees and river's
# anomaly.HalfSpaceTrees — we just don't depend on those packages.

_FOREST_MAGIC = b"HF\x01\x00"     # 4-byte magic for serialized blobs
_FOREST_SCHEMA_VERSION = 1        # bump if _FEATURES changes order/count


@dataclass
class HalfSpaceTree:
    """One half-space tree. Stored as parallel flat arrays — no Python
    objects per node — so a depth-6 tree is 63 splits + 64 leaves = a
    few hundred bytes. The whole forest is small.

    Layout (BFS index, root = 0):
      - internal nodes are indices [0, 2**depth - 1)
        - splits[i] = (feature_index, threshold)
        - left  child of i = 2*i + 1
        - right child of i = 2*i + 2
      - leaves are indices [2**depth - 1, 2**(depth+1) - 1)
        - leaf_offset = node_index - (2**depth - 1)
        - reference[leaf_offset] = frozen mass (used for scoring)
        - latest[leaf_offset]    = accumulating mass (becomes reference
                                   on next rollover)
    """
    n_features: int
    depth: int
    splits: list[tuple[int, float]]  # len = 2**depth - 1
    reference: list[int]             # len = 2**depth
    latest: list[int]                # len = 2**depth

    @classmethod
    def build(cls, n_features: int, depth: int, rng: random.Random) -> "HalfSpaceTree":
        n_internal = (1 << depth) - 1
        n_leaves = 1 << depth
        splits: list[tuple[int, float]] = [(0, 0.0)] * n_internal
        # Per-node bounds [lo, hi] for the *split feature only*. Implicitly
        # other features stay at their parent's bounds — but since we only
        # split on one feature per node, and the same feature can be split
        # again deeper, we need per-feature current bounds at each node.
        # Storing all-features-bounds at every node is wasteful at depth 6
        # but it's only built once per (camera, weekday, hour) and reused
        # forever, so we eat the cost for clarity.
        per_node_bounds: list[list[tuple[float, float]] | None] = [None] * n_internal
        per_node_bounds[0] = [(0.0, 1.0)] * n_features
        for i in range(n_internal):
            bounds = per_node_bounds[i]
            assert bounds is not None  # BFS guarantees parents fill children
            f = rng.randrange(n_features)
            lo, hi = bounds[f]
            t = 0.5 * (lo + hi)  # exact midpoint per HS-tree construction
            splits[i] = (f, t)
            left, right = 2 * i + 1, 2 * i + 2
            if left < n_internal:
                lb = list(bounds); lb[f] = (lo, t)
                per_node_bounds[left] = lb
                rb = list(bounds); rb[f] = (t, hi)
                per_node_bounds[right] = rb
            # else: children are leaves; no bounds tracking needed below
        return cls(
            n_features=n_features, depth=depth, splits=splits,
            reference=[0] * n_leaves, latest=[0] * n_leaves,
        )

    def _leaf_offset(self, x: list[float]) -> int:
        """Walk x down to a leaf; return its mass-array offset."""
        i = 0
        n_internal = (1 << self.depth) - 1
        for _ in range(self.depth):
            f, t = self.splits[i]
            i = 2 * i + (1 if x[f] < t else 2)
        return i - n_internal

    def update(self, x: list[float]) -> None:
        self.latest[self._leaf_offset(x)] += 1

    def score_mass(self, x: list[float]) -> int:
        """Raw reference mass at the cell containing x. Lower = rarer."""
        return self.reference[self._leaf_offset(x)]

    def rollover(self) -> None:
        """Promote `latest` to `reference` and start accumulating fresh."""
        self.reference = self.latest
        self.latest = [0] * len(self.latest)


@dataclass
class HSForest:
    """Ensemble of half-space trees plus the streaming bookkeeping
    (samples-in-window, rollover state, cumulative count)."""
    trees: list[HalfSpaceTree]
    window_size: int
    n_samples_in_window: int = 0
    n_total: int = 0
    has_reference: bool = False  # set True after first rollover

    @classmethod
    def build(cls, n_features: int, n_trees: int, depth: int,
              window_size: int, seed: int) -> "HSForest":
        # Seed the master RNG once (clock-based if seed==0), then spawn
        # per-tree RNGs from it. Reproducibility per (seed) without trees
        # sharing the same split sequence.
        master = random.Random(seed if seed else None)
        trees = [
            HalfSpaceTree.build(
                n_features, depth,
                random.Random(master.randint(0, 2**32 - 1)),
            )
            for _ in range(n_trees)
        ]
        return cls(trees=trees, window_size=window_size)

    def update(self, x: list[float]) -> None:
        for t in self.trees:
            t.update(x)
        self.n_total += 1
        self.n_samples_in_window += 1
        if self.n_samples_in_window >= self.window_size:
            for t in self.trees:
                t.rollover()
            self.n_samples_in_window = 0
            self.has_reference = True

    def score(self, x: list[float]) -> float:
        """Mean across trees of 1 / (1 + reference_mass). Returns 0.0
        before the first rollover (no reference yet → can't score)."""
        if not self.has_reference:
            return 0.0
        total = 0.0
        for t in self.trees:
            total += 1.0 / (1.0 + t.score_mass(x))
        return total / len(self.trees)

    # --- persistence ----------------------------------------------------
    #
    # Compact binary blob — one row per (camera, weekday, hour). We pack
    # tree splits as (uint8 feature_idx, float32 threshold) and leaf masses
    # as paired uint32s, so depth-6 / 8-tree comes out to roughly:
    #   header(28) + 8 * (63 * 5 + 64 * 8) = ~7 KB per bucket.

    def serialize(self) -> bytes:
        if not self.trees:
            raise ValueError("empty forest can't serialize")
        t0 = self.trees[0]
        n_features = t0.n_features
        depth = t0.depth
        n_internal = (1 << depth) - 1
        n_leaves = 1 << depth
        header = struct.pack(
            "<4sBBBBHIQB",
            _FOREST_MAGIC,
            _FOREST_SCHEMA_VERSION,
            n_features,
            depth,
            0,  # reserved / pad
            len(self.trees),
            self.window_size,
            self.n_total,
            1 if self.has_reference else 0,
        )
        # samples_in_window separately so the alignment is obvious
        header += struct.pack("<I", self.n_samples_in_window)
        body = bytearray()
        for tr in self.trees:
            # splits: feature byte + float32 threshold per internal node
            for f, th in tr.splits:
                body += struct.pack("<Bf", f, th)
            # leaves: reference + latest as uint32 pairs
            for ref, lat in zip(tr.reference, tr.latest):
                body += struct.pack("<II", ref, lat)
            assert len(tr.splits) == n_internal
            assert len(tr.reference) == n_leaves
        return bytes(header) + bytes(body)

    @classmethod
    def deserialize(cls, blob: bytes) -> "HSForest":
        if len(blob) < 28 or blob[:4] != _FOREST_MAGIC:
            raise ValueError("not a Hound HS-Forest blob (bad magic)")
        (
            _, version, n_features, depth, _pad,
            n_trees, window_size, n_total, has_ref_byte,
        ) = struct.unpack("<4sBBBBHIQB", blob[:23])
        (n_samples_in_window,) = struct.unpack("<I", blob[23:27])
        if version != _FOREST_SCHEMA_VERSION:
            raise ValueError(
                f"HS-Forest blob schema {version} != current "
                f"{_FOREST_SCHEMA_VERSION}; bucket needs rebuild",
            )
        # Header has a 1-byte pad, so the body starts at offset 27
        n_internal = (1 << depth) - 1
        n_leaves = 1 << depth
        per_tree = n_internal * 5 + n_leaves * 8  # split=5 bytes, leaf=8 bytes
        if len(blob) != 27 + n_trees * per_tree:
            raise ValueError(
                f"HS-Forest blob length {len(blob)} doesn't match "
                f"expected {27 + n_trees * per_tree}",
            )
        offset = 27
        trees: list[HalfSpaceTree] = []
        for _ in range(n_trees):
            splits: list[tuple[int, float]] = []
            for _ in range(n_internal):
                f, th = struct.unpack_from("<Bf", blob, offset)
                splits.append((int(f), float(th)))
                offset += 5
            reference: list[int] = []
            latest: list[int] = []
            for _ in range(n_leaves):
                ref, lat = struct.unpack_from("<II", blob, offset)
                reference.append(int(ref))
                latest.append(int(lat))
                offset += 8
            trees.append(HalfSpaceTree(
                n_features=n_features, depth=depth, splits=splits,
                reference=reference, latest=latest,
            ))
        return cls(
            trees=trees, window_size=window_size,
            n_samples_in_window=n_samples_in_window, n_total=n_total,
            has_reference=bool(has_ref_byte),
        )


class HSEngine:
    """Engine that holds one HSForest per (camera, weekday, hour) bucket
    and matches BaselineEngine's API so daemon.py can hold either one
    behind the same attribute."""

    def __init__(self, cfg: BaselineCfg) -> None:
        self.cfg = cfg
        self._buckets: dict[tuple[str, int, int], HSForest] = {}
        self._dirty: set[tuple[str, int, int]] = set()
        self._last_flush_at: float = 0.0

    # --- bootstrap / persistence -----------------------------------------

    def bootstrap_from(self, store: HoundStore) -> None:
        rebuilt = 0
        loaded = 0
        for r in store.load_forests():
            try:
                self._buckets[(r.camera_ip, r.weekday, r.hour)] = (
                    HSForest.deserialize(r.blob)
                )
                loaded += 1
            except ValueError as e:
                # Schema drift or corrupt row — wipe and rebuild lazily on
                # next observe(). Don't crash the daemon over a bad row.
                log.warning(
                    "baseline (hstree): dropping bucket %s/%d/%d: %s",
                    r.camera_ip, r.weekday, r.hour, e,
                )
                store.delete_forests(
                    camera_ip=r.camera_ip, weekday=r.weekday, hour=r.hour,
                )
                rebuilt += 1
        log.info("baseline (hstree): loaded %d forests (rebuilt %d)",
                 loaded, rebuilt)

    def maybe_flush(self, store: HoundStore, now: float) -> None:
        if not self._dirty:
            return
        if (now - self._last_flush_at) < self.cfg.flush_interval_seconds:
            return
        self.flush(store, now=now)

    def flush(self, store: HoundStore, *, now: float | None = None) -> None:
        if not self._dirty:
            return
        when = now if now is not None else time.time()
        rows: list[BaselineForestRow] = []
        for key in self._dirty:
            f = self._buckets[key]
            camera_ip, weekday, hour = key
            rows.append(BaselineForestRow(
                camera_ip=camera_ip, weekday=weekday, hour=hour,
                n_samples=f.n_total, n_samples_in_window=f.n_samples_in_window,
                has_reference=f.has_reference, blob=f.serialize(),
                last_updated=when,
            ))
        store.upsert_forests_batch(rows)
        self._dirty.clear()
        self._last_flush_at = when

    # --- per-flow hot path -----------------------------------------------

    def _bucket(self, camera_ip: str, weekday: int, hour: int) -> HSForest:
        key = (camera_ip, weekday, hour)
        f = self._buckets.get(key)
        if f is None:
            f = HSForest.build(
                n_features=len(_FEATURES),
                n_trees=self.cfg.hstree_n_trees,
                depth=self.cfg.hstree_depth,
                window_size=self.cfg.hstree_window_size,
                # Per-bucket seed derived from the master seed + bucket key so
                # different buckets get different random splits without each
                # one needing its own configured seed.
                seed=(
                    self.cfg.hstree_seed
                    + hash((camera_ip, weekday, hour)) & 0x7FFFFFFF
                ),
            )
            self._buckets[key] = f
        return f

    def observe(
        self, camera_ip: str, fl: LiveFlow, fc: FlowClassification, now: float,
    ) -> list[Anomaly]:
        """Score the flow against the bucket's forest, THEN update.

        Same score-before-update contract as Welford: the first sample in
        a fresh bucket can't be flagged against itself. Returns 0 or 1
        Anomaly per call (joint score → joint anomaly, not per-feature).
        """
        ts = fl.last_ts or now
        dt = datetime.fromtimestamp(ts)
        weekday = dt.weekday()
        hour = dt.hour
        f = self._bucket(camera_ip, weekday, hour)
        x = _vec(fl, fc)
        anomalies: list[Anomaly] = []
        # Need a reference window first (one full window_size) AND the
        # min_samples gate from cfg. Both protect against false-positives
        # on cold-start.
        if (
            f.has_reference
            and f.n_total >= self.cfg.min_samples
        ):
            score = f.score(x)
            if score >= self.cfg.hstree_score_threshold:
                anomalies.append(Anomaly(
                    camera_ip=camera_ip, feature="joint",
                    value=score, z=score,
                    baseline_mean=0.0, baseline_std=0.0,
                    weekday=weekday, hour=hour, model="hstree",
                ))
        f.update(x)
        self._dirty.add((camera_ip, weekday, hour))
        return anomalies


# =============================================================================
# Tiny constructor used by daemon.py — picks the engine without daemon.py
# having to know the model names.


def make_engine(cfg: BaselineCfg):
    """Return an instance of the right baseline engine for cfg.model."""
    if cfg.model == "hstree":
        return HSEngine(cfg)
    return BaselineEngine(cfg)
