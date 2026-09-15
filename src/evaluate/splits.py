"""
evaluate/splits.py — train / validation / test splits with a LOCKED test set.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

WHY THIS IS NOT sklearn.train_test_split
----------------------------------------
The unit of analysis is a DEVICE-WINDOW, not a flow and not an independent
sample. Windows from one device share the device's fixed behaviour — its idle
rhythm, its firmware's connection habits, its owner's schedule. A random
row-level split puts some of a device's windows in train and some in test, so
the model can memorise the device and score well on windows it has, in effect,
already seen. The reported number then measures memorisation, not
generalisation, and it does so in the optimistic direction.

Three strategies, answering three different questions:

  group     No device_id appears in more than one split. Tests generalisation
            to UNSEEN DEVICES. This is the default and the one the paper's
            headline uses, because "would this catch a device it was never
            trained on?" is the question a deployment actually asks.

  temporal  Train on earlier windows, test on later ones. Tests generalisation
            to a LATER PERIOD, and deliberately allows the same device in both
            splits — that overlap is the point, not a leak, because the question
            is whether a model trained on the past holds up on the future.

  random    Stratified rows, groups ignored. Kept ONLY to reproduce the
            prototype's published numbers for comparison. Emits a warning and
            must never back a new claim. Its optimism relative to `group` is
            itself a reportable quantity.

THE LOCKED TEST SET
-------------------
The test split is carved off FIRST and is not touched again by anything in this
module's callers until the single final scoring. Model selection, threshold
calibration and importance analysis all run on the validation split. A test set
that is peeked at during tuning is a validation set wearing a test set's name,
and its scores are the best of many looks rather than an estimate of future
performance.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from src.schema import columns as K

STRATEGY_GROUP = "group"
STRATEGY_TEMPORAL = "temporal"
STRATEGY_RANDOM = "random"
STRATEGIES = (STRATEGY_GROUP, STRATEGY_TEMPORAL, STRATEGY_RANDOM)


class SplitError(ValueError):
    """The frame cannot be split as requested."""


@dataclass
class DataSplit:
    """Positional index sets into a frozen copy of the input frame.

    Indices are positions into ``frame`` (which has a reset RangeIndex), not
    labels from the caller's original DataFrame. That keeps a split reusable
    across many feature sets — the incremental experiment fits a dozen models on
    ONE split — and makes :meth:`matrices` a pure slice with no realignment.
    """

    frame: pd.DataFrame
    strategy: str
    seed: int
    train_idx: np.ndarray
    val_idx: np.ndarray
    test_idx: np.ndarray
    diagnostics: dict = field(default_factory=dict)

    def matrices(self, feature_cols: list[str]):
        """Return ``(X_train, y_train, X_val, y_val, X_test, y_test)``.

        ``y`` is the binary label; ``unmapped`` rows are assumed already removed
        by :func:`src.schema.validate.trainable` before the split. Feature
        columns are sliced in the caller's given order so a model always sees
        the same column layout it was trained on.
        """
        missing = [c for c in feature_cols if c not in self.frame.columns]
        if missing:
            raise SplitError(f"feature column(s) not in frame: {missing}")
        y = self.frame[K.LABEL_BINARY].to_numpy()
        if (y == K.LABEL_BINARY_UNMAPPED).any():
            raise SplitError(
                "frame still contains unmapped rows (label_binary == "
                f"{K.LABEL_BINARY_UNMAPPED}); call schema.validate.trainable() "
                "before splitting")
        X = self.frame[feature_cols]
        return (
            X.iloc[self.train_idx], y[self.train_idx],
            X.iloc[self.val_idx], y[self.val_idx],
            X.iloc[self.test_idx], y[self.test_idx],
        )

    def groups(self, which: str) -> np.ndarray:
        """Device ids for one split — the resampling unit for a grouped
        bootstrap. ``which`` in {"train", "val", "test"}."""
        idx = {"train": self.train_idx, "val": self.val_idx,
               "test": self.test_idx}[which]
        return self.frame[K.DEVICE_ID].to_numpy()[idx]


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------
def _apply_min_windows(df: pd.DataFrame, min_windows: int,
                       rep: dict) -> pd.DataFrame:
    """Drop devices contributing fewer than ``min_windows`` windows.

    A device seen for a single window cannot land in both train and test under a
    grouped split, so it is not itself a leak risk — but a device with one window
    contributes a per-window rate computed from almost no data, and in a grouped
    split it can only ever be in one split, skewing that split's class balance by
    a whole device. The floor is a config knob (default 1 = keep everything); the
    number dropped is always reported so a high floor cannot quietly shrink the
    sample without trace.
    """
    if min_windows <= 1:
        rep["devices_dropped_min_windows"] = 0
        rep["rows_dropped_min_windows"] = 0
        return df
    counts = df[K.DEVICE_ID].value_counts()
    keep_devices = counts[counts >= min_windows].index
    kept = df[df[K.DEVICE_ID].isin(keep_devices)]
    rep["devices_dropped_min_windows"] = int(
        df[K.DEVICE_ID].nunique() - len(keep_devices))
    rep["rows_dropped_min_windows"] = int(len(df) - len(kept))
    if kept.empty:
        raise SplitError(
            f"min_windows_per_device={min_windows} removed every row; the "
            "capture has no device with that many windows")
    return kept


# ---------------------------------------------------------------------------
# Grouped split
# ---------------------------------------------------------------------------
def _group_majority_stratum(df: pd.DataFrame) -> pd.Series:
    """One stratification key per device: its majority binary label.

    Whole devices are assigned to splits, so stratification has to act on a
    per-device summary rather than per-row. In Track B a device is benign or
    malicious throughout, so the majority IS the label. In Track A a device can
    carry both benign and malicious windows; the majority is the honest single
    key, and any residual imbalance shows up in the per-split class counts the
    report emits.
    """
    return df.groupby(K.DEVICE_ID)[K.LABEL_BINARY].agg(
        lambda s: int(s.mean() >= 0.5))


def _allocate_groups(strata: pd.Series, test_size: float, val_size: float,
                     rng: np.random.Generator) -> tuple[set, set, set]:
    """Split device ids into (train, val, test) sets, stratified and disjoint.

    Within each stratum the devices are shuffled and cut by cumulative fraction.
    Cutting per stratum rather than globally keeps the class balance stable even
    when one class has few devices — a global cut can, by chance, send every
    malicious device to one split.

    ``val_size`` is expressed as a fraction of the WHOLE, matching test_size, so
    the three fractions read consistently in one config block. It is converted
    to a fraction of the post-test remainder here.
    """
    train, val, test = set(), set(), set()
    val_of_remainder = val_size / (1.0 - test_size) if test_size < 1.0 else 0.0
    for _, group_ids in strata.groupby(strata):
        devices = group_ids.index.to_numpy()
        rng.shuffle(devices)
        n = len(devices)
        n_test = int(round(n * test_size))
        n_val = int(round((n - n_test) * val_of_remainder))
        # Guard the small-stratum case: with 2 devices in a class, rounding can
        # claim both for test and leave train with none of that class. Leave at
        # least one device for train whenever the stratum has more than one.
        if n >= 2:
            n_test = min(n_test, n - 1)
            n_val = min(n_val, n - n_test - 1) if n - n_test >= 2 else 0
        test.update(devices[:n_test])
        val.update(devices[n_test:n_test + n_val])
        train.update(devices[n_test + n_val:])
    return train, val, test


def _grouped_split(df: pd.DataFrame, test_size: float, val_size: float,
                   seed: int, rep: dict) -> tuple[np.ndarray, np.ndarray,
                                                  np.ndarray]:
    rng = np.random.default_rng(seed)
    strata = _group_majority_stratum(df)
    train_g, val_g, test_g = _allocate_groups(strata, test_size, val_size, rng)

    dev = df[K.DEVICE_ID].to_numpy()
    train_idx = np.flatnonzero(np.isin(dev, list(train_g)))
    val_idx = np.flatnonzero(np.isin(dev, list(val_g)))
    test_idx = np.flatnonzero(np.isin(dev, list(test_g)))

    # The invariant that justifies the whole strategy. Asserted, not assumed:
    # a bug in allocation that leaked a device across splits would otherwise
    # inflate every score silently.
    overlap = (train_g & val_g) | (train_g & test_g) | (val_g & test_g)
    if overlap:
        raise SplitError(
            f"grouped split leaked {len(overlap)} device(s) across splits: "
            f"{sorted(overlap)[:5]}")
    rep["group_overlap_count"] = 0
    rep["groups_train"] = len(train_g)
    rep["groups_val"] = len(val_g)
    rep["groups_test"] = len(test_g)
    return train_idx, val_idx, test_idx


# ---------------------------------------------------------------------------
# Temporal split
# ---------------------------------------------------------------------------
def _temporal_split(df: pd.DataFrame, test_size: float, val_size: float,
                    rep: dict) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Earliest windows train, latest windows test.

    Cut by row position after a stable sort on window_start. Each row is one
    atomic device-window, so no window is divided across the boundary and there
    is nothing to leak at the cut itself. The same DEVICE may appear on both
    sides at different times — that is the definition of this split, not a
    defect, and the report states how many devices span the boundary so the
    reader can see it rather than infer it.
    """
    order = df.sort_values(
        [K.WINDOW_START, K.DEVICE_ID, K.OBSERVATION_ID], kind="stable"
    ).index.to_numpy()
    # `order` holds original labels; translate to positions in the reset frame.
    pos = pd.Series(np.arange(len(df)), index=df.index).loc[order].to_numpy()

    n = len(pos)
    n_test = int(round(n * test_size))
    n_val = int(round(n * val_size))
    n_train = n - n_test - n_val
    if min(n_train, n_val, n_test) <= 0:
        raise SplitError(
            f"temporal split of {n} rows into "
            f"{n_train}/{n_val}/{n_test} leaves an empty split")
    train_idx = np.sort(pos[:n_train])
    val_idx = np.sort(pos[n_train:n_train + n_val])
    test_idx = np.sort(pos[n_train + n_val:])

    ts = df[K.WINDOW_START]
    for name, idx in (("train", train_idx), ("val", val_idx),
                      ("test", test_idx)):
        rep[f"{name}_time_range"] = [
            str(ts.iloc[idx].min()), str(ts.iloc[idx].max())]
    dev = df[K.DEVICE_ID].to_numpy()
    spanning = (set(dev[train_idx]) | set(dev[val_idx])) & set(dev[test_idx])
    rep["devices_spanning_boundary"] = int(len(spanning))
    rep["note"] = ("temporal split shares devices across time on purpose; "
                   "it answers generalisation to a later period, not to unseen "
                   "devices")
    return train_idx, val_idx, test_idx


# ---------------------------------------------------------------------------
# Random split (prototype-reproduction only)
# ---------------------------------------------------------------------------
def _random_split(df: pd.DataFrame, test_size: float, val_size: float,
                  seed: int, rep: dict) -> tuple[np.ndarray, np.ndarray,
                                                 np.ndarray]:
    warnings.warn(
        "split_strategy='random' ignores device grouping and leaks devices "
        "across splits. It exists only to reproduce the prototype's numbers "
        "and must not support a new claim. Use 'group' for generalisation "
        "results.", stacklevel=3)
    rng = np.random.default_rng(seed)
    y = df[K.LABEL_BINARY].to_numpy()
    train, val, test = [], [], []
    val_of_remainder = val_size / (1.0 - test_size) if test_size < 1.0 else 0.0
    # Stratify by binary label so each split holds a representative positive
    # rate; a class this rare would otherwise vanish from a split by chance.
    for cls in np.unique(y):
        pos = np.flatnonzero(y == cls)
        rng.shuffle(pos)
        n = len(pos)
        n_test = int(round(n * test_size))
        n_val = int(round((n - n_test) * val_of_remainder))
        test.extend(pos[:n_test])
        val.extend(pos[n_test:n_test + n_val])
        train.extend(pos[n_test + n_val:])
    dev = df[K.DEVICE_ID].to_numpy()
    train_idx = np.sort(np.array(train, dtype=int))
    val_idx = np.sort(np.array(val, dtype=int))
    test_idx = np.sort(np.array(test, dtype=int))
    leaked = (set(dev[train_idx]) | set(dev[val_idx])) & set(dev[test_idx])
    rep["group_overlap_count"] = int(len(leaked))
    rep["warning"] = "device-leaking split; not valid for generalisation claims"
    return train_idx, val_idx, test_idx


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def make_split(df: pd.DataFrame, *, strategy: str = STRATEGY_GROUP,
               seed: int = 42, test_size: float = 0.30, val_size: float = 0.20,
               min_windows_per_device: int = 1) -> DataSplit:
    """Split ``df`` into train / validation / test.

    ``df`` must already be trainable (no ``unmapped`` rows) and single-track —
    this function does not police the two-track rule, because an experiment that
    reaches here with both tracks pooled has a bug upstream that the schema
    validator should have caught first. It does assert single-track as a
    backstop, since a split silently spanning both tracks is exactly the failure
    the whole design exists to prevent.
    """
    if strategy not in STRATEGIES:
        raise SplitError(f"unknown strategy {strategy!r}; use one of {STRATEGIES}")
    for col in (K.DEVICE_ID, K.WINDOW_START, K.LABEL_BINARY, K.OBSERVATION_ID):
        if col not in df.columns:
            raise SplitError(f"required column {col!r} missing from frame")
    if df.empty:
        raise SplitError("cannot split an empty frame")

    tracks = {K.TRACK_OF_CLASS.get(c) for c in df[K.RESEARCH_CLASS].unique()}
    tracks.discard(None)
    if len(tracks) > 1:
        raise SplitError(
            f"frame mixes tracks {tracks}; splits are per-track. Pooling real "
            "and mock rows is the capture-provenance shortcut this project "
            "forbids — see docs/limitations.md")

    rep: dict = {"strategy": strategy, "seed": int(seed),
                 "requested": {"test_size": test_size, "val_size": val_size}}
    work = _apply_min_windows(df, min_windows_per_device, rep).reset_index(
        drop=True)

    if strategy == STRATEGY_GROUP:
        tr, va, te = _grouped_split(work, test_size, val_size, seed, rep)
    elif strategy == STRATEGY_TEMPORAL:
        tr, va, te = _temporal_split(work, test_size, val_size, rep)
    else:
        tr, va, te = _random_split(work, test_size, val_size, seed, rep)

    n = len(work)
    rep["n_rows"] = n
    rep["n_train"], rep["n_val"], rep["n_test"] = len(tr), len(va), len(te)
    rep["achieved"] = {
        "test_size": round(len(te) / n, 4),
        "val_size": round(len(va) / n, 4),
    }
    if len(tr) == 0 or len(te) == 0:
        raise SplitError(
            f"split produced an empty train ({len(tr)}) or test ({len(te)}) "
            "set; check test_size/val_size and that the frame has enough "
            "devices per class")
    rep["class_balance"] = _class_balance(work, tr, va, te)
    return DataSplit(frame=work, strategy=strategy, seed=int(seed),
                     train_idx=tr, val_idx=va, test_idx=te, diagnostics=rep)


def _class_balance(df: pd.DataFrame, tr, va, te) -> dict:
    """Positive rate and per-class counts in each split — the first thing to
    check when a metric looks wrong."""
    y = df[K.LABEL_BINARY].to_numpy()
    cls = df[K.RESEARCH_CLASS].to_numpy()
    out = {}
    for name, idx in (("train", tr), ("val", va), ("test", te)):
        if len(idx) == 0:
            out[name] = {"n": 0, "positive_rate": None, "classes": {}}
            continue
        vals, counts = np.unique(cls[idx], return_counts=True)
        out[name] = {
            "n": int(len(idx)),
            "positive_rate": round(float(y[idx].mean()), 4),
            "classes": {str(v): int(c) for v, c in zip(vals, counts)},
        }
    return out
