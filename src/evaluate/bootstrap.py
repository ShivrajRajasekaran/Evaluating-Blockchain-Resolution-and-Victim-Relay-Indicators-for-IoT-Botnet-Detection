"""
evaluate/bootstrap.py — confidence intervals resampled BY GROUP.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

THE ERROR THIS MODULE EXISTS TO NOT MAKE
----------------------------------------
The prototype reported 95% CIs by resampling ROWS. Under a grouped split that is
wrong, and wrong in the direction that flatters this project's conclusion.

Windows from one device are correlated — they share the device's fixed
behaviour. Resampling rows independently pretends each window is a fresh draw,
so it treats, say, 9,000 correlated windows as 9,000 independent observations.
The resulting interval is too narrow. A too-narrow interval around a difference
of +0.012 F1 can exclude zero and read as "a real improvement" when a correct
interval would straddle zero and read as "indistinguishable from none".

Since the headline finding is precisely that the novel groups add *no
distinguishable value*, an over-narrow interval would manufacture the opposite
finding. So the resampling unit is the DEVICE: each resample draws devices with
replacement and takes all of a drawn device's windows together. The config key
``evaluation.bootstrap_unit`` selects "group" (default) or "row"; "row" is kept
only to reproduce the prototype's intervals and show how much narrower — how
overconfident — they were.

PAIRED DIFFERENCES
------------------
Comparing two feature sets ("base" vs "base + relay") uses a PAIRED bootstrap:
one set of devices is drawn per iteration and both models are scored on that
same set, so the interval is of the *difference* and cancels the variance the
two models share. An unpaired interval of each score, eyeballed for overlap, is
a weaker and slightly wrong test; the paired difference interval is the one the
paper reports.
"""
from __future__ import annotations

import numpy as np

from src.evaluate import metrics as M

UNIT_GROUP = "group"
UNIT_ROW = "row"


def _metric_value(y_true, y_score, metric: str, threshold: float):
    """One scalar for one (resampled) sample, or None if undefined here."""
    if metric == "roc_auc":
        return M.auc(y_true, y_score)
    m = M.score_at_threshold(y_true, y_score, threshold)
    if metric not in m:
        raise ValueError(f"unknown metric {metric!r}")
    # F1/recall/precision/fpr are always defined (0/0 -> 0.0), but a resample
    # with no positives makes recall a 0.0 that carries no information about the
    # model. Flag the single-class case so the caller can count it.
    if len(np.unique(np.asarray(y_true).astype(int))) < 2:
        return None
    return m[metric]


def _positions_by_group(groups: np.ndarray) -> dict:
    return {g: np.flatnonzero(groups == g) for g in np.unique(groups)}


def _resample(groups, uniq, pos_by_group, unit, rng) -> np.ndarray:
    if unit == UNIT_ROW:
        n = len(groups)
        return rng.integers(0, n, size=n)
    chosen = rng.choice(uniq, size=uniq.size, replace=True)
    return np.concatenate([pos_by_group[g] for g in chosen])


def _percentile_ci(stats: list[float], ci: float) -> tuple[float, float]:
    alpha = 1.0 - ci
    lo = float(np.quantile(stats, alpha / 2.0))
    hi = float(np.quantile(stats, 1.0 - alpha / 2.0))
    return lo, hi


def bootstrap_metric(y_true, y_score, groups=None, *, metric: str = "f1",
                     threshold: float = 0.5, n_resamples: int = 1000,
                     ci: float = 0.95, unit: str = UNIT_GROUP,
                     seed: int = 42) -> dict:
    """Percentile CI for one metric of one detector.

    ``groups`` are the device ids aligned to ``y_true``; pass them (and the
    default unit="group") whenever the split was grouped. Omitting them falls
    back to a row bootstrap and records that it did, so a result can never
    silently claim a grouped interval it did not compute.
    """
    y_true = np.asarray(y_true).astype(int)
    y_score = np.asarray(y_score, float)
    n = y_true.size
    if groups is None:
        groups = np.arange(n)
        unit = UNIT_ROW
    groups = np.asarray(groups)
    rng = np.random.default_rng(seed)

    point = _metric_value(y_true, y_score, metric, threshold)
    uniq = np.unique(groups)
    pos_by_group = _positions_by_group(groups)

    stats, n_degenerate = [], 0
    for _ in range(n_resamples):
        idx = _resample(groups, uniq, pos_by_group, unit, rng)
        val = _metric_value(y_true[idx], y_score[idx], metric, threshold)
        if val is None:
            n_degenerate += 1
            continue
        stats.append(val)

    if not stats:
        raise ValueError(
            f"every one of {n_resamples} resamples was single-class; a CI for "
            f"{metric!r} cannot be formed. The split is too small or too "
            "imbalanced for a bootstrap.")
    lo, hi = _percentile_ci(stats, ci)
    return {
        "metric": metric,
        "point": point,
        "ci_low": round(lo, 6),
        "ci_high": round(hi, 6),
        "ci_level": ci,
        "unit": unit,
        "n_resamples": n_resamples,
        "n_effective": len(stats),
        "n_degenerate_resamples": n_degenerate,
        "n_groups": int(uniq.size) if unit == UNIT_GROUP else None,
        "n_rows": int(n),
    }


def _split_thresholds(threshold) -> tuple[float, float]:
    """Accept one threshold for both arrays, or a (thr_a, thr_b) pair.

    The matched-FPR comparison calibrates each feature set to its OWN threshold
    on validation (1% FPR is hit at a different score cut for a base model than
    for a base+novel model), so the paired difference must threshold A and B
    independently. A scalar keeps the simple same-threshold case working.
    """
    if isinstance(threshold, (tuple, list)):
        if len(threshold) != 2:
            raise ValueError("threshold pair must be (thr_a, thr_b)")
        return float(threshold[0]), float(threshold[1])
    return float(threshold), float(threshold)


def bootstrap_difference(y_true, s_a, s_b, groups=None, *, metric: str = "f1",
                         threshold=0.5, n_resamples: int = 1000,
                         ci: float = 0.95, unit: str = UNIT_GROUP,
                         seed: int = 42) -> dict:
    """Paired CI for ``metric(A) - metric(B)`` on the same test rows.

    ``s_a`` and ``s_b`` are two detectors' scores on the SAME rows (e.g. a model
    trained on base+relay features and one on base features). Each resample
    draws devices once and scores both models on that draw, so the interval
    reflects only the difference between the models, not the variance they share.

    ``threshold`` is a scalar applied to both, or a ``(thr_a, thr_b)`` pair when
    each model was calibrated to its own operating point — the matched-FPR case
    the headline experiment uses.

    ``includes_zero`` is the headline test: when the CI of the difference spans
    0, the two feature sets are not distinguishable at this level, which for this
    project is a finding, not a failure.
    """
    y_true = np.asarray(y_true).astype(int)
    s_a = np.asarray(s_a, float)
    s_b = np.asarray(s_b, float)
    thr_a, thr_b = _split_thresholds(threshold)
    n = y_true.size
    if groups is None:
        groups = np.arange(n)
        unit = UNIT_ROW
    groups = np.asarray(groups)
    rng = np.random.default_rng(seed)

    pa = _metric_value(y_true, s_a, metric, thr_a)
    pb = _metric_value(y_true, s_b, metric, thr_b)
    point = None if pa is None or pb is None else pa - pb

    uniq = np.unique(groups)
    pos_by_group = _positions_by_group(groups)

    diffs, n_degenerate = [], 0
    for _ in range(n_resamples):
        idx = _resample(groups, uniq, pos_by_group, unit, rng)
        va = _metric_value(y_true[idx], s_a[idx], metric, thr_a)
        vb = _metric_value(y_true[idx], s_b[idx], metric, thr_b)
        if va is None or vb is None:
            n_degenerate += 1
            continue
        diffs.append(va - vb)

    if not diffs:
        raise ValueError(
            "every paired resample was single-class; the difference CI cannot "
            "be formed")
    lo, hi = _percentile_ci(diffs, ci)
    return {
        "metric": f"delta_{metric}",
        "point": None if point is None else round(point, 6),
        "ci_low": round(lo, 6),
        "ci_high": round(hi, 6),
        "ci_level": ci,
        "unit": unit,
        "includes_zero": bool(lo <= 0.0 <= hi),
        "n_resamples": n_resamples,
        "n_effective": len(diffs),
        "n_degenerate_resamples": n_degenerate,
        "n_groups": int(uniq.size) if unit == UNIT_GROUP else None,
    }
