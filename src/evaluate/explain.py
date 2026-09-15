"""
evaluate/explain.py — why the detector decides, measured two ways.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

The headline experiment (:mod:`src.evaluate.experiment`) answers the research
question at the level of feature GROUPS: does adding resolution/relay buy any
recall at a matched false-positive budget? A null there says "no distinguishable
value". This module corroborates that finding from a second, model-internal
angle — feature importance — so the conclusion does not rest on one method.

TWO IMPORTANCES, ONE OF WHICH IS TRUSTWORTHY HERE
-------------------------------------------------
* PERMUTATION importance is the reported one. A feature's importance is the drop
  in the headline score (f1 at the calibrated operating point) when that one
  column is shuffled on the LOCKED test set, breaking its link to the label
  while leaving every other feature and the fitted model untouched. It is
  computed on held-out data, is model-agnostic, and answers "how much does the
  deployed decision actually lean on this column?". If the resolution/relay
  columns carry no independent signal, their permutation importance sits at
  zero — the same null, seen through the model.

* GAIN importance (tree split-gain) is reported ONLY for contrast, never as a
  finding. It is computed on TRAINING data and is structurally biased toward
  continuous, high-cardinality features, so it can assign a comfortable-looking
  score to a column that a permutation test shows the model does not need. When
  the two disagree, the permutation number is the honest one. This asymmetry is
  exactly why both are shown.

Everything runs on ONE track's frame (unmapped rows removed, single-track
asserted by :func:`make_split`). The split, seed and calibration mirror the
headline experiment so the two results describe the same fitted detector.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.config import load_config, provenance_note
from src.evaluate import metrics as M
from src.evaluate import splits as S
from src.evaluate import thresholds as T
from src.models import registry as R
from src.schema import columns as K
from src.schema.validate import trainable

# The full four-group matrix is the only interesting input for importance: the
# question is whether the novel columns matter WHEN the base columns are also
# present to carry any redundant signal.
_ALL_GROUPS = ["infection", "payload", "resolution", "relay"]


def permutation_importance(df: pd.DataFrame, *, cfg=None, seed: int = 42,
                           model_name: str = R.RANDOM_FOREST) -> dict:
    """Permutation importance of every feature, aggregated by group.

    The detector is fitted once on train and pinned to the FPR budget on
    validation; the threshold is then held FIXED while each test column is
    shuffled ``permutation_repeats`` times. Importance is the mean fall in the
    configured score (f1 by default). Reported per feature and summed per group,
    with the novel-vs-base totals called out — the number that corroborates (or
    would contradict) the headline null.
    """
    cfg = cfg or load_config()
    scoring = cfg.explainability.permutation_scoring
    repeats = int(cfg.explainability.permutation_repeats)

    feats = K.features_for_groups(_ALL_GROUPS)
    split = S.make_split(
        trainable(df), strategy=cfg.evaluation.split_strategy, seed=seed,
        test_size=cfg.evaluation.test_size, val_size=cfg.evaluation.val_size,
        min_windows_per_device=cfg.evaluation.min_windows_per_device)
    Xtr, ytr, Xval, yval, Xte, yte = split.matrices(feats)

    det = R.by_name(model_name, cfg, seed=seed)
    det.fit(Xtr, ytr)
    # Fixed operating point: calibrate on validation to the budget, then never
    # move it — importance must be measured at the point the model is deployed
    # at, not re-optimised for each shuffled column.
    thr = T.calibrate(yval, R.positive_score(det, Xval),
                      target_fpr=cfg.evaluation.target_fpr)["threshold"]

    def _score(X) -> float:
        return M.score_at_threshold(yte, R.positive_score(det, X), thr)[scoring]

    baseline = _score(Xte)
    rng = np.random.default_rng(seed)
    n = len(Xte)

    per_feature: dict[str, dict] = {}
    for col in feats:
        vals = Xte[col].to_numpy()
        drops = np.empty(repeats, float)
        for r in range(repeats):
            Xp = Xte.copy()
            Xp[col] = vals[rng.permutation(n)]     # break this column only
            drops[r] = baseline - _score(Xp)
        per_feature[col] = {
            "group": K.GROUP_OF_FEATURE[col],
            "importance_mean": round(float(drops.mean()), 6),
            "importance_std": round(
                float(drops.std(ddof=1)) if repeats > 1 else 0.0, 6),
        }

    by_group = {
        g: round(sum(per_feature[c]["importance_mean"]
                     for c in feats if K.GROUP_OF_FEATURE[c] == g), 6)
        for g in _ALL_GROUPS}
    novel_total = round(sum(by_group[g] for g in K.NOVEL_GROUPS), 6)
    base_total = round(sum(by_group[g] for g in K.BASE_GROUPS), 6)

    return {
        "track": "B (mock)",
        "model": model_name,
        "seed": seed,
        "method": "permutation",
        "scoring": scoring,
        "repeats": repeats,
        "baseline_score": round(float(baseline), 6),
        "threshold": thr,
        "per_feature": per_feature,
        "by_group": by_group,
        "novel_group_total": novel_total,
        "base_group_total": base_total,
        "gain_importance": _gain_importance(det, feats, cfg),
        "interpretation": _interpret(novel_total, base_total, scoring),
        "provenance": provenance_note(cfg),
    }


def _gain_importance(det, feats: list[str], cfg) -> dict | None:
    """Tree split-gain importance, for CONTRAST only (see module docstring).

    Returns None when the detector exposes no gain (the heuristic) or when the
    config disables it. Never read as a finding; the permutation number governs.
    """
    if not cfg.explainability.report_gain_importance:
        return None
    getter = getattr(det, "feature_importances_gain", None)
    imp = getter() if callable(getter) else None
    if imp is None:
        return None
    # The estimator was fitted on ``feats`` in this exact order, so position i
    # of the importance vector is feats[i].
    return {
        "note": ("computed on TRAINING data; biased toward continuous / "
                 "high-cardinality features; contrast only, not a finding"),
        "by_feature": {feats[i]: round(float(imp[i]), 6)
                       for i in range(len(feats))},
    }


def _interpret(novel_total: float, base_total: float, scoring: str) -> str:
    """Plain reading of the group totals, honest about a near-zero novel total."""
    near_zero = abs(novel_total) < 0.01
    if near_zero:
        return (
            f"The resolution+relay columns together move the test {scoring} by "
            f"{novel_total:+.4f} when permuted — indistinguishable from zero — "
            f"while the base columns account for {base_total:+.4f}. The model "
            "does not lean on the novel groups; this corroborates the headline "
            "null from a model-internal angle.")
    return (
        f"The resolution+relay columns move the test {scoring} by "
        f"{novel_total:+.4f} when permuted (base columns {base_total:+.4f}). "
        "Read this alongside the headline build-up result before treating it as "
        "evidence the novel groups carry independent signal.")
