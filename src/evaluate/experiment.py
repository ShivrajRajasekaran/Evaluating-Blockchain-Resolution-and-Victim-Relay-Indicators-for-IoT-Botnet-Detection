"""
evaluate/experiment.py — the headline incremental-value experiment (Track B).

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

THE QUESTION, MADE OPERATIONAL
------------------------------
"Do blockchain-resolution and victim-relay indicator groups add measurable
detection value beyond conventional IoT-botnet features, at a low false-positive
rate?" becomes, precisely:

  1. Build UP from the generic-signal base (infection + payload) by adding the
     novel groups one at a time, then together.
  2. Calibrate EACH feature set's detector to the same benign false-positive
     budget (default 1%) on the VALIDATION split — so every set is compared at
     the same false-alarm cost, not at an arbitrary p>=0.5.
  3. Score on the LOCKED test split and read the recall (detection rate) each
     set buys at that budget.
  4. Bootstrap the DIFFERENCE in recall between each augmented set and the base,
     resampling BY DEVICE and pairing on the same devices. If the interval
     includes zero, the novel groups add no distinguishable value.

WHY BUILD-UP, NOT DROP-ONE, IS THE HEADLINE
-------------------------------------------
When feature groups correlate, a drop-one ablation is ambiguous: removing a
redundant-but-informative group costs nothing, which looks identical to removing
a useless one. Build-up from a fixed base asks the question the research
question actually poses — "what does adding this buy?" — and is reported as the
headline. Drop-one is still computed (:func:`run_drop_one`) as a diagnostic, read
only in the light of the build-up.

Everything here runs on ONE track's frame. The frame is made trainable (unmapped
rows removed) and single-track before it reaches :func:`make_split`, which
asserts single-track as a backstop. Pooling tracks is the one thing this whole
design exists to prevent.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.config import load_config, provenance_note
from src.evaluate import bootstrap as B
from src.evaluate import splits as S
from src.evaluate import thresholds as T
from src.models import registry as R
from src.schema import columns as K
from src.schema.validate import trainable

# Headline metric: recall at the matched FPR budget. FPR is equalised by
# calibration, so recall is the clean "extra malicious devices caught"; F1 is
# reported too but moves with precision, which the budget already pins.
HEADLINE_METRIC = "recall"
SECONDARY_METRICS = ("f1", "precision")


def _fit_score_set(split: S.DataSplit, groups: list[str], model_name: str,
                   cfg, seed: int) -> dict:
    """Fit one detector on one feature set; return its scores and operating pt.

    Scores for validation and test are kept so a later paired bootstrap can
    re-threshold them per resample without refitting. The threshold is the one
    calibrated on VALIDATION to the FPR budget, then applied to TEST.
    """
    feats = K.features_for_groups(groups)
    Xtr, ytr, Xval, yval, Xte, yte = split.matrices(feats)

    det = R.by_name(model_name, cfg, seed=seed)
    det.fit(Xtr, ytr)
    s_val = R.positive_score(det, Xval)
    s_test = R.positive_score(det, Xte)

    target = cfg.evaluation.target_fpr
    at_budget = T.evaluate_at_budget(yval, s_val, yte, s_test, target_fpr=target)
    return {
        "groups": list(groups),
        "features": feats,
        "n_features": len(feats),
        "threshold": at_budget["calibration"]["threshold"],
        "calibration": at_budget["calibration"],
        "test": at_budget["test"],
        "fpr_drift_test_minus_target": at_budget["fpr_drift_test_minus_target"],
        "_s_val": s_val,
        "_s_test": s_test,
        "_y_val": yval,
        "_y_test": yte,
    }


def run_incremental(df: pd.DataFrame, *, cfg=None, seed: int = 42,
                    model_name: str = R.RANDOM_FOREST) -> dict:
    """Run the build-up experiment for one detector at one seed.

    Returns a structured result: the split diagnostics, each feature set's
    operating point at the FPR budget, and — the headline — the paired,
    device-level bootstrap of the recall difference between each augmented set
    and the base set.
    """
    cfg = cfg or load_config()
    work = trainable(df)
    split = S.make_split(
        work,
        strategy=cfg.evaluation.split_strategy,
        seed=seed,
        test_size=cfg.evaluation.test_size,
        val_size=cfg.evaluation.val_size,
        min_windows_per_device=cfg.evaluation.min_windows_per_device,
    )
    g_test = split.groups("test")
    unit = cfg.evaluation.bootstrap_unit
    n_boot = cfg.evaluation.n_bootstrap

    sets = cfg.incremental.sets.as_dict()
    base_name = "base (infection+payload)"
    if base_name not in sets:
        # Fall back to the configured base_groups if the canonical key was
        # renamed, so the experiment never silently compares against the wrong
        # reference set.
        base_groups = list(cfg.incremental.base_groups)
        base_name = next((k for k, v in sets.items() if list(v) == base_groups),
                         None)
        if base_name is None:
            raise ValueError(
                "incremental.sets has no base set matching incremental."
                f"base_groups={cfg.incremental.base_groups}")

    fitted = {name: _fit_score_set(split, groups, model_name, cfg, seed)
              for name, groups in sets.items()}
    base = fitted[base_name]

    comparisons = {}
    for name, res in fitted.items():
        if name == base_name:
            continue
        # Paired difference at each set's OWN calibrated threshold: augmented set
        # A at thr_A, base at thr_base, both at their 1%-FPR operating point.
        thr_pair = (res["threshold"], base["threshold"])
        per_metric = {}
        for metric in (HEADLINE_METRIC, *SECONDARY_METRICS):
            per_metric[metric] = B.bootstrap_difference(
                base["_y_test"], res["_s_test"], base["_s_test"], g_test,
                metric=metric, threshold=thr_pair, n_resamples=n_boot,
                unit=unit, seed=seed)
        comparisons[name] = {
            "vs": base_name,
            "delta": per_metric,
            "added_groups": sorted(set(res["groups"]) - set(base["groups"])),
        }

    return {
        "track": "B (mock)",
        "model": model_name,
        "seed": seed,
        "headline_metric": HEADLINE_METRIC,
        "fpr_budget": cfg.evaluation.target_fpr,
        "split": split.diagnostics,
        "operating_points": {
            name: {"n_features": r["n_features"],
                   "threshold": r["threshold"],
                   "test": r["test"],
                   "fpr_drift": r["fpr_drift_test_minus_target"]}
            for name, r in fitted.items()},
        "base_set": base_name,
        "comparisons": comparisons,
        "verdict": _verdict(comparisons),
        "provenance": provenance_note(cfg),
    }


def _verdict(comparisons: dict) -> dict:
    """Summarise the headline: does ANY augmented set beat base distinguishably?

    "Distinguishable" = the recall-difference CI excludes zero AND lies above it.
    Reported flatly; a null verdict is the honest finding, not a failure to fix.
    """
    distinguishable = []
    for name, c in comparisons.items():
        d = c["delta"][HEADLINE_METRIC]
        if not d["includes_zero"] and (d["ci_low"] > 0.0):
            distinguishable.append(name)
    return {
        "any_distinguishable_improvement": bool(distinguishable),
        "sets_beating_base": distinguishable,
        "reading": (
            "At least one augmented set improves recall beyond sampling noise."
            if distinguishable else
            "No augmented set improves recall beyond sampling noise at this FPR "
            "budget; the novel groups add no distinguishable detection value on "
            "Track B. This is the study's headline finding."),
    }


def run_model_comparison(df: pd.DataFrame, *, cfg=None, seed: int = 42,
                         groups: list[str] | None = None) -> dict:
    """Threshold-matched comparison of ALL detectors on one feature set.

    Every detector is calibrated to the same FPR budget on validation and scored
    on the locked test set, so the table answers "at the same false-alarm cost,
    who catches more?". Defaults to the full 4-group feature set.
    """
    cfg = cfg or load_config()
    groups = groups or ["infection", "payload", "resolution", "relay"]
    feats = K.features_for_groups(groups)
    work = trainable(df)
    split = S.make_split(
        work, strategy=cfg.evaluation.split_strategy, seed=seed,
        test_size=cfg.evaluation.test_size, val_size=cfg.evaluation.val_size,
        min_windows_per_device=cfg.evaluation.min_windows_per_device)
    Xtr, ytr, Xval, yval, Xte, yte = split.matrices(feats)

    rows = {}
    for name, det in R.build_all(cfg, seed=seed).items():
        det.fit(Xtr, ytr)
        s_val = R.positive_score(det, Xval)
        s_test = R.positive_score(det, Xte)
        at = T.evaluate_at_budget(yval, s_val, yte, s_test,
                                  target_fpr=cfg.evaluation.target_fpr)
        rows[name] = {
            "threshold": at["calibration"]["threshold"],
            "val_fpr_achieved": at["calibration"]["val_fpr_achieved"],
            "test": at["test"],
            "fpr_drift": at["fpr_drift_test_minus_target"],
        }
    return {
        "track": "B (mock)",
        "feature_groups": groups,
        "n_features": len(feats),
        "fpr_budget": cfg.evaluation.target_fpr,
        "seed": seed,
        "detectors": rows,
        "split": {k: split.diagnostics[k] for k in
                  ("n_train", "n_val", "n_test", "group_overlap_count")},
        "provenance": provenance_note(cfg),
    }


def run_drop_one(df: pd.DataFrame, *, cfg=None, seed: int = 42,
                 model_name: str = R.RANDOM_FOREST) -> dict:
    """Diagnostic: from the FULL feature set, drop each group and measure loss.

    Read only alongside the build-up. When groups correlate, a small drop-one
    loss for a novel group does NOT prove it is useless — its signal may be
    carried by a correlated base feature. Reported with that caveat attached.
    """
    cfg = cfg or load_config()
    all_groups = ["infection", "payload", "resolution", "relay"]
    work = trainable(df)
    split = S.make_split(
        work, strategy=cfg.evaluation.split_strategy, seed=seed,
        test_size=cfg.evaluation.test_size, val_size=cfg.evaluation.val_size,
        min_windows_per_device=cfg.evaluation.min_windows_per_device)
    g_test = split.groups("test")

    full = _fit_score_set(split, all_groups, model_name, cfg, seed)
    drops = {}
    for grp in all_groups:
        kept = [g for g in all_groups if g != grp]
        red = _fit_score_set(split, kept, model_name, cfg, seed)
        d = B.bootstrap_difference(
            full["_y_test"], full["_s_test"], red["_s_test"], g_test,
            metric=HEADLINE_METRIC,
            threshold=(full["threshold"], red["threshold"]),
            n_resamples=cfg.evaluation.n_bootstrap,
            unit=cfg.evaluation.bootstrap_unit, seed=seed)
        drops[grp] = {
            "dropped_group": grp,
            "kept_groups": kept,
            "full_recall": full["test"]["recall"],
            "reduced_recall": red["test"]["recall"],
            "delta_recall_full_minus_reduced": d,
        }
    return {
        "track": "B (mock)",
        "model": model_name,
        "seed": seed,
        "metric": HEADLINE_METRIC,
        "full_operating_point": full["test"],
        "drops": drops,
        "caveat": (
            "Drop-one loss is a lower bound on a group's value under correlation:"
            " a redundant-but-real group can be dropped cheaply because a "
            "correlated base feature carries its signal. Interpret with the "
            "build-up result, which is the headline."),
        "provenance": provenance_note(cfg),
    }


def run_lab_only_sensitivity(df: pd.DataFrame, *, cfg=None, seed: int = 42,
                             model_name: str = R.RANDOM_FOREST) -> dict:
    """Report the full-feature operating point WITH and WITHOUT lab-only features.

    Some features (e.g. ``rc4_string_score``) need plaintext payload inspection
    and are not observable from encrypted traffic in a real deployment. A
    headline recall that quietly depends on them would overstate what a fielded
    detector could do. This refits the detector on the full set and on the
    deployable-only set (both calibrated to the same FPR budget) and reports the
    recall a real deployment would forfeit by not having them.
    """
    cfg = cfg or load_config()
    full_feats = K.features_for_groups(["infection", "payload",
                                        "resolution", "relay"])
    lab_only = [f for f in full_feats if f in set(K.LAB_ONLY_FEATURES)]
    deployable = [f for f in full_feats if f not in set(K.LAB_ONLY_FEATURES)]
    work = trainable(df)
    split = S.make_split(
        work, strategy=cfg.evaluation.split_strategy, seed=seed,
        test_size=cfg.evaluation.test_size, val_size=cfg.evaluation.val_size,
        min_windows_per_device=cfg.evaluation.min_windows_per_device)

    def _operating_point(feats: list[str]) -> dict:
        Xtr, ytr, Xval, yval, Xte, yte = split.matrices(feats)
        det = R.by_name(model_name, cfg, seed=seed).fit(Xtr, ytr)
        at = T.evaluate_at_budget(
            yval, R.positive_score(det, Xval),
            yte, R.positive_score(det, Xte),
            target_fpr=cfg.evaluation.target_fpr)
        return at["test"]

    with_lab = _operating_point(full_feats)
    without_lab = _operating_point(deployable)
    d_recall = round(with_lab["recall"] - without_lab["recall"], 6)
    return {
        "track": "B (mock)",
        "model": model_name,
        "seed": seed,
        "metric": HEADLINE_METRIC,
        "fpr_budget": cfg.evaluation.target_fpr,
        "lab_only_features": lab_only,
        "with_lab_only": with_lab,
        "deployable_only": without_lab,
        "recall_delta_lab_minus_deployable": d_recall,
        "reading": (
            f"Removing lab-only feature(s) {lab_only} changes recall by "
            f"{-d_recall:+.4f} at the {cfg.evaluation.target_fpr:.0%} FPR budget. "
            "The deployable-only number is the one a fielded detector on "
            "encrypted traffic could achieve; the WITH figure is lab-ceiling."),
        "provenance": provenance_note(cfg),
    }


def _aggregate_seed_deltas(per_seed: dict, seeds: list[int],
                           set_names: list[str]) -> dict:
    """Collect each augmented set's headline delta across seeds.

    A single seed's null could be an artefact of one particular device split. A
    null that holds across every seed is a robust finding; a "win" that appears
    in only some seeds is seed-sensitive and must not be sold as real. This
    tallies, per set, the point deltas and how many seeds found a distinguishable
    improvement.
    """
    agg = {}
    for name in set_names:
        deltas = [per_seed[s]["comparisons"][name]["delta"][HEADLINE_METRIC]
                  for s in seeds]
        points = [d["point"] for d in deltas]
        distinguishable = sum(
            1 for d in deltas
            if (not d["includes_zero"]) and (d["ci_low"] > 0.0))
        agg[name] = {
            "delta_points": [round(float(p), 6) for p in points],
            "mean_delta": round(float(np.mean(points)), 6),
            "min_delta": round(float(np.min(points)), 6),
            "max_delta": round(float(np.max(points)), 6),
            "seeds_distinguishable": int(distinguishable),
            "n_seeds": len(seeds),
        }
    return agg


def run_incremental_multiseed(df: pd.DataFrame, *, cfg=None, seeds=None,
                              model_name: str = R.RANDOM_FOREST) -> dict:
    """Run the headline build-up across several split seeds and aggregate.

    Reports, per augmented set, the spread of the recall delta and the count of
    seeds in which it was distinguishable from zero — turning "the null held on
    seed 42" into "the null held on all N seeds", which is the claim the paper
    can actually make.
    """
    cfg = cfg or load_config()
    seeds = [int(s) for s in (seeds if seeds is not None else cfg.seeds.split)]
    if not seeds:
        raise ValueError("run_incremental_multiseed needs at least one seed")

    per_seed = {s: run_incremental(df, cfg=cfg, seed=s, model_name=model_name)
                for s in seeds}
    base_set = per_seed[seeds[0]]["base_set"]
    set_names = list(per_seed[seeds[0]]["comparisons"].keys())
    agg = _aggregate_seed_deltas(per_seed, seeds, set_names)

    robust_wins = [n for n, a in agg.items()
                   if a["seeds_distinguishable"] == a["n_seeds"]]
    any_win = [n for n, a in agg.items() if a["seeds_distinguishable"] > 0]
    if robust_wins:
        reading = (f"Set(s) {robust_wins} improve recall in ALL {len(seeds)} "
                   "seeds — a robust improvement.")
    elif any_win:
        reading = (f"Improvement appears for {any_win} in only some seeds and is "
                   "not robust to the split seed; treated as no reliable gain.")
    else:
        reading = (f"No augmented set improves recall in ANY of the {len(seeds)} "
                   "seeds; the null result is robust to the split seed. This is "
                   "the study's headline finding.")

    return {
        "track": "B (mock)",
        "model": model_name,
        "seeds": seeds,
        "headline_metric": HEADLINE_METRIC,
        "fpr_budget": cfg.evaluation.target_fpr,
        "base_set": base_set,
        "per_set": agg,
        "recall_by_seed": {
            s: {name: per_seed[s]["operating_points"][name]["test"]["recall"]
                for name in per_seed[s]["operating_points"]}
            for s in seeds},
        "verdict": {
            "robust_improvement_sets": robust_wins,
            "seed_sensitive_sets": [n for n in any_win if n not in robust_wins],
            "robust_null": not any_win,
            "reading": reading,
        },
        "provenance": provenance_note(cfg),
    }
