"""
ablation.py — feature-group evidence for the project's central claim.

Two protocols live here, and they answer different questions:

  1. run_ablation()      DROP-ONE. Remove one group from the full model.
                         Weak evidence when groups are correlated: if `payload`
                         already separates the classes, dropping `resolution`
                         costs nothing even if resolution is genuinely
                         informative. A ~zero or negative drop is therefore NOT
                         proof that a group is worthless.

  2. run_incremental()   BUILD-UP (headline). Start from a base of generic
                         malware signals (infection + payload) and measure what
                         `resolution` and `relay` ADD on identical splits, with
                         bootstrap confidence intervals. This is the protocol
                         that actually tests "blockchain-resolution and
                         victim-relay indicators carry independent value".

Both select the model on VALIDATION data and score once on the LOCKED test set.
"""
import numpy as np
import pandas as pd

import config as C
from evaluate import (
    load_split, load_split_3way, fit_predict, metric_row, scale_pos_weight,
    bootstrap_f1_ci,
)
from detectors import make_random_forest, make_xgboost, HAS_XGB


# ----------------------------------------------------------------------------
# Model selection — done on validation, never on test
# ----------------------------------------------------------------------------
def select_best_model(X_train, y_train, X_val, y_val, seed=C.RANDOM_SEED):
    """Return (name, factory) for whichever learned model wins on VALIDATION F1.

    The previous version of this file hardcoded XGBoost while its docstring
    claimed to use "the best-performing model" — and RandomForest was in fact
    ahead on the benchmark table. Selecting here, on validation data, removes
    both the inconsistency and the leakage.
    """
    from sklearn.metrics import f1_score

    spw = scale_pos_weight(y_train)
    candidates = {"RandomForest": lambda s: make_random_forest(s)}
    if HAS_XGB:
        candidates["XGBoost"] = lambda s: make_xgboost(s, spw)

    scores = {}
    for name, factory in candidates.items():
        model = factory(seed)
        y_pred, _ = fit_predict(model, X_train, y_train, X_val)
        scores[name] = f1_score(y_val, y_pred, zero_division=0)

    best = max(scores, key=scores.get)
    return best, candidates[best], scores


# ----------------------------------------------------------------------------
# 1. Drop-one ablation (kept, but demoted to a diagnostic)
# ----------------------------------------------------------------------------
def run_ablation(seed=C.RANDOM_SEED):
    rows = []

    # Choose the model ONCE, on the full feature set, using validation data.
    Xtr, Xva, Xte, ytr, yva, yte = load_split_3way(seed=seed)
    best_name, best_factory, val_scores = select_best_model(Xtr, ytr, Xva, yva, seed)

    def eval_with(feature_cols, tag):
        Xtr, Xva, Xte, ytr, yva, yte = load_split_3way(
            seed=seed, feature_cols=feature_cols)
        model = best_factory(seed)
        y_pred, y_score = fit_predict(model, Xtr, ytr, Xte)
        return metric_row(tag, yte, y_pred, y_score)

    full = eval_with(C.FEATURE_COLS, "ALL features")
    full_f1 = full["F1"]
    rows.append({**full, "Dropped_group": "(none)", "F1_drop": 0.0})

    for group in C.FEATURE_GROUPS:
        cols = C.features_excluding(group)
        m = eval_with(cols, f"drop:{group}")
        rows.append({**m, "Dropped_group": group, "F1_drop": full_f1 - m["F1"]})

    df = pd.DataFrame(rows)[
        ["Dropped_group", "Precision", "Recall", "F1", "ROC_AUC", "FPR", "F1_drop"]
    ]
    df.attrs["selected_model"] = best_name
    df.attrs["val_scores"] = val_scores
    return df


# ----------------------------------------------------------------------------
# 2. Incremental value (the honest test of the thesis)
# ----------------------------------------------------------------------------
def run_incremental(seed=C.RANDOM_SEED):
    """Base vs base+resolution vs base+relay vs base+both, identical splits.

    Reports test F1 with a 95% bootstrap CI, and the delta vs the base model.
    Overlapping CIs mean the added group has NOT demonstrated value.
    """
    Xtr, Xva, Xte, ytr, yva, yte = load_split_3way(seed=seed)
    best_name, best_factory, _ = select_best_model(Xtr, ytr, Xva, yva, seed)

    rows = []
    base_f1 = None
    for tag, groups in C.INCREMENT_SETS.items():
        cols = C.features_for_groups(groups)
        Xtr_i, Xva_i, Xte_i, ytr_i, yva_i, yte_i = load_split_3way(
            seed=seed, feature_cols=cols)
        model = best_factory(seed)
        y_pred, y_score = fit_predict(model, Xtr_i, ytr_i, Xte_i)
        m = metric_row(tag, yte_i, y_pred, y_score)
        lo, hi = bootstrap_f1_ci(yte_i, y_pred, seed=seed)

        if base_f1 is None:
            base_f1 = m["F1"]

        rows.append({
            "Feature_set": tag,
            "N_features": len(cols),
            "Precision": m["Precision"],
            "Recall": m["Recall"],
            "F1": m["F1"],
            "F1_CI_low": lo,
            "F1_CI_high": hi,
            "ROC_AUC": m["ROC_AUC"],
            "FPR": m["FPR"],
            "F1_gain_vs_base": m["F1"] - base_f1,
        })

    df = pd.DataFrame(rows)
    df.attrs["selected_model"] = best_name
    return df


# ----------------------------------------------------------------------------
# 3. Lab-only feature sensitivity
# ----------------------------------------------------------------------------
def run_without_lab_only(seed=C.RANDOM_SEED):
    """Full model WITH vs WITHOUT features that need payload/host visibility.

    `rc4_string_score` carried ~47% of gain importance, and it is not observable
    in encrypted traffic. If performance collapses without it, the detector is
    really a payload-signature detector wearing a network-behaviour costume.
    """
    Xtr, Xva, Xte, ytr, yva, yte = load_split_3way(seed=seed)
    best_name, best_factory, _ = select_best_model(Xtr, ytr, Xva, yva, seed)

    net_only = [c for c in C.FEATURE_COLS if c not in C.LAB_ONLY_FEATURES]
    variants = {
        "all features (incl. lab-only)": C.FEATURE_COLS,
        "network-observable only": net_only,
    }

    rows = []
    for tag, cols in variants.items():
        Xtr_i, Xva_i, Xte_i, ytr_i, yva_i, yte_i = load_split_3way(
            seed=seed, feature_cols=cols)
        model = best_factory(seed)
        y_pred, y_score = fit_predict(model, Xtr_i, ytr_i, Xte_i)
        m = metric_row(tag, yte_i, y_pred, y_score)
        lo, hi = bootstrap_f1_ci(yte_i, y_pred, seed=seed)
        rows.append({
            "Feature_set": tag, "N_features": len(cols),
            "Precision": m["Precision"], "Recall": m["Recall"],
            "F1": m["F1"], "F1_CI_low": lo, "F1_CI_high": hi,
            "ROC_AUC": m["ROC_AUC"], "FPR": m["FPR"],
        })

    df = pd.DataFrame(rows)
    df.attrs["selected_model"] = best_name
    return df


if __name__ == "__main__":
    print("--- drop-one (diagnostic) ---")
    print(run_ablation().to_string(index=False))
    print("\n--- incremental value (headline) ---")
    print(run_incremental().to_string(index=False))
    print("\n--- lab-only sensitivity ---")
    print(run_without_lab_only().to_string(index=False))
