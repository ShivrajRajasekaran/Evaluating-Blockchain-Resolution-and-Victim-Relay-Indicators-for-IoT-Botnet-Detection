"""
evaluate.py — shared evaluation helpers.

Provides:
  - load_split()          : load CSV, stratified train/test split, scaled X
  - metric_row()          : P / R / F1 / ROC-AUC / FPR for one model
  - fit_predict()         : uniform fit + predict + proba for any detector
  - plotting helpers used by run_all.py
"""
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, roc_curve, precision_recall_curve, average_precision_score,
)

import config as C
from detectors import HeuristicDetector


def load_split(csv=C.DATASET_CSV, seed=C.RANDOM_SEED, feature_cols=None):
    """Return X_train, X_test, y_train, y_test as DataFrames/Series.

    Tree models and the heuristic use raw feature values (no scaling needed);
    scaling is applied only where a model benefits. We keep DataFrames so the
    heuristic can address columns by name.

    NOTE: this two-way split is kept for backwards compatibility with the
    original benchmark table. Anything that *selects* a model, a threshold or a
    feature set must use load_split_3way() instead, so the test set stays locked.
    """
    feature_cols = feature_cols or C.FEATURE_COLS
    df = pd.read_csv(csv)
    X = df[feature_cols]
    y = df[C.LABEL_COL]
    return train_test_split(
        X, y, test_size=C.TEST_SIZE, stratify=y, random_state=seed
    )


def load_split_3way(csv=C.DATASET_CSV, seed=C.RANDOM_SEED, feature_cols=None):
    """Train / validation / LOCKED-test split.

    The test set is carved off first and never used for model selection,
    threshold calibration or feature-importance estimation — only for the single
    final score. This removes the model-selection leakage that the earlier
    two-way protocol allowed.

    Returns (X_train, X_val, X_test, y_train, y_val, y_test).
    """
    feature_cols = feature_cols or C.FEATURE_COLS
    df = pd.read_csv(csv)
    X = df[feature_cols]
    y = df[C.LABEL_COL]

    X_fit, X_test, y_fit, y_test = train_test_split(
        X, y, test_size=C.TEST_SIZE, stratify=y, random_state=seed
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_fit, y_fit, test_size=C.VAL_SIZE, stratify=y_fit, random_state=seed
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


def scale_pos_weight(y_train):
    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    return neg / max(pos, 1)


def fit_predict(model, X_train, y_train, X_test):
    """Fit and return (y_pred, y_score). Handles models with/without proba."""
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(X_test)[:, 1]
    else:
        y_score = y_pred.astype(float)
    return y_pred, y_score


def metric_row(name, y_true, y_pred, y_score):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "Model": name,
        "Precision": precision_score(y_true, y_pred, zero_division=0),
        "Recall": recall_score(y_true, y_pred, zero_division=0),
        "F1": f1_score(y_true, y_pred, zero_division=0),
        "ROC_AUC": roc_auc_score(y_true, y_score),
        "FPR": fpr,
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
    }


# ----------------------------------------------------------------------------
# Threshold-matched comparison
# ----------------------------------------------------------------------------
def threshold_at_fpr(y_val, score_val, target_fpr=C.TARGET_FPR):
    """Smallest score threshold whose VALIDATION FPR is <= target_fpr.

    Comparing a rule-based detector at 'vote >= 3' against a tree model at
    'p >= 0.5' compares two arbitrary operating points, so the winner is partly
    an artefact of those two constants. Instead every detector is pinned to the
    same false-positive budget on validation data, and only then scored on the
    locked test set.
    """
    fpr, _tpr, thr = roc_curve(y_val, score_val)
    ok = np.where(fpr <= target_fpr)[0]
    if len(ok) == 0:                      # cannot meet the budget at all
        return float(np.max(score_val)) + 1e-9
    # roc_curve returns thresholds in decreasing order; take the most permissive
    # threshold that still satisfies the budget (largest index among `ok`).
    t = thr[ok[-1]]
    return float(t)


def metrics_at_threshold(name, y_true, y_score, threshold):
    """Score a detector at an explicitly chosen operating point."""
    y_pred = (np.asarray(y_score) >= threshold).astype(int)
    row = metric_row(name, y_true, y_pred, y_score)
    row["Threshold"] = threshold
    return row


# ----------------------------------------------------------------------------
# Uncertainty
# ----------------------------------------------------------------------------
def bootstrap_f1_ci(y_true, y_pred, n_boot=C.N_BOOTSTRAP, seed=C.RANDOM_SEED,
                    alpha=0.05):
    """Percentile bootstrap 95% CI for F1 on a single test set.

    This quantifies sampling uncertainty of the test set ONLY. It says nothing
    about generator uncertainty or about generalisation to real traffic.
    """
    rng = np.random.default_rng(seed)
    y_true = np.asarray(y_true)
    y_pred = np.asarray(y_pred)
    n = len(y_true)
    stats = np.empty(n_boot)
    for i in range(n_boot):
        idx = rng.integers(0, n, n)
        stats[i] = f1_score(y_true[idx], y_pred[idx], zero_division=0)
    lo = float(np.percentile(stats, 100 * alpha / 2))
    hi = float(np.percentile(stats, 100 * (1 - alpha / 2)))
    return lo, hi
