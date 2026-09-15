"""
evaluate/metrics.py — the scoreboard.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

The metrics here are ordinary; the care is in the edge cases, because this
project's headline is a NULL result (novel groups add no distinguishable value)
and a null result is exactly where a naive metric silently lies:

  * FALSE-POSITIVE RATE is a first-class output, not derived on demand. The
    research question fixes a false-positive budget on real benign traffic, so
    FPR = FP / (FP + TN) is reported for every model at every threshold. It is
    computed over the negative class only; a model that abstains on half its
    inputs must not look safer merely because it predicted less.

  * A DEGENERATE PREDICTION (all-benign, all-malicious, one class absent from a
    split) yields a defined, honest number — 0.0 recall for the all-benign
    detector, not a divide-by-zero that a caller might paper over. Where a
    metric is genuinely undefined (ROC-AUC with one class present) the value is
    None and the reason is recorded, never a filler 0.5 that reads as "no skill"
    when it means "not measurable".
"""
from __future__ import annotations

import numpy as np

from sklearn.metrics import roc_auc_score


def confusion_counts(y_true, y_pred) -> dict:
    """The four cells, as plain ints. Everything else is derived from these.

    Positive = malicious (1), negative = benign (0). Keeping the raw counts in
    every result means a reviewer can recompute any rate by hand and catch a
    metric that was averaged the wrong way.
    """
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def _safe_div(num: float, den: float) -> float:
    """0/0 -> 0.0 here, deliberately. Every caller divides by a count of events
    of one class; when that class is absent the rate is reported as 0.0 with the
    supporting count (n=0) alongside, so the zero cannot be mistaken for a
    measured value."""
    return float(num) / float(den) if den else 0.0


def rate_metrics(y_true, y_pred) -> dict:
    """Precision, recall, F1, specificity and — the one that matters here — FPR.

    All derived from the confusion counts so they cannot disagree with them.
    """
    c = confusion_counts(y_true, y_pred)
    tp, tn, fp, fn = c["tp"], c["tn"], c["fp"], c["fn"]
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)          # sensitivity / TPR
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return {
        **c,
        "n_positive": tp + fn,
        "n_negative": tn + fp,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "specificity": round(_safe_div(tn, tn + fp), 6),
        # THE budgeted quantity. FP over all true negatives; undefined-as-0.0
        # only when a split genuinely has no benign rows, in which case
        # n_negative == 0 says so.
        "fpr": round(_safe_div(fp, fp + tn), 6),
    }


def auc(y_true, y_score) -> float | None:
    """ROC-AUC, or None when the split has only one class.

    None, not 0.5. A single-class split makes AUC undefined; filling 0.5 would
    read as "no discrimination" — a measured claim — when the truth is that it
    could not be measured. Callers record the None and move on.
    """
    y_true = np.asarray(y_true).astype(int)
    if len(np.unique(y_true)) < 2:
        return None
    return round(float(roc_auc_score(y_true, np.asarray(y_score, float))), 6)


def score_at_threshold(y_true, y_score, threshold: float) -> dict:
    """Full metric bundle for scores thresholded at ``threshold``.

    ``predict = score >= threshold``. Threshold is inclusive on the malicious
    side so that a model whose scores pile up exactly on the boundary is counted
    as alerting, not as silently benign — the conservative direction for a
    detector.
    """
    y_score = np.asarray(y_score, float)
    y_pred = (y_score >= threshold).astype(int)
    m = rate_metrics(y_true, y_pred)
    m["threshold"] = float(threshold)
    m["roc_auc"] = auc(y_true, y_score)
    return m


def summary_line(m: dict) -> str:
    """One-line human rendering for logs and the mentor demo."""
    a = m.get("roc_auc")
    return (f"P {m['precision']:.3f}  R {m['recall']:.3f}  F1 {m['f1']:.3f}  "
            f"FPR {m['fpr']:.3f}  AUC {a:.3f}" if a is not None else
            f"P {m['precision']:.3f}  R {m['recall']:.3f}  F1 {m['f1']:.3f}  "
            f"FPR {m['fpr']:.3f}  AUC n/a")
