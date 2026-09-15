"""
evaluate/thresholds.py — pin every detector to one false-positive budget.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

THE PROBLEM THIS SOLVES
-----------------------
A heuristic firing at "3 of N rules agree", a random forest at "p >= 0.5" and a
gradient booster at "p >= 0.5" are three different operating points chosen by
three different conventions. Comparing their F1 scores compares those
conventions as much as the models. One model can be made to "win" by nudging its
own default.

The fix, applied uniformly: choose each detector's threshold on the VALIDATION
split so that all of them sit at the same false-positive rate on benign traffic
— the budget the research question names (default 1%). Then score every detector
on the LOCKED test split at its own calibrated threshold. Now the comparison is
"at the same false-alarm cost, who catches more?", which is the question a
deployment actually faces.

WHY CALIBRATE ON VALIDATION, NOT TEST
-------------------------------------
A threshold chosen on the test set to hit exactly 1% FPR has used the test set's
labels, so the test FPR it reports is not an estimate of anything future — it is
a fit. Calibrating on validation and then measuring on test means the test FPR
can drift from the budget, and that drift is itself reported: it is the honest
generalisation gap of the calibration, not something to hide.
"""
from __future__ import annotations

import numpy as np

from src.evaluate import metrics as M


class ThresholdError(ValueError):
    """A threshold cannot be calibrated from the given validation data."""


def threshold_for_fpr(neg_scores, target_fpr: float) -> float:
    """Smallest threshold whose FPR on ``neg_scores`` does not exceed target.

    ``neg_scores`` are the model's scores on the BENIGN (true-negative)
    validation rows. Predict-malicious is ``score >= threshold``, so the
    threshold returned admits at most ``floor(target_fpr * n_benign)`` benign
    rows as false positives. Under ties it admits fewer, never more: the budget
    is a ceiling, and exceeding it to hit it exactly would defeat the purpose.
    """
    neg = np.sort(np.asarray(neg_scores, float))[::-1]   # descending
    n = neg.size
    if n == 0:
        raise ThresholdError(
            "no benign rows in the validation split, so a false-positive rate "
            "cannot be calibrated; check the split's class balance")
    if not 0.0 <= target_fpr <= 1.0:
        raise ThresholdError(f"target_fpr must be in [0, 1], got {target_fpr}")

    k = int(np.floor(target_fpr * n))     # benign we are allowed to misfire on
    if k <= 0:
        # Zero budget: the threshold must sit strictly above the highest benign
        # score. Recall then falls to whatever the malicious scores support —
        # possibly zero. That is the true cost of a 0% budget on overlapping
        # distributions, and it is reported rather than softened.
        return float(np.nextafter(neg[0], np.inf))
    if k >= n:
        # Budget admits every benign row (target >= 1); threshold below all.
        return float(np.nextafter(neg[-1], -np.inf))
    # Admit only scores strictly greater than the (k+1)-th highest benign score.
    # With distinct scores that is exactly k false positives; with ties it is
    # fewer, keeping FPR <= target.
    return float(np.nextafter(neg[k], np.inf))


def calibrate(y_val, s_val, *, target_fpr: float) -> dict:
    """Calibrate one detector on validation scores.

    Returns the chosen threshold and the operating point it actually achieves on
    the validation split — the achieved FPR can be below target when the score
    is coarse (a rule detector's integer vote count cannot land on 1% exactly),
    and reporting it stops that coarseness from being mistaken for a tuning win.
    """
    y_val = np.asarray(y_val).astype(int)
    s_val = np.asarray(s_val, float)
    neg = s_val[y_val == 0]
    thr = threshold_for_fpr(neg, target_fpr)
    achieved = M.score_at_threshold(y_val, s_val, thr)
    return {
        "threshold": thr,
        "target_fpr": float(target_fpr),
        "val_fpr_achieved": achieved["fpr"],
        "val_recall_achieved": achieved["recall"],
        "val_precision_achieved": achieved["precision"],
        "score_is_coarse": bool(np.unique(neg).size <= 20),
    }


def evaluate_at_budget(y_val, s_val, y_test, s_test, *,
                       target_fpr: float) -> dict:
    """Calibrate on validation, score on the locked test set, report both.

    The returned dict carries the calibration, the test metrics at the
    calibrated threshold, and the drift between the budgeted FPR and the FPR
    actually seen on test — the number that says whether the calibration
    generalised.
    """
    cal = calibrate(y_val, s_val, target_fpr=target_fpr)
    test = M.score_at_threshold(y_test, s_test, cal["threshold"])
    return {
        "calibration": cal,
        "test": test,
        "fpr_drift_test_minus_target": round(test["fpr"] - target_fpr, 6),
    }
