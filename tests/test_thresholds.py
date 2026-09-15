"""
tests/test_thresholds.py — calibrating every detector to one FPR budget.

The budget is a CEILING, and these tests pin the ceiling behaviour:

  * With distinct scores the calibrated threshold admits exactly
    floor(target * n_benign) false positives.
  * A coarse score (many ties) admits FEWER — never more — so the achieved FPR
    can sit below target, and that is correct, not a bug to round away.
  * A 0% budget puts the threshold above the highest benign score, so recall is
    whatever the malicious scores support: the true cost of the budget, reported.
  * No benign rows -> cannot calibrate -> a loud error, not a silent 0.5.
"""
from __future__ import annotations

import unittest

import numpy as np

from src.evaluate import thresholds as T


class ThresholdForFPR(unittest.TestCase):
    def test_distinct_scores_admit_floor_k_false_positives(self):
        neg = np.linspace(0.1, 1.0, 10)          # 10 distinct benign scores
        thr = T.threshold_for_fpr(neg, 0.1)      # k = floor(0.1*10) = 1
        admitted = int(np.sum(neg >= thr))
        self.assertEqual(admitted, 1)

    def test_zero_budget_admits_no_benign(self):
        neg = np.linspace(0.1, 1.0, 10)
        thr = T.threshold_for_fpr(neg, 0.0)
        self.assertEqual(int(np.sum(neg >= thr)), 0)
        self.assertGreater(thr, neg.max())

    def test_full_budget_admits_every_benign(self):
        neg = np.linspace(0.1, 1.0, 10)
        thr = T.threshold_for_fpr(neg, 1.0)
        self.assertEqual(int(np.sum(neg >= thr)), 10)

    def test_ties_keep_fpr_at_or_below_target(self):
        # Coarse score: five 0.5s and five 0.1s. target 0.3 -> k=3, but the
        # threshold just above 0.5 admits 0 (all are 0.5 or 0.1), never 3.
        neg = np.array([0.5] * 5 + [0.1] * 5)
        thr = T.threshold_for_fpr(neg, 0.3)
        self.assertLessEqual(np.mean(neg >= thr), 0.3)

    def test_no_benign_rows_raises(self):
        with self.assertRaises(T.ThresholdError):
            T.threshold_for_fpr([], 0.1)

    def test_out_of_range_target_raises(self):
        with self.assertRaises(T.ThresholdError):
            T.threshold_for_fpr([0.1, 0.2], 1.5)


class CalibrateAndEvaluate(unittest.TestCase):
    def test_calibrate_achieves_fpr_at_or_below_target(self):
        y = np.array([0] * 10 + [1] * 10)
        s = np.concatenate([np.linspace(0.0, 0.9, 10),      # benign, low-ish
                            np.linspace(0.6, 1.0, 10)])      # malicious, high-ish
        cal = T.calibrate(y, s, target_fpr=0.1)
        self.assertLessEqual(cal["val_fpr_achieved"], 0.1 + 1e-9)
        self.assertIn("threshold", cal)

    def test_evaluate_at_budget_reports_drift(self):
        rng = np.random.default_rng(0)
        yv = np.array([0] * 50 + [1] * 50)
        sv = np.concatenate([rng.uniform(0.0, 0.5, 50), rng.uniform(0.5, 1.0, 50)])
        yt = np.array([0] * 50 + [1] * 50)
        st = np.concatenate([rng.uniform(0.0, 0.5, 50), rng.uniform(0.5, 1.0, 50)])
        out = T.evaluate_at_budget(yv, sv, yt, st, target_fpr=0.1)
        self.assertIn("calibration", out)
        self.assertIn("test", out)
        self.assertAlmostEqual(
            out["fpr_drift_test_minus_target"],
            round(out["test"]["fpr"] - 0.1, 6))

    def test_no_benign_in_validation_raises(self):
        with self.assertRaises(T.ThresholdError):
            T.calibrate([1, 1, 1], [0.2, 0.8, 0.9], target_fpr=0.1)


if __name__ == "__main__":
    unittest.main()
