"""
tests/test_metrics.py — the scoreboard's edge cases.

Ordinary metric formulas are not worth testing; the reasons these have tests are
the edges where a naive implementation lies, and this project's headline is a
null result that lives exactly in those edges:

  * FPR is a first-class number, computed over the negative class only.
  * A degenerate prediction yields a defined, honest value (0.0 recall for an
    all-benign detector) rather than a divide-by-zero a caller might swallow.
  * ROC-AUC on a single-class split is None (not measurable), never a filler 0.5
    that reads as "no skill".
"""
from __future__ import annotations

import math
import unittest

from src.evaluate import metrics as M


class ConfusionAndRates(unittest.TestCase):
    def test_confusion_counts_are_plain_ints(self):
        c = M.confusion_counts([0, 0, 0, 1, 1], [1, 0, 0, 1, 0])
        self.assertEqual(c, {"tp": 1, "tn": 2, "fp": 1, "fn": 1})
        self.assertIsInstance(c["tp"], int)

    def test_fpr_is_over_negatives_only(self):
        # 4 benign, 2 malicious; one benign misfires.
        m = M.rate_metrics([0, 0, 0, 0, 1, 1], [1, 0, 0, 0, 1, 1])
        self.assertAlmostEqual(m["fpr"], 0.25)          # 1 of 4 benign
        self.assertAlmostEqual(m["recall"], 1.0)
        self.assertAlmostEqual(m["precision"], 2 / 3, places=5)   # rounded to 6dp
        self.assertEqual(m["n_negative"], 4)
        self.assertEqual(m["n_positive"], 2)

    def test_all_benign_detector_has_zero_recall_not_error(self):
        # Only malicious rows present, detector predicts benign for all.
        m = M.rate_metrics([1, 1, 1], [0, 0, 0])
        self.assertEqual(m["recall"], 0.0)
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["f1"], 0.0)

    def test_fpr_with_no_benign_rows_is_zero_and_flagged_by_count(self):
        m = M.rate_metrics([1, 1], [0, 0])
        self.assertEqual(m["fpr"], 0.0)
        self.assertEqual(m["n_negative"], 0)     # the zero is explained, not hidden

    def test_safe_div_zero_over_zero(self):
        self.assertEqual(M._safe_div(0, 0), 0.0)
        self.assertEqual(M._safe_div(3, 0), 0.0)
        self.assertAlmostEqual(M._safe_div(1, 4), 0.25)


class AUCAndThresholding(unittest.TestCase):
    def test_auc_perfectly_separable_is_one(self):
        self.assertEqual(M.auc([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9]), 1.0)

    def test_auc_single_class_is_none_not_half(self):
        self.assertIsNone(M.auc([1, 1, 1], [0.1, 0.9, 0.5]))
        self.assertIsNone(M.auc([0, 0], [0.2, 0.3]))

    def test_threshold_is_inclusive_on_malicious_side(self):
        # Scores landing exactly on the boundary must alert, not stay benign.
        m = M.score_at_threshold([1, 1], [0.5, 0.5], 0.5)
        self.assertEqual(m["tp"], 2)
        self.assertEqual(m["recall"], 1.0)

    def test_score_at_threshold_carries_threshold_and_auc(self):
        m = M.score_at_threshold([0, 1], [0.2, 0.8], 0.5)
        self.assertEqual(m["threshold"], 0.5)
        self.assertEqual(m["roc_auc"], 1.0)

    def test_summary_line_handles_none_auc(self):
        m = M.score_at_threshold([1, 1], [0.9, 0.9], 0.5)   # single class -> AUC None
        self.assertIn("AUC n/a", M.summary_line(m))
        m2 = M.score_at_threshold([0, 1], [0.2, 0.8], 0.5)
        self.assertIn("AUC 1.000", M.summary_line(m2))


if __name__ == "__main__":
    unittest.main()
