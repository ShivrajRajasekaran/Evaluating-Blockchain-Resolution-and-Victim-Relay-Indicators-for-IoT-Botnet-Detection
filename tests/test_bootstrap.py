"""
tests/test_bootstrap.py — confidence intervals resampled BY GROUP.

The one that matters: a grouped bootstrap must produce a WIDER interval than a
row bootstrap on the same correlated data, because windows from one device are
not independent draws. A row bootstrap that treats them as independent reports a
too-narrow interval — and a too-narrow interval around a small difference is
exactly how a null result gets mis-sold as a real improvement.

Also pinned:
  * A paired difference of a detector against itself is exactly zero with a
    degenerate [0, 0] interval that includes zero.
  * The per-array threshold pair (matched-FPR case) is honoured.
  * An all-one-class input cannot form a CI and says so loudly.
"""
from __future__ import annotations

import unittest

import numpy as np

from src.evaluate import bootstrap as B


def correlated_devices():
    """10 devices x 20 identical windows each. 5 malicious (3 detected at 0.9,
    2 missed at 0.1), 5 benign at 0.1. Perfect within-device correlation, so the
    true independent unit is the device, not the window."""
    y, s, g = [], [], []
    detected = {"m0", "m1", "m2"}
    for d in ["m0", "m1", "m2", "m3", "m4"]:
        for _ in range(20):
            y.append(1); s.append(0.9 if d in detected else 0.1); g.append(d)
    for d in ["b0", "b1", "b2", "b3", "b4"]:
        for _ in range(20):
            y.append(0); s.append(0.1); g.append(d)
    return np.array(y), np.array(s, float), np.array(g)


class GroupVsRow(unittest.TestCase):
    def test_group_interval_is_wider_than_row_interval(self):
        y, s, g = correlated_devices()
        grp = B.bootstrap_metric(y, s, g, metric="recall", threshold=0.5,
                                 n_resamples=500, unit="group", seed=1)
        row = B.bootstrap_metric(y, s, g, metric="recall", threshold=0.5,
                                 n_resamples=500, unit="row", seed=1)
        group_width = grp["ci_high"] - grp["ci_low"]
        row_width = row["ci_high"] - row["ci_low"]
        self.assertGreater(group_width, row_width)
        self.assertEqual(grp["n_groups"], 10)
        self.assertIsNone(row["n_groups"])

    def test_point_estimate_is_the_unresampled_metric(self):
        y, s, g = correlated_devices()
        out = B.bootstrap_metric(y, s, g, metric="recall", threshold=0.5,
                                 n_resamples=200, unit="group", seed=1)
        self.assertAlmostEqual(out["point"], 0.6)   # 3 of 5 malicious devices


class PairedDifference(unittest.TestCase):
    def test_detector_against_itself_is_exactly_zero(self):
        y, s, g = correlated_devices()
        out = B.bootstrap_difference(y, s, s, g, metric="f1", threshold=0.5,
                                     n_resamples=200, unit="group", seed=1)
        self.assertEqual(out["point"], 0.0)
        self.assertEqual(out["ci_low"], 0.0)
        self.assertEqual(out["ci_high"], 0.0)
        self.assertTrue(out["includes_zero"])

    def test_per_array_threshold_pair_is_honoured(self):
        # Same scores, different thresholds: A alerts on everything, B on nothing.
        y = np.array([0, 1, 0, 1])
        s = np.full(4, 0.9)
        g = np.array(["d0", "d1", "d2", "d3"])
        out = B.bootstrap_difference(y, s, s, g, metric="recall",
                                     threshold=(0.5, 0.95), n_resamples=100,
                                     unit="group", seed=1)
        # A recall = 1.0 (0.9 >= 0.5), B recall = 0.0 (0.9 < 0.95) -> delta 1.0.
        self.assertAlmostEqual(out["point"], 1.0)
        self.assertFalse(out["includes_zero"])


class Degenerate(unittest.TestCase):
    def test_single_class_cannot_form_ci(self):
        y = np.ones(20, int)
        s = np.linspace(0, 1, 20)
        g = np.repeat(["d0", "d1"], 10)
        with self.assertRaises(ValueError):
            B.bootstrap_metric(y, s, g, metric="recall", threshold=0.5,
                               n_resamples=50, unit="group", seed=1)


if __name__ == "__main__":
    unittest.main()
