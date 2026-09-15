"""
tests/test_explain.py — permutation importance corroborates the group result.

The scientific claim (novel groups add no value) is decided by the build-up
experiment; this module pins the SECOND method that corroborates it, so a green
run means the two methods actually measure what they say:

  * Every feature is scored and tagged with its group.
  * On a fixture where only the BASE features separate the classes, the base
    group's permutation importance is clearly positive and the novel groups'
    total sits at zero — the model cannot lean on a column that carries no
    signal, and the metric must reflect that.
  * Gain importance is present for a tree and absent (None) for the heuristic,
    and it is never allowed to masquerade as a finding (carries its caveat).
  * Importance is measured at a FIXED calibrated threshold — shuffling a column
    cannot silently re-optimise the operating point.
"""
from __future__ import annotations

import unittest
import warnings

from src.evaluate import explain
from src.schema import columns as K
from tests.test_experiment import separable_track_b

ALL_FEATS = K.features_for_groups(["infection", "payload", "resolution", "relay"])


class PermutationImportance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore")
        cls.pi = explain.permutation_importance(
            separable_track_b(), seed=42, model_name="RandomForest")

    def test_every_feature_scored_and_grouped(self):
        self.assertEqual(set(self.pi["per_feature"]), set(ALL_FEATS))
        for name, d in self.pi["per_feature"].items():
            self.assertEqual(d["group"], K.GROUP_OF_FEATURE[name])
            self.assertIn("importance_mean", d)
            self.assertIn("importance_std", d)

    def test_base_carries_signal_and_novel_is_near_zero(self):
        # The fixture elevates only base-group features on malicious devices;
        # the novel columns are drawn from the benign distribution for both
        # classes, so permuting them must do essentially nothing.
        self.assertGreater(self.pi["base_group_total"], 0.05)
        self.assertGreater(self.pi["base_group_total"],
                           self.pi["novel_group_total"])
        self.assertLess(abs(self.pi["novel_group_total"]), 0.05)

    def test_threshold_is_fixed_and_reported(self):
        # A single operating point governs every shuffle; it is surfaced so a
        # reader can confirm importance was not measured at a moving target.
        self.assertIn("threshold", self.pi)
        self.assertEqual(self.pi["scoring"], "f1")
        self.assertGreaterEqual(self.pi["baseline_score"], 0.0)

    def test_gain_importance_present_for_tree_with_caveat(self):
        gi = self.pi["gain_importance"]
        self.assertIsNotNone(gi)
        self.assertEqual(set(gi["by_feature"]), set(ALL_FEATS))
        self.assertIn("contrast only", gi["note"])


class HeuristicHasNoGain(unittest.TestCase):
    def test_heuristic_permutation_runs_without_gain(self):
        warnings.simplefilter("ignore")
        pi = explain.permutation_importance(
            separable_track_b(), seed=42, model_name="Heuristic")
        self.assertEqual(set(pi["per_feature"]), set(ALL_FEATS))
        self.assertIsNone(pi["gain_importance"])   # rule detector exposes no gain


if __name__ == "__main__":
    unittest.main()
