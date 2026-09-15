"""
tests/test_experiment.py — the headline experiment's plumbing and guards.

The scientific finding (novel groups add no distinguishable value) is produced
and checked on the real generated Track B dataset, not here. These tests pin the
EXPERIMENT MACHINERY so a green run can be trusted:

  * run_incremental returns an operating point for every configured feature set
    and a paired-bootstrap comparison of each against the base.
  * Every set is calibrated to the SAME FPR budget, so the comparison is
    honest (recall at matched false-alarm cost), and the achieved test FPR is
    reported.
  * The two-track guard fires: an experiment can never run on pooled tracks.
  * The verdict object is well-formed and its reading matches the intervals.
"""
from __future__ import annotations

import unittest
import warnings

import numpy as np
import pandas as pd

from src.evaluate import experiment as E
from src.evaluate import splits as S
from src.schema import columns as K
from tests.helpers import mock_frame, iot23_frame


def separable_track_b(n_benign_dev=60, n_mal_dev=30, windows_per=6, seed=0):
    """A single-track Track B frame with enough devices to split, and mild
    separation so the models are non-degenerate. Malicious devices carry
    elevated base-group features; the novel groups are left at benign levels so
    the experiment has something to (correctly) find no value in."""
    rng = np.random.default_rng(seed)
    nb, nm = n_benign_dev * windows_per, n_mal_dev * windows_per
    ben = mock_frame(nb, research_class=K.CLS_BENIGN_MOCK, device_prefix="ben",
                     n_devices=n_benign_dev)
    mal = mock_frame(nm, research_class=K.CLS_COMBINED_MOCK, device_prefix="mal",
                     n_devices=n_mal_dev)
    # Elevate base-group signal on malicious rows only.
    mal.loc[:, "scan_rate"] = np.clip(rng.normal(7.0, 1.0, nm), 0, 10)
    mal.loc[:, "beacon_interval"] = np.clip(rng.normal(45.0, 5.0, nm), 0, None)
    mal.loc[:, "login_burst_count"] = np.clip(rng.normal(6.0, 1.0, nm), 0, None)
    return pd.concat([ben, mal], ignore_index=True)


class RunIncremental(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore")
        cls.df = separable_track_b()
        cls.res = E.run_incremental(cls.df, seed=42, model_name="RandomForest")

    def test_every_feature_set_has_an_operating_point(self):
        ops = self.res["operating_points"]
        self.assertEqual(set(ops), {
            "base (infection+payload)", "base + resolution",
            "base + relay", "base + resolution + relay"})
        for name, op in ops.items():
            for k in ("precision", "recall", "f1", "fpr"):
                self.assertIn(k, op["test"])

    def test_every_augmented_set_is_compared_against_base(self):
        comps = self.res["comparisons"]
        self.assertNotIn(self.res["base_set"], comps)
        for name, c in comps.items():
            self.assertEqual(c["vs"], self.res["base_set"])
            d = c["delta"]["recall"]
            self.assertIn("includes_zero", d)
            self.assertLessEqual(d["ci_low"], d["ci_high"])

    def test_fpr_budget_is_approximately_held_on_test(self):
        # Calibrated to 1%; test drift is reported and should be modest, not wild.
        for op in self.res["operating_points"].values():
            self.assertLess(op["test"]["fpr"], 0.10)

    def test_verdict_reading_matches_intervals(self):
        v = self.res["verdict"]
        any_beat = v["any_distinguishable_improvement"]
        recomputed = any(
            (not c["delta"]["recall"]["includes_zero"])
            and c["delta"]["recall"]["ci_low"] > 0.0
            for c in self.res["comparisons"].values())
        self.assertEqual(any_beat, recomputed)


class ModelComparisonAndGuards(unittest.TestCase):
    def test_model_comparison_covers_available_detectors(self):
        warnings.simplefilter("ignore")
        mc = E.run_model_comparison(separable_track_b(), seed=42)
        self.assertIn("RandomForest", mc["detectors"])
        self.assertIn("Heuristic", mc["detectors"])
        self.assertEqual(mc["split"]["group_overlap_count"], 0)

    def test_experiment_refuses_pooled_tracks(self):
        pooled = pd.concat([iot23_frame(12, n_devices=6),
                            mock_frame(12, n_devices=6)], ignore_index=True)
        with self.assertRaises(S.SplitError):
            E.run_incremental(pooled, seed=42)


class LabOnlySensitivity(unittest.TestCase):
    def test_reports_both_operating_points_and_delta(self):
        warnings.simplefilter("ignore")
        ls = E.run_lab_only_sensitivity(separable_track_b(), seed=42)
        # rc4_string_score is the declared lab-only feature.
        self.assertEqual(ls["lab_only_features"], list(K.LAB_ONLY_FEATURES))
        for key in ("with_lab_only", "deployable_only"):
            for m in ("recall", "f1", "fpr"):
                self.assertIn(m, ls[key])
        self.assertIsInstance(ls["recall_delta_lab_minus_deployable"], float)


class MultiSeedRobustness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore")
        # Two seeds keep the test quick; the aggregation logic is seed-count
        # agnostic, and the real run uses cfg.seeds.split (five).
        cls.ms = E.run_incremental_multiseed(
            separable_track_b(), seeds=[42, 7], model_name="RandomForest")

    def test_aggregates_every_augmented_set_across_seeds(self):
        per_set = self.ms["per_set"]
        self.assertEqual(set(per_set), {
            "base + resolution", "base + relay", "base + resolution + relay"})
        for a in per_set.values():
            self.assertEqual(a["n_seeds"], 2)
            self.assertEqual(len(a["delta_points"]), 2)
            self.assertLessEqual(a["min_delta"], a["max_delta"])
            self.assertLessEqual(a["seeds_distinguishable"], 2)

    def test_null_is_robust_on_a_noise_only_novel_fixture(self):
        # The novel columns carry no class signal in this fixture, so no set can
        # be distinguishable in any seed and the aggregate null must hold.
        v = self.ms["verdict"]
        self.assertTrue(v["robust_null"])
        self.assertEqual(v["robust_improvement_sets"], [])


if __name__ == "__main__":
    unittest.main()
