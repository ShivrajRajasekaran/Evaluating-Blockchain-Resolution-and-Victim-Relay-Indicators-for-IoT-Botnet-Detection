"""
tests/test_models.py — the three detectors behind one interface.

What is worth testing here is not that a RandomForest can learn — sklearn's job —
but the contract this project layered on top:

  * The heuristic degrades to the rules it can still evaluate when columns are
    missing (the incremental experiment fits it on feature subsets), and a NaN
    feature casts no vote (absence of evidence, never a spurious alert).
  * The tree wrapper reindexes to the trained column order, so a caller passing
    columns in a different order cannot get silently wrong predictions.
  * A NaN reaching a tree RAISES rather than being imputed to a number.
  * XGBoost's absence is graceful: the registry omits it, nothing crashes.
  * positive_score is the single place the "column 1 is malicious" convention
    lives.
"""
from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from src.models import registry as R
from src.models import trees
from src.models.heuristic import HeuristicDetector
from src.schema import columns as K
from tests.helpers import feature_frame

ALL_FEATS = K.features_for_groups(["infection", "payload", "resolution", "relay"])
BASE_FEATS = K.features_for_groups(["infection", "payload"])


class Heuristic(unittest.TestCase):
    def test_votes_count_only_rules_that_fire(self):
        # One row tuned to trip exactly three rules: upnp, serverlist, ens.
        X = feature_frame(1, serverlist_pull=1.0, upnp_addportmapping=1.0,
                          ens_query_rate=9.0,
                          # keep the other four rule-features below threshold
                          beacon_interval=5.0, updownlink_ratio=0.1,
                          login_burst_count=0.0, rc4_string_score=0.0)
        h = HeuristicDetector(vote_threshold=3).fit(X)
        self.assertEqual(int(h.votes(X)[0]), 3)
        self.assertEqual(int(h.predict(X)[0]), 1)          # 3 >= 3

    def test_missing_columns_reduce_active_rules(self):
        X = feature_frame(2)[BASE_FEATS]      # only base columns present
        h = HeuristicDetector(vote_threshold=3).fit(X)
        # Of the 7 rules, only beacon_interval, login_burst_count, rc4_string
        # live in the base groups.
        self.assertEqual(h.n_active_rules(), 3)
        p = h.predict_proba(X)
        self.assertTrue(np.all((p >= 0.0) & (p <= 1.0)))
        self.assertEqual(p.shape, (2, 2))

    def test_nan_feature_casts_no_vote(self):
        X = feature_frame(1, ens_query_rate=9.0)     # would fire the ENS rule
        X.loc[:, "ens_query_rate"] = np.nan          # ...but it is not measurable
        h = HeuristicDetector(vote_threshold=1).fit(X)
        reasons = h.explain(X)[0]
        self.assertNotIn("high blockchain-name query rate", reasons)

    def test_predict_proba_is_fraction_of_active_rules(self):
        X = feature_frame(1, serverlist_pull=1.0, upnp_addportmapping=0.0,
                          ens_query_rate=0.0, beacon_interval=5.0,
                          updownlink_ratio=0.1, login_burst_count=0.0,
                          rc4_string_score=0.0)
        h = HeuristicDetector(vote_threshold=3).fit(X)   # 7 active rules
        self.assertAlmostEqual(h.predict_proba(X)[0, 1], 1 / 7)


class Trees(unittest.TestCase):
    def _xy(self, n=60):
        rng = np.random.default_rng(0)
        X = feature_frame(n)
        # Make a learnable target from one feature, so fit/predict is meaningful.
        y = (np.arange(n) % 2).astype(int)
        X.loc[:, "scan_rate"] = np.where(y == 1, 8.0, 0.5) + rng.normal(0, 0.01, n)
        return X, y

    def test_random_forest_fits_and_scores(self):
        X, y = self._xy()
        det = trees.make_random_forest(seed=42)
        det.fit(X, y)
        proba = det.predict_proba(X)
        self.assertEqual(proba.shape, (len(X), 2))
        self.assertEqual(set(np.unique(det.predict(X))) <= {0, 1}, True)

    def test_column_order_is_realigned_at_predict(self):
        X, y = self._xy()
        det = trees.make_random_forest(seed=42).fit(X, y)
        shuffled = X[list(reversed(list(X.columns)))]     # same data, new order
        np.testing.assert_array_equal(det.predict(X), det.predict(shuffled))

    def test_nan_in_features_raises_not_imputed(self):
        X, y = self._xy()
        det = trees.make_random_forest(seed=42)
        Xn = X.copy()
        Xn.loc[0, "beacon_jitter"] = np.nan
        with self.assertRaises(trees.NaNInFeaturesError):
            det.fit(Xn, y)


class Registry(unittest.TestCase):
    def test_build_all_keys_match_availability(self):
        built = R.build_all(seed=42)
        self.assertIn(R.HEURISTIC, built)
        self.assertIn(R.RANDOM_FOREST, built)
        self.assertEqual(R.XGBOOST in built, trees.xgboost_available())

    def test_xgboost_absence_is_graceful(self):
        if trees.xgboost_available():
            self.skipTest("xgboost present; absence path not exercised here")
        with self.assertRaises(trees.ModelUnavailableError):
            trees.make_xgboost(seed=42)

    def test_positive_score_is_one_dimensional(self):
        X = feature_frame(5)
        det = R.by_name(R.HEURISTIC)
        s = R.positive_score(det.fit(X), X)
        self.assertEqual(s.ndim, 1)
        self.assertEqual(len(s), 5)

    def test_unknown_detector_name_raises(self):
        with self.assertRaises(ValueError):
            R.by_name("NotADetector")


if __name__ == "__main__":
    unittest.main()
