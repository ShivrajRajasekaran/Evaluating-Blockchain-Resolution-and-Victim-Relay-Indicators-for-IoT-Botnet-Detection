"""
tests/test_cross_track.py — the one sanctioned crossing, kept honest.

This crossing exists to answer the research question's second clause (low FPR on
REAL benign traffic) and nothing else. The tests pin the properties that keep it
from quietly becoming the forbidden pooling:

  * The used feature set is exactly the both-tracks-computable one: the five
    IoT-23-unavailable features are never in it, and the two proxies are out by
    default (their meaning differs per track) but can be opted in.
  * A real window missing a USED feature abstains and is counted; a window
    missing only an UNUSED (unavailable) feature does not abstain, because that
    feature was never going to be read. Coverage is the honest denominator.
  * FPR is over scored benign rows only — every positive there is a false alarm.
  * The crossing refuses a non-IoT-23 source and refuses any non-benign real row
    (scoring real malicious would re-open the capture-provenance shortcut).
"""
from __future__ import annotations

import unittest
import warnings

import numpy as np

from src.evaluate import cross_track as X
from src.schema import columns as K
from tests.helpers import iot23_frame, mock_frame
from tests.test_experiment import separable_track_b


class FeatureSet(unittest.TestCase):
    def test_excludes_unavailable_always(self):
        feats = set(X.cross_track_features())
        self.assertEqual(feats & set(K.unavailable_features(K.SOURCE_IOT23)),
                         set())

    def test_proxies_out_by_default_in_on_request(self):
        default = set(X.cross_track_features())
        withpx = set(X.cross_track_features(include_proxies=True))
        proxies = set(K.proxy_features(K.SOURCE_IOT23))
        self.assertEqual(default & proxies, set())
        self.assertTrue(proxies <= withpx)


class Crossing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore")
        cls.track_b = separable_track_b()

    def test_clean_benign_frame_has_full_coverage_and_measures_fpr(self):
        real = iot23_frame(120, n_devices=12)   # 5 unavailable feats NaN by build
        rep = X.cross_track_fpr(self.track_b, real, seed=42)
        # The NaN unavailable features are excluded, so they cause no abstention.
        self.assertEqual(rep["n_abstained"], 0)
        self.assertEqual(rep["coverage"], 1.0)
        self.assertIsNotNone(rep["fpr_real_benign"])
        self.assertEqual(rep["n_false_positive"],
                         round(rep["fpr_real_benign"] * rep["n_scored"]))

    def test_missing_used_feature_abstains_and_is_counted(self):
        real = iot23_frame(100, n_devices=10)
        real.loc[:9, "beacon_interval"] = np.nan     # a USED feature, 10 rows
        rep = X.cross_track_fpr(self.track_b, real, seed=42)
        self.assertEqual(rep["n_abstained"], 10)
        self.assertEqual(rep["n_scored"], 90)
        self.assertEqual(rep["abstain_reason_feature_nan_counts"]["beacon_interval"],
                         10)
        self.assertAlmostEqual(rep["coverage"], 0.9)

    def test_fpr_is_over_scored_benign_only(self):
        real = iot23_frame(80, n_devices=8)
        rep = X.cross_track_fpr(self.track_b, real, seed=42)
        # Every scored row is truly benign, so FP count / scored == reported FPR.
        self.assertGreaterEqual(rep["fpr_real_benign"], 0.0)
        self.assertLessEqual(rep["fpr_real_benign"], 1.0)
        self.assertLessEqual(rep["n_false_positive"], rep["n_scored"])


class Guards(unittest.TestCase):
    def setUp(self):
        warnings.simplefilter("ignore")
        self.track_b = separable_track_b()

    def test_refuses_non_iot23_source(self):
        with self.assertRaises(X.CrossTrackError):
            X.cross_track_fpr(self.track_b, mock_frame(10, n_devices=3), seed=42)

    def test_refuses_malicious_real_row(self):
        bad = iot23_frame(12, n_devices=3)
        bad.loc[0, K.RESEARCH_CLASS] = "traditional_c2"
        with self.assertRaises(X.CrossTrackError):
            X.cross_track_fpr(self.track_b, bad, seed=42)

    def test_refuses_empty_real_frame(self):
        with self.assertRaises(X.CrossTrackError):
            X.cross_track_fpr(self.track_b, iot23_frame(4).iloc[0:0], seed=42)


if __name__ == "__main__":
    unittest.main()
