"""
tests/test_splits.py — the LOCKED-test protocol and its invariants.

The split is where a leak becomes an inflated result, so the invariants are
asserted, not assumed:

  * GROUPED. No device_id appears in more than one split. This is the property
    the whole strategy exists for; if it ever fails, every downstream number is
    optimistic. Tested directly on the returned index sets.
  * TEMPORAL. Train windows precede test windows in time, and the split reports
    how many devices span the boundary (allowed here, unlike grouped).
  * RANDOM. Emits a warning, because it leaks devices and must never quietly
    back a new claim.
  * TWO TRACKS. A frame pooling real and mock rows is refused — the split is the
    last line of defence behind the schema validator.
  * UNMAPPED. matrices() refuses a frame that still carries unmapped rows.
"""
from __future__ import annotations

import unittest
import warnings

import numpy as np
import pandas as pd

from src.evaluate import splits as S
from src.schema import columns as K
from tests.helpers import mock_frame, iot23_frame


def mixed_mock(n_benign_dev=30, n_mal_dev=12, windows_per=4):
    """A single-track (Track B) frame: benign and malicious devices, disjoint
    device id namespaces, a fixed number of windows each."""
    b = mock_frame(n_benign_dev * windows_per, research_class=K.CLS_BENIGN_MOCK,
                   device_prefix="ben", n_devices=n_benign_dev)
    m = mock_frame(n_mal_dev * windows_per, research_class=K.CLS_COMBINED_MOCK,
                   device_prefix="mal", n_devices=n_mal_dev)
    return pd.concat([b, m], ignore_index=True)


class GroupedSplit(unittest.TestCase):
    def setUp(self):
        self.df = mixed_mock()

    def test_no_device_in_two_splits(self):
        sp = S.make_split(self.df, strategy="group", seed=42)
        tr = set(sp.groups("train"))
        va = set(sp.groups("val"))
        te = set(sp.groups("test"))
        self.assertEqual(tr & va, set())
        self.assertEqual(tr & te, set())
        self.assertEqual(va & te, set())
        self.assertEqual(sp.diagnostics["group_overlap_count"], 0)

    def test_both_classes_present_in_every_split(self):
        sp = S.make_split(self.df, strategy="group", seed=42)
        for which in ("train", "val", "test"):
            y = self.df.iloc[getattr(sp, f"{which}_idx")][K.LABEL_BINARY]
            self.assertIn(0, set(y.tolist()))
            self.assertIn(1, set(y.tolist()))

    def test_matrices_shapes_and_feature_order(self):
        sp = S.make_split(self.df, strategy="group", seed=42)
        feats = K.features_for_groups(["infection", "payload"])
        Xtr, ytr, Xv, yv, Xte, yte = sp.matrices(feats)
        self.assertEqual(list(Xtr.columns), feats)      # exact requested order
        self.assertEqual(len(Xtr), len(ytr))
        self.assertEqual(len(Xtr) + len(Xv) + len(Xte), len(self.df))

    def test_matrices_rejects_missing_feature(self):
        sp = S.make_split(self.df, strategy="group", seed=42)
        with self.assertRaises(S.SplitError):
            sp.matrices(["not_a_feature"])

    def test_matrices_rejects_unmapped_rows(self):
        sp = S.make_split(self.df, strategy="group", seed=42)
        sp.frame.loc[0, K.LABEL_BINARY] = K.LABEL_BINARY_UNMAPPED
        with self.assertRaises(S.SplitError):
            sp.matrices(K.features_for_groups(["payload"]))


class TemporalSplit(unittest.TestCase):
    def test_train_precedes_test_in_time(self):
        df = mixed_mock()
        sp = S.make_split(df, strategy="temporal", seed=42)
        ts = df[K.WINDOW_START]
        train_max = ts.iloc[sp.train_idx].max()
        test_min = ts.iloc[sp.test_idx].min()
        self.assertLessEqual(train_max, test_min)
        self.assertIn("devices_spanning_boundary", sp.diagnostics)


class RandomSplit(unittest.TestCase):
    def test_random_split_warns(self):
        df = mixed_mock()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            S.make_split(df, strategy="random", seed=42)
        self.assertTrue(any("random" in str(w.message).lower() for w in caught))


class Guards(unittest.TestCase):
    def test_pooling_two_tracks_is_refused(self):
        # A Track A benign frame plus a Track B benign frame -> two tracks.
        pooled = pd.concat([iot23_frame(8, n_devices=4),
                            mock_frame(8, n_devices=4)], ignore_index=True)
        with self.assertRaises(S.SplitError):
            S.make_split(pooled, strategy="group", seed=42)

    def test_unknown_strategy_raises(self):
        with self.assertRaises(S.SplitError):
            S.make_split(mixed_mock(), strategy="nope", seed=42)

    def test_empty_frame_raises(self):
        with self.assertRaises(S.SplitError):
            S.make_split(mock_frame(4).iloc[0:0], strategy="group", seed=42)

    def test_min_windows_per_device_drops_and_reports(self):
        # 30 benign devices x 4 windows, plus one benign device with a single
        # window; a floor of 2 should drop exactly that device.
        df = mixed_mock(n_benign_dev=30, n_mal_dev=12, windows_per=4)
        singleton = mock_frame(1, research_class=K.CLS_BENIGN_MOCK,
                               device_prefix="solo", n_devices=1)
        df = pd.concat([df, singleton], ignore_index=True)
        sp = S.make_split(df, strategy="group", seed=42,
                          min_windows_per_device=2)
        self.assertEqual(sp.diagnostics["devices_dropped_min_windows"], 1)
        self.assertEqual(sp.diagnostics["rows_dropped_min_windows"], 1)


if __name__ == "__main__":
    unittest.main()
