"""
tests/test_schema_validate.py — the validator, especially the two-track rule.

The tests in TestTwoTrackRule are the most important in the project. They are
the mechanism that turns "do not pool real and mock observations" from advice
in a design document into something the code refuses to do.

Why it deserves this much test coverage: IoT-23 was captured before
blockchain-anchored C2 existed, so its rows physically cannot carry
blockchain-resolution or victim-relay behaviour. A model trained on
real-benign + mock-malicious separates the classes using capture artefacts —
TTL, MTU, clock resolution, byte-count granularity — and returns a high F1.
That failure produces no error, no warning and no visible symptom. It just
produces a number that looks like success and measures which file a row came
from. A test suite is the only place it can be caught.
"""
import unittest

import numpy as np
import pandas as pd

from src.schema import columns as K
from src.schema import (SchemaError, assert_valid, build_observations,
                        trainable, validate_observations)
from tests.helpers import feature_frame, iot23_frame, mock_frame, windows


class TestValidFrames(unittest.TestCase):

    def test_mock_frame_is_valid(self):
        rep = validate_observations(mock_frame(6))
        self.assertTrue(rep.ok, rep.summary())

    def test_iot23_frame_is_valid_with_expected_warnings(self):
        rep = validate_observations(iot23_frame(6))
        self.assertTrue(rep.ok, rep.summary())
        # Five features are unavailable for IoT-23, so every row is missing
        # cells and carries a proxy feature. Both must be surfaced, not hidden.
        self.assertTrue(any("approximation" in w for w in rep.warnings),
                        rep.warnings)

    def test_stats_are_collected(self):
        rep = validate_observations(mock_frame(8, n_devices=4))
        self.assertEqual(rep.stats["devices"], 4)
        self.assertEqual(rep.stats["windows_per_device"], 2.0)

    def test_all_malicious_mock_classes_validate(self):
        for cls in (K.CLS_BLOCKCHAIN_RESOLUTION_MOCK, K.CLS_VICTIM_RELAY_MOCK,
                    K.CLS_COMBINED_MOCK):
            rep = validate_observations(mock_frame(4, research_class=cls))
            self.assertTrue(rep.ok, f"{cls}: {rep.summary()}")

    def test_all_track_a_classes_validate(self):
        for cls in K.TRACK_A_CLASSES:
            rep = validate_observations(iot23_frame(4, research_class=cls))
            self.assertTrue(rep.ok, f"{cls}: {rep.summary()}")


class TestTwoTrackRule(unittest.TestCase):
    """Each test here corresponds to one way the tracks could get crossed."""

    def test_pooling_real_and_mock_is_rejected(self):
        # The exact mistake the original build instruction's §5 would have
        # produced: one merged frame feeding one multi-class model.
        pooled = pd.concat([iot23_frame(4), mock_frame(4)], ignore_index=True)
        rep = validate_observations(pooled)
        self.assertFalse(rep.ok)
        self.assertTrue(any("TWO-TRACK VIOLATION" in e and "pools" in e
                            for e in rep.errors), rep.errors)

    def test_pooling_real_benign_with_mock_malicious_is_rejected(self):
        # The most seductive version: it looks like a balanced dataset.
        pooled = pd.concat([
            iot23_frame(4, research_class=K.CLS_BENIGN_REAL),
            mock_frame(4, research_class=K.CLS_COMBINED_MOCK),
        ], ignore_index=True)
        self.assertFalse(validate_observations(pooled).ok)

    def test_mock_source_carrying_a_real_class_is_rejected(self):
        df = mock_frame(4)
        df[K.RESEARCH_CLASS] = K.CLS_TRADITIONAL_C2
        df[K.LABEL_BINARY] = 1          # keep labels self-consistent
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("TWO-TRACK VIOLATION" in e for e in rep.errors),
                        rep.errors)

    def test_real_source_carrying_a_mock_class_is_rejected(self):
        # Labelling an IoT-23 flow as blockchain C2 — explicitly forbidden.
        df = iot23_frame(4)
        df[K.RESEARCH_CLASS] = K.CLS_BLOCKCHAIN_RESOLUTION_MOCK
        df[K.LABEL_BINARY] = 1
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("TWO-TRACK VIOLATION" in e for e in rep.errors),
                        rep.errors)

    def test_provenance_must_match_source(self):
        df = mock_frame(4)
        df[K.CAPTURE_PROVENANCE] = K.PROV_REAL_CAPTURE
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("capture_provenance" in e for e in rep.errors),
                        rep.errors)

    def test_label_confidence_must_match_source(self):
        # Claiming a dataset annotation for a self-generated label, or vice
        # versa. Different kinds of evidence with different error rates.
        df = mock_frame(4)
        df[K.LABEL_CONFIDENCE] = K.CONF_DATASET_ANNOTATED
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("label_confidence" in e for e in rep.errors),
                        rep.errors)

    def test_same_track_concatenation_is_allowed(self):
        # Two mock scenarios in one frame is legitimate and must stay so.
        df = pd.concat([
            mock_frame(4, scenario_id="mock-a", device_prefix="a"),
            mock_frame(4, research_class=K.CLS_VICTIM_RELAY_MOCK,
                       scenario_id="mock-b", device_prefix="b"),
        ], ignore_index=True)
        self.assertTrue(validate_observations(df).ok)


class TestAvailabilityEnforcement(unittest.TestCase):

    def test_imputing_an_unavailable_feature_is_rejected(self):
        df = iot23_frame(4)
        df["serverlist_pull"] = 0.0        # a value the capture never recorded
        df[K.N_FEATURES_MISSING] = df[K.FEATURE_COLS].isna().sum(axis=1)
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("invents evidence" in e for e in rep.errors),
                        rep.errors)

    def test_missing_features_must_be_flagged(self):
        df = mock_frame(4)
        df.loc[0, "scan_rate"] = np.nan
        df.loc[0, K.N_FEATURES_MISSING] = 1
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any(K.FLAG_MISSING_FEATURES in e for e in rep.errors),
                        rep.errors)

    def test_n_features_missing_must_match_reality(self):
        df = mock_frame(4)
        df.loc[0, K.N_FEATURES_MISSING] = 3
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(
            any(K.N_FEATURES_MISSING in e and "disagrees" in e
                for e in rep.errors), rep.errors)

    def test_iot23_rows_declare_five_missing_features(self):
        df = iot23_frame(4)
        self.assertTrue((df[K.N_FEATURES_MISSING] == 5).all())


class TestLabelConsistency(unittest.TestCase):

    def test_label_binary_must_agree_with_research_class(self):
        df = mock_frame(4, research_class=K.CLS_BENIGN_MOCK)
        df.loc[0, K.LABEL_BINARY] = 1
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("disagrees" in e for e in rep.errors), rep.errors)

    def test_unmapped_rows_warn_and_are_excluded_from_training(self):
        df = build_observations(
            feature_frame(4),
            source_dataset=K.SOURCE_IOT23,
            device_id=["d0", "d0", "d1", "d1"],
            window_start=windows(4),
            research_class=[K.CLS_BENIGN_REAL, K.CLS_UNMAPPED,
                            K.CLS_BENIGN_REAL, K.CLS_UNMAPPED],
            original_label=["Benign", "PartOfAHorizontalPortScan&Attack",
                            "Benign", "SomethingNew"],
            scenario_id="CTU-IoT-Malware-Capture-TEST-1",
        )
        rep = validate_observations(df)
        self.assertTrue(rep.ok, rep.summary())
        self.assertTrue(any(K.CLS_UNMAPPED in w for w in rep.warnings),
                        rep.warnings)
        self.assertEqual(len(trainable(df)), 2)
        self.assertEqual(
            set(df.loc[df[K.RESEARCH_CLASS] == K.CLS_UNMAPPED, K.LABEL_BINARY]),
            {K.LABEL_BINARY_UNMAPPED})

    def test_unmapped_rows_must_carry_the_flag(self):
        df = build_observations(
            feature_frame(2),
            source_dataset=K.SOURCE_IOT23,
            device_id=["d0", "d1"],
            window_start=windows(2),
            research_class=[K.CLS_UNMAPPED, K.CLS_BENIGN_REAL],
            original_label=["?", "Benign"],
            scenario_id="s",
        )
        df.loc[0, K.QUALITY_FLAGS] = ""      # strip the flag
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any(K.FLAG_UNMAPPED_LABEL in e for e in rep.errors),
                        rep.errors)


class TestStructuralChecks(unittest.TestCase):

    def test_missing_column_is_rejected(self):
        df = mock_frame(4).drop(columns=[K.DEVICE_ID])
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("missing required column" in e for e in rep.errors))

    def test_duplicate_observation_id_is_rejected(self):
        df = mock_frame(4)
        df.loc[1, K.OBSERVATION_ID] = df.loc[0, K.OBSERVATION_ID]
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("duplicate id" in e for e in rep.errors))

    def test_unknown_enum_value_is_rejected(self):
        df = mock_frame(4)
        df[K.SOURCE_DATASET] = "some_other_dataset"
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(
            any("controlled vocabulary" in e for e in rep.errors), rep.errors)

    def test_unknown_quality_flag_is_rejected(self):
        df = mock_frame(4)
        df.loc[0, K.QUALITY_FLAGS] = "invented_flag"
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("unknown flag" in e for e in rep.errors))

    def test_wrong_window_size_is_rejected(self):
        df = mock_frame(4)
        df[K.WINDOW_SECONDS] = 60
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("fixes the window" in e for e in rep.errors))

    def test_string_window_start_is_rejected(self):
        # Guards the read_observations() path: a CSV read with plain read_csv
        # gives strings here, and a temporal split would then sort them
        # lexicographically without complaining.
        df = mock_frame(4)
        df[K.WINDOW_START] = df[K.WINDOW_START].astype(str)
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("datetime64" in e for e in rep.errors))

    def test_empty_frame_is_rejected(self):
        rep = validate_observations(mock_frame(4).iloc[0:0])
        self.assertFalse(rep.ok)

    def test_assert_valid_raises_with_every_problem_listed(self):
        df = mock_frame(4)
        df[K.SOURCE_DATASET] = "bogus"
        df.loc[1, K.OBSERVATION_ID] = df.loc[0, K.OBSERVATION_ID]
        with self.assertRaises(SchemaError) as ctx:
            assert_valid(df)
        msg = str(ctx.exception)
        self.assertIn("controlled vocabulary", msg)
        self.assertIn("duplicate id", msg)


class TestFeatureRanges(unittest.TestCase):

    def test_negative_value_is_rejected(self):
        df = mock_frame(4, scan_rate=-1.0)
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("below minimum" in e for e in rep.errors))

    def test_ratio_above_one_is_rejected(self):
        df = mock_frame(4, failed_conn_ratio=1.5)
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("above maximum" in e for e in rep.errors))

    def test_non_binary_value_in_binary_feature_is_rejected(self):
        df = mock_frame(4, serverlist_pull=0.5)
        rep = validate_observations(df)
        self.assertFalse(rep.ok)
        self.assertTrue(any("declared binary" in e for e in rep.errors))

    def test_infinity_is_rejected(self):
        df = mock_frame(4)
        df.loc[0, "bidir_flow_duration"] = np.inf
        rep = validate_observations(df)
        self.assertFalse(rep.ok)


class TestGroupedSplitWarning(unittest.TestCase):

    def test_one_window_per_device_warns(self):
        # The prototype's implicit situation. A grouped split over
        # one-window-per-device devices is a random split wearing a costume, and
        # reporting it as cross-device generalisation would overstate the result.
        df = mock_frame(4, n_devices=4)
        rep = validate_observations(df)
        self.assertTrue(rep.ok)
        self.assertTrue(any("grouped split" in w for w in rep.warnings),
                        rep.warnings)

    def test_many_windows_per_device_does_not_warn(self):
        rep = validate_observations(mock_frame(20, n_devices=2))
        self.assertFalse(any("grouped split" in w for w in rep.warnings),
                         rep.warnings)


if __name__ == "__main__":
    unittest.main()
