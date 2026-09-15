"""
tests/test_schema_build.py — frame construction and CSV round-tripping.

The round-trip tests exist because ``pd.read_csv`` corrupts this schema in
three quiet ways, none of which raise:

  * ``window_start`` comes back as strings, so a temporal split sorts
    lexicographically and silently produces the wrong ordering
  * an empty ``quality_flags`` cell comes back as NaN, so ``.str.contains``
    returns NaN and every flag check becomes unreliable
  * a numeric-looking ``device_id`` comes back as int64, so grouping keys stop
    matching across files

All three would produce wrong results rather than errors, which is why
read_observations exists and why nothing may use bare read_csv.
"""
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.schema import columns as K
from src.schema import (build_observations, make_observation_id,
                        read_observations, validate_observations,
                        write_observations)
from tests.helpers import (feature_frame, iot23_frame, mock_frame, op_frame,
                          windows)


class TestBuildDerivation(unittest.TestCase):

    def test_derived_columns_are_not_passed_in(self):
        df = mock_frame(4)
        self.assertTrue((df[K.WINDOW_SECONDS] == K.WINDOW_SECONDS_VALUE).all())
        self.assertTrue((df[K.CAPTURE_PROVENANCE] == K.PROV_SYNTHETIC).all())
        self.assertTrue(
            (df[K.LABEL_CONFIDENCE] == K.CONF_SYNTHETIC_GROUND_TRUTH).all())
        self.assertTrue((df[K.LABEL_BINARY] == 0).all())

    def test_column_order_is_canonical(self):
        self.assertEqual(list(mock_frame(2).columns), K.ALL_COLS)

    def test_unavailable_features_are_forced_to_nan(self):
        # The caller supplies real numbers for all 16 features; the five that
        # IoT-23 cannot observe must still come out NaN. This is the single
        # most consequential rule in the schema — a number in a cell the
        # capture never recorded is fabricated evidence.
        df = iot23_frame(4, serverlist_pull=1.0, ens_query_rate=9.9,
                         rc4_string_score=0.8)
        for c in K.unavailable_features(K.SOURCE_IOT23):
            self.assertTrue(df[c].isna().all(), c)
        # ...while the computable ones survive untouched.
        self.assertTrue((df["flow_fanout"] == 3.0).all())

    def test_missing_feature_columns_are_created_as_nan(self):
        partial = feature_frame(3)[["scan_rate", "flow_fanout"]]
        df = build_observations(
            partial,
            source_dataset=K.SOURCE_MOCK_LOCAL,
            device_id=["d0"] * 3,
            window_start=windows(3),
            research_class=[K.CLS_BENIGN_MOCK] * 3,
            original_label=[K.CLS_BENIGN_MOCK] * 3,
            scenario_id="s",
        )
        self.assertEqual(list(df.columns), K.ALL_COLS)
        self.assertTrue((df[K.N_FEATURES_MISSING] == 14).all())

    def test_flags_record_which_features_are_missing(self):
        flags = K.parse_flags(iot23_frame(2)[K.QUALITY_FLAGS].iloc[0])
        self.assertEqual(sorted(flags[K.FLAG_MISSING_FEATURES]),
                         sorted(K.unavailable_features(K.SOURCE_IOT23)))
        self.assertEqual(sorted(flags[K.FLAG_PROXY_FEATURES]),
                         sorted(K.proxy_features(K.SOURCE_IOT23)))

    def test_extra_flags_are_merged(self):
        df = build_observations(
            feature_frame(2),
            source_dataset=K.SOURCE_MOCK_LOCAL,
            device_id=["d0", "d1"],
            window_start=windows(2),
            research_class=[K.CLS_BENIGN_MOCK] * 2,
            original_label=[K.CLS_BENIGN_MOCK] * 2,
            scenario_id="s",
            extra_flags=[{K.FLAG_LOW_FLOW_COUNT: None}, {}],
        )
        self.assertIn(K.FLAG_LOW_FLOW_COUNT,
                      K.parse_flags(df[K.QUALITY_FLAGS].iloc[0]))
        self.assertEqual(df[K.QUALITY_FLAGS].iloc[1], "")

    def test_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            build_observations(
                feature_frame(4),
                source_dataset=K.SOURCE_MOCK_LOCAL,
                device_id=["d0", "d1"],              # 2 != 4
                window_start=windows(4),
                research_class=[K.CLS_BENIGN_MOCK] * 4,
                original_label=[K.CLS_BENIGN_MOCK] * 4,
                scenario_id="s",
            )

    def test_unknown_source_raises(self):
        with self.assertRaises(ValueError):
            build_observations(
                feature_frame(2), source_dataset="nope",
                device_id=["a", "b"], window_start=windows(2),
                research_class=[K.CLS_BENIGN_MOCK] * 2,
                original_label=["x"] * 2, scenario_id="s")

    def test_unknown_research_class_raises(self):
        with self.assertRaises(ValueError):
            build_observations(
                feature_frame(2), source_dataset=K.SOURCE_MOCK_LOCAL,
                device_id=["a", "b"], window_start=windows(2),
                research_class=["invented_class"] * 2,
                original_label=["x"] * 2, scenario_id="s")

    def test_zero_rows_raises(self):
        with self.assertRaises(ValueError):
            build_observations(
                feature_frame(0), source_dataset=K.SOURCE_MOCK_LOCAL,
                device_id=[], window_start=[], research_class=[],
                original_label=[], scenario_id="s")


class TestOperationalBuild(unittest.TestCase):
    """Operational ingest builds unlabelled, provenance-honest frames that still
    pass full schema validation — the proof the schema additions compose."""

    def test_operational_frame_is_unmapped_and_unlabelled(self):
        df = op_frame(4, source_dataset=K.SOURCE_OP_ZEEK)
        self.assertTrue((df[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())
        self.assertTrue((df[K.CAPTURE_PROVENANCE] == K.PROV_REAL_CAPTURE).all())
        self.assertTrue((df[K.LABEL_CONFIDENCE] == K.CONF_UNLABELLED).all())
        # unmapped => the binary view is the -1 sentinel, never 0. Defaulting
        # unknown operational traffic to benign would fabricate a clean baseline.
        self.assertTrue((df[K.LABEL_BINARY] == K.LABEL_BINARY_UNMAPPED).all())

    def test_operational_unavailable_features_forced_nan(self):
        # Same rule as IoT-23: a value the capture never recorded is fabricated.
        df = op_frame(4, source_dataset=K.SOURCE_OP_ZEEK,
                      serverlist_pull=1.0, ens_query_rate=9.9,
                      rc4_string_score=0.8)
        for c in K.unavailable_features(K.SOURCE_OP_ZEEK):
            self.assertTrue(df[c].isna().all(), c)

    def test_operational_rows_flag_unmapped_and_proxies(self):
        df = op_frame(2, source_dataset=K.SOURCE_OP_NETFLOW)
        flags = K.parse_flags(df[K.QUALITY_FLAGS].iloc[0])
        self.assertIn(K.FLAG_UNMAPPED_LABEL, flags)
        self.assertEqual(sorted(flags[K.FLAG_PROXY_FEATURES]),
                         sorted(K.proxy_features(K.SOURCE_OP_NETFLOW)))

    def test_every_operational_source_validates(self):
        for s in K.OPERATIONAL_SOURCES:
            rep = validate_observations(op_frame(4, source_dataset=s))
            self.assertTrue(rep.ok, f"{s} failed validation: {rep.errors}")


class TestObservationId(unittest.TestCase):

    def test_is_deterministic(self):
        # A UUID here would make every regeneration produce a different CSV,
        # which destroys byte-level reproducibility checks and makes diffs
        # useless for reviewing a data change.
        a = mock_frame(4)[K.OBSERVATION_ID].tolist()
        b = mock_frame(4)[K.OBSERVATION_ID].tolist()
        self.assertEqual(a, b)

    def test_encodes_the_natural_key(self):
        oid = make_observation_id("mock_local", "scen-1", "dev-7",
                                  pd.Timestamp("2026-01-06T00:05:00"))
        self.assertEqual(oid, "mock_local|scen-1|dev-7|20260106T000500")

    def test_distinct_windows_give_distinct_ids(self):
        df = mock_frame(12, n_devices=3)
        self.assertEqual(df[K.OBSERVATION_ID].nunique(), 12)


class TestCsvRoundTrip(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "obs.csv"

    def tearDown(self):
        self._tmp.cleanup()

    def test_mock_frame_survives(self):
        original = mock_frame(10, n_devices=2)
        write_observations(original, self.path)
        back = read_observations(self.path)
        self.assertEqual(list(back.columns), K.ALL_COLS)
        pd.testing.assert_frame_equal(
            original.reset_index(drop=True), back.reset_index(drop=True),
            check_dtype=False)

    def test_window_start_returns_as_datetime(self):
        write_observations(mock_frame(4), self.path)
        back = read_observations(self.path)
        self.assertTrue(
            pd.api.types.is_datetime64_any_dtype(back[K.WINDOW_START]))

    def test_empty_quality_flags_returns_as_empty_string_not_nan(self):
        write_observations(mock_frame(4), self.path)
        back = read_observations(self.path)
        self.assertTrue((back[K.QUALITY_FLAGS] == "").all())
        self.assertFalse(back[K.QUALITY_FLAGS].isna().any())

    def test_nan_features_survive_as_nan(self):
        write_observations(iot23_frame(4), self.path)
        back = read_observations(self.path)
        for c in K.unavailable_features(K.SOURCE_IOT23):
            self.assertTrue(back[c].isna().all(), c)
        self.assertTrue((back[K.N_FEATURES_MISSING] == 5).all())

    def test_numeric_device_ids_stay_strings(self):
        df = mock_frame(4, n_devices=2)
        df[K.DEVICE_ID] = ["100", "200", "100", "200"]
        df[K.OBSERVATION_ID] = [
            make_observation_id(K.SOURCE_MOCK_LOCAL, "mock-test-01",
                                d, t)
            for d, t in zip(df[K.DEVICE_ID], df[K.WINDOW_START])
        ]
        write_observations(df, self.path)
        back = read_observations(self.path)
        self.assertTrue(pd.api.types.is_object_dtype(back[K.DEVICE_ID]))
        self.assertEqual(back[K.DEVICE_ID].iloc[0], "100")

    def test_writing_an_invalid_frame_is_refused(self):
        # A malformed frame must fail where it is produced, not three steps
        # later where the cause is no longer visible.
        bad = mock_frame(4)
        bad.loc[0, "failed_conn_ratio"] = 2.0
        with self.assertRaises(Exception):
            write_observations(bad, self.path)
        self.assertFalse(self.path.exists())

    def test_written_file_is_byte_stable(self):
        write_observations(mock_frame(6, n_devices=2), self.path)
        first = self.path.read_bytes()
        write_observations(mock_frame(6, n_devices=2), self.path)
        self.assertEqual(first, self.path.read_bytes())

    def test_round_tripped_frame_still_validates(self):
        write_observations(iot23_frame(6, n_devices=2), self.path)
        self.assertTrue(validate_observations(read_observations(self.path)).ok)


if __name__ == "__main__":
    unittest.main()
