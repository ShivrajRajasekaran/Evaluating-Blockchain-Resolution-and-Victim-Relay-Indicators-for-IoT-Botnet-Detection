"""
tests/test_windowing.py — the flow table contract and the window grid.

Windowing is the layer where a bug is least likely to announce itself. A
misaligned grid, a silently coerced column, or a groupby whose row order differs
from the index's does not raise; it produces a full result table with features
attached to the wrong labels. So these tests check the two things that would
otherwise pass unnoticed:

  * the grid is ABSOLUTE, not capture-relative — verified by trimming flows off
    the front of a table and asserting the surviving windows keep their
    boundaries
  * validation REFUSES bad input rather than repairing it
"""
from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from src.features import windowing as W
from src.schema import columns as K
from tests.helpers import flow_table


class TestFlowTableContract(unittest.TestCase):
    def test_a_valid_table_passes(self):
        W.validate_flow_table(flow_table(6))

    def test_helper_produces_exactly_the_contract_columns(self):
        # If the helper and the contract drift apart, every other test in this
        # module and test_derive.py is exercising a table the adapter will never
        # produce.
        self.assertEqual(list(flow_table(3).columns), W.FLOW_COLS)

    def test_missing_column_is_rejected_by_name(self):
        bad = flow_table(4).drop(columns=[W.F_RESP_PKTS])
        with self.assertRaises(W.FlowTableError) as cm:
            W.validate_flow_table(bad)
        self.assertIn(W.F_RESP_PKTS, str(cm.exception))

    def test_string_timestamps_are_rejected_not_parsed(self):
        # Parsing here would be convenient and wrong: a reader that emitted
        # strings has probably also lost sub-second precision or timezone, and
        # silently fixing the dtype hides that.
        bad = flow_table(4)
        bad[W.F_TS] = bad[W.F_TS].astype(str)
        with self.assertRaises(W.FlowTableError):
            W.validate_flow_table(bad)

    def test_null_timestamp_is_rejected(self):
        bad = flow_table(4)
        bad.loc[2, W.F_TS] = pd.NaT
        with self.assertRaises(W.FlowTableError):
            W.validate_flow_table(bad)

    def test_string_byte_counts_are_rejected(self):
        bad = flow_table(4)
        bad[W.F_ORIG_BYTES] = bad[W.F_ORIG_BYTES].astype(str)
        with self.assertRaises(W.FlowTableError):
            W.validate_flow_table(bad)

    def test_negative_counts_are_rejected(self):
        # Zeek writes "-" for an unset field. A reader that mapped it to -1
        # instead of NaN would make every sum wrong by an amount that depends on
        # how many fields were unset.
        for col in (W.F_ORIG_BYTES, W.F_DURATION, W.F_RESP_PKTS):
            bad = flow_table(4)
            bad.loc[1, col] = -1.0
            with self.assertRaises(W.FlowTableError, msg=col):
                W.validate_flow_table(bad)

    def test_empty_table_is_rejected(self):
        with self.assertRaises(W.FlowTableError):
            W.validate_flow_table(flow_table(3).iloc[0:0])

    def test_null_device_id_is_rejected(self):
        bad = flow_table(4)
        bad.loc[0, W.F_DEVICE_ID] = None
        with self.assertRaises(W.FlowTableError):
            W.validate_flow_table(bad)


class TestWindowGrid(unittest.TestCase):
    def test_window_start_is_floored_to_the_300s_grid(self):
        w = W.assign_windows(flow_table(4, ts="2026-01-06T00:07:43",
                                        gap_seconds=1.0))
        self.assertTrue((w[W.WINDOW_START] ==
                         pd.Timestamp("2026-01-06T00:05:00")).all())

    def test_every_window_start_is_a_multiple_of_the_window_length(self):
        w = W.assign_windows(flow_table(50, ts="2026-01-06T03:17:11",
                                        gap_seconds=37.0))
        epoch_seconds = (w[W.WINDOW_START].astype("int64") // 10**9)
        self.assertTrue((epoch_seconds % K.WINDOW_SECONDS_VALUE == 0).all())

    def test_flows_split_across_the_boundary_land_in_different_windows(self):
        flows = flow_table(2, ts=["2026-01-06T00:04:59", "2026-01-06T00:05:01"])
        w = W.assign_windows(flows)
        self.assertEqual(w[W.WINDOW_START].nunique(), 2)

    def test_grid_is_absolute_not_capture_relative(self):
        # THE POINT OF THE WHOLE DESIGN. Drop the first three flows and the
        # remaining flows must keep the window boundaries they already had. With
        # a capture-relative grid every boundary would shift, so observation_ids
        # would change between a full run and a partial re-run of the same
        # capture, and the two could not be compared.
        full = W.assign_windows(
            flow_table(12, ts="2026-01-06T00:00:00", gap_seconds=90.0))
        trimmed = W.assign_windows(
            flow_table(12, ts="2026-01-06T00:00:00", gap_seconds=90.0).iloc[3:])
        pd.testing.assert_series_equal(
            full[W.WINDOW_START].iloc[3:], trimmed[W.WINDOW_START])

    def test_assign_windows_does_not_mutate_its_input(self):
        flows = flow_table(4)
        W.assign_windows(flows)
        self.assertNotIn(W.WINDOW_START, flows.columns)

    def test_assign_windows_validates(self):
        with self.assertRaises(W.FlowTableError):
            W.assign_windows(flow_table(4).drop(columns=[W.F_PROTO]))


class TestWindowIndex(unittest.TestCase):
    """The diagnostics that drive the quality flags."""

    def setUp(self):
        # dev-a: 6 flows, 30 s apart, two peers, all bidirectional.
        a = flow_table(6, device_id="dev-a", ts="2026-01-06T00:00:00",
                       gap_seconds=30.0,
                       dst_ip=["10.0.0.1"] * 4 + ["10.0.0.2"] * 2)
        # dev-b: 1 flow, one peer, one-way (no response bytes).
        b = flow_table(1, device_id="dev-b", ts="2026-01-06T00:00:10",
                       resp_bytes=0.0)
        self.w = W.assign_windows(pd.concat([a, b], ignore_index=True))
        self.idx = W.window_index(self.w)

    def test_one_row_per_device_window(self):
        self.assertEqual(len(self.idx), 2)
        self.assertEqual(set(self.idx[W.F_DEVICE_ID]), {"dev-a", "dev-b"})

    def test_counts_and_span(self):
        a = self.idx.set_index(W.F_DEVICE_ID).loc["dev-a"]
        self.assertEqual(a["n_flows"], 6)
        self.assertEqual(a["n_peers"], 2)
        self.assertEqual(a["span_seconds"], 150.0)   # 5 gaps of 30 s
        self.assertEqual(a["n_bidir"], 6)

    def test_span_is_zero_for_a_single_flow_window(self):
        b = self.idx.set_index(W.F_DEVICE_ID).loc["dev-b"]
        self.assertEqual(b["n_flows"], 1)
        self.assertEqual(b["span_seconds"], 0.0)

    def test_one_way_flows_are_not_counted_as_bidirectional(self):
        b = self.idx.set_index(W.F_DEVICE_ID).loc["dev-b"]
        self.assertEqual(b["n_bidir"], 0)

    def test_outbound_flows_are_counted_separately(self):
        # scan_rate is derived from n_outbound, so this count is the one index
        # column a feature depends on directly.
        mixed = W.assign_windows(flow_table(
            6, device_id="mix", outbound=[True, True, False, False, True, False]))
        idx = W.window_index(mixed)
        self.assertEqual(idx["n_flows"].iloc[0], 6)
        self.assertEqual(idx["n_outbound"].iloc[0], 3)

    def test_requires_assign_windows_first(self):
        with self.assertRaises(W.FlowTableError):
            W.window_index(flow_table(4))

    def test_index_row_order_is_deterministic(self):
        # derive.py reindexes onto this order, so if it varied between calls the
        # features and the labels could be attached to different windows on two
        # runs of the same input.
        again = W.window_index(self.w.sample(frac=1.0, random_state=1))
        pd.testing.assert_frame_equal(self.idx, again)


class TestQualityFlags(unittest.TestCase):
    def setUp(self):
        thin = flow_table(2, device_id="thin", ts="2026-01-06T00:00:00",
                          gap_seconds=1.0)                  # burst, 1 peer
        busy = flow_table(10, device_id="busy", ts="2026-01-06T00:00:00",
                          gap_seconds=25.0,
                          dst_ip=[f"10.0.0.{i}" for i in range(10)])
        self.idx = W.window_index(
            W.assign_windows(pd.concat([thin, busy], ignore_index=True)))
        self.flags = W.window_quality_flags(
            self.idx, min_flows=3, min_span_seconds=60.0)
        self.by_dev = dict(zip(self.idx[W.F_DEVICE_ID], self.flags))

    def test_one_flag_dict_per_row(self):
        self.assertEqual(len(self.flags), len(self.idx))

    def test_thin_burst_window_gets_all_three_flags(self):
        self.assertEqual(set(self.by_dev["thin"]),
                         {K.FLAG_LOW_FLOW_COUNT, K.FLAG_SINGLE_PEER,
                          K.FLAG_SHORT_WINDOW})

    def test_healthy_window_gets_no_flags(self):
        self.assertEqual(self.by_dev["busy"], {})

    def test_single_flow_window_is_not_called_short(self):
        # One flow has span 0 by arithmetic, not by bursting. Flagging it
        # SHORT_WINDOW would make the flag mean two different things and inflate
        # its rate in the coverage report.
        one = W.window_index(W.assign_windows(flow_table(1, device_id="one")))
        f = W.window_quality_flags(one, min_flows=3, min_span_seconds=60.0)[0]
        self.assertIn(K.FLAG_LOW_FLOW_COUNT, f)
        self.assertNotIn(K.FLAG_SHORT_WINDOW, f)

    def test_flag_names_exist_in_the_schema(self):
        for f in self.flags:
            for name in f:
                self.assertIn(name, K.QUALITY_FLAG_NAMES)


class TestCoverageReport(unittest.TestCase):
    def test_reports_what_windowing_did(self):
        flows = pd.concat([
            # 8 flows a minute apart -> 00:00 window gets 5, 00:05 window gets 3
            flow_table(8, device_id="d1", ts="2026-01-06T00:00:00",
                       gap_seconds=60.0),
            flow_table(4, device_id="d2", ts="2026-01-06T02:00:00",
                       gap_seconds=30.0, resp_bytes=0.0),
        ], ignore_index=True)
        w = W.assign_windows(flows)
        rep = W.coverage_report(w, W.window_index(w))
        self.assertEqual(rep["flows"], 12)
        self.assertEqual(rep["devices"], 2)
        self.assertEqual(rep["windows"], 3)   # d1 spans 2 windows, d2 spans 1
        self.assertEqual(rep["windows_with_no_bidir_flow"], 1)
        # d1's first flow at 00:00:00 to d2's last at 02:01:30
        self.assertAlmostEqual(rep["capture_span_hours"], 2.0 + 90 / 3600, 4)

    def test_reports_the_inbound_share(self):
        # Six of eleven derivable features are outbound-only, so a capture that
        # is mostly inbound leaves them near-empty. The report has to say so
        # before anyone interprets those six.
        flows = pd.concat([
            flow_table(3, device_id="d1", outbound=True),
            flow_table(9, device_id="d2", outbound=False),
        ], ignore_index=True)
        w = W.assign_windows(flows)
        rep = W.coverage_report(w, W.window_index(w))
        self.assertAlmostEqual(rep["inbound_flow_fraction"], 0.75)
        self.assertEqual(rep["windows_with_no_outbound_flow"], 1)

    def test_all_values_are_json_serialisable_scalars(self):
        # The report is written into results/ as JSON; a numpy scalar here fails
        # json.dump at the very end of a long run.
        w = W.assign_windows(flow_table(10, gap_seconds=20.0))
        for k, v in W.coverage_report(w, W.window_index(w)).items():
            self.assertIsInstance(v, (int, float), msg=k)
            self.assertNotIsInstance(v, np.generic, msg=k)


if __name__ == "__main__":
    unittest.main(verbosity=2)
