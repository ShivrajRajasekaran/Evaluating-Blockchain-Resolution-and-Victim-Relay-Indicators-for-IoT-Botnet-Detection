"""
tests/test_derive.py — the 16 feature definitions.

Ordered by how much damage the bug would do if the test were absent.

1. THE NaN RULE (TestNotMeasurableIsNaN)
   The one class of bug here that produces a publishable-looking wrong number.
   A beacon_jitter of 0.0 is the most malicious value the feature can take, so
   emitting it for an unmeasurable window manufactures the project's central
   piece of evidence out of nothing. Every "cannot measure" path is checked.

2. GROUP ISOLATION (TestRelayFeaturesDoNotMeasureScanning)
   If a relay feature moves when a device scans, the incremental-value
   experiment is unfalsifiable — the novel group is measuring the base group
   under a different name. Checked by scoring a pure scanner.

3. ALIGNMENT (TestAlignment)
   A misalignment attaches features to the wrong window and raises nothing.

4. ARITHMETIC (the remaining classes)
   Hand-computed expected values for each formula.
"""
from __future__ import annotations

import unittest

import numpy as np
import pandas as pd

from src.features import derive as D
from src.features import windowing as W
from src.schema import columns as K
from tests.helpers import flow_table

P = D.DeriveParams()


def run(flows: pd.DataFrame, source: str = K.SOURCE_IOT23) -> D.Derived:
    return D.derive_features(W.assign_windows(flows), source=source, params=P)


def one(flows: pd.DataFrame, feature: str) -> float:
    """The feature value of a single-window flow table."""
    d = run(flows)
    assert len(d.features) == 1, f"expected 1 window, got {len(d.features)}"
    return float(d.features[feature].iloc[0])


class TestOutputShape(unittest.TestCase):
    def test_one_feature_row_per_window(self):
        flows = pd.concat([
            flow_table(4, device_id="a", ts="2026-01-06T00:00:00"),
            flow_table(4, device_id="a", ts="2026-01-06T00:05:00"),
            flow_table(4, device_id="b", ts="2026-01-06T00:00:00"),
        ], ignore_index=True)
        d = run(flows)
        self.assertEqual(len(d.features), 3)
        self.assertEqual(len(d.features), len(d.index))

    def test_only_iot23_available_features_are_emitted(self):
        # The availability table is the authority. Emitting a column here that
        # the schema calls unavailable would let a value survive into the
        # observation frame that no real capture can support.
        d = run(flow_table(6))
        expected = set(K.features_by_availability(
            K.SOURCE_IOT23, K.AVAIL_COMPUTABLE)) | set(
                K.features_by_availability(K.SOURCE_IOT23, K.AVAIL_PROXY))
        self.assertEqual(set(d.features.columns), expected)

    def test_the_five_unavailable_features_are_absent_entirely(self):
        d = run(flow_table(6))
        for f in K.features_by_availability(K.SOURCE_IOT23,
                                            K.AVAIL_UNAVAILABLE):
            self.assertNotIn(f, d.features.columns)

    def test_operational_sources_derive_like_iot23(self):
        # The product's operational flow logs go through the same deriver. Each
        # emits exactly its declared computable+proxy set and never a gap, and
        # the internal agreement check (which would raise) passes for all four.
        for s in K.OPERATIONAL_SOURCES:
            d = run(flow_table(6), source=s)
            expected = set(K.features_by_availability(s, K.AVAIL_COMPUTABLE)) | \
                set(K.features_by_availability(s, K.AVAIL_PROXY))
            self.assertEqual(set(d.features.columns), expected, s)
            for f in K.unavailable_features(s):
                self.assertNotIn(f, d.features.columns, f"{s}/{f}")

    def test_every_emitted_column_is_a_real_feature_name(self):
        d = run(flow_table(6))
        for c in d.features.columns:
            self.assertIn(c, K.FEATURE_COLS)

    def test_all_columns_are_float64(self):
        # An int column cannot hold NaN, so a silently integer feature would
        # break the NaN rule at the dtype level.
        d = run(flow_table(6))
        for c in d.features.columns:
            self.assertEqual(d.features[c].dtype, np.dtype("float64"), msg=c)

    def test_unknown_source_is_rejected(self):
        with self.assertRaises(ValueError):
            D.derive_features(W.assign_windows(flow_table(4)),
                              source="not_a_dataset")

    def test_the_mock_source_is_rejected(self):
        # Track B has no flow log; its features are produced at their origin by
        # the generator. Deriving from it would silently return 11 of 16
        # features and every resolution/relay result would be quietly wrong.
        with self.assertRaises(ValueError) as cm:
            D.derive_features(W.assign_windows(flow_table(4)),
                              source=K.SOURCE_MOCK_LOCAL)
        self.assertIn("no flow log", str(cm.exception))

    def test_values_are_inside_the_declared_ranges(self):
        # Extreme but legal input: huge byte counts, no response, many ports.
        flows = flow_table(
            40, gap_seconds=7.0, orig_bytes=10_000_000.0, resp_bytes=0.0,
            resp_ip_bytes=0.0, resp_pkts=0.0, orig_pkts=1.0,
            orig_ip_bytes=9_000_000.0,
            dst_port=[1000 + i for i in range(40)],
            dst_ip=[f"10.1.0.{i}" for i in range(40)])
        d = run(flows)
        for c in d.features.columns:
            lo, hi = K.FEATURE_RANGES[c]
            v = d.features[c].dropna()
            if v.empty:      # legitimately unmeasurable throughout; see below
                continue
            if lo is not None:
                self.assertGreaterEqual(v.min(), lo, msg=c)
            if hi is not None:
                self.assertLessEqual(v.max(), hi, msg=c)


class TestNotMeasurableIsNaN(unittest.TestCase):
    """Rule 1. The reason this class is first: see the module docstring."""

    def test_beacon_jitter_is_nan_with_only_one_gap(self):
        # Two flows to the modal peer = one gap = no standard deviation.
        self.assertTrue(np.isnan(one(flow_table(2), "beacon_jitter")))

    def test_beacon_jitter_is_nan_with_a_single_flow(self):
        self.assertTrue(np.isnan(one(flow_table(1), "beacon_jitter")))

    def test_beacon_interval_is_nan_with_a_single_flow(self):
        self.assertTrue(np.isnan(one(flow_table(1), "beacon_interval")))

    def test_beacon_interval_exists_with_two_flows(self):
        # Interval needs 2 timestamps; jitter needs 3. The asymmetry is
        # deliberate and this pins it down.
        self.assertAlmostEqual(one(flow_table(2, gap_seconds=45.0),
                                   "beacon_interval"), 45.0)

    def test_beacon_jitter_exists_with_three_flows(self):
        self.assertFalse(np.isnan(one(flow_table(3), "beacon_jitter")))

    def test_zero_jitter_is_only_ever_a_real_measurement(self):
        # A perfectly regular 3-flow beacon genuinely has jitter 0. That value
        # must be reachable ONLY this way — never as a stand-in for "unknown".
        self.assertEqual(one(flow_table(3, gap_seconds=60.0), "beacon_jitter"),
                         0.0)

    def test_mean_pkt_size_is_nan_when_no_packets(self):
        flows = flow_table(4, orig_pkts=0.0, resp_pkts=0.0,
                           orig_ip_bytes=0.0, resp_ip_bytes=0.0)
        self.assertTrue(np.isnan(one(flows, "mean_pkt_size")))

    def test_mean_pkt_size_is_nan_when_ip_bytes_unreported(self):
        # Some Zeek analysers leave *_ip_bytes at 0 while counting packets.
        # Dividing would give 0 bytes per packet, which clips up to the schema's
        # 40-byte floor and invents a header that was never observed.
        flows = flow_table(4, orig_ip_bytes=0.0, resp_ip_bytes=0.0)
        self.assertTrue(np.isnan(one(flows, "mean_pkt_size")))

    def test_updownlink_ratio_is_nan_when_no_payload_either_way(self):
        flows = flow_table(4, orig_bytes=0.0, resp_bytes=0.0)
        self.assertTrue(np.isnan(one(flows, "updownlink_ratio")))

    def test_rpc_endpoint_ratio_is_nan_with_no_resolver_traffic(self):
        # The overwhelmingly common case on a real capture: the ratio has no
        # denominator, so it has no value. 0.0 would assert "this device made
        # lookups and none were RPC", which is a different and unsupported claim.
        self.assertTrue(np.isnan(one(flow_table(4, dst_port=443),
                                     "rpc_endpoint_ratio")))

    def test_features_that_are_measurements_at_zero_are_not_nan(self):
        # The counterpart to the rule: these four have a well-defined 0, and
        # turning them into NaN would throw away real observations.
        flows = flow_table(4, dst_port=443, conn_state="SF", resp_bytes=0.0)
        d = run(flows)
        for f in ("login_burst_count", "failed_conn_ratio",
                  "bidir_flow_duration", "flow_fanout"):
            self.assertFalse(np.isnan(d.features[f].iloc[0]), msg=f)
            self.assertEqual(d.features[f].iloc[0], 0.0, msg=f)

    def test_unmeasurable_fractions_are_reported(self):
        d = run(flow_table(2))
        self.assertEqual(d.diagnostics["beacon_jitter_unmeasurable_fraction"],
                         1.0)
        self.assertEqual(d.diagnostics["beacon_interval_unmeasurable_fraction"],
                         0.0)


class TestRelayFeaturesDoNotMeasureScanning(unittest.TestCase):
    """Rule 2. Group isolation, checked against a pure scanner.

    A scanner is the adversarial case for the relay group: it produces huge
    fanout and thousands of zero-duration flows. Under the naive definitions
    (all flows, not just bidirectional) its flow_fanout would be in the hundreds
    and its bidir_flow_duration near zero — both strong signals, both actually
    reporting infection behaviour from inside the relay group.
    """

    def setUp(self):
        # 200 SYNs to 200 hosts, no response, all in one window.
        self.scan = flow_table(
            200, gap_seconds=1.0, duration=0.0,
            dst_ip=[f"10.2.{i // 256}.{i % 256}" for i in range(200)],
            dst_port=[23] * 200, orig_bytes=0.0, resp_bytes=0.0,
            orig_ip_bytes=40.0, resp_ip_bytes=0.0,
            orig_pkts=1.0, resp_pkts=0.0, conn_state="S0")

    def test_scanner_has_zero_relay_fanout(self):
        self.assertEqual(one(self.scan, "flow_fanout"), 0.0)

    def test_scanner_has_zero_bidir_duration(self):
        self.assertEqual(one(self.scan, "bidir_flow_duration"), 0.0)

    def test_scanner_lights_up_the_infection_group_instead(self):
        # Where the signal belongs: 200 flows / 5 min = 40/min, all failed, all
        # to a login port.
        d = run(self.scan)
        self.assertAlmostEqual(d.features["scan_rate"].iloc[0], 40.0)
        self.assertEqual(d.features["failed_conn_ratio"].iloc[0], 1.0)
        self.assertEqual(d.features["login_burst_count"].iloc[0], 200.0)

    def test_a_relay_is_distinguished_from_a_scanner_by_the_relay_features(self):
        # 8 long two-way conversations: few flows, high fanout, long duration.
        relay = flow_table(
            8, gap_seconds=30.0, duration=240.0,
            dst_ip=[f"198.51.100.{i}" for i in range(8)],
            dst_port=[40000 + i for i in range(8)])
        self.assertEqual(one(relay, "flow_fanout"), 8.0)
        self.assertAlmostEqual(one(relay, "bidir_flow_duration"), 240.0)
        self.assertAlmostEqual(one(relay, "scan_rate"), 1.6)

    def test_handshake_only_flows_do_not_count_as_conversations(self):
        # IP bytes flow both ways during a SYN/SYN-ACK/RST exchange while no
        # payload is exchanged. Using IP bytes for the bidirectional test would
        # make every refused probe look like a conversation.
        refused = flow_table(6, orig_bytes=0.0, resp_bytes=0.0,
                             orig_ip_bytes=120.0, resp_ip_bytes=80.0,
                             conn_state="REJ")
        self.assertEqual(one(refused, "flow_fanout"), 0.0)
        self.assertEqual(one(refused, "bidir_flow_duration"), 0.0)


class TestDirectionOfInitiation(unittest.TestCase):
    """A device being scanned must not look like a device that scans.

    Same damage class as group isolation, on the other half of the research
    question. Ambient inbound scanning is the normal condition of any exposed IoT
    device; if it were counted as the device's own behaviour, every benign real
    capture would show high port variety and a high failure ratio, and the
    false-positive rate Track A exists to measure would be inflated by the
    internet's background noise rather than by anything the detector did.
    """

    def setUp(self):
        # 200 inbound SYNs from one host to 200 different ports ON the device.
        # After orientation normalisation the peer's port is what lands in
        # dst_port, so a naive count would see 200 "distinct ports".
        self.scanned = flow_table(
            200, gap_seconds=1.0, duration=0.0, outbound=False,
            dst_ip="198.51.100.7",
            dst_port=[40000 + i for i in range(200)],
            orig_bytes=0.0, resp_bytes=0.0,
            orig_ip_bytes=0.0, resp_ip_bytes=40.0,
            orig_pkts=0.0, resp_pkts=1.0, conn_state="S0")

    def test_being_scanned_does_not_raise_the_infection_features(self):
        d = run(self.scanned)
        self.assertEqual(d.features["scan_rate"].iloc[0], 0.0)
        self.assertEqual(d.features["distinct_dst_ports"].iloc[0], 0.0)
        self.assertEqual(d.features["login_burst_count"].iloc[0], 0.0)

    def test_being_scanned_leaves_the_failure_ratio_undefined_not_high(self):
        # NaN, not 0.0 and certainly not 1.0: the device made no attempt, so the
        # fraction of its attempts that failed has no denominator.
        self.assertTrue(np.isnan(one(self.scanned, "failed_conn_ratio")))

    def test_inbound_arrivals_are_not_the_devices_beacon(self):
        # A peer polling the device every second is the peer's schedule.
        for f in ("beacon_interval", "beacon_jitter"):
            self.assertTrue(np.isnan(one(self.scanned, f)), f)

    def test_the_same_flows_outbound_do_light_up_the_infection_group(self):
        # The only difference from setUp is who opened the connections.
        outbound = self.scanned.copy()
        outbound[W.F_OUTBOUND] = True
        d = run(outbound)
        self.assertAlmostEqual(d.features["scan_rate"].iloc[0], 40.0)
        self.assertEqual(d.features["distinct_dst_ports"].iloc[0], 200.0)
        self.assertEqual(d.features["failed_conn_ratio"].iloc[0], 1.0)

    def test_relay_features_still_see_inbound_traffic(self):
        # A relay's defining property is that it ACCEPTS connections, so the
        # relay group must not be gated on direction the way infection is.
        inbound_relay = flow_table(
            8, gap_seconds=30.0, duration=240.0, outbound=False,
            dst_ip=[f"198.51.100.{i}" for i in range(8)],
            dst_port=[40000 + i for i in range(8)])
        self.assertEqual(one(inbound_relay, "flow_fanout"), 8.0)
        self.assertAlmostEqual(one(inbound_relay, "bidir_flow_duration"), 240.0)

    def test_byte_and_packet_features_still_see_inbound_traffic(self):
        inbound = flow_table(6, outbound=False)
        self.assertFalse(np.isnan(one(inbound, "updownlink_ratio")))
        self.assertFalse(np.isnan(one(inbound, "mean_pkt_size")))

    def test_a_mixed_window_uses_only_its_outbound_half(self):
        # 4 outbound flows to port 23, 4 inbound flows to 4 other ports.
        mixed = flow_table(
            8, gap_seconds=10.0,
            outbound=[True] * 4 + [False] * 4,
            dst_port=[23, 23, 23, 23, 8080, 8081, 8082, 8083],
            conn_state=["S0"] * 4 + ["SF"] * 4)
        d = run(mixed)
        # 4 outbound flows / 5 min, one distinct port, all four failed.
        self.assertAlmostEqual(d.features["scan_rate"].iloc[0], 0.8)
        self.assertEqual(d.features["distinct_dst_ports"].iloc[0], 1.0)
        self.assertEqual(d.features["failed_conn_ratio"].iloc[0], 1.0)
        self.assertEqual(d.features["login_burst_count"].iloc[0], 4.0)

    def test_the_flow_table_rejects_string_booleans(self):
        # Zeek writes T/F; both are truthy, so an unconverted column would mark
        # every flow outbound.
        bad = flow_table(4)
        bad[W.F_OUTBOUND] = "F"
        with self.assertRaises(W.FlowTableError) as ctx:
            W.assign_windows(bad)
        self.assertIn(W.F_OUTBOUND, str(ctx.exception))


class TestAlignment(unittest.TestCase):
    """Rule 3. Features must follow their own window regardless of input order."""

    def _flows(self):
        return pd.concat([
            # dev-a window 0: 2 peers, duration 10
            flow_table(4, device_id="dev-a", ts="2026-01-06T00:00:00",
                       gap_seconds=30.0, dst_ip=["10.0.0.1"] * 2
                       + ["10.0.0.2"] * 2),
            # dev-a window 1: 1 peer, duration 99
            flow_table(4, device_id="dev-a", ts="2026-01-06T00:05:00",
                       gap_seconds=30.0, duration=99.0, dst_ip="10.0.0.3"),
            # dev-b window 0: 3 peers, duration 55
            flow_table(6, device_id="dev-b", ts="2026-01-06T00:00:00",
                       gap_seconds=20.0, duration=55.0,
                       dst_ip=["10.0.0.4"] * 2 + ["10.0.0.5"] * 2
                       + ["10.0.0.6"] * 2),
        ], ignore_index=True)

    def test_each_window_gets_its_own_values(self):
        d = run(self._flows())
        got = {(r[W.F_DEVICE_ID], str(r[W.WINDOW_START])):
               (d.features["bidir_flow_duration"].iloc[i],
                d.features["flow_fanout"].iloc[i])
               for i, r in d.index.iterrows()}
        self.assertEqual(got[("dev-a", "2026-01-06 00:00:00")], (10.0, 2.0))
        self.assertEqual(got[("dev-a", "2026-01-06 00:05:00")], (99.0, 1.0))
        self.assertEqual(got[("dev-b", "2026-01-06 00:00:00")], (55.0, 3.0))

    def test_shuffling_the_input_rows_changes_nothing(self):
        base = run(self._flows())
        shuffled = run(self._flows().sample(frac=1.0, random_state=7))
        pd.testing.assert_frame_equal(base.features, shuffled.features)
        pd.testing.assert_frame_equal(base.index, shuffled.index)

    def test_a_window_with_no_bidirectional_flows_does_not_borrow_from_others(
            self):
        # The bidirectional-only aggregates are computed on a SUBSET of rows, so
        # they must be reindexed back onto the full window list. Without that,
        # window 1 here would silently inherit window 0's value.
        flows = pd.concat([
            flow_table(4, device_id="dev-a", ts="2026-01-06T00:00:00",
                       duration=77.0),
            flow_table(4, device_id="dev-a", ts="2026-01-06T00:05:00",
                       duration=77.0, resp_bytes=0.0),
        ], ignore_index=True)
        d = run(flows)
        self.assertEqual(list(d.features["bidir_flow_duration"]), [77.0, 0.0])
        self.assertEqual(list(d.features["flow_fanout"]), [1.0, 0.0])


class TestBeaconing(unittest.TestCase):
    """The modal-peer rule, which is what makes beaconing measurable at all."""

    def test_gaps_are_taken_to_the_most_contacted_peer_only(self):
        # A device beaconing to 10.0.0.1 every 60 s while also chatting to
        # 10.0.0.9 at offset moments. Pooling all peers would interleave the two
        # schedules and report a jitter caused by the interleaving.
        ts = ["2026-01-06T00:00:00", "2026-01-06T00:00:07",
              "2026-01-06T00:01:00", "2026-01-06T00:01:23",
              "2026-01-06T00:02:00", "2026-01-06T00:03:00"]
        ips = ["10.0.0.1", "10.0.0.9", "10.0.0.1", "10.0.0.9",
               "10.0.0.1", "10.0.0.1"]
        flows = flow_table(6, ts=ts, dst_ip=ips)
        self.assertAlmostEqual(one(flows, "beacon_interval"), 60.0)
        self.assertAlmostEqual(one(flows, "beacon_jitter"), 0.0)

    def test_interval_is_the_median_gap_not_the_mean(self):
        # Gaps 30, 30, 30, 150. The median (30) describes the beacon; the mean
        # (60) describes neither the beacon nor the pause.
        ts = ["2026-01-06T00:00:00", "2026-01-06T00:00:30",
              "2026-01-06T00:01:00", "2026-01-06T00:01:30",
              "2026-01-06T00:04:00"]
        self.assertAlmostEqual(one(flow_table(5, ts=ts), "beacon_interval"),
                               30.0)

    def test_jitter_is_a_standard_deviation_with_ddof_one(self):
        # gaps: 30, 30, 60 -> sample sd = 17.3205...
        ts = ["2026-01-06T00:00:00", "2026-01-06T00:00:30",
              "2026-01-06T00:01:00", "2026-01-06T00:02:00"]
        self.assertAlmostEqual(one(flow_table(4, ts=ts), "beacon_jitter"),
                               float(np.std([30.0, 30.0, 60.0], ddof=1)), 6)

    def test_irregular_beacon_has_higher_jitter_than_regular_one(self):
        regular = flow_table(6, gap_seconds=50.0)
        ts = ["2026-01-06T00:00:00", "2026-01-06T00:00:05",
              "2026-01-06T00:01:30", "2026-01-06T00:01:35",
              "2026-01-06T00:04:00", "2026-01-06T00:04:50"]
        irregular = flow_table(6, ts=ts)
        self.assertLess(one(regular, "beacon_jitter"),
                        one(irregular, "beacon_jitter"))

    def test_modal_peer_tie_is_broken_deterministically(self):
        # Two peers with 3 flows each. Whichever is chosen, choosing the SAME one
        # every run is what matters — otherwise the same capture yields different
        # numbers on different days.
        ts = ["2026-01-06T00:00:00", "2026-01-06T00:00:20",
              "2026-01-06T00:00:40", "2026-01-06T00:01:00",
              "2026-01-06T00:01:40", "2026-01-06T00:02:40"]
        ips = ["10.0.0.2", "10.0.0.1", "10.0.0.2", "10.0.0.1",
               "10.0.0.2", "10.0.0.1"]
        flows = flow_table(6, ts=ts, dst_ip=ips)
        first = one(flows, "beacon_interval")
        for seed in (1, 2, 3):
            shuffled = flows.sample(frac=1.0, random_state=seed)
            self.assertAlmostEqual(one(shuffled, "beacon_interval"), first)

    def test_unsorted_input_still_produces_positive_gaps(self):
        # Gaps come from diff() after an explicit sort. Without the sort, a
        # conn.log that is not perfectly ordered would yield negative gaps and a
        # negative median interval, which the schema range would then reject.
        flows = flow_table(6, gap_seconds=40.0).iloc[::-1]
        self.assertAlmostEqual(one(flows, "beacon_interval"), 40.0)
        self.assertGreaterEqual(one(flows, "beacon_interval"), 0.0)


class TestByteAndRateFeatures(unittest.TestCase):
    def test_updownlink_ratio_is_uplink_over_downlink(self):
        flows = flow_table(4, orig_bytes=250.0, resp_bytes=1000.0)
        self.assertAlmostEqual(one(flows, "updownlink_ratio"), 0.25)

    def test_updownlink_ratio_uses_payload_not_ip_bytes(self):
        # Same payload asymmetry, wildly different header totals. If headers
        # counted, the ratio would drift toward 1.0 for every device and the
        # feature would stop describing data symmetry.
        a = flow_table(4, orig_bytes=250.0, resp_bytes=1000.0,
                       orig_ip_bytes=300.0, resp_ip_bytes=1100.0)
        b = flow_table(4, orig_bytes=250.0, resp_bytes=1000.0,
                       orig_ip_bytes=9000.0, resp_ip_bytes=1100.0)
        self.assertAlmostEqual(one(a, "updownlink_ratio"),
                               one(b, "updownlink_ratio"))

    def test_uplink_only_window_lands_on_the_cap_and_is_reported(self):
        flows = flow_table(4, orig_bytes=500.0, resp_bytes=0.0)
        hi = K.FEATURE_RANGES["updownlink_ratio"][1]
        d = run(flows)
        self.assertEqual(d.features["updownlink_ratio"].iloc[0], hi)
        self.assertEqual(d.diagnostics["updownlink_ratio_capped_fraction"], 1.0)

    def test_cap_rate_is_zero_for_ordinary_traffic(self):
        # The cap rate is the numeric form of the distribution-shift caveat for
        # the cross-track FPR test, so it must not fire on normal windows.
        d = run(flow_table(10, gap_seconds=25.0))
        self.assertEqual(d.diagnostics["updownlink_ratio_capped_fraction"], 0.0)

    def test_mean_pkt_size_uses_ip_bytes_over_total_packets(self):
        flows = flow_table(4, orig_ip_bytes=600.0, resp_ip_bytes=900.0,
                           orig_pkts=5.0, resp_pkts=5.0)
        # (600+900)*4 / (5+5)*4 = 150
        self.assertAlmostEqual(one(flows, "mean_pkt_size"), 150.0)

    def test_mean_pkt_size_is_clipped_to_the_mtu(self):
        flows = flow_table(4, orig_ip_bytes=100_000.0, resp_ip_bytes=0.0,
                           orig_pkts=1.0, resp_pkts=0.0)
        self.assertEqual(one(flows, "mean_pkt_size"),
                         K.FEATURE_RANGES["mean_pkt_size"][1])

    def test_scan_rate_is_flows_per_minute(self):
        self.assertAlmostEqual(one(flow_table(15, gap_seconds=10.0),
                                   "scan_rate"), 3.0)

    def test_distinct_dst_ports_counts_unique_ports(self):
        flows = flow_table(6, gap_seconds=20.0,
                           dst_port=[80, 80, 443, 443, 8080, 80])
        self.assertEqual(one(flows, "distinct_dst_ports"), 3.0)

    def test_bidir_duration_is_the_mean_over_bidirectional_flows_only(self):
        # durations 100, 200 bidirectional; 999 one-way and must be excluded.
        flows = flow_table(3, gap_seconds=30.0, duration=[100.0, 200.0, 999.0],
                           resp_bytes=[1000.0, 1000.0, 0.0])
        self.assertAlmostEqual(one(flows, "bidir_flow_duration"), 150.0)

    def test_bidir_duration_is_the_mean_not_the_max(self):
        # The max is set by a single flow and moves with wherever the capture is
        # cut, so it is not a stable per-window property.
        flows = flow_table(4, gap_seconds=30.0,
                           duration=[10.0, 10.0, 10.0, 250.0])
        self.assertAlmostEqual(one(flows, "bidir_flow_duration"), 70.0)


class TestProxyFeatures(unittest.TestCase):
    """The two approximations, and the honest-zero result they produce."""

    def test_both_proxies_are_declared_as_proxies_in_the_schema(self):
        # If either were ever promoted to "computable", its rows would stop
        # carrying FLAG_PROXY_FEATURES and a reader could mistake the
        # approximation for a measurement.
        for f in ("rpc_endpoint_ratio", "login_burst_count"):
            self.assertEqual(K.FEATURE_AVAILABILITY[K.SOURCE_IOT23][f],
                             K.AVAIL_PROXY, msg=f)

    def test_rpc_ratio_is_rpc_flows_over_resolver_plus_rpc_flows(self):
        # 2 flows to 8545, 6 to 53 -> 2/8 = 0.25
        flows = flow_table(8, gap_seconds=20.0,
                           dst_port=[8545, 8545] + [53] * 6)
        self.assertAlmostEqual(one(flows, "rpc_endpoint_ratio"), 0.25)

    def test_rpc_ratio_is_zero_when_only_standard_dns_is_used(self):
        # Distinct from NaN: here the device DID make lookups and none went to
        # an RPC port. That is a measurement of 0, and it is the expected
        # IoT-23 result.
        self.assertEqual(one(flow_table(6, dst_port=53), "rpc_endpoint_ratio"),
                         0.0)

    def test_https_traffic_does_not_raise_the_rpc_ratio(self):
        # THE REASON 443 AND 8443 WERE REMOVED FROM THE PORT LIST. With them
        # included, this window — ordinary web traffic — scored ~1.0 and the
        # feature was really detecting TLS use. See configs/default.yaml.
        for port in (443, 8443):
            flows = flow_table(6, dst_port=[port] * 4 + [53, 53])
            self.assertEqual(one(flows, "rpc_endpoint_ratio"), 0.0, msg=port)

    def test_config_port_lists_do_not_reintroduce_443(self):
        from src.config import load_config
        cfg = load_config()
        self.assertNotIn(443, list(cfg.iot23.rpc_proxy_ports))
        self.assertNotIn(8443, list(cfg.iot23.rpc_proxy_ports))

    def test_derive_params_from_config_matches_the_yaml(self):
        from src.config import load_config
        p = D.DeriveParams.from_config(load_config().iot23)
        self.assertEqual(p.rpc_proxy_ports, (8545, 8546))
        self.assertEqual(p.resolver_ports, (53, 5353))
        self.assertEqual(p.login_ports, (22, 23, 2323, 5555))

    def test_login_burst_counts_flows_to_login_ports(self):
        flows = flow_table(8, gap_seconds=20.0,
                           dst_port=[23, 2323, 22, 5555, 80, 443, 8080, 23])
        self.assertEqual(one(flows, "login_burst_count"), 5.0)

    def test_login_burst_counts_connections_not_authentications(self):
        # Five separate connections to port 23 count 5, whatever happened inside
        # them. conn.log has no authentication visibility; this is precisely the
        # approximation the proxy flag warns about.
        flows = flow_table(5, gap_seconds=30.0, dst_port=23, conn_state="SF")
        self.assertEqual(one(flows, "login_burst_count"), 5.0)

    def test_failed_conn_ratio_uses_the_configured_state_list(self):
        flows = flow_table(8, gap_seconds=20.0,
                           conn_state=["S0", "REJ", "SH", "SF",
                                       "SF", "SF", "SF", "SF"])
        self.assertAlmostEqual(one(flows, "failed_conn_ratio"), 3 / 8)

    def test_unknown_conn_state_is_not_counted_as_failed(self):
        flows = flow_table(4, conn_state="OTH")
        self.assertEqual(one(flows, "failed_conn_ratio"), 0.0)


class TestDiagnostics(unittest.TestCase):
    def test_coverage_and_derivation_diagnostics_are_both_present(self):
        d = run(flow_table(10, gap_seconds=25.0))
        for key in ("flows", "devices", "windows",
                    "updownlink_ratio_capped_fraction",
                    "beacon_jitter_unmeasurable_fraction",
                    "rpc_endpoint_ratio_undefined_fraction",
                    "rpc_endpoint_ratio_nonzero_fraction"):
            self.assertIn(key, d.diagnostics)

    def test_diagnostics_are_json_serialisable(self):
        import json
        d = run(flow_table(10, gap_seconds=25.0))
        json.dumps(d.diagnostics)

    def test_rpc_nonzero_fraction_survives_an_all_nan_column(self):
        # The overwhelmingly likely real-capture case. np.nanmean of an all-NaN
        # array warns and returns NaN, which then fails json.dumps as a bare
        # float only after a long run has finished.
        import json
        d = run(flow_table(6, dst_port=443))
        self.assertTrue(np.isnan(d.features["rpc_endpoint_ratio"]).all())
        self.assertEqual(d.diagnostics["rpc_endpoint_ratio_undefined_fraction"],
                         1.0)
        json.dumps(d.diagnostics)


class TestEndToEndIntoTheSchema(unittest.TestCase):
    """Derivation output must be directly acceptable to build_observations."""

    def test_derived_features_build_a_valid_observation_frame(self):
        from src.schema import build_observations, validate_observations

        flows = pd.concat([
            flow_table(8, device_id="192.168.1.10", ts="2026-01-06T00:00:00",
                       gap_seconds=30.0),
            flow_table(2, device_id="192.168.1.11", ts="2026-01-06T00:05:00",
                       gap_seconds=30.0),
        ], ignore_index=True)
        d = run(flows)

        obs = build_observations(
            d.features,
            source_dataset=K.SOURCE_IOT23,
            device_id=d.index[W.F_DEVICE_ID].tolist(),
            window_start=d.index[W.WINDOW_START].tolist(),
            research_class=[K.CLS_BENIGN_REAL] * len(d.features),
            original_label=["Benign"] * len(d.features),
            scenario_id="CTU-IoT-Malware-Capture-TEST-1",
            extra_flags=W.window_quality_flags(
                d.index, min_flows=3, min_span_seconds=60.0),
        )
        report = validate_observations(obs)
        self.assertTrue(report.ok, msg=str(report))

    def test_the_unavailable_five_arrive_as_nan_not_missing_columns(self):
        from src.schema import build_observations
        d = run(flow_table(8, gap_seconds=30.0))
        obs = build_observations(
            d.features,
            source_dataset=K.SOURCE_IOT23,
            device_id=d.index[W.F_DEVICE_ID].tolist(),
            window_start=d.index[W.WINDOW_START].tolist(),
            research_class=[K.CLS_BENIGN_REAL] * len(d.features),
            original_label=["Benign"] * len(d.features),
            scenario_id="s",
        )
        for f in K.features_by_availability(K.SOURCE_IOT23,
                                            K.AVAIL_UNAVAILABLE):
            self.assertIn(f, obs.columns, msg=f)
            self.assertTrue(obs[f].isna().all(), msg=f)


if __name__ == "__main__":
    unittest.main(verbosity=2)
