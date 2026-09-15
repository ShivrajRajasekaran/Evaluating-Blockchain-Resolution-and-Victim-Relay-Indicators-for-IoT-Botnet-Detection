"""
tests/test_mock_generator.py — Track B generator.

Three jobs, in order of how much damage their absence would do.

1. THE ANTI-WIDENING GUARD (TestGeneratorConstants). Every distribution constant
   is pinned here. The standing rule in the generator's docstring says a null
   result must not be "fixed" by moving the classes further apart; a rule stated
   only in a comment is a rule that gets edited away in a late-night session.
   These tests make widening a deliberate, visible act: the diff shows both the
   generator change and the test change, and a reviewer can ask why.

2. THE DEVICE MODEL (TestDeviceLatents). The whole reason for grouped splits and
   group-level bootstrap is that windows from one device are correlated. If the
   latents were accidentally redrawn per window, every grouped-split result in
   the paper would silently become a random-split result.

3. SCHEMA CONFORMANCE (TestOutputIsValid). The generator's output feeds
   everything else, so it validates here rather than three modules downstream.
"""
import unittest

import numpy as np
import pandas as pd

from src.config import load_config
from src.ingest import mock_generator as G
from src.schema import columns as K
from src.schema import trainable, validate_observations

# Generated once: 9,200 rows x 2 class models is a few seconds, and every test
# below reads the same frame rather than regenerating it.
CFG = load_config()
DF_SCENARIO = G.generate(seed=42, cfg=CFG, class_model="scenario")
DF_PARITY = G.generate(seed=42, cfg=CFG, class_model="parity")


class TestOutputIsValid(unittest.TestCase):

    def test_scenario_frame_validates(self):
        rep = validate_observations(DF_SCENARIO)
        self.assertTrue(rep.ok, rep.summary())

    def test_parity_frame_validates(self):
        rep = validate_observations(DF_PARITY)
        self.assertTrue(rep.ok, rep.summary())

    def test_row_and_device_counts_match_config(self):
        m = CFG.mock
        n_dev = m.n_devices_benign + m.n_devices_malicious
        self.assertEqual(len(DF_SCENARIO), n_dev * m.windows_per_device)
        self.assertEqual(DF_SCENARIO[K.DEVICE_ID].nunique(), n_dev)

    def test_every_device_contributes_the_same_number_of_windows(self):
        counts = DF_SCENARIO[K.DEVICE_ID].value_counts()
        self.assertEqual(set(counts), {CFG.mock.windows_per_device})

    def test_no_features_are_missing(self):
        # Unlike IoT-23, the mock source can supply all 16. A NaN here would
        # mean a sampler silently failed.
        self.assertEqual(DF_SCENARIO[K.N_FEATURES_MISSING].sum(), 0)
        self.assertFalse(DF_SCENARIO[K.FEATURE_COLS].isna().any().any())

    def test_all_rows_are_track_b(self):
        self.assertEqual(set(DF_SCENARIO[K.SOURCE_DATASET]),
                         {K.SOURCE_MOCK_LOCAL})
        self.assertTrue(
            set(DF_SCENARIO[K.RESEARCH_CLASS]) <= set(K.TRACK_B_CLASSES))

    def test_no_unmapped_rows(self):
        # The generator knows the truth of every window it makes. An unmapped
        # row here would be a bug, not a data limitation.
        self.assertNotIn(K.CLS_UNMAPPED, set(DF_SCENARIO[K.RESEARCH_CLASS]))
        self.assertEqual(len(trainable(DF_SCENARIO)), len(DF_SCENARIO))

    def test_every_feature_is_within_its_declared_range(self):
        for c in K.FEATURE_COLS:
            lo, hi = K.FEATURE_RANGES[c]
            col = DF_SCENARIO[c]
            self.assertGreaterEqual(col.min(), lo, c)
            if hi is not None:
                self.assertLessEqual(col.max(), hi, c)

    def test_binary_features_are_binary(self):
        for c in K.BINARY_FEATURES:
            self.assertEqual(set(DF_SCENARIO[c].unique()) - {0.0, 1.0}, set(), c)


class TestDeterminism(unittest.TestCase):

    def test_same_seed_gives_an_identical_frame(self):
        again = G.generate(seed=42, cfg=CFG, class_model="scenario")
        pd.testing.assert_frame_equal(DF_SCENARIO, again)

    def test_different_seed_gives_different_values(self):
        other = G.generate(seed=7, cfg=CFG, class_model="scenario")
        self.assertFalse(
            np.allclose(DF_SCENARIO["scan_rate"].to_numpy(),
                        other["scan_rate"].to_numpy()))

    def test_no_wall_clock_dependency(self):
        # start_time comes from config, so a run today and a run next month
        # produce the same timestamps. Wall-clock timestamps would make every
        # observation_id — and therefore every stored CSV — unreproducible.
        self.assertEqual(DF_SCENARIO[K.WINDOW_START].min(),
                         pd.Timestamp(CFG.mock.start_time))


class TestDeviceLatents(unittest.TestCase):
    """Per-device latents, not per-window draws. See the module docstring."""

    def test_windows_from_one_device_are_correlated(self):
        # The direct test of the device model. Between-device variance in a
        # device's mean scan_rate must exceed within-device variance; if the
        # latents were redrawn per window the two would be equal.
        mal = DF_SCENARIO[DF_SCENARIO[K.LABEL_BINARY] == 1]
        grouped = mal.groupby(K.DEVICE_ID)["scan_rate"]
        between = grouped.mean().var()
        within = grouped.var().mean()
        self.assertGreater(between, within)

    def test_one_device_has_one_true_class(self):
        # original_label carries the true generating class. A device that
        # changed class mid-capture would make grouped splits incoherent.
        per_device = DF_SCENARIO.groupby(K.DEVICE_ID)[K.ORIGINAL_LABEL].nunique()
        self.assertEqual(set(per_device), {1})

    def test_one_device_has_one_scenario(self):
        per_device = DF_SCENARIO.groupby(K.DEVICE_ID)[K.SCENARIO_ID].nunique()
        self.assertEqual(set(per_device), {1})

    def test_a_grouped_split_is_therefore_meaningful(self):
        # Guards the validator warning from the other direction: with 10 windows
        # per device, a grouped split really does hold out unseen devices.
        rep = validate_observations(DF_SCENARIO)
        self.assertGreaterEqual(rep.stats["windows_per_device"], 2.0)
        self.assertFalse(any("grouped split" in w for w in rep.warnings),
                         rep.warnings)


class TestWindowTiming(unittest.TestCase):

    def test_a_device_is_sampled_once_per_stride(self):
        stride = CFG.mock.window_stride_seconds
        one = DF_SCENARIO[DF_SCENARIO[K.DEVICE_ID] == "mockdev-00000"]
        deltas = one[K.WINDOW_START].sort_values().diff().dropna()
        self.assertEqual(set(deltas), {pd.Timedelta(seconds=stride)})

    def test_windows_do_not_overlap_within_a_device(self):
        self.assertGreater(CFG.mock.window_stride_seconds,
                          K.WINDOW_SECONDS_VALUE)

    def test_temporal_and_grouped_splits_are_different_protocols(self):
        # If every device were observed in one contiguous burst, a temporal cut
        # would fall between devices and the two protocols would collapse into
        # one. Here the earliest and latest thirds of time both contain most
        # devices, so a temporal split genuinely tests a later period.
        t = DF_SCENARIO[K.WINDOW_START]
        early = DF_SCENARIO[t <= t.quantile(0.33)][K.DEVICE_ID].nunique()
        late = DF_SCENARIO[t >= t.quantile(0.67)][K.DEVICE_ID].nunique()
        total = DF_SCENARIO[K.DEVICE_ID].nunique()
        self.assertGreater(early / total, 0.9)
        self.assertGreater(late / total, 0.9)


class TestClassComposition(unittest.TestCase):

    def test_scenario_model_produces_three_malicious_classes(self):
        classes = set(DF_SCENARIO[K.ORIGINAL_LABEL])
        self.assertEqual(classes, set(K.TRACK_B_CLASSES))

    def test_parity_model_produces_one_malicious_class(self):
        classes = set(DF_PARITY[K.ORIGINAL_LABEL])
        self.assertEqual(classes,
                         {K.CLS_BENIGN_MOCK, K.CLS_COMBINED_MOCK})

    def test_class_mix_is_honoured_as_exact_counts(self):
        m = CFG.mock
        mal = DF_SCENARIO[DF_SCENARIO[K.ORIGINAL_LABEL] != K.CLS_BENIGN_MOCK]
        per_class = (mal.groupby(K.ORIGINAL_LABEL)[K.DEVICE_ID].nunique())
        for cls, share in m.class_mix.as_dict().items():
            self.assertEqual(per_class[cls],
                             round(share * m.n_devices_malicious), cls)

    def test_nominal_class_counts_are_exact(self):
        m = CFG.mock
        W = m.windows_per_device
        true_benign = (DF_SCENARIO[K.ORIGINAL_LABEL] == K.CLS_BENIGN_MOCK).sum()
        self.assertEqual(true_benign, m.n_devices_benign * W)
        self.assertEqual(len(DF_SCENARIO) - true_benign,
                         m.n_devices_malicious * W)

    def test_realised_imbalance_matches_the_prototype(self):
        # Nominal is 8,000 / 1,200 = 6.67:1, but the RECORDED labels are not
        # nominal. Annotation error is applied uniformly over rows, and 87% of
        # rows are benign, so ~160 of the 184 flips move benign -> malicious and
        # only ~24 move the other way. The realised ratio therefore lands near
        # 5.9:1, not 6.7:1 — an easy thing to misread as a generator bug.
        #
        # 5.90 is the prototype's own realised ratio (7,866 / 1,334). Matching it
        # is what keeps the enterprise numbers comparable to the published ones.
        n_pos = int((DF_SCENARIO[K.LABEL_BINARY] == 1).sum())
        n_neg = int((DF_SCENARIO[K.LABEL_BINARY] == 0).sum())
        self.assertAlmostEqual(n_neg / n_pos, 5.90, delta=0.25)

    def test_invalid_class_model_raises(self):
        with self.assertRaises(ValueError):
            G.generate(seed=42, cfg=CFG, class_model="whatever")


class TestScenarioSemantics(unittest.TestCase):
    """A resolver-only device is not relaying, and vice versa."""

    def _mean(self, cls, col):
        sel = DF_SCENARIO[K.ORIGINAL_LABEL] == cls
        return DF_SCENARIO.loc[sel, col].mean()

    def test_resolver_only_devices_look_benign_on_relay_features(self):
        benign = self._mean(K.CLS_BENIGN_MOCK, "bidir_flow_duration")
        res_only = self._mean(K.CLS_BLOCKCHAIN_RESOLUTION_MOCK,
                              "bidir_flow_duration")
        combined = self._mean(K.CLS_COMBINED_MOCK, "bidir_flow_duration")
        self.assertLess(abs(res_only - benign), abs(combined - benign))

    def test_relay_only_devices_look_benign_on_resolution_features(self):
        benign = self._mean(K.CLS_BENIGN_MOCK, "ens_query_rate")
        rel_only = self._mean(K.CLS_VICTIM_RELAY_MOCK, "ens_query_rate")
        combined = self._mean(K.CLS_COMBINED_MOCK, "ens_query_rate")
        self.assertLess(abs(rel_only - benign), abs(combined - benign))

    def test_unexpressed_groups_are_not_zeroed(self):
        # The failure mode this guards: setting a non-relaying device's relay
        # features to 0 instead of drawing them from the benign distribution.
        # That would be a separator no real capture could contain, and the model
        # would learn it instead of the behaviour.
        sel = DF_SCENARIO[K.ORIGINAL_LABEL] == K.CLS_BLOCKCHAIN_RESOLUTION_MOCK
        relay = DF_SCENARIO.loc[sel, "bidir_flow_duration"]
        self.assertGreater(relay.min(), 0.0)
        self.assertGreater(relay.std(), 1.0)

    def test_all_malicious_classes_express_the_base_groups(self):
        # Blockchain-anchored C2 is still malware: it still spreads and beacons.
        # If a subtype came out benign on infection too, the "incremental value
        # over a generic base" question would be unanswerable for it.
        benign_scan = self._mean(K.CLS_BENIGN_MOCK, "scan_rate")
        for cls in (K.CLS_BLOCKCHAIN_RESOLUTION_MOCK, K.CLS_VICTIM_RELAY_MOCK,
                    K.CLS_COMBINED_MOCK):
            self.assertGreater(self._mean(cls, "scan_rate"), benign_scan, cls)

    def test_scenario_model_is_not_easier_than_parity(self):
        # The direction check that matters. Splitting the malicious class into
        # subtypes that express only one novel group must make separation on
        # those groups HARDER, never easier — otherwise the scenario model would
        # be inflating the thesis rather than stress-testing it.
        def separation(df, col):
            pos = df.loc[df[K.LABEL_BINARY] == 1, col]
            neg = df.loc[df[K.LABEL_BINARY] == 0, col]
            pooled = np.sqrt((pos.var() + neg.var()) / 2)
            return abs(pos.mean() - neg.mean()) / pooled

        for col in (K.FEATURE_GROUPS["resolution"]
                    + K.FEATURE_GROUPS["relay"]):
            self.assertLessEqual(separation(DF_SCENARIO, col),
                                 separation(DF_PARITY, col) + 1e-9, col)


class TestLabelNoise(unittest.TestCase):

    def test_noise_rate_matches_config(self):
        n_flipped = int(DF_SCENARIO[K.QUALITY_FLAGS].str.contains(
            K.FLAG_LABEL_NOISE_INJECTED, regex=False).sum())
        self.assertEqual(n_flipped,
                         round(CFG.mock.label_noise * len(DF_SCENARIO)))

    def test_flipped_rows_are_exactly_those_where_labels_disagree(self):
        flagged = DF_SCENARIO[K.QUALITY_FLAGS].str.contains(
            K.FLAG_LABEL_NOISE_INJECTED, regex=False)
        disagree = DF_SCENARIO[K.RESEARCH_CLASS] != DF_SCENARIO[K.ORIGINAL_LABEL]
        pd.testing.assert_series_equal(flagged, disagree, check_names=False)

    def test_label_binary_follows_the_recorded_class_not_the_true_one(self):
        # The point of injecting annotation error is that the model trains on the
        # wrong label. If label_binary tracked original_label instead, the noise
        # would be recorded but never actually applied.
        flipped = DF_SCENARIO[
            DF_SCENARIO[K.RESEARCH_CLASS] != DF_SCENARIO[K.ORIGINAL_LABEL]]
        self.assertGreater(len(flipped), 0)
        for _, row in flipped.iterrows():
            self.assertEqual(row[K.LABEL_BINARY],
                             K.binary_label_for(row[K.RESEARCH_CLASS]))

    def test_noise_flips_in_both_directions(self):
        flipped = DF_SCENARIO[
            DF_SCENARIO[K.RESEARCH_CLASS] != DF_SCENARIO[K.ORIGINAL_LABEL]]
        self.assertIn(K.CLS_BENIGN_MOCK, set(flipped[K.RESEARCH_CLASS]))
        self.assertTrue(
            set(flipped[K.RESEARCH_CLASS]) & set(K.MALICIOUS_CLASSES))

    def test_scenario_id_is_not_flipped(self):
        # The capture a window came from is a fact; the label is a judgement.
        # Keeping scenario_id tied to the true class is what makes the injected
        # error recoverable later.
        flipped = DF_SCENARIO[
            DF_SCENARIO[K.RESEARCH_CLASS] != DF_SCENARIO[K.ORIGINAL_LABEL]]
        for _, row in flipped.iterrows():
            self.assertEqual(row[K.SCENARIO_ID],
                             G._SCENARIO_OF_CLASS[row[K.ORIGINAL_LABEL]])

    def test_zero_noise_leaves_labels_untouched(self):
        import copy
        raw = copy.deepcopy(CFG.as_dict())
        raw["mock"]["label_noise"] = 0.0
        raw["mock"]["n_devices_benign"] = 40
        raw["mock"]["n_devices_malicious"] = 10
        from src.config import ConfigNode
        df = G.generate(seed=42, cfg=ConfigNode(raw))
        self.assertTrue(
            (df[K.RESEARCH_CLASS] == df[K.ORIGINAL_LABEL]).all())
        self.assertTrue((df[K.QUALITY_FLAGS] == "").all())


class TestGeneratorConstants(unittest.TestCase):
    """The anti-widening guard. See the module docstring, point 1.

    Bounds are derived analytically from the prototype's distribution constants,
    then widened to cover the observed spread across the five configured seeds.
    They are pinned by observable effect rather than by re-listing the constants,
    so a refactor passes and an edit to a constant fails.

    Worked example, so the numbers are checkable rather than magic:
    malicious ``rpc_endpoint_ratio`` is ``beta(2,6) + e_res * beta(4,3)`` with
    ``e_res ~ beta(1.6,1.8)``. The three means are 2/8, 1.6/3.4 and 4/7, giving
    0.250 + 0.471 * 0.571 = 0.519. Observed: 0.508-0.528 across seeds. Bound:
    (0.48, 0.56).

    The malicious bounds are wider than the benign ones for a real reason, not
    laziness: the expression strengths are per-DEVICE, so a per-device quantity
    has an effective sample size of 120 malicious devices, not 1,200 rows.
    """

    # feature: (benign mean lo, hi, malicious mean lo, hi)
    EXPECTED = {
        "ens_query_rate":      (1.50, 1.68, 3.65, 4.30),
        "rpc_endpoint_ratio":  (0.19, 0.24, 0.48, 0.56),
        "resolution_entropy":  (2.78, 2.96, 4.10, 4.41),
        "bidir_flow_duration": (63.0, 78.0, 200.0, 250.0),
        "flow_fanout":         (3.32, 3.77, 6.70, 8.40),
        "updownlink_ratio":    (0.44, 0.47, 0.73, 0.83),
        "login_burst_count":   (0.55, 0.65, 3.42, 4.20),
        "scan_rate":           (1.23, 1.39, 4.70, 5.70),
        "distinct_dst_ports":  (4.10, 4.68, 7.70, 9.20),
        "failed_conn_ratio":   (0.155, 0.180, 0.46, 0.56),
        "beacon_jitter":       (14.4, 15.8, 1.70, 2.10),
        "rc4_string_score":    (0.092, 0.105, 0.62, 0.68),
        "mean_pkt_size":       (324.0, 336.0, 241.0, 258.0),
        # Binary features: the bounds are event rates.
        "serverlist_pull":     (0.080, 0.112, 0.45, 0.55),
        "upnp_addportmapping": (0.192, 0.229, 0.39, 0.50),
    }

    # Every feature is covered except beacon_interval, which is deliberately
    # NOT a class signal: benign heartbeat devices and malicious beacons have
    # almost the same mean interval (~41 s), and only the regularity differs.
    # A bound on its mean would assert the opposite of the design.
    def test_expected_covers_every_feature_but_beacon_interval(self):
        self.assertEqual(set(self.EXPECTED) | {"beacon_interval"},
                         set(K.FEATURE_COLS))

    def test_beacon_interval_is_not_a_class_signal_by_itself(self):
        ben, mal = self._split(DF_PARITY)
        self.assertAlmostEqual(ben["beacon_interval"].mean(),
                               mal["beacon_interval"].mean(), delta=6.0)

    @staticmethod
    def _split(df):
        return (df[df[K.ORIGINAL_LABEL] == K.CLS_BENIGN_MOCK],
                df[df[K.ORIGINAL_LABEL] != K.CLS_BENIGN_MOCK])

    def test_class_means_are_where_the_prototype_put_them(self):
        # Checked on the parity frame and on original_label: parity is the model
        # that corresponds one-to-one with the prototype's generator, and the
        # true class is the one the distributions were drawn from.
        ben, mal = self._split(DF_PARITY)
        for col, (b_lo, b_hi, m_lo, m_hi) in self.EXPECTED.items():
            self.assertTrue(b_lo <= ben[col].mean() <= b_hi,
                            f"{col} benign mean {ben[col].mean():.4f} "
                            f"outside [{b_lo}, {b_hi}]")
            self.assertTrue(m_lo <= mal[col].mean() <= m_hi,
                            f"{col} malicious mean {mal[col].mean():.4f} "
                            f"outside [{m_lo}, {m_hi}]")

    def test_benign_controls_overlap_the_malicious_class(self):
        # The most important guard in the file. Chatty benign devices must reach
        # into malicious territory on every novel feature: the top 5% of benign
        # devices must look more suspicious than the bottom 25% of malicious
        # ones. If they did not, the novel groups would separate the classes
        # trivially, the reported metrics would be an artefact of the generator,
        # and the paper's central claim would be untestable.
        #
        # bidir_flow_duration is the tightest case (benign p95 ~192 vs malicious
        # p25 ~136), which is worth knowing: it is the novel feature closest to
        # being a giveaway.
        ben, mal = self._split(DF_PARITY)
        for col in K.FEATURE_GROUPS["resolution"] + K.FEATURE_GROUPS["relay"]:
            if col in K.BINARY_FEATURES:
                continue        # a rate, not a distribution; covered above
            self.assertGreater(ben[col].quantile(0.95), mal[col].quantile(0.25),
                               col)

    def test_no_novel_feature_separates_the_classes(self):
        # The test that protects the headline result. If a resolution or relay
        # feature were a near-perfect separator, the generator rather than the
        # detector would have decided whether the novel groups add value.
        # Highest observed is bidir_flow_duration at ~0.91.
        for col in K.FEATURE_GROUPS["resolution"] + K.FEATURE_GROUPS["relay"]:
            auc = _abs_auc(DF_PARITY, col)
            self.assertLess(auc, 0.95, f"{col} AUC={auc:.4f}")

    def test_the_only_near_separators_are_the_two_documented_ones(self):
        # A KNOWN LIMITATION, pinned here rather than hidden. beacon_jitter
        # (~0.975) and rc4_string_score (~0.993) are close to perfect separators
        # on their own. Both are inherited from the prototype's generator and
        # both belong to the PAYLOAD group.
        #
        # Why this is not corrected here, and must not be:
        #   * They are in the BASE feature set. A strong base makes the
        #     incremental-value question HARDER for the novel groups, not
        #     easier — it is very likely part of why the prototype's result was
        #     null (base F1 already 0.914, leaving little headroom).
        #   * Narrowing them would therefore inflate the apparent contribution
        #     of resolution and relay. That is precisely the direction the
        #     standing rule forbids.
        #   * rc4_string_score needs plaintext payload, so it is in
        #     LAB_ONLY_FEATURES and its influence is already quantified by the
        #     lab-only sensitivity analysis rather than left implicit.
        # What IS owed to the reader is a plain statement of it in
        # docs/limitations.md; see docs/paper-results-policy.md.
        near = {c for c in K.FEATURE_COLS if _abs_auc(DF_PARITY, c) >= 0.95}
        self.assertEqual(near, {"beacon_jitter", "rc4_string_score"})
        for c in near:
            self.assertEqual(K.GROUP_OF_FEATURE[c], "payload", c)
        self.assertIn("rc4_string_score", K.LAB_ONLY_FEATURES)

    def test_benign_devices_are_not_uniformly_quiet(self):
        m = CFG.mock
        ben, _ = self._split(DF_PARITY)
        # UPnP rate sits between the quiet-device and chatty-device rates,
        # confirming the population is genuinely mixed.
        rate = ben["upnp_addportmapping"].mean()
        self.assertGreater(rate, 0.10)
        self.assertLess(rate, 0.10 + m.benign_chatty_fraction)
        # Heartbeat devices, and only those, have a non-zero beacon interval.
        beaconing = (ben["beacon_interval"] > 0).mean()
        self.assertAlmostEqual(beaconing, m.benign_heartbeat_fraction, delta=0.05)


def _abs_auc(df: pd.DataFrame, col: str) -> float:
    """Single-feature AUC, oriented so that 1.0 means "perfectly separating in
    either direction". Computed via the rank-sum identity to avoid a
    scikit-learn import in a data-only test module; ties are handled correctly
    by pandas' average ranking."""
    y = (df[K.ORIGINAL_LABEL] != K.CLS_BENIGN_MOCK).to_numpy()
    ranks = pd.Series(df[col].to_numpy()).rank().to_numpy()
    n_pos, n_neg = int(y.sum()), int((~y).sum())
    auc = (ranks[y].sum() - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)
    return max(auc, 1.0 - auc)


if __name__ == "__main__":
    unittest.main()
