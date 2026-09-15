"""
tests/test_schema_columns.py — the data model's own invariants.

These tests guard the definitions rather than any behaviour: that the taxonomy
is complete and non-overlapping, that every feature has a range and a group,
and that the IoT-23 availability table still says what the project's central
limitation claims it says.

The last one matters most. docs/limitations.md and the paper both state that
IoT-23 cannot supply the novelty features. If someone later marks
`serverlist_pull` computable to make Track A produce a fuller table, that claim
becomes false everywhere it appears — and nothing else in the codebase would
notice.
"""
import unittest

from src.schema import columns as K


class TestTaxonomy(unittest.TestCase):

    def test_tracks_partition_the_class_list(self):
        self.assertEqual(
            set(K.TRACK_A_CLASSES) | set(K.TRACK_B_CLASSES),
            set(K.RESEARCH_CLASSES),
        )
        self.assertEqual(
            set(K.TRACK_A_CLASSES) & set(K.TRACK_B_CLASSES), set())

    def test_seven_classes(self):
        self.assertEqual(len(K.RESEARCH_CLASSES), 7)
        self.assertEqual(len(set(K.RESEARCH_CLASSES)), 7)

    def test_unmapped_is_not_a_trainable_class(self):
        self.assertNotIn(K.CLS_UNMAPPED, K.RESEARCH_CLASSES)
        self.assertNotIn(K.CLS_UNMAPPED, K.TRACK_OF_CLASS)
        with self.assertRaises(ValueError):
            K.binary_label_for(K.CLS_UNMAPPED)

    def test_benign_and_malicious_partition_the_classes(self):
        self.assertEqual(
            set(K.BENIGN_CLASSES) | set(K.MALICIOUS_CLASSES),
            set(K.RESEARCH_CLASSES),
        )
        self.assertEqual(set(K.BENIGN_CLASSES) & set(K.MALICIOUS_CLASSES), set())

    def test_every_class_has_a_track(self):
        for c in K.RESEARCH_CLASSES:
            self.assertIn(K.TRACK_OF_CLASS[c], ("A", "B"), c)

    def test_binary_label_mapping(self):
        self.assertEqual(K.binary_label_for(K.CLS_BENIGN_REAL), 0)
        self.assertEqual(K.binary_label_for(K.CLS_BENIGN_MOCK), 0)
        self.assertEqual(K.binary_label_for(K.CLS_TRADITIONAL_C2), 1)
        self.assertEqual(
            K.binary_label_for(K.CLS_BLOCKCHAIN_RESOLUTION_MOCK), 1)
        self.assertEqual(K.binary_label_for(K.CLS_COMBINED_MOCK), 1)

    def test_unmapped_sentinel_is_not_benign(self):
        # -1, never 0. Defaulting unknown traffic to benign would deflate the
        # measured false-positive rate.
        self.assertEqual(K.LABEL_BINARY_UNMAPPED, -1)
        self.assertNotEqual(K.LABEL_BINARY_UNMAPPED, 0)


class TestFeatureDefinitions(unittest.TestCase):

    def test_sixteen_features_in_four_groups(self):
        self.assertEqual(len(K.FEATURE_GROUPS), 4)
        self.assertEqual(len(K.FEATURE_COLS), 16)
        self.assertEqual(len(set(K.FEATURE_COLS)), 16)
        for group, cols in K.FEATURE_GROUPS.items():
            self.assertEqual(len(cols), 4, group)

    def test_novel_and_base_groups_partition_the_groups(self):
        self.assertEqual(
            set(K.NOVEL_GROUPS) | set(K.BASE_GROUPS), set(K.FEATURE_GROUPS))
        self.assertEqual(set(K.NOVEL_GROUPS) & set(K.BASE_GROUPS), set())

    def test_every_feature_has_a_range_and_a_group(self):
        for c in K.FEATURE_COLS:
            self.assertIn(c, K.FEATURE_RANGES, c)
            self.assertIn(c, K.GROUP_OF_FEATURE, c)
            lo, hi = K.FEATURE_RANGES[c]
            if hi is not None:
                self.assertLess(lo, hi, c)

    def test_binary_features_have_zero_one_range(self):
        for c in K.BINARY_FEATURES:
            self.assertEqual(K.FEATURE_RANGES[c], (0.0, 1.0), c)

    def test_lab_only_features_are_real_features(self):
        for c in K.LAB_ONLY_FEATURES:
            self.assertIn(c, K.FEATURE_COLS, c)

    def test_network_observable_excludes_lab_only(self):
        obs = K.network_observable_features()
        self.assertEqual(len(obs), 16 - len(K.LAB_ONLY_FEATURES))
        for c in K.LAB_ONLY_FEATURES:
            self.assertNotIn(c, obs)

    def test_all_cols_is_meta_then_features(self):
        self.assertEqual(K.ALL_COLS, K.META_COLS + K.FEATURE_COLS)
        self.assertEqual(len(set(K.ALL_COLS)), len(K.ALL_COLS))


class TestGroupSelection(unittest.TestCase):

    def test_features_for_groups_preserves_canonical_order(self):
        cols = K.features_for_groups(["payload", "resolution"])
        self.assertEqual(cols, K.FEATURE_GROUPS["resolution"]
                         + K.FEATURE_GROUPS["payload"])

    def test_features_excluding_drops_exactly_one_group(self):
        cols = K.features_excluding("relay")
        self.assertEqual(len(cols), 12)
        for c in K.FEATURE_GROUPS["relay"]:
            self.assertNotIn(c, cols)

    def test_unknown_group_raises(self):
        with self.assertRaises(KeyError):
            K.features_for_groups(["resolution", "typo"])
        with self.assertRaises(KeyError):
            K.features_excluding("typo")


class TestIoT23Availability(unittest.TestCase):
    """The machine-checkable form of the project's central limitation."""

    def test_mock_source_can_supply_every_feature(self):
        self.assertEqual(K.unavailable_features(K.SOURCE_MOCK_LOCAL), [])
        self.assertEqual(K.proxy_features(K.SOURCE_MOCK_LOCAL), [])

    def test_every_feature_has_an_availability_entry_per_source(self):
        for source in K.SOURCE_DATASETS:
            table = K.FEATURE_AVAILABILITY[source]
            for c in K.FEATURE_COLS:
                self.assertIn(c, table, f"{source}/{c}")
                self.assertIn(
                    table[c],
                    (K.AVAIL_COMPUTABLE, K.AVAIL_PROXY, K.AVAIL_UNAVAILABLE),
                    f"{source}/{c}")

    def test_iot23_cannot_supply_the_resolution_signals(self):
        # 3 of the 4 resolution features are unrecoverable from
        # conn.log.labeled, which has no dns.log and no http.log. This is the
        # reason the thesis cannot be tested on IoT-23.
        summary = K.availability_summary(K.SOURCE_IOT23)
        self.assertEqual(summary["resolution"][K.AVAIL_UNAVAILABLE], 3)
        self.assertEqual(summary["resolution"][K.AVAIL_COMPUTABLE], 0)
        self.assertEqual(summary["resolution"][K.AVAIL_PROXY], 1)

    def test_iot23_cannot_supply_upnp(self):
        # AddPortMapping is an SSDP/SOAP payload event, not a conn.log field.
        self.assertEqual(
            K.FEATURE_AVAILABILITY[K.SOURCE_IOT23]["upnp_addportmapping"],
            K.AVAIL_UNAVAILABLE)

    def test_iot23_cannot_supply_lab_only_features(self):
        for c in K.LAB_ONLY_FEATURES:
            self.assertEqual(
                K.FEATURE_AVAILABILITY[K.SOURCE_IOT23][c],
                K.AVAIL_UNAVAILABLE, c)

    def test_iot23_unavailable_count_is_five(self):
        # ens_query_rate, resolution_entropy, serverlist_pull,
        # upnp_addportmapping, rc4_string_score.
        self.assertEqual(len(K.unavailable_features(K.SOURCE_IOT23)), 5)

    def test_availability_summary_totals_four_per_group(self):
        for source in K.SOURCE_DATASETS:
            for group, counts in K.availability_summary(source).items():
                self.assertEqual(sum(counts.values()), 4, f"{source}/{group}")


class TestOperationalSources(unittest.TestCase):
    """The product's operational sources: additive, unlabelled, and honest
    about what each telemetry format can actually measure."""

    OP = (K.SOURCE_OP_ZEEK, K.SOURCE_OP_FLOW_CSV, K.SOURCE_OP_NETFLOW,
          K.SOURCE_OP_FIREWALL)

    # The eleven features any flow log yields; the other five need DNS/HTTP
    # logs, SSDP/SOAP payload or plaintext, which no connection record carries.
    FLOW_ELEVEN = frozenset(K.FEATURE_COLS) - frozenset((
        "ens_query_rate", "resolution_entropy", "serverlist_pull",
        "upnp_addportmapping", "rc4_string_score"))

    def test_operational_sources_are_registered_datasets(self):
        self.assertEqual(K.OPERATIONAL_SOURCES, self.OP)
        for s in self.OP:
            self.assertIn(s, K.SOURCE_DATASETS)

    def test_unlabelled_confidence_is_a_distinct_controlled_value(self):
        self.assertIn(K.CONF_UNLABELLED, K.LABEL_CONFIDENCES)
        self.assertNotIn(
            K.CONF_UNLABELLED,
            (K.CONF_SYNTHETIC_GROUND_TRUTH, K.CONF_DATASET_ANNOTATED))

    def test_every_operational_source_forces_exactly_the_five_gaps(self):
        # Identical to IoT-23's unavailable set — the invariant that keeps a
        # source in agreement with the feature deriver.
        for s in self.OP:
            self.assertEqual(
                set(K.unavailable_features(s)),
                set(K.unavailable_features(K.SOURCE_IOT23)), s)
            self.assertEqual(len(K.unavailable_features(s)), 5, s)

    def test_computable_plus_proxy_is_exactly_the_flow_eleven(self):
        # Exactly what derive_features emits, so the deriver can never disagree
        # with the availability table for an operational source.
        for s in self.OP:
            union = set(K.features_by_availability(s, K.AVAIL_COMPUTABLE)) | \
                set(K.features_by_availability(s, K.AVAIL_PROXY))
            self.assertEqual(union, set(self.FLOW_ELEVEN), s)

    def test_honesty_is_monotone_in_coarseness(self):
        # Zeek/CSV are as capable as IoT-23 (two proxies); NetFlow loses
        # bidirectional/outcome/symmetry fidelity; a firewall log also loses
        # packet size. Each coarser format's proxy set contains the finer one's.
        self.assertEqual(len(K.proxy_features(K.SOURCE_OP_ZEEK)), 2)
        self.assertEqual(len(K.proxy_features(K.SOURCE_OP_FLOW_CSV)), 2)
        self.assertEqual(len(K.proxy_features(K.SOURCE_OP_NETFLOW)), 5)
        self.assertEqual(len(K.proxy_features(K.SOURCE_OP_FIREWALL)), 6)
        self.assertLessEqual(set(K.proxy_features(K.SOURCE_OP_ZEEK)),
                             set(K.proxy_features(K.SOURCE_OP_NETFLOW)))
        self.assertLessEqual(set(K.proxy_features(K.SOURCE_OP_NETFLOW)),
                             set(K.proxy_features(K.SOURCE_OP_FIREWALL)))

    def test_flow_availability_rejects_impossible_proxy_sets(self):
        with self.assertRaises(ValueError):
            K._flow_availability(("not_a_feature",))
        with self.assertRaises(ValueError):
            K._flow_availability(("serverlist_pull",))  # a gap cannot be a proxy


class TestQualityFlags(unittest.TestCase):

    def test_round_trip(self):
        flags = {K.FLAG_MISSING_FEATURES: ["b", "a"],
                 K.FLAG_LOW_FLOW_COUNT: None}
        s = K.make_flags(flags)
        back = K.parse_flags(s)
        self.assertEqual(back[K.FLAG_MISSING_FEATURES], ["a", "b"])
        self.assertIn(K.FLAG_LOW_FLOW_COUNT, back)
        self.assertEqual(back[K.FLAG_LOW_FLOW_COUNT], [])

    def test_rendering_is_deterministic(self):
        # Two runs producing the same flags must produce byte-identical CSVs,
        # so flag order cannot depend on dict insertion order.
        a = K.make_flags({K.FLAG_PROXY_FEATURES: ["x"],
                          K.FLAG_MISSING_FEATURES: ["y"]})
        b = K.make_flags({K.FLAG_MISSING_FEATURES: ["y"],
                          K.FLAG_PROXY_FEATURES: ["x"]})
        self.assertEqual(a, b)

    def test_empty_and_missing_inputs(self):
        self.assertEqual(K.make_flags(None), "")
        self.assertEqual(K.make_flags({}), "")
        self.assertEqual(K.parse_flags(""), {})
        self.assertEqual(K.parse_flags(None), {})
        self.assertEqual(K.parse_flags(float("nan")), {})

    def test_flag_names_avoid_separator_characters(self):
        for name in K.QUALITY_FLAG_NAMES:
            for sep in (K.FLAG_SEP, K.FLAG_ARG_SEP, K.FLAG_LIST_SEP):
                self.assertNotIn(sep, name, name)


if __name__ == "__main__":
    unittest.main()
