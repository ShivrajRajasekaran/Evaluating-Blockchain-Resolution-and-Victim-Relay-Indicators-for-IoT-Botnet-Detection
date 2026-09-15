"""
tests/test_iot23_labels.py — the IoT-23 label mapping.

This mapping is the single most contestable decision in Track A, so the tests
are written to be read as an argument rather than as coverage. Three things
matter more than the rest:

  * NO IoT-23 label, however spelled, may reach a Track B class. That would
    fabricate real-world evidence for this project's central claim out of a 2018
    dataset that contains none of the phenomenon. Tested exhaustively over a
    vocabulary of real and deliberately awkward labels, not just spot-checked.
  * An unrecognised label becomes CLS_UNMAPPED and is never guessed into the
    nearest-spelled class.
  * A window is malicious if ANY flow in it is, and the malicious FRACTION
    survives so that the 3%-malicious and 100%-malicious windows sharing one
    label remain distinguishable downstream.
"""
from __future__ import annotations

import math
import unittest

from src.ingest import iot23_labels as L
from src.schema import columns as K

# Labels observed in the published IoT-23 tables, plus the composed and
# oddly-spelled forms the corpus actually contains. Used by the exhaustive
# no-Track-B test below, so anything added here is automatically covered.
REAL_DETAILED_LABELS: tuple[str, ...] = (
    "-",
    "C&C",
    "C&C-HeartBeat",
    "C&C-FileDownload",
    "C&C-HeartBeat-FileDownload",
    "C&C-HeartBeat-Attack",
    "C&C-Mirai",
    "C&C-Torii",
    "C&C-PartOfAHorizontalPortScan",
    "PartOfAHorizontalPortScan",
    "PartOfAHorizontalPortScan-Attack",
    "Attack",
    "DDoS",
    "FileDownload",
    "Okiru",
    "Okiru-Attack",
    "Torii",
    "Mirai",
    "Muhstik",
    "Hakai",
    "Hajime",
    "Kenjiro",
    "HideAndSeek",
    "Hide and Seek",
    # Awkward but plausible: casing, padding, and vocabulary this module has
    # never seen.
    "   c&c-heartbeat   ",
    "CC-HeartBeat",
    "SomeFutureLabelNobodyHasWrittenYet",
    "blockchain",              # the adversarial case: the WORD appears
    "ENS-Resolution",          # ditto, and it must still not map to Track B
    "victim-relay",
)

COARSE_LABELS: tuple[str, ...] = (
    "Benign", "benign", "  BENIGN  ",
    "Malicious", "malicious", " MALICIOUS ",
    "-", "", "Unknown", "nan", "(empty)",
)


class TestTheAbsoluteRule(unittest.TestCase):
    """No IoT-23 label may ever map to a Track B (mock) class.

    IoT-23 was captured in 2018-2019 and predates blockchain-anchored C2. If a
    label here could reach blockchain_resolution_mock or victim_relay_mock, the
    project would be able to report real-world detections of a phenomenon its
    real dataset does not contain — which is the exact fabrication the whole
    two-track design exists to prevent.
    """

    def test_no_pair_in_the_vocabulary_reaches_a_track_b_class(self):
        for coarse in COARSE_LABELS:
            for detail in REAL_DETAILED_LABELS:
                cls = L.map_flow_label(coarse, detail)
                self.assertNotIn(cls, K.TRACK_B_CLASSES,
                                 msg=f"({coarse!r}, {detail!r}) -> {cls}")

    def test_labels_naming_the_phenomenon_still_do_not_map_to_it(self):
        # The strongest form of the rule. Even a label that literally says
        # "blockchain" is only ever a string in a 2018 capture; treating it as
        # ground truth for the thesis would be circular.
        for detail in ("blockchain", "ENS-Resolution", "victim-relay",
                       "BlockchainC2", "ens", "sns-domain"):
            cls = L.map_flow_label("Malicious", detail)
            self.assertNotIn(cls, K.TRACK_B_CLASSES, msg=detail)
            self.assertIn(cls, (K.CLS_TRADITIONAL_C2, K.CLS_TRADITIONAL_BOTNET,
                                K.CLS_UNMAPPED), msg=detail)

    def test_every_reachable_class_is_a_track_a_class_or_unmapped(self):
        reachable = {L.map_flow_label(c, d)
                     for c in COARSE_LABELS for d in REAL_DETAILED_LABELS}
        allowed = set(K.TRACK_A_CLASSES) | {K.CLS_UNMAPPED}
        self.assertTrue(reachable <= allowed, msg=sorted(reachable - allowed))

    def test_class_priority_holds_no_track_b_class(self):
        # The module asserts this at import time; asserting it here too means the
        # failure is reported by name in the test run rather than as an
        # ImportError in whichever module happened to import first.
        self.assertFalse(set(L.CLASS_PRIORITY) & set(K.TRACK_B_CLASSES))

    def test_window_resolution_cannot_invent_a_track_b_class(self):
        # The per-flow mapping is not the only path to a class: resolve_window_
        # class picks one. Feed it Track B classes directly — the pathological
        # input a future caller might produce — and it must still only return
        # something from its own priority list.
        cls, _ = L.resolve_window_class(
            [K.CLS_BENIGN_REAL, K.CLS_TRADITIONAL_C2])
        self.assertIn(cls, L.CLASS_PRIORITY)


class TestCoarseLabel(unittest.TestCase):
    def test_benign_maps_to_benign_real(self):
        for spelling in ("Benign", "benign", "  BENIGN  "):
            self.assertEqual(L.map_flow_label(spelling, "-"),
                             K.CLS_BENIGN_REAL, msg=spelling)

    def test_benign_wins_over_a_contradictory_detailed_label(self):
        # A benign flow carrying "C&C" is a contradiction in the source. The
        # source's own coarse verdict is what we defer to; the contradiction
        # stays visible in original_label rather than being reinterpreted here.
        self.assertEqual(L.map_flow_label("Benign", "C&C"), K.CLS_BENIGN_REAL)

    def test_unreadable_coarse_label_is_unmapped(self):
        for spelling in ("-", "", "   ", "nan", "Unknown", "(empty)"):
            self.assertEqual(L.map_flow_label(spelling, "C&C"), K.CLS_UNMAPPED,
                             msg=spelling)

    def test_unreadable_coarse_label_is_unmapped_even_with_a_known_detail(self):
        # Worth stating separately: the detail is recognisable, so a mapping that
        # short-circuited on the detail field would classify this as C2. It must
        # not — we do not know whether the source called this flow malicious.
        self.assertEqual(L.map_flow_label("-", "PartOfAHorizontalPortScan"),
                         K.CLS_UNMAPPED)


class TestMaliciousDetail(unittest.TestCase):
    def test_c2_markers_map_to_traditional_c2(self):
        for detail in ("C&C", "C&C-HeartBeat", "C&C-FileDownload",
                       "C&C-HeartBeat-FileDownload", "C&C-Torii", "C&C-Mirai",
                       "CC-HeartBeat", "  c&c  "):
            self.assertEqual(L.map_flow_label("Malicious", detail),
                             K.CLS_TRADITIONAL_C2, msg=detail)

    def test_botnet_markers_map_to_traditional_botnet(self):
        for detail in ("PartOfAHorizontalPortScan", "DDoS", "Attack", "Okiru",
                       "Torii", "Mirai", "Muhstik", "Hakai", "Hajime",
                       "Kenjiro", "HideAndSeek", "FileDownload", "HeartBeat"):
            self.assertEqual(L.map_flow_label("Malicious", detail),
                             K.CLS_TRADITIONAL_BOTNET, msg=detail)

    def test_c2_outranks_botnet_in_a_composed_label(self):
        # "C&C-PartOfAHorizontalPortScan" holds both markers. C2 is the more
        # specific observation: collapsing it to generic botnet activity would
        # erase the finding that matters.
        self.assertEqual(
            L.map_flow_label("Malicious", "C&C-PartOfAHorizontalPortScan"),
            K.CLS_TRADITIONAL_C2)

    def test_malicious_with_no_detail_is_botnet_not_unmapped(self):
        # Known-bad of unknown kind is real information. Dropping it to unmapped
        # would discard confirmed malicious traffic; the broader of the two
        # malicious classes is the honest home for it.
        for detail in ("-", "", "none", "(empty)", "nan"):
            self.assertEqual(L.map_flow_label("Malicious", detail),
                             K.CLS_TRADITIONAL_BOTNET, msg=detail)

    def test_malicious_with_an_unrecognised_detail_is_unmapped(self):
        # The distinction that keeps the mapping honest. We know it is malicious
        # but not which kind, and there is no basis for choosing — so it is not
        # chosen. Contrast with the no-detail case above, where the ABSENCE of a
        # detail is itself the information.
        self.assertEqual(
            L.map_flow_label("Malicious", "SomeFutureLabelNobodyWroteYet"),
            K.CLS_UNMAPPED)


class TestRawLabelString(unittest.TestCase):
    """original_label must let a reader recover what the dataset said."""

    def test_pair_is_joined_with_a_pipe(self):
        self.assertEqual(L.raw_label_string("Malicious", "C&C-HeartBeat"),
                         "Malicious|C&C-HeartBeat")

    def test_null_detail_is_omitted_not_rendered(self):
        for detail in ("-", "", "  ", "none", "(empty)"):
            self.assertEqual(L.raw_label_string("Benign", detail), "Benign",
                             msg=detail)

    def test_source_spelling_is_preserved_exactly(self):
        # Not normalised: the point of this column is that it is the source's own
        # words, so a reviewer can check our interpretation against them.
        self.assertEqual(L.raw_label_string("MALICIOUS", "c&c-HeArTbEaT"),
                         "MALICIOUS|c&c-HeArTbEaT")

    def test_surrounding_whitespace_is_stripped(self):
        # Stripping is not normalising: a trailing tab from the TSV is an
        # artefact of the file format, not something the dataset said.
        self.assertEqual(L.raw_label_string("  Malicious ", " C&C "),
                         "Malicious|C&C")

    def test_the_string_round_trips_back_to_a_class(self):
        # The adapter reconstructs the per-flow class from this string after
        # windowing (_class_of_raw). If the two ever disagreed, window labels
        # would be resolved from classes that no flow actually had.
        from src.ingest.iot23 import _class_of_raw
        for coarse in ("Benign", "Malicious", "-"):
            for detail in REAL_DETAILED_LABELS:
                raw = L.raw_label_string(coarse, detail)
                self.assertEqual(_class_of_raw(raw),
                                 L.map_flow_label(coarse, detail),
                                 msg=f"{coarse!r} {detail!r} -> {raw!r}")


class TestWindowResolution(unittest.TestCase):
    def test_all_benign_window_is_benign(self):
        cls, frac = L.resolve_window_class([K.CLS_BENIGN_REAL] * 5)
        self.assertEqual(cls, K.CLS_BENIGN_REAL)
        self.assertEqual(frac, 0.0)

    def test_a_single_malicious_flow_makes_the_window_malicious(self):
        # ANY, not majority. A detector that misses a compromised device because
        # only one of its flows was attack traffic has missed the device; a
        # majority vote would relabel that device benign and understate the
        # false-negative rate.
        cls, frac = L.resolve_window_class(
            [K.CLS_BENIGN_REAL] * 99 + [K.CLS_TRADITIONAL_C2])
        self.assertEqual(cls, K.CLS_TRADITIONAL_C2)
        self.assertAlmostEqual(frac, 0.01)

    def test_c2_outranks_botnet_within_a_window(self):
        cls, _ = L.resolve_window_class(
            [K.CLS_TRADITIONAL_BOTNET] * 10 + [K.CLS_TRADITIONAL_C2])
        self.assertEqual(cls, K.CLS_TRADITIONAL_C2)

    def test_fraction_distinguishes_a_trace_from_a_saturated_window(self):
        # The cost of ANY-semantics is that these two share a label. The fraction
        # is what pays it back — the adapter writes it into
        # FLAG_MIXED_LABEL_WINDOW so the distinction survives into the table.
        _, trace = L.resolve_window_class(
            [K.CLS_BENIGN_REAL] * 19 + [K.CLS_TRADITIONAL_C2])
        _, saturated = L.resolve_window_class([K.CLS_TRADITIONAL_C2] * 20)
        self.assertAlmostEqual(trace, 0.05)
        self.assertAlmostEqual(saturated, 1.0)
        self.assertLess(trace, saturated)

    def test_unmapped_flows_do_not_contaminate_a_labelled_window(self):
        # Most windows in a real capture will contain a few unreadable rows.
        # Letting those decide the window would throw away the labelled majority.
        cls, _ = L.resolve_window_class(
            [K.CLS_UNMAPPED] * 3 + [K.CLS_BENIGN_REAL] * 7)
        self.assertEqual(cls, K.CLS_BENIGN_REAL)

    def test_a_window_of_only_unmapped_flows_is_unmapped_with_nan_fraction(self):
        # NaN, not 0.0. Zero would assert "this window contained no malicious
        # traffic", which is precisely what is not known.
        cls, frac = L.resolve_window_class([K.CLS_UNMAPPED] * 4)
        self.assertEqual(cls, K.CLS_UNMAPPED)
        self.assertTrue(math.isnan(frac))

    def test_unmapped_flows_are_in_the_fraction_denominator(self):
        # 1 malicious + 1 benign + 2 unmapped is 25% malicious, not 50%. The
        # denominator is every flow observed, because the fraction's job is to
        # describe the window, not the subset we could label.
        _, frac = L.resolve_window_class(
            [K.CLS_TRADITIONAL_C2, K.CLS_BENIGN_REAL] + [K.CLS_UNMAPPED] * 2)
        self.assertAlmostEqual(frac, 0.25)

    def test_an_empty_window_raises(self):
        # A window with no flows cannot exist downstream — windows are created BY
        # flows. Returning a default class would mean a bug upstream produced a
        # labelled row from nothing.
        with self.assertRaises(ValueError):
            L.resolve_window_class([])


if __name__ == "__main__":
    unittest.main(verbosity=2)
