"""
tests/test_detection_engine — the rule engine: category mapping, the coverage
honesty gate, config-driven severity and confidence, the ML gate that refuses,
and the abstention channel.

The load-bearing tests here are the ones about SILENCE. A rule that cannot be
evaluated does not fire, so a naive engine reports an unmeasurable device and a
genuinely quiet one identically and calls both benign. On a Zeek conn.log both
resolution rules are NaN on every window, so that failure would not be an edge
case — it would be the product's normal output. `CoverageGate` and
`OperationalZeekEndToEnd` pin the correct behaviour: INSUFFICIENT_TELEMETRY,
with the configured reason attached.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import ConfigNode, load_config
from src.detection import categories as C
from src.detection import coverage as COV
from src.detection import engine as E
from src.detection import model_gate as G
from src.detection.severity import (SEVERITIES, SeverityConfigError,
                                    SeverityPolicy, SeverityRule, max_severity)
from src.models.heuristic import RULES, HeuristicDetector
from src.schema import columns as K

from tests import helpers as H

# A frame built from tests/helpers defaults already fires one rule:
# beacon_interval defaults to 60.0 and the rule is `> 20.0`. Every "quiet"
# fixture below therefore has to say so explicitly, which is itself worth
# knowing — QuietBaseline.test_default_helper_frame_is_not_quiet pins it so a
# future change to the helper defaults cannot silently turn these tests green.
QUIET = {"beacon_interval": 5.0}


def _cfg_with(**detection_overrides):
    """The default config with `detection` keys replaced, as a ConfigNode.

    Deep-copies through ``as_dict`` so a test cannot mutate the module-level
    config cache that every other test shares.
    """
    data = load_config().as_dict()
    for dotted, value in detection_overrides.items():
        node = data["detection"]
        *parents, leaf = dotted.split(".")
        for p in parents:
            node = node[p]
        node[leaf] = value
    return ConfigNode(data)


# ===========================================================================
# categories
# ===========================================================================
class Categories(unittest.TestCase):
    def test_the_seven_names_are_verbatim(self):
        # These strings are persisted, filtered on and rendered; changing one is
        # a data migration, so they are pinned literally rather than by symbol.
        self.assertEqual(
            C.CATEGORIES,
            ("BENIGN_OR_NO_ALERT", "SUSPICIOUS_RESOLUTION_PATTERN",
             "SUSPICIOUS_RELAY_PATTERN", "SUSPICIOUS_COMBINED_PATTERN",
             "SUSPICIOUS_CONVENTIONAL_BOTNET_PATTERN", "INSUFFICIENT_TELEMETRY",
             "ABSTAIN"))

    def test_no_category_claims_confirmation(self):
        banned = ("CONFIRM", "MALICIOUS", "COMPROMIS", "INFECTED", "CLEAN")
        for cat in C.CATEGORIES:
            for word in banned:
                self.assertNotIn(word, cat.upper(),
                                 f"{cat} reads as a confirmation")

    def test_group_to_category_mapping(self):
        self.assertEqual(C.category_for_groups({"resolution"}),
                         C.CAT_SUSPICIOUS_RESOLUTION)
        self.assertEqual(C.category_for_groups({"relay"}),
                         C.CAT_SUSPICIOUS_RELAY)
        self.assertEqual(C.category_for_groups({"infection"}),
                         C.CAT_SUSPICIOUS_CONVENTIONAL)
        self.assertEqual(C.category_for_groups({"payload"}),
                         C.CAT_SUSPICIOUS_CONVENTIONAL)

    def test_resolution_plus_relay_is_the_combined_category(self):
        self.assertEqual(C.category_for_groups({"resolution", "relay"}),
                         C.CAT_SUSPICIOUS_COMBINED)
        # ...and stays combined when conventional groups fire alongside it.
        self.assertEqual(
            C.category_for_groups({"resolution", "relay", "infection"}),
            C.CAT_SUSPICIOUS_COMBINED)

    def test_novel_group_outranks_conventional_in_the_headline(self):
        self.assertEqual(C.category_for_groups({"resolution", "payload"}),
                         C.CAT_SUSPICIOUS_RESOLUTION)
        self.assertEqual(C.category_for_groups({"relay", "infection"}),
                         C.CAT_SUSPICIOUS_RELAY)

    def test_no_fired_group_is_not_a_verdict(self):
        # None, not "benign": the caller decides from coverage.
        self.assertIsNone(C.category_for_groups(set()))

    def test_only_the_four_suspicious_categories_alert(self):
        for cat in C.CATEGORIES:
            expected = cat.startswith("SUSPICIOUS_")
            self.assertEqual(C.raises_alert(cat), expected, cat)

    def test_every_rule_feature_has_a_category(self):
        for feat, _op, _thr, _reason in RULES:
            self.assertIn(C.category_for_feature(feat), C.ALERTING_CATEGORIES)

    def test_unknown_names_raise(self):
        with self.assertRaises(KeyError):
            C.category_for_groups({"not_a_group"})
        with self.assertRaises(KeyError):
            C.raises_alert("MALICIOUS")


# ===========================================================================
# coverage
# ===========================================================================
class CoverageAssessment(unittest.TestCase):
    def test_a_fully_measured_window_gates_nothing(self):
        values = {c: 1.0 for c in K.FEATURE_COLS}
        report = COV.assess_window(values)
        self.assertEqual(report.gated_groups, ())
        self.assertEqual(report.n_rules_evaluable, len(RULES))
        self.assertEqual(report.note(), "")

    def test_nan_is_not_measured_and_is_never_zero(self):
        values = {c: 1.0 for c in K.FEATURE_COLS}
        values["ens_query_rate"] = float("nan")
        cov = COV.assess_window(values)["resolution"]
        self.assertEqual(cov.n_features_present, 3)
        self.assertEqual(cov.feature_coverage, 0.75)
        # serverlist_pull is still evaluable, so the group is judgeable.
        self.assertFalse(cov.gated)

    def test_a_group_with_no_evaluable_rule_is_gated(self):
        values = {c: 1.0 for c in K.FEATURE_COLS}
        for feat in ("ens_query_rate", "serverlist_pull"):
            values[feat] = float("nan")
        report = COV.assess_window(values)
        self.assertIn("resolution", report.gated_groups)
        # Gated despite half its FEATURES being present — silence from zero
        # evaluable rules carries no information at any coverage threshold.
        self.assertEqual(report["resolution"].feature_coverage, 0.5)
        self.assertEqual(report["resolution"].rule_coverage, 0.0)

    def test_missing_column_counts_exactly_like_nan(self):
        values = {c: 1.0 for c in K.FEATURE_COLS
                  if c not in ("ens_query_rate", "serverlist_pull")}
        self.assertIn("resolution", COV.assess_window(values).gated_groups)

    def test_infinity_and_unparseable_values_are_not_measurements(self):
        for bad in (float("inf"), "n/a", None):
            values = {c: 1.0 for c in K.FEATURE_COLS}
            values["ens_query_rate"] = bad
            values["serverlist_pull"] = bad
            self.assertIn("resolution",
                          COV.assess_window(values).gated_groups, repr(bad))

    def test_gated_group_carries_the_configured_reason(self):
        cfg = load_config()
        values = {c: 1.0 for c in K.FEATURE_COLS}
        values["ens_query_rate"] = float("nan")
        values["serverlist_pull"] = float("nan")
        report = COV.assess_window(values, cov_cfg=cfg.detection.coverage)
        note = report.note()
        self.assertIn("Resolution indicators require resolver/DNS/HTTP "
                      "telemetry absent from this source", note)

    def test_ungated_group_without_a_configured_reason_gets_a_measured_one(self):
        values = {c: 1.0 for c in K.FEATURE_COLS}
        values["login_burst_count"] = float("nan")
        cov = COV.assess_window(values)["infection"]
        self.assertTrue(cov.gated)
        self.assertIn("3 of 4 features present", cov.reason)
        self.assertIn("0 of 1 rules evaluable", cov.reason)

    def test_min_group_coverage_gates_a_partly_present_group(self):
        cfg = _cfg_with(**{"coverage.min_group_coverage": 0.8})
        values = {c: 1.0 for c in K.FEATURE_COLS}
        values["ens_query_rate"] = float("nan")     # resolution -> 0.75
        report = COV.assess_window(values, cov_cfg=cfg.detection.coverage)
        self.assertIn("resolution", report.gated_groups)
        # The other groups are fully present and stay judgeable at 1.0 > 0.8.
        self.assertEqual(set(report.gated_groups), {"resolution"})

    def test_note_can_exclude_a_group_that_fired_after_all(self):
        values = {c: 1.0 for c in K.FEATURE_COLS}
        values["login_burst_count"] = float("nan")
        report = COV.assess_window(values)
        self.assertNotEqual(report.note(), "")
        self.assertEqual(report.note(exclude=("infection",)), "")

    def test_assess_frame_is_row_wise_and_order_preserving(self):
        frame = H.feature_frame(3)
        frame.loc[1, "ens_query_rate"] = np.nan
        frame.loc[1, "serverlist_pull"] = np.nan
        reports = COV.assess_frame(frame)
        self.assertEqual([r.gated_groups for r in reports],
                         [(), ("resolution",), ()])

    def test_frame_with_no_feature_columns_measures_nothing(self):
        reports = COV.assess_frame(pd.DataFrame({"x": [1, 2]}))
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0].n_rules_evaluable, 0)
        self.assertEqual(set(reports[0].gated_groups), set(K.FEATURE_GROUPS))


class SourceCoverage(unittest.TestCase):
    """What a source can say BEFORE any file is uploaded, read from the schema."""

    def test_mock_source_can_judge_every_group(self):
        cov = COV.source_coverage(K.SOURCE_MOCK_LOCAL)
        self.assertTrue(all(g["judgeable"] for g in cov.values()))

    def test_zeek_conn_log_can_say_nothing_about_resolution(self):
        for source in (K.SOURCE_IOT23, K.SOURCE_OP_ZEEK):
            cov = COV.source_coverage(source)
            self.assertFalse(cov["resolution"]["judgeable"], source)
            self.assertEqual(cov["resolution"]["rule_coverage"], 0.0, source)
            # Relay is partial, not absent: updownlink_ratio survives, UPnP
            # does not. This is the project's central limitation, in numbers.
            self.assertEqual(cov["relay"]["rule_coverage"], 0.5, source)
            self.assertTrue(cov["infection"]["judgeable"], source)

    def test_every_operational_source_is_covered(self):
        for source in K.OPERATIONAL_SOURCES:
            cov = COV.source_coverage(source)
            self.assertEqual(set(cov), set(K.FEATURE_GROUPS), source)


# ===========================================================================
# severity + confidence
# ===========================================================================
class Severity(unittest.TestCase):
    def setUp(self):
        self.policy = SeverityPolicy.from_config(load_config().detection)

    def test_default_table_grades_by_votes_and_groups(self):
        p = self.policy
        self.assertEqual(p.severity_for(votes=0, n_groups=0), "INFO")
        self.assertEqual(p.severity_for(votes=1, n_groups=1), "LOW")
        self.assertEqual(p.severity_for(votes=2, n_groups=1), "MEDIUM")
        self.assertEqual(p.severity_for(votes=3, n_groups=2), "HIGH")

    def test_breadth_matters_not_just_count(self):
        # Three votes inside ONE group does not reach HIGH; the table requires
        # two independent indicator groups to agree.
        self.assertEqual(self.policy.severity_for(votes=3, n_groups=1),
                         "MEDIUM")

    def test_combined_floor_raises_but_never_lowers(self):
        low_only = SeverityPolicy(
            default="INFO", rules=(SeverityRule(1, 1, "LOW"),),
            combined_floor="MEDIUM", medium_at=0.34, high_at=0.67)
        self.assertEqual(low_only.severity_for(votes=2, n_groups=2), "LOW")
        self.assertEqual(
            low_only.severity_for(votes=2, n_groups=2, floor="MEDIUM"),
            "MEDIUM")
        # A floor below an earned severity leaves it alone.
        self.assertEqual(
            self.policy.severity_for(votes=3, n_groups=2, floor="MEDIUM"),
            "HIGH")

    def test_confidence_bands(self):
        p = self.policy
        self.assertEqual(p.confidence_for(0.0), "low")
        self.assertEqual(p.confidence_for(0.33), "low")
        self.assertEqual(p.confidence_for(0.34), "medium")
        self.assertEqual(p.confidence_for(0.66), "medium")
        self.assertEqual(p.confidence_for(0.67), "high")
        self.assertEqual(p.confidence_for(1.0), "high")

    def test_vote_fraction_divides_by_evaluable_rules(self):
        p = self.policy
        self.assertAlmostEqual(p.vote_fraction(1, 3), 1 / 3)
        self.assertAlmostEqual(p.vote_fraction(3, 3), 1.0)
        # Nothing evaluable is 0.0, not a ZeroDivisionError.
        self.assertEqual(p.vote_fraction(0, 0), 0.0)

    def test_malformed_config_fails_at_load_not_at_alert_time(self):
        with self.assertRaises(SeverityConfigError):
            SeverityPolicy.from_config(_cfg_with(**{
                "severity.default": "CRITICAL"}).detection)
        with self.assertRaises(SeverityConfigError):
            SeverityPolicy.from_config(_cfg_with(**{
                "severity.rules": [{"min_votes": 1, "severity": "LOW"}],
            }).detection)
        with self.assertRaises(SeverityConfigError):
            SeverityPolicy.from_config(_cfg_with(**{
                "confidence_bands.medium_at": 0.9,
                "confidence_bands.high_at": 0.2}).detection)

    def test_max_severity_orders_by_urgency(self):
        self.assertEqual(max_severity("LOW", "HIGH"), "HIGH")
        self.assertEqual(max_severity("MEDIUM", "INFO"), "MEDIUM")
        self.assertEqual(SEVERITIES[-1], "HIGH")


# ===========================================================================
# the ML gate
# ===========================================================================
class ModelGate(unittest.TestCase):
    def setUp(self):
        self.cfg = load_config()

    def test_rule_mode_needs_no_gate_and_is_always_available(self):
        decision = G.evaluate_gate(self.cfg, requested_mode=G.MODE_RULE)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.mode, G.MODE_RULE)
        self.assertEqual(decision.reasons, ())

    def test_model_mode_is_refused_by_shipped_config(self):
        decision = G.evaluate_gate(self.cfg, requested_mode=G.MODE_MODEL)
        self.assertTrue(decision.refused)
        self.assertEqual(decision.mode, G.MODE_RULE)   # falls back, never fails
        self.assertIn("disabled in configuration", " ".join(decision.reasons))

    def test_refusal_notice_says_rule_based_and_not_ml_validated(self):
        decision = G.evaluate_gate(self.cfg, requested_mode=G.MODE_MODEL)
        self.assertIn("Rule-based detection; not ML-validated.",
                      decision.notice)

    def test_enabled_but_no_registry_still_refuses(self):
        cfg = _cfg_with(**{"model.enabled": True})
        decision = G.evaluate_gate(cfg, requested_mode=G.MODE_MODEL)
        self.assertTrue(decision.refused)
        self.assertIn("no model registry", " ".join(decision.reasons))

    def test_unknown_mode_raises(self):
        with self.assertRaises(ValueError):
            G.evaluate_gate(self.cfg, requested_mode="guess")


class ModelGateAgainstTheRegistry(unittest.TestCase):
    """The gate against a real database, which is where it will actually run."""

    def setUp(self):
        from src.storage import Database, Repository, migrate, utcnow_iso
        self._dir = Path(tempfile.mkdtemp(prefix="als_gate_"))
        self.db = Database(self._dir / "app.db")
        migrate(self.db)
        self._Repository = Repository
        self._now = utcnow_iso
        self.cfg = _cfg_with(**{"model.enabled": True})

    def tearDown(self):
        shutil.rmtree(self._dir, ignore_errors=True)

    def _register(self, **kwargs):
        with self.db.transaction() as conn:
            self._Repository(conn).models.register(
                name="detector", version="v1", kind="ml",
                registered_at=self._now(), **kwargs)

    def _decide(self):
        with self.db.connection() as conn:
            return G.evaluate_gate(self.cfg,
                                   repo=self._Repository(conn),
                                   requested_mode=G.MODE_MODEL)

    def _valid_kwargs(self, **overrides):
        kwargs = {
            "is_validated": True,
            "training_provenance": "authorised labelled capture 2026-03",
            "validation_metrics_json": json.dumps({"f1": 0.81}),
            "calibrated_threshold": 0.62,
            "feature_schema_json": json.dumps(list(K.FEATURE_COLS)),
        }
        kwargs.update(overrides)
        return kwargs

    def test_empty_registry_refuses(self):
        decision = self._decide()
        self.assertTrue(decision.refused)
        self.assertIn("no registered detection model is marked validated",
                      " ".join(decision.reasons))

    def test_rule_baseline_is_not_a_model(self):
        with self.db.transaction() as conn:
            self._Repository(conn).models.get_or_create_rule_baseline(
                name="rule-baseline", version=E.RULESET_VERSION,
                registered_at=self._now())
        self.assertTrue(self._decide().refused)

    def test_unvalidated_model_refuses(self):
        self._register(**self._valid_kwargs(is_validated=False))
        self.assertTrue(self._decide().refused)

    def test_synthetic_training_provenance_is_refused_outright(self):
        self._register(**self._valid_kwargs(
            training_provenance="Track B synthetic mock generator, seed 42"))
        decision = self._decide()
        self.assertTrue(decision.refused)
        self.assertIn("synthetic training provenance",
                      " ".join(decision.reasons))

    def test_missing_metrics_threshold_or_schema_each_refuse(self):
        for field, value in (("validation_metrics_json", None),
                             ("calibrated_threshold", None),
                             ("feature_schema_json", None)):
            with self.subTest(field=field):
                shutil.rmtree(self._dir, ignore_errors=True)
                self.setUp()
                self._register(**self._valid_kwargs(**{field: value}))
                self.assertTrue(self._decide().refused)

    def test_schema_mismatch_refuses(self):
        self._register(**self._valid_kwargs(
            feature_schema_json=json.dumps(list(K.FEATURE_COLS)[:-1])))
        decision = self._decide()
        self.assertTrue(decision.refused)
        self.assertIn("feature schema does not match",
                      " ".join(decision.reasons))

    def test_a_fully_validated_model_is_the_only_thing_that_passes(self):
        self._register(**self._valid_kwargs())
        decision = self._decide()
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.mode, G.MODE_MODEL)
        self.assertEqual(decision.model_version, "v1")


# ===========================================================================
# the engine
# ===========================================================================
class QuietBaseline(unittest.TestCase):
    def test_default_helper_frame_is_not_quiet(self):
        # Guards every QUIET fixture below: beacon_interval defaults to 60.0 and
        # the rule fires above 20.0, so "no overrides" is a firing window.
        result = E.detect(H.mock_frame(1))
        self.assertEqual(result.verdicts[0].category,
                         C.CAT_SUSPICIOUS_CONVENTIONAL)

    def test_fully_measured_quiet_window_is_benign_or_no_alert(self):
        result = E.detect(H.mock_frame(2, **QUIET))
        for v in result.verdicts:
            self.assertEqual(v.category, C.CAT_BENIGN_OR_NO_ALERT)
            self.assertEqual(v.votes, 0)
            self.assertEqual(v.n_evaluable_rules, len(RULES))
            self.assertEqual(v.coverage_note, "")
            self.assertFalse(v.raises_alert)
            self.assertEqual(v.severity, "INFO")


class CategoryFromRules(unittest.TestCase):
    """Which rule fires decides the headline, on a fully measurable source."""

    def _one(self, **overrides):
        result = E.detect(H.mock_frame(1, **{**QUIET, **overrides}))
        return result.verdicts[0]

    def test_resolution_rule_yields_the_resolution_category(self):
        v = self._one(ens_query_rate=9.0)
        self.assertEqual(v.category, C.CAT_SUSPICIOUS_RESOLUTION)
        self.assertEqual(v.fired_groups, ("resolution",))
        self.assertEqual(v.severity, "LOW")
        self.assertTrue(v.raises_alert)

    def test_relay_rule_yields_the_relay_category(self):
        v = self._one(upnp_addportmapping=1.0)
        self.assertEqual(v.category, C.CAT_SUSPICIOUS_RELAY)
        self.assertEqual(v.fired_groups, ("relay",))

    def test_conventional_rules_yield_the_conventional_category(self):
        v = self._one(login_burst_count=5.0)
        self.assertEqual(v.category, C.CAT_SUSPICIOUS_CONVENTIONAL)
        self.assertEqual(v.fired_groups, ("infection",))

    def test_resolution_and_relay_together_are_the_combined_category(self):
        v = self._one(ens_query_rate=9.0, upnp_addportmapping=1.0)
        self.assertEqual(v.category, C.CAT_SUSPICIOUS_COMBINED)
        self.assertEqual(v.fired_groups, ("resolution", "relay"))
        self.assertEqual(v.votes, 2)
        # Two votes across two groups earns MEDIUM, and combined_floor holds it
        # at MEDIUM or above whatever the table says.
        self.assertEqual(v.severity, "MEDIUM")

    def test_breadth_escalates_severity_to_high(self):
        v = self._one(ens_query_rate=9.0, upnp_addportmapping=1.0,
                      login_burst_count=5.0)
        self.assertEqual(v.severity, "HIGH")
        self.assertEqual(v.votes, 3)
        self.assertEqual(v.category, C.CAT_SUSPICIOUS_COMBINED)


class Evidence(unittest.TestCase):
    def setUp(self):
        self.v = E.detect(
            H.mock_frame(1, **QUIET, ens_query_rate=9.0)).verdicts[0]

    def test_a_hit_carries_the_value_and_the_threshold_it_crossed(self):
        self.assertEqual(len(self.v.hits), 1)
        hit = self.v.hits[0]
        self.assertEqual(hit.feature, "ens_query_rate")
        self.assertEqual(hit.group, "resolution")
        self.assertEqual(hit.op, ">")
        self.assertEqual(hit.threshold, 3.0)
        self.assertEqual(hit.value, 9.0)

    def test_explanation_names_the_rule_in_words(self):
        self.assertIn("high blockchain-name query rate", self.v.explanation)
        self.assertIn("ens_query_rate = 9", self.v.explanation)

    def test_user_facing_explanation_always_carries_the_marker(self):
        self.assertTrue(self.v.explanation_with_marker.endswith(
            "Rule-based detection; not ML-validated."))

    def test_the_coverage_note_is_a_field_not_an_inlined_sentence(self):
        """It travels separately so no page states it three times.

        Every surface renders coverage_note in its own right — a notice box, an
        evidence row, a CSV column — so folding it into the explanation too
        would triplicate it and make the evidence line a run-on.
        """
        v = E.detect(H.op_frame(1, **QUIET,
                                updownlink_ratio=0.9)).verdicts[0]
        self.assertIn("no resolution judgement can be made", v.coverage_note)
        self.assertNotIn("no resolution judgement can be made",
                         v.explanation_with_marker)

    def test_verdict_serialises_for_storage_and_the_api(self):
        d = self.v.as_dict()
        self.assertEqual(d["category"], C.CAT_SUSPICIOUS_RESOLUTION)
        self.assertEqual(d["provenance"], E.PROV_RULE_ENGINE)
        self.assertEqual(d["detection_version"], "ruleset-1")
        self.assertEqual(d["hits"][0]["feature"], "ens_query_rate")
        self.assertIn("resolution", d["coverage"])
        json.dumps(d)     # must survive the API's JSON encoder


class CoverageGate(unittest.TestCase):
    """The honesty rule: unmeasurable is not benign."""

    def test_zeek_quiet_window_is_insufficient_telemetry_not_benign(self):
        result = E.detect(H.op_frame(2, **QUIET))
        for v in result.verdicts:
            self.assertEqual(v.category, C.CAT_INSUFFICIENT_TELEMETRY)
            self.assertEqual(v.reason, E.REASON_COVERAGE)
            self.assertEqual(v.coverage.gated_groups, ("resolution",))
            self.assertIn("no resolution judgement can be made",
                          v.coverage_note)
            # It is a state of knowledge, not a finding: no analyst queue entry.
            self.assertFalse(v.raises_alert)

    def test_a_window_nothing_could_be_evaluated_on_says_so(self):
        frame = H.mock_frame(1, **QUIET)
        for feat, _op, _thr, _reason in RULES:
            frame.loc[0, feat] = np.nan
        v = E.detect(frame).verdicts[0]
        self.assertEqual(v.category, C.CAT_INSUFFICIENT_TELEMETRY)
        self.assertEqual(v.reason, E.REASON_NO_EVALUABLE_RULES)
        self.assertEqual(v.n_evaluable_rules, 0)
        self.assertEqual(v.confidence_fraction, 0.0)

    def test_an_alert_never_carries_a_note_denying_its_own_evidence(self):
        # min_group_coverage raised high enough to gate a group that fires.
        cfg = _cfg_with(**{"coverage.min_group_coverage": 0.9})
        frame = H.mock_frame(1, **QUIET, ens_query_rate=9.0)
        frame.loc[0, "resolution_entropy"] = np.nan      # resolution -> 0.75
        v = E.DetectionEngine(cfg=cfg).detect_frame(frame).verdicts[0]
        self.assertEqual(v.category, C.CAT_SUSPICIOUS_RESOLUTION)
        self.assertNotIn("resolution", v.coverage_note.lower())

    def test_a_firing_rule_still_wins_over_a_gated_sibling_group(self):
        v = E.detect(H.op_frame(1, **QUIET, updownlink_ratio=0.9)).verdicts[0]
        self.assertEqual(v.category, C.CAT_SUSPICIOUS_RELAY)
        # The alert is raised AND the resolution blind spot is disclosed on it.
        self.assertTrue(v.raises_alert)
        self.assertIn("resolution", v.coverage.gated_groups)
        self.assertIn("no resolution judgement can be made", v.coverage_note)


class ConfidenceHonesty(unittest.TestCase):
    def test_denominator_is_evaluable_rules_not_seven(self):
        # A conn.log can evaluate three of the seven rules. All three firing is
        # everything the telemetry could say, so confidence is high — while the
        # raw count of 3/7 would have reported "low" for a total agreement.
        v = E.detect(H.op_frame(
            1, beacon_interval=60.0, updownlink_ratio=0.9,
            login_burst_count=5.0)).verdicts[0]
        self.assertEqual(v.n_evaluable_rules, 3)
        self.assertEqual(v.votes, 3)
        self.assertEqual(v.confidence_fraction, 1.0)
        self.assertEqual(v.confidence, "high")
        self.assertEqual(v.severity, "HIGH")

    def test_one_of_seven_is_low_confidence(self):
        v = E.detect(H.mock_frame(1, **QUIET, ens_query_rate=9.0)).verdicts[0]
        self.assertEqual(v.n_evaluable_rules, 7)
        self.assertAlmostEqual(v.confidence_fraction, 1 / 7)
        self.assertEqual(v.confidence, "low")


class Abstention(unittest.TestCase):
    def test_frame_without_feature_columns_abstains(self):
        frame = pd.DataFrame({
            K.OBSERVATION_ID: ["obs-1", "obs-2"],
            K.DEVICE_ID: ["dev-a", "dev-b"],
            K.WINDOW_START: ["2026-01-06T00:00:00", "2026-01-06T00:05:00"],
        })
        result = E.detect(frame)
        self.assertEqual([v.category for v in result.verdicts],
                         [C.CAT_ABSTAIN] * 2)
        self.assertEqual(result.verdicts[0].reason, E.REASON_SCHEMA)
        self.assertFalse(result.verdicts[0].raises_alert)
        # Identity is still carried through, so an operator can see what was
        # skipped rather than losing the rows silently.
        self.assertEqual(result.verdicts[1].device_id, "dev-b")

    def test_frame_without_identity_columns_abstains(self):
        frame = H.mock_frame(2, **QUIET).drop(columns=[K.OBSERVATION_ID])
        result = E.detect(frame)
        self.assertEqual(result.verdicts[0].category, C.CAT_ABSTAIN)
        self.assertIn("identity column", result.notice)

    def test_partial_feature_columns_are_not_a_schema_failure(self):
        # Missing SOME features is "not measurable", which coverage models
        # correctly; only an unreadable frame abstains.
        frame = H.mock_frame(1, **QUIET).drop(columns=["ens_query_rate"])
        v = E.detect(frame).verdicts[0]
        self.assertNotEqual(v.category, C.CAT_ABSTAIN)
        self.assertEqual(v.n_evaluable_rules, len(RULES) - 1)

    def test_abstention_can_be_configured_off(self):
        data = load_config().as_dict()
        data["service"]["abstain_on_schema_failure"] = False
        frame = pd.DataFrame({K.OBSERVATION_ID: ["o"], K.DEVICE_ID: ["d"],
                              K.WINDOW_START: ["2026-01-06T00:00:00"]})
        engine = E.DetectionEngine(cfg=ConfigNode(data))
        with self.assertRaises(E.DetectionError):
            engine.detect_frame(frame)


class AgreementWithTheResearchBaseline(unittest.TestCase):
    """The product and the published baseline evaluate identical rules."""

    def test_engine_votes_match_heuristic_detector_votes(self):
        frame = H.mock_frame(
            8, ens_query_rate=[0.0, 9.0, 9.0, 0.0, 1.0, 9.0, 0.0, 4.0],
            upnp_addportmapping=[0.0, 0.0, 1.0, 1.0, 0.0, 1.0, 0.0, 1.0],
            login_burst_count=[0.0, 0.0, 0.0, 5.0, 5.0, 5.0, 1.0, 3.0],
            beacon_interval=[5.0, 5.0, 5.0, 5.0, 60.0, 60.0, 5.0, 60.0])
        result = E.detect(frame)
        expected = HeuristicDetector().votes(frame[K.FEATURE_COLS])
        self.assertEqual([v.votes for v in result.verdicts], list(expected))

    def test_thresholds_are_never_redeclared_in_the_engine(self):
        # Structural, not stylistic: a threshold literal anywhere in the engine
        # is a second place the baseline could drift from, so there are none.
        source = Path(E.__file__).read_text(encoding="utf-8")
        for feat, _op, thr, _reason in RULES:
            self.assertNotIn(f"{thr}", source,
                             f"the engine restates {feat}'s threshold; it must "
                             "read it from models.heuristic.RULES")

    def test_ruleset_digest_is_stable_and_short(self):
        self.assertEqual(E.ruleset_digest(), E.ruleset_digest())
        self.assertEqual(len(E.ruleset_digest()), 12)


class ResultReporting(unittest.TestCase):
    def test_summary_counts_the_unjudgeable_as_well_as_the_alerts(self):
        result = E.detect(H.op_frame(4, **QUIET))
        summary = result.summary()
        self.assertEqual(summary["n_windows"], 4)
        self.assertEqual(summary["n_alerting"], 0)
        self.assertEqual(summary["by_category"][C.CAT_INSUFFICIENT_TELEMETRY], 4)
        self.assertEqual(summary["by_category"][C.CAT_BENIGN_OR_NO_ALERT], 0)
        # "0 alerts" alone would be misleading; the blind spot is counted too.
        self.assertEqual(summary["windows_with_group_ungradeable"],
                         {"resolution": 4})

    def test_result_carries_the_marker_and_the_operational_note(self):
        result = E.detect(H.op_frame(1, **QUIET))
        self.assertEqual(result.marker,
                         "Rule-based detection; not ML-validated.")
        self.assertIn("suspicious indicator pattern requiring analyst review",
                      result.provenance_note)
        self.assertIn("UNLABELLED", result.provenance_note)

    def test_alerting_selects_only_the_analyst_queue(self):
        frame = H.mock_frame(3, **QUIET,
                             ens_query_rate=[0.0, 9.0, 0.0])
        result = E.detect(frame)
        self.assertEqual(len(result), 3)
        self.assertEqual(len(result.alerting), 1)
        self.assertEqual(result.alerting[0].category,
                         C.CAT_SUSPICIOUS_RESOLUTION)

    def test_run_defaults_to_rule_mode_with_no_refusal_notice(self):
        result = E.detect(H.mock_frame(1, **QUIET))
        self.assertEqual(result.mode, G.MODE_RULE)
        self.assertTrue(result.gate.allowed)
        self.assertEqual(result.notice, "")
        self.assertEqual(result.detection_version, "ruleset-1")

    def test_requesting_model_mode_falls_back_and_explains_why(self):
        result = E.detect(H.mock_frame(1, **QUIET), mode=G.MODE_MODEL)
        self.assertEqual(result.mode, G.MODE_RULE)
        self.assertTrue(result.gate.refused)
        self.assertIn("ML-based detection is not active", result.notice)
        self.assertIn("Rule-based detection; not ML-validated.", result.notice)


class OperationalZeekEndToEnd(unittest.TestCase):
    """The shape of a real product run over authorised, UNLABELLED telemetry."""

    def test_operational_windows_never_claim_a_research_class(self):
        obs = H.op_frame(3, **QUIET, updownlink_ratio=0.9)
        self.assertTrue((obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())
        result = E.detect(obs)
        for v in result.verdicts:
            self.assertIn(v.category, C.CATEGORIES)
            self.assertNotIn(v.category, K.RESEARCH_CLASSES)
            self.assertEqual(v.provenance, E.PROV_RULE_ENGINE)
            self.assertEqual(v.source_dataset, K.SOURCE_OP_ZEEK)

    def test_every_operational_source_produces_usable_verdicts(self):
        for source in K.OPERATIONAL_SOURCES:
            with self.subTest(source=source):
                result = E.detect(H.op_frame(2, source_dataset=source, **QUIET))
                self.assertEqual(len(result), 2)
                for v in result.verdicts:
                    self.assertIn(v.category, C.CATEGORIES)
                    self.assertIn(v.severity, SEVERITIES)
                    self.assertIn("resolution", v.coverage.gated_groups)


if __name__ == "__main__":
    unittest.main()
