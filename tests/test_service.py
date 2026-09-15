"""
tests/test_service.py — the offline detection service, and its containment.

The service is the only component a demo actually "runs" against fresh traffic,
so these tests pin two things at once:

  BEHAVIOUR — the decision set is exactly {MALICIOUS, BENIGN, ABSTAIN}, and each
  of the three abstention channels fires for its own reason and no other:
    * schema_invalid   — the batch is not a valid observation frame
    * missing_features — a row has a NaN in a feature the model needs
    * low_confidence   — the score sits within the abstain band of the threshold
  A missing feature is never imputed: a tree abstains on it, and the heuristic's
  NaN-tolerance is honoured only when the operator turns missing-feature
  abstention off.

  CONTAINMENT — the module opens no socket, binds no port and starts no server.
  This is a static guarantee of the project's ethics posture, so it is asserted
  as a test over the source text, not just documented.
"""
from __future__ import annotations

import os
import tempfile
import unittest
import warnings
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd

from src.schema import columns as K
from src.schema.validate import SchemaError, write_observations
from src.services import score as SVC
from tests.helpers import mock_frame
from tests.test_experiment import separable_track_b

_OUT_COLS = ["decision", "score", "confidence", "threshold", "reason",
             "explanation"]


def fake_cfg(**over):
    """A minimal cfg exposing just the ``service`` block score_frame reads."""
    base = dict(max_rows_per_request=100000, abstain_on_schema_failure=True,
                abstain_on_missing_features=True, abstain_below_confidence=0.15)
    base.update(over)
    return SimpleNamespace(service=SimpleNamespace(**base))


def rewrap(svc, **service_over):
    """Reuse a fitted detector under a different service config, no retrain."""
    return SVC.DetectionService(svc.detector, svc.feature_names, svc.threshold,
                                cfg=fake_cfg(**service_over))


def malicious_rows(n=4):
    """Rows on which every heuristic rule fires (and trees see the elevated
    base-group signal too)."""
    return mock_frame(n, research_class=K.CLS_COMBINED_MOCK, device_prefix="mal",
                      n_devices=max(2, n // 2), serverlist_pull=1.0,
                      upnp_addportmapping=1.0, beacon_interval=45.0,
                      updownlink_ratio=0.9, login_burst_count=6.0,
                      rc4_string_score=0.9, ens_query_rate=5.0, scan_rate=8.0)


def benign_rows(n=4):
    """Rows on which no heuristic rule fires (beacon below the 20s rule too)."""
    return mock_frame(n, research_class=K.CLS_BENIGN_MOCK, device_prefix="ben",
                      n_devices=max(2, n // 2), beacon_interval=10.0)


class _Fitted(unittest.TestCase):
    """Train one RF and one Heuristic service once for the whole module."""

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore")
        train = separable_track_b()
        cls.rf = SVC.DetectionService.from_training_frame(
            train, model_name="RandomForest", seed=42)
        cls.heur = SVC.DetectionService.from_training_frame(
            train, model_name="Heuristic", seed=42)


class DecisionShape(_Fitted):
    def test_one_decision_per_row_ids_preserved_columns_present(self):
        df = pd.concat([malicious_rows(6), benign_rows(6)], ignore_index=True)
        out = self.rf.score_frame(df)
        self.assertEqual(len(out), len(df))
        self.assertTrue(set(out["decision"]) <=
                        {SVC.DECISION_MALICIOUS, SVC.DECISION_BENIGN,
                         SVC.DECISION_ABSTAIN})
        for c in _OUT_COLS:
            self.assertIn(c, out.columns)
        # ids carried through unchanged, in order
        self.assertEqual(list(out[K.OBSERVATION_ID]),
                         list(df[K.OBSERVATION_ID]))
        # the fixed operating point is reported on every row
        self.assertTrue((out["threshold"] == self.rf.threshold).all())


class MissingFeatureAbstention(_Fitted):
    def test_nan_in_used_feature_abstains_with_reason(self):
        df = benign_rows(8).reset_index(drop=True)
        df.loc[[0, 1], "scan_rate"] = np.nan
        out = self.rf.score_frame(df)
        self.assertEqual(list(out.loc[[0, 1], "decision"]),
                         [SVC.DECISION_ABSTAIN, SVC.DECISION_ABSTAIN])
        self.assertEqual(set(out.loc[[0, 1], "reason"]), {SVC.REASON_MISSING})
        # a NaN row is never scored (never imputed)
        self.assertTrue(out.loc[[0, 1], "score"].isna().all())
        # untouched rows are not flagged missing
        self.assertNotIn(SVC.REASON_MISSING, set(out.loc[2:, "reason"]))


class SchemaAbstention(_Fitted):
    def test_absent_feature_column_abstains_whole_batch(self):
        df = benign_rows(5).drop(columns=["scan_rate"])
        out = self.rf.score_frame(df)
        self.assertTrue((out["decision"] == SVC.DECISION_ABSTAIN).all())
        self.assertTrue((out["reason"] == SVC.REASON_SCHEMA).all())
        self.assertIn("scan_rate", out["explanation"].iloc[0])

    def test_absent_feature_column_raises_when_abstain_off(self):
        svc = rewrap(self.rf, abstain_on_schema_failure=False)
        df = benign_rows(5).drop(columns=["scan_rate"])
        with self.assertRaises(SVC.ServiceError):
            svc.score_frame(df)


class LowConfidenceBand(_Fitted):
    def test_wide_band_abstains_every_scored_row(self):
        # A band wider than any possible |score - threshold| (scores in [0,1])
        # means no row can be confident enough to commit.
        svc = rewrap(self.rf, abstain_below_confidence=2.0)
        out = svc.score_frame(pd.concat([malicious_rows(6), benign_rows(6)],
                                        ignore_index=True))
        self.assertEqual(set(out["decision"]), {SVC.DECISION_ABSTAIN})
        self.assertEqual(set(out["reason"]), {SVC.REASON_LOW_CONF})

    def test_zero_band_never_abstains_on_confidence(self):
        svc = rewrap(self.rf, abstain_below_confidence=0.0)
        out = svc.score_frame(pd.concat([malicious_rows(6), benign_rows(6)],
                                        ignore_index=True))
        self.assertNotIn(SVC.REASON_LOW_CONF, set(out["reason"]))
        # with no missing features and no band, every row commits
        self.assertTrue(set(out["decision"]) <=
                        {SVC.DECISION_MALICIOUS, SVC.DECISION_BENIGN})


class MaxRowsGuard(_Fitted):
    def test_batch_over_cap_is_refused(self):
        svc = rewrap(self.rf, max_rows_per_request=5)
        with self.assertRaises(SVC.ServiceError):
            svc.score_frame(benign_rows(6))


class Explanations(_Fitted):
    def test_heuristic_names_fired_rules_on_malicious_only(self):
        svc = rewrap(self.heur, abstain_below_confidence=0.0)
        df = pd.concat([malicious_rows(4), benign_rows(4)], ignore_index=True)
        out = svc.score_frame(df)
        mal = out[out["decision"] == SVC.DECISION_MALICIOUS]
        ben = out[out["decision"] == SVC.DECISION_BENIGN]
        self.assertGreater(len(mal), 0)
        self.assertTrue((mal["explanation"].str.len() > 0).all())
        self.assertIn("UPnP AddPortMapping observed", mal["explanation"].iloc[0])
        # benign rows carry no fabricated rationale
        self.assertTrue((ben["explanation"] == "").all())


class NaNToleranceFlag(_Fitted):
    def test_heuristic_scores_nan_rows_when_missing_abstention_off(self):
        df = benign_rows(6).reset_index(drop=True)
        df.loc[[0, 1], "rc4_string_score"] = np.nan
        off = rewrap(self.heur, abstain_on_missing_features=False,
                     abstain_below_confidence=0.0)
        out = off.score_frame(df)
        # NaN-tolerant detector + flag off => the NaN rows are scored, not abstained
        self.assertNotIn(SVC.REASON_MISSING, set(out.loc[[0, 1], "reason"]))
        self.assertTrue(out.loc[[0, 1], "score"].notna().all())

    def test_flag_on_abstains_same_rows(self):
        df = benign_rows(6).reset_index(drop=True)
        df.loc[[0, 1], "rc4_string_score"] = np.nan
        on = rewrap(self.heur, abstain_on_missing_features=True)
        out = on.score_frame(df)
        self.assertEqual(set(out.loc[[0, 1], "reason"]), {SVC.REASON_MISSING})

    def test_tree_abstains_on_nan_even_with_flag_off(self):
        # A tree cannot consume NaN and imputing is forbidden, so the flag can
        # never make it score a missing feature.
        df = benign_rows(6).reset_index(drop=True)
        df.loc[[0, 1], "scan_rate"] = np.nan
        off = rewrap(self.rf, abstain_on_missing_features=False)
        out = off.score_frame(df)
        self.assertEqual(set(out.loc[[0, 1], "reason"]), {SVC.REASON_MISSING})


class CsvRoundTrip(_Fitted):
    def test_score_csv_writes_decisions_and_summary_adds_up(self):
        df = pd.concat([malicious_rows(6), benign_rows(6)], ignore_index=True)
        with tempfile.TemporaryDirectory() as d:
            in_csv = os.path.join(d, "obs.csv")
            out_csv = os.path.join(d, "decisions.csv")
            write_observations(df, in_csv)
            summary = self.rf.score_csv(in_csv, out_csv)
            self.assertTrue(os.path.exists(out_csv))
            back = pd.read_csv(out_csv)
        self.assertEqual(len(back), len(df))
        for c in _OUT_COLS:
            self.assertIn(c, back.columns)
        self.assertEqual(summary["n_rows"], len(df))
        self.assertEqual(
            summary["n_malicious"] + summary["n_benign"] + summary["n_abstain"],
            len(df))

    def test_score_csv_abstains_all_on_malformed_input(self):
        df = mock_frame(6, device_prefix="ben", n_devices=3)
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "good.csv")
            bad = os.path.join(d, "bad.csv")
            out_csv = os.path.join(d, "out.csv")
            write_observations(df, good)
            raw = pd.read_csv(good).drop(columns=["scan_rate"])  # break the schema
            raw.to_csv(bad, index=False)
            summary = self.rf.score_csv(bad, out_csv)
            back = pd.read_csv(out_csv)
        self.assertEqual(summary["n_abstain"], len(df))
        self.assertTrue((back["reason"] == SVC.REASON_SCHEMA).all())

    def test_score_csv_raises_on_malformed_input_when_abstain_off(self):
        df = mock_frame(6, device_prefix="ben", n_devices=3)
        svc = rewrap(self.rf, abstain_on_schema_failure=False)
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "good.csv")
            bad = os.path.join(d, "bad.csv")
            write_observations(df, good)
            pd.read_csv(good).drop(columns=["scan_rate"]).to_csv(bad, index=False)
            with self.assertRaises(SchemaError):
                svc.score_csv(bad, os.path.join(d, "out.csv"))


class Containment(unittest.TestCase):
    """The service must remain a batch function over files: no network surface."""

    FORBIDDEN = ("import socket", "socketserver", "http.server", "httpx",
                 "import flask", "fastapi", "import requests", "urllib",
                 "aiohttp", ".bind(", ".listen(", ".connect(", "uvicorn")

    def test_source_has_no_network_surface(self):
        src = Path(SVC.__file__).read_text(encoding="utf-8")
        for token in self.FORBIDDEN:
            self.assertNotIn(token, src,
                             f"containment breach: {token!r} in score.py")

    def test_docstring_states_the_guarantee(self):
        normalized = " ".join((SVC.__doc__ or "").split())
        self.assertIn("opens no socket", normalized)


if __name__ == "__main__":
    unittest.main()
