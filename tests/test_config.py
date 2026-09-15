"""
tests/test_config.py — the config bridge and the filesystem layout.

config.py is load-bearing: every module reads its numbers through it, and the
two provenance disclaimers it holds are attached verbatim to every artefact. So
this pins:

  * attribute access resolves real keys and fails LOUDLY on a typo (a mistyped
    threshold that silently returned None would corrupt a result quietly);
  * the cache returns the same object, and the reproducibility copy (as_dict) is
    safe to mutate without disturbing the live config;
  * the layout keeps the two tracks in two separate canonical files — the first
    line of defence against pooling;
  * the Track A / Track B disclaimers say the specific things a reader must be
    told, including that neither number is evidence of real-world thesis
    detection.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from src import config as C


def _write(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class LoadAndCache(unittest.TestCase):
    def test_default_config_loads_and_reads(self):
        cfg = C.load_config()
        self.assertIsInstance(cfg, C.ConfigNode)
        # a known scalar and a known nested node from configs/default.yaml
        self.assertEqual(cfg.evaluation.target_fpr, 0.01)
        self.assertIsInstance(cfg.evaluation, C.ConfigNode)
        self.assertIsInstance(cfg.seeds.split, list)

    def test_same_path_is_cached_use_cache_false_rebuilds(self):
        p = _write("a:\n  b: 1\n")
        try:
            first = C.load_config(p)
            self.assertIs(C.load_config(p), first)          # cached identity
            fresh = C.load_config(p, use_cache=False)
            self.assertIsNot(fresh, first)                  # freshly built
            self.assertEqual(fresh.a.b, 1)
        finally:
            os.unlink(p)

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            C.load_config("does-not-exist-12345.yaml", use_cache=False)

    def test_non_mapping_yaml_is_rejected(self):
        p = _write("- 1\n- 2\n")   # parses to a list, not a mapping
        try:
            with self.assertRaises(C.ConfigError):
                C.load_config(p, use_cache=False)
        finally:
            os.unlink(p)


class AttributeAccess(unittest.TestCase):
    def setUp(self):
        self.cfg = C.ConfigNode({"evaluation": {"target_fpr": 0.01},
                                 "seeds": {"split": [42, 7]}, "flag": True})

    def test_nested_dict_becomes_node_scalar_passes_through(self):
        self.assertIsInstance(self.cfg.evaluation, C.ConfigNode)
        self.assertEqual(self.cfg.evaluation.target_fpr, 0.01)
        self.assertIs(self.cfg.flag, True)

    def test_typo_raises_with_available_keys_and_path(self):
        with self.assertRaises(C.ConfigError) as cm:
            _ = self.cfg.evaluation.target_fpr_typo
        msg = str(cm.exception)
        self.assertIn("target_fpr_typo", msg)
        self.assertIn("target_fpr", msg)        # available keys are listed
        self.assertIn("evaluation", msg)        # the path is named

    def test_mapping_protocol(self):
        self.assertEqual(self.cfg["evaluation"]["target_fpr"], 0.01)
        self.assertIn("seeds", self.cfg)
        self.assertNotIn("nope", self.cfg)
        self.assertEqual(self.cfg.get("nope", "d"), "d")
        self.assertEqual(set(self.cfg.keys()), {"evaluation", "seeds", "flag"})

    def test_as_dict_is_a_mutation_safe_deep_copy(self):
        d = self.cfg.as_dict()
        d["evaluation"]["target_fpr"] = 0.99
        # the live node is unchanged, and a second copy is unpolluted
        self.assertEqual(self.cfg.evaluation.target_fpr, 0.01)
        self.assertEqual(self.cfg.as_dict()["evaluation"]["target_fpr"], 0.01)


class Layout(unittest.TestCase):
    def test_two_tracks_two_files_under_processed(self):
        self.assertNotEqual(C.TRACK_B_MOCK_CSV, C.TRACK_A_IOT23_CSV)
        self.assertEqual(C.TRACK_B_MOCK_CSV.parent, C.PROCESSED_DIR)
        self.assertEqual(C.TRACK_A_IOT23_CSV.parent, C.PROCESSED_DIR)

    def test_raw_and_processed_live_under_data(self):
        self.assertEqual(C.RAW_DIR.parent, C.DATA_DIR)
        self.assertEqual(C.PROCESSED_DIR.parent, C.DATA_DIR)

    def test_ensure_dirs_is_idempotent_and_creates_outputs(self):
        C.ensure_dirs()
        C.ensure_dirs()   # second call must not raise
        for d in C._OUTPUT_DIRS:
            self.assertTrue(d.exists())


class Provenance(unittest.TestCase):
    def test_track_b_note_marks_synthetic_and_disclaims_real_world(self):
        note = C.provenance_note()
        self.assertIn("SYNTHETIC (Track B)", note)
        self.assertIn("NOT", note)
        self.assertIn("real-world detection performance", note)

    def test_track_a_note_marks_real_capture_and_disclaims_thesis(self):
        note = C.real_data_note()
        self.assertIn("REAL CAPTURE (Track A)", note)
        self.assertIn("IoT-23", note)
        self.assertIn("false alarms", note)
        self.assertIn("NOT this project's thesis", note)


class ProductConfig(unittest.TestCase):
    """The operational-product config blocks. These pin the safety defaults a
    later edit could weaken silently: the two verbatim honesty strings, the
    local-only bind, and the two capabilities that stay OFF until explicitly
    authorised (ML scoring, PostgreSQL). If any of these regress, the product is
    no longer the defensive, review-only tool it is documented to be."""

    def setUp(self):
        self.cfg = C.load_config()

    def test_review_banner_is_present_verbatim(self):
        # This exact wording is required on every dashboard page and export. A
        # tool that reads metadata cannot confirm compromise and must not imply
        # it, so the string is pinned here, not just written in a template.
        self.assertEqual(
            self.cfg.product.review_banner,
            "Alerts indicate suspicious behavioural patterns and require "
            "analyst review. They are not confirmation of compromise.",
        )

    def test_rule_marker_is_present_verbatim(self):
        self.assertEqual(
            self.cfg.detection.rule_marker,
            "Rule-based detection; not ML-validated.",
        )

    def test_server_binds_local_only_by_default(self):
        # Loopback only. Exposing the product beyond localhost is an explicit,
        # approval-gated act — never the default.
        self.assertEqual(self.cfg.api.host, "127.0.0.1")

    def test_ml_mode_is_gated_off(self):
        # No model is trained or scored until an authorised labelled dataset and
        # a registered, validated model version exist.
        self.assertFalse(self.cfg.detection.model.enabled)
        self.assertEqual(self.cfg.detection.mode, "rule")

    def test_postgres_is_gated_off_and_sqlite_is_the_running_backend(self):
        self.assertEqual(self.cfg.storage.backend, "sqlite")
        self.assertFalse(self.cfg.storage.postgres.enabled)

    def test_no_secret_value_is_stored_in_the_config_file(self):
        # The signing secret and any DB URL are read from the environment. The
        # config may name the env var but must never hold the value itself.
        self.assertEqual(
            self.cfg.auth.session_secret_env, "PRODUCT_SESSION_SECRET")
        self.assertNotIn("session_secret", self.cfg.auth)
        self.assertEqual(self.cfg.storage.postgres.dsn_env, "PRODUCT_DATABASE_URL")
        self.assertNotIn("dsn", self.cfg.storage.postgres)

    def test_upload_controls_are_bounded(self):
        self.assertGreater(self.cfg.api.max_upload_bytes, 0)
        exts = self.cfg.api.allowed_extensions
        self.assertIn(".log", exts)          # Zeek conn.log
        self.assertIn(".csv", exts)          # flow / netflow / firewall exports
        for e in exts:
            self.assertTrue(e.startswith("."), e)

    def test_severity_table_escalates_monotonically(self):
        # Higher-severity rules must demand at least as much evidence as lower
        # ones, or the "highest matching rule wins" engine would be incoherent.
        rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
        rules = [self.cfg.detection.severity.rules[i]
                 for i in range(len(list(self.cfg.detection.severity.rules)))]
        ordered = sorted(rules, key=lambda r: rank[r["severity"]])
        for lo, hi in zip(ordered, ordered[1:]):
            self.assertLessEqual(lo["min_votes"], hi["min_votes"])
            self.assertLessEqual(lo["min_groups"], hi["min_groups"])


if __name__ == "__main__":
    unittest.main()
