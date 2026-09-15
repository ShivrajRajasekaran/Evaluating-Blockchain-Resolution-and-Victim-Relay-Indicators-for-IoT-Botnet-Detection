"""
tests/test_reports.py — the reporting layer, and its provenance guarantees.

The reports layer is where a number stops being an in-memory dict and becomes a
file someone could paste into a paper. So these tests pin the properties that
keep that file honest:

  * every table opens with a ``#`` provenance banner carrying the RIGHT
    disclaimer — SYNTHETIC (Track B) for the mock experiments, REAL CAPTURE
    (Track A) for the cross-track false-alarm number — and still reloads to the
    exact frame;
  * the base row of the headline table has no delta (it is the reference), and
    every augmented row carries a well-ordered interval;
  * figures are real PNGs;
  * the generated feature catalogue is DERIVED from the schema — its availability
    counts equal ``availability_summary`` rather than any literal, so the doc
    cannot claim a feature is computable from IoT-23 after the schema says NaN.

Runs on a deliberately shrunk config (small forests, few bootstraps): the
science is checked in test_experiment; here we check rendering.
"""
from __future__ import annotations

import tempfile
import unittest
import warnings
from pathlib import Path

from src import config as C
from src.evaluate import cross_track as CT
from src.evaluate import experiment as E
from src.evaluate import explain as X
from src.reports import figures as FG
from src.reports import generate_docs as GD
from src.reports import tables as TB
from src.schema import columns as K
from tests.helpers import iot23_frame
from tests.test_experiment import separable_track_b


def fast_cfg():
    """Default config with small forests and few bootstraps, for speed."""
    d = C.load_config().as_dict()
    d["evaluation"]["n_bootstrap"] = 80
    d["models"]["random_forest"]["n_estimators"] = 40
    d["models"]["xgboost"]["n_estimators"] = 50
    return C.ConfigNode(d)


def _banner_lines(path: Path) -> list[str]:
    return [ln for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.startswith(TB.BANNER_PREFIX)]


class _Computed(unittest.TestCase):
    """Compute each result dict once for the whole module."""

    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore")
        cfg = fast_cfg()
        df = separable_track_b(n_benign_dev=30, n_mal_dev=15)
        cls.inc = E.run_incremental(df, cfg=cfg, seed=42)
        cls.mdl = E.run_model_comparison(df, cfg=cfg, seed=42)
        cls.perm = X.permutation_importance(df, cfg=cfg, seed=42)
        cls.ct = CT.cross_track_fpr(df, iot23_frame(120, n_devices=12),
                                    cfg=cfg, seed=42)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


class IncrementalTable(_Computed):
    def test_row_per_set_base_has_no_delta_augmented_intervals_ordered(self):
        p = TB.write_incremental_table(self.inc, path=self.tmp / "inc.csv")
        back = TB.read_table(p)
        self.assertEqual(len(back), len(self.inc["operating_points"]))
        base = back[back["is_base"]]
        self.assertEqual(len(base), 1)
        self.assertTrue(base["delta_recall_vs_base"].isna().all())
        aug = back[~back["is_base"]]
        self.assertTrue((aug["ci_low"] <= aug["ci_high"]).all())

    def test_banner_is_synthetic_and_carries_the_verdict(self):
        p = TB.write_incremental_table(self.inc, path=self.tmp / "inc.csv")
        banner = "\n".join(_banner_lines(p))
        self.assertTrue(banner.startswith(TB.BANNER_PREFIX))
        self.assertIn("SYNTHETIC (Track B)", banner)
        self.assertIn(self.inc["verdict"]["reading"][:30], banner)


class ModelComparisonTable(_Computed):
    def test_row_per_detector_reloads_with_metrics(self):
        p = TB.write_model_comparison_table(self.mdl, path=self.tmp / "m.csv")
        back = TB.read_table(p)
        self.assertEqual(set(back["detector"]), set(self.mdl["detectors"]))
        for col in ("test_recall", "test_precision", "test_f1", "test_fpr"):
            self.assertIn(col, back.columns)
        self.assertIn("SYNTHETIC (Track B)", "\n".join(_banner_lines(p)))


class PermutationTable(_Computed):
    def test_one_row_per_feature_sorted_desc(self):
        p = TB.write_permutation_table(self.perm, path=self.tmp / "p.csv")
        back = TB.read_table(p)
        self.assertEqual(set(back["feature"]), set(K.FEATURE_COLS))
        means = back["perm_importance_mean"].tolist()
        self.assertEqual(means, sorted(means, reverse=True))
        # novel flag agrees with the schema
        for _, r in back.iterrows():
            self.assertEqual(bool(r["is_novel_group"]),
                             r["group"] in K.NOVEL_GROUPS)


class CrossTrackTable(_Computed):
    def test_single_row_uses_real_capture_disclaimer(self):
        p = TB.write_cross_track_table(self.ct, path=self.tmp / "ct.csv")
        back = TB.read_table(p)
        self.assertEqual(len(back), 1)
        banner = "\n".join(_banner_lines(p))
        # The number is about REAL benign traffic, so the Track A note applies.
        self.assertIn("REAL CAPTURE (Track A)", banner)
        self.assertNotIn("SYNTHETIC (Track B)", banner)


class Figures(_Computed):
    def test_all_three_are_real_pngs(self):
        outs = [
            FG.fig_incremental(self.inc, path=self.tmp / "a.png"),
            FG.fig_permutation(self.perm, path=self.tmp / "b.png"),
            FG.fig_cross_track(self.ct, path=self.tmp / "c.png"),
        ]
        for o in outs:
            self.assertTrue(o.exists())
            with open(o, "rb") as fh:
                self.assertEqual(fh.read(4), b"\x89PNG")


class GeneratedCatalogue(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "feature-catalogue.md"
        self.text = GD.write_feature_catalogue(path=self.path).read_text(
            encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_generated_banner_and_all_features_present(self):
        self.assertIn("GENERATED FILE", self.text)
        for feat in K.FEATURE_COLS:
            self.assertIn(feat, self.text)

    def test_availability_counts_are_derived_not_hardcoded(self):
        # The count of unavailable IoT-23 features stated in the doc must equal
        # what the schema says — a test would fail if prose and code diverged.
        n_unavail = len(K.unavailable_features(K.SOURCE_IOT23))
        self.assertIn(f"{n_unavail} of 16 features are unavailable", self.text)
        # a specific unavailable feature is labelled unavailable, never computable
        self.assertRegex(self.text, r"`ens_query_rate`.*unavailable")

    def test_novel_groups_are_marked_on_trial(self):
        self.assertIn("NOVEL", self.text)
        # resolution + relay are the novel groups
        for g in K.NOVEL_GROUPS:
            self.assertIn(g, self.text)


if __name__ == "__main__":
    unittest.main()
