"""
reports/tables.py — result dicts to provenance-headed CSVs in results/tables/.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

Every table written here begins with a commented provenance banner (lines
starting ``#``) carrying the track's disclaimer verbatim. That banner is not
decoration. A CSV of recall numbers with no provenance attached is *precisely*
the artefact that gets pasted into a paper and read as a real-world performance
claim. The banner travels with the file, so the reader is told — in the file
itself — that a Track-B number is synthetic and a cross-track FPR is a
distribution-shift caveat, not a validation of the thesis.

Read any table back with :func:`read_table`, which skips the banner. The banner
uses ``#`` so ``pandas.read_csv(path, comment="#")`` recovers the frame exactly.

Nothing here recomputes a result. It renders the dicts produced by
``src.evaluate.experiment`` / ``.explain`` / ``.cross_track`` — so a number in a
table can only be a number the evaluation code actually returned.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.config import (TABLE_DIR, ensure_dirs, provenance_note, real_data_note)
from src.schema import columns as K

# Marker so a human (or a test) can tell a generated banner from stray data.
BANNER_PREFIX = "# "


def _write(frame: pd.DataFrame, path: Path, note_lines: list[str]) -> Path:
    """Write ``frame`` to ``path`` under a ``#``-commented provenance banner."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    banner = "".join(f"{BANNER_PREFIX}{line}\n" for line in note_lines)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(banner)
        frame.to_csv(fh, index=False)
    return path


def read_table(path) -> pd.DataFrame:
    """Read a table written here, skipping the provenance banner."""
    return pd.read_csv(path, comment="#")


def _round(x, n=6):
    return None if x is None else round(float(x), n)


# ---------------------------------------------------------------------------
# The headline: incremental value of the novel groups
# ---------------------------------------------------------------------------
def write_incremental_table(result: dict, *, path=None) -> Path:
    """One row per feature set: its operating point and its recall gain vs base.

    The base set's delta cells are blank (it is the reference). Each augmented
    set carries the paired, device-level bootstrap of the recall difference and
    whether that interval excludes zero — the actual headline finding.
    """
    base = result["base_set"]
    comps = result["comparisons"]
    rows = []
    for name, op in result["operating_points"].items():
        t = op["test"]
        row = {
            "feature_set": name,
            "is_base": name == base,
            "n_features": op["n_features"],
            "threshold": _round(op["threshold"]),
            "test_recall": _round(t["recall"]),
            "test_precision": _round(t["precision"]),
            "test_f1": _round(t["f1"]),
            "test_fpr": _round(t["fpr"]),
            "fpr_drift_vs_budget": _round(op["fpr_drift"]),
        }
        if name in comps:
            d = comps[name]["delta"][result["headline_metric"]]
            row.update({
                "added_groups": "+".join(comps[name]["added_groups"]),
                "delta_recall_vs_base": _round(d["point"]),
                "ci_low": _round(d["ci_low"]),
                "ci_high": _round(d["ci_high"]),
                "ci_excludes_zero": not d["includes_zero"],
                "distinguishable_gain": (not d["includes_zero"]) and d["ci_low"] > 0,
            })
        else:  # the base row
            row.update({"added_groups": "", "delta_recall_vs_base": None,
                        "ci_low": None, "ci_high": None,
                        "ci_excludes_zero": None, "distinguishable_gain": None})
        rows.append(row)

    note = [
        f"TABLE: incremental value of novel groups — headline metric "
        f"{result['headline_metric']} at {result['fpr_budget']:.0%} FPR budget "
        f"(model={result['model']}, seed={result['seed']}).",
        f"VERDICT: {result['verdict']['reading']}",
        provenance_note(),
    ]
    out = Path(path) if path else TABLE_DIR / "incremental_value.csv"
    return _write(pd.DataFrame(rows), out, note)


# ---------------------------------------------------------------------------
# Threshold-matched detector comparison
# ---------------------------------------------------------------------------
def write_model_comparison_table(result: dict, *, path=None) -> Path:
    """One row per detector, all pinned to the same FPR budget on validation."""
    rows = []
    for name, r in result["detectors"].items():
        t = r["test"]
        rows.append({
            "detector": name,
            "threshold": _round(r["threshold"]),
            "val_fpr_achieved": _round(r["val_fpr_achieved"]),
            "test_recall": _round(t["recall"]),
            "test_precision": _round(t["precision"]),
            "test_f1": _round(t["f1"]),
            "test_fpr": _round(t["fpr"]),
            "test_roc_auc": _round(t["roc_auc"]),
            "fpr_drift_vs_budget": _round(r["fpr_drift"]),
        })
    note = [
        f"TABLE: detectors on {'+'.join(result['feature_groups'])} "
        f"({result['n_features']} features), each calibrated to "
        f"{result['fpr_budget']:.0%} FPR on validation, scored once on the locked "
        f"test set (seed={result['seed']}).",
        provenance_note(),
    ]
    out = Path(path) if path else TABLE_DIR / "model_comparison.csv"
    return _write(pd.DataFrame(rows), out, note)


# ---------------------------------------------------------------------------
# Permutation importance (corroborating the headline from inside the model)
# ---------------------------------------------------------------------------
def write_permutation_table(result: dict, *, path=None) -> Path:
    """Per-feature permutation importance, most-important first.

    Gain importance is included as a separate column ONLY when the detector
    exposes it, and its column name says 'contrast_only' so it cannot be mistaken
    for the reported number.
    """
    gain = (result.get("gain_importance") or {}).get("by_feature", {})
    rows = []
    for feat, r in result["per_feature"].items():
        rows.append({
            "feature": feat,
            "group": r["group"],
            "is_novel_group": r["group"] in K.NOVEL_GROUPS,
            "perm_importance_mean": _round(r["importance_mean"]),
            "perm_importance_std": _round(r["importance_std"]),
            "gain_importance_contrast_only": _round(gain.get(feat)) if gain else None,
        })
    frame = (pd.DataFrame(rows)
             .sort_values("perm_importance_mean", ascending=False,
                          kind="stable", ignore_index=True))
    note = [
        f"TABLE: permutation importance ({result['scoring']}, "
        f"{result['repeats']} repeats) on the locked test set; baseline "
        f"{result['scoring']}={result['baseline_score']} "
        f"(model={result['model']}, seed={result['seed']}).",
        f"NOVEL groups total {result['novel_group_total']:+.4f} vs BASE "
        f"{result['base_group_total']:+.4f}. Gain importance is contrast only "
        f"(biased, computed on training data) — never a finding.",
        provenance_note(),
    ]
    out = Path(path) if path else TABLE_DIR / "permutation_importance.csv"
    return _write(frame, out, note)


# ---------------------------------------------------------------------------
# Cross-track FPR (the one sanctioned crossing) — REAL benign false alarms
# ---------------------------------------------------------------------------
def write_cross_track_table(report: dict, *, path=None) -> Path:
    """A single-row summary of the Track-B-detector -> IoT-23-benign FPR check.

    Uses the REAL-capture disclaimer, because the number describes false alarms
    on real benign traffic — while stating plainly that the detector itself was
    trained on synthetic Track B.
    """
    row = {
        "crossing": report["crossing"],
        "model": report["model"],
        "seed": report["seed"],
        "n_features_used": report["n_features"],
        "n_real_total": report["n_real_total"],
        "n_scored": report["n_scored"],
        "n_abstained": report["n_abstained"],
        "coverage": _round(report["coverage"]),
        "threshold": _round(report["threshold"]),
        "mock_val_fpr_calibrated": _round(report["mock_val_fpr_calibrated"]),
        "fpr_real_benign": _round(report["fpr_real_benign"]),
        "n_false_positive": report["n_false_positive"],
        "fpr_budget": _round(report["fpr_budget"]),
    }
    note = [
        "TABLE: cross-track false-alarm rate. A detector trained + calibrated "
        "entirely on SYNTHETIC Track B, scored on REAL IoT-23 benign windows.",
        f"Excluded (unavailable on IoT-23): {report['excluded_unavailable']}. "
        f"Excluded proxies: {report['excluded_proxies']}.",
        report["reading"],
        real_data_note(),
    ]
    out = Path(path) if path else TABLE_DIR / "cross_track_fpr.csv"
    return _write(pd.DataFrame([row]), out, note)


# ---------------------------------------------------------------------------
# Multi-seed robustness of the headline
# ---------------------------------------------------------------------------
def write_multiseed_table(result: dict, *, path=None) -> Path:
    """Per augmented set: spread of the recall delta across seeds and how many
    seeds found a distinguishable gain. Turns 'the null held on seed 42' into
    'the null held on all N seeds'."""
    rows = []
    for name, a in result["per_set"].items():
        rows.append({
            "feature_set": name,
            "mean_delta_recall": _round(a["mean_delta"]),
            "min_delta_recall": _round(a["min_delta"]),
            "max_delta_recall": _round(a["max_delta"]),
            "seeds_distinguishable": a["seeds_distinguishable"],
            "n_seeds": a["n_seeds"],
        })
    note = [
        f"TABLE: multi-seed robustness of the headline over seeds "
        f"{result['seeds']} (metric={result['headline_metric']}, "
        f"{result['fpr_budget']:.0%} FPR budget, model={result['model']}).",
        f"VERDICT: {result['verdict']['reading']}",
        provenance_note(),
    ]
    out = Path(path) if path else TABLE_DIR / "multiseed_incremental.csv"
    return _write(pd.DataFrame(rows), out, note)


if __name__ == "__main__":   # pragma: no cover - convenience only
    ensure_dirs()
    print(f"tables are written under {TABLE_DIR}")
