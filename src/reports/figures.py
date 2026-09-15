"""
reports/figures.py — result dicts to PNGs in results/figures/.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

Uses the non-interactive Agg backend, so it runs headless (CI, a server, a
mentor's laptop with no display) and never pops a window. Every figure carries
its provenance disclaimer as a footer caption for the same reason the tables do:
a chart of Track-B recall lifted into a slide with no caption reads as a
real-world result. The caption makes that misreading impossible without deleting
it on purpose.

Like tables.py, nothing here computes a result — it draws the dicts the
evaluation code returned.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib
matplotlib.use("Agg")            # headless: set before pyplot is imported
import matplotlib.pyplot as plt  # noqa: E402

from src.config import FIGURE_DIR, provenance_note, real_data_note  # noqa: E402
from src.schema import columns as K  # noqa: E402

_BASE_COLOR = "#4C72B0"    # base groups (infection + payload)
_NOVEL_COLOR = "#DD8452"   # novel groups (resolution + relay) — the ones on trial


def _finish(fig, path: Path, caption: str) -> Path:
    """Add the provenance caption, tighten, and save."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.text(0.5, 0.008, caption, ha="center", va="bottom", fontsize=6.5,
             color="#444444", wrap=True)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def fig_incremental(result: dict, *, path=None) -> Path:
    """Two panels: recall per feature set, and recall gain vs base with CIs.

    The right panel is the headline: each augmented set's paired recall
    difference from the base with its 95% device-bootstrap interval and a zero
    line. An interval straddling zero is 'no distinguishable value', drawn so.
    """
    ops = result["operating_points"]
    comps = result["comparisons"]
    names = list(ops.keys())
    recalls = [ops[n]["test"]["recall"] for n in names]
    short = [n.replace("base ", "").replace("(infection+payload)", "base")
             for n in names]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.6))

    colors = [_BASE_COLOR if n == result["base_set"] else _NOVEL_COLOR
              for n in names]
    ax1.bar(range(len(names)), recalls, color=colors)
    ax1.set_xticks(range(len(names)))
    ax1.set_xticklabels(short, rotation=20, ha="right", fontsize=8)
    ax1.set_ylabel(f"test recall @ {result['fpr_budget']:.0%} FPR")
    ax1.set_ylim(0, 1)
    ax1.set_title("Detection rate by feature set")
    for i, v in enumerate(recalls):
        ax1.text(i, v + 0.02, f"{v:.2f}", ha="center", fontsize=8)

    aug = [n for n in names if n in comps]
    pts, los, his = [], [], []
    for n in aug:
        d = comps[n]["delta"][result["headline_metric"]]
        pts.append(d["point"]); los.append(d["point"] - d["ci_low"])
        his.append(d["ci_high"] - d["point"])
    y = range(len(aug))
    ax2.errorbar(pts, y, xerr=[los, his], fmt="o", color=_NOVEL_COLOR,
                 capsize=4, lw=1.5)
    ax2.axvline(0, color="#888888", ls="--", lw=1)
    ax2.set_yticks(list(y))
    ax2.set_yticklabels([n.replace("base + ", "+ ") for n in aug], fontsize=8)
    ax2.set_xlabel("Δ recall vs base (95% device bootstrap)")
    ax2.set_title("Does the novel group add recall?")

    fig.suptitle("Incremental value of resolution/relay groups — "
                 "Track B (SYNTHETIC)", fontsize=12)
    caption = ("SYNTHETIC (Track B) mock data. A zero-crossing interval means no "
               "distinguishable gain. NOT a real-world detection result.")
    out = Path(path) if path else FIGURE_DIR / "incremental_value.png"
    return _finish(fig, out, caption)


def fig_permutation(result: dict, *, path=None) -> Path:
    """Horizontal bars of per-feature permutation importance, novel vs base."""
    items = sorted(result["per_feature"].items(),
                   key=lambda kv: kv[1]["importance_mean"])
    feats = [k for k, _ in items]
    means = [v["importance_mean"] for _, v in items]
    stds = [v["importance_std"] for _, v in items]
    colors = [_NOVEL_COLOR if v["group"] in K.NOVEL_GROUPS else _BASE_COLOR
              for _, v in items]

    fig, ax = plt.subplots(figsize=(8, 5.2))
    ax.barh(range(len(feats)), means, xerr=stds, color=colors, capsize=2.5,
            error_kw={"lw": 0.8, "ecolor": "#666666"})
    ax.axvline(0, color="#888888", lw=1)
    ax.set_yticks(range(len(feats)))
    ax.set_yticklabels(feats, fontsize=8)
    ax.set_xlabel(f"drop in test {result['scoring']} when column is permuted")
    ax.set_title(f"Permutation importance — Track B (SYNTHETIC)\n"
                 f"novel groups total {result['novel_group_total']:+.4f}, "
                 f"base {result['base_group_total']:+.4f}")
    handles = [plt.Rectangle((0, 0), 1, 1, color=_NOVEL_COLOR),
               plt.Rectangle((0, 0), 1, 1, color=_BASE_COLOR)]
    ax.legend(handles, ["resolution / relay (novel)", "infection / payload (base)"],
              loc="lower right", fontsize=8)
    caption = ("SYNTHETIC (Track B). Importance measured on the locked test set "
               "at the deployed threshold. Gain importance is excluded here — it "
               "is biased and shown only in the table, never as a finding.")
    out = Path(path) if path else FIGURE_DIR / "permutation_importance.png"
    return _finish(fig, out, caption)


def fig_cross_track(report: dict, *, path=None) -> Path:
    """Three bars: FPR budget, achieved mock-val FPR, real-benign FPR."""
    labels = ["FPR budget", "mock val\n(calibrated)", "real benign\n(IoT-23)"]
    vals = [report["fpr_budget"], report["mock_val_fpr_calibrated"],
            report["fpr_real_benign"] or 0.0]
    colors = ["#888888", _BASE_COLOR, _NOVEL_COLOR]

    fig, ax = plt.subplots(figsize=(6.4, 4.4))
    ax.bar(range(3), vals, color=colors)
    ax.axhline(report["fpr_budget"], color="#888888", ls="--", lw=1)
    ax.set_xticks(range(3))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("false-positive rate")
    ax.set_title("Cross-track false alarms on REAL benign traffic")
    for i, v in enumerate(vals):
        ax.text(i, v + max(vals) * 0.02, f"{v:.3f}", ha="center", fontsize=9)
    ax.text(0.5, 0.94, f"coverage {report['coverage']:.0%} "
            f"({report['n_scored']}/{report['n_real_total']} windows scored)",
            transform=ax.transAxes, ha="center", fontsize=8, color="#444444")
    caption = ("Detector trained on SYNTHETIC Track B, scored on REAL IoT-23 "
               "benign. This is a distribution-shift false-alarm caveat, NOT "
               "validation of the thesis (absent from IoT-23).")
    out = Path(path) if path else FIGURE_DIR / "cross_track_fpr.png"
    return _finish(fig, out, caption)
