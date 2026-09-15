"""
run_all.py — end-to-end prototype run. Produces every mentor-showable artifact:

  results/tables/model_comparison.csv      P/R/F1/AUC/FPR at default thresholds
  results/tables/threshold_matched.csv     all detectors pinned to a common FPR
  results/tables/incremental_value.csv     base vs +resolution vs +relay (HEADLINE)
  results/tables/lab_only_sensitivity.csv  with vs without payload-derived feature
  results/tables/ablation.csv              per-group F1 drop (diagnostic only)
  results/tables/robustness.csv            multi-seed mean +/- std (split seeds)
  results/tables/robustness_generator.csv  INDEPENDENT regenerated datasets
  results/tables/feature_importance.csv    gain-based (biased, kept for contrast)
  results/tables/permutation_importance.csv held-out permutation (preferred)
  results/figures/*.png                    matching figures

PROTOCOL NOTES
  * Test set is LOCKED: model choice, thresholds and importances use validation.
  * The heuristic's score has only 8 distinct levels (7 binary votes), so its
    ROC-AUC is computed over a coarse, heavily-tied curve and is not comparable
    to a continuous-score model's AUC. Prefer the threshold-matched table.
"""
import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, roc_curve, precision_recall_curve

import config as C
from detectors import build_all, HAS_XGB
from evaluate import (
    load_split, load_split_3way, fit_predict, metric_row, scale_pos_weight,
    threshold_at_fpr, metrics_at_threshold, bootstrap_f1_ci,
)
from ablation import run_ablation, run_incremental, run_without_lab_only

sns.set_theme(style="whitegrid", context="talk")


def main():
    print("=" * 68)
    print(" IoT Blockchain-C2 Detection — Prototype Benchmark")
    print(" (LOCAL SYNTHETIC DATA — no real network / C2 / malware)")
    print("=" * 68)
    print(f" XGBoost available: {HAS_XGB}")
    print(f" Unit of analysis : {C.UNIT_OF_ANALYSIS}")

    # Realised class counts (NOT the nominal N_BENIGN / N_MALICIOUS — label
    # noise moves them).
    _full = pd.read_csv(C.DATASET_CSV)
    _pos = int(_full[C.LABEL_COL].sum())
    _neg = len(_full) - _pos
    print(f" Realised labels  : {_neg} benign / {_pos} malicious "
          f"(nominal was {C.N_BENIGN}/{C.N_MALICIOUS} before "
          f"{C.LABEL_NOISE:.0%} label noise)")

    Xtr, Xte, ytr, yte = load_split()
    spw = scale_pos_weight(ytr)
    print(f" Train={len(Xtr)}  Test={len(Xte)}  scale_pos_weight={spw:.2f}\n")

    models = build_all(scale_pos_weight=spw)
    results, preds = [], {}
    for name, model in models.items():
        y_pred, y_score = fit_predict(model, Xtr, ytr, Xte)
        results.append(metric_row(name, yte, y_pred, y_score))
        preds[name] = (y_pred, y_score)
        r = results[-1]
        print(f"  {name:13s}  P={r['Precision']:.3f}  R={r['Recall']:.3f}  "
              f"F1={r['F1']:.3f}  AUC={r['ROC_AUC']:.3f}  FPR={r['FPR']:.3f}")

    res_df = pd.DataFrame(results)
    res_df.to_csv(C.TAB_DIR / "model_comparison.csv", index=False)

    # ---- Figure 1: model comparison bars ----
    fig, ax = plt.subplots(figsize=(9, 5.5))
    m = res_df.melt(id_vars="Model", value_vars=["Precision", "Recall", "F1", "ROC_AUC"])
    sns.barplot(data=m, x="Model", y="value", hue="variable", ax=ax)
    ax.set_ylim(0, 1.05); ax.set_ylabel("score"); ax.set_xlabel("")
    ax.set_title("Detector comparison (synthetic test set)")
    ax.legend(title="", ncol=4, loc="lower center", bbox_to_anchor=(0.5, -0.28))
    fig.tight_layout(); fig.savefig(C.FIG_DIR / "model_comparison.png", dpi=150,
                                    bbox_inches="tight"); plt.close(fig)

    # ---- Figure 2: confusion matrices ----
    n = len(preds)
    fig, axes = plt.subplots(1, n, figsize=(4.5 * n, 4))
    if n == 1:
        axes = [axes]
    for ax, (name, (y_pred, _)) in zip(axes, preds.items()):
        cm = confusion_matrix(yte, y_pred)
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False, ax=ax,
                    xticklabels=["benign", "malic."], yticklabels=["benign", "malic."])
        ax.set_title(name); ax.set_xlabel("predicted"); ax.set_ylabel("actual")
    fig.suptitle("Confusion matrices"); fig.tight_layout()
    fig.savefig(C.FIG_DIR / "confusion_matrices.png", dpi=150); plt.close(fig)

    # ---- Figure 3: ROC + PR ----
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.5))
    for name, (_, y_score) in preds.items():
        fpr, tpr, _ = roc_curve(yte, y_score)
        ax1.plot(fpr, tpr, label=name, lw=2)
        pr, rc, _ = precision_recall_curve(yte, y_score)
        ax2.plot(rc, pr, label=name, lw=2)
    ax1.plot([0, 1], [0, 1], "k--", lw=1)
    ax1.set_title("ROC"); ax1.set_xlabel("FPR"); ax1.set_ylabel("TPR"); ax1.legend()
    ax2.set_title("Precision–Recall"); ax2.set_xlabel("Recall"); ax2.set_ylabel("Precision"); ax2.legend()
    fig.tight_layout(); fig.savefig(C.FIG_DIR / "roc_pr_curves.png", dpi=150); plt.close(fig)

    # ---- Threshold-matched comparison (fair operating point) ----
    print(f"\n Threshold-matched comparison @ validation FPR <= {C.TARGET_FPR:.1%}:")
    tm = _threshold_matched()
    tm.to_csv(C.TAB_DIR / "threshold_matched.csv", index=False)
    print(tm.drop(columns=["TP", "FP", "FN", "TN"]).round(4).to_string(index=False))

    # ---- Incremental value: the honest test of the thesis ----
    print("\n Incremental value (base -> +resolution / +relay), locked test set:")
    inc = run_incremental()
    inc.to_csv(C.TAB_DIR / "incremental_value.csv", index=False)
    print(inc.round(4).to_string(index=False))
    print(f"   [model selected on validation: {inc.attrs.get('selected_model')}]")
    _plot_incremental(inc)

    # ---- Lab-only feature sensitivity ----
    print("\n Sensitivity to payload-derived (lab-only) features:")
    labs = run_without_lab_only()
    labs.to_csv(C.TAB_DIR / "lab_only_sensitivity.csv", index=False)
    print(labs.round(4).to_string(index=False))

    # ---- Drop-one ablation (now a diagnostic, not the headline) ----
    print("\n Drop-one ablation (DIAGNOSTIC — weak when groups correlate):")
    abl = run_ablation()
    abl.to_csv(C.TAB_DIR / "ablation.csv", index=False)
    print(abl.to_string(index=False))
    print(f"   [model selected on validation: {abl.attrs.get('selected_model')}"
          f"  val F1: {abl.attrs.get('val_scores')}]")

    fig, ax = plt.subplots(figsize=(9, 5))
    d = abl[abl["Dropped_group"] != "(none)"]
    sns.barplot(data=d, x="Dropped_group", y="F1_drop", ax=ax, color="#2E75B6")
    ax.axhline(0, color="black", lw=1)
    ax.set_title("Drop-one ablation (diagnostic)")
    ax.set_xlabel("feature group removed"); ax.set_ylabel("F1 drop vs. full model")
    fig.tight_layout(); fig.savefig(C.FIG_DIR / "ablation.png", dpi=150); plt.close(fig)

    # ---- Multi-seed robustness (SPLIT/MODEL seeds, one fixed dataset) ----
    print("\n Robustness A — split/model seeds on ONE dataset:")
    seed_rows = []
    for s in C.SEEDS:
        Xtr2, Xte2, ytr2, yte2 = load_split(seed=s)
        spw2 = scale_pos_weight(ytr2)
        for name, model in build_all(seed=s, scale_pos_weight=spw2).items():
            yp, ys = fit_predict(model, Xtr2, ytr2, Xte2)
            row = metric_row(name, yte2, yp, ys); row["seed"] = s
            seed_rows.append(row)
    sdf = pd.DataFrame(seed_rows)
    rob = sdf.groupby("Model")[["Precision", "Recall", "F1", "ROC_AUC"]].agg(["mean", "std"])
    rob.to_csv(C.TAB_DIR / "robustness.csv")
    print(rob.round(3).to_string())
    print("   (measures split variance only — NOT generator variance)")

    # ---- Generator-level robustness (INDEPENDENT datasets per seed) ----
    print("\n Robustness B — independently REGENERATED datasets per seed:")
    gen_rob = _generator_robustness()
    gen_rob.to_csv(C.TAB_DIR / "robustness_generator.csv")
    print(gen_rob.round(3).to_string())

    # ---- Feature importance (explainability) ----
    # NOTE: SHAP is intentionally NOT used here — the shap package crashes the
    # interpreter at import time in this env (native/DLL fault that try/except
    # cannot catch). Two substitutes are reported:
    #   (a) gain-based feature_importances_  — fast, but BIASED toward
    #       high-cardinality/continuous features and arbitrary among correlated
    #       features. Kept only for contrast.
    #   (b) permutation importance on held-out VALIDATION data — model-agnostic
    #       and measures actual predictive contribution. This is the one to cite.
    _feature_importance(Xtr, ytr, spw)
    _permutation_importance()

    print("\nDONE. Tables -> results/tables/ , Figures -> results/figures/")


def _threshold_matched(seed=C.RANDOM_SEED):
    """Pin every detector to the same validation FPR budget, then score on test.

    Comparing 'vote >= 3' against 'p >= 0.5' compares two arbitrary constants.
    Here each detector's threshold is chosen on VALIDATION data to sit at or
    under TARGET_FPR, and only then applied to the locked test set — so the
    comparison is about detection power at a fixed false-alarm cost.
    """
    Xtr, Xva, Xte, ytr, yva, yte = load_split_3way(seed=seed)
    spw = scale_pos_weight(ytr)

    rows = []
    for name, model in build_all(seed=seed, scale_pos_weight=spw).items():
        model.fit(Xtr, ytr)
        s_val = model.predict_proba(Xva)[:, 1]
        s_test = model.predict_proba(Xte)[:, 1]
        thr = threshold_at_fpr(yva, s_val, C.TARGET_FPR)
        row = metrics_at_threshold(name, yte, s_test, thr)
        lo, hi = bootstrap_f1_ci(yte, (s_test >= thr).astype(int), seed=seed)
        row["F1_CI_low"], row["F1_CI_high"] = lo, hi
        rows.append(row)

    cols = ["Model", "Threshold", "Precision", "Recall", "F1",
            "F1_CI_low", "F1_CI_high", "ROC_AUC", "FPR", "TP", "FP", "FN", "TN"]
    return pd.DataFrame(rows)[cols]


def _generator_robustness():
    """Regenerate INDEPENDENT synthetic datasets and re-run the benchmark.

    The original robustness table varied only the split/model seed on a single
    fixed CSV, so it measured split variance and called it stability. This
    varies the data-generating seed itself, which is the larger source of
    variation — and still does not measure generalisation to real traffic.
    """
    from generate_synthetic import generate
    from sklearn.model_selection import train_test_split

    rows = []
    for s in C.SEEDS:
        df = generate(seed=s)
        X = df[C.FEATURE_COLS]
        y = df[C.LABEL_COL]
        Xtr, Xte, ytr, yte = train_test_split(
            X, y, test_size=C.TEST_SIZE, stratify=y, random_state=C.RANDOM_SEED)
        spw = scale_pos_weight(ytr)
        for name, model in build_all(seed=C.RANDOM_SEED, scale_pos_weight=spw).items():
            yp, ys = fit_predict(model, Xtr, ytr, Xte)
            row = metric_row(name, yte, yp, ys)
            row["gen_seed"] = s
            rows.append(row)

    gdf = pd.DataFrame(rows)
    return gdf.groupby("Model")[["Precision", "Recall", "F1", "ROC_AUC"]].agg(
        ["mean", "std"])


def _plot_incremental(inc):
    """Bar chart with 95% CI error bars — overlapping bars mean 'no evidence'."""
    fig, ax = plt.subplots(figsize=(10, 5.5))
    x = np.arange(len(inc))
    lo = (inc["F1"] - inc["F1_CI_low"]).clip(lower=0).values
    hi = (inc["F1_CI_high"] - inc["F1"]).clip(lower=0).values
    ax.bar(x, inc["F1"].values, color="#2E75B6",
           yerr=np.vstack([lo, hi]), capsize=6)
    ax.set_xticks(x)
    ax.set_xticklabels(inc["Feature_set"], rotation=18, ha="right", fontsize=10)
    lo_lim = max(0.0, float(inc["F1_CI_low"].min()) - 0.02)
    ax.set_ylim(lo_lim, 1.0)
    ax.set_ylabel("test F1 (95% bootstrap CI)")
    ax.set_title("Incremental value of resolution / relay indicators")
    fig.tight_layout()
    fig.savefig(C.FIG_DIR / "incremental_value.png", dpi=150)
    plt.close(fig)


def _permutation_importance(seed=C.RANDOM_SEED):
    """Permutation importance on held-out VALIDATION data.

    Preferred over tree gain: gain is computed on the training data and is
    biased toward continuous / high-cardinality features, while permutation
    importance measures the actual drop in held-out F1 when a feature is
    shuffled.
    """
    from sklearn.inspection import permutation_importance
    from ablation import select_best_model

    Xtr, Xva, Xte, ytr, yva, yte = load_split_3way(seed=seed)
    best_name, best_factory, _ = select_best_model(Xtr, ytr, Xva, yva, seed)
    model = best_factory(seed)
    model.fit(Xtr, ytr)

    r = permutation_importance(
        model, Xva, yva, n_repeats=10, random_state=seed,
        scoring="f1", n_jobs=-1)

    imp = pd.DataFrame({
        "feature": Xva.columns,
        "importance_mean": r.importances_mean,
        "importance_std": r.importances_std,
    }).sort_values("importance_mean", ascending=False)
    imp["group"] = imp["feature"].map(
        {c: g for g, cols in C.FEATURE_GROUPS.items() for c in cols})
    imp.to_csv(C.TAB_DIR / "permutation_importance.csv", index=False)

    plot_df = imp.sort_values("importance_mean")
    palette = {"resolution": "#1F4E79", "relay": "#2E75B6",
               "infection": "#C55A11", "payload": "#548235"}
    colors = [palette[g] for g in plot_df["group"]]

    fig, ax = plt.subplots(figsize=(9, 7))
    ax.barh(plot_df["feature"], plot_df["importance_mean"],
            xerr=plot_df["importance_std"], color=colors, capsize=3)
    ax.axvline(0, color="black", lw=1)
    ax.set_title(f"Permutation importance on validation ({best_name})")
    ax.set_xlabel("mean drop in F1 when feature is shuffled")
    handles = [plt.Rectangle((0, 0), 1, 1, color=palette[g]) for g in palette]
    ax.legend(handles, palette.keys(), title="group", loc="lower right")
    fig.tight_layout()
    fig.savefig(C.FIG_DIR / "permutation_importance.png", dpi=150)
    plt.close(fig)
    print("\n Permutation importance (top 6, validation):")
    print(imp.head(6).round(4).to_string(index=False))


def _feature_importance(Xtr, ytr, spw):
    from detectors import make_xgboost, make_random_forest
    model = make_xgboost(scale_pos_weight=spw) if HAS_XGB else make_random_forest()
    model.fit(Xtr, ytr)
    imp = pd.Series(model.feature_importances_, index=Xtr.columns).sort_values()

    # colour bars by feature group
    group_of = {c: g for g, cols in C.FEATURE_GROUPS.items() for c in cols}
    palette = {"resolution": "#1F4E79", "relay": "#2E75B6",
               "infection": "#C55A11", "payload": "#548235"}
    colors = [palette[group_of[c]] for c in imp.index]

    fig, ax = plt.subplots(figsize=(9, 7))
    ax.barh(imp.index, imp.values, color=colors)
    ax.set_title(f"Feature importance ({'XGBoost' if HAS_XGB else 'RandomForest'})")
    ax.set_xlabel("importance (gain)")
    handles = [plt.Rectangle((0, 0), 1, 1, color=palette[g]) for g in palette]
    ax.legend(handles, palette.keys(), title="group", loc="lower right")
    fig.tight_layout()
    fig.savefig(C.FIG_DIR / "feature_importance.png", dpi=150)
    plt.close(fig)
    imp.sort_values(ascending=False).to_csv(C.TAB_DIR / "feature_importance.csv",
                                            header=["importance"])
    print("\n Feature importance saved -> results/figures/feature_importance.png")


if __name__ == "__main__":
    main()
