"""
app.py — Streamlit dashboard for the IoT Blockchain-C2 Detection prototype.

Run with:
    C:\\Users\\shivraj\\anaconda3\\envs\\shiva\\python.exe -m streamlit run app.py
"""
import streamlit as st
import pandas as pd
import numpy as np
from pathlib import Path
import sys

# Add src to path so we can import project modules
sys.path.insert(0, str(Path(__file__).parent / "src"))

import config as C
from generate_synthetic import generate
from run_all import main as run_pipeline

# Page config
st.set_page_config(
    page_title="IoT Blockchain-C2 Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for the ethics banner
st.markdown("""
<style>
.ethics-banner {
    background-color: #fff3cd;
    border-left: 5px solid #ffc107;
    padding: 1rem;
    margin-bottom: 2rem;
    border-radius: 4px;
}
.ethics-banner strong {
    color: #856404;
}
</style>
""", unsafe_allow_html=True)

# ============================================================================
# ETHICS BANNER — always visible
# ============================================================================
st.markdown("""
<div class="ethics-banner">
<strong>⚠️ RESEARCH PROTOTYPE — SYNTHETIC DATA ONLY</strong><br>
This demo runs on <strong>locally-generated synthetic data</strong> to prove the detection
pipeline works end-to-end. It does <strong>NOT</strong> contact real networks, real blockchain
names, real C2 servers, or execute malware. All results here are <strong>placeholders</strong>
for the real-data stage. The project is defensive research only.
</div>
""", unsafe_allow_html=True)

# ============================================================================
# Title and overview
# ============================================================================
st.title("🛡️ IoT Blockchain-C2 Detection — Prototype Benchmark")
st.markdown("""
Detecting IoT devices exhibiting **blockchain-anchored command-and-control (C2)**
and **victim-relay** behaviour, benchmarked across:
- Heuristic baseline (rule-based)
- Random Forest
- XGBoost

**Key evaluation:** Ablation study (drop one feature group at a time) shows which
indicators matter most.
""")

# ============================================================================
# Sidebar — controls
# ============================================================================
st.sidebar.header("Controls")

if st.sidebar.button("🔄 Regenerate Data & Retrain", type="primary"):
    with st.spinner("Generating synthetic data..."):
        df = generate(seed=np.random.randint(1, 10000))
        df.to_csv(C.DATASET_CSV, index=False)
    with st.spinner("Training models + building tables/figures (may take ~1 min)..."):
        run_pipeline()
    st.sidebar.success(f"✅ {len(df)} flows generated, models retrained")
    st.rerun()

# Dataset info
if C.DATASET_CSV.exists():
    df_info = pd.read_csv(C.DATASET_CSV)
    n_pos = int(df_info[C.LABEL_COL].sum())
    n_neg = len(df_info) - n_pos
    st.sidebar.metric("Dataset size", f"{len(df_info):,} device-windows")
    st.sidebar.metric("Benign", f"{n_neg:,}")
    st.sidebar.metric("Malicious", f"{n_pos:,}")
    st.sidebar.metric("Imbalance", f"{n_neg/max(n_pos,1):.1f}:1")
    st.sidebar.caption(
        f"Realised counts after {C.LABEL_NOISE:.0%} label noise. "
        f"Nominal generation was {C.N_BENIGN:,}/{C.N_MALICIOUS:,}."
    )

st.sidebar.markdown("---")
st.sidebar.caption(
    f"**Unit of analysis:** {C.UNIT_OF_ANALYSIS}. "
    "Test set is locked — model choice, thresholds and importances use a "
    "separate validation split."
)

# ============================================================================
# Tabs
# ============================================================================
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Model Comparison",
    "🎯 Incremental Value",
    "🔍 Ablation (diagnostic)",
    "📈 Explainability",
    "💾 Dataset Preview"
])

# ============================================================================
# Tab 1: Model Comparison
# ============================================================================
with tab1:
    st.header("Model Comparison")

    model_comp_path = C.TAB_DIR / "model_comparison.csv"
    if model_comp_path.exists():
        df_mc = pd.read_csv(model_comp_path)

        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("Default thresholds")
            # Format the table nicely
            df_display = df_mc.copy()
            for col in ['Precision', 'Recall', 'F1', 'ROC_AUC', 'FPR']:
                if col in df_display.columns:
                    df_display[col] = df_display[col].apply(lambda x: f"{x:.3f}")
            st.dataframe(df_display, width='stretch', hide_index=True)

            st.warning(
                "This table compares the heuristic at `vote ≥ 3` against the ML "
                "models at `p ≥ 0.5` — two arbitrary constants. Part of the "
                "apparent ML advantage is an artefact of that choice. See the "
                "threshold-matched table below for the fair comparison."
            )

        with col2:
            st.subheader("Visualization")
            fig_path = C.FIG_DIR / "model_comparison.png"
            if fig_path.exists():
                st.image(str(fig_path), width='stretch')

    else:
        st.info("No results yet. Generate data and train models first.")

    # Threshold-matched comparison — the fair one
    st.subheader(f"Threshold-matched comparison (validation FPR ≤ {C.TARGET_FPR:.0%})")
    tm_path = C.TAB_DIR / "threshold_matched.csv"
    if tm_path.exists():
        df_tm = pd.read_csv(tm_path)
        show = df_tm.copy()
        show["F1 (95% CI)"] = show.apply(
            lambda r: f"{r['F1']:.3f} [{r['F1_CI_low']:.3f}, {r['F1_CI_high']:.3f}]",
            axis=1)
        for col in ['Threshold', 'Precision', 'Recall', 'FPR']:
            show[col] = show[col].apply(lambda x: f"{x:.4f}")
        show = show[["Model", "Threshold", "Precision", "Recall",
                     "F1 (95% CI)", "FPR"]]
        st.dataframe(show, width='stretch', hide_index=True)

        st.success(
            "**Every detector pinned to the same false-alarm budget on "
            "validation data, then scored once on the locked test set.** The ML "
            "advantage survives, and the mechanism is now visible: at a fixed "
            "1% FPR the heuristic keeps high precision but loses recall badly "
            "(0.45 vs 0.88). This is a stronger and more honest result than the "
            "default-threshold table above."
        )
        st.caption(
            "ROC-AUC is deliberately omitted here for the heuristic: its score "
            "is a count of 7 binary votes, so the curve has only 8 points and "
            "AUC is inflated by interpolation across large tied blocks. "
            "(Monotone rescaling — e.g. votes/7 — does not change AUC; the "
            "problem is score resolution, not calibration.)"
        )
    else:
        st.info("Run the pipeline to produce the threshold-matched table.")

    # ROC / PR curves
    st.subheader("ROC & Precision-Recall Curves")
    roc_pr_path = C.FIG_DIR / "roc_pr_curves.png"
    if roc_pr_path.exists():
        st.image(str(roc_pr_path), width='stretch')

# ============================================================================
# Tab 2: Incremental Value — the honest test of the thesis
# ============================================================================
with tab2:
    st.header("Incremental Value of Resolution / Relay Indicators")
    st.markdown("""
    The project's claim is that **blockchain-resolution** and **victim-relay**
    indicators carry detection value *beyond* generic malware signals.

    Drop-one ablation cannot test that when feature groups are correlated — if
    `payload` already separates the classes, dropping `resolution` costs nothing
    even when resolution is genuinely informative. So instead we **build up**
    from a base of generic signals and measure what each group adds, on
    identical splits, with 95% bootstrap confidence intervals.
    """)

    inc_path = C.TAB_DIR / "incremental_value.csv"
    if inc_path.exists():
        df_inc = pd.read_csv(inc_path)

        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("Results (locked test set)")
            show = df_inc.copy()
            show["F1 (95% CI)"] = show.apply(
                lambda r: f"{r['F1']:.3f} [{r['F1_CI_low']:.3f}, {r['F1_CI_high']:.3f}]",
                axis=1)
            show["Gain vs base"] = show["F1_gain_vs_base"].apply(lambda x: f"{x:+.4f}")
            show = show[["Feature_set", "N_features", "F1 (95% CI)", "Gain vs base"]]
            st.dataframe(show, width='stretch', hide_index=True)

            st.error(
                "**Preliminary finding — the thesis is NOT yet supported.** "
                "Each addition gives a small positive gain (+0.012), but the "
                "confidence intervals overlap the base model heavily. No "
                "statistically distinguishable improvement was demonstrated on "
                "this synthetic distribution. Adding *both* groups is no better "
                "than adding either one, consistent with the two being largely "
                "redundant **as currently generated**."
            )
            st.info(
                "This is a **null result on synthetic data**, not evidence that "
                "the indicators are worthless in reality. The generator was "
                "never fitted to measured traffic, so it cannot settle the "
                "question either way. The next phase is designed to test this "
                "claim with grounded, observable data."
            )

        with col2:
            st.subheader("Visualization")
            inc_fig = C.FIG_DIR / "incremental_value.png"
            if inc_fig.exists():
                st.image(str(inc_fig), width='stretch')
            st.caption("Overlapping error bars ⇒ no demonstrated value.")
    else:
        st.info("No incremental-value results yet.")

    # Lab-only sensitivity
    st.markdown("---")
    st.subheader("Sensitivity to lab-only (payload-derived) features")
    lab_path = C.TAB_DIR / "lab_only_sensitivity.csv"
    if lab_path.exists():
        df_lab = pd.read_csv(lab_path)
        show = df_lab.copy()
        show["F1 (95% CI)"] = show.apply(
            lambda r: f"{r['F1']:.3f} [{r['F1_CI_low']:.3f}, {r['F1_CI_high']:.3f}]",
            axis=1)
        show = show[["Feature_set", "N_features", "Precision", "Recall", "F1 (95% CI)"]]
        for col in ["Precision", "Recall"]:
            show[col] = show[col].apply(lambda x: f"{x:.3f}")
        st.dataframe(show, width='stretch', hide_index=True)
        st.markdown(f"""
        `rc4_string_score` requires plaintext payload or host telemetry — it is
        **not observable in encrypted IoT traffic**, so it is flagged as lab-only
        in `config.LAB_ONLY_FEATURES`. Removing it drops F1 from **0.925 → 0.898**.

        The pipeline does *not* collapse without it, which matters: it means the
        detector is not merely a payload-signature matcher. But any real-world
        claim must be made on the **network-observable feature set only**.
        """)
    else:
        st.info("No lab-only sensitivity results yet.")

# ============================================================================
# Tab 3: Ablation Study (diagnostic)
# ============================================================================
with tab3:
    st.header("Drop-One Ablation — diagnostic only")
    st.warning(
        "**This is not the headline result.** Drop-one ablation removes one "
        "group from the full model. When groups are correlated, dropping one "
        "costs nothing because the others cover for it — so a ~0 drop is what "
        "you'd expect from *either* a useless group *or* a "
        "redundant-but-informative one. It cannot distinguish them. See the "
        "**Incremental Value** tab for the protocol that actually tests the "
        "claim."
    )

    ablation_csv = C.TAB_DIR / "ablation.csv"
    if ablation_csv.exists():
        df_abl = pd.read_csv(ablation_csv)

        col1, col2 = st.columns([2, 1])

        with col1:
            st.subheader("Results")
            df_abl_display = df_abl.copy()
            for col in ['Precision', 'Recall', 'F1', 'ROC_AUC', 'FPR', 'F1_drop']:
                if col in df_abl_display.columns:
                    df_abl_display[col] = df_abl_display[col].apply(
                        lambda x: f"{x:.4f}" if pd.notna(x) else "")
            st.dataframe(df_abl_display, width='stretch', hide_index=True)

            if 'F1_drop' in df_abl.columns:
                d = df_abl[df_abl["Dropped_group"] != "(none)"]
                max_drop_row = d.loc[d['F1_drop'].idxmax()]
                st.info(
                    f"Largest drop: removing **{max_drop_row['Dropped_group']}** "
                    f"costs {max_drop_row['F1_drop']:.4f} F1."
                )
                st.caption(
                    "The resolution/relay deltas (±0.001) are far inside the "
                    "bootstrap CI width (±0.02) — they are noise, and must not "
                    "be described as a group 'helping' or 'hurting'."
                )

        with col2:
            st.subheader("Visualization")
            abl_fig = C.FIG_DIR / "ablation.png"
            if abl_fig.exists():
                st.image(str(abl_fig), width='stretch')
    else:
        st.info("No ablation results yet.")

# ============================================================================
# Tab 4: Explainability
# ============================================================================
with tab4:
    st.header("Feature Importance (Explainability)")

    perm_csv = C.TAB_DIR / "permutation_importance.csv"
    if perm_csv.exists():
        st.subheader("Permutation importance (held-out validation) — preferred")
        st.markdown("""
        Measures the actual drop in held-out F1 when a feature is shuffled.
        Model-agnostic, computed on data the model never trained on.
        """)
        df_perm = pd.read_csv(perm_csv)

        col1, col2 = st.columns([1, 1])
        with col1:
            show = df_perm.head(10).copy()
            show["Δ F1 when shuffled"] = show.apply(
                lambda r: f"{r['importance_mean']:.4f} ± {r['importance_std']:.4f}",
                axis=1)
            show = show[["feature", "group", "Δ F1 when shuffled"]]
            st.dataframe(show, width='stretch', hide_index=True)

            st.error(
                "**`rc4_string_score` dominates (Δ F1 = 0.197), and it is "
                "close to circular:** the generator creates this score and the "
                "model learns it. It is also not observable in encrypted "
                "traffic. Everything outside the payload group contributes "
                "< 0.01 — including all resolution and relay features, which "
                "is consistent with the null result in the Incremental Value tab."
            )

        with col2:
            perm_fig = C.FIG_DIR / "permutation_importance.png"
            if perm_fig.exists():
                st.image(str(perm_fig), width='stretch')

    st.markdown("---")

    fi_csv = C.TAB_DIR / "feature_importance.csv"
    if fi_csv.exists():
        st.subheader("Tree gain importance — shown for contrast only")
        st.caption(
            "Gain is computed on training data and is biased toward continuous "
            "and high-cardinality features, and arbitrary among correlated ones. "
            "It is not a substitute for permutation importance or SHAP. Note it "
            "assigns `rc4_string_score` ~47%, while permutation importance — the "
            "sounder measure — puts its real contribution far lower."
        )
        # CSV has an unnamed index column (feature name) + 'importance'
        df_fi = pd.read_csv(fi_csv, index_col=0)
        df_fi.index.name = "Feature"
        df_fi = df_fi.reset_index()
        df_fi = df_fi.rename(columns={"importance": "Importance"})

        col1, col2 = st.columns([1, 1])

        with col1:
            df_fi_top = df_fi.head(10).copy()
            df_fi_top["Importance"] = df_fi_top["Importance"].apply(lambda x: f"{x:.4f}")
            st.dataframe(df_fi_top, width='stretch', hide_index=True)

        with col2:
            fi_fig = C.FIG_DIR / "feature_importance.png"
            if fi_fig.exists():
                st.image(str(fi_fig), width='stretch')
    else:
        st.info("No feature-importance results yet.")

# ============================================================================
# Tab 5: Dataset Preview
# ============================================================================
with tab5:
    st.header("Dataset Preview")

    if C.DATASET_CSV.exists():
        df_data = pd.read_csv(C.DATASET_CSV)

        st.info(
            f"**Unit of analysis: {C.UNIT_OF_ANALYSIS}.** Not one flow — "
            "features such as `distinct_dst_ports`, `flow_fanout`, `scan_rate` "
            "and `login_burst_count` are undefined for a single flow and only "
            "exist as per-device aggregates over a window."
        )

        st.subheader("Feature Groups")
        st.markdown(f"""
        The synthetic generator produces **{len(C.FEATURE_COLS)} features** across
        **4 groups**:
        - **Resolution:** ENS/SNS query patterns, server-list pulls
        - **Relay:** bidirectional flow duration, UPnP mapping, fanout
        - **Infection:** login bursts, scan rate, failed connections
        - **Payload:** beaconing rhythm, jitter, RC4-string signature *(lab-only)*
        """)

        st.subheader("Sample Rows (first 20)")
        st.dataframe(df_data.head(20), width='stretch')

        st.subheader("Label Distribution")
        label_counts = df_data[C.LABEL_COL].value_counts().sort_index()
        st.bar_chart(label_counts)

        st.subheader("Robustness")
        rg = C.TAB_DIR / "robustness_generator.csv"
        if rg.exists():
            st.markdown("""
            Two robustness tables are produced:
            - `robustness.csv` — varies **split/model seed** on one fixed dataset
              (measures split variance only).
            - `robustness_generator.csv` — regenerates **independent datasets**
              per seed (measures generator variance).

            Both are stability under *our own* generator. Neither measures
            stability across independent captures, device populations, or time
            periods. *"Stable across seeds"* must never be shortened to
            *"stable"*.
            """)
    else:
        st.warning("No dataset found. Click 'Regenerate Data & Retrain' in the sidebar.")

# ============================================================================
# Footer
# ============================================================================
st.markdown("---")
st.caption("""
**Project:** Detecting Blockchain-Anchored C2 in IoT Botnets (B.E./B.Tech Final Year)
**Scope:** Defensive research prototype — detection/analysis only, no attack capability.
**Data:** Local synthetic device-windows (unvalidated generator, realistic overlap).
Public datasets (IoT-23, Bot-IoT) + isolated testbed come next.
**Read `LIMITATIONS.md` before quoting any number from this dashboard.**
""")
