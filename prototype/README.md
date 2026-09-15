# IoT Blockchain-C2 Detection — Prototype

**Defensive research prototype.** Detects IoT hosts exhibiting blockchain-anchored
command-and-control (C2) and victim-relay behaviour, using a benchmarked set of
detectors over engineered behavioural features.

> ## Scope & ethics (non-negotiable)
> This code performs **detection / analysis / classification / visualisation only**.
> It does **NOT** build or operate a botnet, C2, DDoS tool, or any attack capability;
> it does **NOT** contact real devices, real ENS/SNS domains, or live C2; it does
> **NOT** execute malware. The dataset here is **locally generated and synthetic** —
> it only produces realistic *feature shapes* for labelling so the pipeline can
> be built before any real capture exists. Real public datasets (IoT-23, Bot-IoT,
> N-BaIoT, CIC-IDS) and an isolated mock testbed are introduced later, only after
> mentor approval. All threat-intelligence specifics from the proposal (names, dates,
> domains, CVE, scale figures) are **UNVERIFIED** and are not used as ground truth.

> ## ⚠️ Read `LIMITATIONS.md` before quoting any number from this repo
> This is a **controlled feasibility experiment on an unvalidated synthetic
> generator**. It demonstrates that the pipeline runs; it is **not** evidence that
> the detection method works on real IoT traffic.

## Unit of analysis

One row = **one device observed over one 5-minute window**. Not one flow —
features such as `distinct_dst_ports`, `flow_fanout`, `scan_rate` and
`login_burst_count` are undefined for a single flow and only exist as per-device
aggregates over a window.

## Evaluation protocol

- **Locked test set.** A 30% test split is carved off first and scored exactly
  once. Model selection, threshold calibration and feature importance all use a
  separate validation split (20% of the remainder).
- **Threshold matching.** Every detector is pinned to the same validation
  false-positive budget (≤1%) before being scored, so the comparison is not an
  artefact of `vote ≥ 3` vs `p ≥ 0.5`.
- **Build-up over drop-one.** The headline is incremental value (base →
  +resolution → +relay) with 95% bootstrap CIs, not drop-one ablation.
- **Two robustness axes.** Split/model seeds on a fixed dataset, *and*
  independently regenerated datasets.

## Environment

Runs in the Anaconda environment **`shiva`**:

```
C:\Users\shivraj\anaconda3\envs\shiva\python.exe
```

Exact versions the published results were produced with: Python 3.13.12,
numpy 2.3.5, pandas 2.2.3, scikit-learn 1.9.0, scipy 1.18.0, matplotlib 3.11.0,
seaborn 0.13.2, xgboost 3.3.0, imbalanced-learn 0.14.2, streamlit 1.60.0.
Installed via `conda-forge` (ABI-aligned — plain pip wheels caused a native
numpy/BLAS crash on Windows). Full lock in `environment.yml`:

```bash
conda env create -n shiva -f environment.yml
```

(SHAP is intentionally not used — it faults on import in this env. Explainability
is provided by permutation importance on held-out validation data, with gain
importance reported alongside only for contrast.)

## How to run

```bash
P="C:\Users\shivraj\anaconda3\envs\shiva\python.exe"
cd prototype/src
"$P" generate_synthetic.py     # writes data/synthetic_device_windows.csv
"$P" run_all.py                # trains, evaluates, writes all tables + figures
```

Dashboard:

```bash
cd prototype
"C:\Users\shivraj\anaconda3\envs\shiva\python.exe" -m streamlit run app.py
```

## Layout

```
prototype/
  src/
    config.py             feature groups, labels, paths, seeds, protocol (single source of truth)
    generate_synthetic.py synthetic labelled generator (overlapping classes, unvalidated)
    detectors.py          Heuristic baseline + RandomForest + XGBoost
    evaluate.py           3-way split / metrics / threshold matching / bootstrap CIs
    ablation.py           model selection, incremental value, drop-one, lab-only sensitivity
    run_all.py            orchestrator -> all tables + figures
  data/                   synthetic_device_windows.csv
  results/
    tables/               model_comparison, threshold_matched, incremental_value,
                          lab_only_sensitivity, ablation, robustness,
                          robustness_generator, feature_importance,
                          permutation_importance (CSV)
    figures/              model_comparison, confusion_matrices, roc_pr_curves,
                          incremental_value, ablation, feature_importance,
                          permutation_importance (PNG)
  app.py                  Streamlit dashboard (5 tabs)
  LIMITATIONS.md          what these numbers do and do not mean — READ FIRST
  environment.yml         full locked conda environment
```

## Current results (synthetic, seed 42)

Dataset: 9,200 device-windows. **Realised labels 7,866 benign / 1,334 malicious**
(5.9:1). Nominal generation was 8,000/1,200 before 2% label noise — always quote
the realised counts.

### Detector comparison at a matched false-alarm budget (validation FPR ≤ 1%)

| Model | Precision | Recall | F1 (95% CI) | FPR |
|---|---|---|---|---|
| Heuristic (rules) | 0.973 | 0.450 | 0.615 [0.567, 0.663] | 0.002 |
| RandomForest | 0.936 | 0.883 | 0.909 [0.888, 0.929] | 0.010 |
| XGBoost | 0.962 | 0.883 | **0.921** [0.901, 0.939] | 0.006 |

The ML advantage survives threshold matching. The mechanism is that at a fixed
false-alarm budget the heuristic holds precision but **loses recall badly**
(0.45 vs 0.88). ROC-AUC is not used to compare against the heuristic: its score
has only 8 distinct levels, so its curve is coarse and heavily tied.

### Incremental value of the claimed novelty — **null result**

| Feature set | F1 | 95% CI | Gain vs base |
|---|---|---|---|
| base (infection+payload) | 0.9144 | [0.894, 0.934] | — |
| base + resolution | 0.9263 | [0.908, 0.944] | +0.0120 |
| base + relay | 0.9263 | [0.908, 0.944] | +0.0120 |
| base + resolution + relay | 0.9253 | [0.907, 0.943] | +0.0109 |

**The confidence intervals overlap the base model heavily — no statistically
distinguishable improvement was demonstrated.** Adding both groups is no better
than adding either one, consistent with the two being largely redundant *as
currently generated*.

This is a **null result on synthetic data**, and it is reported as such. It is
not evidence that resolution/relay indicators are worthless in reality — the
generator was never fitted to measured traffic, so it cannot settle the question.
Fixing it by widening the class distributions in the generator would be
fabrication-by-design; see `LIMITATIONS.md`.

### Explainability

Permutation importance on held-out validation data:

| Feature | Δ F1 when shuffled | Group |
|---|---|---|
| rc4_string_score | 0.1966 | payload |
| beacon_jitter | 0.0688 | payload |
| failed_conn_ratio | 0.0084 | infection |
| all others (incl. every resolution/relay feature) | < 0.008 | — |

`rc4_string_score` is flagged **lab-only** (`config.LAB_ONLY_FEATURES`): it needs
plaintext payload or host telemetry and is not observable in encrypted traffic.
Removing it drops F1 from 0.925 → 0.898 — the pipeline does not collapse, but any
real-world claim must use the network-observable feature set only.

Tree gain importance is also reported, purely for contrast: it assigns
`rc4_string_score` ~47%, while permutation importance puts its true contribution
much lower — a concrete illustration of gain's bias.

### Robustness

| Axis | XGBoost F1 |
|---|---|
| Split/model seeds, one fixed dataset | 0.920 ± 0.004 |
| Independently regenerated datasets | 0.919 ± 0.004 |

Both measure stability under *our own* generator. Neither measures stability
across independent captures, device populations, or time periods.

## Next phase

1. Ground each feature in a specific observable event; build benign controls that
   use the same mechanisms legitimately.
2. Emit device IDs and time windows so **grouped** and **temporal** splits become
   possible (the current random split can only measure in-distribution accuracy).
3. Build a safe PCAP-to-feature adapter; validate on approved public benign
   captures plus isolated mock-labelled captures.
