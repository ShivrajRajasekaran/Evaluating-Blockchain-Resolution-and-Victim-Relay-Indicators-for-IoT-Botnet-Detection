# Limitations — read this before quoting any number from this repo

This prototype is a **controlled feasibility experiment on synthetic data**.
Every result here describes the behaviour of a *generator we wrote*, not the
behaviour of real IoT traffic. This file exists so that no number from this repo
is quoted without its caveat.

## 1. The headline claim is NOT yet supported

The project's thesis is that **blockchain-resolution** and **victim-relay**
indicators carry detection value beyond generic malware signals.

Current evidence (`results/tables/incremental_value.csv`):

| Feature set | F1 | 95% CI | Gain vs base |
|---|---|---|---|
| base (infection+payload) | 0.9144 | [0.894, 0.934] | — |
| base + resolution | 0.9263 | [0.908, 0.944] | +0.0120 |
| base + relay | 0.9263 | [0.908, 0.944] | +0.0120 |
| base + resolution + relay | 0.9253 | [0.907, 0.943] | +0.0109 |

Each addition gives a small positive gain, but **the confidence intervals
overlap the base model heavily**. The correct reading is: *no statistically
distinguishable improvement was demonstrated on this synthetic distribution.*
Adding both groups is no better than adding either one — consistent with the two
groups being largely redundant with each other **as currently generated**.

This is a **null result on synthetic data**, not evidence that the indicators are
worthless in reality. The generator was never fitted to measured traffic, so it
cannot settle the question either way.

## 2. Drop-one ablation is a weak instrument (and was previously mis-read)

`results/tables/ablation.csv` shows removing `resolution` or `relay` *improves*
F1 by ~0.001. Earlier framing treated this as "these groups are redundant".

That inference is unsound. When feature groups are correlated, dropping one
costs nothing because the others cover for it — even if it is genuinely
informative. A ~0 or slightly negative drop is what you'd expect from **either**
a useless group **or** a redundant-but-informative one. Drop-one ablation cannot
distinguish these. It is retained as a diagnostic only; the build-up protocol in
§1 is the headline.

Also note the deltas (±0.001) are far inside the bootstrap CI width (±0.02).
They are noise, and should never be described as one group "helping" or
"hurting".

## 3. `rc4_string_score` dominates, and is not deployable

Permutation importance on held-out data (`permutation_importance.csv`):

| Feature | Δ F1 when shuffled | Group |
|---|---|---|
| rc4_string_score | 0.1966 | payload |
| beacon_jitter | 0.0688 | payload |
| failed_conn_ratio | 0.0084 | infection |
| everything else | < 0.008 | — |

Two problems:

1. **Circularity.** The generator creates this score; the model learns it. It is
   close to reading the label off a synthetic "maliciousness" dial.
2. **Not observable in the real world.** RC4 string signatures require plaintext
   payload or host telemetry. In encrypted modern IoT traffic this feature does
   not exist. It is flagged in `config.LAB_ONLY_FEATURES`.

Sensitivity check (`lab_only_sensitivity.csv`): removing it drops F1 from
**0.9253 → 0.8976**. The pipeline does not collapse without it, which is
reassuring, but the remaining performance still rests on synthetic assumptions.

**Any real-world claim must be made on the network-observable feature set only.**

## 4. Generalisation ceiling (often mislabelled "leakage")

Train and test rows are independent draws from the same parametric generator.
There is **no contamination bug** — nothing from a test row appears in training.

The real limitation is subtler and more serious: because both splits come from
one fixed distribution, the test set can only measure *in-distribution* accuracy.
It cannot measure generalisation to a new device, a new network, a later time
period, or a different attacker configuration. Test-set F1 here is an upper
bound on real-world performance, and a loose one.

Fixing this requires the generator to emit device identities and time windows so
that **grouped** (by device) and **temporal** (train past → test future) splits
become possible. Not yet implemented.

## 5. What the robustness tables do and don't show

- `robustness.csv` — varies split/model seed on **one fixed dataset**. Measures
  split variance only (F1 std ≈ 0.005).
- `robustness_generator.csv` — regenerates **independent datasets** per seed
  (F1 std ≈ 0.006).

Both are stability under *our own* generator. Neither measures stability across
independent traffic captures, device populations, or time periods. "Results are
stable across seeds" must never be shortened to "results are stable".

## 6. Threshold fairness

The default comparison (`model_comparison.csv`) puts the heuristic at `vote ≥ 3`
and the ML models at `p ≥ 0.5` — two arbitrary constants. Part of the apparent
ML advantage is an artefact of that choice.

`threshold_matched.csv` pins every detector to **validation FPR ≤ 1%**, then
scores once on the locked test set. Under matched conditions:

| Model | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Heuristic | 0.973 | 0.450 | 0.615 | 0.002 |
| RandomForest | 0.936 | 0.883 | 0.909 | 0.010 |
| XGBoost | 0.962 | 0.883 | 0.921 | 0.006 |

The ML advantage **survives** threshold matching, and the mechanism becomes
clear: at a fixed false-alarm budget the heuristic loses recall badly (0.45 vs
0.88). This is a stronger and more honest result than the default table.

## 7. Heuristic ROC-AUC is not comparable

The heuristic's score is a count of 7 binary votes → only **8 distinct levels**.
Its ROC curve has 8 points, and AUC is computed by interpolating across large
tied blocks. The resulting 0.919 is not comparable to a continuous-score model's
AUC. (Note: this is a *resolution* problem, not a calibration problem — AUC is
invariant to monotone rescaling, so dividing votes by 7 changes nothing.)

Use the threshold-matched table for detector comparison, not AUC.

## 8. Unit of analysis

One row = **one device over one 5-minute window** (`config.UNIT_OF_ANALYSIS`).
Not one flow. Features like `distinct_dst_ports`, `flow_fanout`, `scan_rate` and
`login_burst_count` are undefined for a single flow. The dataset was previously
named `synthetic_flows.csv`, which was wrong; it is now
`synthetic_device_windows.csv`.

## 9. Class counts

Nominal generation is 8,000 benign / 1,200 malicious, but 2% label noise is
applied afterwards. **Realised counts (seed 42): 7,866 benign / 1,334
malicious**, imbalance 5.9:1. Always quote realised counts.

## 10. Reproducibility

`environment.yml` (full conda export) and pinned versions in `requirements.txt`.
Results were produced with Python 3.13.12, numpy 2.3.5, pandas 2.2.3,
scikit-learn 1.9.0, xgboost 3.3.0 on Windows.

---

## What would actually settle the thesis

1. Ground each feature in a specific, observable, defensible event.
2. Build benign controls that use the **same mechanism** legitimately — devices
   with genuine periodic resolver/RPC activity and genuine UPnP use.
3. Construct scenarios where resolution/relay behaviour appears **independently**
   of payload/infection signals, so the groups are not redundant by construction.
4. Re-run the build-up protocol (§1) with grouped and temporal splits.
5. Validate on approved public benign captures + isolated mock-labelled captures
   via a PCAP-to-feature adapter.

**Standing rule:** if resolution/relay show no value, the response is to improve
grounding and controls — **never** to widen the distance between class
distributions in the generator until the thesis is confirmed. That would be
fabrication-by-design.
