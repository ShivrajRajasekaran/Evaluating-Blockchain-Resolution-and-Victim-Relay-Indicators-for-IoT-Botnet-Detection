# Evaluation protocol

*Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT
Botnet Detection*

This document is the protocol a result must have followed to be trustworthy. It
describes how data is split, how detectors are made comparable, how the headline
question is answered, and how uncertainty is quantified. Each rule is here
because skipping it produces an optimistic number, and the whole point of the
project is to *risk* the hypothesis rather than flatter it.

The protocol is applied **per track**. Track B answers the incremental-value
question; Track A answers the false-alarm question. They are never pooled
(`docs/data-provenance.md`, `docs/limitations.md` L2).

---

## 1. The unit of analysis is a device-window

One row is one device observed over one 300-second window. This matters for the
split: windows from the same device are **not** independent samples — they share
that device's fixed behaviour (idle rhythm, firmware habits, owner schedule). Any
protocol that treats them as independent will overstate performance.

## 2. Splits: a locked test set, grouped by device

`src/evaluate/splits.py` offers three strategies, answering three different
questions:

| Strategy | Question it answers | Devices across splits |
|---|---|---|
| **`group`** (default) | Does it catch an **unseen device**? | disjoint — no device in two splits |
| `temporal` | Does a model trained on the past hold on a **later period**? | shared *on purpose* |
| `random` | *(prototype reproduction only)* | leaked — **not valid for new claims** |

**`group` is the headline default**, because "would this catch a device it was
never trained on?" is the question a deployment actually asks. A random row-level
split lets a device appear in both train and test, so the model can memorise the
device and score well on windows it has effectively already seen — memorisation
reported as generalisation, in the optimistic direction.

- `random` **emits a warning** and exists only to reproduce the prototype's
  published numbers for comparison; its optimism relative to `group` is itself a
  reportable quantity.
- The grouped split is **stratified per device** by the device's majority label,
  and cut per stratum so a rare class cannot vanish from a split by chance.
- The no-leak invariant is **asserted, not assumed**: if allocation ever leaked a
  device across splits, `splits.py` raises rather than silently inflating scores.
- `min_windows_per_device` (default 1 = keep everything) can drop thin devices;
  the number dropped is always reported.

**The test set is carved off first and touched exactly once**, at the final
scoring. Model selection, threshold calibration, and importance analysis all run
on the **validation** split. A test set peeked at during tuning is a validation
set wearing a test set's name.

## 3. Calibration: one false-positive budget for everyone

Detectors pick their operating points by different conventions — a rule detector
at "3 of N rules", a forest at "p ≥ 0.5". Comparing their F1 at those defaults
compares the conventions as much as the models, and any model can be made to
"win" by nudging its own default.

`src/evaluate/thresholds.py` removes that freedom:

1. Choose each detector's threshold on the **validation** split so all sit at the
   same false-positive rate on benign traffic — the budget the research question
   names (`evaluation.target_fpr`, default **1%**).
2. Score every detector on the **locked test** split at its own calibrated
   threshold.

The comparison becomes "at the same false-alarm cost, who catches more?" — the
question a deployment faces.

- **The budget is a ceiling, never exceeded to hit it exactly.** Under ties the
  threshold admits *fewer* false positives, not more.
- **Calibrating on validation, not test, is deliberate.** A threshold chosen on
  test to hit exactly 1% has used the test labels, so its test FPR is a fit, not
  an estimate. Because we calibrate on validation, the test FPR is allowed to
  **drift** from the budget — and that drift is reported
  (`fpr_drift_test_minus_target`). It is the honest generalisation gap of the
  calibration, not something to hide.
- A coarse score (a rule detector's integer vote count) may not land on 1%
  exactly; the achieved validation FPR is reported so coarseness is not mistaken
  for a tuning win (`score_is_coarse`).

## 4. The headline metric is recall at the FPR budget

At a fixed 1% false-alarm cost, the question is how much malicious traffic each
feature set catches — so the headline metric is **recall**
(`experiment.py::HEADLINE_METRIC`). Precision, F1, and ROC-AUC are reported
alongside, but the ranking that answers the research question is recall at the
budget.

## 5. The incremental-value experiment

`run_incremental` fits one model per feature set on **one shared split**:

- `base (infection + payload)` — the reference;
- `base + resolution`;
- `base + relay`;
- `base + resolution + relay`.

For each augmented set it reports the **paired recall difference from base** with
a 95% device-level bootstrap interval, and whether that interval **excludes
zero**. The verdict is read straight off the intervals:

- interval excludes zero and lies above it → a **distinguishable gain**;
- interval **straddles zero** → **no distinguishable value** — reported as a null
  result, never re-tuned away (`docs/paper-results-policy.md` §2).

`run_incremental_multiseed` repeats this across `seeds.split` and reports whether
the verdict is robust across seeds or seed-sensitive, so a claim rests on "held
across N seeds", not one lucky seed.

Supporting analyses: `run_model_comparison` (heuristic vs RF vs XGBoost at the
same budget), `run_drop_one` (leave-one-group-out), `run_lab_only_sensitivity`
(the effect of the payload-only `rc4_string_score`), and permutation importance
(`explain.py`) as an inside-the-model corroboration. **Gain importance is
contrast-only** — biased, computed on training data — and is never reported as a
finding.

## 6. Uncertainty: bootstrap by group, not by row

`src/evaluate/bootstrap.py` resamples the **resampling unit named in the config**
(`bootstrap_unit`, default `group`). Under a grouped split, resampling *rows*
would treat a device's many windows as independent draws and produce an interval
far too narrow — false confidence. Resampling **devices** (with their windows
kept together) yields an interval whose width reflects how many *independent
devices* the estimate actually rests on. `n_bootstrap` defaults to 1000.

This is adjustment (4) of the build: **bootstrap CIs under grouped splits
resample by group, not row.**

## 7. The one permitted crossing

`cross_track.py` scores a **Track-B-trained, Track-B-calibrated** detector
against **IoT-23 benign** windows, using only the features IoT-23 can supply
(unavailable features excluded; proxies excluded unless explicitly included).
It reports the real-benign FPR **and** coverage (how many real windows could be
scored versus abstained). This measures false alarms under distribution shift; it
is not validation of the thesis, which is absent from IoT-23
(`docs/paper-results-policy.md` §4).

## 8. What makes a result reportable

A number may be reported only if:

- it came from the **`group`** split (or `temporal` for the later-period
  question) — never `random` for a new claim;
- every detector in the comparison was **calibrated to the same budget**;
- its interval was computed by **group bootstrap**;
- the **test set was scored once**;
- its **track, config, and seed(s)** are recorded on the artefact.

See `docs/paper-results-policy.md` for how such a number may then be described.
