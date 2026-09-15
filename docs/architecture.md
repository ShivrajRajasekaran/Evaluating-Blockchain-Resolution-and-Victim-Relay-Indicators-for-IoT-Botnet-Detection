# Architecture

*Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT
Botnet Detection*

This document describes how the code is organised and why. It is a map for a
reader who wants to find where a decision is made, not a tutorial — for running
things, see the root `README.md` and `docs/mentor-demo.md`.

---

## The shape of the pipeline

Everything flows one way, from a data source to a set of decisions and reports,
and the two tracks stay in separate lanes the whole way down:

```
        Track B (synthetic)                    Track A (real)
   src/ingest/mock_generator.py          local IoT-23 conn.log.labeled
              │                                       │
              │                             src/ingest/iot23.py
              │                          (zeek.py + iot23_labels.py)
              ▼                                       ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  src/features/  windowing.py -> derive.py                     │
   │  flows  ->  300 s device-windows  ->  16-feature observations │
   └─────────────────────────────────────────────────────────────┘
              │                                       │
   data/processed/track_b_*.csv          data/processed/track_a_*.csv
              │                                       │
              ▼                                       ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  src/schema/  columns.py (meaning) · validate.py (gate)       │
   └─────────────────────────────────────────────────────────────┘
              │                                       │
              ▼                                       ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  src/evaluate/  splits -> models -> thresholds -> metrics     │
   │                 -> bootstrap ; experiment / explain           │
   │                 cross_track.py  ← the one permitted crossing  │
   └─────────────────────────────────────────────────────────────┘
              │                                       │
              ▼                                       ▼
   src/reports/ (tables.py · figures.py)      src/services/score.py
        results/tables · results/figures         decisions CSV
```

The lanes converge in exactly one place — `src/evaluate/cross_track.py` — and
only in the safe direction: a Track-B detector is scored against Track-A benign
rows to measure false alarms. No Track-A label ever enters training and no
Track-B label is ever claimed of a real row. Everywhere else the tracks are
physically separate files with disjoint label vocabularies.

## Package by package

### `src/config.py` — paths and the config object
The filesystem layout (`ROOT`, `DATA_DIR`, `RESULTS_DIR`, …) and the YAML-backed
`ConfigNode`. Attribute access (`cfg.evaluation.target_fpr`) that raises
`ConfigError` on a typo instead of returning `None`. Also the two provenance
strings, `provenance_note()` and `real_data_note()`, kept here so no artefact can
carry a softer disclaimer than another.

### `src/schema/` — what a column *means*
- `columns.py` — the single source of truth: the 16 features, their 4 groups
  (`infection`, `payload` = base; `resolution`, `relay` = novel/on-trial),
  validated ranges, which are binary or lab-only, the label vocabularies for both
  tracks, and `FEATURE_AVAILABILITY` (which features IoT-23 can supply). *Not*
  tunable — changing it changes the meaning of stored data, so it lives in code
  where a diff is reviewable.
- `validate.py` — the gate every frame passes before it is trusted: schema
  validation, `read_observations`, and `trainable` (drops `unmapped` rows).
- `build.py` — assembles a valid observation frame from derived features.

The split of responsibility is deliberate and strict: **`columns.py` holds what a
column means (code); `configs/*.yaml` holds what number to use (data);
`config.py` bridges them.**

### `src/ingest/` — sources to observations
- `mock_generator.py` — Track B. Generates numeric flow/observation metadata for
  the scenarios under study. Sends nothing (see `docs/ethics-and-containment.md`).
  Carries the standing rule against widening class separation.
- `iot23.py` — Track A. Parses one local `conn.log.labeled` into observations.
  Its hard problem is orientation: a Zeek log is written from the connection
  originator's view, so every flow is normalised to **device-relative**
  orientation before any feature is computed.
- `zeek.py` — robust chunked TSV parsing with exact malformed-line accounting.
- `iot23_labels.py` — maps IoT-23's label strings to Track A research classes,
  and **cannot** emit a Track B class for any input — asserted exhaustively in
  `tests/test_iot23_labels.py`, including adversarial label strings.

### `src/features/` — flows to a feature table
- `windowing.py` — groups flows into 300 s device-windows on an absolute
  (epoch-aligned) grid, assigning each flow to the window of its start time.
  Emits quality flags for thin windows rather than dropping them silently.
- `derive.py` — computes the 16 features per window. Not-measurable stays `NaN`,
  never imputed to `0.0`.

### `src/models/` — the detectors
- `heuristic.py` — a transparent rule detector; NaN-tolerant (reads a missing
  feature as "no evidence") and able to `explain()` which rules fired.
- `trees.py` — RandomForest and XGBoost wrappers.
- `registry.py` — `by_name`, `positive_score`, and the canonical name list, so
  callers pick a detector by string and always read its positive-class score the
  same way.

### `src/evaluate/` — the protocol (see `docs/evaluation-protocol.md`)
- `splits.py` — grouped / temporal / random splits with a **locked** test set.
- `thresholds.py` — calibrate every detector to the same FPR budget on
  validation; score on test at that threshold; report the drift.
- `metrics.py` — `score_at_threshold` and friends.
- `bootstrap.py` — confidence intervals that resample by **group (device)**, not
  by row, under a grouped split.
- `experiment.py` — the headline: `run_incremental`, `run_model_comparison`,
  `run_incremental_multiseed`, `run_drop_one`, `run_lab_only_sensitivity`.
- `explain.py` — permutation importance (the reported kind); gain importance is
  contrast-only.
- `cross_track.py` — the one sanctioned crossing.

### `src/reports/` — dicts to artefacts (see `src/reports/__init__.py`)
- `tables.py` — result dicts to provenance-headed CSVs in `results/tables/`.
- `figures.py` — result dicts to PNGs in `results/figures/` (headless Agg
  backend), each with a provenance caption.
- `generate_docs.py` — generates `docs/feature-catalogue.md` **from the schema**,
  so the doc's availability counts cannot drift from the code.

### `src/services/` — offline detection
- `score.py` — a batch function over CSVs with a real abstention channel
  (`MALICIOUS` / `BENIGN` / `ABSTAIN`). No network layer, by design
  (`docs/deployment-guide.md`).

## Cross-cutting design decisions

- **Two tracks, never pooled.** The most consequential decision; it shapes the
  filenames, the label vocabularies, and the split guard. See
  `docs/data-provenance.md` and `docs/limitations.md` (L1, L2).
- **`NaN` means not-measurable, never zero.** Zero is a measurement; absence is
  not. Trees abstain on `NaN`; the heuristic reads it as no evidence.
- **Abstention is a first-class output.** There is no "unknown" class to predict
  (L3).
- **Provenance is attached at the artefact boundary.** A number cannot leave the
  pipeline as a bare CSV cell; it leaves under a banner (`docs/paper-results-policy.md`).
- **Importing a module has no filesystem side effects.** Directory creation is in
  `ensure_dirs()`, called by entry points, not at import time.

## Where to look first

| To understand… | Start at |
|---|---|
| what a feature is | `src/schema/columns.py`, `docs/feature-catalogue.md` |
| why mock, not real | `docs/limitations.md` L1, `docs/data-provenance.md` |
| how models are compared fairly | `src/evaluate/thresholds.py`, `docs/evaluation-protocol.md` |
| the headline result shape | `src/evaluate/experiment.py::run_incremental` |
| how a number is allowed to be reported | `docs/paper-results-policy.md` |
| what the project will never do | `docs/ethics-and-containment.md` |
