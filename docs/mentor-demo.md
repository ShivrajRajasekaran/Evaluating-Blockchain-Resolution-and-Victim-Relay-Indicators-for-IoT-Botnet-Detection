# Mentor demo

*Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT
Botnet Detection*

A ten-minute walkthrough for a supervisor: what to run, what to look at, and what
to say about each artefact. It is designed so the honesty of the project is the
thing that shows — the two-track separation, the provenance banners, and the null
result reported as found.

Everything here is **offline**. Nothing contacts a network, a device, a
blockchain, or any C2 infrastructure (`docs/ethics-and-containment.md`).

---

## 0. Environment (once)

The project runs in the Anaconda environment **`shiva`**:

```bash
conda activate shiva
```

All commands below are run from the repository root (`Entreprise/`).

## 1. The Streamlit prototype (optional, the visual hook)

The `prototype/` app is a self-contained demo and is preserved untouched. If you
want a visual opener, run it per its own README. The rigorous pipeline is the
subject of the rest of this walkthrough — the prototype is illustrative, the
`src/` pipeline is what the paper rests on.

## 2. Generate the Track B data (or note it exists)

Track B is locally generated synthetic metadata — it sends nothing:

```bash
python -m src.ingest.mock_generator
```

This writes `data/processed/track_b_mock_observations.csv`. (It may already be
present; the generator is deterministic under its seed.) Good talking point: this
is *numeric feature metadata*, not emulated traffic — see the module's own
"WHAT THIS IS NOT" header.

## 3. Run the whole experiment pipeline

```bash
python scripts/run_pipeline.py --fast
```

`--fast` uses smaller forests and fewer bootstraps for a live demo; drop it for
the full run. Watch the six numbered stages, then the **HEADLINE** block it
prints at the end — the single-seed and multi-seed readings of the research
question. It ends with the SYNTHETIC provenance note, which is the point to
pause on: *these are synthetic numbers, not a real-world detection rate.*

Artefacts land in:

- `results/tables/` — CSVs, each opening with a `#` provenance banner;
- `results/figures/` — PNGs, each with a provenance caption;
- `results/reports/` — the raw result dicts as JSON, for exact reproduction.

## 4. Look at an artefact — and its banner

Open `results/tables/incremental_value.csv`. The first lines begin with `#`:
they name the metric, the FPR budget, the **verdict**, and carry the
`SYNTHETIC (Track B)` disclaimer verbatim. Below that is one row per feature set,
with the recall gain of each novel-group set over base and whether its confidence
interval excludes zero.

**The talking point:** if `distinguishable_gain` is `False` across the augmented
sets, the novel groups added no distinguishable value on Track B — and that is
reported plainly, not tuned away. This is the study's headline finding, and its
honesty is the contribution. See `docs/paper-results-policy.md` §2.

## 5. Show the detector abstaining

The offline service returns `MALICIOUS` / `BENIGN` / **`ABSTAIN`**:

```bash
python -m src.services.score \
    --train data/processed/track_b_mock_observations.csv \
    --score data/processed/track_b_mock_observations.csv \
    --out   results/reports/demo_decisions.csv
```

The printed summary shows the abstain breakdown by reason
(`missing_features`, `low_confidence`, `schema_invalid`). Talking point: there is
no "unknown" class — a not-measurable feature makes the detector *decline* rather
than guess, which keeps the miss rate honest (`docs/deployment-guide.md`,
`docs/limitations.md` L3).

## 6. Show the test suite

```bash
python -m unittest discover -s tests -v
```

Point out `tests/test_iot23_labels.py` (proves an IoT-23 label can never become a
blockchain/relay class) and `tests/test_reports.py` (proves every table carries
the correct provenance banner). The tests encode the honesty rules, so a future
edit that broke them would fail loudly.

## 7. What to say about Track A (IoT-23)

If asked "where is the real-data result?": IoT-23 predates blockchain-anchored
C2 and contains no instance of the phenomenon, so it **cannot** test the thesis —
five of sixteen features are unmeasurable on it. Its role is to measure the
**false-positive rate** on real benign traffic and conventional-botnet
separability, via the one sanctioned crossing. The integration steps are in
`docs/iot23-integration-plan.md`; no capture ships with the repo, and none is
downloaded.

---

## The four things this demo is meant to convey

1. **Two tracks, never pooled.** Synthetic tests the thesis; real measures false
   alarms. Pooling them would fabricate a result (`docs/data-provenance.md`).
2. **Provenance travels with every number.** No artefact leaves the pipeline
   without a track disclaimer.
3. **A null result is reported as found.** The generator is not tuned until the
   thesis is confirmed (`docs/paper-results-policy.md`).
4. **The system declines when it cannot know.** Abstention over a fabricated
   "unknown" class.

## If something goes wrong

- **`Track B data not found`** — run step 2 first.
- **Slow run** — use `--fast`, or reduce `seeds.split` / `n_bootstrap` in
  `configs/default.yaml`.
- **A skipped test** — one XGBoost-conditional case skips when the environment
  differs; that is expected, not a failure.
