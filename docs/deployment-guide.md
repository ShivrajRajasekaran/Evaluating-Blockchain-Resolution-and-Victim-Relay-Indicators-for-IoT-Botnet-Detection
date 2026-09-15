# Deployment guide

*Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT
Botnet Detection*

The "deployment" this project ships is deliberately modest: an **offline batch
detector** that reads a local CSV of device-window observations and writes a
local CSV of decisions. That modesty is the point. A detector with no network
layer cannot be pointed at a live device, which is exactly the containment
guarantee `docs/ethics-and-containment.md` requires.

This guide covers how to run it, what its decisions mean, and how to read its
abstentions.

---

## What it is (and is not)

`src/services/score.py` is **a function over files**. It loads or trains a
detector, reads observations, and writes decisions. It **opens no socket, binds
no port, starts no server, resolves no name, and forwards no packet.** There is
no streaming API, and adding one is out of scope by design — the module docstring
states plainly that "the absence of an HTTP layer is a feature, not a gap."

If you need to classify more rows than `service.max_rows_per_request`, split the
batch. The service refuses an oversized request rather than quietly streaming it,
because there is no server to stream to.

## The decision set: {MALICIOUS, BENIGN, ABSTAIN}

Every input row gets exactly one decision. `ABSTAIN` is a **first-class output**,
not a low-confidence `MALICIOUS`, and it fires for three distinct, recorded
reasons:

| `reason` | Meaning | Config knob |
|---|---|---|
| `schema_invalid` | the input could not be trusted as a valid observation (a required feature column is absent) | `service.abstain_on_schema_failure` |
| `missing_features` | this row lacks a value the model needs — a `NaN` feature ("not measurable", never imputed to 0) | `service.abstain_on_missing_features` |
| `low_confidence` | the score sits within `service.abstain_below_confidence` of the threshold — too close to commit | `service.abstain_below_confidence` |

There is **no "unknown" class**. `unmapped` is a data state; a model trained to
predict "unknown" would learn the signature of whatever happened to be
unlabelled — a fact about the annotation process, not the traffic. Abstention
keeps that distinction intact (`docs/limitations.md` L3).

**Why abstain instead of guess:** a `NaN` feature is *not measurable*, and most
of these features take their most malicious-looking value at zero — so imputing
zero would fabricate evidence. A tree cannot consume a `NaN` and therefore
abstains on any row with a missing feature; the heuristic can read `NaN` as "no
evidence" and score it, so `abstain_on_missing_features` only changes behaviour
for a NaN-tolerant detector.

## Running it

### Train + score in one call (CLI)
```bash
python -m src.services.score \
    --train data/processed/track_b_mock_observations.csv \
    --score data/processed/observations_to_classify.csv \
    --out   results/reports/decisions.csv \
    --model RandomForest \
    --seed 42
```
The detector trains on the labelled `--train` frame and is **calibrated to
`evaluation.target_fpr`** (the same 1% operating point the experiments use), so
its alarms are comparable to the reported numbers. It then scores `--score`
(labels there are optional and ignored) and writes decisions to `--out`.

The run prints a one-line summary and the provenance note:
```
decisions -> results/reports/decisions.csv
  malicious 12  benign 340  abstain 48 {'missing_features': 41, 'low_confidence': 7}
  provenance: SYNTHETIC (Track B): ...
```

### From Python
```python
from src.schema.validate import read_observations
from src.services.score import DetectionService

svc = DetectionService.from_training_frame(
    read_observations("data/processed/track_b_mock_observations.csv"),
    model_name="RandomForest", seed=42)
summary = svc.score_csv("to_classify.csv", "decisions.csv")
```
The operating point is fixed at construction; scoring never re-tunes it.

## Output columns

One decision row per input row, order preserved:

| Column | Meaning |
|---|---|
| passthrough ids | `observation_id`, `device_id`, `window_start`, `source_dataset` (when present) — so a decision traces back to its exact device-window |
| `decision` | `MALICIOUS` / `BENIGN` / `ABSTAIN` |
| `score` | positive-class score, or `NaN` if unscored (abstained before scoring) |
| `confidence` | distance from the threshold; `NaN` where unscored |
| `threshold` | the calibrated operating point |
| `reason` | blank, or one of the three abstention reasons |
| `explanation` | for `MALICIOUS` rows from the heuristic, the rules that fired; blank otherwise (a tree is not given a fabricated rationale) |

## Reading the results honestly

- **Report abstention volume and reasons.** A recall or precision computed only
  over the rows the service *chose* to score, presented as if it covered all
  traffic, understates the miss rate by exactly the abstained volume. The
  `summarize()` breakdown exists so this is reported, not hidden
  (`docs/paper-results-policy.md` §7).
- **A batch trained on Track B carries the SYNTHETIC provenance note.** Its
  decisions are not real-world detections (`docs/paper-results-policy.md` §1).
- **Schema-invalid input abstains as a whole batch** (when
  `abstain_on_schema_failure` is set), carrying the ids through so an operator can
  see which windows were skipped and why — rather than emitting decisions the
  schema cannot vouch for.

## Configuration

The `service` block in `configs/default.yaml` controls the knobs above
(`max_rows_per_request`, `abstain_on_schema_failure`,
`abstain_on_missing_features`, `abstain_below_confidence`). Changing a knob
changes behaviour, so — like every tunable — it lives in the config file that can
be attached to a result for provenance, not in code (`src/config.py`).

---

# Part two — deploying the product

Everything above describes the **offline research component**: a function over
files, with no network layer at all. That description remains accurate and
unchanged.

This part covers the **product** — the local-first detection platform added on
top of the same pipeline. It does have a network layer, because it serves a
dashboard, so the containment boundary is stated precisely rather than by
absence: it accepts **inbound** connections on a loopback bind, and makes **no
outbound connections of any kind**.

For day-to-day operation see `docs/product-operation.md`; for accounts and data
governance, `docs/user-admin.md`.

## Local deployment (the supported path)

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt          # pandas stays < 3.0

export PRODUCT_SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"

python -m scripts.init_db
python -m scripts.create_user --username alice --role Admin
python -m scripts.run_server                            # http://127.0.0.1:8000
```

`python -m scripts.run_server --check` runs the preflight and exits, reporting
exactly what is missing.

## The bind is the security boundary

On loopback, the operating system is the access control. On `0.0.0.0` it is
whatever sits in front of the port — and by default nothing does, because this
product ships no TLS, no reverse proxy and no IP allowlist.

So a non-loopback host requires `--i-accept-the-risk-of-exposing-this-service`.
Not because the code cannot do it, but because *"I typed `--host 0.0.0.0` so I
could reach it from my laptop"* and *"I have decided to expose this service"*
should not be the same keystroke.

If you do put it behind a TLS terminator, set `auth.cookie_secure: true`.

## Containment, stated precisely

| | |
|---|---|
| Inbound | **allowed** — a loopback HTTP listener, that is the point |
| Outbound | **none** — no HTTP client is installed, imported or importable |
| Device contact | **none** — no scanning, probing, connecting or controlling |
| File access | an authenticated upload, or `data/authorised_input/`. Nothing else |
| Training | never, on ingested data |

`tests/test_containment_outbound.py` enforces this by parsing every module in
`src/{api,alerts,detection,storage,auth,audit,ingest}` with `ast` — imports of
networking modules, calls to their entry points, subprocess use, and external
references in any template or static asset. CI runs it as its own named check,
and separately verifies that no outbound HTTP client appears even transitively
in the installed dependency set.

## Approval-gated actions

Written and reviewed, deliberately **not performed** in this build. Each needs
an explicit decision:

| Action | Why it is gated | To enable |
|---|---|---|
| **Running Docker** | builds and runs a container | `Dockerfile` and `docker-compose.yml` are written and annotated; publish the port as `127.0.0.1:8000:8000`, never `8000:8000` |
| **PostgreSQL** | needs `psycopg2`, a new dependency | repository SQL is already portable; set `storage.postgres.enabled: true` and install the `postgres` extra |
| **PDF export** | needs `reportlab` | reports export CSV, JSON and printable HTML today |
| **`httpx` for tests** | an outbound HTTP client in the tree | `tests/asgi_shim.py` drives the ASGI app directly instead |
| **Vendoring HTMX** | a one-time download | the dashboard uses plain forms plus one first-party script |
| **Enabling ML mode** | needs an authorised labelled dataset | see `src/detection/model_gate.py`; the gate refuses until a validated, non-synthetic model is registered |
| **Exposing a non-loopback bind** | no TLS ships with the product | pass the explicit acknowledgement flag |
| **CI on a remote** | needs a remote and credentials | `.github/workflows/ci.yml` is written, not run |

## Operator commands

| Command | Purpose |
|---|---|
| `python -m scripts.init_db` | create or migrate the database (idempotent) |
| `python -m scripts.init_db --check` | report state, change nothing |
| `python -m scripts.create_user` | create an account; password prompted or from stdin, never an argument |
| `python -m scripts.ingest_file --input F` | ingest one authorised capture |
| `python -m scripts.ingest_file --all` | ingest everything in the authorised input directory |
| `python -m scripts.ingest_file --dry-run` | report what would be raised; write nothing |
| `python -m scripts.run_server` | serve the dashboard on 127.0.0.1 |

## What a fresh deployment does NOT have

No default administrator, no default password, no seeded demonstration data, and
no sample alerts. The queue is empty until an authorised capture is ingested,
and an account exists only because someone created it.
