# Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT Botnet Detection

A **defensive-security** research pipeline. It measures whether two families of
network indicators — *blockchain-resolution* (a bot resolving its C2 through an
ENS/SNS-style name instead of DNS) and *victim-relay* (a compromised device
relaying for the mesh) — add anything to IoT-botnet detection beyond the
conventional infection- and payload-shape features already in the literature.

It builds **no** botnet, C2, scanner, relay, or resolver. Every experiment reads
local CSVs of numeric flow/observation metadata and writes local files. Nothing
here opens a socket, resolves a name, or contacts a device
(`docs/ethics-and-containment.md`).

> A separate Streamlit **prototype** is maintained alongside this repository as
> the visual demo and is preserved untouched. *This* repository (`Entreprise/`)
> is the rigorous analysis pipeline the paper rests on.

---

## The research question

> Do blockchain-resolution and victim-relay indicator groups add measurable
> detection value beyond conventional IoT-botnet features, while maintaining a
> low false-positive rate on real benign IoT traffic?

The question has two halves, and they are answered on **two separate tracks that
are never pooled** (`docs/data-provenance.md`):

- **Track A — real IoT-23 capture.** Establishes the false-positive rate on real
  benign traffic and whether *conventional* botnet behaviour is separable. IoT-23
  predates blockchain-anchored C2 and contains no instance of it, so Track A
  **cannot** test the thesis — five of the sixteen features are not even
  measurable on it (`docs/feature-catalogue.md`). No capture ships with this
  repo, and none is downloaded.
- **Track B — locally generated mock metadata.** Runs the headline
  incremental-value experiment. It is **synthetic**, and every number it produces
  is labelled synthetic.

The only sanctioned crossing is scoring a Track-B-trained detector against IoT-23
**benign** windows, to read a real-benign false-alarm rate. Nothing else crosses.

## The headline finding (stated plainly)

On Track B, **the novel resolution and relay groups add no detection value
distinguishable from sampling noise** beyond the base groups, and this null
result is robust across split seeds. That is the study's headline, and it is
**reported as found** — not tuned away by widening the synthetic class
distributions (`docs/paper-results-policy.md`, `docs/limitations.md` L5). Because
Track B is synthetic, this is a finding *under the generator's assumptions*, not
a real-world detection claim.

## Quickstart

The project runs in the Anaconda environment **`shiva`**. All commands are run
from this repository root.

```bash
conda activate shiva
```

**1 — Generate the Track B data** (local, deterministic, sends nothing):
```bash
python -m src.ingest.mock_generator
```
This writes `data/processed/track_b_mock_observations.csv`.

**2 — Run the whole experiment pipeline** and write every artefact under
`results/`:
```bash
python scripts/run_pipeline.py --fast
```
`--fast` uses smaller forests and fewer bootstraps for a quick demo; drop it for
the paper run. Add `--model XGBoost` to switch detector, or
`--iot23-benign <csv>` to enable the one permitted cross-track check when a Track
A capture exists. Model names are `RandomForest` (default), `XGBoost`,
`Heuristic`.

**3 — Run the test suite** (stdlib `unittest`; pytest is not required):
```bash
python -m unittest discover -s tests -v
```

**4 — Score a batch with the offline detector** (`MALICIOUS` / `BENIGN` /
`ABSTAIN`):
```bash
python -m src.services.score \
    --train data/processed/track_b_mock_observations.csv \
    --score data/processed/track_b_mock_observations.csv \
    --out   results/reports/decisions.csv
```

A ten-minute supervisor walkthrough is in `docs/mentor-demo.md`.

## Repository layout

```
Entreprise/
├─ src/
│  ├─ config.py            paths, config loading, provenance-note wording
│  ├─ schema/              the observation contract
│  │   ├─ columns.py         16 features, 4 groups, per-track class vocabularies
│  │   ├─ validate.py        read_observations(): load + schema-gate a frame
│  │   └─ build.py           assemble a validated observations frame
│  ├─ ingest/
│  │   ├─ mock_generator.py  Track B: numeric mock metadata (no packets)
│  │   ├─ iot23.py           Track A: adapt one local IoT-23 conn.log.labeled
│  │   ├─ zeek.py            tolerant Zeek conn.log reader (malformed-line safe)
│  │   └─ iot23_labels.py    IoT-23 label → Track A class (never a Track B class)
│  ├─ features/
│  │   ├─ windowing.py       300-second device-windows
│  │   └─ derive.py          the 16 features (NaN = not measurable, never 0)
│  ├─ models/
│  │   ├─ heuristic.py       transparent rule-vote detector (NaN-tolerant)
│  │   ├─ trees.py           RandomForest and optional XGBoost
│  │   └─ registry.py        by_name(); the "column 1 is malicious" convention
│  ├─ evaluate/
│  │   ├─ splits.py          grouped / temporal / random splits; track-mix guard
│  │   ├─ thresholds.py      calibrate to an FPR budget, score on locked test
│  │   ├─ metrics.py         recall (headline), precision, F1
│  │   ├─ bootstrap.py       group-level (device) bootstrap CIs
│  │   ├─ experiment.py      the headline incremental-value build-up
│  │   ├─ explain.py         permutation importance
│  │   └─ cross_track.py     the one permitted crossing (real-benign FPR)
│  ├─ reports/
│  │   ├─ tables.py          provenance-headed CSVs; read_table()
│  │   ├─ figures.py         captioned PNGs
│  │   └─ generate_docs.py   regenerates docs/feature-catalogue.md
│  └─ services/
│     └─ score.py            offline batch detector with first-class ABSTAIN
├─ scripts/run_pipeline.py   one command: Track B data → results/ artefacts
├─ tests/                    unittest suite (schema, ingest, features, models,
│                            splits, thresholds, experiment, cross-track,
│                            service, reports, …)
├─ configs/default.yaml      every tunable (attached to a result for provenance)
├─ docs/                     the documentation set (indexed below)
├─ data/
│  ├─ raw/                   IoT-23 captures — read-only, empty, never downloaded
│  └─ processed/             generated observations CSVs
└─ results/                  tables/ figures/ reports/ — provenance-headed
```

## The 16 features, at a glance

Four groups; the unit of analysis is **one device over one 300-second window**.

| Group | Role | Features |
|---|---|---|
| **infection** | base (conventional) | `login_burst_count`, `scan_rate`, `distinct_dst_ports`, `failed_conn_ratio` |
| **payload** | base (conventional) | `beacon_interval`, `beacon_jitter`, `rc4_string_score`, `mean_pkt_size` |
| **resolution** | **novel — on trial** | `ens_query_rate`, `rpc_endpoint_ratio`, `resolution_entropy`, `serverlist_pull` |
| **relay** | **novel — on trial** | `bidir_flow_duration`, `flow_fanout`, `upnp_addportmapping`, `updownlink_ratio` |

The experiment asks whether **resolution + relay** add anything on top of
**infection + payload**. The full definitions, ranges, and IoT-23 availability
are generated into `docs/feature-catalogue.md`.

## Documentation

| Document | What it covers |
|---|---|
| `docs/architecture.md` | data-flow diagram and package-by-package map |
| `docs/data-provenance.md` | the two tracks, how the separation is enforced, `NaN` vs `0` |
| `docs/evaluation-protocol.md` | device-window unit, splits, FPR-budget calibration, group bootstrap |
| `docs/feature-catalogue.md` | *(generated)* the 16 features and their IoT-23 availability |
| `docs/iot23-integration-plan.md` | how to bring a real IoT-23 capture into Track A |
| `docs/deployment-guide.md` | the offline detector's `ABSTAIN` decision, **and** deploying the product |
| `docs/paper-results-policy.md` | how each number may (and may not) be described in the paper |
| `docs/ethics-and-containment.md` | the prohibitions, approval gates, and containment proof |
| `docs/limitations.md` | L1–L9: what this design cannot claim, and why |
| `docs/mentor-demo.md` | a ten-minute supervisor walkthrough |

**The product** (see below):

| Document | What it covers |
|---|---|
| `docs/product-operation.md` | verdict categories, coverage gating, severity, dedup, the workflow |
| `docs/user-admin.md` | accounts, roles, pseudonymisation, retention, upgrades |
| `docs/incident-response.md` | the analyst playbook for a queued alert |
| `docs/api-reference.md` | the HTTP API — also served live at `/docs` |
| `docs/backup-restore.md` | what to back up, how, and what a restore costs |

## The product: Authorised Log Analytics

Built on the same pipeline, a **local-first defensive detection platform**:
authorised telemetry in, explainable review alerts out.

```bash
export PRODUCT_SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python -m scripts.init_db
python -m scripts.create_user --username alice --role Admin
python -m scripts.run_server                 # http://127.0.0.1:8000
```

It ingests Zeek `conn.log`, flow CSV, NetFlow CSV or firewall CSV; normalises to
device-windows; applies the same seven transparent rules the research baseline
votes on; and raises deduplicated, evidence-backed alerts behind
authentication, RBAC and an append-only audit trail.

**The three things it refuses to do are the design:**

1. **It never claims a compromise.** Every alert is a *suspicious indicator
   pattern requiring analyst review*, every page carries that banner verbatim,
   and every stored explanation ends with *"Rule-based detection; not
   ML-validated."*
2. **It never calls "unmeasurable" benign.** A Zeek `conn.log` carries no DNS or
   payload, so both resolution rules are `NaN` on every window. A quiet window
   on a source that cannot see the behaviour yields `INSUFFICIENT_TELEMETRY`
   with the reason attached — not `BENIGN_OR_NO_ALERT`. Missing is never zero.
3. **It never trains on what it ingests.** Operational telemetry is unlabelled
   by policy (`research_class = unmapped`), and the ML gate refuses to score
   until an authorised labelled dataset and a registered, validated,
   **non-synthetic** model exist. It ships refused.

Containment: it accepts **inbound** connections on a loopback bind and makes
**no outbound connections of any kind** — no HTTP client is installed, imported
or importable, and `tests/test_containment_outbound.py` parses every module to
keep it that way.

Start at `docs/product-operation.md`.

## Four things this project is built to guarantee

1. **Two tracks, never pooled.** Synthetic tests the thesis; real measures false
   alarms. Pooling them would fabricate a result — the split guard in
   `src/evaluate/splits.py` raises rather than allow it.
2. **Provenance travels with every number.** No table or figure leaves the
   pipeline without its `SYNTHETIC (Track B)` / real-capture banner.
3. **A null result is reported as found.** The generator carries a standing rule
   against widening class separation to manufacture a positive
   (`src/ingest/mock_generator.py`, `docs/paper-results-policy.md`).
4. **The detector declines when it cannot know.** `ABSTAIN` is a first-class
   output over a `NaN` (not-measurable) feature — there is no fabricated
   "unknown" class (`docs/deployment-guide.md`).

## What does not ship here

- No botnet, C2, scanner, exploit, relay, resolver, or any functional attack
  capability — and none is built by any code path (`docs/ethics-and-containment.md`).
- No IoT-23 data. `data/raw/` is intentionally empty; a capture is added by hand
  under the approval process, never downloaded.
- No real attacker domains, IP addresses, malware, or unverified threat
  intelligence used as ground truth.

## Environment

A project-local virtual environment, created from the pinned
`requirements.txt`:

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # POSIX
```

`numpy`, `pandas`, `scikit-learn`, `matplotlib` (Agg backend) and `pyyaml` for
the research pipeline; `starlette`, `uvicorn`, `jinja2`, `itsdangerous` and
`python-multipart` for the product. Nothing else — no FastAPI, no ORM, no auth
framework, and deliberately **no HTTP client** (see `requirements.txt` for the
annotated reasoning on each omission).

**`pandas` is pinned below 3.0.** pandas 3.0 changes timestamp flooring that
`src/features/windowing.py` depends on for the fixed 5-minute window grid;
upgrading is a deliberate migration, not a version bump. CI checks it.

`xgboost` is optional — the model registry omits it silently when the library is
missing, so a machine without it still produces a complete Heuristic +
RandomForest comparison (`src/models/registry.py`).

Tests run on the standard-library `unittest`; pytest is not required:

```bash
python -m unittest discover -s tests -t .
```
