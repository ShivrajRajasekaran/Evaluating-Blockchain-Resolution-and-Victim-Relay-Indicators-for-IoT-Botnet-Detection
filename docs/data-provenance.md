# Data provenance

*Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT
Botnet Detection*

This document says where every row of data comes from, how the two tracks are
kept apart, and how a number carries its origin with it. Provenance is not
metadata here — it is the difference between a defensible measurement and a
fabricated one.

---

## Two tracks, and why they are never one

| | **Track A** | **Track B** |
|---|---|---|
| Source | IoT-23 (real capture, 2018–2019) | locally generated mock metadata |
| Nature | real benign + conventional botnet traffic | numeric flow/observation *shapes* |
| Classes | `benign_real`, `traditional_c2`, `traditional_botnet_activity` | `benign_mock`, `blockchain_resolution_mock`, `victim_relay_mock`, `combined_mock` |
| Answers | FPR on real benign traffic; conventional-botnet separability | the incremental-value question (the thesis) |
| Files | `data/processed/track_a_iot23_observations.csv` | `data/processed/track_b_mock_observations.csv` |

**They are never pooled into one training set.** Training on real-benign plus
mock-malicious rows would yield a high, meaningless F1: the two row sources differ
in *capture provenance* — TTL distributions, MTU, clock resolution, inter-arrival
quantisation — before they differ in anything behavioural. A loss-minimising
classifier finds the provenance shortcut because it is the cleaner signal, and
then "can you tell a 2018 university capture from a 2026 generator?" gets reported
as "can you detect blockchain C2?". See `docs/limitations.md` L2.

### How the separation is enforced, not just intended

- **Distinct filenames.** `src/config.py` defines `TRACK_A_IOT23_CSV` and
  `TRACK_B_MOCK_CSV` as two paths — "never one … the filenames are the first line
  of defence against pooling the tracks by accident."
- **Disjoint label vocabularies.** `src/schema/columns.py` gives each track its
  own classes; there is no shared malicious label to merge on.
- **A one-way label mapping.** `src/ingest/iot23_labels.py` cannot emit a Track B
  class for *any* IoT-23 label — asserted exhaustively over the label vocabulary
  in `tests/test_iot23_labels.py`, including adversarial strings that literally
  contain `blockchain`, `ENS-Resolution`, or `victim-relay`.
- **A split guard.** `src/evaluate/splits.py` raises if a frame mixes tracks — a
  split silently spanning both is the exact failure the design exists to prevent.

### The one permitted crossing

A Track-B-trained detector may be scored against Track-A **benign** rows to
measure false-alarm rate on real traffic (`src/evaluate/cross_track.py`). Safe
because no Track A label enters training and no Track B label is claimed of a real
row. Nothing else crosses.

## Track A: real IoT-23 capture

IoT-23 is a real, third-party labelled dataset. It is **not** downloaded by this
project — a capture must be placed on disk under the approval process in
`docs/ethics-and-containment.md`, then adapted with `src/ingest/iot23.py` (see
`docs/iot23-integration-plan.md`). Its lightweight distribution ships Zeek
`conn.log.labeled` only — no `dns.log`, `http.log`, `ssl.log`, and no payload —
so **five of the sixteen features are not derivable from it** and are emitted as
`NaN` (`docs/feature-catalogue.md`).

Crucially, IoT-23 predates blockchain-anchored C2 and contains **no** instance of
the phenomenon. Track A therefore cannot test the thesis; it measures false
alarms and conventional-botnet separability. Its labels are the *dataset authors'*
annotations, not independently verified.

## Track B: locally generated mock metadata

Track B is produced by `src/ingest/mock_generator.py`. It generates **numeric
flow/observation metadata** describing the *shapes* of blockchain-resolution and
victim-relay behaviour, for labelling purposes. It **sends no packets and makes
no connections** (`docs/ethics-and-containment.md`). It exists because no public
dataset contains labelled blockchain-resolved C2 traffic, and constructing one
from live malware is prohibited (`docs/limitations.md` L1).

Track B carries a **standing rule against fabrication-by-design**: its class
distributions are not to be widened to manufacture a positive result. The base
groups are deliberately left with strong separators so the incremental test is
hard (`docs/limitations.md` L5, `docs/paper-results-policy.md` §2).

## `unmapped` is a data state, not a class

A window whose flows carry labels the project cannot interpret is `unmapped`. It
is **not** a class any model is trained to predict — that would be training a
classifier on our own annotation coverage. At scoring time, `unmapped` produces an
**abstention** (`docs/deployment-guide.md`). Windows whose flows are *all*
unmapped carry `malicious_fraction = NaN`, not `0.0`, because "no malicious
traffic" is precisely what is unknown (`docs/limitations.md` L3).

## `NaN` never means zero

Throughout the pipeline, a feature that could not be measured is `NaN`, never
imputed to `0.0`. Zero is a measurement ("this happened zero times"); `NaN` is the
absence of one ("this could not be observed"). Many of these features take their
most malicious-looking value at zero, so imputing zero would fabricate evidence.
Trees abstain on `NaN`; the heuristic reads it as "no evidence".

## Provenance travels with the number

Origin is attached at the artefact boundary and cannot be stripped without intent:

- **Tables** (`results/tables/`) begin with a `#`-commented banner carrying the
  track's disclaimer verbatim (`src/reports/tables.py`); read them back with
  `read_table`, which skips the banner.
- **Figures** (`results/figures/`) carry a provenance caption.
- The disclaimer wording is centralised in `src/config.py`
  (`provenance_note()` for Track B, `real_data_note()` for Track A) so no artefact
  can carry a softer wording than another.

The two banners state their limits outright: the Track B note ends "NOT evidence
of real-world detection performance"; the Track A note ends "NOT this project's
thesis." How these numbers may then be described in the paper is governed by
`docs/paper-results-policy.md`.

## Where data lives

| Path | Contents | Written by |
|---|---|---|
| `data/raw/` | untouched inputs (IoT-23 captures) | **nothing** — read-only to the project |
| `data/processed/track_a_iot23_observations.csv` | Track A observations | `src/ingest/iot23.py` |
| `data/processed/track_b_mock_observations.csv` | Track B observations | `src/ingest/mock_generator.py` |
| `results/tables/`, `results/figures/`, `results/reports/` | provenance-headed artefacts | `src/reports/` |
