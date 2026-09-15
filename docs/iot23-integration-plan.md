# IoT-23 integration plan

*Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT
Botnet Detection*

This is the plan for bringing a **real** IoT-23 capture into Track A: what to
obtain, where to put it, how to adapt it, and what it can and cannot be used for
once adapted. It is written so the step can be done later, once — no IoT-23 data
ships with this repository, and none is downloaded by any code path.

> **Status:** `data/raw/` is intentionally **empty**. The adapter and its tests
> run against small synthetic Zeek fixtures. A real capture is added only under
> the approval process in `docs/ethics-and-containment.md`.

---

## What Track A is for (read this first)

IoT-23 was captured in 2018–2019 and **predates blockchain-anchored C2**. It
contains no ENS/SNS resolution and no victim-relay mesh. So Track A does **not**
test this project's thesis, and no number produced from it may be presented as
evidence for it. It answers the other half of the research question:

- what **false-positive rate** do these features produce on real benign IoT
  traffic, and
- can **conventional** botnet behaviour be detected from the base groups alone.

See `docs/data-provenance.md` and `docs/evaluation-protocol.md`.

## Feature availability on IoT-23

IoT-23's lightweight distribution ships Zeek **`conn.log.labeled` only** — no
`dns.log`, `http.log`, `ssl.log`, and no payload. The consequences, derived from
`src/schema/columns.py` and rendered in `docs/feature-catalogue.md`:

- **5 of 16 features are unavailable** (emitted as `NaN`):
  `ens_query_rate`, `resolution_entropy`, `serverlist_pull`,
  `upnp_addportmapping`, `rc4_string_score`.
- **2 features are proxies** (structural analogues, flagged as such):
  `rpc_endpoint_ratio`, `login_burst_count`.
- Both **resolution** and **relay** — the groups the thesis is about — are among
  the unavailable/proxy features. This is *why* the thesis is tested on Track B.
- The per-row missing-feature floor is **6 of 16, not 5**, on any capture without
  resolver traffic (`rpc_endpoint_ratio` becomes `NaN` there too — see
  `docs/limitations.md` L7). The ingest report states the missing count as a
  range, not a single number.

## Steps

### 1. Obtain a capture (manual, approved)
Acquire an IoT-23 scenario's `conn.log.labeled` under the dataset's own licence
and citation terms, and under this project's approval process. Note the scenario
identifier — it is recorded on every derived row for traceability.

### 2. Place it in `data/raw/`
`data/raw/` is read-only to the project's code; a human places the file there.
Nothing in the pipeline writes to it or downloads into it.

### 3. Run the adapter (local, no network)
```bash
python -m src.ingest.iot23 --input data/raw/<scenario>/conn.log.labeled --scenario-id <id>
```
This reads that one local file and writes one local observations CSV. It opens no
socket, resolves no name, and downloads nothing (`src/ingest/iot23.py`).

### 4. What the adapter handles for you
- **Device-relative orientation.** A Zeek `conn.log` is written from the
  connection *originator's* view. The monitored device is the originator of some
  flows and the responder of others, so reading columns as-is would invert
  `updownlink_ratio` and `mean_pkt_size` for every inbound flow — and inbound
  flows are exactly what a victim relay looks like. Every flow is normalised so
  `orig_*` means *device → peer* throughout; which end initiated is preserved in
  the `outbound` column.
- **One unavoidable approximation.** Zeek's `conn_state` has no device-relative
  equivalent (it describes the originator's attempt), so it is **not** swapped.
  Consequently `failed_conn_ratio` is computed over **outbound flows only** and
  is silent about inbound ones — the honest reading (`docs/limitations.md` L6).
  A responder-heavy capture leaves the six outbound-only features near-empty; the
  ingest report surfaces `inbound_flow_fraction` and
  `windows_with_no_outbound_flow` so the reader knows before interpreting them.
- **Exact malformed-line accounting.** `rows_skipped_malformed` reports lines
  with too many fields; truncated lines cannot be silently mislabelled, and the
  count of dropped flows is reported (`docs/limitations.md` L8,
  `src/ingest/zeek.py`).
- **Label safety.** `src/ingest/iot23_labels.py` maps IoT-23 labels to Track A
  classes and can **never** emit a Track B (blockchain/relay) class — enforced by
  test.

### 5. Windowing and validation
The adapter derives 300-second device-windows (`src/features/windowing.py`) and
the 16 features (`src/features/derive.py`), then validates the frame against the
schema before writing. `unmapped` windows are retained as a data state, not a
class (`docs/data-provenance.md`).

### 6. Use in the sanctioned crossing
Once a Track A observations CSV exists, the one permitted crossing can be run —
scoring a Track-B-trained detector against IoT-23 **benign** windows for a
real-benign false-alarm rate:
```bash
python -m src.evaluate.cross_track \
    --track-b data/processed/track_b_mock_observations.csv \
    --iot23-benign data/processed/track_a_iot23_observations.csv
```
Report the FPR **with its coverage**; interpret it as a distribution-shift caveat,
not validation (`docs/paper-results-policy.md` §4).

## What must never happen at integration time

- Never label IoT-23 malicious flows as blockchain C2 or victim relay.
- Never pool Track A rows with Track B rows into one training set.
- Never present any Track A number as evidence for the thesis.
- Never treat IoT-23's labels as independently verified ground truth in the paper
  — attribute them to the dataset authors.
