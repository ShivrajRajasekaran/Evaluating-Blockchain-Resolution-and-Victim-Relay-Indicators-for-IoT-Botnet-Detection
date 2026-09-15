# Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT Botnet Detection

Final-year B.E. project (CSE — Internet of Things), Saveetha Engineering College.
**Defensive security research. Measurement only.**

## Research question

Do blockchain-resolution and victim-relay feature groups improve IoT botnet detection
beyond conventional infection and payload features, while controlling the false-positive
rate?

The question is posed as an **evaluation, not an assertion**. If the two novel groups add
no distinguishable value once conventional features are present, that null result is the
finding and is reported as such.

## Scope boundary (non-negotiable)

This project **reads network metadata and classifies shapes**. It does not build, operate,
test or simulate: botnets, C2 servers, DDoS capability, scanners, exploits, malware,
functional relays or proxies, UPnP port mapping, live ENS/SNS resolution, or blockchain RPC
querying. No real attacker infrastructure is contacted. No device is scanned or probed.
Indicators of compromise appear in this repository only as inert text in documentation.

## Layout

| Path | Purpose |
|---|---|
| `src/schema/` | Single source of truth for every column; feature availability per source |
| `src/features/` | Device-window assignment and feature derivation |
| `src/ingest/` | Zeek and CSV adapters; normalisation to the observation schema |
| `src/models/` | Transparent rule baseline, Random Forest, XGBoost |
| `src/evaluate/` | Splits, threshold calibration, metrics, bootstrap, incremental-value study |
| `src/reports/` | Table and figure generation |
| `src/storage/`, `src/auth/`, `src/audit/` | Persistence, identity and audit trail (built, not extended) |
| `tests/` | Full unittest suite |
| `docs/` | Build methodology and the Phase I report |
| `references/` | Threat-intelligence source documents |
| `data/raw/` | Authorised input captures (empty until a dataset is obtained) |

## Environment

```
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m unittest discover -s tests
```

## Data policy

Real and synthetic observations are never pooled. Features a telemetry source cannot supply
are recorded as **missing**, never substituted with zero — zero is frequently the most
suspicious value such a feature can take, and substituting it would fabricate evidence.
Where evidence is insufficient the detector abstains rather than assigning a class.

Results derived from laboratory-generated traffic are reported as such and are never
presented as operational detection performance.

## Status

Rebuild in progress. See `docs/build-methodology.md` for the full plan and its rationale.
