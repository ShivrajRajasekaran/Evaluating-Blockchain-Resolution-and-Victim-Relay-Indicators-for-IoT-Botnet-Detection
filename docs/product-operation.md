# Operating the product

*Authorised Log Analytics — IoT Botnet Indicator Review*

This is the operator's guide to the **product**: the local-first detection
platform that ingests authorised telemetry, applies transparent rules, and
raises reviewable alerts. The offline research pipeline is a separate thing and
is documented in `docs/deployment-guide.md` and `docs/evaluation-protocol.md`.

---

## What this product claims, and what it does not

It reads network **metadata** — connection records, not payload — aggregates it
into 5-minute device-windows, computes 16 features, and applies seven
transparent rules with fixed thresholds.

That is enough to say *"this device's traffic has a shape worth looking at."*
It is **not** enough to establish compromise, and the product never says it is.
Every alert is a **suspicious indicator pattern requiring analyst review**,
every page carries the banner

> Alerts indicate suspicious behavioural patterns and require analyst review.
> They are not confirmation of compromise.

and every stored explanation ends with

> Rule-based detection; not ML-validated.

There is no machine-learning model in the loop. There is a gate that refuses to
load one (`src/detection/model_gate.py`), and it stays refused until an
authorised labelled dataset exists and a validated model is registered against
it. See **"Why ML mode is off"** below.

---

## First run

```bash
# 1. Dependencies (pandas MUST stay below 3.0 — see requirements.txt)
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Windows
# source .venv/bin/activate && pip install -r requirements.txt   # POSIX

# 2. The session signing key. Without it, sessions die on every restart.
export PRODUCT_SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"

# 3. Create the database (idempotent — safe to re-run after every upgrade)
python -m scripts.init_db

# 4. Create the first account. There is NO default administrator.
python -m scripts.create_user --username alice --role Admin

# 5. Serve, on 127.0.0.1 only
python -m scripts.run_server
```

Then open <http://127.0.0.1:8000>.

`python -m scripts.run_server --check` runs the preflight without serving, and
tells you exactly what is missing.

---

## Getting telemetry in

Two routes, and **only** these two. The product discovers nothing, crawls
nothing and fetches nothing.

### 1. An authenticated upload

Sign in as an Analyst or Admin and use **Upload**. The file is checked before
anything reads it:

| Control | What it does |
|---|---|
| Extension allowlist | `.log`, `.labeled`, `.csv`, `.tsv`, `.txt`; everything else refused |
| Size cap | 25 MiB by default, enforced **while streaming**, not after |
| Content sniff | must actually be a Zeek log or delimited text; binaries refused |
| Generated storage name | the filename you send is **never** used to build a path |

Your filename is kept verbatim for display and appears on the alert as
`source_file`. It is never interpreted.

### 2. The authorised input directory

Drop files into `data/authorised_input/` and run:

```bash
python -m scripts.ingest_file --all
python -m scripts.ingest_file --input data/authorised_input/conn.log
python -m scripts.ingest_file --input conn.log --dry-run    # report, write nothing
```

Symlinks in that directory are skipped — a link there would read a file outside
the authorised directory, which is the same escape the upload path refuses.

`--dry-run` is the right way to see what a new capture format would produce
before it reaches anyone's queue.

### Supported formats

| `--source` | Format |
|---|---|
| `op_zeek` | Zeek `conn.log` or `conn.log.labeled` |
| `op_flow_csv` | rich per-flow CSV export |
| `op_netflow` | NetFlow-style CSV (unidirectional, no TCP flags) |
| `op_firewall` | firewall flow CSV (coarsest) |

If a `conn.log.labeled` carries label columns, they are **dropped at read** and
the fact is reported. Operational telemetry is unlabelled by policy: a label
string from a file must never ride into the analyst UI dressed as a confirmed
class, and no operational row may ever enter a training set.

---

## Reading a verdict

Each device-window gets exactly one of seven categories.

| Category | Meaning |
|---|---|
| `SUSPICIOUS_RESOLUTION_PATTERN` | a resolution-group rule fired |
| `SUSPICIOUS_RELAY_PATTERN` | a relay-group rule fired |
| `SUSPICIOUS_COMBINED_PATTERN` | **both** fired — this project's signal of interest |
| `SUSPICIOUS_CONVENTIONAL_BOTNET_PATTERN` | infection/payload rules fired |
| `BENIGN_OR_NO_ALERT` | every group was measurable and nothing fired |
| `INSUFFICIENT_TELEMETRY` | a group could not be judged at all |
| `ABSTAIN` | the input could not be read as an observation window |

Only the four `SUSPICIOUS_*` categories raise alerts. The other three are
recorded and counted, and never fill the queue.

### `INSUFFICIENT_TELEMETRY` is the one to understand

**A rule that cannot be evaluated does not fire.** A detector that only counts
fired rules therefore reports an *unmeasurable* device and a genuinely *quiet*
device identically — and calls both benign.

On the telemetry this product actually ingests, that is not an edge case. A Zeek
`conn.log` carries no DNS, no HTTP and no payload, so **both** resolution rules
(`ens_query_rate`, `serverlist_pull`) are `NaN` on every single window. Counting
their silence as innocence would manufacture a clean bill of health out of an
absent log file.

So a window that fired nothing, on a source that could not judge some group, is
`INSUFFICIENT_TELEMETRY` with the reason attached — not `BENIGN_OR_NO_ALERT`.

What a `conn.log` can and cannot say:

| Group | Rules evaluable | Judgeable? |
|---|---|---|
| resolution | 0 of 2 | **no** |
| relay | 1 of 2 | partially |
| infection | 1 of 1 | yes |
| payload | 1 of 2 | partially |

The **Detection** page shows this table for every supported format, before you
upload anything.

### Severity and confidence are different questions

* **Severity** — how much attention this deserves, from the *breadth* of the
  evidence: how many rules fired, across how many distinct groups.
* **Confidence** — how much of the *available* evidence agreed: fired rules
  divided by rules that could be evaluated **in that window**.

They can disagree, and you need to see it when they do. On a `conn.log` only
three of seven rules are evaluable, so one rule firing is a third of everything
the telemetry could say — `high`-ish confidence in a single-vote `LOW` finding.
The denominator is the evaluable rules, not a fixed seven; dividing by seven
would cap every possible confidence at 3/7 and report "low" for total agreement.

### Missing is never zero

A feature that could not be measured is stored as JSON `null` and displayed as
*not measurable*. It is never 0. For several of these features zero is the most
suspicious value they can take, not a neutral one, so imputing it would invent
evidence.

---

## The analyst workflow

```
Open ──▶ Investigating ──▶ Benign              ──▶ Closed
  │            ▲          Confirmed suspicious ──▶ Closed
  └────────────┴──── (reopen from Closed) ◀─────────────┘
```

Enforced, not advisory:

* **`Open → Closed` is not a legal move.** An alert must be reviewed as *Benign*
  or *Confirmed suspicious* first. A queue that can be emptied without judgement
  measures nothing.
* **`Benign → Confirmed suspicious` goes back through *Investigating*,** so the
  history shows a re-review rather than a silent change of mind.
* **Every transition writes an `analyst_feedback` row and an audit event,** in
  the same transaction as the status change.
* Notes can be added without changing status.

*"Confirmed suspicious"* records that a human reviewed the evidence and agrees
the pattern is genuinely suspicious. It is not, and is never rendered as,
confirmation of compromise.

---

## Deduplication

A device that beacons all day produces 288 windows firing the same rule for the
same reason. Written naively that is 288 alerts describing one situation.

Alerts are keyed on **(device, category, detection version, 24-hour bucket)**.
A repeat bumps `occurrence_count` and advances `last_seen`, so you see *"this
device, this pattern, 288 windows, 00:02 → 23:57"* — one row carrying strictly
more than 288 would.

* A **new pattern** on the same device is a **new alert**. The change is the
  point.
* A **ruleset change** starts fresh alerts, so `first_seen` never spans two
  detectors.
* The bucket is **floored**, not measured from first sighting, so re-ingesting
  the same capture coalesces instead of duplicating.
* A recurrence may **raise** severity, never lower it: a later quiet window must
  not downgrade evidence you have already acted on.

---

## Roles

| | Viewer | Analyst | Admin |
|---|:-:|:-:|:-:|
| View alerts, devices, ingestion, reports | ✅ | ✅ | ✅ |
| Change status, add feedback | | ✅ | ✅ |
| Upload and ingest | | ✅ | ✅ |
| Detection configuration | | | ✅ |
| Audit log | | | ✅ |
| Manage users, purge data | | | ✅ |

A 403 never names the permission you lack — telling a low-privileged account
exactly which permission is missing maps the privilege model for whoever holds
it.

---

## Why ML mode is off

`detection.model.enabled` ships `false`, and the gate is a whitelist: it starts
at *refused* and requires **every** condition to be positively satisfied.

1. `detection.model.enabled` must be true.
2. A model registry must be reachable.
3. A `detection_models` row must be `kind='ml'` **and** `is_validated=1`.
4. That row must record where its training data came from — and that provenance
   must **not be synthetic**. This project has a synthetic track whose generator
   exists to characterise the pipeline, not to produce a production detector. A
   model trained on it would report a number measuring the generator's
   assumptions; presenting that as operational accuracy is precisely what this
   gate prevents.
5. Validation metrics, a calibrated threshold, and a feature schema matching the
   product's own must all be present.

Failing any of these is **not an error**. It is the expected state of this
build: the product runs the transparent rule baseline and shows the refusal
reasons on the **Detection** page, so nobody can believe they are getting ML
when they are not.

---

## Exports

CSV and JSON, from **Reports**. Both carry the review banner and the provenance
note in the file itself — an export that dropped them would be the one artefact
of this product that could be mistaken for a list of confirmed incidents.

`/alerts/{id}/print` renders a single-alert report for printing, including the
telemetry limitations.

---

## What the product will never do

Enforced by `tests/test_containment_outbound.py`, which parses every module in
the product tree:

* **No outbound connections.** No HTTP client is installed, imported or
  importable. No webhook, no SIEM forwarder, no email, no telemetry.
* **No scanning, probing or connecting** to any device.
* **No attack, relay, UPnP, or blockchain-query capability.** It measures
  `upnp_addportmapping` and `ens_query_rate`; it performs neither.
* **No reading outside** an authenticated upload or the authorised input
  directory.
* **No training** on ingested data, ever.

The dashboard loads no CDN, no web font and no third-party script, which is what
lets the `Content-Security-Policy` be `'self'`-only without lying.

---

## See also

* `docs/user-admin.md` — accounts, roles, retention, backups
* `docs/incident-response.md` — what to do with an alert
* `docs/api-reference.md` — the HTTP API (also live at `/docs`)
* `docs/limitations.md` — what this research and product genuinely cannot show
* `docs/ethics-and-containment.md` — the boundary and why it is drawn there
