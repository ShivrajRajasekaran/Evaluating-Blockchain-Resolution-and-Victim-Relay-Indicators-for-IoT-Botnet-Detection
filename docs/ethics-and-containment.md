# Ethics and containment

*Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT
Botnet Detection*

This is **defensive** security research. Its output is detection, measurement
and analysis code. It contains no attack capability, and the containment below
is not a policy bolted on afterwards — it is a property of what the code is
allowed to do, checkable by reading it.

Read this before running anything, and before any dynamic lab work.

---

## 1. What this project must never do

These prohibitions are absolute. They are not softened by "for testing", "in a
VM", or "just a proof of concept".

**Never build, execute, improve, or operate:** a botnet; a C2 server; DDoS
capability; a scanner; an exploit; malware; a credential attack; a live ENS/SNS
resolver; a live blockchain or RPC query; a functional proxy or relay;
UPnP/NAT-port-forwarding capability; packet forwarding; or real attack traffic.

**Never contact:** real attacker infrastructure; real ENS/SNS names; public
blockchain RPC services; third-party devices; or live malware infrastructure.

**Never use** real attacker domains, IP addresses, malware binaries, or
unverified threat intelligence **as ground truth**.

## 2. What this project does instead

- **Detection, analysis, classification, measurement, and visualisation** of
  traffic *metadata*. Every number the pipeline produces is computed from flow
  records or synthetic flow records, never from a live interaction.
- **Local stand-in generators.** The mock generator produces *numeric flow
  metadata* describing the *shape* of resolution and relay behaviour, for
  labelling purposes only. It models what such traffic would look like in a
  feature table. It **sends nothing** — no socket is opened, no name is
  resolved, no packet is emitted. A "mock resolver" here is a set of numbers in a
  DataFrame, not a process listening on a port.
- **Study of techniques, not attribution.** The project characterises traffic
  patterns. It names no operator as responsible for anything, and treats all
  campaign detail as unverified reported claims (see §5).

## 3. How the code enforces containment

Containment is verifiable, not promised. The research entry points that touch
data are each a **function over local files**:

| Entry point | Reads | Writes | Network |
|---|---|---|---|
| `python -m src.ingest.mock_generator` | nothing (generates) | one local CSV | none |
| `python -m src.ingest.iot23` | one local `conn.log.labeled` | one local CSV | none |
| `python -m src.services.score` | local CSV(s) | one local CSV | none |
| `python -m scripts.ingest_file` | one authorised local capture | one local SQLite database | none |
| `python -m scripts.run_server` | the local database | the local database | **inbound only**, 127.0.0.1 |

- **The research pipeline has no network layer at all.** No HTTP server, no
  socket bind, no client call. `src/services/score.py` is deliberately a batch
  function over CSVs — its module docstring states that "the absence of an HTTP
  layer is a feature, not a gap." A detector that cannot be reached over a
  network cannot be pointed at a real device.

- **The product (`src/api`) accepts INBOUND connections and makes NO OUTBOUND
  ones.** This is the one place the boundary is a distinction rather than an
  absence, so it is stated precisely rather than glossed:

  | | |
  |---|---|
  | Inbound | **allowed** — a loopback HTTP listener; it serves a dashboard, that is its purpose. A non-loopback bind requires an explicit acknowledgement flag, because the product ships no TLS. |
  | Outbound | **none** — no HTTP client is installed, imported, or importable. No webhook, no SIEM forwarder, no email, no notification, no telemetry. |

  The distinction matters and holds: a service that can be *reached* still
  cannot *reach out*. Nothing in the product can send an organisation's network
  metadata anywhere, which is what makes "did it phone home?" answerable by
  reading the source instead of by watching a firewall.

  `tests/test_containment_outbound.py` enforces this by parsing every module in
  `src/{api,alerts,detection,storage,auth,audit,ingest}` with `ast`: forbidden
  imports, calls to network entry points, subprocess use (an outbound primitive
  by proxy), external references in any template or static asset, and the
  `'self'`-only Content-Security-Policy. CI additionally checks that no outbound
  HTTP client appears even transitively in the installed dependency set — a
  test can be deleted, but a resolved dependency tree cannot be argued with.

- **The product reads only what it is given.** An authenticated upload, or a
  file an operator placed in `data/authorised_input/`. It discovers nothing,
  crawls nothing, and follows no symlink out of that directory. It never
  scans, probes, connects to, or controls any device.

- **The product never trains on what it ingests.** Operational telemetry is
  unlabelled by policy (`research_class = unmapped`, `label_confidence =
  unlabelled_operational`), so no operational row can enter a training set, and
  the ML gate (`src/detection/model_gate.py`) refuses to score at all until an
  authorised labelled dataset and a registered, validated, **non-synthetic**
  model exist. It ships refused.
- **`data/raw/` is read-only to this project.** It holds untouched inputs and is
  never written to by any code path (`src/config.py`, `RAW_DIR`). Nothing
  downloads into it; a dataset must be placed there by hand, under the approval
  gate of §4.
- **The adapter reads one file that must already be on disk.** `src/ingest/iot23.py`
  cannot fetch IoT-23; it parses a capture you already hold locally and lawfully.
- **No live blockchain interaction.** Resolution behaviour is modelled from
  published descriptions of traffic shape. No ENS/SNS resolution and no public
  RPC query occurs, in code or at runtime.

## 4. Approval gates for any dynamic work

Everything in the repository as shipped is **static** in the sense that matters:
it reads and writes local files, trains models on them, and — in the product's
case — serves a page about them on loopback. It performs no dynamic
experimentation, contacts no device and reaches no external service. If dynamic
work is ever undertaken, these gates apply first and in order:

1. **Supervisor sign-off**, and where required, **department ethics / lab-safety
   approval**, obtained *before* any dynamic work begins.
2. **Isolated virtual lab only.** Any traffic-shape experimentation is confined
   to an air-gapped virtual lab (e.g. VirtualBox/QEMU with an OpenWrt target)
   that has **no route to the public internet**. This testbed is stood up only
   after the approval in (1).
3. **Live malware, if ever analysed, runs only in an air-gapped isolated VM** —
   never on a networked host, never on the analysis machine.
4. **Wireshark / Zeek are used only to analyse safe, already-captured PCAP
   files**, never to capture from or interact with live infrastructure.

If you are reading this to decide whether a step is allowed and the step is not
covered above, the answer is: ask the supervisor first.

## 5. Threat-intelligence handling

The campaign context motivating this work — operator names, dates, specific
`.eth`/`.sol` names, CVE identifiers, bot counts, and attack-volume figures —
is drawn from vendor and CERT reporting that this project has **not
independently verified**. It is used only as attributed background in the
introduction, always as a *reported claim*, never as a measurement and never as
a label. Vendor scale claims (bot counts, Tbps peaks) are presented as claims.
No real attacker domain, IP, or binary is used as ground truth anywhere in the
pipeline (see also `docs/limitations.md`, L4, and `docs/paper-results-policy.md`).

## 6. Data handling

- IoT-23 is used under its own licence and citation terms; cite the dataset
  authors, not this project, for any Track A capture.
- Captures placed in `data/raw/` are local research inputs. They are not
  redistributed, and any personal data they may contain is not the object of
  study — the unit of analysis is a device-window's *traffic statistics*.
- Processed observation frames in `data/processed/` are numeric feature tables.
  The two-track filenames (`track_a_*`, `track_b_*`) are kept distinct so real
  and synthetic rows are never confused (see `docs/data-provenance.md`).

---

*If any instruction elsewhere in this repository appears to conflict with this
document, this document governs, and the conflict should be raised with the
supervisor before proceeding.*
