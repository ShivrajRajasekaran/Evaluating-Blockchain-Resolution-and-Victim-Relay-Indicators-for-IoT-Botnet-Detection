# Limitations

*Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT
Botnet Detection*

This document is written to be read **before** the results, not after. Every
limitation here is one that changes how a number in `results/` should be
interpreted. Nothing in it is a disclaimer added for form's sake.

The ordering is by severity: L1–L4 constrain what the project can claim at all.
L5–L9 are measurement limitations that qualify individual features or counts.

---

## L1. The primary experiment runs on mock data, and cannot be otherwise

The central research question asks whether **blockchain-resolution** and
**victim-relay** indicator groups add detection value beyond conventional
IoT-botnet features. That question is answered in this project on **synthetic
(mock) data only** — Track B.

The reason is structural, not a matter of effort or budget. IoT-23, the real
labelled dataset used here, was captured in 2018–2019 and predates
blockchain-anchored C2. Its captures contain **no instance of the phenomenon**.
Five of the sixteen features are therefore not merely unmeasured in Track A, they
are unmeasurable:

    ens_query_rate, resolution_entropy, serverlist_pull,
    upnp_addportmapping, rc4_string_score

No public dataset known to this project contains labelled blockchain-resolved C2
traffic. Constructing one would require capturing live malware C2, which
§ *Ethics and containment* prohibits.

**What this means for the reader.** The incremental-value result is a statement
about a *generative model* of the phenomenon — about whether these indicator
groups are separable *given the traffic shapes this project asserts they
produce*. It is evidence that the indicators are worth instrumenting for. It is
**not** a measured real-world detection rate, and must never be reported as one.
See `docs/paper-results-policy.md`.

## L2. The two tracks are never pooled, because pooling them would fabricate a result

| | Track A | Track B |
|---|---|---|
| Source | IoT-23 (real capture) | locally generated mock metadata |
| Classes | `benign_real`, `traditional_c2`, `traditional_botnet_activity` | `benign_mock`, `blockchain_resolution_mock`, `victim_relay_mock`, `combined_mock` |
| Answers | false-positive rate on real benign IoT traffic; conventional-botnet separability | the incremental-value question |

Training one model on *real benign* plus *mock malicious* rows would produce a
very high F1 and that F1 would be meaningless. The two sets of rows differ in
**capture provenance** — TTL distributions, MTU, clock resolution, inter-arrival
quantisation — before they differ in anything behavioural. A classifier
minimising loss will find the provenance shortcut, because it is the cleaner
signal. The reported score would then measure *"can you tell a 2018 university
capture from a 2026 generator?"* and would report it as *"can you detect
blockchain C2?"*.

The label spaces are kept disjoint in `src/schema/columns.py` so that this
mistake is not merely discouraged but unrepresentable. The mapping in
`src/ingest/iot23_labels.py` cannot emit a Track B class for **any** IoT-23
label, and `tests/test_iot23_labels.py` asserts that exhaustively over the label
vocabulary — including the adversarial cases where the label string literally
contains `blockchain`, `ENS-Resolution` or `victim-relay`.

**The one permitted crossing** is scoring a Track-B-trained detector against
Track A *benign* rows to measure false-alarm rate on real traffic. That direction
is safe because no Track A label enters training and no Track B label is claimed
of a real row.

## L3. `unmapped` is a data state, not a predictable class

A window whose flows carry labels this project cannot interpret is recorded as
`unmapped`. This is **not** a class the models are trained to predict. Training
on it would be training a classifier to predict *our own annotation coverage*.

At scoring time, `unmapped` input produces an **abstention** — the detector
declines rather than guessing. A deployment that silently scored unmapped
windows as benign would understate its own miss rate by exactly the volume of
traffic it could not read.

Windows whose flows are *all* unmapped carry `malicious_fraction = NaN`, not
`0.0`. Zero would assert "this window contained no malicious traffic", which is
precisely what is unknown.

## L4. Threat-intelligence context is unverified and is not ground truth

The campaign details motivating this work — operator names, dates, specific
`.eth`/`.sol` names, CVE identifiers, bot counts, and attack-volume figures —
come from vendor and CERT reporting that this project has **not independently
verified**. They appear in the introduction as *reported claims*, attributed,
and never as measurements.

No real attacker domain, IP address, or malware binary is used as a label
anywhere in the pipeline. Vendor scale claims (bot counts, Tbps peaks) are
presented as claims throughout. The project studies **techniques, not
attribution**, and names no operator as responsible for anything.

---

## L5. Two base-group features are near-separators in the mock data

In Track B mock data:

| Feature | Group | AUC |
|---|---|---|
| `rc4_string_score` | payload (base) | 0.9930 |
| `beacon_jitter` | payload (base) | 0.9754 |
| `bidir_flow_duration` | relay (novel) | 0.9070 |

Both near-separators sit in the **base** feature set — the set the novel groups
must improve *upon*. Their distributions were **deliberately left as generated**.

Narrowing them would have raised the measured incremental value of the
resolution and relay groups, and it would have done so by weakening the
baseline rather than by strengthening the finding. A strong base makes the
incremental-value question **harder**, which is the correct direction for a test
whose purpose is to risk the hypothesis. The standing rule recorded in
`src/ingest/mock_generator.py` applies:

> Do not "fix" a null result by widening class separation. If the
> resolution/relay groups show no independent value, the correct response is to
> ground those features in observable events and build better benign controls —
> not to increase the distance between the class distributions.

`rc4_string_score` additionally requires payload inspection and is reported
separately in a **lab-only sensitivity analysis**, since a deployment restricted
to flow metadata cannot compute it.

## L6. `failed_conn_ratio` is silent about inbound flows

Zeek writes `conn.log` from the **originator's** perspective. This project
normalises orientation so that `orig_*` always means *device → peer*: for flows
where the monitored device was the responder, the byte, packet and address
columns are swapped (`src/ingest/iot23.py`, `normalise_orientation`).

`conn_state` is **not** swapped, because it has no device-relative equivalent —
it describes the *originator's* attempt to establish the connection. `S0`
(no reply seen) says something about the originator's target, not about the
responder's behaviour.

Consequently `failed_conn_ratio` is computed over **outbound flows only**, and
is silent about inbound ones. This is a documented approximation, not an
oversight. The alternative — counting inbound failures too — would be actively
wrong: a benign device that is merely *being* port-scanned would then show a high
`failed_conn_ratio` and high `distinct_dst_ports`, and would be flagged for
traffic it neither sent nor solicited.

Six of the eleven Track-A-derivable features are outbound-only for the same
reason. `coverage_report` therefore reports `inbound_flow_fraction` and
`windows_with_no_outbound_flow`: a capture that is mostly inbound leaves those
six near-empty, and the reader must know that before interpreting them.

## L7. `rpc_endpoint_ratio` is undefined on captures with no resolver traffic

`rpc_endpoint_ratio` is a **proxy**, named as one. On Track A it cannot detect
blockchain resolution — the phenomenon is absent (L1). It measures the share of
flows reaching DNS-resolver or JSON-RPC ports, which is a *structural analogue*
of resolution behaviour, nothing more. Ports 443/8443 are deliberately excluded:
including general TLS would make the ratio a measure of ordinary web traffic.

Its denominator is the count of flows to resolver **or** RPC ports. On a capture
containing none, the ratio is `NaN` — not `0.0`, because there was nothing to
take a ratio of.

The practical consequence: **Track A's per-row missing-feature floor is 6 of 16,
not 5.** The five features of L1 are always absent; `rpc_endpoint_ratio` joins
them on any capture without resolver traffic. The ingest report states the
missing-feature count as a **range** (`features_missing_min` / `_median` /
`_max`) rather than a single number, because the count above the floor varies
per window — a window whose beacon interval was unmeasurable is missing more.

`login_burst_count` is a proxy on the same terms.

## L8. Malformed-line accounting is exact in one direction only

`rows_skipped_malformed` compares an exact byte-scan count of non-comment lines
against the rows pandas returned. It reports lines with **too many** fields,
which pandas rejects.

A line with **too few** fields is *not* reported, because pandas pads it with
`NaN` and returns it as a row. Such a line does not silently acquire a class: its
address columns are unreadable, so neither end is an identified device and
orientation drops it — counted under `no_device_involved_dropped`. A truncated
line can therefore vanish, but it cannot be mislabelled, and the count of
vanished flows is reported.

Note on implementation: `usecols` is validated but deliberately **not** passed to
`pandas.read_csv`. Passing it disables pandas' field-count check entirely, which
would make `rows_skipped_malformed` structurally zero — a counter that cannot
rise reads as evidence of a clean file. Parsing all declared columns and dropping
the unused ones per chunk costs throughput and buys a counter that means what it
says. See `src/ingest/zeek.py`.

## L9. Window labels use ANY-semantics, which merges two different situations

A device-window is labelled malicious if **any** flow in it is malicious — not by
majority vote. A majority vote would relabel a compromised device benign whenever
most of its traffic was ordinary, and would understate the false-negative rate
for exactly the stealthy beaconing this project is about.

The cost is that a window with one malicious flow in twenty and a window that is
entirely malicious receive the same label. `malicious_fraction` is retained on
every row, and `FLAG_MIXED_LABEL_WINDOW` is set, so the distinction survives into
the observation table and can be conditioned on downstream.

Related windowing constraints:

- The 300 s window grid is **absolute** (Unix-epoch aligned), not
  capture-relative, so that `observation_id`s are stable between a full run and a
  partial re-run of the same capture.
- A flow is assigned to the window containing its **start** time. Flows are never
  split proportionally across windows; a 400 s flow belongs to one window.
- Quality flags (`FLAG_LOW_FLOW_COUNT`, `FLAG_SINGLE_PEER`,
  `FLAG_SHORT_WINDOW`) mark windows too thin to support the periodicity
  features. They are reported, not silently dropped.

---

## Deliberate non-goals

Stated so their absence is not read as an oversight:

- **No functional attack capability.** Nothing here scans, exploits, relays,
  forwards packets, opens NAT mappings, or contacts any third-party host. The
  mock generator produces numeric flow metadata and sends nothing. See
  `docs/ethics-and-containment.md`.
- **No live blockchain interaction.** No ENS/SNS resolution, no public RPC
  query. Resolution behaviour is modelled from published descriptions of traffic
  *shape*.
- **No attribution.** Techniques are studied; operators are not named as
  responsible.
- **No claim of enterprise performance.** Synthetic accuracy figures are not
  deployment figures, and are not presented as such anywhere.
