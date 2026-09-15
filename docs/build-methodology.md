# Build Methodology — Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT Botnet Detection

> **Status:** Methodology reference. Supersedes the enterprise-product build approach described in
> `PROJECT_MASTER_INFORMATION.md` §14 (Enterprise product roadmap). The research question,
> ethics constraints and evaluation protocol in that document remain authoritative and unchanged.
>
> **Date:** 3 September 2026
> **Deliverable this serves:** a final-year research paper backed by real captured network traffic.
> **Purpose:** to state, in one place and with evidence, why the project is being rebuilt and what
> "building it correctly" concretely means — so that any reader (supervisor, examiner, or the author
> in six months) can evaluate the approach without needing the conversation that produced it.

---

## 1. Executive summary

This project evaluates whether two behavioural indicator groups — **blockchain-resolution** and
**victim-relay** — add measurable detection value beyond conventional IoT-botnet features. A
research pipeline was built to test that question, comprising schema validation, ingestion, feature
engineering, three detectors, an incremental-value experiment protocol and 541 automated tests.

Three problems were found on inspection, one of which is fatal to the research question as
currently implemented:

1. The Python environment the pipeline runs on no longer exists on the machine.
2. No real network data has ever entered the pipeline; every published number is synthetic.
3. **The thesis cannot be measured on the telemetry format the pipeline ingests.** Four of the seven
   detection rules are structurally incapable of firing, and both indicator categories the project
   exists to study are unreachable.

The third finding is not a bug to fix in code. It is a **telemetry** problem: a Zeek connection log
physically does not record the behaviour in question. Five threat-intelligence documents covering
the *Dysphoria* / *JackSkid* botnet lineage confirm precisely where that behaviour does appear —
in DNS, HTTP and TLS records rather than connection records.

The rebuild therefore replaces synthetic data with **real captured packets from three sources**,
extends ingestion from single-file to multi-log Zeek output, and reimplements the four dead features
against evidence-grounded definitions. No hardware purchase is required. The existing null result is
preserved as an honest finding and is not to be overturned by tuning the data generator.

---

## 2. Why this rebuild — the three findings

### 2.1 The runtime environment is gone

The project's documentation, run commands and test instructions all reference an Anaconda
environment named `shiva`. It is absent:

```
C:\Users\shivraj\anaconda3          → does not exist
conda                                → not on PATH
python                               → Windows Store Python 3.13.14
  installed: numpy, matplotlib
  missing:   pandas, scikit-learn, xgboost, pyyaml, seaborn, imbalanced-learn
```

Every module under `src/` imports `pandas` and `yaml`. Nothing can be imported, no test can run, and
the pipeline cannot execute. **Consequence:** the frequently cited "541 tests passing" is a
*historical* statement. It is not a current fact and must not be reported as one until the
environment is rebuilt and the suite re-run.

### 2.2 No real data has ever been ingested

`data/raw/` — the directory the ingestion path reads from — is empty, and has been since the project
began. Every artefact in `results/` derives from `data/processed/track_b_mock_observations.csv`,
which is generated numerically by `src/ingest/mock_generator.py`. No packet was ever captured.

The Track-A (IoT-23) ingestion path — `src/ingest/iot23.py`, `src/ingest/iot23_labels.py`, and 87
associated tests — has only ever been exercised against small synthetic fixtures. It has never
processed a real capture file.

**Consequence:** the project's headline finding ("the novel feature groups add no distinguishable
detection value") is a statement about a random number generator's output, not about network
traffic. It is a valid *pipeline integrity* result and an invalid *scientific* one.

### 2.3 The thesis is structurally unmeasurable on the current input format

This was verified by executing the project's own feature-availability table against its own rule
set, not by reading documentation. For every operational telemetry source the pipeline supports:

| Rule feature | Group | Availability on all flow-derived sources |
|---|---|---|
| `serverlist_pull` | resolution | **UNAVAILABLE** (always NaN) |
| `ens_query_rate` | resolution | **UNAVAILABLE** (always NaN) |
| `upnp_addportmapping` | relay | **UNAVAILABLE** (always NaN) |
| `rc4_string_score` | payload | **UNAVAILABLE** (always NaN) |
| `beacon_interval` | payload | computable |
| `updownlink_ratio` | relay | computable (proxy on NetFlow/firewall) |
| `login_burst_count` | infection | proxy |

Only **3 of 7** rules can ever evaluate. Since `vote_threshold` is 3, a window must fire *every
single evaluable rule* to be flagged. More seriously:

> Both resolution rules are permanently NaN, therefore
> **`SUSPICIOUS_RESOLUTION_PATTERN` and `SUSPICIOUS_COMBINED_PATTERN` can never be emitted** —
> on `op_zeek`, `op_flow_csv`, `op_netflow` and `op_firewall` alike.

The two alert categories the entire research question concerns are unreachable by construction. The
coverage gate handles this honestly (it emits `INSUFFICIENT_TELEMETRY` rather than a false negative),
which is the correct engineering behaviour — but it means the delivered system is a conventional
botnet triage tool that correctly reports it *cannot* assess the blockchain-resolution hypothesis.

**Consequence:** no amount of feature engineering, model selection or tuning over `conn.log` can
recover this. The input format must change.

---

## 3. Non-negotiable constraints

These bind every decision below. They come from the project specification and are not relaxed by
this rebuild.

### 3.1 Scientific integrity

- The deliverable is a **research paper**, not a product.
- **Synthetic results are never presented as findings.** Mock data is called "mock", "synthetic" or
  "local numerical observations" every time it is mentioned.
- **The generator is never tuned to confirm the thesis.** If the novel indicator groups show no
  independent value, that null result stands. Adjusting distributions until the result is favourable
  is fabrication, and is enforced against by existing tests.
- Missing data is **never silently converted to zero.** A feature that cannot be measured is `NaN`,
  and the correct inference output is abstention, not a guess.
- Threat-intelligence claims (campaign names, domains, infection counts, attack capacity) are cited
  as **reported claims**, never as project measurements or established fact.

### 3.2 Defensive-only scope

The following are never built, operated, tested or simulated:

- botnets, C2 servers, DDoS capability, scanners, exploits, or malware
- packet forwarding, functional relays or proxies
- UPnP/NAT port mapping against any real gateway
- live ENS/SNS resolution, blockchain queries, or RPC endpoint contact
- interaction of any kind with real attacker infrastructure

No device is scanned, probed, connected to or controlled. Reported indicators of compromise (the
`.eth`/`.sol` domains, C2 IP addresses, RPC provider hostnames, sample hashes) exist in this project
**only as defanged text in documentation**. None is ever resolved, contacted or embedded as a live
target.

### 3.3 Practical constraints

- **No hardware budget.** No component may be purchased or requested. (Section 6 establishes that
  none is needed.)
- All processing is local. No dataset is downloaded, no package installed, and no external service
  called without explicit approval.

---

## 4. What the threat intelligence established

Five documents inform the design. They are treated as *evidence about what to measure*, not as
ground truth about any specific incident.

### 4.1 The sources

| # | Document | Author / Publisher | Date | Type |
|---|---|---|---|---|
| 1 | *Botnet Rising Star: Dysphoria Evolution and Deep Technical Analysis* | Wang Hao, Qi'anxin XLab (with CNCERT) | 2026-07-25 | Primary technical |
| 2 | *CNCERT: Risk Tips for the Widespread Spread of the Dysphoria Botnet* | CNCERT, via SecRSS | 2026-07-24 | Primary (mirror of #1) |
| 3 | *Reverse-engineering Jackskid: from bare-bones Mirai fork to persistent TV box botnet* | Nokia Deepfield ERT + Comcast CTRL | 2026-03-24 | Primary technical |
| 4 | *Name-resolving malware DDoS attacks on Ethereum and Solana* | NICTER Analysis Team, NICT (Japan) | 2026-05-21 | Primary technical |
| 5 | *Linksys E1700 command injection (CVE-2025-9528)* | Jiaqian Peng, IIE / Chinese Academy of Sciences | — | Primary PoC |

Three independent laboratories on three continents (China, Japan, United States) converge on the
same technical picture. That cross-corroboration is itself worth reporting.

### 4.2 The indicator groups map onto documented behaviour

The project's 16 features were not invented speculatively. Each corresponds to something a
documented campaign is reported to do:

| Reported behaviour | Project feature | Group |
|---|---|---|
| ENS/SNS C2 resolution via blockchain name records | `ens_query_rate`, `resolution_entropy` | resolution |
| HTTP `GET /nodes?key=…` server-list pull from a distribution node | `serverlist_pull` | resolution |
| Requests to non-standard resolver / RPC endpoints | `rpc_endpoint_ratio` | resolution |
| Victim hosts converted into C2 relay nodes | `flow_fanout`, `bidir_flow_duration` | relay |
| Automated UPnP port mapping to traverse NAT | `upnp_addportmapping` | relay |
| `epoll` bidirectional transparent relay | `updownlink_ratio` | relay |
| Custom RC4 string encryption | `rc4_string_score` | payload |
| Periodic JSON status heartbeat (~4 s interval) | `beacon_interval`, `beacon_jitter` | payload |
| Telnet/SSH weak-credential brute forcing | `login_burst_count` | infection |
| Known IoT RCE exploitation | `scan_rate`, `distinct_dst_ports`, `failed_conn_ratio` | infection |

**This is the argument for the feature catalogue's construct validity** and belongs in the paper.

### 4.3 The correction: resolution does not use DNS

The single most important technical finding, and one that changes the implementation:

> **ENS/SNS resolution never touches the DNS protocol.** The malware does not issue a DNS query for
> `m3rnbvs5d.eth`. It POSTs a **JSON-RPC payload over HTTPS** to a small, named set of third-party
> RPC gateway services, and decodes an IPv6-shaped text record into the real C2 IPv4 address.

Attribution must be precise here. **This mechanism is stated explicitly only by source #4 (NICTER):**

> "Even though it's blockchain-based name resolution, it doesn't actually connect to Ethereum's Peer
> to Peer (P2P) network, but rather uses a service that provides an endpoint to mediate it."
> … "Name resolution utilizes text records, and ENS requires POSTing a JSON-RPC format payload to
> the endpoint."

Sources #1 and #3 describe the *decode* step (the IPv6→IPv4 permutation) and the record keys, but do
**not** themselves specify the wire protocol used to retrieve the record. They are consistent with
NICTER's account — `.eth` is not an ICANN TLD and cannot be resolved by a conventional resolver — but
the claim should be cited to NICTER specifically, not attributed to all three.

The RPC gateway hosts named by NICTER (Table 1 of source #4):

```
Ethereum: eth.llamarpc.com, ethereum.publicnode.com, ethereum-rpc.publicnode.com,
          eth-mainnet.public.blastapi.io, eth.drpc.org, rpc.mevblocker.io,
          eth-protect.rpc.blxrbdn.com, 1rpc.io
Solana:   sdk-proxy.sns.id, sns-sdk-proxy.bonfida.workers.dev
```

NICTER notes these are legitimate general-purpose services, unrelated to the attacker. That matters
for false-positive reasoning: legitimate software may also contact them.

**Design implication:** resolution indicators are observable in **`ssl.log` (SNI)** or `http.log`
(Host header) as a hostname match against a documented allowlist. No payload decryption, no DGA
entropy heuristics, no DNS log required for the primary signal. This is cheaper, more precise and
better-evidenced than the design it replaces.

### 4.4 A citation-caution example worth reporting

Sources #1 and #2 present the *same joint research* by the *same two organisations*. Their exploited-
vulnerability lists nonetheless differ:

| | Count | Shared | Unique |
|---|---|---|---|
| XLab (#1) | 13 | 6 | CVE-2017-17215, CVE-2017-5259, CVE-2018-14558, CVE-2020-25499, CVE-2020-8515, CVE-2025-28137, CVE-2025-55182 |
| CNCERT (#2) | 13 | 6 | CNVD-2017-38447, CNVD-2018-01041, CNVD-2020-35174, CNVD-2020-70958, CNVD-2020-08128, CNVD-2025-12011, CNVD-2025-29924 |

Only 6 of 13 entries overlap, and the divergence is not merely CVE↔CNVD identifier translation —
the enumerations genuinely differ. Behavioural claims (RC4 algorithm, C2 acquisition flow, UPnP
mechanism, relay heartbeat) and infection-scale figures are, by contrast, identical across both.

**Reporting rule that follows:** behavioural mechanisms are well corroborated; the vulnerability
enumeration and scale figures are single-sourced and unverified, and must be presented as reported
claims with that caveat attached.

---

## 5. Architecture — three real telemetry tracks

Synthetic Track B is retired from all reported results. Three sources of **real captured packets**
replace it.

| Track | Source | What it provides | Cost | Gate |
|---|---|---|---|---|
| **A** | IoT-23 scenario **PCAPs**, replayed through local Zeek | Real labelled IoT traffic with `dns.log` + `http.log` + `ssl.log`; conventional botnet/C2 controls | free | dataset download approval |
| **B′** | Zeek sniffing the author's own network | Real benign home/IoT traffic → honest false-positive control on real data | free | own network only |
| **C** | Isolated VirtualBox lab, mock services only | Real packets exhibiting resolution + relay indicators, ground-truth labelled by construction | free | **institutional sign-off** |

### 5.1 Track A — the IoT-23 unlock

IoT-23 is published in two distributions. **This distinction is the crux of the project's central
problem:**

- **Lightweight distribution (~8.8 GB)** — `conn.log.labeled` only. No `dns.log`, no `http.log`, no
  `ssl.log`, and no PCAP from which to regenerate them. *This is the format the existing codebase
  assumes, and it is exactly why four rules are dead.*
- **Full distribution (~21 GB)** — includes per-scenario **PCAP files**.

**Decision: take the full/PCAP distribution.** Running Zeek locally over a scenario PCAP produces
the complete log set, at which point the resolution features become computable for the first time.
Downloading the lightweight version would consume 8.8 GB to arrive back at the existing dead end.

**Do not download the entire 21 GB archive.** IoT-23 publishes per-scenario downloads. Sufficient
selection:

- 1–2 **small malicious** scenarios — conventional botnet/C2 controls with real DNS and HTTP activity
- 1–2 **benign honeypot** captures (`CTU-Honeypot-Capture-*`; the Somfy door lock, Philips Hue and
  Amazon Echo captures are small) — real-benign false-positive control

Expect roughly 1–3 GB. Disk is not a constraint (155 GB free, verified). Confirm at the download page
that the chosen scenarios actually bundle `.pcap` files and prefer the smallest that do.

**Honest limitation to record:** IoT-23 was captured in 2018–2019 and predates blockchain-anchored
C2 entirely. It cannot validate the resolution hypothesis. Its role is to validate the pipeline on
real labelled data and to measure false alarms on real benign IoT traffic — nothing more. This must
be stated explicitly in the paper.

### 5.2 Track B′ — the author's own network

Zeek running under WSL2 on the author's own network, capturing genuinely benign traffic from devices
the author owns and is authorised to monitor. Provides a real-traffic false-positive control that is
independent of IoT-23's capture conditions. Zero cost, no approval beyond ownership of the network.

### 5.3 Track C — the isolated lab

This is what makes the thesis testable at all, and is explicitly permitted by the project
specification: *"a strictly isolated lab using mock services only, subject to institutional
approval."*

The lab generates **real packets** — captured by Zeek, processed by the real pipeline, labelled as
ground truth because the author controls which component is running. This is categorically different
from the current generator, which fabricates feature *values* directly. Section 7 specifies its
design and containment.

---

## 6. Zero hardware required

No Raspberry Pi, mini-PC, managed switch or network tap needs to be purchased or requested from the
institution. A single laptop produces all three tracks:

| Need | Solution | Cost |
|---|---|---|
| Convert PCAP → full Zeek log set | Zeek under WSL2 | free |
| Capture real benign traffic | Zeek under WSL2 on own network | free |
| Isolated multi-host lab | VirtualBox, internal-network mode | free |
| Linux guests | any free distribution ISO | free |

The hardware extension described in `PROJECT_MASTER_INFORMATION.md` §6 remains optional and is not
required to answer the research question.

---

## 7. Track C lab design

### 7.1 Governing principle

> **Generate the observable, never the capability.**

Every component reproduces the *log signature* of a documented behaviour while deliberately lacking
the *function* that makes that behaviour dangerous. This keeps the lab strictly inside the
defensive-only constraint while still producing genuine, ground-truth-labelled packets.

### 7.2 Components

| Component | Produces | Deliberately does NOT |
|---|---|---|
| **Mock RPC gateway** | `ssl.log` SNI + JSON-RPC-shaped HTTPS POST, matching the documented resolution flow. Hostname resolved locally within the lab only. | contact any real RPC provider; run any blockchain client; perform any live ENS/SNS lookup |
| **Mock distribution node** | `http.log` entry for `GET /nodes?key=<token>` returning a static list — the documented `serverlist_pull` shape | serve any real C2 address, or contact anything |
| **Mock IGD (UPnP gateway)** | SSDP `M-SEARCH` on UDP/1900 and a SOAP `AddPortMapping` POST to a WANIPConnection control URL, answered with success | **open any port**; alter any real gateway's NAT table |
| **Relay shape** | Symmetric up/down byte ratios, long-lived bidirectional flows, periodic small-JSON heartbeat | route to the internet; accept configuration; bind on the host; forward anything outside two fixed lab addresses |
| **Mock vulnerable endpoint** | `http.log` record of `POST /goform/systemCommand` carrying shell metacharacters — the CVE-2025-9528 signature | execute anything; run real vulnerable firmware; touch a real Linksys device |

### 7.3 Containment

- **VirtualBox *internal network* only** — no NAT adapter, no bridged adapter, no host-only route to
  the internet. Isolation is structural, not policy-based.
- No real reported infrastructure is contacted, resolved or configured as a live target. Mock
  services stand in entirely, keyed to locally-owned names and addresses.
- No malware sample is downloaded, executed or possessed. No attack traffic is generated. Nothing in
  the lab is capable of functioning outside it.

### 7.4 Verification of containment

Containment is asserted only after it is tested:

- the guest VM cannot reach any external address (verified by failed route)
- the mock IGD has opened no port (verified by scanning the mock gateway *from inside the lab only*)
- the relay component refuses any endpoint other than its two hardcoded lab addresses

---

## 8. Feature redesign

| Feature | Previous status | Corrected design | Evidence |
|---|---|---|---|
| `ens_query_rate` | UNAVAILABLE (NaN) | Rate of `ssl.log` SNI / `http.log` Host matches against the documented RPC-gateway allowlist, per window | NICTER §"Blockchain-based C2 name resolution" |
| `rpc_endpoint_ratio` | proxy (port-share only) | Fraction of the device's TLS/HTTP sessions going to allowlisted RPC gateways | NICTER Table 1 |
| `serverlist_pull` | UNAVAILABLE (NaN) | `http.log` GET carrying a `key=` query parameter within *N* seconds of an RPC-allowlist match | XLab §II.2; CNCERT §II.2 |
| `upnp_addportmapping` | UNAVAILABLE (NaN) | `conn.log` UDP/1900 SSDP activity **plus** an `http.log` SOAP `AddPortMapping` POST | XLab §III.1; CNCERT §III.1 |
| `resolution_entropy` | UNAVAILABLE (NaN) | **Demoted to secondary.** Shannon entropy over `dns.log` qnames — retained because campaigns fall back to plain DNS when RPC endpoints are unstable, but not the primary signal | NICTER (Public DNS fallback) |
| `rc4_string_score` | UNAVAILABLE (NaN) | **Stays UNAVAILABLE.** Requires plaintext payload inspection; honestly out of reach for flow/log telemetry. Not faked, not proxied. | — |
| `tcp_syn_fingerprint` | *(new, optional)* | TCP options `MSS-NOP-NOP-SACK-NOP-WS` with no timestamps — "a combination produced by no modern OS". Included only if Zeek can expose raw TCP options; otherwise omitted rather than approximated. | Deepfield/Comcast §Key findings |

A new source constant `SOURCE_ZEEK_BUNDLE` is added to `src/schema/columns.py` with a
`FEATURE_AVAILABILITY` entry marking the redesigned features `computable`. **Any log type absent
from a given capture yields `NaN`, never `0`** — the existing missing-data policy is preserved
exactly.

**Expected outcome:** on a bundle source, `unavailable_features()` returns only `rc4_string_score`,
and both resolution rules become reachable — the direct inverse of the finding in §2.3 that
motivated this rebuild.

---

## 9. Code reuse map

The existing research pipeline is sound engineering and is preserved. Only ingestion and feature
derivation change.

### 9.1 Carried over unchanged

| Component | Path | Why it survives |
|---|---|---|
| Schema / column contract | `src/schema/` | The single source of truth for the data model; already operational-source aware |
| Windowing | `src/features/windowing.py` | `assign_windows`, `window_quality_flags`, `FLOW_COLS` are format-agnostic |
| Zeek read primitives | `src/ingest/zeek.py` | `read_header` / `read_log` are **generic Zeek TSV readers** — they already parse `dns.log`, `http.log` and `ssl.log` without modification |
| IoT-23 adapter | `src/ingest/iot23.py`, `iot23_labels.py` | Device identification and the orientation transform are reused verbatim |
| Detectors | `src/models/` | Heuristic rules, Random Forest, XGBoost, registry |
| Evaluation engine | `src/evaluate/` | `run_incremental`, `run_incremental_multiseed`, `run_drop_one`, `run_model_comparison`, threshold calibration, grouped bootstrap — this is the paper's entire experimental apparatus |
| Reporting | `src/reports/` | Table and figure generation |
| Config | `src/config.py`, `configs/` | Attribute-access config with fail-loud key errors |

### 9.2 New work

| Component | Path | Purpose |
|---|---|---|
| Multi-log ingest | `src/ingest/zeek_bundle.py` | Read a Zeek output **directory** rather than one file; join `conn`/`dns`/`http`/`ssl` by `uid` and device IP |
| Feature derivation extension | `src/features/derive.py` | Add a bundle-aware path alongside the existing flow path; `_nans(keys)` remains the fallback |
| New source constant | `src/schema/columns.py` | `SOURCE_ZEEK_BUNDLE` + availability entry |
| Lab services | `lab/` | The five mock components of §7.2 |
| Tests | `tests/` | Multi-log ingest, corrected features, containment assertions |

### 9.3 Retired or deprioritised

| Component | Disposition | Rationale |
|---|---|---|
| `src/ingest/mock_generator.py` | Demoted to **unit-test fixture only** | Never again a source of reported results |
| `src/storage/`, `src/auth/`, `src/audit/` | Kept as-is, **not extended** | Already built and tested; no further investment |
| `src/api/`, dashboard, `src/alerts/`, Docker | **Not built** | Adds nothing to a research paper |
| Synthetic `results/` and `data/processed/*mock*.csv` | Deleted **only after** real results replace them | Currently the only copy of the existing finding and not regenerable until the environment is rebuilt |

---

## 10. Phased build plan

| # | Phase | Verification |
|---|---|---|
| 0 | **Environment.** Create `.venv` from Python 3.13.14; install pandas, scikit-learn, xgboost, pyyaml, matplotlib, seaborn, imbalanced-learn; pin `requirements.txt`. | `python -m unittest discover -s tests` → 541 tests green. Until this passes, no claim about test status is current. |
| 1 | **Project root.** Carry the reusable tree into `IoT-Botnet-Detection/`. Leave `Entreprise/` intact as reference until the new tree is green. | Full suite green in the new location. |
| 2 | **Multi-log ingest.** `zeek_bundle.py`, reusing `zeek.read_header` / `read_log` unchanged. | Ingest of a Zeek output directory passes `assert_valid`. |
| 3 | **Feature redesign.** Implement §8 against `ssl.log` / `http.log` / `dns.log`. | `unavailable_features(SOURCE_ZEEK_BUNDLE)` returns only `rc4_string_score`; resolution rules reachable. |
| 4 | **Track A.** Download selected IoT-23 scenario PCAPs; run Zeek; ingest; validate. | Zeek emits `dns.log` + `http.log` + `ssl.log`; frame passes schema validation. |
| 5 | **Track B′.** Capture own-network benign traffic; ingest. | Real benign frame validates; feature distributions are plausible. |
| 6 | **Track C.** Build the isolated lab; capture; label by construction; ingest. | Containment tests of §7.4 pass **before** any capture is used. |
| 7 | **Experiments.** Re-run the incremental-value study on real data, reusing `src/evaluate/` unchanged. Cross-track FPR: Track C detector against Track A / B′ benign. | Recall/FPR deltas with grouped-bootstrap confidence intervals. |
| 8 | **Retire synthetic; write the paper.** | Every reported number traces to a real capture. |

---

## 11. Governance and approval gates

| Item | Status | Why the gate exists |
|---|---|---|
| `venv` + `pip install` of pipeline dependencies | **Approved** | Package installation requires explicit approval |
| IoT-23 scenario download (full/PCAP distribution, selected scenarios) | **Pending** | Dataset download requires explicit approval; licence terms must be accepted and recorded |
| Track C isolated lab | **Pending — institutional sign-off** | Required by the project specification for any lab work, however contained |
| Any outbound network call from the pipeline | **Prohibited** | Containment invariant; enforced by test |
| Contact with real reported infrastructure | **Prohibited** | Defensive-only constraint; no exception |

**Data provenance to record at download time:** scenario name, source URL, download date, licence
terms accepted, checksum where available, and every preprocessing decision.

---

## 12. What this rebuild does not promise

Stated plainly, because the alternative is overclaiming:

- **The null result may survive.** Real data may show that the resolution and relay groups add no
  distinguishable value. That is a legitimate finding and will be reported as such. The generator
  will not be adjusted to produce a more attractive conclusion.
- **IoT-23 cannot validate the thesis.** It predates blockchain-anchored C2. It validates the
  pipeline and measures false alarms on real benign traffic. Nothing more.
- **Track C is a controlled lab, not the wild.** It demonstrates that the indicators are *detectable
  when present under known conditions*. It does not establish base rates, real-world prevalence, or
  operational detection performance.
- **`rc4_string_score` remains unmeasurable** from network telemetry. It is reported as a lab-only
  feature and every headline result is computed both with and without it.
- **No claim of confirmed compromise is ever made.** Detections are described as *suspicious
  indicator patterns requiring analyst review*.

---

## 13. References

1. Wang Hao (Qi'anxin X Lab, jointly with CNCERT). *Botnet Rising Star: Dysphoria Evolution and Deep
   Technical Analysis.* 25 July 2026.
2. CNCERT (National Internet Emergency Response Center), published via SecRSS. *Risk Tips for the
   Widespread Spread of the Dysphoria Botnet.* 24 July 2026.
3. Nokia Deepfield Emergency Response Team and Comcast Threat Research Lab. *Reverse-engineering
   Jackskid: from bare-bones Mirai fork to persistent TV box botnet.* 24 March 2026.
4. NICTER Analysis Team, NICT (Japan). *Name-resolving malware DDoS attacks on Ethereum and Solana.*
   21 May 2026.
5. Peng, Jiaqian (Institute of Information Engineering, Chinese Academy of Sciences). *Linksys E1700
   remote command execution (CVE-2025-9528).*
6. Garcia, S. et al. *IoT-23: A Labeled Dataset with Malicious and Benign IoT Network Traffic.*
   Stratosphere Laboratory / CTU, Zenodo, 2020. DOI: 10.5281/zenodo.4743746

**Handling note.** Sources 1–5 contain indicators of compromise: domain names, IP addresses, sample
hashes and blockchain domains. Within this project these appear **only as defanged text in
documentation**. None is resolved, contacted, or embedded in any executable path. Infection-scale
figures, attack-capacity claims and vulnerability enumerations from these sources are **reported
claims, independently unverified**, and are cited as such — see §4.4 for a concrete instance of two
co-publishers disagreeing on the same list.
