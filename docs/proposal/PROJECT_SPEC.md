# Detecting Blockchain-Anchored Command-and-Control in IoT Botnets

**Complete Project Specification — Final-Year Project & Paper**

> **Purpose of this file:** This is a single, self-contained specification for a defensive
> security research project. It is written to be handed directly to an AI coding agent
> (Codex, Claude Code, Gemini) as a build spec, and to a project supervisor as a proposal.
> It contains the threat background, the research justification, the full proposal, the
> implementation plan, the expected outputs, the free-tooling guide, and an agent-ready
> build plan.
>
> **Prepared for:** Shivraj — B.E./B.Tech Final-Year Project
> **Target:** peer-reviewed conference / workshop paper
> **Date:** July 2026
> **Reference template:** *"Offline Reinforcement Learning Exposes FQI–DQN Tradeoffs for
> Sepsis Treatment Under Covariate Shift"* (VIT Chennai) — used as the structural and
> rigor benchmark throughout.

---

## 🛑 SOURCE-PROVENANCE WARNING — READ BEFORE CITING ANYTHING

**The threat-intelligence specifics in this document have NOT been verified against a
primary source, and you must verify them yourself before submitting any of it.**

While this spec was being written, the assistant had **no web access**: fetching
`thehackernews.com` was blocked by a network allowlist, and web search was unavailable in
the environment. The article that started this project was therefore **never read**.

That means every one of the following is **unconfirmed and may be wrong** — wrong dates,
wrong names, wrong numbers, or entirely non-existent:

- The campaign/malware names (*Dysphoria*, *JackSkid*, *Kimwolf*, *AISURU*)
- All dates (the March 2026 takedown, the March 2026 ENS pivot, the June 2026 relay-only
  variant, the July 2026 XLab/CNCERT publication)
- All blockchain identifiers (`m3rnbvs5d[.]eth`, `burrberry[.]eth`,
  `24carnforth2merseyside[.]sol`)
- All scale and volume figures (90,000+ commands; 200,000 bots; 239,000 peak; ~4 Tbps;
  31.4 Tbps; 1.8M devices)
- The CVE reference (`CVE-2025-9528`)
- All named organisations and vendors (XLab, CNCERT, NICT, Nokia Deepfield, Comcast)

**Required action before you use this document for anything graded or published:**

1. Open the original article and every vendor/CERT report it cites. Check each fact above
   against it. Correct or delete whatever does not match.
2. Search Google Scholar, IEEE Xplore, the ACM Digital Library, and arXiv yourself for
   *blockchain C2*, *ENS command and control*, *IoT botnet detection*, and *victim relay /
   proxy botnet* to confirm the novelty claim in Part I §3 still holds. The assistant could
   not run these searches.
3. Replace the placeholder citations in Part II §18 with real, verified references.

Treat the *research design* here (methodology, features, ablation, evaluation protocol,
build plan) as the usable contribution, and treat the *threat facts* as a draft to be
fact-checked. Do not present unverified numbers to a supervisor or reviewer as established.

---

## ⚠️ SCOPE AND ETHICS — READ FIRST (NON-NEGOTIABLE)

This project is **defensive only**. Any AI agent or developer working from this file must
respect the following hard boundaries:

- **DO NOT** build, improve, or operate a working botnet, C2 server, DDoS tool, or any
  functional attack capability.
- **DO NOT** write code that scans, attacks, or connects to real third-party devices or to
  real attacker infrastructure (no real ENS/SNS attacker domains, no live C2 endpoints).
- **DO NOT** execute live malware outside an air-gapped, isolated virtual machine.
- **DO** build detection, analysis, classification, measurement, and visualization code.
- **DO** use local stand-in/mock resolvers and mock relay nodes to generate *traffic shapes*
  for labelling purposes.
- All dynamic experimentation is confined to an isolated virtual lab with no route to the
  public internet.
- Study **techniques, not attribution** — do not name or accuse any operator.
- Obtain supervisor and (where required) department ethics/lab-safety approval before any
  dynamic work.

The purpose is to help defenders detect infected devices. Nothing in this project creates
offensive capability.

---

# TABLE OF CONTENTS

**PART I — BACKGROUND AND JUSTIFICATION**
1. The Threat: What Happened and Why It Matters
2. Is This an Existing/Solved Problem? (direct answer)
3. Justification Against Existing IoT-Botnet Papers (direct answer)

**PART II — THE PROJECT PROPOSAL (full text)**
4. Abstract
5. Problem Statement and Motivation
6. Background
7. Research Gap and Novelty (incl. Positioning + Advanced Features)
8. Research Questions and Objectives
9. Related Work
10. Proposed Methodology
11. Experimental Setup and Testbed
12. Ethical, Legal, and Safety Considerations
13. Evaluation Plan
14. Expected Contributions
15. Publication Strategy
16. Project Timeline
17. Risk Assessment and Mitigation
18. References

**PART III — IMPLEMENTATION AND OUTPUTS**
19. Mapping to the Reference Paper
20. Implementation: Stage by Stage
21. Concrete Outputs (figures/tables the project produces)
22. Tools and Tech Stack

**PART IV — FREE BUILD & AI TOOLING GUIDE**
23. Is It Really Free?
24. Free Tools, Datasets, Compute
25. Using Claude / Codex / Gemini Effectively
26. Honest Caveats

**PART V — AGENT-READY BUILD PLAN**
27. Repository Layout
28. Build Milestones with Acceptance Criteria
29. Paper Skeleton (13-section journal format)

---

# PART I — BACKGROUND AND JUSTIFICATION

## 1. The Threat: What Happened and Why It Matters

### 1.1 The timeline (the core story of the project)

This project is driven by a real, current case that demonstrates a decisive shift in the
botnet takedown arms race:

| Date | Event |
|---|---|
| Late 2025 | **Kimwolf** botnet documented using ENS-based C2; related AISURU/Kimwolf activity measured by Cloudflare at up to 31.4 Tbps (Q4 2025 report). Reported ~1.8M devices. |
| Aug 2025 | CVE-2025-9528 (Linksys E1700 command injection) disclosed — example of the known-RCE entry vector class. |
| **19 Mar 2026** | Coordinated **US / German / Canadian law-enforcement takedown** of four IoT botnets, including **JackSkid**. Court documents attributed **90,000+ DDoS commands** to it. |
| **25 Mar 2026** | **Six days later**, a captured sample resolves its C2 via an **ENS blockchain domain** (`m3rnbvs5d[.]eth`). The botnet survived the takedown. |
| Late Apr 2026 | New builds add **custom RC4 string encryption** and ENS resolution. |
| Early May 2026 | **Solana Name Service (SNS)** resolution added (`24carnforth2merseyside[.]sol`). Japan's **NICT** independently confirms the ENS/SNS shift. |
| **25 Jun 2026** | A **relay-only variant** appears: DDoS modules removed entirely; uses **UPnP** for NAT traversal and Linux **epoll** to relay traffic. Victims become proxy hops. |
| Days later | UPnP-based NAT traversal refined. |
| **25 Jul 2026** | **CNCERT + XLab publish the Dysphoria analysis.** |
| 27 Jul 2026 | Reported by The Hacker News. |

### 1.2 Why this defeats existing defences

The defender's most effective historical weapon is **infrastructure seizure**: find the C2
servers, get court orders, sinkhole or seize them. The March 2026 action is a textbook
example.

**Blockchain-anchored C2 breaks this.** ENS and SNS map human-readable names (e.g.
`burrberry[.]eth`) to arbitrary records stored on a public blockchain. Those records are:

- globally replicated,
- censorship-resistant,
- **not removable by any single authority**.

The attacker publishes the current location of distribution infrastructure somewhere nobody
can delete it. The bot flow is:

```
bot → resolve blockchain name (ENS/SNS)
    → receive distribution-node IPv4 address(es)
    → HTTP request to distribution node for a current "server list"
    → connect to an infected VICTIM RELAY (not the real controller)
```

Two layers of indirection mean **seizing any single server no longer decapitates the botnet**.
The real controllers stay one hop removed from anything a bot ever sees.

### 1.3 The victim-relay mesh (the newest behaviour)

The June 2026 relay-only variant:
- drops DDoS modules entirely,
- uses **UPnP `AddPortMapping`** to open ports on the local gateway,
- uses Linux **epoll** to shuttle traffic bidirectionally between an inbound connection and
  a remote C2 service.

Ordinary compromised home/small-office devices become **proxy hops that shield the operator**.
This is the same ENS resolution model seen in Kimwolf (late 2025), now combined with a relay
mesh built from the botnet's own victims.

### 1.4 ⚠️ MEASUREMENT CAVEAT (must be respected in the paper)

The reported scale figures are **unverified vendor/operator claims**, not measured ground truth:

- population "above 200,000 bots"
- single-day peak of 239,000 abroad
- ~4 Tbps storefront claim

**No de-duplication methodology was published.** Any use of these numbers in your paper must
present them explicitly as claims (e.g., "the operators advertise…", "XLab reports…"), never
as your own measurement. This matters for credibility — reviewers punish uncritical repetition
of vendor numbers.

Additionally: NICT, Nokia, and Comcast all report **shared code and strings across several
families**, which points to **shared tooling rather than a single attributed operator**.
Therefore: study techniques, not attribution.

---

## 2. Is This an Existing/Solved Problem? — DIRECT ANSWER

Two separate questions, often confused:

### 2.1 Is the threat still live, or was it solved?

**It is live, ongoing, and unsolved.** The critical detail is the *order of events*:

> The defence came **first** (March 2026 takedown). The attackers adapted **around it**
> (blockchain C2, six days later). The analysis was published **25 July 2026**.

A botnet is an *active campaign*, not a bug that gets patched and closed. The entire point of
blockchain-anchored C2 is **takedown resistance**, so the usual "solution" (seizure) is
precisely what no longer works. This is an open defensive problem — which is exactly what
makes it a legitimate research topic rather than a history report.

### 2.2 Does an academic paper on this already exist?

**Almost certainly not for this specific angle.** The botnet was publicly analysed on
25 July 2026; peer review takes months. A published, evaluated *detection* paper on
blockchain-anchored IoT-botnet C2 is very unlikely to exist yet.

**⚠️ VERIFY THIS YOURSELF BEFORE SUBMITTING.** Search Google Scholar, IEEE Xplore, ACM DL,
and arXiv for:

- `"blockchain C2" botnet detection`
- `ENS command and control detection`
- `"Ethereum Name Service" malware C2`
- `blockchain-based botnet command and control`
- `Dysphoria botnet` / `JackSkid botnet` / `Kimwolf botnet`
- `IoT botnet relay proxy detection UPnP`

If someone has beaten you to the resolution angle, **pivot to the victim-relay mesh**
(§1.3) — it is even newer (June 2026) and less studied.

---

## 3. Justification Against Existing IoT-Botnet Papers — DIRECT ANSWER

### 3.1 The legitimate concern

IoT botnet detection is a **crowded field**. Hundreds of papers detect Mirai and its variants
with ML on N-BaIoT, Bot-IoT, and IoT-23. If your project is *"detect IoT botnet traffic with
ML,"* a reviewer will correctly say **"this has been done a thousand times"** and reject it.

**That version of the project is NOT publishable.** You must not submit that.

### 3.2 The defensible claim (memorise this sentence)

> **Existing IoT-botnet detectors fingerprint the *attack stage* (DDoS floods, scanning,
> infection) or hard-coded/DGA C2. This project detects the *blockchain-anchored C2
> resolution and victim-relay stage* — a signal that did not exist in the traffic before
> late 2025, and which defeats the takedown-based defences prior work implicitly assumes.**

### 3.3 The three pillars of novelty

**Pillar 1 — The detection target is new.**
Prior work fingerprints Mirai-style hard-coded IPs or DGA domains. Blockchain-resolved C2
looks different on the wire, and benign Web3 traffic makes it non-trivial to separate. The
resolution step is largely unstudied in the open literature.

**Pillar 2 — The resilience problem is new.**
The research question shifts from *"how do I classify DDoS traffic?"* to **"how do you defend
when the infrastructure cannot be removed?"** That reframing is itself a contribution.

**Pillar 3 — You contribute a dataset.**
No public labelled dataset of blockchain-C2 botnet traffic exists. Producing one — even
testbed-generated — is a citable contribution. N-BaIoT and Bot-IoT became heavily cited
*precisely because* they released data.

### 3.4 ⚠️ THE HONEST RISK

**Your entire novelty claim lives or dies on one experiment.** If you cannot show that
resolution/relay indicators add detection value that attack-stage features alone do **not**
provide, you collapse back into the crowded "yet another IoT botnet classifier" space and get
rejected.

**This is why the ablation study is the single most important result in the paper.** It must
isolate the contribution of the blockchain-resolution feature group. Design everything else
around making that result clean and convincing.

---

# PART II — THE PROJECT PROPOSAL (FULL TEXT)

**Title:** Detecting Blockchain-Anchored Command-and-Control in IoT Botnets

**Subtitle:** A defensive measurement and detection study of ENS/SNS-based C2 and victim-relay
meshes, using the Dysphoria / JackSkid lineage as a driving case

## 4. Abstract

IoT botnets have long depended on a small number of hard-coded command-and-control (C2)
servers, which makes them vulnerable to coordinated takedowns. The Dysphoria botnet line —
analysed by CNCERT and XLab and reported in July 2026 — demonstrates a decisive shift in this
arms race. After a March 2026 law-enforcement operation disrupted its predecessor JackSkid,
the operators re-anchored their C2 in decentralised blockchain name services (Ethereum Name
Service, ENS, and Solana Name Service, SNS) and built a traffic-relay mesh out of infected
victim devices, deliberately keeping the true controllers one hop removed from the addresses
exposed to bots. Because blockchain records cannot easily be seized or blocked, conventional
server-seizure defences are substantially weakened.

This project proposes a defensive study that (i) characterises how blockchain-anchored C2 and
victim-relay meshes work across the JackSkid / Dysphoria / Kimwolf lineage, and (ii) designs
and evaluates a detection method that identifies devices resolving C2 through blockchain name
services and participating in relay behaviour, using only observable network and host
indicators. All experimentation is performed on public malware samples, public
threat-intelligence telemetry, and an isolated laboratory testbed; no live attack
infrastructure is created or operated. The intended contribution is a reproducible detection
pipeline plus an open, labelled indicator dataset suitable for publication at a
student-accessible security venue.

**Keywords:** IoT Botnet; Blockchain Command-and-Control; Ethereum Name Service; Takedown
Resilience; Network Traffic Classification; Explainable Detection; Victim Relay Mesh

## 5. Problem Statement and Motivation

The economic value of an IoT botnet is proportional to how long it survives. Defenders' most
effective weapon has historically been infrastructure seizure: identify the C2 servers, obtain
court orders, and sinkhole or take them offline. The March 19, 2026 coordinated action by
U.S., German, and Canadian authorities — which targeted four IoT botnets including JackSkid,
to which court documents attributed more than 90,000 DDoS commands — is a textbook example of
this approach.

The motivating problem is that this defence is now being systematically neutralised. Within
six days of the JackSkid takedown, a captured sample (March 25, 2026) resolved its C2 through
an ENS domain (`m3rnbvs5d[.]eth`). Subsequent builds added custom RC4 string encryption and
ENS resolution (late April), Solana Name Service resolution (early May), a relay-only variant
(June 25), and UPnP-based NAT traversal days later. **The design keeps the real controllers
hidden behind blockchain-published distribution nodes and victim relays, so seizing any single
server no longer decapitates the botnet.**

This creates an urgent and currently open detection gap. If infrastructure cannot be removed,
defenders must instead detect participation early — at the endpoint or the network edge —
before a device is drawn into DDoS or relay activity. Yet blockchain-anchored resolution does
not look like the classic hard-coded IP or DGA-domain behaviour that most existing detectors
are tuned for. A device querying a public blockchain resolver or an ENS/SNS gateway can appear
superficially benign. This project targets exactly that gap.

## 6. Background

### 6.1 IoT botnet C2 evolution

Since Mirai (2016), the dominant IoT botnet model has been: compromise poorly secured devices
via weak Telnet/SSH credentials or known remote-code-execution (RCE) flaws, receive orders
from a C2 server, and launch distributed denial-of-service (DDoS) attacks. Defenders responded
with sinkholing, DGA reverse-engineering, and infrastructure seizure. Attackers responded with
domain-generation algorithms, fast-flux DNS, and — most recently — decentralised name services.

### 6.2 Blockchain name services as a C2 channel

Ethereum Name Service (ENS) and Solana Name Service (SNS) map human-readable names (e.g.,
`burrberry[.]eth`) to arbitrary records stored on a public blockchain. Because these records
are globally replicated and censorship-resistant, an attacker can publish the current location
of distribution infrastructure in a place no single authority can delete. In the Dysphoria
case, the `burrberry[.]eth` record encodes distribution-node IPv4 addresses, while
`24carnforth2merseyside[.]sol` supplies further infrastructure records. A bot resolves the
name, contacts a distribution node over HTTP for a current server list, and is pointed at
infected relays rather than at the real controllers.

### 6.3 Victim-relay mesh and NAT traversal

The June 2026 relay-only variant drops the DDoS modules entirely and instead uses UPnP to map
ports on the local gateway and Linux epoll to shuttle traffic between an inbound connection and
a remote C2 service. In effect, ordinary compromised home and small-office devices become proxy
hops that shield the operator. This is the same ENS-based resolution model previously
documented in the related Kimwolf botnet (late 2025), now coupled with a relay mesh built from
the botnet's own victims.

### 6.4 Important measurement caveat

The reported scale — a population above 200,000 bots, a single-day peak of 239,000 abroad, and
a ~4 Tbps storefront claim — has not been independently reproduced, and the researchers
published no de-duplication methodology. Any project that cites these figures must present them
as unverified operator/vendor claims, not as measured ground truth. This proposal treats scale
claims accordingly.

## 7. Research Gap and Novelty

Prior academic work on botnet detection concentrates on hard-coded IP C2, DGA domains, and
peer-to-peer botnets. Blockchain-anchored C2 is comparatively under-studied in the open
literature, and most existing coverage of Dysphoria/JackSkid is industry threat-intelligence
reporting rather than reproducible, evaluated detection research. The novelty of this project
rests on three points:

- It focuses detection on the **resolution step** — the moment a device consults a blockchain
  name service or ENS/SNS gateway for C2 records — rather than on the DDoS step, enabling
  earlier detection.
- It treats the **victim-relay mesh** as a first-class detectable behaviour (UPnP
  port-mapping plus epoll-style bidirectional relaying), not merely as background noise.
- It produces an **open, labelled indicator dataset** and a reproducible pipeline, addressing
  the reproducibility gap in current vendor reporting.

This scope is deliberately defensive and self-contained, which makes it both ethically clean
and realistically achievable for a final-year timeline at a moderate engineering skill level.

### 7.1 Positioning against existing IoT-botnet detection work

A large body of prior work already detects IoT botnets — mostly Mirai and its variants — using
machine learning on public datasets (N-BaIoT, Bot-IoT, IoT-23). A reviewer will immediately ask
how this project differs. The distinction is the detection target: **existing detectors
fingerprint the attack stage (DDoS floods, scanning, infection) or hard-coded/DGA C2, whereas
this project detects the blockchain-anchored C2 resolution and victim-relay stage — a signal
that did not exist in the traffic before late 2025 and that defeats the takedown-based defences
prior work implicitly assumes.** The central, falsifiable claim of the paper is therefore:
resolution- and relay-stage indicators add detection value that attack-stage features alone do
not provide. The ablation study is designed specifically to prove or disprove this claim.

*Note on literature verification: because this botnet was reported in July 2026, a targeted
search of Google Scholar / IEEE Xplore / arXiv for "blockchain C2 botnet detection" and
"ENS/SNS command-and-control detection" should be run before submission to confirm the gap and
to cite any concurrent work. If the resolution angle is already taken, the victim-relay
detection (§7.2) is an even newer fallback contribution.*

### 7.2 Advanced features that strengthen the contribution

Beyond the baseline detection pipeline, the following features each constitute a distinct
research contribution and are what elevate the work from a routine classifier to a selectable
paper. The two marked **(core)** are the primary novelty; the remainder add rigor.

1. **Blockchain-resolution fingerprinting (core):** characterise how ENS/SNS lookups and the
   subsequent HTTP server-list pull differ from benign Web3 / blockchain traffic (resolver
   endpoints, query timing, record-pull pattern). This specific profiling is largely unstudied.
2. **Victim-relay detection (core):** a dedicated detector for devices turned into proxy hops
   (UPnP `AddPortMapping` plus epoll-style bidirectional relaying). The relay-only variant is
   the newest behaviour in the lineage and the least studied.
3. **Concept-drift / temporal evaluation:** train on an earlier malware build and test on a
   later one to measure detector decay as the family evolves — the security analogue of the
   reference paper's covariate-shift analysis.
4. **Adversarial robustness:** test whether simple evasions (jittered beacon timing, packet
   padding) degrade detection, demonstrating the method's resilience and maturity.
5. **Early-detection metric:** measure how far in advance of the DDoS/relay stage a device can
   be flagged (in seconds or packets) — a headline, deployment-relevant result.
6. **Edge/real-time feasibility:** report inference latency and memory footprint and argue the
   detector can run on a home router or gateway, turning a lab study into a deployable defence.

**Recommended strategic selection:** use features **1 and 2** as your two novel cores, and
**ablation + concept-drift + early-detection** as your three rigor pillars.

## 8. Research Questions and Objectives

### 8.1 Research questions

1. **RQ1:** What observable network and host indicators distinguish a device resolving C2
   through blockchain name services (ENS/SNS) from benign use of the same resolvers?
2. **RQ2:** Can victim-relay behaviour (UPnP port mapping plus bidirectional traffic relaying)
   be detected reliably at the network edge without host access?
3. **RQ3:** How well does a lightweight detection model built on these indicators generalise
   across the JackSkid / Dysphoria / Kimwolf lineage, and where does it fail?
4. **RQ4 (optional, adds rigor):** How much detection performance is lost as the malware family
   evolves over time (concept drift), and under simple adversarial evasion?
5. **RQ5 (optional, adds rigor):** How early — in packets or seconds — can a device be flagged
   before it participates in DDoS or relay activity, and is inference cheap enough for edge
   deployment?

### 8.2 Objectives

| # | Objective | Success criterion |
|---|---|---|
| O1 | Characterise the C2 resolution and relay mechanisms across the lineage from public reports and samples | A documented, cited technical taxonomy with an attack/kill-chain diagram |
| O2 | Build an isolated testbed that safely reproduces blockchain-name resolution and relay traffic patterns | Reproducible lab that emits labelled benign vs. suspicious traces with no external attack capability |
| O3 | Design a detection method (heuristics + ML) over network/host indicators | Documented feature set and model with an ablation study |
| O4 | Evaluate detection accuracy and generalisation | Precision/recall/F1, ROC-AUC, and false-positive analysis on held-out traces |
| O5 | Release an open indicator dataset and pipeline | Public, documented artifact with a reproducibility README |

## 9. Related Work

The project situates itself against three bodies of work.

**First,** classical IoT botnet studies (Mirai and its many descendants) establish the
weak-credential / known-RCE infection model and the DDoS objective.

**Second,** C2-resilience research covers DGAs, fast-flux, and peer-to-peer botnets, from which
blockchain name services are the logical next step.

**Third,** recent industry reporting — Nokia Deepfield and Comcast on the JackSkid-to-ENS
fallback, XLab's Dysphoria timeline, Japan's NICT independent confirmation of the ENS/SNS shift,
and Cloudflare's DDoS measurements of the related AISURU/Kimwolf botnet — provides the primary
source material.

A recurring finding across NICT, Nokia, and Comcast is shared code and strings across several
families, which points to shared tooling rather than a single attributed operator; the project
therefore studies techniques, not attribution.

## 10. Proposed Methodology

### 10.1 System overview

The detection pipeline has four stages:

1. **Trace collection** from the isolated testbed and from public capture datasets.
2. **Feature extraction** focused on resolution and relay indicators.
3. **A two-tier detector** combining explainable heuristics with a supervised classifier.
4. **Evaluation** against held-out and cross-family traces.

### 10.2 Candidate detection indicators

| Category | Example indicators | Rationale |
|---|---|---|
| **Resolution** | Queries to ENS/SNS gateways or public blockchain RPC endpoints; HTTP pulls of a "server list" after resolution | Captures the moment a bot fetches C2 records from a blockchain name service |
| **Relay** | UPnP `AddPortMapping` requests on the local gateway; long-lived bidirectional flows with epoll-style fan-out | Identifies victim devices acting as proxy hops |
| **Infection** | Telnet/SSH login bursts against the device; scan patterns; known IoT RCE signatures | Detects the entry vector (weak credentials / known CVEs) |
| **Payload** | Custom RC4-encrypted strings; small periodic beacons | Distinguishes malware traffic from benign IoT chatter |

### 10.3 Data sources (ethically obtained)

- Public malware sample repositories and published IOCs from the cited
  CNCERT/XLab/NICT/Nokia/Comcast reports (**for static characterisation only**).
- Isolated-testbed captures generated by the student, fully air-gapped from the public
  internet's attack surface.
- Public benign IoT traffic datasets (academic IoT-traffic corpora) to model the negative class
  and measure false positives.

### 10.4 Detection model

A transparent baseline (rule-based heuristics on the indicators above) is compared against
supervised classifiers (gradient-boosted trees / compact random forest) chosen for
interpretability and low compute — appropriate for a moderate skill level and for potential edge
deployment. An optional sequence model (LSTM/1D-CNN) captures beaconing rhythm. An ablation
study quantifies each indicator group's contribution, which strengthens the paper's analytical
contribution.

## 11. Experimental Setup and Testbed

All dynamic experimentation runs inside a virtualised, network-isolated lab:

- emulated IoT devices (e.g., QEMU/OpenWrt images),
- a **local stand-in name resolver** that mimics ENS/SNS lookups **without touching real
  blockchains**,
- a controlled relay node.

This lets the project reproduce the observable traffic shapes (resolution query, server-list
pull, UPnP mapping, bidirectional relay) for labelling purposes, while guaranteeing that no
functional attack tool, live C2, or outbound DDoS capability is ever created. The testbed design
and its containment controls are themselves a documented contribution.

## 12. Ethical, Legal, and Safety Considerations

- **No offensive capability:** the project never builds, improves, or operates a working botnet,
  C2, or DDoS tool. Malware samples are handled statically or in a contained sandbox for
  analysis only.
- **Containment:** all dynamic analysis is air-gapped/virtualised; the relay and resolver are
  local stand-ins, so no traffic can reach third parties.
- **Responsible use of data:** only public IOCs and public/academic datasets are used; no
  scanning of live third-party devices and no interaction with real attacker infrastructure.
- **Attribution restraint:** consistent with the primary sources, the project studies techniques
  and does not name or accuse any operator.
- **Institutional approval:** the plan will be reviewed by the project supervisor and, where
  required, the department ethics/lab-safety process before any dynamic work begins.

## 13. Evaluation Plan

Detection performance is reported with **precision, recall, F1, and ROC-AUC**, plus a dedicated
**false-positive analysis** against benign IoT traffic (the practical barrier to deployment).
Generalisation is tested by training on one family's traces and testing on another's within the
lineage. Runtime cost (CPU/memory) is measured to assess edge feasibility. The heuristic baseline
and the ML models are compared head-to-head, and the **ablation study isolates the value of the
blockchain-resolution indicators specifically — the paper's central claim.**

## 14. Expected Contributions

1. A cited technical taxonomy of blockchain-anchored C2 and victim-relay meshes across the
   JackSkid/Dysphoria/Kimwolf lineage.
2. A reproducible, containment-safe testbed for generating labelled traces of these behaviours.
3. A detection method with an ablation study isolating the contribution of blockchain-resolution
   indicators.
4. An open, labelled indicator dataset and pipeline addressing the reproducibility gap in
   current vendor reporting.

## 15. Publication Strategy

The work is scoped to be publishable at a student-accessible venue. Realistic targets, in rough
order of accessibility, include undergraduate/student research tracks and workshops, then
regional and mid-tier security conferences. A short "systematization + small evaluation" framing
is the most reliable route to acceptance for a first paper; a strong evaluation can then justify
a fuller submission.

| Venue type | Examples of fit | Notes |
|---|---|---|
| Student / workshop tracks | IEEE/ACM student research competitions; security workshops co-located with larger conferences | Most accessible; good for a first paper and feedback |
| Regional / national conferences | Regional IEEE conferences; national cybersecurity symposia | Higher visibility; expect a full evaluation |
| Preprint + artifact | arXiv preprint with a public dataset/code release | Establishes priority and lets others reproduce your work |

**Note:** confirm current venue names, deadlines, and scope with your supervisor before
committing — venue details change year to year, and this proposal was written from a July 2026
snapshot.

## 16. Project Timeline

An indicative plan across a typical two-semester final-year schedule. Adjust to your
institution's dates.

| Phase | Duration | Key deliverables |
|---|---|---|
| Literature & scoping | Weeks 1–4 | Related-work review; finalized RQs; ethics/lab approval |
| Characterisation (O1) | Weeks 4–7 | Technical taxonomy; kill-chain diagram; IOC catalogue |
| Testbed build (O2) | Weeks 7–12 | Isolated lab; labelled trace generation |
| Detection design (O3) | Weeks 11–16 | Feature set; heuristic baseline; ML model |
| Evaluation (O4) | Weeks 16–21 | Metrics, ablation, generalisation, FP analysis |
| Artifact & paper (O5) | Weeks 20–26 | Open dataset/pipeline; paper draft; submission |

## 17. Risk Assessment and Mitigation

| Risk | Likelihood | Mitigation |
|---|---|---|
| Scarce ground-truth traces for a new family | High | Generate labelled data in the testbed; use public IOCs; frame as few-shot/heuristic-assisted |
| High false positives from benign resolver use | Medium | Dedicated FP analysis; combine resolution + relay indicators before alerting |
| Scope creep into offensive territory | Medium | Hard ethical boundary: analysis/detection only; supervisor sign-off |
| Unverifiable scale/impact claims | High | Cite as vendor/operator claims; do not present as measured results |
| Sample handling / containment failure | Low | Air-gapped VMs; local resolver/relay stand-ins; no live infrastructure |
| Topic already published by concurrent work | Medium | Run the literature check early; fall back to victim-relay detection angle |

## 18. References (starting set)

Formatted informally; convert to your required citation style. **Verify every link and detail
before submission.**

- [1] S. Khandelwal, "Dysphoria IoT Botnet Adds Blockchain C2 and Victim Relays After JackSkid
  Disruption," *The Hacker News*, Jul. 27, 2026.
- [2] XLab (Qi'anxin), "Dysphoria" analysis, `blog.xlab.qianxin.com/dysphoria/`, Jul. 25, 2026.
- [3] CNCERT, joint Dysphoria notice (mirrored at `secrss.com/articles/92461`), 2026.
- [4] Nokia Deepfield & Comcast threat lab, JackSkid ENS fallback report,
  `github.com/deepfield/public-research/blob/main/jackskid/report.md`, 2026.
- [5] NICT (Japan), "JackSkid-to-ENS/SNS shift," `blog.nicter.jp`, May 2026.
- [6] *The Hacker News*, "DoJ Disrupts 3-Million-Device IoT Botnet," Mar. 2026 (JackSkid takedown).
- [7] *The Hacker News*, "Kimwolf Botnet Hijacks 1.8M Devices," Dec. 2025 (ENS-based C2).
- [8] Cloudflare, "DDoS Threat Report 2025 Q4" (31.4 Tbps AISURU/Kimwolf measurement).
- [9] NVD, CVE-2025-9528, Linksys E1700 command injection, disclosed Aug. 2025.
- [10] M. Antonakakis et al., "Understanding the Mirai Botnet," *USENIX Security*, 2017.
- [+] **Add:** ENS/SNS technical documentation; academic surveys on DGA/fast-flux and P2P botnet
  detection; the public IoT benign-traffic datasets used for your negative class; the N-BaIoT,
  Bot-IoT, and IoT-23 dataset papers.

---

# PART III — IMPLEMENTATION AND OUTPUTS

## 19. Mapping to the Reference Paper

The sepsis RL paper is a finished, empirical study: real data, several algorithms benchmarked
against each other, concrete outputs (convergence curves, comparison tables, SHAP plots,
cross-cohort results). **This project follows the exact same pattern.** The one structural
difference is the data source: the sepsis authors downloaded ready-made labelled datasets
(MIMIC-III, eICU); we generate our labelled traffic in an isolated testbed and supplement with
public IoT datasets.

| Sepsis paper element | Our project equivalent | Same technique? |
|---|---|---|
| Data: MIMIC-III + eICU (downloaded, labelled) | Testbed-generated PCAP traces + public IoT datasets (IoT-23, Bot-IoT, N-BaIoT) | Yes — supervised labelled data |
| Action imbalance 384:1, capped inverse-frequency weighting | Benign-vs-malicious flow imbalance; class weights / SMOTE | Yes — imbalance correction |
| Benchmark 3 algorithms: FQI, DQN, CQL | Benchmark detectors: heuristic baseline, Random Forest, XGBoost, LSTM | Yes — multi-model comparison |
| Reward shaping (domain-grounded) | Feature engineering (resolution + relay indicators) | Yes — domain-grounded inputs |
| Multi-seed robustness (5 seeds) | Multi-seed training, mean ± std | Yes — identical protocol |
| Ablation study | Ablation: drop each indicator group | Yes — identical protocol |
| SHAP explainability (platelet, temp, creatinine) | SHAP on flow features (ENS-query rate, UPnP mapping, beacon interval) | Yes — same library, same idea |
| Cross-cohort generalization (MIMIC → eICU) | Cross-dataset generalization (train family A → test family B) | Yes — identical protocol |
| Off-policy value estimates | Held-out and false-positive analysis on benign traffic | Analogous — rigorous evaluation |
| Covariate shift | Concept drift across malware builds | Yes — direct analogue |

**Takeaway:** the reference paper is essentially a benchmarking study with explainability. This
project is a detection benchmarking study with explainability. The scaffolding is the same; only
the domain and the data-collection step differ.

## 20. Implementation: Stage by Stage

### Stage 1 — Data and trace generation

- Build an isolated virtual lab (VirtualBox/QEMU or GNS3) **with no route to the public
  internet**: emulated IoT devices (OpenWrt images), a local stand-in ENS/SNS resolver, and a
  controlled relay node.
- Capture all traffic with `tcpdump` / Wireshark into PCAP files while reproducing the observable
  behaviours: blockchain-name resolution query, HTTP "server-list" pull, UPnP port-mapping, and
  long-lived bidirectional relay flows.
- Add public datasets for realism and a negative class: **IoT-23, Bot-IoT, N-BaIoT, CIC-IDS** for
  benign + known-botnet traffic (Mirai-family), so the model sees real IoT noise.
- Static-only analysis of public malware samples / published IOCs to confirm which indicators to
  engineer (**no execution of live malware, no live C2**).

**Output:** a labelled corpus of PCAP files tagged benign / suspicious-resolution / relay, plus a
documented IOC catalogue. *(Parallel to the sepsis "Datasets and MDP Formulation" section.)*

### Stage 2 — Feature extraction

- Convert PCAPs to flow records using **Zeek** and/or **CICFlowMeter**; use **Scapy** for custom
  packet-level features.
- Engineer the discriminating features:
  - rate of queries to ENS/SNS gateways or blockchain RPC endpoints
  - presence of an HTTP server-list pull after resolution
  - UPnP `AddPortMapping` events
  - bidirectional flow duration and fan-out
  - beacon periodicity / inter-arrival time statistics
  - RC4-encrypted string signatures / entropy measures
  - Telnet/SSH login-burst counts

**Output:** a clean feature matrix (rows = flows/devices, columns = engineered features, plus a
label). This is the equivalent of the sepsis paper's preprocessed MDP state features.

### Stage 3 — Detection models (the benchmark)

- **Heuristic baseline:** threshold rules on the strongest indicators — transparent and
  explainable (the "FQI-like" simple baseline).
- **Random Forest and XGBoost:** interpretable, low-compute tabular classifiers (the "DQN-like"
  workhorses).
- **Optional LSTM / 1D-CNN** on flow sequences to capture beaconing rhythm (the "CQL-like" more
  powerful model).
- Handle class imbalance with class weights or SMOTE — directly parallel to the reference paper's
  capped inverse-frequency weighting.

**Output:** three-to-four trained detectors, ready for head-to-head comparison.

### Stage 4 — Evaluation, ablation, and explainability

- **Metrics:** Precision, Recall, F1, ROC-AUC, and a dedicated false-positive rate on benign
  traffic.
- **Multi-seed robustness:** repeat training over 5 seeds, report mean ± standard deviation.
- **Ablation:** remove each feature group (resolution / relay / infection / payload) and measure
  the drop — **proves which indicators matter (the paper's central claim).**
- **Cross-dataset generalization:** train on one botnet family/dataset, test on another.
- **SHAP explainability:** identify which features drive detections — the direct analogue of the
  reference paper's SHAP analysis naming platelet/temperature/creatinine.
- **Concept drift:** train on earlier build, test on later build.
- **Adversarial robustness:** jittered beacon timing, packet padding.
- **Early detection:** how many seconds/packets before the attack stage a flag is raised.
- **Edge feasibility:** inference latency and memory footprint.

**Output:** the full results set (tables + figures) listed in §21.

### Stage 5 — Analysis, artifact release, and paper

- Interpret results, discuss limitations and deployment, release the labelled dataset + code with
  a reproducibility README, and write the paper in the reference paper's structure (§29).

## 21. Concrete Outputs (what the project actually produces)

Every output below is directly analogous to a figure or table in the sepsis paper, so a reviewer
will recognise the same level of rigor.

| # | Output (figure/table) | Sepsis-paper analogue |
|---|---|---|
| 1 | System/pipeline architecture diagram | Their Figure 1 (framework overview) |
| 2 | Dataset composition table + class-imbalance ratio | Their action-imbalance (384:1) reporting |
| 3 | Model training/convergence curves | Their DQN convergence plots |
| 4 | Model comparison table (heuristic vs RF vs XGB vs LSTM): P/R/F1/AUC | Their FQI–DQN–CQL comparison |
| 5 | Multi-seed robustness table (mean ± std) | Their 5-seed robustness |
| 6 | **Ablation table (contribution of each feature group)** | Their ablation study |
| 7 | ROC and Precision–Recall curves | Their off-policy value curves |
| 8 | Confusion matrices + false-positive analysis | Their clinical-override analysis |
| 9 | **SHAP summary plot (top detection-driving features)** | Their SHAP feature-importance |
| 10 | Cross-dataset generalization matrix | Their MIMIC→eICU cross-cohort table |
| 11 | Concept-drift curve (performance vs. malware build date) | Their covariate-shift analysis |
| 12 | Adversarial robustness table | (extension beyond reference paper) |
| 13 | Early-detection lead-time distribution | (extension beyond reference paper) |
| 14 | Edge-feasibility table (latency, memory) | (extension beyond reference paper) |
| 15 | Released labelled dataset + reproducible code | Their reproducibility artifact |

## 22. Tools and Tech Stack

| Purpose | Tools |
|---|---|
| Testbed / emulation | VirtualBox or QEMU, GNS3, OpenWrt device images |
| Traffic capture | tcpdump, Wireshark |
| Feature extraction | Zeek, CICFlowMeter, Scapy, pandas |
| Modelling | scikit-learn (Random Forest), XGBoost, PyTorch (optional LSTM) |
| Imbalance handling | imbalanced-learn (SMOTE), class weights |
| Explainability | SHAP |
| Plots / reporting | Matplotlib, Seaborn |
| Public datasets | IoT-23, Bot-IoT, N-BaIoT, CIC-IDS (benign + known botnet) |
| Writing | Overleaf (free tier) or local LaTeX |
| Version control | Git + GitHub |

## 22.1 The one honest caveat

The sepsis team's biggest advantage was a large, ready-made, labelled dataset. **We do not have
that for a July-2026 botnet** — so Stage 1 (testbed trace generation) is real work and the main
risk to matching this paper's depth.

**Mitigation:** lean on established public IoT/botnet datasets for volume and the negative class,
use the testbed to synthesise the specific blockchain-C2 and relay behaviours, and **be explicit
in the paper that the blockchain-C2 traces are synthesised in a controlled lab.** Reviewers accept
synthetic/testbed data when the generation process is documented and reproducible — which is
itself a contribution.

**Bottom line:** the project is fully implementable, produces the same class of concrete outputs
as the reference paper, and fits the same section structure. The work that earns the paper is the
empirical depth — building the dataset and running the full benchmark + ablation + SHAP +
generalization suite.

---

# PART IV — FREE BUILD & AI TOOLING GUIDE

## 23. Is It Really Free? — Yes, essentially 100%

Every component of this project is free for academic use. There is no required paid cloud
service, no paid dataset, and no proprietary software. The only real costs are your time and,
optionally, a faster internet connection for downloading datasets. A mid-range laptop is enough;
a free Google Colab or Kaggle notebook covers any GPU need for the optional deep model.

## 24. Free Tools, Datasets, Compute

### 24.1 Free tools (open-source stack)

| Stage | Free tool | Cost |
|---|---|---|
| Testbed / VM emulation | VirtualBox or QEMU; GNS3; OpenWrt device images | Free / open-source |
| Traffic capture | tcpdump, Wireshark | Free / open-source |
| Flow feature extraction | Zeek, CICFlowMeter, Scapy | Free / open-source |
| Data handling | Python, pandas, NumPy | Free / open-source |
| Classical ML | scikit-learn (Random Forest), XGBoost | Free / open-source |
| Deep model (optional) | PyTorch or TensorFlow/Keras (LSTM/CNN) | Free / open-source |
| Imbalance handling | imbalanced-learn (SMOTE), class weights | Free / open-source |
| Explainability | SHAP | Free / open-source |
| Plots / figures | Matplotlib, Seaborn | Free / open-source |
| Writing / LaTeX | Overleaf (free tier), or local TeX | Free tier |
| Version control | Git + GitHub | Free |

### 24.2 Free datasets (academic use)

Use these for the benign class, for realistic IoT noise, and for known-botnet comparison;
generate the blockchain-C2 and relay traces yourself in the testbed.

| Dataset | What it gives you |
|---|---|
| IoT-23 (Stratosphere/CTU) | Labelled benign + malicious IoT captures, incl. Mirai-family |
| Bot-IoT (UNSW) | Large IoT botnet traffic dataset with attack labels |
| N-BaIoT | Benign vs. botnet (Mirai/BASHLITE) per-device features |
| CIC-IDS / CSE-CIC-IDS | General benign + attack flows for the negative class |
| MedBIoT / IoT-Flock (optional) | Additional benign IoT device traffic for realism |
| **Your testbed traces** | The novel blockchain-C2 + victim-relay behaviours (you create) |

*Always check each dataset's licence/terms and cite it. Most are free for research with
registration.*

### 24.3 Free compute

- **Local laptop:** enough for feature extraction and the Random Forest / XGBoost models.
- **Google Colab (free) or Kaggle Notebooks (free):** GPU access for the optional LSTM/CNN, with
  no setup cost.
- **GitHub Student Developer Pack** (free with a student email): extra credits and tools, though
  not required for this project.

## 25. Using Claude / Codex / Gemini Effectively

AI coding assistants are genuinely useful here and all have free tiers. Think of them as a fast
pair-programmer for the scripting-heavy stages, **not** as a replacement for understanding your
own project.

| Project stage | How the AI assistant helps | Do it yourself |
|---|---|---|
| Testbed setup | Explain VM/network config; draft UPnP and resolver stubs | Actually building & isolating the lab; safe sample handling |
| Feature extraction | Write Zeek/Scapy/CICFlowMeter parsing scripts fast | Deciding which indicators matter (your novelty) |
| Model training | Draft scikit-learn/XGBoost/PyTorch training + CV loops | Interpreting results; defending choices to your guide |
| Ablation / SHAP / plots | Generate the evaluation and plotting boilerplate | Reading the plots and writing the analysis |
| Paper writing | Improve phrasing, structure, LaTeX formatting | The actual claims, results, and honesty about limits |

### 25.1 Practical tips

- **Rotate tools** if you hit free-tier limits: use one for code drafting, another for debugging,
  another for writing. This effectively extends your free usage.
- **Give the assistant your feature list and dataset schema up front** — it produces far better
  code when it knows the exact columns and labels.
- **Always run and test AI-generated code** on a small sample before trusting it; ask the
  assistant to add comments so you can explain each step in your viva/defence.
- **Never let AI invent results or citations.** Every number in the paper must come from a run you
  actually executed, and every reference must be one you verified.

## 26. Honest Caveats

**Free to build — yes. Effortless — no.** Two parts resist automation and are where your real
effort goes:

1. the isolated testbed and safe generation of blockchain-C2 / relay traces, and
2. understanding your own results well enough to defend them.

These are also exactly where your novelty and your marks come from, so the effort is well spent.
AI assistants accelerate the surrounding code, but the scientific judgement — which indicators,
which experiments, what the results mean — must be yours.

Free-tier limits on AI tools change over time and heavy use may be throttled; plan to spread
coding work across days or across tools. None of this blocks the project — it just means pacing.

---

# PART V — AGENT-READY BUILD PLAN

> **Instructions for the AI coding agent reading this file:** Build the project described below.
> Respect the ethics boundaries in the "SCOPE AND ETHICS" section at the top of this file
> absolutely. Everything you generate must be detection/analysis code. Where this spec calls for
> a "mock resolver" or "mock relay," implement a local, isolated stand-in that only produces
> traffic *shapes* for labelling — never a functional C2 or attack tool.

## 27. Repository Layout

```
iot-blockchain-c2-detection/
├── README.md                      # setup, ethics statement, reproduction steps
├── requirements.txt
├── LICENSE
├── data/
│   ├── raw/                       # downloaded public datasets (gitignored)
│   ├── testbed/                   # your generated PCAPs (gitignored if large)
│   ├── processed/                 # feature matrices (CSV/Parquet)
│   └── README.md                  # dataset provenance + licences
├── testbed/
│   ├── README.md                  # how to build the isolated lab, containment checks
│   ├── topology.md                # network diagram + IP plan (isolated, no NAT to internet)
│   ├── mock_resolver/             # local ENS/SNS stand-in (returns fake records)
│   ├── mock_relay/                # controlled relay node (UPnP + bidirectional forward)
│   └── capture/                   # tcpdump wrapper scripts + labelling manifest
├── src/
│   ├── __init__.py
│   ├── config.py                  # paths, feature groups, seeds, hyperparameters
│   ├── extract/
│   │   ├── pcap_to_flows.py       # Zeek/CICFlowMeter wrapper
│   │   ├── features_resolution.py # ENS/SNS query + server-list-pull features
│   │   ├── features_relay.py      # UPnP mapping + bidirectional/fan-out features
│   │   ├── features_infection.py  # telnet/ssh bursts, scan patterns
│   │   ├── features_payload.py    # entropy/RC4-ish signatures, beacon periodicity
│   │   └── build_matrix.py        # merge into labelled feature matrix
│   ├── models/
│   │   ├── heuristic.py           # transparent threshold baseline
│   │   ├── tree_models.py         # RandomForest, XGBoost
│   │   ├── sequence_model.py      # optional LSTM/1D-CNN
│   │   └── train.py               # unified training entrypoint, multi-seed
│   ├── evaluate/
│   │   ├── metrics.py             # P/R/F1/AUC, FPR on benign
│   │   ├── ablation.py            # drop-one-feature-group study  ← MOST IMPORTANT
│   │   ├── cross_dataset.py       # train on A, test on B
│   │   ├── concept_drift.py       # train early build → test later build
│   │   ├── adversarial.py         # jitter/padding perturbations
│   │   ├── early_detection.py     # lead-time before attack stage
│   │   ├── edge_cost.py           # latency + memory footprint
│   │   └── explain_shap.py        # SHAP summary + per-feature importance
│   └── viz/
│       ├── plot_curves.py         # ROC, PR, convergence
│       ├── plot_confusion.py
│       └── plot_shap.py
├── experiments/
│   ├── run_all.sh                 # reproduce every result end-to-end
│   └── configs/                   # one YAML per experiment
├── results/
│   ├── figures/                   # all output figures (PNG/PDF)
│   └── tables/                    # all output tables (CSV + LaTeX)
├── notebooks/
│   └── exploration.ipynb
└── paper/
    ├── main.tex
    ├── sections/                  # one .tex per section (see §29)
    └── refs.bib
```

## 28. Build Milestones with Acceptance Criteria

### Milestone 1 — Environment and data foundation
**Build:** `requirements.txt`, `src/config.py`, dataset download/verification scripts,
`data/README.md` documenting provenance and licences.
**Accept when:** a single command sets up the environment; public datasets download and verify by
checksum; config centralises all paths, seeds, and the four feature-group definitions.

### Milestone 2 — Isolated testbed
**Build:** `testbed/` — topology doc, mock ENS/SNS resolver (returns canned records for canned
names), mock relay node (UPnP `AddPortMapping` + bidirectional forwarding), capture scripts with a
labelling manifest.
**Accept when:** the lab has **no route to the public internet** (documented containment check);
running the capture scripts produces labelled PCAPs for each behaviour class:
`benign`, `resolution`, `relay`.

### Milestone 3 — Feature extraction pipeline
**Build:** `src/extract/*` — PCAP→flow conversion plus the four feature modules, merged by
`build_matrix.py` into a labelled matrix.
**Accept when:** `python -m src.extract.build_matrix` turns any PCAP directory into a
`processed/*.parquet` feature matrix with a documented schema, and each feature group can be
selected/deselected by name (required for ablation).

### Milestone 4 — Models and imbalance handling
**Build:** `src/models/*` — heuristic baseline, RandomForest, XGBoost, optional LSTM; class
weights and SMOTE options; multi-seed training (5 seeds).
**Accept when:** `python -m src.models.train --model {heuristic,rf,xgb,lstm} --seeds 5` trains and
persists models plus per-seed metrics, and reports the class-imbalance ratio of the dataset.

### Milestone 5 — Evaluation suite
**Build:** `src/evaluate/*` — metrics, **ablation**, cross-dataset, concept-drift, adversarial,
early-detection, edge-cost, SHAP.
**Accept when:** each script writes a CSV to `results/tables/` and (where applicable) a figure to
`results/figures/`. **The ablation must report per-feature-group performance deltas** — this is the
central claim of the paper.

### Milestone 6 — Figures, reproduction, and artifact
**Build:** `src/viz/*`, `experiments/run_all.sh`, README with reproduction steps and the ethics
statement.
**Accept when:** `bash experiments/run_all.sh` regenerates every table and figure in §21 from raw
data, and the README lets a stranger reproduce it.

### Milestone 7 — Paper
**Build:** `paper/` in the 13-section structure of §29, with results auto-pulled from
`results/tables/`.
**Accept when:** every number in the paper traces to a file in `results/`, every citation is
verified, and vendor scale claims are explicitly labelled as claims.

## 29. Paper Skeleton (13-section journal format)

Mirrors the reference sepsis paper's structure so reviewers see familiar rigor.

1. **Introduction** — IoT botnets; takedown as the classic defence; the JackSkid→Dysphoria
   pivot; blockchain C2 breaks seizure; the detection gap; contributions list.
2. **Related Work**
   - 2.1 IoT botnets and the Mirai lineage
   - 2.2 C2 resilience: DGA, fast-flux, P2P
   - 2.3 Blockchain/decentralised-name-service abuse
   - 2.4 ML-based IoT botnet detection (and **why it doesn't cover this** — §7.1)
   - 2.5 Explainability in security ML
   - 2.6 Datasets for IoT botnet research
3. **Research Questions** — RQ1–RQ5 (§8.1)
4. **Problem Formulation: Threat Model and Data**
   - 4.1 Threat model (attacker capabilities, defender vantage point)
   - 4.2 Blockchain-anchored C2 resolution flow
   - 4.3 Victim-relay mesh
   - 4.4 Datasets (public + testbed) and labelling
5. **Methodology**
   - 5.1 Feature groups: resolution / relay / infection / payload
   - 5.2 Heuristic baseline
   - 5.3 Tree ensembles (RF, XGBoost)
   - 5.4 Optional sequence model
   - 5.5 Class-imbalance correction
   - 5.6 Evaluation metrics
   - 5.7 SHAP explainability
6. **Experimental Setup** — testbed and containment; preprocessing; hyperparameters;
   multi-seed protocol; ablation configuration; compute resources.
7. **Results**
   - 7.1 Dataset composition and imbalance
   - 7.2 Model comparison (P/R/F1/AUC)
   - 7.3 Multi-seed robustness
   - 7.4 **Ablation: contribution of resolution/relay features** ← headline
   - 7.5 ROC/PR curves and confusion matrices
   - 7.6 False-positive analysis on benign traffic
   - 7.7 Cross-dataset generalization
   - 7.8 Concept drift across builds
   - 7.9 Adversarial robustness
   - 7.10 Early-detection lead time
   - 7.11 SHAP explainability
8. **Discussion** — why resolution-stage detection works; the benign-Web3 confusion problem;
   what generalises and what doesn't; deployment implications.
9. **Deployment Considerations** — edge feasibility; ISP/gateway vantage points; operator
   workflow; ethical use.
10. **Sensitivity Analysis** — thresholds, window sizes, feature-set granularity, normalisation.
11. **Limitations** — synthetic/testbed traces; no live-botnet ground truth; unverified vendor
    scale claims; single-lab validation.
12. **Future Work** — real-world validation with an ISP partner; multi-family extension;
    online/streaming detection; blockchain-side monitoring.
13. **Conclusion** — restate the central claim and the evidence for it.

---

## FINAL CHECKLIST BEFORE YOU SUBMIT

- [ ] **Every threat fact fact-checked against the original article and vendor reports (see
      SOURCE-PROVENANCE WARNING at the top). Names, dates, domains, CVE, and scale figures in
      this spec are UNVERIFIED.**
- [ ] Literature check run (§2.2) — confirm no concurrent publication on this exact angle.
- [ ] Supervisor + ethics/lab-safety approval obtained before dynamic work.
- [ ] Every vendor scale claim labelled as a claim, never as your measurement.
- [ ] Ablation study clearly proves resolution/relay features add value (§3.4).
- [ ] Every number in the paper traces to a file in `results/`.
- [ ] Every citation verified — no AI-invented references.
- [ ] Dataset + code released with a reproducibility README.
- [ ] Containment documented: no route to public internet, no live C2, no real attacker domains.
- [ ] Venue name, deadline, and formatting requirements confirmed with supervisor.

---

*End of specification. This file is self-contained: it needs no other document to be understood
or acted upon.*
