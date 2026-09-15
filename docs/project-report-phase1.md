# EVALUATING BLOCKCHAIN-RESOLUTION AND VICTIM-RELAY INDICATORS FOR IoT BOTNET DETECTION

**PROJECT PHASE I (REVIEW 1)**

Submitted by

**SHIVRAJ R — 212223110051**

in partial fulfillment for the award of the degree of

**BACHELOR OF ENGINEERING**

in

**COMPUTER SCIENCE AND ENGINEERING (INTERNET OF THINGS)**

SAVEETHA ENGINEERING COLLEGE, THANDALAM
An Autonomous Institution Affiliated to
ANNA UNIVERSITY — CHENNAI 600 025

DECEMBER 2026

---

## ABSTRACT

Internet of Things devices such as cameras, routers, digital video recorders and set-top boxes are deployed in enormous numbers, are frequently shipped with default credentials, and are rarely patched after installation. These properties have made them the preferred recruitment pool for large botnets. Detection of such compromise has traditionally depended on recognising known command-and-control servers, observing scanning behaviour, or measuring the distributed denial-of-service traffic that a device emits after it has already been enlisted. Each of these signals arrives late in the compromise lifecycle, and each depends on infrastructure that a coordinated takedown can remove. Recent threat-intelligence reporting describes botnet families that resolve their control infrastructure through blockchain name services rather than conventional domain names, and that convert infected victims into relay nodes which conceal the true controller. Where such techniques are used, the single blockable domain that most detection strategies rely upon no longer exists.

This project evaluates whether two behavioural indicator groups derived from authorised network telemetry — blockchain-resolution indicators and victim-relay indicators — provide measurable detection value beyond the conventional infection and payload indicators already used in IoT botnet detection. Network observations are aggregated into device-observation windows of three hundred seconds, from which sixteen features across four groups are derived. A transparent rule-voting baseline is compared against Random Forest and Extreme Gradient Boosting classifiers under a common false-positive budget, and the specific contribution of the two novel groups is isolated through an incremental-value experiment in which feature sets are built upward from a conventional base rather than removed from a complete set. Decision thresholds are calibrated on a validation partition and locked before the test partition is scored.

The work is defensive in scope throughout. No botnet, command-and-control server, scanner, exploit or relay capability is constructed, and no real attacker infrastructure is contacted at any point. Analysis is performed on public academic datasets, on network traffic the author is authorised to monitor, and on packets generated within a strictly isolated virtual laboratory whose services reproduce the observable signatures of the reported behaviours without reproducing their capability. Features that cannot be measured from a given telemetry source are recorded as missing rather than substituted with zero, and the detector abstains rather than guessing when evidence is insufficient. The central research question is one of measurement rather than assertion: should the two indicator groups prove to add no distinguishable value once conventional features are already available, that negative result will be reported as the finding of the study.

---

## LIST OF ABBREVIATIONS

| Abbreviation | Expansion |
|---|---|
| ADB | Android Debug Bridge |
| C2 | Command and Control |
| CI | Confidence Interval |
| CNCERT | National Computer Network Emergency Response Technical Team (China) |
| DDoS | Distributed Denial of Service |
| DNS | Domain Name System |
| DoH | DNS over HTTPS |
| ENS | Ethereum Name Service |
| FPR | False Positive Rate |
| IoT | Internet of Things |
| JSON-RPC | JavaScript Object Notation Remote Procedure Call |
| ML | Machine Learning |
| NAT | Network Address Translation |
| NICT | National Institute of Information and Communications Technology (Japan) |
| PCAP | Packet Capture |
| RCE | Remote Code Execution |
| RF | Random Forest |
| ROC-AUC | Receiver Operating Characteristic — Area Under Curve |
| SNI | Server Name Indication |
| SNS | Solana Name Service |
| SOAP | Simple Object Access Protocol |
| SSDP | Simple Service Discovery Protocol |
| TLS | Transport Layer Security |
| UPnP | Universal Plug and Play |
| XGBoost | Extreme Gradient Boosting |

---

## TABLE OF CONTENTS

| CHAPTER NO | TITLE | PAGE NO |
|---|---|---|
| 1 | Introduction | 1 |
| 2 | Problem Definition | 3 |
| 2.1 | Existing System | 5 |
| 2.1.1 | Understanding the Mirai Botnet | 7 |
| 2.1.2 | N-BaIoT: Network-Based Detection of IoT Botnet Attacks Using Deep Autoencoders | 9 |
| 2.1.3 | IoT-23: A Labeled Dataset with Malicious and Benign IoT Network Traffic | 11 |
| 2.1.4 | Blockchain-Based Command-and-Control Resolution and Victim-Relay Infrastructure | 13 |
| 2.1.5 | Literature Survey Summary | 15 |
| 2.2 | Scope of the Project | 17 |
| 2.3 | Proposed System | 19 |
| 3 | System Analysis and Design | 22 |
| | References | 25 |

---

## 1. INTRODUCTION

The Internet of Things has placed an enormous quantity of network-connected computing devices into homes, offices and industrial premises. Cameras, routers, digital video recorders, network-attached storage units and television set-top boxes are manufactured at low cost and high volume, and their security properties reflect that economic reality. Many ship with default administrative credentials, expose remote management services to the public internet, and receive no firmware updates after the point of sale. Individually each device is of little value to an attacker. Collectively they represent a large, persistently available and poorly monitored pool of computing and bandwidth resources, and they have been recruited into botnets on a scale that conventional computing platforms have rarely matched.

Detection of such compromise has conventionally relied upon three categories of evidence. The first is knowledge of command-and-control infrastructure, in which traffic to a known malicious domain or address is treated as an indicator of infection. The second is scanning behaviour, in which a compromised device attempting to propagate to further victims reveals itself through connection attempts across many destinations and ports. The third is attack traffic itself, in which a device participating in a distributed denial-of-service campaign is identified by the volume and shape of the packets it emits. Each of these signals is genuine and each is useful, but each shares a common weakness: it appears comparatively late. Scanning and attack traffic occur only after compromise is complete, and knowledge of control infrastructure depends upon that infrastructure having been previously identified and catalogued.

The reliance on known infrastructure carries a further consequence. If detection and mitigation both depend upon the ability to identify and block a domain name, then the operator of a botnet has a strong incentive to remove that single point of failure. Recent threat-intelligence reporting describes exactly this adaptation. Following a coordinated international law-enforcement action against several large IoT botnets in March 2026, analysis published independently by the Nokia Deepfield Emergency Response Team with the Comcast Threat Research Lab, by the National Institute of Information and Communications Technology in Japan, and jointly by the National Computer Network Emergency Response Technical Team of China with the Qi'anxin X Laboratory, documented families whose successors resolve control infrastructure through blockchain name services rather than through the conventional domain name system. The same reporting describes a second adaptation in which infected devices are converted into relay nodes, so that the addresses exposed to the wider botnet population are those of other victims rather than those of the true controller.

Two behavioural consequences follow from these techniques, and they form the subject of this project. The first is a resolution behaviour: a device that obtains its control address from a decentralised naming system must contact the services that mediate access to that system, and must subsequently retrieve infrastructure information before it can communicate with a controller. The second is a relay behaviour: a device acting as a traffic relay exhibits a traffic profile unlike that of either an ordinary client or an attacking bot, characterised by persistent bidirectional flows, approximate symmetry between transmitted and received volumes, and attempts to establish inbound reachability through automated port mapping on the local gateway.

This project asks whether these two behaviours, expressed as measurable features over authorised network telemetry, add detection value beyond the conventional indicators that are already available. The question is deliberately posed as an evaluation rather than as an assertion. A feature group that appears intuitively meaningful may nonetheless contribute nothing once conventional indicators are present, and the correct response to that outcome is to report it rather than to conceal it. The remainder of this report defines the problem precisely, surveys the existing literature and its limitations, establishes the scope and boundaries of the work, and describes the proposed system and its requirements.

---

## 2. PROBLEM DEFINITION

IoT botnet detection systems must identify compromised devices from network observations alone, because the devices themselves typically cannot host security agents, cannot be inspected, and in many cases cannot even be enumerated by their owners. The evidence available to such a system is therefore restricted to the metadata of the traffic that a device generates. Within that constraint, existing detection approaches depend heavily upon indicators that appear only after compromise has succeeded, or upon prior knowledge of the specific infrastructure an attacker is using. Both dependencies limit how early and how reliably a compromise can be identified.

The adoption of decentralised name resolution for control infrastructure weakens the second dependency in particular. When a botnet resolves its controller through a blockchain naming service, there is no registrar to serve a takedown notice upon, no authoritative nameserver to seize, and no single record whose removal disables the population. Blocking the resolution mechanism wholesale is not straightforward either, because the services that mediate access to blockchain name records are ordinary commercial infrastructure used by legitimate software. The detection problem therefore shifts from recognising a known bad destination to recognising an anomalous *pattern of behaviour* in a device that has no legitimate reason to exhibit it.

The conversion of victims into relay nodes weakens detection in a different manner. A detector tuned to identify attack traffic will not flag a device whose role in the botnet is to forward traffic on behalf of others, because such a device emits no attack traffic at all. Its network profile more closely resembles that of a busy but benign host. Reporting on the relay-only variants of the families concerned describes builds from which the denial-of-service modules have been removed entirely, leaving only the forwarding function and the mechanism used to make the device reachable from outside the local network.

There is, however, a prior problem that must be solved before either behaviour can be evaluated at all, and it is a problem of telemetry rather than of algorithms. A connection log records which endpoints communicated, for how long, and how many bytes and packets were exchanged. It does not record what name was resolved, what protocol was spoken above the transport layer, or what service discovery messages were exchanged on the local network. The behaviours described above are expressed precisely in those layers. Consequently, a detection pipeline that consumes connection records alone cannot observe the resolution behaviour under investigation, regardless of the sophistication of the model applied to it. Any honest evaluation of these indicator groups must therefore begin by specifying the telemetry required to observe them, and must record features that a given source cannot supply as missing rather than as zero.

---

### 2.1 EXISTING SYSTEM

Existing approaches to IoT botnet detection fall broadly into two categories. The first is signature and reputation based. Traffic is compared against lists of known malicious addresses, domains and payload patterns, and a match is treated as evidence of compromise. This approach is precise when the underlying intelligence is current, imposes low computational cost, and produces explanations that an analyst can act upon immediately. Its weakness is structural: it can only recognise infrastructure that has already been observed and catalogued elsewhere, and it therefore offers no protection during the period between the emergence of new infrastructure and its documentation. Where infrastructure rotates rapidly, or where it is resolved through a mechanism that does not produce a stable, blockable identifier, the approach degrades further.

The second category is behavioural and statistical. Features are derived from flow records or packet captures and supplied to machine-learning models trained to distinguish benign from malicious hosts. This approach generalises beyond specific infrastructure and can identify previously unseen variants whose behaviour resembles that of known families. Published work in this category has demonstrated strong results on public datasets using both classical ensemble methods and deep architectures. Its weaknesses are equally well documented: models trained on one capture environment frequently fail to transfer to another, evaluation protocols that split data randomly rather than by device produce optimistic results that do not survive deployment, and the features that drive the classification are often opaque to the analyst who must act on the alert.

A third and more fundamental limitation affects both categories, and it concerns the data available for evaluation rather than the methods themselves. The public datasets on which IoT botnet detection research is predominantly conducted were captured before the techniques described in Chapter 1 were in use. They contain conventional botnet behaviour of high quality and genuine provenance, and they are entirely appropriate for evaluating conventional detection. They do not, however, contain blockchain-resolution or victim-relay behaviour, and they carry no labels for it. Research that claims to evaluate such indicators on these datasets is therefore evaluating something else.

A fourth limitation is the one identified at the end of the preceding section, and it is the one this project treats as decisive. The most widely used distribution of the principal public IoT dataset supplies connection logs only. Detection pipelines built upon it inherit the assumption that connection records are the available telemetry. Under that assumption, the features corresponding to name resolution, to service-discovery-based port mapping, and to payload content are not merely difficult to compute — they are undefined, and any pipeline that reports a value for them is reporting a fabrication. A detection system constructed on this basis may function correctly as a conventional botnet triage tool while being structurally incapable of assessing the hypothesis it was built to test.

In summary, the existing systems provide a sound foundation for conventional IoT botnet detection and a well-developed methodology for evaluating it. What they do not provide is either the telemetry or the labelled data necessary to determine whether blockchain-resolution and victim-relay indicators contribute additional detection value. Establishing both, under strict defensive constraints and without presenting synthetic data as evidence, is the problem this project addresses.

---

#### 2.1.1 UNDERSTANDING THE MIRAI BOTNET

The study by Antonakakis and colleagues, presented at the USENIX Security Symposium in 2017, remains the foundational empirical account of large-scale IoT botnet behaviour. The authors combined network telescope observations, active internet-wide scanning, passive domain name system measurements, and analysis of the leaked source code to reconstruct the growth, composition and operational behaviour of the Mirai botnet across its lifetime. The resulting picture is unusually complete: it establishes how the population expanded, which device classes were recruited, how the control infrastructure was organised, and how the family fragmented into variants after publication of its source code.

The mechanism the paper documents is directly relevant to the present work. Mirai propagated through brute-force authentication against Telnet services using a compact embedded credential list, and it located victims through high-rate scanning of the address space. Both behaviours are observable in network metadata without payload inspection, and both have accordingly become standard features in IoT botnet detection. The infection and scanning indicators used in this project derive from precisely this lineage. The paper also establishes the operational significance of the recruitment vector, showing that a small credential list was sufficient to compromise a population numbering in the hundreds of thousands.

The paper's treatment of command-and-control infrastructure is equally significant, though for a different reason. Mirai bots resolved their controller through the conventional domain name system, and the authors were able to track the botnet's evolution partly because that resolution was observable and the domains were enumerable. This property — that the control channel produces a stable, observable, blockable identifier — underpins a substantial proportion of subsequent detection and mitigation work. It is exactly this property that the families described in the recent threat-intelligence literature have set out to remove, and the contrast between the two situations motivates the research question addressed here.

The principal limitation of the study, from the perspective of this project, is temporal rather than methodological. The measurement was conducted in an era in which conventional control infrastructure was universal, and the analytical techniques it validates assume that such infrastructure exists to be observed. The study therefore establishes an authoritative baseline for conventional IoT botnet behaviour and detection, and simultaneously delimits the boundary beyond which that baseline may no longer apply.

#### 2.1.2 N-BaIoT: NETWORK-BASED DETECTION OF IoT BOTNET ATTACKS USING DEEP AUTOENCODERS

Meidan and colleagues, publishing in IEEE Pervasive Computing in 2018, addressed the problem of detecting compromised IoT devices from network behaviour without prior knowledge of the attacking family. Their method trains a deep autoencoder on statistical features extracted from the traffic of each device while it is known to be operating normally. Because the autoencoder learns to reconstruct only the behaviour it has observed during training, an elevated reconstruction error on subsequent traffic indicates that the device has begun behaving in a manner inconsistent with its established profile, and is treated as an indication of compromise.

The design has two properties that are directly instructive for the present work. The first is that a per-device model captures the fact that IoT devices are highly stereotyped: a camera that ordinarily contacts a single cloud endpoint at regular intervals has a far narrower behavioural envelope than a general-purpose computer, and departures from that envelope are correspondingly informative. The second is that training exclusively on benign traffic removes the requirement for labelled malicious examples, which is valuable precisely because such labels are scarce and, for novel techniques, absent altogether. The authors evaluated the approach against commercial IoT devices infected with real Mirai and BASHLITE samples in a controlled environment and reported high detection rates with low false-positive rates.

The limitations of the approach are also instructive. Anomaly detection identifies departure from a learned norm, but it does not identify the *nature* of that departure. A device that begins behaving unusually because of a firmware update, a change in usage pattern, or a network reconfiguration produces the same signal as one that has been compromised, and the model provides no evidence with which an analyst can distinguish the two. The approach additionally requires a clean training period per device, which is difficult to guarantee in a deployment where compromise may predate monitoring.

For this project, the study establishes both a methodological precedent and a design constraint. It demonstrates that behavioural network features derived from ordinary traffic metadata are sufficient to detect IoT compromise, which supports the feasibility of the present approach. It simultaneously motivates the decision to employ a transparent rule-voting detector alongside the machine-learning models, so that every alert the system produces can be expressed as the specific conditions that generated it rather than as an unexplained deviation score.

#### 2.1.3 IoT-23: A LABELED DATASET WITH MALICIOUS AND BENIGN IoT NETWORK TRAFFIC

The IoT-23 dataset, released by Garcia and colleagues at the Stratosphere Laboratory of the Czech Technical University in 2020, is among the most widely used resources for IoT botnet detection research. It comprises twenty-three captures, twenty of which record devices deliberately infected with real malware samples and three of which record genuine benign IoT device traffic. Captures were produced in a controlled environment with unrestricted network access, so that the recorded malware behaviour reflects genuine operation rather than a constrained approximation. Labels are supplied at flow granularity, and the dataset is distributed both as raw packet captures and as processed connection logs.

The dataset's principal contribution is the provision of real, labelled IoT malware traffic at a scale suitable for supervised learning. Prior work in the field was frequently constrained to synthetic traffic or to small captures of limited diversity, and the availability of IoT-23 substantially improved the empirical basis for the field. Its benign captures are equally valuable, since a realistic estimate of the false-positive rate on genuine IoT traffic is often more operationally important than a marginal improvement in recall.

Two characteristics of the dataset are decisive for the design of the present project. The first is temporal: the captures date from 2018 to 2019 and therefore predate blockchain-based control resolution entirely. The dataset contains no examples of the behaviour this project investigates and carries no labels for it. Any claim that the novel indicator groups have been validated on IoT-23 would be unsupportable, and the dataset's role in this work is correspondingly restricted to validating the processing pipeline on real labelled data and to measuring the false-positive rate on real benign IoT traffic.

The second characteristic concerns distribution format, and it is the observation that shaped the telemetry design described in Section 2.3. The dataset is published in two forms: a complete distribution that includes the original packet captures, and a lighter distribution that includes only the labelled connection logs. Research conducted on the lighter distribution inherits connection records as the only available telemetry, and therefore cannot compute any feature that depends on name resolution, application-layer protocol, or local service discovery. Because the complete distribution retains the packet captures, those captures may be reprocessed locally to regenerate the full set of protocol logs, restoring the visibility that the lighter distribution discards. This project uses the complete distribution for that reason.

#### 2.1.4 BLOCKCHAIN-BASED COMMAND-AND-CONTROL RESOLUTION AND VICTIM-RELAY INFRASTRUCTURE

A body of threat-intelligence reporting published during 2026 documents the specific techniques that motivate this project. The Nokia Deepfield Emergency Response Team, working with the Comcast Threat Research Lab, published a detailed reverse-engineering analysis of a Mirai-derived family in March 2026, based on examination of more than eighty samples spanning thirteen build generations. Their analysis documents a layered encryption architecture, control-domain rotation on an approximately fortnightly cadence, resolution of control domains through DNS over HTTPS in order to evade plaintext monitoring, and — following the law-enforcement disruption of March 2026 — a rapid migration to control-address resolution through the Ethereum Name Service. In May 2026, the analysis team at Japan's National Institute of Information and Communications Technology independently reported the same migration in the same lineage, and additionally documented the extension of the technique to the Solana Name Service. In July 2026, the National Computer Network Emergency Response Technical Team of China and the Qi'anxin X Laboratory jointly published an analysis of a successor family, describing both the blockchain resolution mechanism and the conversion of infected hosts into relay nodes.

The technical detail supplied by the Japanese analysis is of particular importance to the feature design adopted in this project. That report states explicitly that the malware does not participate in the Ethereum peer-to-peer network in order to resolve a name. Instead it issues a remote procedure call, formatted as JSON and transported over HTTPS, to one of a small number of commercial gateway services that mediate access to the blockchain, and it retrieves a text record from which the true control address is subsequently decoded. This is a materially different observable from a conventional name lookup: it appears not as a query in a resolver log but as an encrypted session to a specific and enumerable set of service hostnames. The distinction determines which telemetry must be collected in order to observe the behaviour at all, and it is the basis of the resolution features specified in Section 2.3.

The Chinese analysis supplies complementary detail concerning the relay behaviour. It describes a variant from which the denial-of-service modules have been removed entirely, whose sole function is to forward traffic. Upon execution, the sample searches the local network for a gateway supporting Universal Plug and Play and requests port mappings in order to make itself reachable from outside the network address translation boundary. It then forwards traffic bidirectionally between an external connection and a remote controller using non-blocking asynchronous input and output, and reports its availability periodically to a collection endpoint as a small structured status message. Each of these steps produces an observable network signature that is distinct from ordinary client behaviour, and together they define the relay indicator group.

Two cautions must accompany the use of this material, and both are observed throughout this project. The first is that these are vendor and national-agency reports rather than peer-reviewed publications, and their quantitative claims — population sizes, attack capacities and infection counts — have not been independently reproduced. They are cited in this work as reported claims and never as measurements of this project. The second is a specific and instructive inconsistency: the Chinese agency and the laboratory that co-authored the same joint research published materially different enumerations of the vulnerabilities exploited by the family, with fewer than half of the entries appearing in both lists. The behavioural descriptions across all sources are consistent and mutually corroborating; the vulnerability enumerations are not. This project therefore treats the described behaviours as a reliable specification of what to measure, while treating enumerations and scale figures as unverified.

#### 2.1.5 LITERATURE SURVEY SUMMARY

| S.No | Research | Technique | Features Used | Domain | Advantage / Disadvantage | Future Direction |
|---|---|---|---|---|---|---|
| 1 | Antonakakis et al., 2017 | Longitudinal empirical measurement combining network telescope, active scanning and passive DNS | Telnet credential brute-force attempts, scan rate, destination diversity, DNS-based C2 resolution | IoT botnet measurement and characterisation | Advantage: authoritative, multi-source empirical account of IoT botnet growth and structure. Disadvantage: assumes conventional, enumerable DNS-based control infrastructure | Extension of measurement methodology to families whose control channel does not produce a stable, blockable identifier |
| 2 | Meidan et al., 2018 | Per-device deep autoencoder trained on benign traffic; reconstruction error as anomaly score | Statistical traffic-stream features over multiple time windows | Network-based IoT compromise detection | Advantage: requires no labelled malicious data and generalises to unseen families. Disadvantage: signals deviation without explaining it; requires a guaranteed-clean training period per device | Combination of anomaly scoring with explainable indicators so that alerts carry actionable evidence |
| 3 | Garcia et al., 2020 | Controlled infection of real devices with real malware; flow-level labelling of captured traffic | Zeek connection records with per-flow labels; raw packet captures in the full distribution | Labelled dataset provision for IoT botnet research | Advantage: real, labelled, large-scale IoT malware traffic with genuine benign controls. Disadvantage: captured 2018–2019, predates blockchain-based C2 and contains no labels for it; the widely used lighter distribution omits packet captures | Reprocessing of the full-distribution captures to regenerate application-layer logs; construction of datasets covering contemporary resolution techniques |
| 4 | Nokia Deepfield and Comcast, 2026; NICT, 2026; CNCERT and Qi'anxin X Lab, 2026 | Reverse engineering of samples; independent corroboration across three laboratories | ENS and SNS resolution via JSON-RPC over HTTPS to named gateway services; HTTP retrieval of infrastructure lists; UPnP port mapping; bidirectional relay forwarding; periodic status reporting | Contemporary IoT botnet threat intelligence | Advantage: detailed, mutually corroborating specification of the observable behaviour, sufficient to define detection features. Disadvantage: vendor and agency reporting rather than peer-reviewed; quantitative claims unreproduced; vulnerability enumerations inconsistent between co-publishers | Independent measurement of whether the described behaviours are separable from benign traffic, and at what false-positive cost |

---

### 2.2 SCOPE OF THE PROJECT

The scope of this project is the design, implementation and evaluation of a defensive analysis pipeline that ingests authorised network telemetry, derives behavioural features over device-observation windows, applies both transparent and machine-learning detectors, and measures whether blockchain-resolution and victim-relay indicator groups contribute detection value beyond conventional indicators. The unit of analysis is one device observed over one window of three hundred seconds. Sixteen features are derived across four groups: infection, payload, blockchain-resolution and victim-relay. The first two constitute the conventional baseline against which the latter two are measured.

The project encompasses the ingestion layer required to obtain the necessary telemetry. Because the resolution behaviour under investigation is expressed in name resolution, application-layer protocol and local service-discovery messages rather than in connection records, the pipeline processes a complete set of protocol logs rather than connection logs alone. Packet captures from the public dataset are reprocessed locally to generate these logs, and the ingestion layer normalises the resulting records into a single validated observation schema irrespective of their source.

Three sources of real network data are within scope. The first is the public IoT-23 dataset, used in its complete distribution so that packet captures are available for local reprocessing; its role is to validate the pipeline on real labelled data and to establish conventional-botnet controls and false-positive rates on genuine benign IoT traffic. The second is traffic captured from a network the author owns and is authorised to monitor, providing an independent estimate of the false-positive rate on real benign traffic. The third is a strictly isolated virtual laboratory, described below, in which the behaviours under investigation can be observed with ground-truth labels.

The laboratory is within scope subject to institutional approval, and its design is governed by a single principle: it generates the observable signature of a reported behaviour without generating the capability that makes that behaviour harmful. A service reproduces the network appearance of a blockchain gateway without contacting any blockchain. A gateway service accepts a port-mapping request, records it and returns success without opening any port. A forwarding component operates between two fixed addresses within an internal virtual network that has no route to the internet. Isolation is structural rather than procedural: the virtual network provides no address translation adapter and no bridge to the host network.

The evaluation methodology is within scope and is fixed before results are examined. Data are partitioned such that no device contributes to more than one partition, preventing a model from recognising individual devices rather than behaviours. Decision thresholds are calibrated on a validation partition under a stated false-positive budget and locked before the test partition is scored. Performance is reported as precision, recall, F1-score, false-positive rate and area under the receiver operating characteristic curve, accompanied by confidence intervals obtained by bootstrap resampling at the device level. The contribution of the two novel groups is isolated by constructing feature sets upward from the conventional base rather than by removing groups from a complete set, because removal of a redundant but informative group is indistinguishable from removal of an uninformative one.

Several matters are explicitly outside the scope of this work, and the boundary is a security boundary rather than a matter of convenience. No botnet, command-and-control server, denial-of-service capability, scanner, exploit or malware is constructed, operated or simulated. No functional relay or proxy is created, and no port mapping is performed against any real gateway. No blockchain name is resolved, no remote procedure call is issued to any blockchain gateway service, and no address, domain or sample identified in the threat-intelligence literature is contacted, resolved or executed. No device is scanned or probed. Indicators of compromise appear in this work only as inert text within documentation.

Finally, the reporting standard is within scope. Features that a telemetry source cannot supply are recorded as missing and are never replaced by a substitute value, since zero is frequently the most suspicious value such a feature can take and substituting it would fabricate evidence. Where evidence is insufficient the detector abstains rather than assigning a class. Results obtained from laboratory-generated traffic are reported as such and are never presented as operational detection performance. Should the novel indicator groups prove to add no distinguishable value, that outcome is reported as the finding of the study rather than adjusted until a more favourable result is obtained.

---

### 2.3 PROPOSED SYSTEM

The proposed system is a staged analysis pipeline. Authorised telemetry enters an ingestion layer which parses protocol logs, identifies the devices under observation, normalises the direction of each record so that measurements are expressed consistently from the device's perspective, and emits a validated observation frame. A windowing stage aggregates records into device-observation windows of three hundred seconds. A derivation stage computes the sixteen features from the windowed records and annotates each window with quality flags recording low record counts, short observation spans, approximated features and missing values. A detection stage applies the configured detectors, and an evaluation stage measures performance under the fixed protocol described in Section 2.2.

The feature catalogue comprises four groups. The infection group measures compromise and propagation behaviour through login-burst counts against remote-administration ports, outbound connection rate, destination-port diversity and the proportion of failed connections. The payload group measures timing and traffic-shape characteristics through beacon interval, beacon jitter and mean packet size. The blockchain-resolution group measures the rate of contact with blockchain gateway services, the proportion of a device's sessions directed to such services, the entropy of resolved names, and the retrieval of an infrastructure list following a resolution event. The victim-relay group measures bidirectional flow duration, the number of distinct peers a device exchanges traffic with, the observation of automated port mapping through service discovery, and the ratio of transmitted to received volume as an indicator of forwarding behaviour.

The design of the resolution features follows directly from the threat-intelligence analysis discussed in Section 2.1.4, and departs from the approach that would have been adopted on intuition alone. Because the reported malware resolves blockchain names by issuing a remote procedure call over HTTPS to a small set of named commercial gateway services rather than by issuing a conventional name query, the corresponding observable is the server name presented during the encrypted session handshake, matched against an enumerated and documented set of such services. This measurement requires neither decryption of the session nor inspection of its payload, and it is both more precise and less computationally costly than the name-entropy heuristics that a conventional design would employ. Name entropy is retained as a secondary signal, since the same reporting notes that families fall back to conventional resolution when gateway services are unavailable.

The relay features follow the reported mechanism equally directly. Automated port mapping is observed as service-discovery traffic on the local network accompanied by a structured control request to the gateway's connection service. Forwarding behaviour is observed as persistent bidirectional flows exhibiting approximate volume symmetry, and periodic status reporting appears as a regular, low-volume, structured transmission that reinforces the beaconing measurements of the payload group. One feature of the payload group — a measure of encrypted string content — is not obtainable from network metadata under any circumstances, and it is recorded as permanently unavailable rather than approximated; every headline result is reported both with and without it.

Three detectors are applied. The first is a transparent rule-voting baseline in which each rule tests a single feature against a fixed threshold and a device-window is flagged when a sufficient number of rules agree. This detector exists so that every alert can be presented to an analyst as the precise conditions that produced it, and it functions correctly when features are missing, since a rule whose feature is unavailable simply does not vote. The second and third are Random Forest and Extreme Gradient Boosting classifiers, which capture interactions among features that a rule set cannot express. All three are evaluated at a common false-positive budget so that their alarm rates are directly comparable, and permutation importance is used to identify which features drive each model's decisions.

The system's reporting behaviour is a designed component rather than an afterthought. Because operational telemetry carries no ground-truth labels, any finding derived from it is presented as a suspicious indicator pattern requiring analyst review rather than as a confirmed compromise. Where a required feature group cannot be measured from the available telemetry, the system reports insufficient telemetry rather than returning a negative verdict, so that an absence of evidence is never misreported as evidence of absence. Where a decision falls too close to the threshold to be meaningful, the system abstains. Each of these behaviours is enforced by automated tests rather than by convention.

The expected outcome of the work is a reproducible measurement of whether the two novel indicator groups improve recall at a fixed false-positive budget, accompanied by confidence intervals that indicate whether any observed improvement is distinguishable from sampling variation. A positive result would establish that the behaviours described in contemporary threat-intelligence reporting are detectable from authorised telemetry and would quantify the benefit. A negative result would establish that conventional indicators already capture the available signal, which is an equally publishable and equally useful finding. The methodology is fixed in advance precisely so that either outcome can be reported with confidence.

---

## 3. SYSTEM ANALYSIS AND DESIGN

**Functional Requirements:**

- Ingestion of authorised network telemetry in multiple formats, including packet captures reprocessed into protocol logs, connection logs, and flow exports
- Normalisation of heterogeneous input into a single validated observation schema with explicit provenance recording
- Aggregation of network records into device-observation windows of three hundred seconds
- Derivation of sixteen behavioural features across the infection, payload, blockchain-resolution and victim-relay groups
- Explicit representation of unmeasurable features as missing values, with per-window quality flags
- Transparent rule-based detection with human-readable justification for every alert
- Machine-learning detection using Random Forest and Extreme Gradient Boosting classifiers
- Threshold calibration on a validation partition under a stated false-positive budget, locked before test scoring
- Incremental-value experimentation comparing feature sets built upward from a conventional base
- Reporting of precision, recall, F1-score, false-positive rate and area under the receiver operating characteristic curve with bootstrap confidence intervals
- Abstention when evidence is insufficient, and reporting of insufficient telemetry when a feature group cannot be measured

**Non-Functional Requirements:**

- Correctness and reproducibility: fixed random seeds, versioned configuration, and recorded data provenance for every reported result
- Scientific integrity: no substitution of missing values, no presentation of laboratory-generated data as operational performance, no adjustment of data generation to obtain a favourable result
- Containment: no outbound network communication from the analysis pipeline, and no contact with any external infrastructure
- Explainability: every alert traceable to the specific feature values that produced it
- Data governance: analysis restricted to authorised sources, with provenance recorded at ingestion
- Testability: automated verification of schema validity, missing-value policy, containment properties and reporting language
- Efficiency: capable of processing dataset-scale captures on commodity hardware without specialised infrastructure
- Maintainability: modular separation of ingestion, feature derivation, detection and evaluation stages

---

## REFERENCES

[1] M. Antonakakis, T. April, M. Bailey, M. Bernhard, E. Bursztein, J. Cochran, Z. Durumeric, J. A. Halderman, L. Invernizzi, M. Kallitsis, D. Kumar, C. Lever, Z. Ma, J. Mason, D. Menscher, C. Seaman, N. Sullivan, K. Thomas and Y. Zhou, "Understanding the Mirai botnet," *Proceedings of the 26th USENIX Security Symposium*, pp. 1093–1110, 2017.

[2] Y. Meidan, M. Bohadana, Y. Mathov, Y. Mirsky, A. Shabtai, D. Breitenbacher and Y. Elovici, "N-BaIoT: Network-based detection of IoT botnet attacks using deep autoencoders," *IEEE Pervasive Computing*, vol. 17, no. 3, pp. 12–22, 2018, doi: 10.1109/MPRV.2018.03367731.

[3] S. Garcia, A. Parmisano and M. J. Erquiaga, "IoT-23: A labeled dataset with malicious and benign IoT network traffic," Stratosphere Laboratory, Czech Technical University, Zenodo, 2020, doi: 10.5281/zenodo.4743746.

[4] N. Koroniotis, N. Moustafa, E. Sitnikova and B. Turnbull, "Towards the development of a realistic botnet dataset in the Internet of Things for network forensic analytics: Bot-IoT dataset," *Future Generation Computer Systems*, vol. 100, pp. 779–796, 2019.

[5] Nokia Deepfield Emergency Response Team and Comcast Threat Research Lab, "Reverse-engineering Jackskid: from bare-bones Mirai fork to persistent TV box botnet," public research report, 24 March 2026.

[6] NICTER Analysis Team, National Institute of Information and Communications Technology, "Name-resolving malware DDoS attacks on Ethereum and Solana," 21 May 2026.

[7] National Computer Network Emergency Response Technical Team (CNCERT) and Qi'anxin X Laboratory, "Risk tips for the widespread spread of the Dysphoria botnet," 24 July 2026.

[8] K. Lekssays, B. Sadighian, B. Falah and S. Rovelli, "PAutoBotCatcher: A blockchain-based privacy-preserving botnet detector for the Internet of Things," *Computer Networks*, art. 108512, 2022.

[9] A. Al-Sarawi, M. Anbar, R. Abdullah and A. B. Al Hawari, "Internet of Things botnets: A survey on artificial intelligence based detection techniques," *Journal of Network and Computer Applications*, vol. 236, art. 104110, 2025.

---

**SIGNATURE OF TEAM MEMBER**
SHIVRAJ R — 212223110051
Computer Science and Engineering (Internet of Things)
Saveetha Engineering College, Chennai – 602105, India

**SIGNATURE OF SUPERVISOR**
*Supervisor Name*
SUPERVISOR
*Supervisor Designation*
Computer Science and Engineering (Internet of Things)
Saveetha Engineering College, Chennai – 602105, India
