# Project Presentation — Tanglish Script
**Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT Botnet Detection**
Shivraj R · 212223110051 · CSE (IoT)

---

## 1. OPENING — Problem enna? (1 min)

> "Sir, namma project IoT botnet detection pathi.
>
> IoT devices — CCTV camera, router, smart bulb, DVR — idhellam romba cheap ah manufacture pannuvanga. Default password `admin/admin` maadhiri irukkum, update kooda varadhu. So attackers idha easy ah hack panni, **botnet** la sethuduvanga.
>
> Normal ah detection epdi work aagum na — attacker oda **C2 server domain name** kandupidipom, adha block pannuvom. Simple.
>
> **Aana 2026 la oru problem varudhu.**
>
> March 2026 la police coordinated ah oru periya IoT botnet operation-a disrupt pannanga. Adhukku appuram, attackers **blockchain** use panna aarambichanga — Ethereum Name Service, Solana Name Service. Domain name-ku badhila blockchain la C2 address store panranga.
>
> Ippo enna problem na — **block panradhukku domain-e illa.** Registrar kitta takedown notice kudukka mudiyadhu. Nameserver seize panna mudiyadhu.
>
> Rendaavadhu problem — infected device-a **relay node** ah maathitranga. So bot-ku theriyaradhu innoru victim oda address, real controller oda address illa."

**Delivery note:** Slow ah sollu. "Block panradhukku domain-e illa" — indha line dhaan hook. Konjam pause pannu.

---

## 2. RESEARCH QUESTION (30 sec)

> "So namma question simple:
>
> **Indha rendu behaviour — blockchain resolution, victim relay — idha network traffic la irundhu detect panna mudiyuma? Adhu already irukkura conventional detection-a vida extra value kudukkuma?**
>
> Important point sir — naan 'idhu work aagum' nu solla varala. Naan **measure** panna varen. Result negative ah vandhaalum, adha honest ah report panren. Adhaan proper research."

**Delivery note:** Indha honesty framing romba important. Reviewers ivanga idha appreciate pannuvanga.

---

## 3. THE KEY DISCOVERY (2 min) — *idhaan project oda heart*

> "Sir, project start panna appo naan IoT-23 dataset use panna decide panen. Idhu Czech Technical University oda standard dataset — real IoT malware traffic, properly labelled.
>
> Aana naan oru **serious problem** kandupidichen.
>
> IoT-23 kudukradhu ஒரே ஒரு file dhaan — `conn.log`. Connection log. Adhula enna irukkum na:
> - Yaar yaar kitta pesinaanga
> - Evlo neram
> - Evlo bytes
>
> **Aana enna pesinaanga-nu therilai.**
>
> Indha connection log la —
> - DNS query **illa**
> - HTTP request **illa**
> - TLS handshake **illa**
>
> Naan code la verify panen. Namma 7 detection rules la **4 rules永remaneously dead** — avanga use panra feature values ellam NaN, permanent ah.
>
> Adhaan meaning enna na — `SUSPICIOUS_RESOLUTION_PATTERN` nu oru alert category irukku. Adhu **eppovume fire aagadhu.** Structurally impossible.
>
> **Yosichu paarunga sir** — naan blockchain resolution detect panra project panren, aana en pipeline la adha detect panra feature-e work aagadhu. Idhu build panna appo theriyala, code-la check panna appo dhaan theriñjadhu."

**Delivery note:** "4 rules dead" — indha number-a board la எழுது or slide la periya ah காட்டு.

---

## 4. THE FIX (2 min)

> "So naan enna panen na — mudhalla **primary sources** padichen.
>
> Moonu independent lab reports:
> - **Nokia Deepfield + Comcast** (March 2026)
> - **NICT Japan** (May 2026)
> - **CNCERT + Qi'anxin China** (July 2026)
>
> Moonu perum different country, different lab, aana same finding.
>
> **NICT report la oru crucial line irukku.** Avanga sollranga — malware ENS resolve panradhukku **DNS use panradhe illa.** Ethereum peer-to-peer network-kum connect aagala.
>
> Adhukku badhila, **HTTPS** la oru JSON-RPC request anuppudhu — `eth.llamarpc.com`, `1rpc.io` maadhiri commercial gateway service-ku.
>
> **Idhu romba important sir.** Ennaku mudhalla idea enna na — DNS log la `.eth` domain thedanum nu. **Adhu thappu.** `.eth` name DNS la varave varadhu. Naan avlo naal thedirundhaalum onnum kidaikadhu.
>
> Correct answer enna na — TLS handshake la **SNI field** (Server Name Indication) paakanum. Adhula gateway hostname theriyum. Decrypt panna kooda thevai illa.
>
> So naan panna vellai:
> 1. IoT-23 oda **original pcap files** download panen
> 2. **Zeek** (network analyzer) install panni, local ah pcap-a replay panen
> 3. Missing aana logs — `dns.log`, `http.log`, `ssl.log` — regenerate panen"

---

## 5. RESULTS (1.5 min)

> "Result sir:
>
> **22 captures process panen. 43.8 million connections.**
>
> Adhula irundhu regenerate panna:
> - **10,109 DNS queries**
> - **3,804 HTTP requests**
> - **138 TLS sessions**
>
> **Indha 14,000 records dataset la mudhalla illave illa.** Naan local ah generate panen."

### Before / After table (slide la போடு)

| | conn.log மட்டும் | Zeek bundle |
|---|---|---|
| Resolution features measurable | **0 / 4** | **4 / 4** |
| Unavailable features | 5 | **1** |
| Rules fire aaga mudiyum | 3 / 7 | **6 / 7** |
| Resolution alert | Impossible | **Possible** |

> "Innum oru important result sir.
>
> **Amazon Echo** oda benign capture test panen. Echo nu solradhu — Alexa device. Adhu eppovume cloud-ku TLS la pesikittu irukkum. Romba noisy device.
>
> Result: **274 TLS/HTTP sessions, 21 different hosts, gateway match = 0.**
>
> Meaning enna na — namma feature 'internet use panradhu' nu detect panala. Specifically blockchain gateway contact dhaan detect panradhu. **False positive illa.**"

---

## 6. HONESTY SECTION (1 min) — *idha skip panneenga na credibility poidum*

> "Sir, oru honest point sollanum.
>
> IoT-23 dataset **2018–2019** la capture panradhu. Blockchain C2 nu oru concept-e appo illa.
>
> So `ens_query_rate` feature **zero dhaan varum** — ellame zero. Adhu **expected**, failure illa.
>
> Adhaan meaning na — IoT-23 la naan prove panradhu **specificity** mattum: 'namma feature thappa fire aagala'. **Sensitivity** — 'correct ah fire aaguma' — adha prove panna IoT-23 la mudiyadhu.
>
> Adhukku dhaan **Track C** — isolated virtual lab. Adhula naan mock services vechu, indha behaviour oda **network signature** generate panuven. Aana **capability** generate panna maaten.
>
> Example: mock UPnP gateway — port mapping request-a accept pannum, log pannum, success return pannum — **aana port-e open panna maatan.** Signature irukkum, capability irukkadhu.
>
> Adhu dhaan defensive research."

**Delivery note:** Indha section dhaan unga integrity-a காட்டும். Confident ah sollu, apologetic ah illa.

---

## 7. CLOSING (30 sec)

> "Summary sir:
>
> - **Problem:** Blockchain C2 use panra botnets-a conventional method la detect panna mudiyala
> - **Discovery:** Standard dataset la indha thesis-a test panna telemetry-e illa — code la verify panen
> - **Fix:** Original pcap replay panni missing logs regenerate panen
> - **Result:** 4/4 resolution features ippo measurable. Amazon Echo la zero false positive
> - **Honest:** Sensitivity innum prove panala. Adhu Track C la
>
> Ellame **real captured packets** sir. Simulation illa, synthetic data illa. Fully reproducible.
>
> Thank you."

---

## Q&A PREPARATION — *idhu dhaan important*

**Q: Blockchain use panreengala? Blockchain project ah idhu?**
> "Illa sir. Naan blockchain application build panala. **Attackers** blockchain use panranga — naan adhoda **network signature**-a detect panren. Namma system blockchain-ku connect aagave aagadhu."

**Q: Real malware run panreengala?**
> "Illa sir. Naan already capture panna pcap files-a **read** mattum panren. Malware execute panala, C2 contact panala, scan panala. Purely offline analysis."

**Q: Result enna? Accuracy evlo?**
> "Sir, ippo naan **pipeline** dhaan complete panirukken. Detection accuracy numbers innum illa — ennaku data ready aagi irukku, experiments next phase.
>
> Aana oru result irukku: **specificity**. Amazon Echo la 274 sessions, zero false positive. Adhu measured result."

**Q: Namma feature work aagalana?**
> "Adhuvum oru valid finding sir. Conventional features already enough nu prove aana, adha honest ah report panren. Null result-um research dhaan. Data-va adjust panni favourable result kondu varadhu — adhu fabrication."

**Q: IoT-23 la blockchain data illana, epdi test panreenga?**
> "Correct question sir. IoT-23 la **specificity** mattum test panna mudiyum — false positive varudha nu. **Sensitivity**-ku isolated lab (Track C) venum. Adhula ground truth naan control panren, so labels exact ah theriyum."

**Q: Zeek nu enna?**
> "Network traffic analyzer sir. Pcap file kuduthaa, protocol-wise logs generate pannum — DNS log, HTTP log, TLS log. Open source, industry standard. WSL la local ah run panen, offline mode la."

**Q: Evlo data?**
> "43.8 million connections sir, 22 captures. Adhula 12 malicious device, 3 benign device. 10,000+ DNS queries, 138 TLS sessions regenerate panen."

---

## NUMBERS — *ivai mattum manapaadam pannu*

| Number | Edhu |
|---|---|
| **43.8 million** | connections processed |
| **22** | captures |
| **4 → 1** | unavailable features (before → after) |
| **0/4 → 4/4** | resolution features measurable |
| **3/7 → 6/7** | rules that can fire |
| **274 sessions, 0 matches** | Amazon Echo specificity |
| **560** | tests passing (541 + 19) |
| **3** | independent labs corroborating |

---

## DELIVERY TIPS

1. **Slide 3 (discovery) dhaan strongest.** "4 rules dead" — adhula time spend pannu.
2. **Honesty section-a skip panaadha.** Adhu weakness illa, adhu strength. Reviewers "limitation enna?" nu kekka mudiyadha alavukku neenga already sollirukkeenga.
3. **"Naan verify panen" nu sollu**, "naan assume panen" nu sollaadha. Code la check panradhu unga advantage.
4. Number sollum bodhu **confident ah** sollu — ellam real measured values.
5. Result illa nu kekka, defensive aagaadha. "Pipeline complete, experiments next" — adhu proper answer.
