# Project-a Puriyanum — Tanglish Explanation

Idhu translation illa. Idhu **puriyaradhukku** — concept by concept.
English version: `MENTOR_BRIEFING.md` (adhu mentor-kitta pesuradhukku).
Idhu neenga **understand** panradhukku.

---

## 0. ONE PARAGRAPH SUMMARY (mudhalla idha padinga)

> Botnet-la attacker oru C2 server (command server) vechurupaan. Adhoda address-a
> devices DNS-la kandupidikkum. Police/defenders andha domain-a seize pannitta
> botnet sethuidum. Aana ippo attackers andha address-a **blockchain-la**
> (ENS - Ethereum Name Service) store panranga. Blockchain-a yaarum delete panna
> mudiyadhu — so takedown impossible. Naan andha behaviour-a **kandupidikkira**
> system build panniruken. Attack tool illa — **detection** tool. Data ellam
> synthetic (naanae generate panradhu), because real-world-la indha behaviour-ku
> labelled dataset ipo varaikkum illa.

---

## 1. PROBLEM-A PURIYUNGA

### Normal botnet eppadi work aagum?

```
IoT device (CCTV camera, router) → hack aagudhu
        ↓
"Enna panna-nu attacker-kitta kekkanum"
        ↓
DNS-la kekkudhu: "evil-c2.com enna IP?"
        ↓
Attacker-oda server IP kedaikkudhu → orders vaangudhu
```

**Idhoda weakness:** `evil-c2.com` — idhu oru **domain name**. Domain-a oru
company (registrar) control pannudhu. Police adhukitta poi "idha block pannu"
sonna, block aagidum. Appo botnet-la irukkura ella devices-um address kandupidikka
mudiyadhu → **botnet motham sethuidum**. Idha *sinkholing* / *takedown* nu solvaanga.

### Ippo attackers enna panranga? (idhu dhaan project-oda core)

DNS-ku badhila **blockchain name** use panranga:

```
Device → Ethereum blockchain-la kekkudhu: "botmaster.eth enna address?"
        ↓
Blockchain-la answer irukku
        ↓
Attacker server kedaikkudhu
```

**Yen idhu dangerous?**

| DNS | Blockchain (ENS) |
|---|---|
| Oru company control pannudhu | **Yaarum** control panla — decentralised |
| Delete panna mudiyum | **Delete panna mudiyadhu** — immutable |
| Registrar-kitta complaint panlaam | Complaint panna **aalae illa** |
| Takedown = botnet dead | Takedown **possible-e illa** |

Ipdi solli puriyavainga:
> "Sir, DNS-la address vechirundha adha nammalaala remove panna mudiyum.
> Blockchain-la vechirundha remove panna **mudiyavae mudiyadhu**. So takedown
> nu oru option-e illa. Adhanaala **detection** mattum dhaan bachi irukku
> defence — network-la andha behaviour-a paathu kandupidikkanum."

Idhu dhaan project-oda **whole justification**. Idha clear-a sonna half battle won.

### Second problem — victim-relay (UPnP)

Infected device sonna kettu attack panradhu mattum illa. Adhu **UPnP
AddPortMapping** nu oru command use panni, thanoda router-la oru **port open**
pannudhu. Appuram andha device oru **relay** (middle-man) aagidudhu.

```
Real attacker → victim device 1 → victim device 2 → target
                (relay)          (relay)
```

So traffic-a trace panna poi paathaa, **innocent home camera** dhaan
theriyum — real attacker romba pinnadi olinjiruppaan. Idha **victim-relay**
nu solvom.

> "UPnP-nu solradhu router-la 'ennaku oru port open pannu'-nu automatic-a
> kekkura protocol. Normal-a smart TV, game console idha use pannum. Aana
> malware idha use pannina, victim-oda router-e attacker-oda proxy aagidudhu."

### ⚠️ Ethics — idha kandippa solunga

> "Sir, naan indha attack-a **build panlai**. Naan andha attack vidra
> **thadam** (behavioural traces) kandupidikkira detector build panniruken.
> Real malware illa, real C2 illa, oru packet-um network-ku anuppala,
> oru device-ayum scan panla. Ellam local, ellam synthetic. Purely defensive."

---

## 2. NAAN ENNA BUILD PANNEN — 4 pieces

### (a) Data Generator

**Problem:** Blockchain-C2 behaviour-ku labelled public dataset **illa**. Ivlo
new-aana attack. IoT-23, Bot-IoT nu datasets irukku, aana adhula Mirai maadhiri
old botnets dhaan — ENS resolution label, relay label ellam illa.

**Solution:** Naanae synthetic data generate panren. **9,200 rows**.

Ithula oru important point — naan deliberately **kashtama** panniruken:

> "Benign devices-um beacon pannum, benign devices-um UPnP use pannum, benign
> devices-um connection fail aagum. Rendu class-um **overlap** aagum madhiri
> generate panniruken. Plus **2% label noise** — real-world-la humans label
> panna thappu panradha simulate panradhukku."

**Yen ipdi?** Easy-a generate pannirundha model-ku 100% accuracy varum — aana
adhu **use illa**. Adhu model kathukitchu nu artham illa, data thappu nu artham.

### (b) 16 Features, 4 Groups

Feature-nu solradhu — oru device-oda behaviour-la irundhu naan **alakkura
number**. Example: "indha device 5 minutes-la ethana thadava ENS query pannuchu?"

| Group | Features | Idhu enna sollum |
|---|---|---|
| **Resolution** 🆕 | ENS query rate, RPC endpoint ratio, resolution entropy, server-list pull | Blockchain-la address thedudha? |
| **Relay** 🆕 | bidirectional flow duration, fanout, UPnP AddPortMapping, up/down ratio | Idhu middle-man-a maarudha? |
| **Infection** | login bursts, scan rate, distinct dst ports, failed connections | Vera devices-a hack panna try pannudha? |
| **Payload** | beacon interval, beacon jitter, RC4 string score, mean packet size | Traffic-oda pattern malware maadhiri iruka? |

🆕 potta rendu group dhaan **en novelty** — idhu dhaan naan pudhusa contribute
panradhu. Infection & Payload-a already irukkura antivirus/IDS tools
kandupidichudum. So en claim:

> "Resolution + Relay features **extra value** kudukkum."

Indha claim-a test panradhu dhaan project-oda main experiment. (Answer §4-la.)

**Beacon-nu enna?** Malware regular interval-la C2-ku "naan uyirodha iruken"-nu
message anuppum — every 60 seconds maadhiri. Adhu **beacon**. Andha timing-oda
regularity dhaan `beacon_interval` / `beacon_jitter`.

### (c) 3 Detectors

1. **Heuristic** — simple rules. "7 conditions-la 3 true-na → malicious."
   Idhu **baseline**. Idha vida ML nallaruka-nu compare panradhukku.
2. **Random Forest** — niraiya decision trees, ellathayum vote pannum.
3. **XGBoost** — trees onnukku pinnadi onna build aagum, mundhaanadhoda thappa
   correct pannindae. **Idhu dhaan win aagudhu.**

### (d) Evaluation Protocol ← **IDHU DHAAN PROJECT-A "RESEARCH" AAKKUDHU**

Idha next section-la.

---

## 3. PROTOCOL — yen idhu dhaan important

Mentor-kitta **idha dhaan** proud-a sollanum. Model build panradhu easy.
**Honest-a evaluate panradhu** dhaan kashtam.

### (a) Locked Test Set

```
9,200 rows
   ├── 30% TEST  ← LOCK. Onnu thadava mattum use. Kadaisila.
   └── 70% remaining
         ├── 80% TRAIN      ← model kathukkardhukku
         └── 20% VALIDATION ← decisions edukka
```

**Yen?** Test data-va paathu paathu model tune panna, adhu **cheating**.
Exam paper-a munnadiyae paathutu answer padikkardhu maadhiri. So:

- Enda model best-nu decide → **validation**-la
- Threshold set panradhu → **validation**-la
- Feature importance → **validation**-la
- Final score → **test**-la, **oru thadava mattum**

> "Sir, naan test set-a lock pannitten. Model selection, threshold, importance
> ellam separate validation split-la. Illena naan en sonthama exam paper-la
> tune panradhu maadhiri aagidum."

### (b) Threshold Matching ← subtle, aana romba important

**Problem enna?**

- Heuristic: "3 votes-ku mela → malicious" — yen 3? Random-a select panninadhu.
- XGBoost: "probability 0.5-ku mela → malicious" — yen 0.5? Adhuvum random.

Rendu **verrveru arbitrary number**. Ipdi compare panradhu **unfair**.

**Solution:** Rendu detector-ayum **same false-alarm rate**-ku set panren.
`FPR = 1%` — adhaavadhu "100 benign devices-la maximum 1 dhaan thappa
alarm adikkanum". Andha condition-la rendu perum evlo attacks pidikkuraanga?

**Result:**

| Detector | Recall (ethana % attacks pidichudhu) |
|---|---|
| Heuristic | **0.450** — pathila konjam dhaan |
| XGBoost | **0.883** — kaal-la moonu pangu |

Munnadi heuristic F1 0.715 nu nallaa irundhudhu maadhiri thonuchu. Aana adhu
**7.8% FPR**-la run aagi irundhudhu! Adhaavadhu 100 normal devices-la 8-a
thappa alarm adikkum. Real network-la dhinam **aayiram** false alarms. Yaarum
adha use panna maattaanga.

> "Fair comparison panna pothu heuristic collapse aagudhu — recall 0.45 mattum
> dhaan. ML-oda advantage **real** dhaan, threshold artefact illa."

### (c) Build-up (kootitae poradhu), Drop-one illa

Naan test panna vendiyadhu: **Resolution + Relay features useful-a?**

**Simple way (thappu way) — drop-one:** Ellathayum vechu model build panni,
appuram Resolution-a remove panni paakaradhu. Score korainja → useful.

**Yen idhu thappu?** Features **correlate** aagum. Payload group already class-a
separate pannidudhu-na, Resolution-a remove pannaalum score korayaadhu — **aana
adhu Resolution useless nu artham illa!** Adhu just redundant. Drop-one-aala
"useless" and "redundant-but-useful" rendayum **verupaduthi paakka mudiyadhu**.

**Correct way — build-up:** Base-la irundhu **koottikitae** poradhu.

```
base (infection + payload)          → F1 ethana?
base + resolution                   → evlo koorudhu?
base + relay                        → evlo koorudhu?
base + resolution + relay           → evlo koorudhu?
```

Idhu dhaan **incremental value**. "Indha group **extra-va** enna kondu
varudhu?"-nu direct-a alakkudhu.

### (d) Confidence Intervals (Bootstrap)

Score 0.9144-la irundhu 0.9263-ku poga, "improve aagiduchu!"-nu sollalaama?

**Illa.** Adhu **luck**-aala kooda irukkalaam.

So **bootstrap** panren — test set-la irundhu random-a resample panni **1,000
thadava** score-a kanakku panren. Appo oru **range** kedaikkum:

```
base           : 0.9144  [0.894 — 0.934]
base+resolution: 0.9263  [0.908 — 0.944]
                          ↑ overlap aagudhu!
```

Rendu range-um **overlap** aagudhu. Adhaavadhu andha +0.012 improvement
**noise-la irundhu verupaduthi paakka mudiyala**.

> "Confidence interval-nu solradhu 'en real answer indha range-la irukkum'-nu
> sollradhu. Rendu range overlap aana, difference **statistically significant
> illa**."

---

## 4. RESULT — NULL RESULT. Idha eppadi defend panradhu.

### Nadandhadhu enna

| Feature set | F1 | 95% CI | Gain |
|---|---|---|---|
| base (infection+payload) | 0.9144 | [0.894, 0.934] | — |
| base + resolution | 0.9263 | [0.908, 0.944] | +0.0120 |
| base + relay | 0.9263 | [0.908, 0.944] | +0.0120 |
| base + rendum | 0.9253 | [0.907, 0.943] | +0.0109 |

Score **koorudhu** (+0.012). Aana CI **heavy-a overlap** aagudhu.

**Correct statement:**
> "**No statistically distinguishable improvement.**"

**Thappana statements — idha sollaadheenga:**
- ❌ "Resolution/relay work aagudhu" — CI overlap-la, prove panla
- ❌ "Resolution/relay useless" — adhuvum prove panla!
- ✅ "En synthetic data-la **measurable independent value illa**"

Innoru observation: rendu group-um sethu potta, ondra pottadha vida **better
illa**. Adhaavadhu andha rendu group-um oruthar-oruthar **redundant** — naan
generate pannirukkura vidhathula.

### Mentor "adhaanaala project fail-a?" nu ketta

**Deep breath. Ipdi solunga:**

> "Illa sir. Rendu reason:
>
> **Onnu** — en generator **real traffic-a vechu fit pannadhu illa**. So adhu
> indha question-ku **enda pakkamum** answer sollaadhu. 'Work aagudhu'-nu
> sollavum mudiyaadhu, 'work aagaadhu'-nu sollavum mudiyaadhu. Adhu just
> **pipeline correct-a irukka**-nu prove pannudhu.
>
> **Rendu** — enakku indha result-a **maathi kaatra power irundhudhu**.
> Generator-la rendu class-oda distribution-a konjam thooram nakathirundha,
> azhagaana +0.15 gain kaatirukkalaam. Aana adhu **fabrication**. Naan
> en own thesis-a confirm panna data-va tune panna koodadhu. Adhukku badhila
> naan result-a **document** panniruken — `LIMITATIONS.md`-la.
>
> Indha null result enakku **phase 2-la enna panna-nu** exactly sollidudhu:
> features-a real observable events-la ground pannanum, and benign controls-a
> better-a build pannanum."

**Idha manasula vechukonga:** Research-la null result-nu solradhu **failure
illa**. Failure-nu solradhu — thappana result-a correct-a kaatradhu. Neenga
un sonatha limitation-a **neengalae mudhalla kandupidichu solradhu** — adhu
dhaan strongest move. Reviewer adha kandupidikka mundhi neenga solliteenga-na,
"ivan thanoda work-a **puriyaravan**"-nu artham.

---

## 5. rc4_string_score — indha issue-a explain panna

Model-la enda feature romba important nu paatha, `rc4_string_score` dhaan
top-la irukku.

**Rendu problem:**

1. **Circular.** Naan dhaan andha score-a generate panren, appuram model
   adha kathukudhu. Konjam "answer-a data-la vechutu, model kandupidichadhu"
   maadhiri.
2. **Real-world-la observable illa.** RC4 string signature paakkanumna
   **plaintext payload** venum. Modern IoT traffic ellam **encrypted**. So
   real deployment-la indha feature **kedaikkavae kedaikkaadhu**.

**Naan enna panninen:** Adha `LAB_ONLY_FEATURES`-la flag panniten, appuram
**adha remove panni** test panniten:

```
rc4_string_score kooda : F1 0.9253
rc4_string_score illama: F1 0.8976
```

Detector **collapse aagala**. Idhu important — adhaavadhu en detector just oru
"payload signature matcher" illa. Vera features-um kaththukidhu.

### Innoru nalla point — Permutation vs Gain importance

- **Tree gain importance** (built-in) sollutu: rc4 = **47%** of the model
- **Permutation importance** (held-out data-la) sollutu: Δ F1 = **0.197**

Yen indha gap? Gain importance **training data**-la calculate aagudhu, and adhu
continuous features-a **over-value** pannudhu — adhu oru **known bias**.
Permutation importance dhaan sound-aana measure — "indha feature-a shuffle
panna, held-out score evlo korayudhu?"

> "En own data-la gain importance-oda bias-a live-a demonstrate panniruken.
> Adhaanala naan permutation importance-a dhaan headline-a use panren."

---

## 6. VOCABULARY — indha words-a mentor kepaanga

| Word | Tanglish meaning |
|---|---|
| **C2 (Command & Control)** | Attacker-oda control server. Botnet-ku orders anupparadhu. |
| **ENS** | Ethereum Name Service. Blockchain-oda DNS. `name.eth` → address. |
| **Sinkholing** | Malicious domain-a defenders hijack panni traffic-a divert panradhu. |
| **UPnP** | Router-la automatic-a port open pannikkura protocol. |
| **Beaconing** | Malware regular interval-la C2-ku "alive" message anupparadhu. |
| **Jitter** | Andha interval-la irukkura random variation. Malware detect aagaama irukka jitter add pannum. |
| **Precision** | Naan "malicious"-nu sonna-la, ethana % **unmaiyilaeyae** malicious. |
| **Recall** | Motham irukkura attacks-la, ethana % **naan pidichen**. |
| **F1** | Precision + Recall-oda balance (harmonic mean). Onnu paravaalanaalum F1 korayum. |
| **FPR (False Positive Rate)** | Benign devices-la ethana % thappa alarm adichen. |
| **ROC-AUC** | Ella threshold-layum model-oda overall separation power. |
| **Bootstrap CI** | Resample panni score-oda uncertainty range kandupidikkardhu. |
| **Ablation** | Oru part-a remove panni impact paakardhu. |
| **Null result** | "Effect irukku-nu prove panna mudiyala." (≠ "effect illa") |
| **Overfitting** | Training data-va **manapaadam** panniduchu, pudhu data-la fail aagum. |
| **Grouped split** | Same device-oda rows train & test rendulayum varaama paathukkardhu. |
| **Temporal split** | Pazhaya data-la train, pudhu data-la test. Real deployment maadhiri. |

---

## 7. DASHBOARD DEMO — order-la

`http://localhost:8501`

| Tab | Enna kaatanum |
|---|---|
| **Sidebar** | 9,200 device-windows, 7,866 benign / 1,334 malicious |
| **Tab 1 — Model Comparison** | Mela irukkura table **unfair**-nu solunga. Keezha irukkura **threshold-matched** table dhaan fair. Heuristic recall 0.45 vs XGBoost 0.883. |
| **Tab 2 — Incremental Value** | ⭐ **MAIN SLIDE.** Null result. CI overlap-a point panni kaatunga. |
| **Tab 3 — Ablation** | "Idhu diagnostic mattum, headline illa"-nu solunga. Yen weak-nu explain panunga. |
| **Tab 4 — Explainability** | Permutation vs Gain gap. rc4 lab-only issue. |
| **Tab 5 — Dataset** | Oru row = oru device, 5-minute window. Flow illa. |

### ⚠️ DEMO WARNING

**"🔄 Regenerate Data & Retrain" button-a press panniraadheenga!** Adhu 1 minute
edukkum, and random seed use pannum — appuram screen-la irukkura numbers
document-la irukkura numbers-oda **match aagaadhu**. Romba awkward aagidum.

Streamlit off aayiducha:
```bash
cd prototype && python -m streamlit run app.py
```

---

## 8. NEXT PHASE (mentor kandippa kepaaru)

> "Moonu vishayam sir:
>
> **1. Features-a ground pannanum.** Ovvoru feature-um oru **specific
> observable event**-la irundhu vandhurukkanum. And benign controls build
> pannanum — **same mechanism-a legitimate-a use panra** devices. Adhaavadhu
> real-a periodic resolver activity irukkura device, real-a UPnP use panra
> device. Ippo en benign class romba easy-a irukkalaam.
>
> **2. Grouped + temporal splits.** Ippo en generator device ID emit panradhu
> illa. So train and test onnae distribution-la irundhu varudhu. Adhu
> **in-distribution accuracy** mattum dhaan alakkum — adhu oru upper bound,
> and loose-aana upper bound.
>
> **3. PCAP-to-feature adapter.** Approved public benign captures + isolated
> mock-labelled captures-la same protocol run pannanum. Appo 'en generator
> ipdi solludhu' nu solradhukku badhila **grounded evidence** kedaikkum."

---

## 9. MUDIVA — indha oru line dhaan room-a win pannum

> "Indha work **pipeline-a validate pannudhu**, and oru important **preliminary
> result** kudukkudhu: en synthetic generator-la resolution and relay
> indicators-ku **measurable independent value illa**. Next phase adha
> **grounded, observable data** vechu test panradhukku design pannirukken."

Ipdi solradhula strength enna-na — **neenga unga sonatha limitation-a
neengalae mudhalla solreenga**. Mentor adha kandupidikka mundhi. Adhu
"ivanukku thanoda work-a nallaa theriyum"-nu signal kudukkum.

---

## 10. CONFIDENCE NOTE

Mentor kekkura kelvi purila-na, guess pannaadheenga. Ipdi solunga:

> "Sir, adha naan indha stage-la verify panla. `LIMITATIONS.md`-la naan enna
> claim panren enna claim panlai-nu document panniruken. Adha check panni
> sollren."

Adhu **weakness illa** — adhu dhaan researcher-oda answer. Theriyaadhadha
theriyum-nu sollradhu dhaan pothu **real** damage.

Nalla pesunga. 👍
