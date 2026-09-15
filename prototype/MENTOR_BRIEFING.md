# Mentor Briefing — What to Say, In Order

**Project:** Detecting Blockchain-Anchored Command-and-Control in IoT Botnets:
A Synthetic Benchmark and Feature-Group Analysis

Total time: ~10 minutes talking + questions. Dashboard on `http://localhost:8501`.

---

## NUMBERS YOU MUST KNOW COLD

If you remember nothing else, remember these. Your mentor will ask.

| Thing | Number |
|---|---|
| Dataset size | 9,200 device-windows |
| Realised labels | 7,866 benign / 1,334 malicious (5.9:1) |
| Features / groups | 16 features across 4 groups |
| Unit of analysis | one device over one 5-minute window |
| **Threshold-matched @ 1% FPR** | Heuristic F1 **0.615** (recall 0.45) · RF **0.909** · XGBoost **0.921** (recall 0.883) |
| **Incremental value** | base 0.9144 → +resolution 0.9263 → +relay 0.9263 → both 0.9253 |
| Gain from novelty groups | **+0.012, but 95% CIs overlap** → not significant |
| rc4_string_score | gain says 47%, permutation says Δ F1 0.197; removing it: 0.925 → 0.898 |
| Robustness | split seeds 0.920 ± 0.004 · regenerated datasets 0.919 ± 0.004 |

---

## PART 1 — THE PROBLEM (2 min)

"Normal botnets have a weakness: the C2 server address is hardcoded or uses DNS.
Defenders can take down the domain or sinkhole it, and the whole botnet dies.

Attackers found a way around this. Instead of DNS, they store the C2 address in a
**blockchain name** — like ENS on Ethereum. Blockchain is decentralised and
immutable, so **nobody can take it down.** No registrar to call, no domain to
seize.

Second problem: infected IoT devices don't just attack. They open a **UPnP port
mapping** and become a **relay** — traffic passes through the victim's own router.
So the real attacker is hidden behind thousands of innocent home devices.

My project is a **detection** system. I am not building any of this. I detect the
*behavioural traces* it leaves."

**Ethics line — say this explicitly:**
"No real malware, no real C2, no network traffic sent, no scanning. Everything is
local and synthetic. It is detection and analysis only."

---

## PART 2 — WHAT I BUILT (2 min)

"I built a full detection pipeline. Four things:

1. **A data generator.** Since no public dataset labels blockchain-C2 behaviour, I
   generate synthetic device-windows. Deliberately made *hard* — benign devices
   also beacon, also use UPnP, also fail connections. Plus 2% label noise, like
   real annotation errors.

2. **16 features in 4 groups:**
   - *Resolution* — ENS query rate, RPC endpoint ratio, resolution entropy, server-list pull
   - *Relay* — bidirectional flow duration, fanout, UPnP AddPortMapping, up/down ratio
   - *Infection* — login bursts, scan rate, distinct destination ports, failed connections
   - *Payload* — beacon interval, beacon jitter, RC4 string score, mean packet size

   The first two groups are my **claimed novelty**. Infection and payload are
   generic malware signals that any existing tool already catches.

3. **Three detectors:** a transparent rule-based heuristic (the baseline), Random
   Forest, and XGBoost.

4. **A rigorous evaluation protocol** — this is the part I want to show you."

---

## PART 3 — THE PROTOCOL (2 min) ← THIS IS WHAT MAKES IT RESEARCH

"Four things I do to keep myself honest:

**Locked test set.** 30% is carved off and scored exactly once. Model choice,
thresholds, feature importance — all on a separate validation split. Otherwise I
would be tuning on my own exam paper.

**Threshold matching.** My first comparison was unfair: heuristic at `vote ≥ 3`
versus ML at `probability ≥ 0.5` — two arbitrary constants. So now every detector
is pinned to the **same false-alarm budget (1% FPR)** on validation data, then
scored once.

**Build-up instead of drop-one.** To test whether resolution/relay matter, the
obvious way is to remove them and see if the score drops. That is *wrong* when
features are correlated — if payload already separates the classes, dropping
resolution costs nothing even if resolution is genuinely useful. So instead I
**start from a base and add**.

**Confidence intervals.** 1,000 bootstrap resamples on every F1, so I can say
whether a difference is real or noise."

---

## PART 4 — RESULTS (3 min) — walk the dashboard

### Tab 1 — Model Comparison
"Look at the matched comparison. At the same 1% false-alarm rate:
- Heuristic: recall **0.45**
- XGBoost: recall **0.883**

The rules keep high precision but **only find half the attacks**. Earlier the
heuristic looked fine at F1 0.715 — but only because it was running at a 7.8%
false-positive rate. On a real network that is thousands of false alarms a day.
Nobody would deploy it."

### Tab 2 — Incremental Value ← **THE MOST IMPORTANT SLIDE**
"This is my main finding, and it is a **negative result.**

Base model, generic signals only: F1 **0.9144**
Add resolution: **0.9263** (+0.012)
Add relay: **0.9263** (+0.012)

Both go *up*. But look at the confidence intervals — they **overlap the base model
heavily**. So the honest statement is: **no statistically distinguishable
improvement.** Not 'they help'. Not 'they are useless'. No measurable independent
value — *on this synthetic data*.

And notice adding both groups is no better than adding one, which means the two
are largely redundant with each other, as currently generated."

**If the mentor looks concerned, say this:**
"This does not break the project. My generator was never fitted to measured
traffic — so it *cannot* settle the question either way. What it tells me is that
the next phase must ground these features in real observable events. If I had
tuned the generator until the numbers confirmed my thesis, that would be
fabrication. I documented the result instead."

### Tab 4 — Explainability
"Tree gain importance says `rc4_string_score` is 47% of the model. Permutation
importance on held-out data says its real contribution is Δ F1 0.197. That gap is
a live demonstration of why gain importance is biased.

Two problems with that feature:
1. **Circular** — my generator creates the score, the model learns it.
2. **Not deployable** — RC4 string signatures need plaintext payload. In encrypted
   IoT traffic that feature does not exist.

So I flagged it lab-only and tested removing it: F1 goes 0.925 → **0.898**. The
detector does *not* collapse. That matters — it means this is not just a payload
signature matcher wearing a costume."

### Tab 5 — Dataset
"One row = one device over a 5-minute window. Not one flow — `distinct_dst_ports`
for a single flow is 1 by definition. And the realised counts are 7,866 / 1,334,
not the nominal 8,000 / 1,200, because 2% label noise moves them."

---

## PART 5 — WHAT'S NEXT (1 min)

"Three things:

1. **Ground the features** in specific observable events, and build benign controls
   that use the *same mechanism* legitimately — devices with real periodic resolver
   activity, real UPnP use. Right now my benign class may be too easy.

2. **Grouped and temporal splits.** My generator does not emit device IDs yet, so
   train and test come from the same distribution. That measures in-distribution
   accuracy only — it is an upper bound, and a loose one.

3. **A safe PCAP-to-feature adapter** — run the same protocol on approved public
   benign captures plus isolated mock-labelled captures. That replaces 'my
   generator says these differ' with something grounded."

---

## LIKELY QUESTIONS — PREPARED ANSWERS

**"Why synthetic data? Why not a real dataset?"**
> No public dataset labels blockchain-anchored C2 — it is too new. IoT-23 and
> Bot-IoT have Mirai-style botnets but not ENS resolution or victim-relay labels.
> So I build the pipeline on synthetic data first, prove it runs, then swap in
> real data. The generator is documented and released so it is auditable.

**"Then your results mean nothing?"**
> They mean one specific thing: the pipeline is correct and reproducible. They do
> *not* mean the method works on real traffic, and I never claim that. That is
> exactly why my headline is a null result rather than a 99% accuracy number.

**"Why is your accuracy only 92%? I've seen papers with 99%."**
> Because I deliberately made the classes overlap. My first generator gave F1 =
> 1.000 with a flat ablation — that is a red flag, not a success. It meant the
> classes were trivially separable and the model had learned nothing. Papers
> reporting 99% on IoT botnet data are usually detecting the easy Mirai scan
> pattern.

**"Your novel features don't work. Isn't the project a failure?"**
> A negative result on unvalidated synthetic data is not a failed project — it is
> a correctly-reported preliminary finding. I could have made resolution and relay
> more different between classes and shown a beautiful result. That would be
> fabrication-by-design. The finding tells me precisely what phase 2 must fix.

**"Why XGBoost and not deep learning?"**
> 9,200 rows and 16 tabular features. Gradient boosting is the right tool at that
> scale; a neural net would overfit and give me no explainability. Also I need
> feature-group attribution, which trees give directly.

**"Is any of this dangerous / could it be misused?"**
> No. It sends zero network traffic, contacts nothing, and contains no attack
> capability. It reads a CSV and trains a classifier. The generator only produces
> numbers — it does not emulate any protocol.

---

## THE ONE LINE THAT WINS THE ROOM

> "This validates the pipeline and produces an important preliminary result: our
> synthetic generator shows no measurable independent value from the resolution
> and relay indicators. The next phase is designed to test that claim with
> grounded, observable data."

Leading with a limitation you found yourself — before the reviewer finds it — is
the single strongest move available to you. It signals that you understand your
own work better than the person evaluating it.

---

## DEMO SAFETY

- Dashboard is already running with pre-built artifacts. **Do not press
  "Regenerate Data & Retrain"** — it takes ~1 minute and reseeds randomly, so
  your numbers will stop matching this document.
- If Streamlit dies: `cd prototype && python -m streamlit run app.py`
- All numbers here match `results/tables/*.csv` at seed 42.
