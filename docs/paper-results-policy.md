# Paper-results policy

*Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT
Botnet Detection*

This document governs what may be **written in the paper** from the contents of
`results/`. It exists because the distance between a number in a CSV and a
sentence in a paper is exactly where an honest measurement turns into an
overclaim. Every rule here is a rule about *how a number may be described*, not
about how it was computed.

The single overriding rule: **never invent results, citations, datasets, labels,
real-world detections, or performance claims.** Everything below is a
consequence of it.

---

## 1. Track B numbers are synthetic, and are described as such — always

Every number produced on Track B (the incremental-value headline, the model
comparison, permutation importance, the multi-seed robustness table) is computed
on **locally generated mock data**. When such a number appears in the paper:

- it is introduced as a result **on synthetic data**, in the sentence that
  states it — not only in a distant caption or footnote;
- it is **never** phrased as a real-world detection rate, accuracy, or
  enterprise-performance figure;
- the provenance banner that ships on the source artefact
  (`SYNTHETIC (Track B): …`, see `src/config.py::provenance_note`) is the
  wording the paper's description must remain consistent with.

A Track-B recall of, say, 0.9 is a statement about *separability under the
generator's assumptions*. It is evidence the indicators are worth instrumenting
for. It is not a claim that a deployed detector achieves 0.9 recall on real
blockchain-C2 traffic, because no such traffic was measured.

## 2. The headline may be a null result, and a null result is reported as found

The central experiment asks whether the resolution and relay groups add
detection value **beyond** the base groups. If the answer on Track B is "no
distinguishable improvement" — a confidence interval on the recall delta that
straddles zero — then **that** is the finding, and it is written plainly.

A null result is **never** repaired by widening the distance between the class
distributions in the generator. The standing rule, recorded verbatim in
`src/ingest/mock_generator.py` and in `docs/limitations.md` (L5), applies to the
writing as much as to the code:

> Do not "fix" a null result by widening class separation. If the
> resolution/relay groups show no independent value, the correct response is to
> ground those features in observable events and build better benign controls —
> not to increase the distance between the class distributions. Tuning these
> constants until the thesis is confirmed is fabrication-by-design.

The base set is deliberately left with strong separators (L5) precisely so the
incremental test is *hard*. Reporting that the novel groups did not clear that
bar is the correct scientific outcome, not a disappointment to be engineered
away.

## 3. Track A numbers measure false alarms and conventional separability — not the thesis

IoT-23 predates blockchain-anchored C2 and contains no instance of the
phenomenon (L1). Therefore **no Track A number is evidence for or against the
project's thesis.** Track A answers a different, still-useful question:

- the **false-positive rate** these features produce on real benign IoT traffic;
- whether **conventional** botnet activity is separable from the base groups
  alone.

When a Track A number appears, it is described as one of those two things, under
the `REAL CAPTURE (Track A): …` disclaimer (`src/config.py::real_data_note`),
which states outright that it is "NOT this project's thesis."

## 4. The cross-track FPR is a distribution-shift caveat, not a validation

The one sanctioned crossing — scoring a Track-B-trained detector against IoT-23
benign windows — produces a false-alarm rate on real benign traffic. It is
written as a **caveat about distribution shift**: "a detector built on our
synthetic assumptions raises this many false alarms when shown real benign
traffic." It is **not** written as validation of the detector, because the
malicious phenomenon it targets is absent from the real data. The coverage
figure (how many real windows could be scored versus abstained) is reported
alongside it; a low coverage makes the FPR less representative and must be shown,
not hidden.

## 5. Provenance travels with every quoted number

Each table in `results/tables/` begins with a `#`-commented provenance banner and
each figure in `results/figures/` carries a provenance caption. When a number is
lifted into the paper, its provenance is lifted with it. A results table pasted
into a paper with the banner stripped and no track stated is the specific failure
this whole design exists to prevent — see `src/reports/tables.py`.

## 6. Threat-intelligence context is attributed claims, never measurements

Operator names, dates, `.eth`/`.sol` names, CVE identifiers, bot counts, and
attack-volume figures are **unverified** vendor/CERT reporting. In the paper they
appear only as **attributed claims** in the introduction/motivation, never as
measurements, never as ground-truth labels, and never as this project's own
findings. Vendor scale claims (bot counts, Tbps peaks) are presented as claims.
No operator is named as responsible for anything. (See `docs/limitations.md` L4,
`docs/ethics-and-containment.md` §5.)

## 7. Abstention is part of the result, not an omission

Where the detector abstains (`unmapped` input, missing features, low confidence),
the paper reports the abstention volume and reasons. A metric computed only over
the rows the detector was willing to score, presented as if it covered all
traffic, understates the miss rate by exactly the abstained volume (L3).

## 8. Reproducibility

Any reported number is reproducible from:

- the **config** used (`configs/default.yaml` or the recorded `as_dict()` copy
  attached to the result), and
- the **seed(s)** stated in the artefact's banner.

The headline is additionally reported across multiple seeds
(`configs/default.yaml::seeds.split`) so a claim rests on "held across N seeds",
not "held on seed 42". Do not report a single-seed number as if it were seed-robust.

---

## Pre-submission checklist

Before any number from `results/` enters the paper, confirm:

- [ ] Its **track** is stated in the sentence that reports it (synthetic vs real).
- [ ] It is **not** described as a real-world / deployment / enterprise
      performance figure if it came from Track B.
- [ ] If it is the headline and the interval straddles zero, it is written as a
      **null result**, not omitted or re-tuned.
- [ ] Its **provenance banner/caption** wording is consistent with the paper's
      description.
- [ ] Any threat-intel figure near it is **attributed** and marked unverified.
- [ ] Abstention/coverage is reported where the detector declined to score.
- [ ] The **config and seed** behind it are recorded.

*If a sentence in the paper cannot pass this checklist, the sentence is wrong,
not the checklist.*
