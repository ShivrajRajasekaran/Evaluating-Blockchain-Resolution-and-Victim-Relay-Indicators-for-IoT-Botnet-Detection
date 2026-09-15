# Responding to an alert

*Authorised Log Analytics — IoT Botnet Indicator Review*

A playbook for the analyst looking at a row in the queue. It is written to be
useful *and* to keep you from over-reading the evidence, because the most likely
failure mode of a tool like this is not a missed detection — it is someone
treating a shape in metadata as a finding.

---

## Start here: what you are actually looking at

An alert means **transparent rules fired on aggregated connection metadata for
one device over one or more 5-minute windows.**

It does **not** mean malware was found, a C2 channel was observed, or a device
is compromised. The product has never seen a payload, never resolved a name and
never touched the device. It measured shapes.

So the question in front of you is never *"is this device infected?"* — the data
cannot answer that. It is:

> **Does this device's traffic have a legitimate explanation?**

Most of the time it will, and closing it as *Benign* with the explanation
recorded is a complete and valuable outcome.

---

## Triage in five steps

### 1. Read the coverage note before the evidence

It is the first thing on the alert page, and on most real telemetry it is the
most important field on the row.

> *Resolution indicators require resolver/DNS/HTTP telemetry absent from this
> source, so no resolution judgement can be made.*

That tells you the alert is based on a **partial view**. A
`SUSPICIOUS_CONVENTIONAL_BOTNET_PATTERN` from a `conn.log` is not evidence that
resolution behaviour is absent — it is evidence that nobody looked. If the
resolution question matters for this device, you need different telemetry, not a
closer reading of this alert.

### 2. Read what fired, and the value that fired it

The evidence panel separates them deliberately:

* a **rule** row — what the product concluded (`beacon_interval > 20`)
* a **feature** row — what it measured (`beacon_interval = 60`)

You need the second to dispute the first. `beacon_interval = 21` and
`beacon_interval = 3600` fire the same rule and mean very different things.

Features shown as *not measurable* were `NaN` in the source. They are never
stored or displayed as 0, so a blank is genuinely a blank.

### 3. Weigh severity against confidence — they answer different questions

* **Severity** = breadth. How many rules, across how many independent groups.
* **Confidence** = agreement. Fired rules ÷ rules that *could be evaluated in
  that window*.

`LOW` severity with `high` confidence is common on a `conn.log` and means: *of
the three things this telemetry could check, one fired.* That is a real signal
in a narrow view, not a weak signal in a broad one. Treat it as a prompt to get
better telemetry rather than as a weak alert to dismiss.

### 4. Check `occurrence_count` and the time span

One window is a moment. 288 windows from 00:02 to 23:57 is a pattern — and
sustained, regular behaviour is far more often a legitimate agent, a heartbeat
or a polling loop than anything hostile. Genuinely periodic beaconing is what
well-behaved IoT devices *do*.

### 5. Identify the device before concluding anything

If `storage.pseudonymise_devices` is on, the device key is a salted hash and you
will need your own inventory to resolve it. Deliberately: the product holds no
mapping back to an address.

---

## Pattern-specific notes

### `SUSPICIOUS_CONVENTIONAL_BOTNET_PATTERN`

The commonest, and the most likely to be benign. Driven by
`beacon_interval > 20s`, `login_burst_count >= 3`, or `rc4_string_score > 0.5`.

**Benign explanations to rule out first:** cloud-connected devices with a
keep-alive; update checkers; telemetry agents; monitoring pollers; NTP; any
managed device with a heartbeat. A login burst to 22/23/2323 is a *connection
attempt* count, not an authentication failure count — a backup job or a
monitoring probe produces the same shape.

**What would make it interesting:** a device with no business making outbound
connections at all; a beacon interval that is suspiciously exact; login bursts to
a device that has no remote-management role.

### `SUSPICIOUS_RELAY_PATTERN`

`upnp_addportmapping >= 1` or `updownlink_ratio > 0.7` (byte symmetry near 1).

**Benign explanations:** genuine peer-to-peer applications; video calling; a
device legitimately opening a UPnP mapping because that is how it is designed to
work; any real bidirectional session, which is symmetric by nature.

**What would make it interesting:** symmetric byte flow to a peer the device has
no reason to talk to; a UPnP mapping on a device with no inbound feature.

### `SUSPICIOUS_RESOLUTION_PATTERN`

`ens_query_rate > 3/min` or `serverlist_pull >= 1`.

**Both features are `NaN` on every flow log**, so on `op_zeek`, `op_netflow`,
`op_firewall` and `op_flow_csv` this category **cannot fire at all**. Seeing it
means the source genuinely carried resolver telemetry.

**Important context:** this project's own research found **no evidence** that
these indicators add measurable detection value, and the reference dataset
predates blockchain-anchored C2 entirely. Treat this category as *experimental
and unvalidated*. It is a prompt to look, never a conclusion. See
`docs/limitations.md`.

### `SUSPICIOUS_COMBINED_PATTERN`

Resolution **and** relay in the same window — the co-occurrence this project
exists to study, floored at `MEDIUM` severity so it is never buried.

It is also the category most deserving of scepticism, for exactly that reason:
it is the one the tool was built hoping to find. Two unvalidated indicators
agreeing is not twice the evidence. Escalate the *investigation*, not the
*conclusion*.

### `INSUFFICIENT_TELEMETRY`

Never appears in your queue — it is recorded on the window, not raised. If the
Reports page shows a large count, that is not noise: it is the product telling
you how much of your estate it cannot actually judge, and the fix is more
telemetry (a `dns.log`, an `http.log`), not a threshold change.

---

## Recording the outcome

```
Open ──▶ Investigating ──▶ Benign  or  Confirmed suspicious ──▶ Closed
```

* **Benign** — you found the legitimate explanation. *Write it down.* The next
  analyst to see this device will thank you, and the note is the only thing that
  stops the same investigation happening twice.
* **Confirmed suspicious** — you reviewed the evidence and the pattern is
  genuinely worth acting on. This records **your** judgement, not the product's,
  and it still is not a confirmed compromise.
* **Closed** — filed. Reachable only through a disposition; you cannot close an
  unreviewed alert.

Dispositions: `false_positive`, `true_positive`, `benign_explained`,
`needs_more_telemetry`, `duplicate`.

`needs_more_telemetry` is underused and genuinely valuable. It is the honest
answer far more often than either of the first two, and a queue full of it is a
clear argument for better log sources.

Changed your mind? Go back through *Investigating*. The history shows a
re-review rather than a silent flip, which is what you want six months later.

---

## Escalating beyond this product

The product's job ends at *"this is worth a human look, here is exactly why."*
Everything past that happens with tools this one deliberately does not have.

When you escalate, carry:

1. The **printable report** (`/alerts/{id}/print`) — evidence, coverage note,
   provenance and the full analyst history.
2. The **coverage limitation**, stated explicitly. Whoever receives this must
   know which indicator groups were never evaluated.
3. The **original capture**, identified by its SHA-256 from the Ingestion page.
4. The **detection version** (`ruleset-1` and the digest), so the finding can be
   reproduced against the exact thresholds that produced it.

And carry the framing with it: *a suspicious indicator pattern requiring
analyst review.* Do not let it become "the detector confirmed C2" one hop down
the escalation chain. That sentence is the one thing this product cannot say,
and it is the one most likely to be said on its behalf.

---

## What this product will not do for you

* It will not contact, scan, probe, block or quarantine a device. It has no
  capability to, and `tests/test_containment_outbound.py` enforces that by
  parsing every module.
* It will not notify anyone. There is no webhook, no email, no SIEM forwarder —
  no outbound connection of any kind. Queue review is a human routine here.
* It will not learn from your triage. Feedback is recorded for **audit**, never
  fed back into detection: a detector trained on its own triage labels measures
  the analysts, not the traffic.

---

## See also

* `docs/product-operation.md` — categories, severity, coverage, dedup
* `docs/feature-catalogue.md` — what each of the 16 features means
* `docs/limitations.md` — what this project genuinely cannot show
* `docs/user-admin.md` — accounts, retention, backups
