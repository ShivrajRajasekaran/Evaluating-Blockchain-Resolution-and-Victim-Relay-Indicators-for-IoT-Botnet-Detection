# Engineering report — product build

*Authorised Log Analytics — IoT Botnet Indicator Review*
Build completed 2026-09-11. Full suite: **760 tests, OK** (0 failures, 0 errors,
0 skipped).

---

## 1. What was built

A local-first defensive detection platform on top of the existing research
pipeline. The research code was **not modified** except for two additive
changes noted in §2.

| Package | Modules | What it does |
|---|---|---|
| `src/detection` | 6 | rule engine, coverage gate, severity policy, ML gate |
| `src/alerts` | 5 | dedup identity, lifecycle state machine, persistence |
| `src/api` | 15 | Starlette app, routes, security, uploads, pipeline, views |
| `src/api/templates` | 14 | server-rendered dashboard |
| `src/api/static` | 2 | first-party CSS and JS — no CDN, no framework |
| `scripts/` | 4 new | `init_db`, `create_user`, `ingest_file`, `run_server` |
| `docs/` | 6 new/extended | operation, admin, IR, API, backup, ethics, deployment |

Roughly 5,000 lines of product code, 2,800 lines of new tests, 3,100 lines of
templates, scripts and documentation.

### Detection semantics

Seven verdict categories, verbatim as specified:

```
BENIGN_OR_NO_ALERT              SUSPICIOUS_RESOLUTION_PATTERN
SUSPICIOUS_RELAY_PATTERN        SUSPICIOUS_COMBINED_PATTERN
SUSPICIOUS_CONVENTIONAL_BOTNET_PATTERN
INSUFFICIENT_TELEMETRY          ABSTAIN
```

Only the four `SUSPICIOUS_*` categories raise alerts.

**The load-bearing design decision** is the coverage gate. A rule that cannot be
evaluated does not fire, so a naive engine reports an *unmeasurable* device and
a *quiet* device identically and calls both benign. On a Zeek `conn.log` both
resolution rules (`ens_query_rate`, `serverlist_pull`) are `NaN` on **every**
window, so that failure would have been the product's normal output rather than
an edge case. A group with zero evaluable rules therefore yields
`INSUFFICIENT_TELEMETRY` with the configured reason attached — never
`BENIGN_OR_NO_ALERT`.

Related honesty properties, each with a test:

* NaN persists as JSON `null`, never `0`. For several of these features zero is
  the most suspicious value, not a neutral one.
* Confidence divides by rules evaluable **in that window**, not a fixed seven.
  Dividing by seven would cap every possible confidence on a `conn.log` at 3/7
  and report "low" for total agreement among everything the telemetry could say.
* Severity (breadth of evidence) and confidence (agreement among available
  evidence) are computed separately, because they can legitimately disagree.
* The engine reads thresholds from `src.models.heuristic.RULES` and **cross-checks
  its own vote count against `HeuristicDetector.votes()` on every frame**,
  raising if they disagree. The product and the published research baseline
  cannot silently diverge.

---

## 2. Changes to existing code

Deliberately minimal.

| File | Change | Why |
|---|---|---|
| `src/storage/repository.py` | added `AlertRepo.set_severity` | a recurrence may raise an existing alert's severity; nothing existed to do it |
| `configs/default.yaml` | added the `alerts:` block | dedup window, escalation, initial status, per-run cap |
| `docs/ethics-and-containment.md` | §3 and §4 rewritten | see below |
| `docs/deployment-guide.md` | added "Part two — deploying the product" | the original Part one is unchanged and still accurate |
| `README.md` | product section; environment section corrected | it named the deleted Anaconda env |

### The ethics document had to be corrected

`docs/ethics-and-containment.md` is the governing document and claimed *"There
is no HTTP server, no socket bind, no client call anywhere in `src/`."* The
product binds a listening port, so that sentence had become **false**. Leaving
it would have meant the repository's controlling document contradicted its own
code.

It now states the boundary precisely: the research pipeline has no network layer
at all; the product accepts **inbound** connections on a loopback bind and makes
**no outbound connections of any kind**. A service that can be reached still
cannot reach out.

---

## 3. Security controls

| Control | Implementation |
|---|---|
| Password hashing | PBKDF2-HMAC-SHA256, 600,000 iterations, per-user 16-byte salt, `hmac.compare_digest` |
| Sessions | signed cookies (`itsdangerous`), HttpOnly, SameSite=Lax, 8h |
| CSRF | HMAC over the session cookie; required on every mutating route |
| RBAC | fixed three-role matrix, declared per route with `@guard`, enforced before the handler runs |
| Upload safety | extension allowlist, streaming size cap, content sniff, **generated** storage names |
| Rate limiting | in-process token bucket keyed by (actor, route); anonymous keyed by host |
| Security headers | `'self'`-only CSP, nosniff, DENY framing, no-referrer, Permissions-Policy |
| Error handling | generic client messages with a request id; full detail logged server-side |
| Audit | append-only by construction — the repository exposes no update or delete method |
| SQL | parameterised throughout; injection strings stored and matched as literal data |
| Pseudonymisation | salted device hashes; raw identifiers never reach the database |

Two of these are **structural rather than procedural**, which is why they hold:

* The audit repository has no method that can rewrite or remove a row, so
  history cannot be tampered with through the product at all.
* Upload filenames are never used to build a path — not sanitised, *not used* —
  so path traversal is impossible rather than filtered.

### Containment

`tests/test_containment_outbound.py` parses every module in
`src/{api,alerts,detection,storage,auth,audit,ingest}` with `ast` and fails on:
forbidden imports, calls to network entry points, subprocess use, external
references in any template or asset, and a weakened CSP. CI additionally
verifies no outbound HTTP client appears even transitively in the installed
dependency set — a test can be deleted; a resolved dependency tree cannot be
argued with.

Notably, **`httpx` is not installed**, so Starlette's own `TestClient` is
unusable. `tests/asgi_shim.py` drives the ASGI app directly instead, which is
faster and a more honest test than one proving a TCP stack works.

---

## 4. Verification performed

| Check | Result |
|---|---|
| Full suite (`unittest discover`) | **760 tests, OK**, 350s |
| Suite before this build | 541 tests, OK |
| Live server on 127.0.0.1:8765 | started, all 9 pages 200, banner on every one |
| Real HTTP client over a socket | login, RBAC redirect, CSP and security headers, CSV export all confirmed |
| Headless browser screenshots | login, overview, alerts, alert detail, detection page |
| `scripts/init_db` | creates, migrates, idempotent, `--check` reports state |
| `scripts/create_user` | creates via stdin, lists, 600k iterations |
| `scripts/ingest_file` | `--dry-run` and real ingest from the authorised directory |
| `scripts/run_server --check` | preflight correct, refuses non-loopback without the flag |
| Preserved prototype | untouched — no file modified |
| Module import side effects | `import src.api.app` creates nothing |

The end-to-end test walks the whole product through HTTP: sign in → upload a
real Zeek `conn.log` → ingest → detect → alert → triage → audit → export, and
asserts the honesty statements survive every hop.

---

## 5. Environment change (unplanned)

**The Anaconda environment `shiva` was deleted from this machine** before this
session; `C:\Users\shivraj\anaconda3` no longer exists, and the venvs built on
it are broken. No interpreter on the host could run the suite.

With approval, the environment was rebuilt as a project-local venv
(`.venv`, uv, CPython 3.11.9). **pandas resolved to 3.0.5 initially and broke
`tests/test_windowing.py`** — pandas 3.0 changes timestamp flooring that the
fixed 5-minute window grid depends on. Pinning `pandas>=2.2,<3` (2.3.3) restored
a fully green suite. `requirements.txt`, `pyproject.toml` and CI all enforce that
pin.

Migrating the codebase to pandas 3 is a separate, deliberate piece of work.

---

## 6. What still needs real authorised telemetry

The product is complete and runs, but it has only been exercised against small
synthetic Zeek fixtures. Before operational use:

1. **Ingest a real capture from your own authorised sensor.** Use
   `--dry-run` first to see what it would raise.
2. **Expect `INSUFFICIENT_TELEMETRY` to dominate.** That is correct, not a
   defect: a `conn.log` genuinely cannot judge resolution behaviour. If that
   count matters to you, the fix is a `dns.log` and an `http.log`, not a
   threshold change.
3. **Tune severity against your own traffic.** The table is config-driven
   precisely so it can be retuned without touching code. The defaults are
   untested against a real estate.
4. **The CSV adapters (`op_flow_csv`, `op_netflow`, `op_firewall`) have been
   tested against synthesised exports only.** Real vendor exports vary; the
   column-alias map may need extending.

---

## 7. Known limitations

* **The novel indicators are unvalidated.** This project's own research is a
  null result, and the reference dataset predates blockchain-anchored C2
  entirely. `SUSPICIOUS_RESOLUTION_PATTERN` and `SUSPICIOUS_COMBINED_PATTERN`
  are experimental. See `docs/limitations.md`.
* **On flow logs, the resolution category cannot fire at all.** Both its rules
  are NaN. The product reports this rather than hiding it.
* **No ML.** By design, and gated off until an authorised labelled dataset
  exists. No accuracy is claimed anywhere.
* **Rate limiting is per-process.** The product is single-process by design;
  behind multiple workers the limit becomes per-worker.
* **No TLS.** Loopback deployment only, unless the operator explicitly
  acknowledges otherwise.
* **Feedback is never fed back into detection.** A detector trained on its own
  triage labels measures the analysts, not the traffic.

---

## 8. Deployment

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt

export PRODUCT_SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"

python -m scripts.init_db
python -m scripts.create_user --username alice --role Admin
python -m scripts.run_server            # http://127.0.0.1:8000
```

There is no default administrator and no default password.

---

## 9. Approval-gated — written but deliberately NOT performed

| Action | Artefact | Status |
|---|---|---|
| Running Docker | `Dockerfile`, `docker-compose.yml` | written, annotated, not built |
| PostgreSQL | compose profile, `pyproject` extra | gated off; repository SQL already portable |
| PDF export | — | CSV / JSON / printable HTML instead |
| `httpx` for tests | `tests/asgi_shim.py` | replaced, not installed |
| Vendoring HTMX | — | plain forms + one first-party script |
| Enabling ML mode | `src/detection/model_gate.py` | refuses until a validated, non-synthetic model exists |
| Non-loopback bind | `--i-accept-the-risk-of-exposing-this-service` | requires an explicit flag |
| CI on a remote | `.github/workflows/ci.yml` | written, not run — no remote configured |

One dependency install *was* performed, with explicit approval: rebuilding the
deleted Python environment (§5). Nothing else was downloaded, installed, or sent
anywhere.
