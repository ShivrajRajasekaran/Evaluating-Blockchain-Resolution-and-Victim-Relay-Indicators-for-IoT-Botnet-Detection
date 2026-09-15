# API reference

*Authorised Log Analytics — IoT Botnet Indicator Review*

A live version of this is served at **`/docs`**, and the machine-readable
description at **`/openapi.json`**. Both are generated from the actual route
table (`src/api/routes/__init__.py`), so a documented route and a served route
cannot drift apart — `tests/test_api.py` asserts the two sets are identical.

This page is the narrative version: the parts a generated spec cannot explain.

---

## Base URL

```
http://127.0.0.1:8000
```

Loopback by default. Binding elsewhere requires
`--i-accept-the-risk-of-exposing-this-service`, because the product ships no
TLS and no reverse proxy of its own.

---

## Authentication

**A session cookie. There is no API key.**

That is a deliberate design decision, not an omission. An API key is a
long-lived secret to store, rotate and eventually leak, and nothing here needs
unattended machine access — an operator's own automation runs `scripts/`
locally against the database, not over HTTP. So an API client signs in the way a
person does.

```bash
# Sign in; keep the cookie jar
curl -c jar.txt -X POST http://127.0.0.1:8000/login \
     -d "username=alice" -d "password=..."

# Use it
curl -b jar.txt http://127.0.0.1:8000/api/alerts
```

An unauthenticated request gets **401 JSON** under `/api/`, and a **303 redirect
to `/login`** for dashboard paths. A forged or expired cookie is not an error —
it is simply an anonymous request, so probing for a valid token reveals nothing.

### CSRF on mutating routes

Any route that changes state needs the token as well as the cookie:

```bash
# The token is rendered into every form on a page
TOKEN=$(curl -s -b jar.txt http://127.0.0.1:8000/alerts/1 \
        | grep -o 'name="csrf_token" value="[a-f0-9]*"' \
        | head -1 | cut -d'"' -f4)

curl -b jar.txt -X POST http://127.0.0.1:8000/api/alerts/1/status \
     -H "Content-Type: application/json" \
     -H "X-CSRF-Token: $TOKEN" \
     -d '{"status": "Investigating", "comment": "checking with the owner"}'
```

The token is an HMAC over your session cookie, so it is stable for the life of
the session, unforgeable without the signing secret, and invalidated
automatically when the session ends or the secret is rotated. One user's token
is useless in another user's session.

---

## Endpoints

### Read

| Method | Path | Permission |
|---|---|---|
| GET | `/api/summary` | `view` |
| GET | `/api/alerts` | `view` |
| GET | `/api/alerts/{id}` | `view` |
| GET | `/api/devices` | `view` |
| GET | `/api/ingestion-jobs` | `view` |
| GET | `/api/ingestion-jobs/{id}` | `view` |
| GET | `/api/detection/versions` | `view` |
| GET | `/api/detection/coverage/{source}` | `view` |
| GET | `/api/detection/categories` | `view` |
| GET | `/api/audit` | `view_audit` |

### Write

| Method | Path | Permission | CSRF |
|---|---|---|---|
| POST | `/login` | — | — |
| POST | `/logout` | — | — |
| POST | `/api/alerts/{id}/status` | `triage` | required |

### Anonymous

| Method | Path |
|---|---|
| GET | `/health` |
| GET | `/openapi.json` |
| GET | `/docs` |

Upload is a dashboard route (`POST /upload`, multipart, `upload` permission,
CSRF required) rather than a JSON endpoint. For scripted ingestion use
`python -m scripts.ingest_file`, which runs the identical pipeline locally
without going through HTTP at all.

---

## `GET /api/alerts`

```
?status=Open&category=SUSPICIOUS_RELAY_PATTERN&q=beacon&page=1&page_size=50
```

`q` matches explanation, alert uid and source filename. It is a bound
parameter — a tautology like `' OR '1'='1` is matched as a literal string and
returns nothing (`tests/test_storage_repository.py` proves it).

`page_size` is clamped to `api.max_page_size` (200).

```json
{
  "items": [ { "...": "see below" } ],
  "total": 3, "page": 1, "page_size": 50, "pages": 1,
  "review_banner": "Alerts indicate suspicious behavioural patterns and require analyst review. They are not confirmation of compromise."
}
```

The banner is in the payload on purpose. A client rendering these rows must be
able to carry the qualification without having read this document.

---

## The alert object

```json
{
  "id": 1,
  "alert_uid": "al_9f2c1b7e4d0a3856f1b2c9d4",
  "device_key": "b1946ac92492d2347c6235b4d2611184",
  "category": "SUSPICIOUS_CONVENTIONAL_BOTNET_PATTERN",
  "category_label": "Suspicious conventional botnet pattern",
  "severity": "LOW",
  "confidence": "medium",
  "explanation": "periodic beacon rhythm > 20s (beacon_interval = 60 > 20) Resolution indicators require resolver/DNS/HTTP telemetry absent from this source, so no resolution judgement can be made. Rule-based detection; not ML-validated.",
  "coverage_note": "Resolution indicators require resolver/DNS/HTTP telemetry absent from this source, so no resolution judgement can be made.",
  "provenance": "rule-engine",
  "detection_version": "ruleset-1",
  "source_file": "conn.log",
  "status": "Open",
  "is_active": true,
  "allowed_transitions": ["Investigating", "Benign", "Confirmed suspicious"],
  "occurrence_count": 2,
  "first_seen": "2019-01-01T00:00:00",
  "last_seen": "2019-01-01T00:15:00",
  "review_only": true
}
```

Three fields deserve comment:

* **`coverage_note`** is always present, even when empty. A blind spot that is
  not rendered is a blind spot the analyst does not know about, so it is never
  an optional field a client might forget to select.
* **`explanation`** always ends with the honesty marker. It is stored that way,
  so there is no rendering path on which a finding appears without saying it is
  rule-based and not ML-validated.
* **`review_only`** is always `true`. It is a constant, and it is in the payload
  so that a client cannot build a UI that implies otherwise by accident.

`allowed_transitions` drives the UI's controls, so an illegal move is never
offered — not merely rejected on submit.

---

## `POST /api/alerts/{id}/status`

```json
{ "status": "Benign",
  "disposition": "benign_explained",
  "comment": "vendor heartbeat, documented in the asset register" }
```

Returns the updated alert. `400` for an illegal transition — with the reason —
and `404` for an unknown alert.

The legal moves are enforced, not advisory: `Open → Closed` is refused, because
an alert must carry a disposition before it can be filed. See
`docs/product-operation.md`.

Every accepted call writes an `analyst_feedback` row **and** an audit event in
the same transaction as the status change.

---

## `GET /api/detection/versions`

What is detecting, at what version, and **why it is not a model**:

```json
{
  "mode": "rule",
  "detection_version": "ruleset-1",
  "ruleset_digest": "5fd41d46efe1",
  "marker": "Rule-based detection; not ML-validated.",
  "gate": {
    "allowed": false,
    "reasons": ["model mode is disabled in configuration (detection.model.enabled = false)"],
    "notice": "ML-based detection is not active: ... Rule-based detection; not ML-validated."
  },
  "rules": [ { "feature": "beacon_interval", "group": "payload", "op": ">", "threshold": 20.0, "...": "" } ],
  "severity": { "...": "" },
  "confidence_bands": { "medium_at": 0.34, "high_at": 0.67 },
  "sources": { "op_zeek": { "...": "" } },
  "validated_ml_models": []
}
```

`gate.reasons` is the honest answer to "why am I not getting ML?", available
without anyone having to request model mode to find out. `ruleset_digest` is a
short hash of the rule table — a threshold edited without bumping the version is
still visible here.

---

## `GET /api/detection/coverage/{source}`

For `op_zeek`, `op_flow_csv`, `op_netflow`, `op_firewall`. Answers *"what can
this format be judged on?"* **before** any file is uploaded:

```json
{
  "source": "op_zeek",
  "judgeable_groups": ["relay", "infection", "payload"],
  "blind_groups": ["resolution"],
  "groups": {
    "resolution": { "n_rules": 2, "n_rules_evaluable": 0, "judgeable": false, "...": "" }
  },
  "unavailable_features": ["ens_query_rate", "resolution_entropy", "serverlist_pull", "upnp_addportmapping", "rc4_string_score"],
  "proxy_features": ["rpc_endpoint_ratio", "login_burst_count"]
}
```

---

## `GET /health`

Anonymous, and says as little as possible:

```json
{ "status": "ok", "product": "...", "detection_mode": "rule",
  "detection_version": "ruleset-1", "session_secret_from_env": true }
```

Liveness plus "is it still the honest rule engine". No counts, no paths, no
component versions — a health endpoint is reachable by anything that can reach
the port, and it should not be a reconnaissance surface.

---

## Errors

| Status | When |
|---|---|
| 400 | malformed request, illegal transition, rejected upload |
| 401 | no valid session (JSON) / redirect to `/login` (dashboard) |
| 403 | role lacks the permission, or the CSRF token is missing/wrong |
| 404 | unknown record or route |
| 413 | upload over `api.max_upload_bytes` |
| 429 | rate limit exceeded — `Retry-After` is set |
| 500 | a bug; generic message plus a request id |

Error bodies say what a client needs to fix its own request and **nothing about
the server** — no stack traces, no file paths, no SQL, no exception names. A 403
does not name the permission you lack. The full detail is logged against the
`request_id` that *is* returned, so an operator can find the exact failure from
a screenshot.

---

## Rate limiting

Token bucket, 60 requests burst refilling at 1/second, keyed by
**(actor, route-group)**. Authenticated requests key on username — you cannot
escape your limit by changing address — and anonymous ones key on client host,
which is what throttles the login form before any identity exists.

In-process and per-worker. That is documented rather than papered over: the
product is local-first and single-process, and an external rate limiter would be
a network dependency to solve a problem a dictionary solves.

---

## What the API will never do

No outbound connections, in any direction, from any endpoint. No webhook, no
callback, no notification, no forwarder, no telemetry. There is no HTTP client
installed, imported, or importable in the product tree, and
`tests/test_containment_outbound.py` parses every module to keep it that way.
