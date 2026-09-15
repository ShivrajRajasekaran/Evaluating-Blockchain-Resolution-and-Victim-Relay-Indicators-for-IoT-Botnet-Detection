# Administration

*Authorised Log Analytics — IoT Botnet Indicator Review*

Accounts, roles, data governance, backup and restore. For day-to-day operation
see `docs/product-operation.md`.

---

## Accounts

### There is no default administrator

The product ships **no account and no default password**. A shipped credential
is a backdoor whether or not anyone intended it as one, and the ones that get
forgotten are the ones that get used. The first account exists because you
created it:

```bash
python -m scripts.init_db
python -m scripts.create_user --username alice --role Admin
```

### The password is never a command-line argument

There is no `--password VALUE` option. A password on a command line lands in
shell history, in `ps` output and in process-accounting logs — all readable by
other users on the host. So it is prompted for (hidden, and confirmed), or
piped:

```bash
# interactive (normal)
python -m scripts.create_user --username bob --role Analyst

# provisioning (from a secret store, never from a literal)
read_secret | python -m scripts.create_user --username bob --role Analyst --password-stdin
```

### Managing accounts

```bash
python -m scripts.create_user --list
python -m scripts.create_user --username bob --set-password
python -m scripts.create_user --username bob --disable
python -m scripts.create_user --username bob --enable
```

Disable rather than delete. A deleted user's audit rows lose their actor, and
the audit trail is the thing you will most want intact when you care who did
what.

### Password hashing

PBKDF2-HMAC-SHA256, 600,000 iterations (`auth.pbkdf2_iterations`, the OWASP 2023
floor), a fresh 16-byte salt per user, verified with `hmac.compare_digest`.

Creating a user takes a visible moment. **That cost is the feature** — it is the
same cost an attacker pays per guess offline. Raise the iteration count as
hardware improves; existing users keep the count they were hashed with, stored
per-row, so raising it is safe and takes effect on the next password change.

### Roles

| Permission | Viewer | Analyst | Admin |
|---|:-:|:-:|:-:|
| `view` — alerts, devices, ingestion, reports | ✅ | ✅ | ✅ |
| `triage` — status changes, feedback | | ✅ | ✅ |
| `upload` — ingest telemetry | | ✅ | ✅ |
| `view_config` — detection configuration | | | ✅ |
| `view_audit` — the audit log | | | ✅ |
| `manage_users` | | | ✅ |
| `purge_data` | | | ✅ |

The matrix is fixed in `src/auth/rbac.py`, not configurable. A permission model
that can be edited at runtime is one that gets edited at 2 a.m.

---

## Sessions

Signed cookies (`itsdangerous`), `HttpOnly`, `SameSite=Lax`, 8-hour lifetime.
There is no server-side session table — the cookie carries user id, username and
role, and the signature is what makes it trustworthy.

`PRODUCT_SESSION_SECRET` signs them. Consequences worth knowing:

* **Unset** → a random key is generated at startup, a warning is logged, and
  every session dies on restart. Fine for a first look, wrong for real use.
* **Rotating it** signs everyone out immediately and invalidates every
  outstanding CSRF token. That is the supported way to force a global logout.
* **Leaking it** lets someone forge a cookie for any user, including Admin.
  Treat it like a private key: `chmod 600 .env`.

Set `auth.cookie_secure: true` if you terminate TLS in front of the product.
Leave it false for local `http`, or the browser will discard the cookie and the
login will appear broken.

---

## Data governance

### Device pseudonymisation

`storage.pseudonymise_devices` is **true** by default. Device identifiers are
stored as a salted hash, so the database — and any backup of it — contains no
raw addresses. The salt is generated once by `init_db` and never rotated: it is
what makes a pseudonym stable across ingests, so regenerating it would split one
device's history into two unrelated devices.

Turning this off stores raw identifiers. That is a deliberate choice with a
privacy cost; make it knowingly.

### What is stored

| Table | Contents |
|---|---|
| `observation_windows` | one row per device-window, `research_class` always `unmapped` |
| `feature_snapshots` | the 16 features as JSON, **NaN as `null`, never 0** |
| `alerts` | category, severity, confidence, explanation, coverage note |
| `alert_evidence` | the rule that fired, the value that fired it, the blind spots |
| `analyst_feedback` | every transition and note, with the actor |
| `audit_events` | append-only |
| `uploaded_files` | original filename, SHA-256, size — and the stored path |

No payload is stored, because none is read. The product sees connection records.

### Retention

`storage.retention_days` is 90 by default. Purging is an **Admin** action and
writes a `data.purge` audit event. The audit trail itself is not purged by the
retention window — it is the record of what was purged.

### The audit trail is append-only by construction

`AuditRepo` exposes `append` and reads. There is **no** `update`, `delete`,
`remove`, `set_status` or `edit` method, and `tests/test_storage_repository.py`
asserts that by introspection. History cannot be rewritten through this product
at all — not "should not", *cannot*.

Audited actions: `auth.login`, `auth.login_failed`, `auth.logout`,
`user.create`, `user.disable`, `user.enable`, `user.password_change`,
`file.upload`, `ingest.start`, `ingest.succeed`, `ingest.fail`,
`detection.run`, `alert.status`, `alert.feedback`, `data.purge`.

Passwords and session tokens are never placed in `detail`.

---

## Backup and restore

Everything that matters is **one SQLite file** plus the uploads directory.

### Backup

```bash
# Consistent even while the server is running — do NOT just cp the file.
sqlite3 data/product/app.db ".backup 'backup/app-$(date +%F).db'"

# The original captures, if you want them reproducible
tar czf backup/uploads-$(date +%F).tar.gz data/product/uploads/
```

`.backup` takes a consistent snapshot under SQLite's own locking. A plain `cp`
of a live database can capture a torn write.

**The backup contains the pseudonymisation salt.** Anyone holding the backup and
a list of candidate device addresses can confirm which are present. Store it
with the same care as the telemetry itself.

**Do not back up `.env` alongside the database.** The signing key and the data it
protects in the same archive defeats the point of separating them.

### Restore

```bash
python -m scripts.run_server --check        # confirm nothing is running
cp backup/app-2026-09-11.db data/product/app.db
python -m scripts.init_db                   # apply any newer migrations
python -m scripts.init_db --check           # confirm counts
```

`init_db` is idempotent, so running it against a restored database upgrades the
schema if the backup predates a migration and does nothing otherwise.

### Verify a backup before you need it

```bash
python -m scripts.init_db --db backup/app-2026-09-11.db --check
```

Prints schema version and row counts. An untested backup is a hypothesis.

---

## Upgrading

```bash
# 1. Back up first.
sqlite3 data/product/app.db ".backup 'backup/pre-upgrade.db'"

# 2. Update dependencies — note the pandas pin.
.venv/Scripts/pip install -r requirements.txt

# 3. Apply migrations (idempotent).
python -m scripts.init_db

# 4. Confirm.
python -m unittest discover -s tests -t .
python -m scripts.run_server --check
```

**pandas must stay below 3.0.** pandas 3.0 changes timestamp flooring that
`src/features/windowing.py` depends on for the fixed 5-minute window grid.
CI checks this explicitly.

### A ruleset change is a detection-version change

If detection thresholds change, bump `RULESET_VERSION` in
`src/detection/engine.py`. The version is part of the dedup key, so new alerts
start fresh rather than an old row silently absorbing hits produced by different
logic. `ruleset_digest()` is the machine-checkable companion — a short hash of
the rule table, stamped on every run, so a threshold edit is visible in the
evidence even if someone forgets to bump the version.

---

## Health monitoring

`GET /health` is anonymous and reports liveness, the product name, and the
detection mode in force — nothing else. No counts, no versions of anything, no
paths.

Worth alerting on: `detection_mode` ceasing to be `"rule"`, and
`session_secret_from_env` being `false` in production.

---

## PostgreSQL

**Not active in this build.** The repository speaks portable, parameterised SQL
and `docker-compose.yml` defines a profile-gated Postgres service, but switching
requires `psycopg2` installed *and* `storage.postgres.enabled: true`. Both are
approval-gated; see `docs/deployment-guide.md`.
