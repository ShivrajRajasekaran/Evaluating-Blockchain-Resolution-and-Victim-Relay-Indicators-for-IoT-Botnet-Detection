# Backup and restore

*Authorised Log Analytics — IoT Botnet Indicator Review*

Everything that matters is **one SQLite file** plus, optionally, the original
captures. The product holds no state anywhere else — no cache to warm, no queue
to drain, no external service to coordinate with.

---

## What to back up

| Path | Contains | Back up? |
|---|---|---|
| `data/product/app.db` | **everything**: users, devices, windows, features, alerts, feedback, audit | **yes** |
| `data/product/uploads/` | the original uploaded captures | if you need reproducibility |
| `data/authorised_input/` | files an operator dropped in | usually not — a landing zone |
| `configs/default.yaml` | thresholds, severity table, limits | yes (it is also in version control) |
| `.env` | the session signing key | **separately, and never in the same archive** |

`results/` is not product state. It belongs to the research pipeline and is
reproducible from `scripts/run_pipeline.py`.

### Three things the database contains that change how you handle it

1. **The pseudonymisation salt.** Anyone holding the backup *and* a list of
   candidate device addresses can confirm which are present. The backup is
   therefore roughly as sensitive as the telemetry it pseudonymises.
2. **Password hashes.** PBKDF2 at 600,000 iterations, so offline cracking is
   expensive — expensive, not impossible.
3. **The audit trail**, which is the record you will most want intact when you
   care who did what.

### Why `.env` goes somewhere else

The signing key lets anyone forge a session cookie for any user, including
Admin. Storing it in the same archive as the data it protects defeats the point
of separating them at all. Different destination, different access control.

---

## Backing up

### While the server is running

```bash
sqlite3 data/product/app.db ".backup 'backup/app-$(date +%F).db'"
```

**Use `.backup`, not `cp`.** SQLite's backup API takes a consistent snapshot
under the database's own locking. A plain file copy of a live database can
capture a torn write — a page half-updated — and the result may open cleanly and
be subtly wrong, which is worse than a backup that obviously failed.

If you have no `sqlite3` binary, Python is enough:

```bash
python - <<'PY'
import sqlite3
src = sqlite3.connect("data/product/app.db")
dst = sqlite3.connect("backup/app.db")
with dst:
    src.backup(dst)
src.close(); dst.close()
print("backed up")
PY
```

### With the server stopped

A plain copy is then safe, provided no `-wal` or `-shm` files remain:

```bash
python -m scripts.run_server --check     # confirm nothing is serving
cp data/product/app.db backup/app-$(date +%F).db
```

If `app.db-wal` exists, copy it too — or just use `.backup`, which handles it.

### The captures

```bash
tar czf backup/uploads-$(date +%F).tar.gz data/product/uploads/
```

Only needed if you want to re-run detection over the same files later, for
instance after a ruleset change. Alerts already record each file's SHA-256, so
you can prove which capture produced which finding without keeping the capture.

---

## Verify the backup

An untested backup is a hypothesis.

```bash
python -m scripts.init_db --db backup/app-2026-09-11.db --check
```

```
database        backup/app-2026-09-11.db
  schema        v1
  roles         Admin, Analyst, Viewer
  users         3
  devices       41
  alerts        12
  audit events  318
```

Check the counts are roughly what you expect. A backup reporting 0 alerts from a
busy deployment is telling you something.

For a deeper check:

```bash
sqlite3 backup/app-2026-09-11.db "PRAGMA integrity_check;"
```

---

## Restoring

```bash
# 1. Stop the server.

# 2. Move the current database aside — do not delete it. It may hold
#    triage decisions made after the backup was taken.
mv data/product/app.db data/product/app.db.superseded-$(date +%F)

# 3. Put the backup in place.
cp backup/app-2026-09-11.db data/product/app.db

# 4. Apply any migrations newer than the backup. Idempotent.
python -m scripts.init_db

# 5. Confirm.
python -m scripts.init_db --check
python -m scripts.run_server --check
```

### After a restore

* **Triage decisions made after the backup are gone.** Alerts will reappear as
  `Open`. If the superseded database is intact, the `analyst_feedback` table in
  it is the record of what was lost.
* **Sessions survive**, because they live in signed cookies rather than in the
  database — provided `PRODUCT_SESSION_SECRET` is unchanged.
* **Pseudonyms stay stable**, because the salt is restored with the database.
  This is exactly why the salt must never be regenerated: a new salt turns every
  existing device row into an orphan and every future ingest of the same device
  into a new one.
* **Re-ingesting captures is safe.** The dedup key is deterministic, so replaying
  the same file coalesces into existing alerts rather than duplicating them.

---

## Disaster recovery from nothing

Rebuilding on a fresh host with no database at all:

```bash
git clone <repo> && cd Entreprise
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt

# The signing key must be the ORIGINAL one if you want existing sessions and
# CSRF tokens to remain valid. A new key simply signs everyone out.
export PRODUCT_SESSION_SECRET="<from your secret store>"

python -m scripts.init_db
cp <backup>/app.db data/product/app.db
python -m scripts.init_db          # migrate the restored file
python -m scripts.init_db --check
python -m scripts.run_server
```

With **no** database backup, you start clean: `init_db`, then `create_user`,
then re-ingest the captures you still have. Detection is deterministic — the
same file, same ruleset and same config produce the same alerts — so the alert
set is fully reconstructible. Only the **analyst history** is not: triage
decisions, dispositions and notes exist nowhere else, which is the real argument
for backing up the database rather than relying on the captures.

---

## Retention interacts with backups

`storage.retention_days` (90 by default) purges old rows, and an Admin purge
writes a `data.purge` audit event. A backup older than the retention window
contains data the live system has deliberately discarded.

If retention is a compliance requirement rather than a housekeeping preference,
your backup retention has to match it — otherwise the purge is cosmetic.

---

## A workable schedule

| When | What |
|---|---|
| Daily | `.backup` the database; keep 7 |
| Weekly | copy one daily to separate storage; keep 4 |
| Monthly | `--check` a random archive and confirm the counts; keep 12 |
| Before any upgrade | `.backup` to `backup/pre-upgrade.db` |
| On key rotation | record the new `PRODUCT_SESSION_SECRET` in the secret store **before** restarting |

The monthly verification is the step that gets skipped and the one that matters.
