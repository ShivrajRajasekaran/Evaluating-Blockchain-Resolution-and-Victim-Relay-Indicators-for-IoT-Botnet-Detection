-- 0001_init.sql — the operational product's data model.
--
-- Thirteen domain tables (roles, users, uploaded_files, ingestion_jobs,
-- devices, observation_windows, feature_snapshots, detection_models,
-- detection_runs, alerts, alert_evidence, analyst_feedback, audit_events) plus
-- two infrastructure tables (schema_migrations, app_meta).
--
-- Conventions, chosen for portability and honesty:
--   * timestamps are TEXT ISO-8601 UTC, never a DB clock function, so a row's
--     provenance does not depend on server timezone;
--   * booleans are INTEGER 0/1 (SQLite has no BOOLEAN);
--   * every child row names its parent with a REFERENCES clause and foreign
--     keys are enforced (PRAGMA foreign_keys=ON, set per connection in db.py);
--   * denormalised actor_username on audit_events survives user deletion — an
--     audit trail that a later DELETE could blank is not an audit trail.
--
-- The DDL is SQLite dialect. The repository layer speaks only parameterised
-- INSERT/SELECT/UPDATE, so porting to PostgreSQL is a new migration file plus a
-- paramstyle swap, not a query rewrite. Postgres stays gated off this build.

-- --------------------------------------------------------------------------
-- Infrastructure
-- --------------------------------------------------------------------------
CREATE TABLE schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

-- Key/value install settings. Holds the per-install pseudonymisation salt,
-- generated once at init; keeping it out of the config file means two installs
-- never map the same device to the same pseudonym.
CREATE TABLE app_meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- --------------------------------------------------------------------------
-- Identity & access
-- --------------------------------------------------------------------------
CREATE TABLE roles (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    description  TEXT
);

CREATE TABLE users (
    id             INTEGER PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    -- PBKDF2-HMAC-SHA256; hash and salt are hex, iterations recorded per row so
    -- the cost factor can be raised later without invalidating old hashes.
    password_hash  TEXT NOT NULL,
    password_salt  TEXT NOT NULL,
    iterations     INTEGER NOT NULL,
    role_id        INTEGER NOT NULL REFERENCES roles(id),
    is_active      INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL,
    last_login_at  TEXT
);
CREATE INDEX idx_users_role ON users(role_id);

-- --------------------------------------------------------------------------
-- Ingestion
-- --------------------------------------------------------------------------
CREATE TABLE uploaded_files (
    id                 INTEGER PRIMARY KEY,
    -- Display only; never used to open a path. The bytes live at stored_path
    -- under a generated name, so a crafted filename cannot escape the jobs dir.
    original_filename  TEXT NOT NULL,
    stored_path        TEXT NOT NULL,
    sha256             TEXT NOT NULL,
    size_bytes         INTEGER NOT NULL,
    content_type       TEXT,
    source_hint        TEXT,
    uploaded_by        INTEGER REFERENCES users(id),
    uploaded_at        TEXT NOT NULL
);

CREATE TABLE ingestion_jobs (
    id                INTEGER PRIMARY KEY,
    uploaded_file_id  INTEGER REFERENCES uploaded_files(id),
    source_dataset    TEXT NOT NULL,            -- op_zeek | op_flow_csv | ...
    status            TEXT NOT NULL,            -- pending|running|succeeded|failed
    flows_read        INTEGER,
    windows_emitted   INTEGER,
    note              TEXT,
    error             TEXT,
    created_by        INTEGER REFERENCES users(id),
    created_at        TEXT NOT NULL,
    started_at        TEXT,
    finished_at       TEXT
);
CREATE INDEX idx_jobs_status ON ingestion_jobs(status);

-- --------------------------------------------------------------------------
-- Devices & observations
-- --------------------------------------------------------------------------
CREATE TABLE devices (
    id                INTEGER PRIMARY KEY,
    -- The canonical identifier used everywhere downstream. When
    -- storage.pseudonymise_devices is on this is a salted hash and the raw
    -- address is never stored; when off it is the raw address.
    device_key        TEXT NOT NULL UNIQUE,
    is_pseudonymised  INTEGER NOT NULL,
    note              TEXT,
    first_seen        TEXT,
    last_seen         TEXT
);

CREATE TABLE observation_windows (
    id               INTEGER PRIMARY KEY,
    -- Deterministic natural key from schema.make_observation_id; UNIQUE so
    -- re-ingesting the same file is idempotent rather than duplicating windows.
    observation_id   TEXT NOT NULL UNIQUE,
    ingestion_job_id INTEGER REFERENCES ingestion_jobs(id),
    device_id        INTEGER NOT NULL REFERENCES devices(id),
    window_start     TEXT NOT NULL,
    window_seconds   INTEGER NOT NULL,
    source_dataset   TEXT NOT NULL,
    research_class   TEXT NOT NULL,             -- operational => 'unmapped'
    quality_flags    TEXT,
    n_features_missing INTEGER,
    created_at       TEXT NOT NULL
);
CREATE INDEX idx_windows_device ON observation_windows(device_id);
CREATE INDEX idx_windows_job ON observation_windows(ingestion_job_id);

-- The 16 features as JSON (a NaN the capture never recorded is stored as null,
-- never 0). One snapshot per window; the alert evidence panel reads it back.
CREATE TABLE feature_snapshots (
    id                     INTEGER PRIMARY KEY,
    observation_window_id  INTEGER NOT NULL UNIQUE REFERENCES observation_windows(id),
    features_json          TEXT NOT NULL,
    created_at             TEXT NOT NULL
);

-- --------------------------------------------------------------------------
-- Detection
-- --------------------------------------------------------------------------
CREATE TABLE detection_models (
    id                    INTEGER PRIMARY KEY,
    name                  TEXT NOT NULL,
    version               TEXT NOT NULL,
    kind                  TEXT NOT NULL,        -- 'rule' | 'ml'
    -- ML models must carry all four before they may score (see model_gate).
    -- The rule baseline registers with kind='rule' and is_validated=0: it is
    -- transparent, not ML-validated.
    training_provenance   TEXT,
    validation_metrics_json TEXT,
    calibrated_threshold  REAL,
    feature_schema_json   TEXT,
    is_validated          INTEGER NOT NULL DEFAULT 0,
    registered_at         TEXT NOT NULL,
    UNIQUE(name, version)
);

CREATE TABLE detection_runs (
    id                 INTEGER PRIMARY KEY,
    ingestion_job_id   INTEGER REFERENCES ingestion_jobs(id),
    detection_model_id INTEGER REFERENCES detection_models(id),
    mode               TEXT NOT NULL,           -- 'rule' | 'model'
    windows_scored     INTEGER,
    alerts_created     INTEGER,
    config_digest      TEXT,
    created_at         TEXT NOT NULL,
    started_at         TEXT,
    finished_at        TEXT
);

-- --------------------------------------------------------------------------
-- Alerts & analyst workflow
-- --------------------------------------------------------------------------
CREATE TABLE alerts (
    id                    INTEGER PRIMARY KEY,
    alert_uid             TEXT NOT NULL UNIQUE, -- stable public id
    detection_run_id      INTEGER REFERENCES detection_runs(id),
    ingestion_job_id      INTEGER REFERENCES ingestion_jobs(id),
    device_id             INTEGER NOT NULL REFERENCES devices(id),
    observation_window_id INTEGER REFERENCES observation_windows(id),
    category              TEXT NOT NULL,        -- one of the 7 operational categories
    severity              TEXT NOT NULL,        -- INFO|LOW|MEDIUM|HIGH
    confidence            TEXT NOT NULL,        -- low|medium|high (coarse)
    explanation           TEXT NOT NULL,        -- human-readable rule evidence
    coverage_note         TEXT,                 -- what the source could/could not measure
    provenance            TEXT NOT NULL,        -- e.g. the rule_marker
    detection_version     TEXT NOT NULL,        -- rule-set or model version string
    source_file           TEXT,                 -- original filename, display only
    -- Dedup: repeated windows for the same (device, category, rolling key)
    -- coalesce into one alert with a bumped occurrence_count.
    dedup_key             TEXT NOT NULL,
    occurrence_count      INTEGER NOT NULL DEFAULT 1,
    status                TEXT NOT NULL DEFAULT 'Open',
    first_seen            TEXT NOT NULL,
    last_seen             TEXT NOT NULL,
    created_at            TEXT NOT NULL
);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_device ON alerts(device_id);
CREATE INDEX idx_alerts_category ON alerts(category);
CREATE UNIQUE INDEX idx_alerts_dedup ON alerts(dedup_key);

-- One row per piece of evidence behind an alert: a fired rule, a feature value,
-- or a coverage note. kind keeps them apart in the evidence panel.
CREATE TABLE alert_evidence (
    id          INTEGER PRIMARY KEY,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id),
    kind        TEXT NOT NULL,                  -- 'rule' | 'feature' | 'coverage'
    name        TEXT NOT NULL,
    value       TEXT,
    weight      REAL,
    created_at  TEXT NOT NULL
);
CREATE INDEX idx_evidence_alert ON alert_evidence(alert_id);

-- Analyst lifecycle. Each transition is one row (from_status -> to_status) with
-- an optional disposition and comment; the alerts.status column is the current
-- head and this table is its history.
CREATE TABLE analyst_feedback (
    id           INTEGER PRIMARY KEY,
    alert_id     INTEGER NOT NULL REFERENCES alerts(id),
    user_id      INTEGER REFERENCES users(id),
    from_status  TEXT,
    to_status    TEXT,
    disposition  TEXT,
    comment      TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX idx_feedback_alert ON analyst_feedback(alert_id);

-- --------------------------------------------------------------------------
-- Audit — append only. There is no UPDATE or DELETE path in the repository.
-- --------------------------------------------------------------------------
CREATE TABLE audit_events (
    id              INTEGER PRIMARY KEY,
    -- ON DELETE SET NULL, not RESTRICT: an admin may remove a user, and when
    -- they do the audit row keeps the denormalised actor_username while the id
    -- goes NULL. The trail records who acted even after the account is gone.
    actor_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    actor_username  TEXT,                       -- denormalised, survives deletion
    action          TEXT NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    request_id      TEXT,
    detail_json     TEXT,
    created_at      TEXT NOT NULL
);
CREATE INDEX idx_audit_created ON audit_events(created_at);
CREATE INDEX idx_audit_actor ON audit_events(actor_user_id);
