"""
storage.repository — thin, parameterised data access, one class per entity.

Rules that hold everywhere in this module:

  * Every value that varies at runtime is bound with a ``?`` placeholder, never
    formatted into the SQL string. The dynamic parts of a query (which optional
    filters apply) are assembled from *literal* clause fragments only, so a
    hostile username or search term is data, not code. tests/test_storage_*
    proves this behaviourally by trying an injection string.
  * ``audit_events`` has an ``append`` and reads, and no update or delete — the
    absence is the point. There is no code path that can rewrite history.
  * Idempotent writes (devices, observation windows, feature snapshots, model
    registration, role seeding) use ``INSERT OR IGNORE`` + re-select, so
    re-ingesting the same file does not duplicate rows.

Repositories are constructed on a live connection; group related writes inside
one ``Database.transaction()`` so they commit or roll back together.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from .migrate import PSEUDONYM_SALT_KEY
from .models import (Alert, Device, DetectionModel, IngestionJob, Role, User)

_ALERT_SELECT = (
    "SELECT a.*, d.device_key AS device_key "
    "FROM alerts a JOIN devices d ON d.id = a.device_id"
)


class _Repo:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn


class MetaRepo(_Repo):
    def get(self, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT value FROM app_meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO app_meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def pseudonym_salt(self) -> str:
        salt = self.get(PSEUDONYM_SALT_KEY)
        if salt is None:
            raise RuntimeError(
                "no pseudonymisation salt; database was not migrated/seeded")
        return salt


class RoleRepo(_Repo):
    def all(self) -> list[Role]:
        rows = self.conn.execute("SELECT * FROM roles ORDER BY id").fetchall()
        return [Role.from_row(r) for r in rows]

    def by_name(self, name: str) -> Role | None:
        row = self.conn.execute(
            "SELECT * FROM roles WHERE name = ?", (name,)).fetchone()
        return Role.from_row(row) if row else None

    def by_id(self, role_id: int) -> Role | None:
        row = self.conn.execute(
            "SELECT * FROM roles WHERE id = ?", (role_id,)).fetchone()
        return Role.from_row(row) if row else None


class UserRepo(_Repo):
    _SELECT = (
        "SELECT u.*, r.name AS role_name "
        "FROM users u JOIN roles r ON r.id = u.role_id"
    )

    def create(self, *, username: str, password_hash: str, password_salt: str,
               iterations: int, role_id: int, created_at: str) -> int:
        return self.conn.execute(
            "INSERT INTO users (username, password_hash, password_salt, "
            "iterations, role_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?)",
            (username, password_hash, password_salt, iterations, role_id,
             created_at),
        ).lastrowid

    def by_username(self, username: str) -> User | None:
        row = self.conn.execute(
            self._SELECT + " WHERE u.username = ?", (username,)).fetchone()
        return User.from_row(row) if row else None

    def by_id(self, user_id: int) -> User | None:
        row = self.conn.execute(
            self._SELECT + " WHERE u.id = ?", (user_id,)).fetchone()
        return User.from_row(row) if row else None

    def all(self) -> list[User]:
        rows = self.conn.execute(
            self._SELECT + " ORDER BY u.username").fetchall()
        return [User.from_row(r) for r in rows]

    def count(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM users").fetchone()["n"]

    def set_last_login(self, user_id: int, ts: str) -> None:
        self.conn.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?", (ts, user_id))

    def set_password(self, user_id: int, *, password_hash: str,
                     password_salt: str, iterations: int) -> None:
        self.conn.execute(
            "UPDATE users SET password_hash = ?, password_salt = ?, "
            "iterations = ? WHERE id = ?",
            (password_hash, password_salt, iterations, user_id))

    def set_active(self, user_id: int, active: bool) -> None:
        self.conn.execute(
            "UPDATE users SET is_active = ? WHERE id = ?",
            (int(active), user_id))


class UploadedFileRepo(_Repo):
    def create(self, *, original_filename: str, stored_path: str, sha256: str,
               size_bytes: int, content_type: str | None,
               source_hint: str | None, uploaded_by: int | None,
               uploaded_at: str) -> int:
        return self.conn.execute(
            "INSERT INTO uploaded_files (original_filename, stored_path, "
            "sha256, size_bytes, content_type, source_hint, uploaded_by, "
            "uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (original_filename, stored_path, sha256, size_bytes, content_type,
             source_hint, uploaded_by, uploaded_at),
        ).lastrowid

    def by_id(self, file_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM uploaded_files WHERE id = ?", (file_id,)).fetchone()

    def recent(self, limit: int = 50) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM uploaded_files ORDER BY uploaded_at DESC LIMIT ?",
            (int(limit),),
        ).fetchall()


class IngestionJobRepo(_Repo):
    def create(self, *, uploaded_file_id: int | None, source_dataset: str,
               status: str, created_by: int | None, created_at: str,
               note: str | None = None) -> int:
        return self.conn.execute(
            "INSERT INTO ingestion_jobs (uploaded_file_id, source_dataset, "
            "status, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (uploaded_file_id, source_dataset, status, note, created_by,
             created_at),
        ).lastrowid

    def mark_running(self, job_id: int, ts: str) -> None:
        self.conn.execute(
            "UPDATE ingestion_jobs SET status = 'running', started_at = ? "
            "WHERE id = ?", (ts, job_id))

    def mark_succeeded(self, job_id: int, ts: str, *, flows_read: int,
                       windows_emitted: int) -> None:
        self.conn.execute(
            "UPDATE ingestion_jobs SET status = 'succeeded', finished_at = ?, "
            "flows_read = ?, windows_emitted = ? WHERE id = ?",
            (ts, flows_read, windows_emitted, job_id))

    def mark_failed(self, job_id: int, ts: str, error: str) -> None:
        self.conn.execute(
            "UPDATE ingestion_jobs SET status = 'failed', finished_at = ?, "
            "error = ? WHERE id = ?", (ts, error, job_id))

    def by_id(self, job_id: int) -> IngestionJob | None:
        row = self.conn.execute(
            "SELECT * FROM ingestion_jobs WHERE id = ?", (job_id,)).fetchone()
        return IngestionJob.from_row(row) if row else None

    def recent(self, limit: int = 50) -> list[IngestionJob]:
        rows = self.conn.execute(
            "SELECT * FROM ingestion_jobs ORDER BY created_at DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
        return [IngestionJob.from_row(r) for r in rows]


class DeviceRepo(_Repo):
    def get_or_create(self, device_key: str, *, is_pseudonymised: bool,
                      seen_at: str | None = None) -> int:
        row = self.conn.execute(
            "SELECT id, last_seen FROM devices WHERE device_key = ?",
            (device_key,)).fetchone()
        if row is not None:
            if seen_at is not None:
                self.conn.execute(
                    "UPDATE devices SET last_seen = ? "
                    "WHERE id = ? AND (last_seen IS NULL OR last_seen < ?)",
                    (seen_at, row["id"], seen_at))
            return row["id"]
        return self.conn.execute(
            "INSERT INTO devices (device_key, is_pseudonymised, first_seen, "
            "last_seen) VALUES (?, ?, ?, ?)",
            (device_key, int(is_pseudonymised), seen_at, seen_at),
        ).lastrowid

    def by_id(self, device_id: int) -> Device | None:
        row = self.conn.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return Device.from_row(row) if row else None

    def by_key(self, device_key: str) -> Device | None:
        row = self.conn.execute(
            "SELECT * FROM devices WHERE device_key = ?",
            (device_key,)).fetchone()
        return Device.from_row(row) if row else None

    def all(self, limit: int = 500) -> list[Device]:
        rows = self.conn.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?",
            (int(limit),)).fetchall()
        return [Device.from_row(r) for r in rows]

    def count(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM devices").fetchone()["n"]


class ObservationWindowRepo(_Repo):
    def upsert(self, *, observation_id: str, ingestion_job_id: int | None,
               device_id: int, window_start: str, window_seconds: int,
               source_dataset: str, research_class: str,
               quality_flags: str | None, n_features_missing: int | None,
               created_at: str) -> int:
        self.conn.execute(
            "INSERT OR IGNORE INTO observation_windows (observation_id, "
            "ingestion_job_id, device_id, window_start, window_seconds, "
            "source_dataset, research_class, quality_flags, n_features_missing, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (observation_id, ingestion_job_id, device_id, window_start,
             window_seconds, source_dataset, research_class, quality_flags,
             n_features_missing, created_at),
        )
        return self.conn.execute(
            "SELECT id FROM observation_windows WHERE observation_id = ?",
            (observation_id,)).fetchone()["id"]

    def by_id(self, window_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM observation_windows WHERE id = ?",
            (window_id,)).fetchone()

    def count_for_job(self, job_id: int) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM observation_windows "
            "WHERE ingestion_job_id = ?", (job_id,)).fetchone()["n"]


class FeatureSnapshotRepo(_Repo):
    def upsert(self, *, observation_window_id: int, features_json: str,
               created_at: str) -> int:
        self.conn.execute(
            "INSERT OR IGNORE INTO feature_snapshots (observation_window_id, "
            "features_json, created_at) VALUES (?, ?, ?)",
            (observation_window_id, features_json, created_at),
        )
        return self.conn.execute(
            "SELECT id FROM feature_snapshots WHERE observation_window_id = ?",
            (observation_window_id,)).fetchone()["id"]

    def by_window(self, observation_window_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM feature_snapshots WHERE observation_window_id = ?",
            (observation_window_id,)).fetchone()


class DetectionModelRepo(_Repo):
    def register(self, *, name: str, version: str, kind: str,
                 registered_at: str, training_provenance: str | None = None,
                 validation_metrics_json: str | None = None,
                 calibrated_threshold: float | None = None,
                 feature_schema_json: str | None = None,
                 is_validated: bool = False) -> int:
        self.conn.execute(
            "INSERT OR IGNORE INTO detection_models (name, version, kind, "
            "training_provenance, validation_metrics_json, "
            "calibrated_threshold, feature_schema_json, is_validated, "
            "registered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, version, kind, training_provenance, validation_metrics_json,
             calibrated_threshold, feature_schema_json, int(is_validated),
             registered_at),
        )
        return self.conn.execute(
            "SELECT id FROM detection_models WHERE name = ? AND version = ?",
            (name, version)).fetchone()["id"]

    def get_or_create_rule_baseline(self, *, name: str, version: str,
                                    registered_at: str) -> int:
        # The rule engine's "model": kind='rule', is_validated=0. It is
        # transparent, not ML-validated — the alert marker says exactly that.
        return self.register(name=name, version=version, kind="rule",
                             is_validated=False, registered_at=registered_at)

    def by_name_version(self, name: str, version: str) -> DetectionModel | None:
        row = self.conn.execute(
            "SELECT * FROM detection_models WHERE name = ? AND version = ?",
            (name, version)).fetchone()
        return DetectionModel.from_row(row) if row else None

    def by_id(self, model_id: int) -> DetectionModel | None:
        row = self.conn.execute(
            "SELECT * FROM detection_models WHERE id = ?",
            (model_id,)).fetchone()
        return DetectionModel.from_row(row) if row else None

    def validated_ml_models(self) -> list[DetectionModel]:
        rows = self.conn.execute(
            "SELECT * FROM detection_models "
            "WHERE kind = 'ml' AND is_validated = 1 "
            "ORDER BY registered_at DESC").fetchall()
        return [DetectionModel.from_row(r) for r in rows]

    def all(self) -> list[DetectionModel]:
        rows = self.conn.execute(
            "SELECT * FROM detection_models ORDER BY registered_at DESC"
        ).fetchall()
        return [DetectionModel.from_row(r) for r in rows]


class DetectionRunRepo(_Repo):
    def create(self, *, ingestion_job_id: int | None,
               detection_model_id: int | None, mode: str, created_at: str,
               config_digest: str | None = None) -> int:
        return self.conn.execute(
            "INSERT INTO detection_runs (ingestion_job_id, detection_model_id, "
            "mode, config_digest, created_at, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ingestion_job_id, detection_model_id, mode, config_digest,
             created_at, created_at),
        ).lastrowid

    def finish(self, run_id: int, *, finished_at: str, windows_scored: int,
               alerts_created: int) -> None:
        self.conn.execute(
            "UPDATE detection_runs SET finished_at = ?, windows_scored = ?, "
            "alerts_created = ? WHERE id = ?",
            (finished_at, windows_scored, alerts_created, run_id))

    def by_id(self, run_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM detection_runs WHERE id = ?", (run_id,)).fetchone()


class AlertRepo(_Repo):
    def by_dedup(self, dedup_key: str) -> Alert | None:
        row = self.conn.execute(
            _ALERT_SELECT + " WHERE a.dedup_key = ?", (dedup_key,)).fetchone()
        return Alert.from_row(row) if row else None

    def create(self, *, alert_uid: str, detection_run_id: int | None,
               ingestion_job_id: int | None, device_id: int,
               observation_window_id: int | None, category: str,
               severity: str, confidence: str, explanation: str,
               coverage_note: str | None, provenance: str,
               detection_version: str, source_file: str | None,
               dedup_key: str, status: str, first_seen: str, last_seen: str,
               created_at: str) -> int:
        return self.conn.execute(
            "INSERT INTO alerts (alert_uid, detection_run_id, "
            "ingestion_job_id, device_id, observation_window_id, category, "
            "severity, confidence, explanation, coverage_note, provenance, "
            "detection_version, source_file, dedup_key, status, first_seen, "
            "last_seen, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (alert_uid, detection_run_id, ingestion_job_id, device_id,
             observation_window_id, category, severity, confidence,
             explanation, coverage_note, provenance, detection_version,
             source_file, dedup_key, status, first_seen, last_seen,
             created_at),
        ).lastrowid

    def bump_occurrence(self, alert_id: int, *, last_seen: str) -> None:
        self.conn.execute(
            "UPDATE alerts SET occurrence_count = occurrence_count + 1, "
            "last_seen = ? WHERE id = ?", (last_seen, alert_id))

    def set_status(self, alert_id: int, status: str) -> None:
        self.conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))

    def set_severity(self, alert_id: int, severity: str) -> None:
        # Used only when a recurrence broadens an existing pattern. The caller
        # (alerts.builder) raises severity and never lowers it: a later quiet
        # window must not downgrade evidence an analyst has already acted on.
        self.conn.execute(
            "UPDATE alerts SET severity = ? WHERE id = ?",
            (severity, alert_id))

    def by_id(self, alert_id: int) -> Alert | None:
        row = self.conn.execute(
            _ALERT_SELECT + " WHERE a.id = ?", (alert_id,)).fetchone()
        return Alert.from_row(row) if row else None

    def by_uid(self, alert_uid: str) -> Alert | None:
        row = self.conn.execute(
            _ALERT_SELECT + " WHERE a.alert_uid = ?", (alert_uid,)).fetchone()
        return Alert.from_row(row) if row else None

    def _filters(self, status, category, device_id, q) -> tuple[str, list]:
        clauses: list[str] = []
        params: list[Any] = []
        if status:
            clauses.append("a.status = ?")
            params.append(status)
        if category:
            clauses.append("a.category = ?")
            params.append(category)
        if device_id is not None:
            clauses.append("a.device_id = ?")
            params.append(device_id)
        if q:
            like = f"%{q}%"           # a bound VALUE, never part of the SQL text
            clauses.append("(a.explanation LIKE ? OR a.alert_uid LIKE ? "
                           "OR a.source_file LIKE ?)")
            params.extend([like, like, like])
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def search(self, *, status: str | None = None, category: str | None = None,
               device_id: int | None = None, q: str | None = None,
               limit: int = 50, offset: int = 0) -> list[Alert]:
        where, params = self._filters(status, category, device_id, q)
        sql = _ALERT_SELECT + where + " ORDER BY a.last_seen DESC LIMIT ? OFFSET ?"
        rows = self.conn.execute(
            sql, params + [int(limit), int(offset)]).fetchall()
        return [Alert.from_row(r) for r in rows]

    def count(self, *, status: str | None = None, category: str | None = None,
              device_id: int | None = None, q: str | None = None) -> int:
        where, params = self._filters(status, category, device_id, q)
        sql = "SELECT COUNT(*) AS n FROM alerts a" + where
        return self.conn.execute(sql, params).fetchone()["n"]

    def status_counts(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) AS n FROM alerts GROUP BY status"
        ).fetchall()
        return {r["status"]: r["n"] for r in rows}

    def category_counts(self) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT category, COUNT(*) AS n FROM alerts GROUP BY category"
        ).fetchall()
        return {r["category"]: r["n"] for r in rows}


class AlertEvidenceRepo(_Repo):
    def add(self, *, alert_id: int, kind: str, name: str,
            value: str | None, weight: float | None, created_at: str) -> int:
        return self.conn.execute(
            "INSERT INTO alert_evidence (alert_id, kind, name, value, weight, "
            "created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (alert_id, kind, name, value, weight, created_at),
        ).lastrowid

    def for_alert(self, alert_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM alert_evidence WHERE alert_id = ? ORDER BY id",
            (alert_id,)).fetchall()


class AnalystFeedbackRepo(_Repo):
    def add(self, *, alert_id: int, user_id: int | None,
            from_status: str | None, to_status: str | None,
            disposition: str | None, comment: str | None,
            created_at: str) -> int:
        return self.conn.execute(
            "INSERT INTO analyst_feedback (alert_id, user_id, from_status, "
            "to_status, disposition, comment, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (alert_id, user_id, from_status, to_status, disposition, comment,
             created_at),
        ).lastrowid

    def for_alert(self, alert_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM analyst_feedback WHERE alert_id = ? ORDER BY id",
            (alert_id,)).fetchall()


class AuditRepo(_Repo):
    """Append-only. There is deliberately no update or delete method: the audit
    trail is insert-only by construction, not by convention."""

    def append(self, *, action: str, actor_user_id: int | None = None,
               actor_username: str | None = None,
               target_type: str | None = None, target_id: str | None = None,
               request_id: str | None = None, detail_json: str | None = None,
               created_at: str) -> int:
        return self.conn.execute(
            "INSERT INTO audit_events (actor_user_id, actor_username, action, "
            "target_type, target_id, request_id, detail_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (actor_user_id, actor_username, action, target_type, target_id,
             request_id, detail_json, created_at),
        ).lastrowid

    def recent(self, limit: int = 100, offset: int = 0) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?",
            (int(limit), int(offset))).fetchall()

    def count(self) -> int:
        return self.conn.execute(
            "SELECT COUNT(*) AS n FROM audit_events").fetchone()["n"]


class Repository:
    """Facade bundling every entity repository over one connection."""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.meta = MetaRepo(conn)
        self.roles = RoleRepo(conn)
        self.users = UserRepo(conn)
        self.files = UploadedFileRepo(conn)
        self.jobs = IngestionJobRepo(conn)
        self.devices = DeviceRepo(conn)
        self.windows = ObservationWindowRepo(conn)
        self.features = FeatureSnapshotRepo(conn)
        self.models = DetectionModelRepo(conn)
        self.runs = DetectionRunRepo(conn)
        self.alerts = AlertRepo(conn)
        self.evidence = AlertEvidenceRepo(conn)
        self.feedback = AnalystFeedbackRepo(conn)
        self.audit = AuditRepo(conn)
