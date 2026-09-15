"""
storage.models — typed views over stored rows.

Not every read needs a type: list queries that only feed a template return
``sqlite3.Row`` (which supports both ``row["col"]`` and dotted access from
Jinja). The entities below get dataclasses because Python *logic* — not just a
template — reads them: auth checks a :class:`User`, the lifecycle engine moves an
:class:`Alert`, the model gate inspects a :class:`DetectionModel`. Attribute
access and a single ``from_row`` constructor keep that logic readable and make a
renamed column fail loudly at construction rather than silently at use.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any


def _opt(row: sqlite3.Row, key: str, default: Any = None) -> Any:
    """A column that may not be present in every SELECT (e.g. a joined name)."""
    return row[key] if key in row.keys() else default


@dataclass(frozen=True)
class Role:
    id: int
    name: str
    description: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Role":
        return cls(id=row["id"], name=row["name"],
                   description=_opt(row, "description"))


@dataclass(frozen=True)
class User:
    id: int
    username: str
    password_hash: str
    password_salt: str
    iterations: int
    role_id: int
    is_active: bool
    created_at: str
    last_login_at: str | None
    role: str | None  # joined role name when the query provides it

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "User":
        return cls(
            id=row["id"], username=row["username"],
            password_hash=row["password_hash"],
            password_salt=row["password_salt"],
            iterations=row["iterations"], role_id=row["role_id"],
            is_active=bool(row["is_active"]), created_at=row["created_at"],
            last_login_at=_opt(row, "last_login_at"),
            role=_opt(row, "role_name"),
        )


@dataclass(frozen=True)
class Device:
    id: int
    device_key: str
    is_pseudonymised: bool
    note: str | None
    first_seen: str | None
    last_seen: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Device":
        return cls(
            id=row["id"], device_key=row["device_key"],
            is_pseudonymised=bool(row["is_pseudonymised"]),
            note=_opt(row, "note"), first_seen=_opt(row, "first_seen"),
            last_seen=_opt(row, "last_seen"),
        )


@dataclass(frozen=True)
class IngestionJob:
    id: int
    uploaded_file_id: int | None
    source_dataset: str
    status: str
    flows_read: int | None
    windows_emitted: int | None
    note: str | None
    error: str | None
    created_by: int | None
    created_at: str
    started_at: str | None
    finished_at: str | None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "IngestionJob":
        return cls(
            id=row["id"], uploaded_file_id=_opt(row, "uploaded_file_id"),
            source_dataset=row["source_dataset"], status=row["status"],
            flows_read=_opt(row, "flows_read"),
            windows_emitted=_opt(row, "windows_emitted"),
            note=_opt(row, "note"), error=_opt(row, "error"),
            created_by=_opt(row, "created_by"), created_at=row["created_at"],
            started_at=_opt(row, "started_at"),
            finished_at=_opt(row, "finished_at"),
        )


@dataclass(frozen=True)
class DetectionModel:
    id: int
    name: str
    version: str
    kind: str
    training_provenance: str | None
    validation_metrics_json: str | None
    calibrated_threshold: float | None
    feature_schema_json: str | None
    is_validated: bool
    registered_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "DetectionModel":
        return cls(
            id=row["id"], name=row["name"], version=row["version"],
            kind=row["kind"],
            training_provenance=_opt(row, "training_provenance"),
            validation_metrics_json=_opt(row, "validation_metrics_json"),
            calibrated_threshold=_opt(row, "calibrated_threshold"),
            feature_schema_json=_opt(row, "feature_schema_json"),
            is_validated=bool(row["is_validated"]),
            registered_at=row["registered_at"],
        )


@dataclass(frozen=True)
class Alert:
    id: int
    alert_uid: str
    detection_run_id: int | None
    ingestion_job_id: int | None
    device_id: int
    observation_window_id: int | None
    category: str
    severity: str
    confidence: str
    explanation: str
    coverage_note: str | None
    provenance: str
    detection_version: str
    source_file: str | None
    dedup_key: str
    occurrence_count: int
    status: str
    first_seen: str
    last_seen: str
    created_at: str
    device_key: str | None  # joined for display when the query provides it

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Alert":
        return cls(
            id=row["id"], alert_uid=row["alert_uid"],
            detection_run_id=_opt(row, "detection_run_id"),
            ingestion_job_id=_opt(row, "ingestion_job_id"),
            device_id=row["device_id"],
            observation_window_id=_opt(row, "observation_window_id"),
            category=row["category"], severity=row["severity"],
            confidence=row["confidence"], explanation=row["explanation"],
            coverage_note=_opt(row, "coverage_note"),
            provenance=row["provenance"],
            detection_version=row["detection_version"],
            source_file=_opt(row, "source_file"), dedup_key=row["dedup_key"],
            occurrence_count=row["occurrence_count"], status=row["status"],
            first_seen=row["first_seen"], last_seen=row["last_seen"],
            created_at=row["created_at"], device_key=_opt(row, "device_key"),
        )
