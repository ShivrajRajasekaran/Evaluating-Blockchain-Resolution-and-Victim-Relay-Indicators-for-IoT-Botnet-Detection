"""
alerts — detection verdicts become auditable, deduplicated, triageable rows.

    from src.alerts import AlertWriter, lifecycle as L

    writer = AlertWriter(repo)
    outcome = writer.persist(detection_result, source_file="conn.log")
    writer.transition(alert_id, L.STATUS_INVESTIGATING, actor=session)

WHAT AN ALERT IS
    A suspicious indicator pattern requiring analyst review — never a confirmed
    incident. Every stored explanation ends with "Rule-based detection; not
    ML-validated.", and every alert raised from a source with blind spots
    carries, on the row, a note saying what could not be measured.

MODULE MAP
    models      AlertDraft / EvidenceItem / PersistResult — the shapes
    dedup       the stable (device, category, version, bucket) identity
    lifecycle   the enforced Open -> Investigating -> disposition -> Closed
                state machine
    builder     verdict -> draft (pure), and draft -> database (AlertWriter)

CONTAINMENT
    Reads and writes one local SQLite database. Nothing here opens a socket,
    contacts a device, or sends a notification anywhere.
"""
from __future__ import annotations

from . import builder, dedup, lifecycle, models
from .builder import (EV_COVERAGE, EV_FEATURE, EV_RULE, AlertError,
                      AlertWriter, build_draft)
from .dedup import DedupError, alert_uid, bucket_for, dedup_key
from .lifecycle import (ACTIVE_STATUSES, DISPOSITION_STATUSES, DISPOSITIONS,
                        STATUS_BENIGN, STATUS_CLOSED,
                        STATUS_CONFIRMED_SUSPICIOUS, STATUS_INVESTIGATING,
                        STATUS_OPEN, STATUSES, TransitionError, allowed_from,
                        can_transition, check_transition, is_active)
from .models import AlertDraft, EvidenceItem, PersistResult

__all__ = [
    "builder", "dedup", "lifecycle", "models",
    "AlertWriter", "AlertError", "build_draft",
    "EV_RULE", "EV_FEATURE", "EV_COVERAGE",
    "AlertDraft", "EvidenceItem", "PersistResult",
    "dedup_key", "alert_uid", "bucket_for", "DedupError",
    "STATUSES", "STATUS_OPEN", "STATUS_INVESTIGATING", "STATUS_BENIGN",
    "STATUS_CONFIRMED_SUSPICIOUS", "STATUS_CLOSED", "ACTIVE_STATUSES",
    "DISPOSITION_STATUSES", "DISPOSITIONS", "TransitionError",
    "allowed_from", "can_transition", "check_transition", "is_active",
]
