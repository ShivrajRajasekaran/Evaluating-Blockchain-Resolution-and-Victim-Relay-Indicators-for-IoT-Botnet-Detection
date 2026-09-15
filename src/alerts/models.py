"""
alerts/models.py — the alert as it exists between detection and the database.

WHY A DRAFT TYPE AT ALL
    :class:`~src.detection.engine.WindowVerdict` is about ONE 5-minute window;
    an alert is about a device-and-pattern over time, and carries persistence
    concerns a verdict has no business knowing — a dedup key, a status, a
    device row id, the job and run that produced it. :class:`AlertDraft` is the
    translation, and it exists as its own type so the mapping can be tested
    without a database and so the repository call sites have exactly one shape
    to satisfy.

    A draft is immutable and carries no id. It becomes an alert when the
    builder writes it, or coalesces into an existing one when its dedup key is
    already present.

WHAT EVERY DRAFT PROMISES
    * ``category`` is one of the seven operational categories, never a research
      class and never a confirmation.
    * ``explanation`` is the evidence in words, and always ends with the honesty
      marker, so no rendering path can show a finding without saying it is
      rule-based and not ML-validated.
    * ``coverage_note`` says what the telemetry could NOT speak to, or is empty.
      It is a first-class column rather than a footnote because on most real
      sources it is the most important thing on the row.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .lifecycle import STATUS_OPEN


@dataclass(frozen=True)
class EvidenceItem:
    """One auditable fact behind an alert.

    ``kind`` is 'rule' (a threshold crossed), 'feature' (the measured value) or
    'coverage' (a group that could not be judged). The evidence panel groups by
    it, and an analyst reading a rule row can see the feature row that produced
    it directly beneath.
    """

    kind: str
    name: str
    value: str | None = None
    weight: float | None = None

    def as_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name, "value": self.value,
                "weight": self.weight}


@dataclass(frozen=True)
class AlertDraft:
    """An alert ready to be written, or to coalesce into an existing row."""

    dedup_key: str
    alert_uid: str
    device_key: str
    category: str
    severity: str
    confidence: str
    explanation: str
    coverage_note: str
    provenance: str
    detection_version: str
    window_start: str
    observation_id: str
    source_file: str | None = None
    status: str = STATUS_OPEN
    evidence: tuple[EvidenceItem, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "dedup_key": self.dedup_key,
            "alert_uid": self.alert_uid,
            "device_key": self.device_key,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "coverage_note": self.coverage_note,
            "provenance": self.provenance,
            "detection_version": self.detection_version,
            "window_start": self.window_start,
            "observation_id": self.observation_id,
            "source_file": self.source_file,
            "status": self.status,
            "evidence": [e.as_dict() for e in self.evidence],
        }


@dataclass(frozen=True)
class PersistResult:
    """What one detection run actually wrote, for the run report and audit.

    ``coalesced`` is reported separately from ``created`` on purpose: a run that
    produced 300 hits and 2 alerts is working correctly, and an operator who
    sees only "2 alerts" cannot tell that from a run that barely fired.
    """

    run_id: int | None
    created: int = 0
    coalesced: int = 0
    windows_scored: int = 0
    truncated: bool = False
    alert_ids: tuple[int, ...] = field(default_factory=tuple)

    @property
    def total(self) -> int:
        return self.created + self.coalesced

    def as_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "alerts_created": self.created,
            "alerts_coalesced": self.coalesced,
            "alerts_total": self.total,
            "windows_scored": self.windows_scored,
            "truncated": self.truncated,
        }
