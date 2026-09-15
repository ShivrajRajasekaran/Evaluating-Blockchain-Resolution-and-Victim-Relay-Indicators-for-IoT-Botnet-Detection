"""
alerts/builder.py — detection verdicts become auditable, deduplicated alerts.

TWO HALVES, DELIBERATELY SEPARATE
    :func:`build_draft` is pure: a verdict plus a device key becomes an
    :class:`~src.alerts.models.AlertDraft`, with no database in sight. Every
    mapping decision — which categories raise, what the explanation reads like,
    what counts as evidence — is therefore testable on its own.

    :class:`AlertWriter` is the persistence half: it resolves device keys
    (pseudonymising when configured), writes or coalesces rows, records
    evidence, stamps the audit trail, and drives the lifecycle. It holds a
    repository bound to one connection, so an alert, its evidence and its audit
    event commit together or not at all.

WHAT IS AND IS NOT WRITTEN
    Only the four SUSPICIOUS_… categories become alerts. BENIGN_OR_NO_ALERT,
    INSUFFICIENT_TELEMETRY and ABSTAIN are states of knowledge, counted in the
    run summary and shown on the coverage screens, but never queued — an
    analyst queue that fills with "could not measure this" teaches people to
    ignore the queue, which is the opposite of the point.

    The coverage note still travels ON the alerts that ARE raised, so a relay
    finding from a conn.log says, on the row, that nothing could be determined
    about resolution.

RECURRENCE IS NOT A NEW ALERT
    A window whose dedup key already exists bumps the occurrence count and
    advances ``last_seen``. Severity may be raised by a recurrence but never
    lowered (``alerts.escalate_severity``): a device whose pattern broadens
    should get louder, and a later quieter window must not downgrade evidence
    an analyst has already acted on.

CONTAINMENT
    Reads and writes one local database. No network, no device contact.
"""
from __future__ import annotations

from src.audit import events as A
from src.config import load_config
from src.detection import categories as C
from src.storage import resolve_device_key, utcnow_iso

from . import dedup as D
from . import lifecycle as L
from .models import AlertDraft, EvidenceItem, PersistResult

EV_RULE = "rule"
EV_FEATURE = "feature"
EV_COVERAGE = "coverage"


class AlertError(RuntimeError):
    """An alert could not be built or written."""


# ===========================================================================
# The pure half
# ===========================================================================
def build_draft(verdict, *, device_key: str, source_file: str | None = None,
                hours: int = D.DEFAULT_BUCKET_HOURS,
                status: str = L.STATUS_OPEN) -> AlertDraft | None:
    """One verdict to one draft, or ``None`` when it should not be queued."""
    if not verdict.raises_alert:
        return None
    key = D.dedup_key(device_key=device_key, category=verdict.category,
                      detection_version=verdict.detection_version,
                      window_start=verdict.window_start, hours=hours)
    return AlertDraft(
        dedup_key=key,
        alert_uid=D.alert_uid(key),
        device_key=device_key,
        category=verdict.category,
        severity=verdict.severity,
        confidence=verdict.confidence,
        # The marker rides inside the stored explanation, so every surface that
        # renders an alert — dashboard, CSV export, printable report — says it
        # is rule-based without each of them having to remember to.
        explanation=verdict.explanation_with_marker,
        coverage_note=verdict.coverage_note,
        provenance=verdict.provenance,
        detection_version=verdict.detection_version,
        window_start=verdict.window_start,
        observation_id=verdict.observation_id,
        source_file=source_file,
        status=status,
        evidence=_evidence_for(verdict),
    )


def _evidence_for(verdict) -> tuple[EvidenceItem, ...]:
    """Every auditable fact behind one verdict.

    A fired rule and the value that fired it are separate rows: the rule row
    says what the product concluded, the feature row says what it measured, and
    an analyst disputing the conclusion needs the second one.
    """
    items: list[EvidenceItem] = []
    for hit in verdict.hits:
        items.append(EvidenceItem(
            kind=EV_RULE, name=hit.feature,
            value=f"{hit.feature} {hit.op} {hit.threshold:g}",
            weight=1.0))
        items.append(EvidenceItem(
            kind=EV_FEATURE, name=hit.feature, value=f"{hit.value:g}",
            weight=None))
    for group in verdict.coverage.gated_groups:
        if group in verdict.fired_groups:
            continue
        items.append(EvidenceItem(
            kind=EV_COVERAGE, name=group,
            value=verdict.coverage[group].reason or "not measurable",
            weight=None))
    return tuple(items)


# ===========================================================================
# The persistence half
# ===========================================================================
class AlertWriter:
    """Writes a detection run's verdicts into the local database."""

    def __init__(self, repo, *, cfg=None, audit=None):
        self.repo = repo
        self.cfg = cfg or load_config()
        self.audit = audit if audit is not None else A.AuditLog(repo)
        alerts_cfg = self.cfg.alerts
        self.hours = int(alerts_cfg.get("dedup_window_hours",
                                        D.DEFAULT_BUCKET_HOURS))
        self.escalate = bool(alerts_cfg.get("escalate_severity", True))
        self.initial_status = str(
            alerts_cfg.get("initial_status", L.STATUS_OPEN))
        self.max_per_run = int(alerts_cfg.get("max_alerts_per_run", 5000))
        self._pseudonymise = bool(
            self.cfg.storage.get("pseudonymise_devices", True))
        self._salt = repo.meta.pseudonym_salt() if self._pseudonymise else ""

    # -- device identity -------------------------------------------------
    def device_key_for(self, raw_device_id: str) -> tuple[str, bool]:
        """The stored key for a raw device identifier, and whether it is a
        pseudonym. Centralised so no call site can persist a raw address into a
        pseudonymised deployment by forgetting to convert it."""
        return resolve_device_key(raw_device_id, self._salt,
                                  enabled=self._pseudonymise)

    # -- writing a run ---------------------------------------------------
    def persist(self, result, *, ingestion_job_id: int | None = None,
                detection_model_id: int | None = None,
                source_file: str | None = None,
                window_ids: dict[str, int] | None = None,
                actor=None, now: str | None = None) -> PersistResult:
        """Write every alerting verdict in ``result``; coalesce the repeats.

        ``window_ids`` maps observation_id to the ``observation_windows`` row id
        for callers that persisted the windows first; alerts then link to the
        exact window that produced them. Omitting it is legal — the alert still
        records the observation id in its evidence — so detection can be run and
        triaged without the full window archive.
        """
        now = now or utcnow_iso()
        window_ids = window_ids or {}
        run_id = self.repo.runs.create(
            ingestion_job_id=ingestion_job_id,
            detection_model_id=detection_model_id, mode=result.mode,
            created_at=now, config_digest=result.ruleset_digest)

        created = coalesced = 0
        alert_ids: list[int] = []
        truncated = False

        for verdict in result.alerting:
            if created + coalesced >= self.max_per_run:
                truncated = True
                break
            device_key, is_pseudonymised = self.device_key_for(
                verdict.device_id)
            draft = build_draft(verdict, device_key=device_key,
                                source_file=source_file, hours=self.hours,
                                status=self.initial_status)
            if draft is None:            # pragma: no cover - result.alerting filters
                continue
            device_id = self.repo.devices.get_or_create(
                device_key, is_pseudonymised=is_pseudonymised,
                seen_at=verdict.window_start or now)
            existing = self.repo.alerts.by_dedup(draft.dedup_key)
            if existing is None:
                alert_id = self._create(draft, device_id, run_id,
                                        ingestion_job_id,
                                        window_ids.get(draft.observation_id),
                                        now)
                created += 1
            else:
                alert_id = self._coalesce(existing, draft, now)
                coalesced += 1
            alert_ids.append(alert_id)

        self.repo.runs.finish(run_id, finished_at=utcnow_iso(),
                              windows_scored=len(result.verdicts),
                              alerts_created=created)
        self.audit.record(
            A.DETECTION_RUN, actor=actor, target_type="detection_run",
            target_id=run_id, created_at=now,
            detail={"mode": result.mode,
                    "detection_version": result.detection_version,
                    "ruleset_digest": result.ruleset_digest,
                    "windows_scored": len(result.verdicts),
                    "alerts_created": created, "alerts_coalesced": coalesced,
                    "truncated": truncated, "source_file": source_file})
        return PersistResult(run_id=run_id, created=created,
                             coalesced=coalesced,
                             windows_scored=len(result.verdicts),
                             truncated=truncated,
                             alert_ids=tuple(alert_ids))

    def _create(self, draft: AlertDraft, device_id: int, run_id: int | None,
                ingestion_job_id: int | None, window_id: int | None,
                now: str) -> int:
        alert_id = self.repo.alerts.create(
            alert_uid=draft.alert_uid, detection_run_id=run_id,
            ingestion_job_id=ingestion_job_id, device_id=device_id,
            observation_window_id=window_id, category=draft.category,
            severity=draft.severity, confidence=draft.confidence,
            explanation=draft.explanation,
            coverage_note=draft.coverage_note or None,
            provenance=draft.provenance,
            detection_version=draft.detection_version,
            source_file=draft.source_file, dedup_key=draft.dedup_key,
            status=draft.status, first_seen=draft.window_start or now,
            last_seen=draft.window_start or now, created_at=now)
        for item in draft.evidence:
            self.repo.evidence.add(
                alert_id=alert_id, kind=item.kind, name=item.name,
                value=item.value, weight=item.weight, created_at=now)
        return alert_id

    def _coalesce(self, existing, draft: AlertDraft, now: str) -> int:
        """A recurrence: bump the count, advance last_seen, never downgrade."""
        self.repo.alerts.bump_occurrence(
            existing.id, last_seen=draft.window_start or now)
        if self.escalate:
            from src.detection.severity import max_severity
            raised = max_severity(existing.severity, draft.severity)
            if raised != existing.severity:
                self.repo.alerts.set_severity(existing.id, raised)
        return existing.id

    # -- the analyst workflow --------------------------------------------
    def transition(self, alert_id: int, target: str, *, actor=None,
                   comment: str | None = None, disposition: str | None = None,
                   now: str | None = None):
        """Move an alert through the lifecycle, recording who and why.

        One call does all four things a status change must do — validate the
        move, update the head, append the history row, and write the audit
        event — so no caller can do three of them.
        """
        now = now or utcnow_iso()
        alert = self.repo.alerts.by_id(alert_id)
        if alert is None:
            raise AlertError(f"no alert with id {alert_id}")
        L.check_transition(alert.status, target)
        L.check_disposition(disposition)

        self.repo.alerts.set_status(alert_id, target)
        self.repo.feedback.add(
            alert_id=alert_id, user_id=_actor_id(actor),
            from_status=alert.status, to_status=target,
            disposition=disposition, comment=comment, created_at=now)
        self.audit.record(
            A.ALERT_STATUS, actor=actor, target_type="alert",
            target_id=alert_id, created_at=now,
            detail={"from": alert.status, "to": target,
                    "disposition": disposition,
                    "category": alert.category})
        return self.repo.alerts.by_id(alert_id)

    def add_feedback(self, alert_id: int, *, comment: str, actor=None,
                     disposition: str | None = None,
                     now: str | None = None) -> int:
        """Record an analyst note without changing the status.

        A comment is a first-class contribution: "checked the vendor's docs,
        this device polls every 30s by design" is worth keeping whether or not
        the analyst is ready to close the alert.
        """
        now = now or utcnow_iso()
        alert = self.repo.alerts.by_id(alert_id)
        if alert is None:
            raise AlertError(f"no alert with id {alert_id}")
        L.check_disposition(disposition)
        feedback_id = self.repo.feedback.add(
            alert_id=alert_id, user_id=_actor_id(actor),
            from_status=alert.status, to_status=alert.status,
            disposition=disposition, comment=comment, created_at=now)
        self.audit.record(
            A.ALERT_FEEDBACK, actor=actor, target_type="alert",
            target_id=alert_id, created_at=now,
            detail={"status": alert.status, "disposition": disposition})
        return feedback_id


def _actor_id(actor) -> int | None:
    if actor is None:
        return None
    uid = getattr(actor, "user_id", None)
    return uid if uid is not None else getattr(actor, "id", None)
