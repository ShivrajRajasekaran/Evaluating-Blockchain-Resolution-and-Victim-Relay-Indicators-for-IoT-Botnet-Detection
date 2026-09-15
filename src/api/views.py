"""
api/views.py — the shapes the dashboard and the JSON API both render.

WHY ONE SET OF VIEW MODELS FOR BOTH
    The HTML pages and the JSON routes must not describe the same alert
    differently. If the API said "category" and the page said "type", or the
    page carried the coverage note and the export quietly dropped it, the
    product would be telling two stories about the same row. Every projection
    lives here, once, and both renderers call it.

WHAT EVERY ALERT PROJECTION CARRIES
    The category, severity and confidence — and the coverage note, always, even
    when empty. On the telemetry this product actually ingests the note is
    frequently the most important field on the row ("nothing could be
    determined about resolution"), so it is never an optional extra that a
    caller might forget to select.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.alerts import lifecycle as L
from src.detection import categories as C
from src.detection import coverage as COV
from src.schema import columns as K

# How a category is worded for a human. The constant is what is stored, filtered
# and exported; this is only the label on screen, and it says the same thing.
CATEGORY_LABELS: dict[str, str] = {
    C.CAT_BENIGN_OR_NO_ALERT: "No indicator fired",
    C.CAT_SUSPICIOUS_RESOLUTION: "Suspicious resolution pattern",
    C.CAT_SUSPICIOUS_RELAY: "Suspicious relay pattern",
    C.CAT_SUSPICIOUS_COMBINED: "Suspicious combined pattern",
    C.CAT_SUSPICIOUS_CONVENTIONAL: "Suspicious conventional botnet pattern",
    C.CAT_INSUFFICIENT_TELEMETRY: "Insufficient telemetry",
    C.CAT_ABSTAIN: "Abstained",
}

SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW", "INFO")


@dataclass(frozen=True)
class Page:
    """One page of results, and everything a pager needs to render itself."""

    items: list
    total: int
    page: int
    page_size: int

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.page_size))   # ceil

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.pages

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    def as_dict(self, project=None) -> dict:
        project = project or (lambda x: x)
        return {
            "items": [project(i) for i in self.items],
            "total": self.total, "page": self.page,
            "page_size": self.page_size, "pages": self.pages,
        }


def clamp_page(raw, default: int = 1) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, value)


def clamp_page_size(raw, *, default: int, maximum: int) -> int:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, min(int(maximum), value))


def alert_view(alert, *, evidence=None, feedback=None) -> dict:
    """One alert as both renderers see it."""
    out = {
        "id": alert.id,
        "alert_uid": alert.alert_uid,
        "device_key": alert.device_key,
        "category": alert.category,
        "category_label": CATEGORY_LABELS.get(alert.category, alert.category),
        "severity": alert.severity,
        "confidence": alert.confidence,
        "explanation": alert.explanation,
        # Always present, never omitted when empty: a blind spot that is not
        # rendered is a blind spot the analyst does not know about.
        "coverage_note": alert.coverage_note or "",
        "provenance": alert.provenance,
        "detection_version": alert.detection_version,
        "source_file": alert.source_file,
        "status": alert.status,
        "is_active": L.is_active(alert.status),
        "allowed_transitions": list(L.allowed_from(alert.status)),
        "occurrence_count": alert.occurrence_count,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "created_at": alert.created_at,
        "observation_window_id": alert.observation_window_id,
        "ingestion_job_id": alert.ingestion_job_id,
        "detection_run_id": alert.detection_run_id,
        "review_only": True,
    }
    if evidence is not None:
        out["evidence"] = [evidence_view(e) for e in evidence]
    if feedback is not None:
        out["feedback"] = [feedback_view(f) for f in feedback]
    return out


def evidence_view(row) -> dict:
    return {"kind": row["kind"], "name": row["name"], "value": row["value"],
            "weight": row["weight"], "created_at": row["created_at"]}


def feedback_view(row) -> dict:
    return {"from_status": row["from_status"], "to_status": row["to_status"],
            "disposition": row["disposition"], "comment": row["comment"],
            "created_at": row["created_at"]}


def device_view(device) -> dict:
    return {"id": device.id, "device_key": device.device_key,
            "is_pseudonymised": bool(device.is_pseudonymised),
            "first_seen": device.first_seen, "last_seen": device.last_seen}


def job_view(job) -> dict:
    return {"id": job.id, "source_dataset": job.source_dataset,
            "status": job.status, "flows_read": job.flows_read,
            "windows_emitted": job.windows_emitted, "note": job.note,
            "error": job.error, "created_at": job.created_at,
            "started_at": job.started_at, "finished_at": job.finished_at,
            "uploaded_file_id": job.uploaded_file_id}


def audit_view(row) -> dict:
    return {"id": row["id"], "action": row["action"],
            "actor": row["actor_username"], "target_type": row["target_type"],
            "target_id": row["target_id"], "request_id": row["request_id"],
            "created_at": row["created_at"]}


def upload_view(row) -> dict:
    # stored_path is deliberately NOT projected: it is a server filesystem
    # path, and the original filename is the only part a user needs.
    return {"id": row["id"], "original_filename": row["original_filename"],
            "sha256": row["sha256"], "size_bytes": row["size_bytes"],
            "source_hint": row["source_hint"],
            "uploaded_at": row["uploaded_at"]}


def source_coverage_view(source: str) -> dict:
    """What one telemetry source can and cannot judge, for the coverage page."""
    groups = COV.source_coverage(source)
    return {
        "source": source,
        "groups": groups,
        "judgeable_groups": [g for g, d in groups.items() if d["judgeable"]],
        "blind_groups": [g for g, d in groups.items() if not d["judgeable"]],
        "unavailable_features": K.unavailable_features(source),
        "proxy_features": K.proxy_features(source),
    }


def detection_status_view(engine, repo=None) -> dict:
    """The detection configuration an analyst is entitled to see.

    Includes the gate's refusal reasons verbatim. A product that quietly ran in
    a weaker mode than the operator believed would be the worst kind of silent
    failure, so the reason it is in rule mode is a first-class, visible fact.

    The gate is re-evaluated here AS IF model mode had been requested. The
    engine's own ``gate`` short-circuits to "allowed" when the configured mode
    is already ``rule`` — correct for a run, useless for this page, where the
    question is precisely "why am I not getting ML?" and the answer must be
    available without an operator having to request a mode to find out.
    """
    from src.detection.engine import RULESET_VERSION, ruleset_digest
    from src.detection.model_gate import MODE_MODEL, evaluate_gate
    from src.models.heuristic import RULES

    ml_gate = evaluate_gate(engine.cfg, repo=repo, requested_mode=MODE_MODEL)
    return {
        "mode": engine.mode,
        "detection_version": RULESET_VERSION,
        "ruleset_digest": ruleset_digest(),
        "marker": engine.marker,
        "gate": ml_gate.as_dict(),
        "active_gate": engine.gate.as_dict(),
        "rules": [
            {"feature": f, "group": K.GROUP_OF_FEATURE[f], "op": o,
             "threshold": t, "reason": r,
             "category": C.category_for_feature(f)}
            for f, o, t, r in RULES],
        "severity": {
            "default": engine.policy.default,
            "rules": [{"min_votes": r.min_votes, "min_groups": r.min_groups,
                       "severity": r.severity} for r in engine.policy.rules],
            "combined_floor": engine.policy.combined_floor,
        },
        "confidence_bands": {"medium_at": engine.policy.medium_at,
                             "high_at": engine.policy.high_at},
        "sources": {s: source_coverage_view(s)
                    for s in K.OPERATIONAL_SOURCES},
    }


def summary_view(repo, engine) -> dict:
    """The overview page's numbers."""
    status_counts = repo.alerts.status_counts()
    category_counts = repo.alerts.category_counts()
    return {
        "alerts_total": repo.alerts.count(),
        "alerts_by_status": status_counts,
        "alerts_by_category": category_counts,
        "alerts_active": sum(n for s, n in status_counts.items()
                             if s in L.ACTIVE_STATUSES),
        "devices": repo.devices.count(),
        "jobs": [job_view(j) for j in repo.jobs.recent(limit=5)],
        "mode": engine.mode,
        "detection_version": engine.gate.model_version or "ruleset-1",
        "marker": engine.marker,
    }
