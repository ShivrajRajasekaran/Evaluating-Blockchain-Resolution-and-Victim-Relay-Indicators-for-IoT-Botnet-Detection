"""
api/pipeline.py — one authorised file, end to end.

    stored file
      -> ingest adapter        (Zeek conn.log / flow CSV / NetFlow / firewall)
      -> observation windows   (schema-valid, research_class=unmapped)
      -> detection engine      (transparent rules + coverage gate)
      -> alerts                (deduplicated, evidence-backed, review-only)
      -> audit                 (every step recorded)

WHY THIS IS ITS OWN MODULE AND NOT A ROUTE HANDLER
    The same sequence runs from three places: an authenticated upload, an
    operator's ``scripts/ingest_file.py`` run over the authorised input
    directory, and the end-to-end test. One implementation means the CLI and
    the web app cannot drift into doing subtly different things to the same
    capture — and it means the whole pipeline is testable without an HTTP
    request.

WHAT IS PERSISTED, AND IN WHAT ORDER
    Windows and their feature snapshots are written BEFORE alerts, so an alert
    can link to the exact window that produced it and an analyst can open the
    evidence. Feature values are stored as JSON with NaN written as ``null`` —
    never 0 — because "not measurable" and "measured as zero" are different
    facts and several of these features are at their most suspicious at zero.

    The whole run is one transaction. A capture that fails halfway leaves the
    database as it was, and the job row records the failure.

CONTAINMENT
    Reads one local file that was either uploaded by an authenticated user or
    placed in the authorised input directory. Writes one local database. It
    opens no socket, contacts no device, and resolves no name.
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path

from src.audit import events as A
from src.alerts.builder import AlertWriter
from src.config import load_config, operational_data_note
from src.detection import DetectionEngine
from src.ingest import operational_csv, operational_zeek
from src.schema import columns as K
from src.storage import utcnow_iso

_log = logging.getLogger("als.pipeline")

JOB_PENDING = "pending"
JOB_RUNNING = "running"
JOB_SUCCEEDED = "succeeded"
JOB_FAILED = "failed"

# source -> the adapter that reads it. SOURCE_OP_ZEEK has its own module; the
# three CSV shapes share one adapter that differs only by column profile.
SOURCES: tuple[str, ...] = K.OPERATIONAL_SOURCES


class PipelineError(RuntimeError):
    """The capture could not be turned into observations or alerts.

    The message is safe to show the uploader: it describes the file, never the
    server.
    """


@dataclass
class IngestOutcome:
    """Everything one run did, for the job page, the API and the audit row."""

    job_id: int | None = None
    run_id: int | None = None
    source: str = ""
    scenario_id: str = ""
    source_file: str = ""
    status: str = JOB_PENDING
    windows: int = 0
    devices: int = 0
    alerts_created: int = 0
    alerts_coalesced: int = 0
    truncated: bool = False
    error: str = ""
    summary: dict = field(default_factory=dict)
    ingest_report: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == JOB_SUCCEEDED

    def as_dict(self) -> dict:
        return {
            "job_id": self.job_id, "detection_run_id": self.run_id,
            "source": self.source, "scenario_id": self.scenario_id,
            "source_file": self.source_file, "status": self.status,
            "windows": self.windows, "devices": self.devices,
            "alerts_created": self.alerts_created,
            "alerts_coalesced": self.alerts_coalesced,
            "truncated": self.truncated, "error": self.error,
            "detection_summary": self.summary,
            "provenance_note": operational_data_note(),
        }


def ingest_observations(path: Path, *, source: str, scenario_id: str,
                        cfg=None, device_ips=None, max_flows: int | None = None):
    """Run the right adapter for ``source`` and return ``(obs, report)``.

    The only place the source-to-adapter mapping lives. An unknown source is an
    error rather than a default, so a typo cannot silently route a firewall
    export through the Zeek parser.
    """
    if source == K.SOURCE_OP_ZEEK:
        adapter = operational_zeek.ingest
        kwargs = {}
    elif source in (K.SOURCE_OP_FLOW_CSV, K.SOURCE_OP_NETFLOW,
                    K.SOURCE_OP_FIREWALL):
        adapter = operational_csv.ingest
        kwargs = {"source": source}
    else:
        raise PipelineError(
            f"unknown telemetry source {source!r}; expected one of "
            f"{list(SOURCES)}")
    try:
        return adapter(path, scenario_id=scenario_id, device_ips=device_ips,
                       max_flows=max_flows, **kwargs)
    except (operational_zeek.OperationalIngestError, ValueError) as exc:
        raise PipelineError(str(exc)) from exc


def run_pipeline(path, *, source: str, repo, scenario_id: str | None = None,
                 source_file: str | None = None, uploaded_file_id: int | None = None,
                 cfg=None, actor=None, device_ips=None,
                 max_flows: int | None = None,
                 audit=None) -> IngestOutcome:
    """Ingest, detect and persist one authorised capture.

    ``repo`` must be bound to a connection inside a transaction: everything
    below commits together, so a partially-read capture cannot leave orphaned
    windows or alerts behind.
    """
    cfg = cfg or load_config()
    path = Path(path)
    audit = audit if audit is not None else A.AuditLog(repo)
    now = utcnow_iso()
    display = source_file or path.name
    scenario_id = scenario_id or _default_scenario(display)

    outcome = IngestOutcome(source=source, scenario_id=scenario_id,
                            source_file=display, status=JOB_RUNNING)
    # The scenario id is not a column on ingestion_jobs; it rides in `note`,
    # which is what that column is for, and stays on every observation row.
    job_id = repo.jobs.create(
        uploaded_file_id=uploaded_file_id, source_dataset=source,
        status=JOB_PENDING, created_by=_actor_id(actor), created_at=now,
        note=f"scenario={scenario_id}; file={display}")
    repo.jobs.mark_running(job_id, now)
    outcome.job_id = job_id
    audit.record(A.INGEST_START, actor=actor, target_type="ingestion_job",
                 target_id=job_id, created_at=now,
                 detail={"source": source, "source_file": display,
                         "scenario_id": scenario_id})

    try:
        obs, report = ingest_observations(
            path, source=source, scenario_id=scenario_id, cfg=cfg,
            device_ips=device_ips, max_flows=max_flows)
    except PipelineError as exc:
        repo.jobs.mark_failed(job_id, utcnow_iso(), str(exc))
        audit.record(A.INGEST_FAIL, actor=actor, target_type="ingestion_job",
                     target_id=job_id, created_at=utcnow_iso(),
                     detail={"error": str(exc)})
        outcome.status = JOB_FAILED
        outcome.error = str(exc)
        return outcome

    outcome.ingest_report = _summarise_report(report)
    writer = AlertWriter(repo, cfg=cfg, audit=audit)
    window_ids = _persist_windows(obs, repo=repo, writer=writer, job_id=job_id,
                                  now=now)
    outcome.windows = len(obs)
    outcome.devices = int(obs[K.DEVICE_ID].nunique()) if len(obs) else 0

    engine = DetectionEngine(cfg=cfg, repo=repo)
    result = engine.detect_frame(obs)
    persisted = writer.persist(
        result, ingestion_job_id=job_id, source_file=display,
        window_ids=window_ids, actor=actor, now=now)

    outcome.run_id = persisted.run_id
    outcome.alerts_created = persisted.created
    outcome.alerts_coalesced = persisted.coalesced
    outcome.truncated = persisted.truncated
    outcome.summary = result.summary()
    outcome.status = JOB_SUCCEEDED

    repo.jobs.mark_succeeded(
        job_id, utcnow_iso(), flows_read=_flows_read(outcome.ingest_report),
        windows_emitted=outcome.windows)
    audit.record(A.INGEST_SUCCEED, actor=actor, target_type="ingestion_job",
                 target_id=job_id, created_at=utcnow_iso(),
                 detail={"windows": outcome.windows,
                         "devices": outcome.devices,
                         "alerts_created": persisted.created,
                         "alerts_coalesced": persisted.coalesced})
    return outcome


def _persist_windows(obs, *, repo, writer: AlertWriter, job_id: int | None,
                     now: str) -> dict[str, int]:
    """Write one observation_windows row and feature snapshot per window.

    Returns observation_id -> row id so alerts can link to their window. Device
    keys go through the AlertWriter's resolver, so a pseudonymised deployment
    stores pseudonyms here too rather than only on the alerts.
    """
    ids: dict[str, int] = {}
    for row in obs.to_dict("records"):
        raw_device = str(row[K.DEVICE_ID])
        device_key, is_pseudonymised = writer.device_key_for(raw_device)
        window_start = str(row[K.WINDOW_START])
        device_id = repo.devices.get_or_create(
            device_key, is_pseudonymised=is_pseudonymised,
            seen_at=window_start)
        observation_id = str(row[K.OBSERVATION_ID])
        window_id = repo.windows.upsert(
            observation_id=observation_id, ingestion_job_id=job_id,
            device_id=device_id, window_start=window_start,
            window_seconds=int(row[K.WINDOW_SECONDS]),
            source_dataset=str(row[K.SOURCE_DATASET]),
            research_class=str(row[K.RESEARCH_CLASS]),
            quality_flags=_or_none(row.get(K.QUALITY_FLAGS)),
            n_features_missing=int(row[K.N_FEATURES_MISSING]),
            created_at=now)
        repo.features.upsert(
            observation_window_id=window_id,
            features_json=_features_json(row), created_at=now)
        ids[observation_id] = window_id
    return ids


def _features_json(row: dict) -> str:
    """The 16 features as JSON, with NaN as ``null`` and never as 0.

    This is the honesty rule at the storage layer. Imputing zero here would
    make a feature that could not be measured indistinguishable from one
    measured at its most suspicious value, and every downstream reader — the
    evidence panel, an export, a future model — would inherit the lie.
    """
    out: dict[str, float | None] = {}
    for col in K.FEATURE_COLS:
        value = row.get(col)
        try:
            f = float(value)
        except (TypeError, ValueError):
            out[col] = None
            continue
        out[col] = None if math.isnan(f) or math.isinf(f) else f
    return json.dumps(out, sort_keys=True)


def _summarise_report(report: dict) -> dict:
    """The ingest report, trimmed to what a job page should show.

    Whole-report JSON can carry file paths; this keeps the counts and the notes
    an analyst needs and drops the rest.
    """
    keep = ("adapter", "source_dataset", "scenario_id",
            "label_columns_present_but_ignored", "truncated_by_max_flows",
            "features_unavailable_for_this_source", "features_that_are_proxies",
            "detection_note", "provenance_note")
    out = {k: report[k] for k in keep if k in report}
    for section in ("read", "observations", "devices", "orientation",
                    "windowing"):
        if isinstance(report.get(section), dict):
            out[section] = report[section]
    return out


def _flows_read(report: dict) -> int:
    """Data rows the adapter actually consumed, for the job row."""
    read = report.get("read")
    if isinstance(read, dict):
        try:
            return int(read.get("rows_read") or 0)
        except (TypeError, ValueError):
            return 0
    return 0


def _default_scenario(display_name: str) -> str:
    """A scenario id derived from the filename when the operator gave none."""
    stem = Path(display_name).stem or "capture"
    return f"upload-{stem}"[:120]


def _or_none(value):
    if value is None:
        return None
    text = str(value)
    return text if text.strip() else None


def _actor_id(actor) -> int | None:
    if actor is None:
        return None
    uid = getattr(actor, "user_id", None)
    return uid if uid is not None else getattr(actor, "id", None)
