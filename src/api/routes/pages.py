"""
api/routes/pages.py — the server-rendered dashboard.

WHY SERVER-RENDERED FORMS AND NOT A SPA
    The containment rules forbid outbound requests, which rules out a CDN, and
    installing a front-end toolchain was not approved. Plain HTML forms with a
    303-redirect-after-POST need neither: they work with JavaScript disabled,
    they are trivially auditable, and the one small first-party script in
    ``static/app.js`` only adds convenience (filter submission, confirm
    prompts) on top of pages that already work without it.

WHAT EVERY PAGE CARRIES
    The review banner — "Alerts indicate suspicious behavioural patterns and
    require analyst review. They are not confirmation of compromise." — is
    rendered by the base template on every page, so no individual view can omit
    it.

THE ROUTE / PERMISSION MAP
    /                    VIEW          overview and coverage headline
    /alerts              VIEW          filterable, paginated queue
    /alerts/{id}         VIEW          evidence, coverage, history
    /alerts/{id}/status  TRIAGE  CSRF  lifecycle transition
    /alerts/{id}/feedback TRIAGE CSRF  analyst note
    /alerts/{id}/print   VIEW          printable single-alert report
    /upload              UPLOAD  CSRF  authorised capture -> ingest -> detect
    /ingestion           VIEW          job history
    /devices             VIEW          device inventory
    /detection           VIEW_CONFIG   rules, severity table, gate, coverage
    /audit               VIEW_AUDIT    the append-only trail
    /reports             VIEW          export CSV / JSON
"""
from __future__ import annotations

import csv
import io
import json
import logging

from starlette.responses import RedirectResponse, Response

from src.alerts import lifecycle as L
from src.alerts.builder import AlertError, AlertWriter
from src.audit import events as A
from src.auth import rbac
from src.detection import categories as C
from src.schema import columns as K
from src.storage import Repository, utcnow_iso

from .. import views as V
from ..pipeline import run_pipeline
from ..security import form_data, guard
from ..uploads import UploadRejected, store_stream

_log = logging.getLogger("als.api")


def _page(request, template: str, context: dict, status_code: int = 200):
    """Render a template with the context every page needs."""
    session = request.state.session
    base = {
        "session": session,
        "role": session.role if session else None,
        "can": {p: rbac.has_permission(session.role, p) if session else False
                for p in rbac.ALL_PERMISSIONS},
        "banner": request.app.state.review_banner,
        "product_name": request.app.state.product_name,
        "build_token": request.app.state.build_token,
        "marker": request.app.state.engine.marker,
        "active": template.rsplit(".", 1)[0],
    }
    base.update(context)
    return request.app.state.templates.TemplateResponse(
        request, template, base, status_code=status_code)


# ===========================================================================
# overview
# ===========================================================================
@guard(permission=rbac.VIEW)
async def overview(request):
    engine = request.app.state.engine
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        summary = V.summary_view(repo, engine)
        recent = [V.alert_view(a) for a in repo.alerts.search(limit=10)]
    return _page(request, "overview.html", {
        "summary": summary, "recent": recent,
        "coverage": {s: V.source_coverage_view(s)
                     for s in K.OPERATIONAL_SOURCES},
        "severities": V.SEVERITY_ORDER,
    })


# ===========================================================================
# alerts
# ===========================================================================
@guard(permission=rbac.VIEW)
async def alerts_index(request):
    cfg = request.app.state.cfg
    q = request.query_params
    page = V.clamp_page(q.get("page"))
    size = V.clamp_page_size(q.get("page_size"),
                             default=int(cfg.api.page_size),
                             maximum=int(cfg.api.max_page_size))
    filters = {
        "status": q.get("status") or None,
        "category": q.get("category") or None,
        "q": q.get("q") or None,
    }
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        total = repo.alerts.count(**filters)
        rows = repo.alerts.search(limit=size, offset=(page - 1) * size,
                                  **filters)
        items = [V.alert_view(a) for a in rows]
    return _page(request, "alerts.html", {
        "page": V.Page(items=items, total=total, page=page, page_size=size),
        "filters": filters,
        "categories": C.ALERTING_CATEGORIES,
        "statuses": L.STATUSES,
        "labels": V.CATEGORY_LABELS,
    })


@guard(permission=rbac.VIEW)
async def alert_detail(request):
    alert_id = _int_param(request, "alert_id")
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        alert = repo.alerts.by_id(alert_id)
        if alert is None:
            return _not_found(request)
        view = V.alert_view(alert, evidence=repo.evidence.for_alert(alert_id),
                            feedback=repo.feedback.for_alert(alert_id))
        window = (conn.execute(
            "SELECT * FROM observation_windows WHERE id = ?",
            (alert.observation_window_id,)).fetchone()
            if alert.observation_window_id else None)
        features = _window_features(conn, alert.observation_window_id)
    return _page(request, "alert_detail.html", {
        "alert": view, "window": window, "features": features,
        "dispositions": L.DISPOSITIONS,
        "feature_groups": K.FEATURE_GROUPS,
    })


@guard(permission=rbac.VIEW)
async def alert_print(request):
    alert_id = _int_param(request, "alert_id")
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        alert = repo.alerts.by_id(alert_id)
        if alert is None:
            return _not_found(request)
        view = V.alert_view(alert, evidence=repo.evidence.for_alert(alert_id),
                            feedback=repo.feedback.for_alert(alert_id))
    return _page(request, "alert_print.html", {
        "alert": view,
        "provenance_note": _operational_note(),
        "generated_at": utcnow_iso(),
    })


@guard(permission=rbac.TRIAGE, csrf=True)
async def alert_status(request):
    alert_id = _int_param(request, "alert_id")
    form = await form_data(request)
    target = str(form.get("status") or "")
    disposition = str(form.get("disposition") or "") or None
    comment = str(form.get("comment") or "") or None
    try:
        with request.app.state.db.transaction() as conn:
            writer = AlertWriter(Repository(conn), cfg=request.app.state.cfg)
            writer.transition(alert_id, target, actor=request.state.session,
                              comment=comment, disposition=disposition)
    except (L.TransitionError, AlertError) as exc:
        return _redirect_with(request, f"/alerts/{alert_id}", error=str(exc))
    return RedirectResponse(f"/alerts/{alert_id}?updated=1", status_code=303)


@guard(permission=rbac.TRIAGE, csrf=True)
async def alert_feedback(request):
    alert_id = _int_param(request, "alert_id")
    form = await form_data(request)
    comment = str(form.get("comment") or "").strip()
    disposition = str(form.get("disposition") or "") or None
    if not comment:
        return _redirect_with(request, f"/alerts/{alert_id}",
                              error="A note cannot be empty.")
    try:
        with request.app.state.db.transaction() as conn:
            writer = AlertWriter(Repository(conn), cfg=request.app.state.cfg)
            writer.add_feedback(alert_id, comment=comment,
                                actor=request.state.session,
                                disposition=disposition)
    except (L.TransitionError, AlertError) as exc:
        return _redirect_with(request, f"/alerts/{alert_id}", error=str(exc))
    return RedirectResponse(f"/alerts/{alert_id}?updated=1", status_code=303)


# ===========================================================================
# upload + ingestion
# ===========================================================================
@guard(permission=rbac.UPLOAD)
async def upload_page(request):
    return _page(request, "upload.html", {
        "sources": K.OPERATIONAL_SOURCES,
        "allowed": list(request.app.state.cfg.api.allowed_extensions),
        "max_bytes": int(request.app.state.cfg.api.max_upload_bytes),
        "input_dir": str(request.app.state.cfg.product.input_dir),
        "coverage": {s: V.source_coverage_view(s)
                     for s in K.OPERATIONAL_SOURCES},
        "error": request.query_params.get("error"),
        "outcome": None,
    })


@guard(permission=rbac.UPLOAD, csrf=True)
async def upload_submit(request):
    cfg = request.app.state.cfg
    form = await form_data(request)
    upload = form.get("file")
    source = str(form.get("source") or K.SOURCE_OP_ZEEK)
    scenario_id = str(form.get("scenario_id") or "").strip() or None

    if source not in K.OPERATIONAL_SOURCES:
        raise UploadRejected(
            f"unknown telemetry source; choose one of "
            f"{', '.join(K.OPERATIONAL_SOURCES)}")
    if upload is None or not hasattr(upload, "file"):
        raise UploadRejected("no file was attached to the form")

    try:
        stored = store_stream(
            upload.file, original_name=getattr(upload, "filename", ""),
            jobs_dir=request.app.state.jobs_dir,
            max_bytes=int(cfg.api.max_upload_bytes),
            allowed_extensions=cfg.api.allowed_extensions)
    finally:
        # Starlette spools the body to a temp file. Close it on every path,
        # including a rejected upload, so a refused file does not leave a
        # handle open for the life of the process.
        await _close_upload(upload)

    session = request.state.session
    now = utcnow_iso()
    with request.app.state.db.transaction() as conn:
        repo = Repository(conn)
        audit = A.AuditLog(repo)
        file_id = repo.files.create(
            original_filename=stored.original_name,
            stored_path=str(stored.path), sha256=stored.sha256,
            size_bytes=stored.size_bytes, content_type=None,
            source_hint=source, uploaded_by=session.user_id, uploaded_at=now)
        audit.record(A.FILE_UPLOAD, actor=session, target_type="uploaded_file",
                     target_id=file_id, request_id=request.state.request_id,
                     created_at=now,
                     detail={"filename": stored.original_name,
                             "sha256": stored.sha256,
                             "size_bytes": stored.size_bytes,
                             "source": source})
        outcome = run_pipeline(
            stored.path, source=source, repo=repo, scenario_id=scenario_id,
            source_file=stored.original_name, uploaded_file_id=file_id,
            cfg=cfg, actor=session, audit=audit)

    return _page(request, "upload.html", {
        "sources": K.OPERATIONAL_SOURCES,
        "allowed": list(cfg.api.allowed_extensions),
        "max_bytes": int(cfg.api.max_upload_bytes),
        "input_dir": str(cfg.product.input_dir),
        "coverage": {s: V.source_coverage_view(s)
                     for s in K.OPERATIONAL_SOURCES},
        "error": None,
        "outcome": outcome.as_dict(),
        "labels": V.CATEGORY_LABELS,
    })


@guard(permission=rbac.VIEW)
async def ingestion_index(request):
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        jobs = [V.job_view(j) for j in repo.jobs.recent(limit=100)]
        uploads = [V.upload_view(r) for r in repo.files.recent(limit=100)]
    return _page(request, "ingestion.html",
                 {"jobs": jobs, "uploads": uploads})


@guard(permission=rbac.VIEW)
async def devices_index(request):
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        devices = [V.device_view(d) for d in repo.devices.all(limit=500)]
        counts = {}
        for row in conn.execute(
                "SELECT device_id, COUNT(*) AS n FROM alerts "
                "GROUP BY device_id").fetchall():
            counts[row["device_id"]] = row["n"]
    for d in devices:
        d["alert_count"] = counts.get(d["id"], 0)
    return _page(request, "devices.html", {
        "devices": devices,
        "pseudonymised": bool(
            request.app.state.cfg.storage.pseudonymise_devices),
    })


# ===========================================================================
# detection config, audit, reports
# ===========================================================================
@guard(permission=rbac.VIEW_CONFIG)
async def detection_page(request):
    engine = request.app.state.engine
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        models = repo.models.all()
        detection = V.detection_status_view(engine, repo=repo)
    return _page(request, "detection.html", {
        "detection": detection,
        "models": models,
        "labels": V.CATEGORY_LABELS,
    })


@guard(permission=rbac.VIEW_AUDIT)
async def audit_page(request):
    cfg = request.app.state.cfg
    page = V.clamp_page(request.query_params.get("page"))
    size = V.clamp_page_size(request.query_params.get("page_size"),
                             default=int(cfg.api.page_size),
                             maximum=int(cfg.api.max_page_size))
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        total = repo.audit.count()
        rows = [V.audit_view(r)
                for r in repo.audit.recent(limit=size,
                                           offset=(page - 1) * size)]
    return _page(request, "audit.html", {
        "page": V.Page(items=rows, total=total, page=page, page_size=size),
    })


@guard(permission=rbac.VIEW)
async def reports_page(request):
    engine = request.app.state.engine
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        summary = V.summary_view(repo, engine)
    return _page(request, "reports.html", {
        "summary": summary,
        "provenance_note": _operational_note(),
        "labels": V.CATEGORY_LABELS,
    })


@guard(permission=rbac.VIEW)
async def reports_export(request):
    """Export the current alert selection as CSV or JSON.

    The export carries the same coverage note and honesty marker the dashboard
    shows. A spreadsheet that dropped them would be the one artefact of this
    product that could be mistaken for a list of confirmed incidents.
    """
    fmt = (request.query_params.get("fmt") or "csv").lower()
    if fmt not in ("csv", "json"):
        return _redirect_with(request, "/reports",
                              error="Export format must be csv or json.")
    filters = {
        "status": request.query_params.get("status") or None,
        "category": request.query_params.get("category") or None,
        "q": request.query_params.get("q") or None,
    }
    cap = int(request.app.state.cfg.api.max_page_size) * 20
    with request.app.state.db.connection() as conn:
        rows = [V.alert_view(a) for a in
                Repository(conn).alerts.search(limit=cap, **filters)]

    note = _operational_note()
    if fmt == "json":
        body = json.dumps(
            {"generated_at": utcnow_iso(), "provenance_note": note,
             "review_banner": request.app.state.review_banner,
             "marker": request.app.state.engine.marker,
             "count": len(rows), "alerts": rows},
            indent=2, sort_keys=True)
        return Response(body, media_type="application/json", headers={
            "Content-Disposition": 'attachment; filename="alerts.json"'})

    fields = ["alert_uid", "device_key", "category", "severity", "confidence",
              "status", "occurrence_count", "first_seen", "last_seen",
              "source_file", "detection_version", "provenance", "explanation",
              "coverage_note"]
    buf = io.StringIO()
    # A leading comment row, so the file cannot be separated from what it means.
    buf.write(f"# {request.app.state.review_banner}\n")
    buf.write(f"# {note}\n")
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return Response(buf.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": 'attachment; filename="alerts.csv"'})


# ===========================================================================
# helpers
# ===========================================================================
def _int_param(request, name: str) -> int:
    try:
        return int(request.path_params[name])
    except (KeyError, TypeError, ValueError):
        from starlette.exceptions import HTTPException
        raise HTTPException(status_code=404)


def _not_found(request):
    from ..errors import error_response
    return error_response(request, 404, "That alert does not exist.")


def _redirect_with(request, path: str, *, error: str):
    from urllib.parse import quote
    return RedirectResponse(f"{path}?error={quote(error)}", status_code=303)


def _window_features(conn, window_id):
    """The stored feature snapshot for a window, as name -> value or None.

    ``None`` means the feature could not be measured. It is rendered as "not
    measurable", never as 0.
    """
    if not window_id:
        return None
    row = conn.execute(
        "SELECT features_json FROM feature_snapshots "
        "WHERE observation_window_id = ?", (window_id,)).fetchone()
    if row is None:
        return None
    try:
        return json.loads(row["features_json"])
    except (TypeError, ValueError):
        return None


def _operational_note() -> str:
    from src.config import operational_data_note
    return operational_data_note()


async def _close_upload(upload) -> None:
    """Release Starlette's spooled temp file, whatever shape it arrived in."""
    closer = getattr(upload, "close", None)
    if closer is None:
        return
    try:
        result = closer()
        if hasattr(result, "__await__"):
            await result
    except Exception:          # pragma: no cover - closing must never mask
        _log.debug("could not close upload handle", exc_info=True)
