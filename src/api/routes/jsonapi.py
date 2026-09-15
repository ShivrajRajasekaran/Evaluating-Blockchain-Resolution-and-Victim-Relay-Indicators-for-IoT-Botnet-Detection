"""
api/routes/jsonapi.py — the same data as the dashboard, as JSON.

WHY IT MIRRORS THE PAGES RATHER THAN EXTENDING THEM
    Every projection comes from :mod:`api.views`, the same module the templates
    render. The API cannot describe an alert differently from the page, cannot
    expose a field the dashboard hides, and cannot omit the coverage note. If a
    field needs adding, it is added once and both surfaces get it.

AUTHENTICATION IS THE SAME SESSION COOKIE
    There is no second credential type — no API key, no bearer token. A key
    would be a long-lived secret to store, rotate and leak, and nothing here
    needs unattended machine access: the operator's own automation runs
    ``scripts/`` locally against the database, not over HTTP. An API client
    signs in at ``/login`` like a person does.

    Mutating JSON routes still require the CSRF token, supplied in the
    ``X-CSRF-Token`` header, because they are reachable with a session cookie
    and therefore forgeable from another origin without it.
"""
from __future__ import annotations

from starlette.responses import JSONResponse

from src.alerts import lifecycle as L
from src.alerts.builder import AlertError, AlertWriter
from src.auth import rbac
from src.detection import categories as C
from src.schema import columns as K
from src.storage import Repository

from .. import views as V
from ..security import guard


@guard(permission=rbac.VIEW)
async def summary(request):
    with request.app.state.db.connection() as conn:
        payload = V.summary_view(Repository(conn), request.app.state.engine)
    payload["review_banner"] = request.app.state.review_banner
    return JSONResponse(payload)


@guard(permission=rbac.VIEW)
async def alerts_list(request):
    cfg = request.app.state.cfg
    q = request.query_params
    page = V.clamp_page(q.get("page"))
    size = V.clamp_page_size(q.get("page_size"),
                             default=int(cfg.api.page_size),
                             maximum=int(cfg.api.max_page_size))
    filters = {"status": q.get("status") or None,
               "category": q.get("category") or None,
               "q": q.get("q") or None}
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        total = repo.alerts.count(**filters)
        rows = repo.alerts.search(limit=size, offset=(page - 1) * size,
                                  **filters)
        items = [V.alert_view(a) for a in rows]
    payload = V.Page(items=items, total=total, page=page,
                     page_size=size).as_dict()
    payload["review_banner"] = request.app.state.review_banner
    return JSONResponse(payload)


@guard(permission=rbac.VIEW)
async def alert_detail(request):
    alert_id = _int_param(request, "alert_id")
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        alert = repo.alerts.by_id(alert_id)
        if alert is None:
            return JSONResponse({"error": "no such alert"}, status_code=404)
        payload = V.alert_view(alert,
                               evidence=repo.evidence.for_alert(alert_id),
                               feedback=repo.feedback.for_alert(alert_id))
    payload["review_banner"] = request.app.state.review_banner
    return JSONResponse(payload)


@guard(permission=rbac.TRIAGE, csrf=True)
async def alert_status(request):
    alert_id = _int_param(request, "alert_id")
    body = await _json_body(request)
    target = str(body.get("status") or "")
    try:
        with request.app.state.db.transaction() as conn:
            writer = AlertWriter(Repository(conn), cfg=request.app.state.cfg)
            alert = writer.transition(
                alert_id, target, actor=request.state.session,
                comment=body.get("comment"),
                disposition=body.get("disposition"))
    except L.TransitionError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except AlertError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    return JSONResponse(V.alert_view(alert))


@guard(permission=rbac.VIEW)
async def devices_list(request):
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        items = [V.device_view(d) for d in repo.devices.all(limit=500)]
        total = repo.devices.count()
    return JSONResponse({"items": items, "total": total})


@guard(permission=rbac.VIEW)
async def jobs_list(request):
    with request.app.state.db.connection() as conn:
        items = [V.job_view(j)
                 for j in Repository(conn).jobs.recent(limit=100)]
    return JSONResponse({"items": items, "total": len(items)})


@guard(permission=rbac.VIEW)
async def job_detail(request):
    job_id = _int_param(request, "job_id")
    with request.app.state.db.connection() as conn:
        job = Repository(conn).jobs.by_id(job_id)
    if job is None:
        return JSONResponse({"error": "no such job"}, status_code=404)
    return JSONResponse(V.job_view(job))


@guard(permission=rbac.VIEW)
async def detection_versions(request):
    """What is detecting, at what version, and why it is not a model."""
    engine = request.app.state.engine
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        payload = V.detection_status_view(engine, repo=repo)
        payload["registered_models"] = [
            {"id": m.id, "name": m.name, "version": m.version, "kind": m.kind,
             "is_validated": m.is_validated, "registered_at": m.registered_at}
            for m in repo.models.all()]
        payload["validated_ml_models"] = [
            m.version for m in repo.models.validated_ml_models()]
    return JSONResponse(payload)


@guard(permission=rbac.VIEW)
async def coverage_for_source(request):
    source = request.path_params.get("source", "")
    if source not in K.FEATURE_AVAILABILITY:
        return JSONResponse(
            {"error": f"unknown source; expected one of "
                      f"{list(K.OPERATIONAL_SOURCES)}"}, status_code=404)
    return JSONResponse(V.source_coverage_view(source))


@guard(permission=rbac.VIEW)
async def categories_list(request):
    """The verdict vocabulary, so a client need not hardcode it."""
    return JSONResponse({
        "categories": [
            {"name": name, "label": V.CATEGORY_LABELS.get(name, name),
             "raises_alert": C.raises_alert(name)}
            for name in C.CATEGORIES],
        "statuses": list(L.STATUSES),
        "dispositions": list(L.DISPOSITIONS),
        "transitions": {s: list(L.allowed_from(s)) for s in L.STATUSES},
    })


@guard(permission=rbac.VIEW_AUDIT)
async def audit_list(request):
    cfg = request.app.state.cfg
    page = V.clamp_page(request.query_params.get("page"))
    size = V.clamp_page_size(request.query_params.get("page_size"),
                             default=int(cfg.api.page_size),
                             maximum=int(cfg.api.max_page_size))
    with request.app.state.db.connection() as conn:
        repo = Repository(conn)
        total = repo.audit.count()
        items = [V.audit_view(r)
                 for r in repo.audit.recent(limit=size,
                                            offset=(page - 1) * size)]
    return JSONResponse(V.Page(items=items, total=total, page=page,
                               page_size=size).as_dict())


# ---------------------------------------------------------------------------
def _int_param(request, name: str) -> int:
    try:
        return int(request.path_params[name])
    except (KeyError, TypeError, ValueError):
        from starlette.exceptions import HTTPException
        raise HTTPException(status_code=404)


async def _json_body(request) -> dict:
    """The request body as a dict, tolerating a form post from a browser.

    A malformed body is an empty dict rather than a 500: the handler's own
    validation then produces the clear 400 the client can act on.
    """
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            data = await request.json()
        except (ValueError, TypeError):
            return {}
        return data if isinstance(data, dict) else {}
    from ..security import form_data
    form = await form_data(request)
    return {k: v for k, v in form.items()}
