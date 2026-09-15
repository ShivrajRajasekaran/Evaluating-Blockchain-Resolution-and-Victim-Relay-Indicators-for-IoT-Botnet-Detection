"""
api/openapi.py — the API description, built from the route table it describes.

WHY GENERATED FROM THE ROUTES AND NOT WRITTEN BY HAND
    A hand-maintained spec is a second source of truth that drifts the first
    time someone adds a route in a hurry. This walks ``app.routes``, reads the
    :class:`~src.api.security.RouteGuard` each handler declares, and emits the
    path, the methods, and the permission required. A route that exists is
    documented; a documented route exists. ``tests/test_api.py`` asserts it.

    Descriptions come from each handler's docstring, so the thing a developer
    reads in the source and the thing a client reads in ``/docs`` are the same
    sentence.

WHAT IS DELIBERATELY NOT IN THE SPEC
    Response schemas beyond a short shape note. Without pydantic there is no
    generator, and a hand-written schema for sixteen endpoints would be exactly
    the drifting second source of truth this avoids. The projections live in
    one module (:mod:`api.views`) and the docs page links a reader to the
    fields that matter instead of restating them.
"""
from __future__ import annotations

from src.auth import rbac

OPENAPI_VERSION = "3.0.3"


def _summary_from(handler) -> str:
    """The first line of the handler's docstring, or a generated fallback."""
    doc = (getattr(handler, "__doc__", "") or "").strip()
    if doc:
        return doc.split("\n", 1)[0].strip()
    return getattr(handler, "__name__", "endpoint").replace("_", " ")


def _description_from(handler) -> str:
    doc = (getattr(handler, "__doc__", "") or "").strip()
    if "\n" not in doc:
        return ""
    body = doc.split("\n", 1)[1]
    return " ".join(body.split())


def route_security(route) -> dict:
    """The declared guard for a route, as plain data."""
    guard = getattr(route.endpoint, "route_guard", None)
    if guard is None:
        return {"anonymous": False, "permission": None, "csrf": False,
                "declared": False}
    return {"anonymous": guard.anonymous, "permission": guard.permission,
            "csrf": guard.require_csrf, "declared": True}


def _openapi_path(path: str) -> str:
    """Starlette's ``{alert_id}`` is already OpenAPI's syntax."""
    return path


def _parameters(path: str) -> list[dict]:
    params = []
    for part in path.split("/"):
        if part.startswith("{") and part.endswith("}"):
            name = part[1:-1]
            params.append({
                "name": name, "in": "path", "required": True,
                "schema": {"type": "integer" if name.endswith("_id")
                           else "string"},
            })
    return params


def build_spec(app) -> dict:
    """The OpenAPI document for this application."""
    cfg = app.state.cfg
    paths: dict[str, dict] = {}

    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        endpoint = getattr(route, "endpoint", None)
        if not path or not methods or endpoint is None:
            continue                      # the static mount has no methods
        security = route_security(route)
        entry = paths.setdefault(_openapi_path(path), {})
        params = _parameters(path)
        for method in sorted(m for m in methods if m not in ("HEAD", "OPTIONS")):
            responses = {
                "200": {"description": "Success"},
                "429": {"description": "Rate limit exceeded"},
            }
            if not security["anonymous"]:
                responses["401"] = {
                    "description": "No valid session (JSON) or redirect to "
                                   "/login (dashboard)"}
                responses["403"] = {"description": "Role lacks the permission"}
            if params:
                responses["404"] = {"description": "No such record"}
            if method == "POST":
                responses["303"] = {"description": "Redirect after POST"}
            operation = {
                "operationId": getattr(route, "name", None) or endpoint.__name__,
                "summary": _summary_from(endpoint),
                "responses": responses,
                "x-permission": security["permission"],
                "x-requires-session": not security["anonymous"],
                "x-requires-csrf": security["csrf"],
            }
            description = _description_from(endpoint)
            if description:
                operation["description"] = description
            if params:
                operation["parameters"] = params
            entry[method.lower()] = operation

    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": str(cfg.product.name),
            "version": "1.0.0",
            "description": (
                f"{' '.join(str(cfg.product.review_banner).split())} "
                "This API reads authorised local telemetry and reports "
                "transparent, rule-based indicator patterns for analyst "
                "review. It never confirms compromise, and it never trains a "
                "model on the data it ingests."),
        },
        "servers": [{
            "url": f"http://{cfg.api.host}:{cfg.api.port}",
            "description": "Local-only bind. Do not expose without approval.",
        }],
        "components": {
            "securitySchemes": {
                "sessionCookie": {
                    "type": "apiKey", "in": "cookie",
                    "name": str(cfg.auth.session_cookie_name),
                    "description": (
                        "Signed session cookie issued by POST /login. There is "
                        "no API key: mutating routes additionally require the "
                        "X-CSRF-Token header."),
                },
            },
        },
        "security": [{"sessionCookie": []}],
        "x-roles": {role: sorted(perms)
                    for role, perms in rbac.ROLE_PERMISSIONS.items()},
        "paths": paths,
    }
