"""
api/errors.py — one place where things go wrong, and nothing leaks.

THE RULE
    A client is told what it needs to fix its own request and nothing about the
    server. No stack traces, no file paths, no SQL, no exception class names, no
    configuration values. The full detail goes to the application log, keyed by
    a request id that IS shown to the client, so an operator can find the exact
    failure from a screenshot without the page having exposed anything.

WHAT IS AND IS NOT AN EXPECTED FAILURE
    Missing session, wrong role, bad CSRF token, unreadable upload and unknown
    alert id are all expected — the user did something the product refuses, and
    they get a clear sentence about it. Anything else is a bug: it becomes a
    generic 500 with a request id, and the traceback is logged at exception
    level.
"""
from __future__ import annotations

import logging

from starlette.exceptions import HTTPException
from starlette.responses import HTMLResponse, JSONResponse

from src.auth.rbac import PermissionDenied

from .security import (AuthRequired, forbidden_response, unauthenticated_response,
                       wants_json)
from .uploads import UploadRejected

_log = logging.getLogger("als.api")

_TITLES = {
    400: "Bad request",
    401: "Sign in required",
    403: "Not permitted",
    404: "Not found",
    405: "Method not allowed",
    413: "File too large",
    429: "Too many requests",
    500: "Something went wrong",
}

# What a client may be told for each status. Deliberately generic for 500.
_MESSAGES = {
    400: "The request could not be understood.",
    404: "That page or record does not exist.",
    405: "That action is not available on this address.",
    413: "The uploaded file is larger than this deployment accepts.",
    429: "Too many requests. Wait a moment and try again.",
    500: ("The request could not be completed. The error has been logged; "
          "quote the request id below if you report it."),
}


def error_response(request, status: int, message: str | None = None,
                   *, title: str | None = None):
    """Render an error as JSON or a page, according to what the client wants."""
    title = title or _TITLES.get(status, "Error")
    message = message or _MESSAGES.get(status, "The request failed.")
    request_id = getattr(request.state, "request_id", "") or ""
    if wants_json(request):
        payload = {"error": message, "status": status}
        if request_id:
            payload["request_id"] = request_id
        return JSONResponse(payload, status_code=status)
    templates = request.app.state.templates
    html = templates.get_template("error.html").render(
        request=request, status=status, title=title, message=message,
        request_id=request_id, banner=request.app.state.review_banner)
    return HTMLResponse(html, status_code=status)


async def auth_required_handler(request, exc: AuthRequired):
    return unauthenticated_response(request)


async def permission_denied_handler(request, exc: PermissionDenied):
    # The role and the permission name are logged, never returned: telling a
    # Viewer exactly which permission they lack maps the product's privilege
    # model for anyone who gets hold of a low-privileged account.
    _log.info("permission denied path=%s detail=%s", request.url.path, exc)
    return forbidden_response(request)


async def upload_rejected_handler(request, exc: UploadRejected):
    # UploadRejected messages are written to be shown: they describe the file
    # the user sent, never the server that refused it.
    return error_response(request, 400, str(exc), title="Upload rejected")


async def http_exception_handler(request, exc: HTTPException):
    if exc.status_code == 401:
        return unauthenticated_response(request)
    if exc.status_code == 403:
        return forbidden_response(request)
    detail = exc.detail if isinstance(exc.detail, str) else None
    # Starlette puts the reason phrase in `detail` by default; that is safe.
    return error_response(request, exc.status_code, detail)


async def unhandled_handler(request, exc: Exception):
    _log.exception("unhandled error path=%s request_id=%s", request.url.path,
                   getattr(request.state, "request_id", "-"))
    return error_response(request, 500)


def exception_handlers() -> dict:
    """The mapping handed to Starlette. Order is by specificity, not listing."""
    return {
        AuthRequired: auth_required_handler,
        PermissionDenied: permission_denied_handler,
        UploadRejected: upload_rejected_handler,
        HTTPException: http_exception_handler,
        Exception: unhandled_handler,
    }
