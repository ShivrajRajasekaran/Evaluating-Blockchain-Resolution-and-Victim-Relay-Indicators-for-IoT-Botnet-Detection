"""
api/security.py — who is asking, what they may do, and what every response says.

FOUR CONTROLS, ALL APPLIED BEFORE A HANDLER RUNS
    IDENTITY     the signed session cookie is read (never trusted beyond its
                 signature) into a :class:`~src.auth.sessions.Session`, or the
                 request is anonymous. A forged or expired cookie is not an
                 error — it is simply an anonymous request, so probing for a
                 valid token reveals nothing.

    AUTHORISATION the route declares a permission and
                 :func:`require_permission` checks the session's role against
                 the fixed matrix in :mod:`src.auth.rbac`. Viewer is read-only,
                 Analyst may triage and upload, Admin may manage users and read
                 the audit log. Declaring the requirement on the route means a
                 handler cannot forget to check.

    RATE         a token bucket per (actor, route). Anonymous requests key on
                 client host, which is what protects the login form.

    HEADERS      every response carries a conservative security header set. The
                 Content-Security-Policy is strict because it can be: the
                 dashboard loads no CDN, no external font and no third-party
                 script, so 'self' is not a compromise, it is the actual
                 dependency graph.

CSRF
    The dashboard mutates state through HTML forms, so it needs CSRF protection
    that does not depend on a framework. Each session gets a token derived from
    the session cookie with an HMAC; forms embed it and POST handlers compare it
    with :func:`hmac.compare_digest`. Deriving rather than storing means no
    server-side token table, and rotating the signing secret invalidates every
    outstanding form along with every session.
"""
from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from hashlib import sha256

from starlette.responses import JSONResponse, RedirectResponse

from src.auth import rbac
from src.auth.sessions import Session

_log = logging.getLogger("als.api")

# Conservative and, crucially, accurate: this app really does load everything
# from itself. 'unsafe-inline' is absent for scripts; the one script file is
# served from static/.
SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "object-src 'none'"),
    # The product binds to localhost over http in the default deployment, so
    # HSTS is set only when the operator has configured secure cookies (i.e.
    # they are terminating TLS). Sending it over http is meaningless.
}

CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
_CSRF_SALT = b"als.csrf.v1"


class AuthRequired(Exception):
    """No valid session. HTML routes redirect to login; JSON routes get 401."""


@dataclass(frozen=True)
class RouteGuard:
    """The security declaration attached to one route.

    Kept as data rather than a decorator so the whole policy can be listed —
    :func:`route_permissions` renders it for the docs page and a test asserts
    that every mutating route declares something.
    """

    permission: str | None = None
    require_csrf: bool = False
    anonymous: bool = False


def guard(*, permission: str | None = None, csrf: bool = False,
          anonymous: bool = False):
    """Declare a route's security requirements, and enforce them.

    Applied as a decorator so the requirement sits on the handler it protects
    and cannot be forgotten at wiring time. The :class:`RouteGuard` is also
    attached to the function, so the whole policy is introspectable —
    ``tests/test_api.py`` walks the route table and asserts that every mutating
    route declares a permission and CSRF protection.

        @guard(permission=rbac.TRIAGE, csrf=True)
        async def set_status(request): ...
    """
    declaration = RouteGuard(permission=permission, require_csrf=csrf,
                             anonymous=anonymous)

    def decorate(handler):
        async def wrapped(request):
            if not anonymous:
                session = require_session(request)
                require_permission(session, permission)
                request.state.session = session
            if declaration.require_csrf:
                submitted = await _submitted_csrf(request)
                if not check_csrf(request, submitted):
                    _log.warning("csrf rejected path=%s", request.url.path)
                    return _csrf_failure(request)
            return await handler(request)

        wrapped.__name__ = getattr(handler, "__name__", "endpoint")
        wrapped.__doc__ = handler.__doc__
        wrapped.route_guard = declaration
        return wrapped

    return decorate


async def _submitted_csrf(request) -> str | None:
    """The CSRF token from the form body or the header.

    The parsed form is cached on the request so the handler can read it again
    without consuming the body a second time.
    """
    header = request.headers.get(CSRF_HEADER)
    if header:
        return header
    form = await request.form()
    request.state.form = form
    value = form.get(CSRF_FIELD)
    return str(value) if value is not None else None


def _csrf_failure(request):
    if wants_json(request):
        return JSONResponse({"error": "invalid or missing CSRF token"},
                            status_code=403)
    return forbidden_response(request, message="invalid or missing CSRF token")


async def form_data(request):
    """The submitted form, reusing whatever the CSRF check already parsed."""
    cached = getattr(request.state, "form", None)
    if cached is not None:
        return cached
    form = await request.form()
    request.state.form = form
    return form


def session_from_request(request) -> Session | None:
    """The authenticated session, or ``None``. Never raises on a bad cookie."""
    manager = request.app.state.sessions
    token = request.cookies.get(manager.cookie_name)
    return manager.read(token)


def require_session(request) -> Session:
    session = session_from_request(request)
    if session is None:
        raise AuthRequired("no valid session")
    return session


def require_permission(session: Session, permission: str | None) -> None:
    """Raise :class:`~src.auth.rbac.PermissionDenied` unless the role allows it."""
    if permission is None:
        return
    rbac.require(session.role, permission)


def csrf_token(request) -> str:
    """A CSRF token bound to this session's cookie and the signing secret.

    Derived, not stored: the value is an HMAC over the session cookie, so it is
    stable for the life of the session, unforgeable without the secret, and
    invalidated automatically when the session ends or the secret rotates.
    """
    manager = request.app.state.sessions
    cookie = request.cookies.get(manager.cookie_name, "")
    secret = request.app.state.csrf_secret
    return hmac.new(secret, _CSRF_SALT + cookie.encode("utf-8"),
                    sha256).hexdigest()


def check_csrf(request, submitted: str | None) -> bool:
    """Constant-time comparison against the expected token."""
    if not submitted:
        return False
    return hmac.compare_digest(csrf_token(request), submitted)


def apply_security_headers(response, *, secure: bool = False):
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    if secure:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def wants_json(request) -> bool:
    """Whether this request should get JSON rather than a rendered page.

    True for anything under /api, and for a client that explicitly asked for
    JSON. Browsers send ``Accept: text/html,...`` so a dashboard navigation is
    never mistaken for an API call.
    """
    if request.url.path.startswith("/api/"):
        return True
    accept = request.headers.get("accept", "")
    return "application/json" in accept and "text/html" not in accept


def unauthenticated_response(request):
    """401 for API clients, a redirect to the login page for the dashboard."""
    if wants_json(request):
        return JSONResponse({"error": "authentication required"},
                            status_code=401)
    nxt = request.url.path
    suffix = f"?next={nxt}" if nxt and nxt != "/login" else ""
    return RedirectResponse(f"/login{suffix}", status_code=303)


def forbidden_response(request, *, message: str = "permission denied"):
    """403 with a generic message — never the permission name or the role."""
    if wants_json(request):
        return JSONResponse({"error": message}, status_code=403)
    from starlette.responses import HTMLResponse
    return HTMLResponse(
        request.app.state.templates.get_template("error.html").render(
            request=request, status=403, title="Not permitted",
            message="Your role does not allow that action.",
            banner=request.app.state.review_banner),
        status_code=403)


def client_host(request) -> str:
    client = getattr(request, "client", None)
    return getattr(client, "host", None) or "-"
