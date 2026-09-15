"""
api/routes/auth.py — sign in, sign out.

WHAT THE LOGIN ROUTE IS CAREFUL ABOUT
    ONE FAILURE MESSAGE. An unknown username, a wrong password and a disabled
    account all produce "Incorrect username or password." Telling them apart
    turns the login form into an account-enumeration oracle.
    :meth:`UserService.authenticate` already equalises the timing by verifying
    against a dummy hash when the user does not exist, so the response time does
    not leak what the message does not.

    EVERY ATTEMPT IS AUDITED. Success and failure both write an audit row; the
    failure row carries the submitted username, because "seventeen failures for
    'admin' from one host" is exactly what an operator needs to see. The
    password is never logged, in any form.

    RATE LIMITED BEFORE IDENTITY EXISTS. The middleware keys anonymous requests
    on client host, so the form is throttled without an account to throttle.

    THE REDIRECT TARGET IS VALIDATED. ``?next=`` is honoured only when it is a
    local absolute path, so the login page cannot be used to bounce someone to
    another site.
"""
from __future__ import annotations

import logging

from starlette.responses import RedirectResponse

from src.audit import events as A
from src.auth import UserService
from src.auth.sessions import Session
from src.storage import Repository, utcnow_iso

from .. import security as S
from ..security import guard

_log = logging.getLogger("als.api")

_GENERIC_FAILURE = "Incorrect username or password."


def safe_next(raw: str | None) -> str:
    """A local redirect target, or the dashboard root.

    Accepts only a path beginning with a single "/". That rejects
    ``https://evil.example``, protocol-relative ``//evil.example`` (which a
    browser resolves as absolute), and anything with a scheme.
    """
    value = (raw or "").strip()
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or "\n" in value or "\r" in value:
        return "/"
    return value


@guard(anonymous=True)
async def login_page(request):
    if request.state.session is not None:
        return RedirectResponse(safe_next(request.query_params.get("next")),
                                status_code=303)
    return _render_login(request, next_url=request.query_params.get("next"))


@guard(anonymous=True)
async def login_submit(request):
    form = await S.form_data(request)
    username = str(form.get("username") or "").strip()
    password = str(form.get("password") or "")
    next_url = safe_next(form.get("next") or request.query_params.get("next"))

    cfg = request.app.state.cfg
    db = request.app.state.db
    now = utcnow_iso()

    with db.transaction() as conn:
        repo = Repository(conn)
        users = UserService(repo, iterations=int(cfg.auth.pbkdf2_iterations),
                            salt_bytes=int(cfg.auth.salt_bytes))
        user = users.authenticate(username, password, now=now)
        audit = A.AuditLog(repo)
        if user is None:
            audit.record(A.LOGIN_FAILED, actor_username=username or None,
                         target_type="session", target_id=None,
                         request_id=request.state.request_id, created_at=now,
                         detail={"reason": "authentication_failed"})
        else:
            audit.record(A.LOGIN, actor=user, target_type="session",
                         target_id=user.id,
                         request_id=request.state.request_id, created_at=now)

    if user is None:
        return _render_login(request, next_url=next_url,
                             error=_GENERIC_FAILURE, status_code=401,
                             username=username)

    session = Session(user_id=user.id, username=user.username, role=user.role)
    manager = request.app.state.sessions
    response = RedirectResponse(next_url, status_code=303)
    response.set_cookie(value=manager.issue(session),
                        **manager.set_cookie_kwargs())
    return response


@guard(anonymous=True)
async def logout(request):
    """Sign out. Anonymous-safe: signing out twice is not an error.

    No CSRF token is required here. A forged logout is a nuisance, not a
    privilege escalation, and demanding a token would mean an expired session
    could not be cleared without first getting a new one.
    """
    session = request.state.session
    manager = request.app.state.sessions
    if session is not None:
        with request.app.state.db.transaction() as conn:
            A.AuditLog(Repository(conn)).record(
                A.LOGOUT, actor=session, target_type="session",
                target_id=session.user_id,
                request_id=request.state.request_id, created_at=utcnow_iso())
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(manager.cookie_name, path="/")
    return response


def _render_login(request, *, next_url=None, error: str | None = None,
                  status_code: int = 200, username: str = ""):
    templates = request.app.state.templates
    return templates.TemplateResponse(
        request, "login.html",
        {"error": error, "next": safe_next(next_url) if next_url else "",
         "username": username,
         "banner": request.app.state.review_banner,
         "product_name": request.app.state.product_name},
        status_code=status_code)
