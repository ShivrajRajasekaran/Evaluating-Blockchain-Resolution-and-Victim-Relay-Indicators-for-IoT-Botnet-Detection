"""
api/app.py — the local-first Starlette application.

WHAT IT SERVES
    A server-rendered Jinja2 dashboard and a JSON API over the same data, from
    one process, bound to 127.0.0.1 by default.

DEPENDENCIES, AND THEIR ABSENCE
    Starlette, Uvicorn, Jinja2, itsdangerous, python-multipart — all already
    present — plus the standard library. No FastAPI, no pydantic, no SQLAlchemy,
    no passlib, no CDN. The dashboard's CSS and the one small JavaScript file
    are first-party and served from ``static/``, so the Content-Security-Policy
    in :mod:`api.security` can be strict without lying: this page really does
    load everything from itself. Nothing in the request path makes an outbound
    connection, and ``tests/test_containment_outbound.py`` proves it by reading
    the source.

REQUEST FLOW
    Every request passes through one middleware that stamps a request id, reads
    the signed session cookie, applies the token-bucket rate limit and — on the
    way out — sets the security headers. Route-level authorisation is declared
    on each handler with :func:`~src.api.security.guard`, so a handler cannot
    be wired up without its permission requirement.

STATE
    ``app.state`` holds the configuration, the database handle, the session
    manager, the rate limiter, the templates and a shared
    :class:`~src.detection.DetectionEngine`. The engine is built once because
    constructing it validates the severity policy and evaluates the ML gate —
    work that should happen at startup, where a misconfiguration is visible,
    rather than per request.

    A connection is NOT held on state. Each request opens its own and closes it,
    which is what keeps SQLite honest under concurrent readers.
"""
from __future__ import annotations

import logging
import secrets
import uuid
from pathlib import Path

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from src.auth import SessionManager, resolve_session_secret
from src.config import ROOT, load_config
from src.detection import DetectionEngine
from src.storage import Database

from . import security as S
from .errors import error_response, exception_handlers
from .ratelimit import RateLimiter, request_key
from .routes import all_routes

_log = logging.getLogger("als.api")

HERE = Path(__file__).resolve().parent
TEMPLATE_DIR = HERE / "templates"
STATIC_DIR = HERE / "static"

# Routes that must work before anyone can log in, or that are pure static
# assets. They skip the rate limiter's per-user keying (there is no user) but
# still get one, keyed by client host.
_ANONYMOUS_PREFIXES = ("/login", "/health", "/openapi.json", "/docs",
                       "/static/")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Request id, session, rate limit, security headers — in that order."""

    async def dispatch(self, request, call_next):
        cfg = request.app.state.cfg
        header = str(cfg.api.log.request_id_header)
        request_id = request.headers.get(header) or uuid.uuid4().hex[:16]
        request.state.request_id = request_id
        request.state.session = None
        request.state.form = None

        # Read the cookie once, here, so handlers and templates share one answer
        # and a forged cookie is resolved to "anonymous" exactly once.
        session = S.session_from_request(request)
        request.state.session = session

        limited = self._rate_limit(request, session)
        if limited is not None:
            response = limited
        else:
            response = await call_next(request)

        response.headers.setdefault(header, request_id)
        return S.apply_security_headers(
            response, secure=bool(cfg.auth.cookie_secure))

    def _rate_limit(self, request, session):
        """Refuse over-rate requests before the handler runs, or return None."""
        if request.url.path.startswith("/static/"):
            return None
        limiter = request.app.state.limiter
        key = request_key(route=_route_bucket(request.url.path),
                          username=session.username if session else None,
                          client_host=S.client_host(request))
        decision = limiter.check(key)
        if decision.allowed:
            return None
        _log.warning("rate limited key=%s path=%s", key, request.url.path)
        response = error_response(request, 429)
        for name, value in decision.headers(int(limiter.capacity)).items():
            response.headers[name] = value
        return response


def _route_bucket(path: str) -> str:
    """Collapse a path to the bucket it should be limited under.

    ``/alerts/91`` and ``/alerts/92`` share a bucket — they are the same kind of
    work — while ``/upload`` gets its own, because uploads and browsing have
    completely different natural rates.
    """
    parts = [p for p in path.split("/") if p]
    if not parts:
        return "/"
    head = parts[0]
    if head == "api" and len(parts) > 1:
        return f"/api/{parts[1]}"
    return f"/{head}"


def build_templates() -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    env = templates.env
    env.autoescape = True          # explicit: every value is escaped by default
    env.trim_blocks = True
    env.lstrip_blocks = True
    env.globals["csrf_token"] = S.csrf_token
    env.globals["CSRF_FIELD"] = S.CSRF_FIELD
    return templates


def create_app(*, cfg=None, db=None, config_path=None) -> Starlette:
    """Build the application. Injectable so tests never touch a real database."""
    cfg = cfg or load_config(config_path)
    db = db or Database(ROOT / str(cfg.storage.sqlite_path))

    secret, from_env = resolve_session_secret(str(cfg.auth.session_secret_env))
    if not from_env:
        # Loud, because sessions silently not surviving a restart is the kind of
        # thing that gets diagnosed as "the login is broken".
        _log.warning(
            "%s is not set; using an ephemeral session secret. Sessions will "
            "not survive a restart and must not be used in a real deployment.",
            cfg.auth.session_secret_env)

    app = Starlette(
        routes=all_routes(),
        middleware=[Middleware(RequestContextMiddleware)],
        exception_handlers=exception_handlers(),
    )
    app.state.cfg = cfg
    app.state.db = db
    app.state.sessions = SessionManager(
        secret, max_age=int(cfg.auth.session_max_age_seconds),
        cookie_name=str(cfg.auth.session_cookie_name),
        secure=bool(cfg.auth.cookie_secure))
    app.state.csrf_secret = secret.encode("utf-8")
    app.state.session_secret_from_env = from_env
    app.state.limiter = RateLimiter.from_config(cfg.api)
    app.state.templates = build_templates()
    app.state.engine = DetectionEngine(cfg=cfg)
    app.state.review_banner = " ".join(str(cfg.product.review_banner).split())
    app.state.product_name = str(cfg.product.name)
    app.state.jobs_dir = ROOT / "data" / "product" / "uploads"
    app.state.input_dir = ROOT / str(cfg.product.input_dir)
    app.state.build_token = secrets.token_hex(4)   # cache-busts static assets

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)),
                  name="static")
    return app


def healthcheck_payload(app) -> dict:
    """What ``/health`` reports. Deliberately says nothing sensitive."""
    return {
        "status": "ok",
        "product": app.state.product_name,
        "detection_mode": app.state.engine.mode,
        "detection_version": "ruleset-1",
        "session_secret_from_env": bool(app.state.session_secret_from_env),
    }


# Uvicorn target: `uvicorn src.api.app:app`.
#
# Built on first ATTRIBUTE ACCESS rather than at import, via PEP 562. Importing
# this module must stay free of side effects — `scripts/init_db.py` and the
# tests import it to reach create_app(), and opening the configured database
# just because someone imported the module would create the file in the wrong
# place at the wrong time. A module-level `app = None` would defeat this: a name
# already in the namespace never reaches __getattr__.
_app_singleton = None


def __getattr__(name):
    global _app_singleton
    if name == "app":
        if _app_singleton is None:
            _app_singleton = create_app()
        return _app_singleton
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
