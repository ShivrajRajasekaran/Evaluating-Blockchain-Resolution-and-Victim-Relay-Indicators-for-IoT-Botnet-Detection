"""
api — the local-first web layer: JSON API + server-rendered dashboard.

    from src.api import create_app
    app = create_app()      # then: uvicorn src.api.app:app

MODULE MAP
    app         assembles the Starlette application and holds shared state
    routes/     the complete route table (auth, pages, jsonapi, meta)
    security    sessions, RBAC guards, CSRF, security headers
    ratelimit   in-process token bucket, keyed by (actor, route)
    uploads     validating and storing an uploaded capture safely
    pipeline    one authorised file: ingest -> detect -> alerts -> audit
    views       the projections the dashboard and the API both render
    errors      generic client-facing failures, detailed server-side logs
    openapi     the published description, generated from the route table
    server      the uvicorn entrypoint (binds 127.0.0.1 by default)

CONTAINMENT
    This package accepts INBOUND connections on a loopback bind. It makes no
    outbound ones: there is no HTTP client, no socket connect, no mail or FTP
    transport, and no CDN reference in any template or asset.
    ``tests/test_containment_outbound.py`` enforces that by reading the source
    of every module in the product tree.
"""
from __future__ import annotations

from .app import create_app
from .pipeline import IngestOutcome, PipelineError, run_pipeline
from .uploads import StoredUpload, UploadRejected, store_stream

__all__ = [
    "create_app",
    "run_pipeline",
    "IngestOutcome",
    "PipelineError",
    "store_stream",
    "StoredUpload",
    "UploadRejected",
]
