"""
api/routes/meta.py — health, the API description, and the docs page.

THESE THREE ARE ANONYMOUS, AND SAY NOTHING THEY SHOULD NOT
    ``/health`` exists so a process manager can restart a dead worker without
    holding a credential. It therefore reports liveness, the product name, and
    which detection mode is in force — and nothing else. No version of the
    database, no paths, no counts, no user list. "Is it up, and is it still the
    honest rule engine" is the entire contract.

    ``/openapi.json`` and ``/docs`` describe the shape of the API, which is
    public information about a locally-bound service: the routes are already
    discoverable by anyone who can reach the port, and every one of them
    enforces its own authentication. Publishing the description does not widen
    anything, and it makes the product usable without reading the source.

THE SPEC IS HAND-AUTHORED
    No decorator-driven generator, because there is no pydantic here to
    generate from. :mod:`api.openapi` builds it from the same route table the
    app serves, so a route that exists and a route that is documented cannot
    drift — ``tests/test_api.py`` asserts they match.
"""
from __future__ import annotations

from starlette.responses import HTMLResponse, JSONResponse

from ..security import guard


@guard(anonymous=True)
async def health(request):
    from ..app import healthcheck_payload
    return JSONResponse(healthcheck_payload(request.app))


@guard(anonymous=True)
async def openapi(request):
    from ..openapi import build_spec
    return JSONResponse(build_spec(request.app))


@guard(anonymous=True)
async def docs(request):
    """A static, first-party API reference. No Swagger CDN, no outbound fetch."""
    from ..openapi import build_spec
    spec = build_spec(request.app)
    templates = request.app.state.templates
    return HTMLResponse(templates.get_template("docs.html").render(
        request=request, spec=spec,
        banner=request.app.state.review_banner,
        product_name=request.app.state.product_name,
        build_token=request.app.state.build_token))
