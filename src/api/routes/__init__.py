"""
api/routes — the complete route table, in one readable list.

Keeping every route in one place means the product's attack surface can be read
top to bottom in under a minute, and it is what lets two tests be strict:

  * ``tests/test_api.py`` walks this table and asserts that every route which
    changes state declares both a permission and CSRF protection — a new
    mutating route added without a guard fails the suite rather than shipping.
  * ``src/api/openapi.py`` builds the published description from this same
    table, so a documented route and a served route cannot drift apart.

The dashboard lives at the bare paths and the JSON API under ``/api/``. Both
use the same session cookie and the same view models; the split is only in how
the answer is rendered.
"""
from __future__ import annotations

from starlette.routing import Route

from . import auth, jsonapi, meta, pages


def page_routes() -> list[Route]:
    """The server-rendered dashboard."""
    return [
        Route("/", pages.overview, methods=["GET"], name="overview"),
        Route("/alerts", pages.alerts_index, methods=["GET"], name="alerts"),
        Route("/alerts/{alert_id}", pages.alert_detail, methods=["GET"],
              name="alert_detail"),
        Route("/alerts/{alert_id}/print", pages.alert_print, methods=["GET"],
              name="alert_print"),
        Route("/alerts/{alert_id}/status", pages.alert_status,
              methods=["POST"], name="alert_status"),
        Route("/alerts/{alert_id}/feedback", pages.alert_feedback,
              methods=["POST"], name="alert_feedback"),
        Route("/upload", pages.upload_page, methods=["GET"], name="upload"),
        Route("/upload", pages.upload_submit, methods=["POST"],
              name="upload_submit"),
        Route("/ingestion", pages.ingestion_index, methods=["GET"],
              name="ingestion"),
        Route("/devices", pages.devices_index, methods=["GET"],
              name="devices"),
        Route("/detection", pages.detection_page, methods=["GET"],
              name="detection"),
        Route("/audit", pages.audit_page, methods=["GET"], name="audit"),
        Route("/reports", pages.reports_page, methods=["GET"],
              name="reports"),
        Route("/reports/export", pages.reports_export, methods=["GET"],
              name="reports_export"),
    ]


def auth_routes() -> list[Route]:
    return [
        Route("/login", auth.login_page, methods=["GET"], name="login"),
        Route("/login", auth.login_submit, methods=["POST"],
              name="login_submit"),
        Route("/logout", auth.logout, methods=["POST"], name="logout"),
    ]


def api_routes() -> list[Route]:
    """The JSON mirror."""
    return [
        Route("/api/summary", jsonapi.summary, methods=["GET"],
              name="api_summary"),
        Route("/api/alerts", jsonapi.alerts_list, methods=["GET"],
              name="api_alerts"),
        Route("/api/alerts/{alert_id}", jsonapi.alert_detail, methods=["GET"],
              name="api_alert_detail"),
        Route("/api/alerts/{alert_id}/status", jsonapi.alert_status,
              methods=["POST"], name="api_alert_status"),
        Route("/api/devices", jsonapi.devices_list, methods=["GET"],
              name="api_devices"),
        Route("/api/ingestion-jobs", jsonapi.jobs_list, methods=["GET"],
              name="api_jobs"),
        Route("/api/ingestion-jobs/{job_id}", jsonapi.job_detail,
              methods=["GET"], name="api_job_detail"),
        Route("/api/detection/versions", jsonapi.detection_versions,
              methods=["GET"], name="api_detection_versions"),
        Route("/api/detection/coverage/{source}", jsonapi.coverage_for_source,
              methods=["GET"], name="api_coverage"),
        Route("/api/detection/categories", jsonapi.categories_list,
              methods=["GET"], name="api_categories"),
        Route("/api/audit", jsonapi.audit_list, methods=["GET"],
              name="api_audit"),
    ]


def meta_routes() -> list[Route]:
    return [
        Route("/health", meta.health, methods=["GET"], name="health"),
        Route("/openapi.json", meta.openapi, methods=["GET"], name="openapi"),
        Route("/docs", meta.docs, methods=["GET"], name="docs"),
    ]


def all_routes() -> list[Route]:
    return auth_routes() + page_routes() + api_routes() + meta_routes()


__all__ = ["all_routes", "auth_routes", "page_routes", "api_routes",
           "meta_routes"]
