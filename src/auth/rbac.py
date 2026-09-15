"""
auth.rbac — the three-role permission matrix.

Roles are fixed (Admin / Analyst / Viewer) and each maps to a frozen set of
permissions. Routes ask for a *permission*, not a role, so the policy lives in
one table here rather than being scattered as ``if role == "Admin"`` checks:

    Viewer   — read only (alerts, devices, ingestion, detection versions)
    Analyst  — Viewer + triage (change status, record feedback) + upload/ingest
    Admin    — everything, plus user management, audit log, config, data purge

Nothing here is defence in depth on its own; it is the single source of truth the
API's ``require`` decorator and the templates both consult.
"""
from __future__ import annotations

# Roles — must match the names seeded by storage.migrate.DEFAULT_ROLES.
ADMIN = "Admin"
ANALYST = "Analyst"
VIEWER = "Viewer"
ROLES: tuple[str, ...] = (ADMIN, ANALYST, VIEWER)

# Permissions.
VIEW = "view"                    # read alerts / devices / ingestion / versions
TRIAGE = "triage"               # change alert status, record analyst feedback
UPLOAD = "upload"               # upload a log file and run ingest + detection
MANAGE_USERS = "manage_users"   # create/enable/disable users
VIEW_AUDIT = "view_audit"       # read the audit log
PURGE_DATA = "purge_data"       # retention purge / delete
VIEW_CONFIG = "view_config"     # view detection config & model registry detail

ALL_PERMISSIONS = frozenset({
    VIEW, TRIAGE, UPLOAD, MANAGE_USERS, VIEW_AUDIT, PURGE_DATA, VIEW_CONFIG,
})

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    VIEWER: frozenset({VIEW}),
    ANALYST: frozenset({VIEW, TRIAGE, UPLOAD}),
    ADMIN: ALL_PERMISSIONS,
}


class PermissionDenied(Exception):
    """Raised when a role lacks a required permission. The API maps this to 403
    with a generic message (no detail leaked to the client)."""


def permissions_for(role: str) -> frozenset[str]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: str, permission: str) -> bool:
    return permission in permissions_for(role)


def require(role: str, permission: str) -> None:
    if not has_permission(role, permission):
        raise PermissionDenied(
            f"role {role!r} lacks permission {permission!r}")
