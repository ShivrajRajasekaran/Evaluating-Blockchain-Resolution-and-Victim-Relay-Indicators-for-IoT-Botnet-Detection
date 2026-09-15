"""
tests/test_rbac — the role/permission matrix is the single source of truth for
authorisation, so it gets asserted explicitly and completely.
"""
from __future__ import annotations

import unittest

from src.auth import rbac


class RoleMatrix(unittest.TestCase):
    def test_role_names_match_seeded_roles(self):
        # RBAC role names must equal the DB-seeded ones, or a logged-in user's
        # role string would never match the matrix.
        from src.storage.migrate import DEFAULT_ROLES
        self.assertEqual(set(rbac.ROLES), {name for name, _ in DEFAULT_ROLES})

    def test_viewer_is_read_only(self):
        self.assertTrue(rbac.has_permission(rbac.VIEWER, rbac.VIEW))
        for p in (rbac.TRIAGE, rbac.UPLOAD, rbac.MANAGE_USERS, rbac.VIEW_AUDIT,
                  rbac.PURGE_DATA, rbac.VIEW_CONFIG):
            self.assertFalse(rbac.has_permission(rbac.VIEWER, p),
                             f"Viewer must not have {p}")

    def test_analyst_can_triage_and_upload_but_not_administer(self):
        for p in (rbac.VIEW, rbac.TRIAGE, rbac.UPLOAD):
            self.assertTrue(rbac.has_permission(rbac.ANALYST, p))
        for p in (rbac.MANAGE_USERS, rbac.VIEW_AUDIT, rbac.PURGE_DATA,
                  rbac.VIEW_CONFIG):
            self.assertFalse(rbac.has_permission(rbac.ANALYST, p),
                             f"Analyst must not have {p}")

    def test_admin_has_every_permission(self):
        for p in rbac.ALL_PERMISSIONS:
            self.assertTrue(rbac.has_permission(rbac.ADMIN, p))

    def test_require_raises_permission_denied(self):
        with self.assertRaises(rbac.PermissionDenied):
            rbac.require(rbac.VIEWER, rbac.MANAGE_USERS)
        rbac.require(rbac.ADMIN, rbac.MANAGE_USERS)  # no raise

    def test_unknown_role_has_no_permissions(self):
        self.assertEqual(rbac.permissions_for("Nobody"), frozenset())
        self.assertFalse(rbac.has_permission("Nobody", rbac.VIEW))


if __name__ == "__main__":
    unittest.main()
