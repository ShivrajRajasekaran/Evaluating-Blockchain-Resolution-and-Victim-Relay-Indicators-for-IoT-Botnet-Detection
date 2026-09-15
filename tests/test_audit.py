"""
tests/test_audit — the audit trail records actions durably, serialises detail,
resolves the actor from a Session/User, and is append-only by construction.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from src.audit import AuditLog, events
from src.auth.sessions import Session
from src.storage import Database, Repository, migrate, utcnow_iso


class _AuditCase(unittest.TestCase):
    def setUp(self):
        self._dir = Path(tempfile.mkdtemp(prefix="als_audit_"))
        self.db = Database(self._dir / "app.db")
        migrate(self.db)

    def tearDown(self):
        shutil.rmtree(self._dir, ignore_errors=True)


class Recording(_AuditCase):
    def test_record_writes_a_row_and_returns_id(self):
        with self.db.transaction() as conn:
            log = AuditLog(Repository(conn))
            eid = log.record(events.LOGIN, actor_username="alice",
                             target_type="session", target_id=1,
                             created_at=utcnow_iso())
        self.assertIsInstance(eid, int)
        with self.db.connection() as conn:
            self.assertEqual(AuditLog(Repository(conn)).count(), 1)

    def test_actor_is_resolved_from_a_session(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            uid = repo.users.create(
                username="carol", password_hash="h", password_salt="s",
                iterations=1, role_id=repo.roles.by_name("Admin").id,
                created_at=utcnow_iso())
        session = Session(user_id=uid, username="carol", role="Admin")
        with self.db.transaction() as conn:
            AuditLog(Repository(conn)).record(
                events.ALERT_STATUS, actor=session, target_type="alert",
                target_id=7, created_at=utcnow_iso())
        with self.db.connection() as conn:
            row = AuditLog(Repository(conn)).recent(limit=1)[0]
        self.assertEqual(row["actor_user_id"], uid)
        self.assertEqual(row["actor_username"], "carol")
        self.assertEqual(row["target_id"], "7")  # coerced to text

    def test_detail_is_json_serialised(self):
        with self.db.transaction() as conn:
            AuditLog(Repository(conn)).record(
                events.INGEST_SUCCEED, actor_username="svc",
                detail={"flows_read": 10, "windows": 3},
                created_at=utcnow_iso())
        with self.db.connection() as conn:
            row = AuditLog(Repository(conn)).recent(limit=1)[0]
        self.assertIn('"flows_read": 10', row["detail_json"])

    def test_emits_a_structured_log_line(self):
        with self.assertLogs("als.audit", level="INFO") as captured:
            with self.db.transaction() as conn:
                AuditLog(Repository(conn)).record(
                    events.LOGIN_FAILED, actor_username="mallory",
                    created_at=utcnow_iso())
        self.assertTrue(
            any("auth.login_failed" in line for line in captured.output))


class AppendOnly(_AuditCase):
    def test_audit_log_exposes_no_mutation_method(self):
        with self.db.connection() as conn:
            log = AuditLog(Repository(conn))
        for forbidden in ("update", "delete", "remove", "edit", "set_status"):
            self.assertFalse(hasattr(log, forbidden),
                             f"AuditLog must not expose {forbidden!r}")

    def test_recent_is_newest_first(self):
        with self.db.transaction() as conn:
            log = AuditLog(Repository(conn))
            log.record(events.LOGIN, actor_username="a", created_at=utcnow_iso())
            log.record(events.LOGOUT, actor_username="a",
                       created_at=utcnow_iso())
        with self.db.connection() as conn:
            rows = AuditLog(Repository(conn)).recent(limit=10)
        self.assertEqual(rows[0]["action"], events.LOGOUT)

    def test_actor_username_survives_user_deletion(self):
        # The schema's ON DELETE SET NULL guarantee: deleting the acting user
        # must not erase the audit trail — the id nulls, the username remains.
        with self.db.transaction() as conn:
            repo = Repository(conn)
            uid = repo.users.create(
                username="dave", password_hash="h", password_salt="s",
                iterations=1, role_id=repo.roles.by_name("Admin").id,
                created_at=utcnow_iso())
            AuditLog(repo).record(events.USER_DISABLE, actor_user_id=uid,
                                  actor_username="dave", created_at=utcnow_iso())
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (uid,))
        with self.db.connection() as conn:
            row = AuditLog(Repository(conn)).recent(limit=1)[0]
        self.assertIsNone(row["actor_user_id"])          # reference cleared
        self.assertEqual(row["actor_username"], "dave")  # identity preserved


if __name__ == "__main__":
    unittest.main()
