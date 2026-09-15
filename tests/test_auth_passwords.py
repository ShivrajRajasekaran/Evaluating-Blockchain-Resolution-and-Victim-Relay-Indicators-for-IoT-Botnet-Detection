"""
tests/test_auth_passwords — password hashing/policy, signed sessions, and the
UserService authentication path (including username-enumeration resistance).
"""
from __future__ import annotations

import shutil
import tempfile
import time
import unittest
from pathlib import Path

import src.auth.users as users_mod
from src.auth import (SessionManager, UserService, check_password_policy,
                      hash_password, resolve_session_secret, verify_password)
from src.auth.sessions import Session
from src.storage import Database, Repository, migrate, utcnow_iso


class Passwords(unittest.TestCase):
    def test_hash_verify_roundtrip(self):
        h, s, iters = hash_password("correct horse battery", iterations=1000)
        self.assertTrue(verify_password("correct horse battery", h, s, iters))
        self.assertFalse(verify_password("wrong password", h, s, iters))

    def test_salt_is_random_per_call(self):
        h1, s1, _ = hash_password("same password here", iterations=1000)
        h2, s2, _ = hash_password("same password here", iterations=1000)
        self.assertNotEqual(s1, s2)
        self.assertNotEqual(h1, h2)  # different salt => different hash

    def test_wrong_iterations_does_not_verify(self):
        h, s, _ = hash_password("another password!!", iterations=1000)
        self.assertFalse(verify_password("another password!!", h, s, 2000))

    def test_malformed_stored_values_return_false_not_raise(self):
        self.assertFalse(verify_password("pw", "nothex!!", "zz", 1000))
        self.assertFalse(verify_password("pw", None, None, 1000))

    def test_policy_rejects_short_passwords(self):
        with self.assertRaises(ValueError):
            check_password_policy("short")
        check_password_policy("a sufficiently long one")  # no raise

    def test_hash_rejects_empty_password(self):
        with self.assertRaises(ValueError):
            hash_password("")


class Sessions(unittest.TestCase):
    def setUp(self):
        self.mgr = SessionManager("x" * 32, max_age=60, cookie_name="als_session")
        self.session = Session(user_id=7, username="alice", role="Analyst")

    def test_issue_and_read_roundtrip(self):
        token = self.mgr.issue(self.session)
        got = self.mgr.read(token)
        self.assertEqual(got, self.session)

    def test_tampered_token_is_rejected(self):
        token = self.mgr.issue(self.session)
        tampered = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
        self.assertIsNone(self.mgr.read(tampered))

    def test_token_from_another_secret_is_rejected(self):
        other = SessionManager("y" * 32)
        self.assertIsNone(self.mgr.read(other.issue(self.session)))

    def test_empty_and_none_tokens_are_anonymous(self):
        self.assertIsNone(self.mgr.read(None))
        self.assertIsNone(self.mgr.read(""))

    def test_expired_token_is_rejected(self):
        # itsdangerous stamps tokens at whole-second resolution and expires on
        # age > max_age (see URLSafeTimedSerializer). With max_age=1 a 1.5 s
        # sleep can compute an integer age of exactly 1 depending on sub-second
        # alignment, so the assertion is only deterministic once the read lands
        # two whole seconds past issue. Sleep past that boundary.
        short = SessionManager("x" * 32, max_age=1)
        token = short.issue(self.session)
        time.sleep(2.2)
        self.assertIsNone(short.read(token))

    def test_short_secret_is_refused(self):
        with self.assertRaises(ValueError):
            SessionManager("tooshort")

    def test_cookie_kwargs_are_hardened(self):
        kw = self.mgr.set_cookie_kwargs()
        self.assertTrue(kw["httponly"])
        self.assertEqual(kw["samesite"], "lax")

    def test_resolve_secret_generates_ephemeral_when_unset(self):
        # An unset env var yields a usable random secret flagged not-from-env.
        secret, from_env = resolve_session_secret("DEFINITELY_UNSET_ENV_XYZ")
        self.assertFalse(from_env)
        self.assertGreaterEqual(len(secret), 16)


class UserServiceCase(unittest.TestCase):
    def setUp(self):
        self._dir = Path(tempfile.mkdtemp(prefix="als_auth_"))
        self.db = Database(self._dir / "app.db")
        migrate(self.db)

    def tearDown(self):
        shutil.rmtree(self._dir, ignore_errors=True)

    def _service(self, conn):
        # Low iteration count keeps the suite fast; production uses config's.
        return UserService(Repository(conn), iterations=1000)

    def _create(self, username="alice", password="a good long password",
                role="Analyst"):
        with self.db.transaction() as conn:
            return self._service(conn).create_user(
                username=username, password=password, role_name=role,
                created_at=utcnow_iso())

    def test_create_then_authenticate(self):
        self._create()
        with self.db.transaction() as conn:
            user = self._service(conn).authenticate(
                "alice", "a good long password", now=utcnow_iso())
        self.assertIsNotNone(user)
        self.assertEqual(user.role, "Analyst")
        self.assertIsNotNone(user.last_login_at)

    def test_wrong_password_fails(self):
        self._create()
        with self.db.connection() as conn:
            self.assertIsNone(
                self._service(conn).authenticate("alice", "nope nope nope"))

    def test_unknown_user_returns_none_and_still_runs_pbkdf2(self):
        # Enumeration resistance: the unknown-user path must still compute one
        # PBKDF2, so timing does not reveal whether the username exists.
        calls = []
        original = users_mod.verify_password

        def counting(*a, **k):
            calls.append(a)
            return original(*a, **k)

        users_mod.verify_password = counting
        try:
            with self.db.connection() as conn:
                result = self._service(conn).authenticate(
                    "ghost", "irrelevant password")
        finally:
            users_mod.verify_password = original
        self.assertIsNone(result)
        self.assertEqual(len(calls), 1)

    def test_disabled_account_cannot_authenticate(self):
        uid = self._create()
        with self.db.transaction() as conn:
            self._service(conn).set_active(uid, False)
        with self.db.connection() as conn:
            self.assertIsNone(
                self._service(conn).authenticate(
                    "alice", "a good long password"))

    def test_weak_password_is_refused(self):
        with self.assertRaises(ValueError):
            with self.db.transaction() as conn:
                self._service(conn).create_user(
                    username="bob", password="short", role_name="Viewer",
                    created_at=utcnow_iso())

    def test_unknown_role_is_refused(self):
        with self.assertRaises(ValueError):
            with self.db.transaction() as conn:
                self._service(conn).create_user(
                    username="bob", password="a good long password",
                    role_name="Wizard", created_at=utcnow_iso())

    def test_set_password_changes_credential(self):
        uid = self._create()
        with self.db.transaction() as conn:
            self._service(conn).set_password(uid, "a brand new passphrase")
        with self.db.connection() as conn:
            svc = self._service(conn)
            self.assertIsNone(svc.authenticate("alice", "a good long password"))
            self.assertIsNotNone(
                svc.authenticate("alice", "a brand new passphrase"))


if __name__ == "__main__":
    unittest.main()
