"""
tests/test_storage_repository — the persistence layer: migrations, seeding,
per-entity CRUD, idempotent upserts, alert dedup/search, and the two invariants
that matter for a security tool — SQL injection is treated as data, and the
audit trail is append-only by construction.

These tests use a real temp-file database, not ``:memory:``: the product opens a
fresh connection per unit of work (see storage/db.py), and an in-memory database
does not survive the close, so file-backed is the faithful fixture.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from src.storage import (Database, Repository, device_pseudonym, migrate,
                         resolve_device_key, utcnow_iso)
from src.storage.migrate import DEFAULT_ROLES


class _StorageCase(unittest.TestCase):
    """A migrated temp database with a fresh Repository per test."""

    def setUp(self) -> None:
        self._dir = Path(tempfile.mkdtemp(prefix="als_store_"))
        self.db = Database(self._dir / "app.db")
        self.applied = migrate(self.db)

    def tearDown(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)

    def _admin_role_id(self, repo: Repository) -> int:
        return repo.roles.by_name("Admin").id

    def _make_device(self, repo: Repository, key: str = "dev_test") -> int:
        return repo.devices.get_or_create(
            key, is_pseudonymised=False, seen_at=utcnow_iso())

    def _make_alert(self, repo: Repository, *, device_id: int,
                    dedup_key: str, category: str = "SUSPICIOUS_"
                    "CONVENTIONAL_BOTNET_PATTERN", status: str = "Open",
                    explanation: str = "beacon-like periodicity",
                    source_file: str = "conn.log") -> int:
        now = utcnow_iso()
        return repo.alerts.create(
            alert_uid=f"al_{dedup_key}", detection_run_id=None,
            ingestion_job_id=None, device_id=device_id,
            observation_window_id=None, category=category, severity="MEDIUM",
            confidence="medium", explanation=explanation, coverage_note=None,
            provenance="rule-engine", detection_version="ruleset-1",
            source_file=source_file, dedup_key=dedup_key, status=status,
            first_seen=now, last_seen=now, created_at=now)


class Migrations(_StorageCase):
    def test_first_migrate_applied_one_file(self):
        self.assertEqual(self.applied, 1)

    def test_second_migrate_is_a_noop(self):
        # init_db must be safe to run repeatedly.
        self.assertEqual(migrate(self.db), 0)

    def test_roles_are_seeded_exactly_once(self):
        migrate(self.db)  # run again; INSERT OR IGNORE must not duplicate
        with self.db.connection() as conn:
            repo = Repository(conn)
            roles = repo.roles.all()
        self.assertEqual({r.name for r in roles},
                         {name for name, _ in DEFAULT_ROLES})
        self.assertEqual(len(roles), len(DEFAULT_ROLES))

    def test_schema_migrations_records_the_version(self):
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT MAX(version) AS v FROM schema_migrations").fetchone()
        self.assertEqual(row["v"], 1)


class Meta(_StorageCase):
    def test_pseudonym_salt_is_present_and_stable(self):
        with self.db.connection() as conn:
            salt = Repository(conn).meta.pseudonym_salt()
        self.assertTrue(salt)
        # A second read (new connection) sees the same salt — pseudonyms must be
        # stable across ingests.
        with self.db.connection() as conn:
            self.assertEqual(Repository(conn).meta.pseudonym_salt(), salt)

    def test_salt_drives_a_stable_device_pseudonym(self):
        with self.db.connection() as conn:
            salt = Repository(conn).meta.pseudonym_salt()
        key, flag = resolve_device_key("192.168.1.50", salt, enabled=True)
        self.assertTrue(flag)
        self.assertEqual(key, device_pseudonym("192.168.1.50", salt))


class Users(_StorageCase):
    def test_create_and_fetch_with_role_join(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            uid = repo.users.create(
                username="alice", password_hash="h", password_salt="s",
                iterations=600000, role_id=self._admin_role_id(repo),
                created_at=utcnow_iso())
        with self.db.connection() as conn:
            user = Repository(conn).users.by_username("alice")
        self.assertEqual(user.id, uid)
        self.assertEqual(user.role, "Admin")     # joined role name
        self.assertTrue(user.is_active)

    def test_username_is_unique(self):
        import sqlite3
        with self.db.transaction() as conn:
            repo = Repository(conn)
            rid = self._admin_role_id(repo)
            repo.users.create(username="bob", password_hash="h",
                              password_salt="s", iterations=1, role_id=rid,
                              created_at=utcnow_iso())
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as conn:
                repo = Repository(conn)
                repo.users.create(username="bob", password_hash="h2",
                                  password_salt="s2", iterations=1,
                                  role_id=rid, created_at=utcnow_iso())

    def test_set_last_login_and_active(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            uid = repo.users.create(
                username="carol", password_hash="h", password_salt="s",
                iterations=1, role_id=self._admin_role_id(repo),
                created_at=utcnow_iso())
        with self.db.transaction() as conn:
            repo = Repository(conn)
            repo.users.set_last_login(uid, utcnow_iso())
            repo.users.set_active(uid, False)
        with self.db.connection() as conn:
            user = Repository(conn).users.by_id(uid)
        self.assertIsNotNone(user.last_login_at)
        self.assertFalse(user.is_active)


class Devices(_StorageCase):
    def test_get_or_create_is_idempotent(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            a = repo.devices.get_or_create(
                "dev_x", is_pseudonymised=True, seen_at="2026-01-01T00:00:00")
            b = repo.devices.get_or_create(
                "dev_x", is_pseudonymised=True, seen_at="2026-01-02T00:00:00")
        self.assertEqual(a, b)
        with self.db.connection() as conn:
            self.assertEqual(Repository(conn).devices.count(), 1)

    def test_last_seen_advances_but_never_regresses(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            repo.devices.get_or_create(
                "dev_y", is_pseudonymised=False, seen_at="2026-01-05T00:00:00")
        with self.db.transaction() as conn:
            repo = Repository(conn)
            repo.devices.get_or_create(
                "dev_y", is_pseudonymised=False, seen_at="2026-01-01T00:00:00")
        with self.db.connection() as conn:
            dev = Repository(conn).devices.by_key("dev_y")
        self.assertEqual(dev.last_seen, "2026-01-05T00:00:00")


class Windows(_StorageCase):
    def _upsert(self, repo, device_id, obs_id="obs-1"):
        return repo.windows.upsert(
            observation_id=obs_id, ingestion_job_id=None, device_id=device_id,
            window_start="2026-01-06T00:00:00", window_seconds=300,
            source_dataset="op_zeek", research_class="unmapped",
            quality_flags="proxy_source", n_features_missing=5,
            created_at=utcnow_iso())

    def test_upsert_is_idempotent_on_observation_id(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            dev = self._make_device(repo)
            a = self._upsert(repo, dev)
            b = self._upsert(repo, dev)          # same observation_id
        self.assertEqual(a, b)
        with self.db.connection() as conn:
            self.assertEqual(
                Repository(conn).windows.count_for_job(None) >= 0, True)


class FeatureSnapshots(_StorageCase):
    def test_upsert_is_idempotent_on_window(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            dev = self._make_device(repo)
            wid = repo.windows.upsert(
                observation_id="obs-f", ingestion_job_id=None, device_id=dev,
                window_start="2026-01-06T00:00:00", window_seconds=300,
                source_dataset="op_zeek", research_class="unmapped",
                quality_flags=None, n_features_missing=5,
                created_at=utcnow_iso())
            # NaN features stored as JSON null, never 0.
            a = repo.features.upsert(
                observation_window_id=wid,
                features_json='{"scan_rate": 3.0, "ens_query_rate": null}',
                created_at=utcnow_iso())
            b = repo.features.upsert(
                observation_window_id=wid, features_json='{"scan_rate": 9.9}',
                created_at=utcnow_iso())
        self.assertEqual(a, b)
        with self.db.connection() as conn:
            snap = Repository(conn).features.by_window(wid)
        # First write wins (INSERT OR IGNORE); the null is preserved verbatim.
        self.assertIn("null", snap["features_json"])


class DetectionModels(_StorageCase):
    def test_rule_baseline_registers_unvalidated(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            mid = repo.models.get_or_create_rule_baseline(
                name="rule-baseline", version="ruleset-1",
                registered_at=utcnow_iso())
        with self.db.connection() as conn:
            model = Repository(conn).models.by_id(mid)
        self.assertEqual(model.kind, "rule")
        self.assertFalse(model.is_validated)

    def test_rule_baseline_is_idempotent(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            a = repo.models.get_or_create_rule_baseline(
                name="rule-baseline", version="ruleset-1",
                registered_at=utcnow_iso())
            b = repo.models.get_or_create_rule_baseline(
                name="rule-baseline", version="ruleset-1",
                registered_at=utcnow_iso())
        self.assertEqual(a, b)

    def test_no_validated_ml_models_by_default(self):
        # ML mode is gated off: nothing validated exists until an authorised
        # labelled dataset is supplied and a model is registered as validated.
        with self.db.connection() as conn:
            self.assertEqual(Repository(conn).models.validated_ml_models(), [])


class Alerts(_StorageCase):
    def test_create_dedup_and_bump(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            dev = self._make_device(repo)
            self._make_alert(repo, device_id=dev, dedup_key="k1")
        with self.db.connection() as conn:
            existing = Repository(conn).alerts.by_dedup("k1")
        self.assertIsNotNone(existing)
        self.assertEqual(existing.occurrence_count, 1)
        self.assertEqual(existing.device_key, "dev_test")  # joined

        with self.db.transaction() as conn:
            Repository(conn).alerts.bump_occurrence(
                existing.id, last_seen="2026-02-01T00:00:00")
        with self.db.connection() as conn:
            bumped = Repository(conn).alerts.by_id(existing.id)
        self.assertEqual(bumped.occurrence_count, 2)
        self.assertEqual(bumped.last_seen, "2026-02-01T00:00:00")

    def test_dedup_key_is_unique(self):
        import sqlite3
        with self.db.transaction() as conn:
            repo = Repository(conn)
            dev = self._make_device(repo)
            self._make_alert(repo, device_id=dev, dedup_key="dup")
        with self.assertRaises(sqlite3.IntegrityError):
            with self.db.transaction() as conn:
                repo = Repository(conn)
                dev = repo.devices.by_key("dev_test").id
                self._make_alert(repo, device_id=dev, dedup_key="dup")

    def test_set_status_and_status_counts(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            dev = self._make_device(repo)
            a1 = self._make_alert(repo, device_id=dev, dedup_key="s1")
            self._make_alert(repo, device_id=dev, dedup_key="s2")
        with self.db.transaction() as conn:
            Repository(conn).alerts.set_status(a1, "Investigating")
        with self.db.connection() as conn:
            counts = Repository(conn).alerts.status_counts()
        self.assertEqual(counts.get("Investigating"), 1)
        self.assertEqual(counts.get("Open"), 1)

    def test_search_filters_by_category_and_device_and_text(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            dev1 = repo.devices.get_or_create(
                "dev_a", is_pseudonymised=False, seen_at=utcnow_iso())
            dev2 = repo.devices.get_or_create(
                "dev_b", is_pseudonymised=False, seen_at=utcnow_iso())
            self._make_alert(repo, device_id=dev1, dedup_key="c1",
                             category="SUSPICIOUS_RELAY_PATTERN",
                             explanation="relay fanout burst")
            self._make_alert(repo, device_id=dev2, dedup_key="c2",
                             category="SUSPICIOUS_CONVENTIONAL_BOTNET_PATTERN",
                             explanation="beacon periodicity")
        with self.db.connection() as conn:
            repo = Repository(conn)
            by_cat = repo.alerts.search(category="SUSPICIOUS_RELAY_PATTERN")
            by_dev = repo.alerts.search(device_id=dev2)
            by_text = repo.alerts.search(q="fanout")
            self.assertEqual(repo.alerts.count(), 2)
        self.assertEqual([a.dedup_key for a in by_cat], ["c1"])
        self.assertEqual([a.dedup_key for a in by_dev], ["c2"])
        self.assertEqual([a.dedup_key for a in by_text], ["c1"])


class EvidenceAndFeedback(_StorageCase):
    def test_evidence_and_feedback_roundtrip(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            dev = self._make_device(repo)
            aid = self._make_alert(repo, device_id=dev, dedup_key="e1")
            repo.evidence.add(alert_id=aid, kind="rule", name="beacon_periodic",
                              value="fired", weight=1.0, created_at=utcnow_iso())
            repo.evidence.add(alert_id=aid, kind="coverage",
                              name="resolution", value="unavailable",
                              weight=None, created_at=utcnow_iso())
            repo.feedback.add(alert_id=aid, user_id=None, from_status="Open",
                              to_status="Investigating", disposition=None,
                              comment="triaging", created_at=utcnow_iso())
        with self.db.connection() as conn:
            repo = Repository(conn)
            ev = repo.evidence.for_alert(aid)
            fb = repo.feedback.for_alert(aid)
        self.assertEqual({r["kind"] for r in ev}, {"rule", "coverage"})
        self.assertEqual(fb[0]["to_status"], "Investigating")


class Audit(_StorageCase):
    def test_append_and_recent(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            repo.audit.append(action="login", actor_username="alice",
                              target_type="session", target_id="1",
                              created_at=utcnow_iso())
            repo.audit.append(action="alert.status", actor_username="alice",
                              target_type="alert", target_id="7",
                              created_at=utcnow_iso())
        with self.db.connection() as conn:
            repo = Repository(conn)
            recent = repo.audit.recent(limit=10)
            self.assertEqual(repo.audit.count(), 2)
        # recent is newest-first
        self.assertEqual(recent[0]["action"], "alert.status")

    def test_audit_repo_is_append_only_by_construction(self):
        # The invariant is structural: there is no method that can rewrite or
        # remove an audit row, so history cannot be tampered with through the
        # repository at all.
        with self.db.connection() as conn:
            audit = Repository(conn).audit
        for forbidden in ("update", "delete", "remove", "set_status", "edit"):
            self.assertFalse(hasattr(audit, forbidden),
                             f"audit repo must not expose {forbidden!r}")


class Injection(_StorageCase):
    """Parameterisation proven by behaviour: a classic injection string is
    stored and matched as literal data, and destroys nothing."""

    def test_injection_in_username_is_data_not_code(self):
        evil = "'; DROP TABLE users;--"
        with self.db.transaction() as conn:
            repo = Repository(conn)
            repo.users.create(username=evil, password_hash="h",
                              password_salt="s", iterations=1,
                              role_id=self._admin_role_id(repo),
                              created_at=utcnow_iso())
        with self.db.connection() as conn:
            repo = Repository(conn)
            user = repo.users.by_username(evil)
            # The table still exists (query would raise otherwise) and holds the
            # row keyed by the literal malicious string.
            self.assertEqual(repo.users.count(), 1)
        self.assertEqual(user.username, evil)

    def test_injection_in_device_key_is_data_not_code(self):
        evil = "192.168.0.1'); DELETE FROM devices;--"
        with self.db.transaction() as conn:
            repo = Repository(conn)
            repo.devices.get_or_create(
                evil, is_pseudonymised=False, seen_at=utcnow_iso())
        with self.db.connection() as conn:
            repo = Repository(conn)
            self.assertEqual(repo.devices.count(), 1)
            self.assertIsNotNone(repo.devices.by_key(evil))

    def test_injection_in_alert_search_matches_literally(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            dev = self._make_device(repo)
            self._make_alert(repo, device_id=dev, dedup_key="q1",
                             explanation="ordinary beacon")
        with self.db.connection() as conn:
            repo = Repository(conn)
            # A tautology injection must NOT return all rows — it is matched as a
            # literal LIKE value and matches nothing.
            hits = repo.alerts.search(q="' OR '1'='1")
            self.assertEqual(hits, [])
            # And the table survived.
            self.assertEqual(repo.alerts.count(), 1)


if __name__ == "__main__":
    unittest.main()
