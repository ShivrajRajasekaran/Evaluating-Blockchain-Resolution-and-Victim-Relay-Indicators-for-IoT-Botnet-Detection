"""
tests/test_alerts_lifecycle — verdicts becoming alerts: the dedup identity, the
enforced analyst state machine, and the audit trail every transition leaves.

Three properties carry most of the weight here:

  * A day of identical windows is ONE alert with an occurrence count, not 288
    rows. A queue that cannot be triaged is not a security control.
  * An alert cannot be closed without a disposition. Open -> Closed is rejected,
    so the queue cannot be emptied without anyone saying anything about it.
  * Every transition writes both an analyst_feedback row and an audit event, in
    the same transaction as the status change.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from src.alerts import builder as B
from src.alerts import dedup as D
from src.alerts import lifecycle as L
from src.alerts.models import AlertDraft, EvidenceItem, PersistResult
from src.config import ConfigNode, load_config
from src.detection import categories as C
from src.detection import detect
from src.schema import columns as K
from src.storage import Database, Repository, migrate, utcnow_iso

from tests import helpers as H

QUIET = {"beacon_interval": 5.0}
# A fully-measurable source, so these tests exercise the alert layer rather than
# re-testing the coverage gate (tests/test_detection_engine.py owns that).
RELAY_HIT = {"beacon_interval": 5.0, "upnp_addportmapping": 1.0}


# ===========================================================================
# dedup identity
# ===========================================================================
class DedupKey(unittest.TestCase):
    BASE = dict(device_key="dev-a", category=C.CAT_SUSPICIOUS_RELAY,
                detection_version="ruleset-1",
                window_start="2026-01-06T00:00:00")

    def test_same_inputs_always_give_the_same_key(self):
        self.assertEqual(D.dedup_key(**self.BASE), D.dedup_key(**self.BASE))

    def test_windows_in_one_bucket_coalesce(self):
        later = dict(self.BASE, window_start="2026-01-06T23:59:00")
        self.assertEqual(D.dedup_key(**self.BASE), D.dedup_key(**later))

    def test_the_next_bucket_is_a_new_alert(self):
        later = dict(self.BASE, window_start="2026-01-07T00:01:00")
        self.assertNotEqual(D.dedup_key(**self.BASE), D.dedup_key(**later))

    def test_device_category_and_version_all_separate_alerts(self):
        for field, value in (("device_key", "dev-b"),
                             ("category", C.CAT_SUSPICIOUS_RESOLUTION),
                             ("detection_version", "ruleset-2")):
            with self.subTest(field=field):
                self.assertNotEqual(D.dedup_key(**self.BASE),
                                    D.dedup_key(**dict(self.BASE,
                                                       **{field: value})))

    def test_bucket_is_floored_so_a_replay_is_idempotent(self):
        # Not measured from first sighting: whichever window arrives first, the
        # bucket label is the same, so re-ingesting a capture coalesces.
        a = D.bucket_for("2026-01-06T03:00:00", hours=24)
        b = D.bucket_for("2026-01-06T20:00:00", hours=24)
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("2026-01-06T00:00:00"))

    def test_naive_timestamps_are_read_as_utc_not_local(self):
        # A key that depended on the server's timezone would not be reproducible
        # between the analyst's laptop and the deployment host.
        naive = D.dedup_key(**self.BASE)
        explicit = D.dedup_key(**dict(self.BASE,
                                      window_start="2026-01-06T00:00:00+00:00"))
        self.assertEqual(naive, explicit)

    def test_accepts_the_three_shapes_a_window_start_arrives_in(self):
        dt = datetime(2026, 1, 6, tzinfo=timezone.utc)
        from_dt = D.dedup_key(**dict(self.BASE, window_start=dt))
        from_str = D.dedup_key(**self.BASE)
        from_z = D.dedup_key(**dict(self.BASE,
                                    window_start="2026-01-06T00:00:00Z"))
        self.assertEqual({from_dt, from_str, from_z}, {from_str})

    def test_key_is_fixed_width_and_url_safe(self):
        key = D.dedup_key(**dict(self.BASE, device_key="2001:db8::1/64 ' OR 1"))
        self.assertEqual(len(key), 32)
        self.assertTrue(all(ch in "0123456789abcdef" for ch in key))
        self.assertTrue(D.alert_uid(key).startswith("al_"))

    def test_bad_inputs_raise_rather_than_making_something_up(self):
        for bad in ({"device_key": ""}, {"category": ""},
                    {"window_start": None}, {"window_start": "not a date"}):
            with self.subTest(bad=bad):
                with self.assertRaises(D.DedupError):
                    D.dedup_key(**dict(self.BASE, **bad))
        with self.assertRaises(D.DedupError):
            D.bucket_for("2026-01-06T00:00:00", hours=0)


# ===========================================================================
# the state machine
# ===========================================================================
class Lifecycle(unittest.TestCase):
    def test_the_five_statuses(self):
        self.assertEqual(
            L.STATUSES,
            ("Open", "Investigating", "Benign", "Confirmed suspicious",
             "Closed"))

    def test_the_documented_happy_path_is_legal(self):
        chain = [L.STATUS_OPEN, L.STATUS_INVESTIGATING,
                 L.STATUS_CONFIRMED_SUSPICIOUS, L.STATUS_CLOSED]
        for current, target in zip(chain, chain[1:]):
            L.check_transition(current, target)   # must not raise

    def test_an_alert_cannot_be_closed_without_a_disposition(self):
        with self.assertRaises(L.TransitionError) as ctx:
            L.check_transition(L.STATUS_OPEN, L.STATUS_CLOSED)
        self.assertIn("must be reviewed", str(ctx.exception))
        with self.assertRaises(L.TransitionError):
            L.check_transition(L.STATUS_INVESTIGATING, L.STATUS_CLOSED)

    def test_a_verdict_cannot_be_flipped_without_re_review(self):
        # Benign -> Confirmed suspicious must go back through Investigating, so
        # the history shows a re-review rather than a silent change of mind.
        with self.assertRaises(L.TransitionError):
            L.check_transition(L.STATUS_BENIGN,
                               L.STATUS_CONFIRMED_SUSPICIOUS)
        L.check_transition(L.STATUS_BENIGN, L.STATUS_INVESTIGATING)

    def test_closed_alerts_can_be_reopened(self):
        L.check_transition(L.STATUS_CLOSED, L.STATUS_INVESTIGATING)

    def test_a_no_op_transition_is_rejected(self):
        with self.assertRaises(L.TransitionError):
            L.check_transition(L.STATUS_OPEN, L.STATUS_OPEN)

    def test_unknown_statuses_are_rejected(self):
        with self.assertRaises(L.TransitionError):
            L.check_transition(L.STATUS_OPEN, "Resolved")
        with self.assertRaises(L.TransitionError):
            L.allowed_from("Escalated")

    def test_allowed_from_drives_the_ui_so_illegal_moves_are_never_offered(self):
        self.assertNotIn(L.STATUS_CLOSED, L.allowed_from(L.STATUS_OPEN))
        self.assertIn(L.STATUS_CLOSED, L.allowed_from(L.STATUS_BENIGN))

    def test_active_statuses_are_the_queue(self):
        self.assertTrue(L.is_active(L.STATUS_OPEN))
        self.assertTrue(L.is_active(L.STATUS_INVESTIGATING))
        self.assertFalse(L.is_active(L.STATUS_CLOSED))
        self.assertFalse(L.is_active(L.STATUS_BENIGN))

    def test_dispositions_are_a_controlled_vocabulary(self):
        L.check_disposition(None)
        L.check_disposition(L.DISPOSITION_FALSE_POSITIVE)
        with self.assertRaises(L.TransitionError):
            L.check_disposition("looked fine to me")

    def test_no_status_claims_confirmed_compromise(self):
        # "Confirmed suspicious" qualifies *suspicious*; nothing here may read
        # as a confirmed incident.
        for status in L.STATUSES:
            self.assertNotIn("compromis", status.lower())
            self.assertNotIn("malware", status.lower())
            self.assertNotIn("infected", status.lower())


# ===========================================================================
# verdict -> draft (pure)
# ===========================================================================
class DraftBuilding(unittest.TestCase):
    def _verdict(self, **overrides):
        frame = H.mock_frame(1, **{**QUIET, **overrides})
        return detect(frame).verdicts[0]

    def test_quiet_and_unmeasurable_windows_are_never_queued(self):
        quiet = detect(H.mock_frame(1, **QUIET)).verdicts[0]
        unmeasurable = detect(H.op_frame(1, **QUIET)).verdicts[0]
        self.assertEqual(quiet.category, C.CAT_BENIGN_OR_NO_ALERT)
        self.assertEqual(unmeasurable.category, C.CAT_INSUFFICIENT_TELEMETRY)
        self.assertIsNone(build_or_none(quiet))
        self.assertIsNone(build_or_none(unmeasurable))

    def test_a_firing_verdict_becomes_a_complete_draft(self):
        draft = B.build_draft(self._verdict(ens_query_rate=9.0),
                              device_key="dev-a", source_file="conn.log")
        self.assertIsInstance(draft, AlertDraft)
        self.assertEqual(draft.category, C.CAT_SUSPICIOUS_RESOLUTION)
        self.assertEqual(draft.status, L.STATUS_OPEN)
        self.assertEqual(draft.source_file, "conn.log")
        self.assertEqual(draft.alert_uid, D.alert_uid(draft.dedup_key))

    def test_stored_explanation_always_carries_the_marker(self):
        draft = B.build_draft(self._verdict(ens_query_rate=9.0),
                              device_key="dev-a")
        self.assertTrue(draft.explanation.endswith(
            "Rule-based detection; not ML-validated."))
        self.assertIn("high blockchain-name query rate", draft.explanation)

    def test_evidence_records_the_rule_and_the_value_separately(self):
        draft = B.build_draft(self._verdict(ens_query_rate=9.0),
                              device_key="dev-a")
        rules = [e for e in draft.evidence if e.kind == B.EV_RULE]
        feats = [e for e in draft.evidence if e.kind == B.EV_FEATURE]
        self.assertEqual([e.name for e in rules], ["ens_query_rate"])
        self.assertEqual(rules[0].value, "ens_query_rate > 3")
        # The measurement, so an analyst disputing the conclusion can see it.
        self.assertEqual(feats[0].value, "9")

    def test_coverage_blind_spots_ride_on_the_alert_as_evidence(self):
        v = detect(H.op_frame(1, **QUIET, updownlink_ratio=0.9)).verdicts[0]
        draft = B.build_draft(v, device_key="dev-a")
        cov = [e for e in draft.evidence if e.kind == B.EV_COVERAGE]
        self.assertEqual([e.name for e in cov], ["resolution"])
        self.assertIn("no resolution judgement can be made",
                      draft.coverage_note)

    def test_a_fired_group_is_never_listed_as_unmeasurable(self):
        draft = B.build_draft(self._verdict(ens_query_rate=9.0),
                              device_key="dev-a")
        cov = [e.name for e in draft.evidence if e.kind == B.EV_COVERAGE]
        self.assertNotIn("resolution", cov)

    def test_draft_serialises(self):
        draft = B.build_draft(self._verdict(ens_query_rate=9.0),
                              device_key="dev-a")
        import json
        json.dumps(draft.as_dict())


def build_or_none(verdict):
    return B.build_draft(verdict, device_key="dev-a")


# ===========================================================================
# persistence
# ===========================================================================
class _WriterCase(unittest.TestCase):
    """A migrated temp database plus an AlertWriter on a live connection."""

    def setUp(self):
        self._dir = Path(tempfile.mkdtemp(prefix="als_alerts_"))
        self.db = Database(self._dir / "app.db")
        migrate(self.db)
        # Pseudonymisation off by default here so assertions can name devices;
        # Pseudonymisation has its own test below.
        data = load_config().as_dict()
        data["storage"]["pseudonymise_devices"] = False
        self.cfg = ConfigNode(data)

    def tearDown(self):
        shutil.rmtree(self._dir, ignore_errors=True)

    def _persist(self, result, **kwargs):
        with self.db.transaction() as conn:
            writer = B.AlertWriter(Repository(conn), cfg=self.cfg)
            return writer.persist(result, **kwargs)

    def _repo_read(self):
        return self.db.connection()


class Persistence(_WriterCase):
    def test_one_firing_window_writes_one_open_alert(self):
        result = detect(H.mock_frame(1, **RELAY_HIT))
        outcome = self._persist(result, source_file="conn.log")
        self.assertIsInstance(outcome, PersistResult)
        self.assertEqual(outcome.created, 1)
        self.assertEqual(outcome.coalesced, 0)
        self.assertEqual(outcome.windows_scored, 1)
        with self._repo_read() as conn:
            alerts = Repository(conn).alerts.search()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, C.CAT_SUSPICIOUS_RELAY)
        self.assertEqual(alerts[0].status, L.STATUS_OPEN)
        self.assertEqual(alerts[0].source_file, "conn.log")
        self.assertEqual(alerts[0].provenance, "rule-engine")
        self.assertEqual(alerts[0].detection_version, "ruleset-1")

    def test_quiet_and_unmeasurable_windows_write_nothing(self):
        outcome = self._persist(detect(H.op_frame(5, **QUIET)))
        self.assertEqual(outcome.created, 0)
        self.assertEqual(outcome.windows_scored, 5)
        with self._repo_read() as conn:
            self.assertEqual(Repository(conn).alerts.count(), 0)

    def test_a_day_of_identical_windows_is_one_alert(self):
        # Twelve 5-minute windows for one device, all firing the same rule.
        frame = H.mock_frame(12, n_devices=1, **RELAY_HIT)
        outcome = self._persist(detect(frame))
        self.assertEqual(outcome.created, 1)
        self.assertEqual(outcome.coalesced, 11)
        self.assertEqual(outcome.total, 12)
        with self._repo_read() as conn:
            alerts = Repository(conn).alerts.search()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].occurrence_count, 12)

    def test_coalescing_advances_last_seen_but_not_first_seen(self):
        frame = H.mock_frame(4, n_devices=1, **RELAY_HIT)
        self._persist(detect(frame))
        with self._repo_read() as conn:
            alert = Repository(conn).alerts.search()[0]
        self.assertLess(alert.first_seen, alert.last_seen)

    def test_two_devices_are_two_alerts(self):
        frame = H.mock_frame(4, n_devices=2, **RELAY_HIT)
        outcome = self._persist(detect(frame))
        self.assertEqual(outcome.created, 2)
        self.assertEqual(outcome.coalesced, 2)

    def test_a_different_pattern_on_one_device_is_a_new_alert(self):
        frame = H.mock_frame(
            2, n_devices=1, beacon_interval=5.0,
            upnp_addportmapping=[1.0, 0.0], login_burst_count=[0.0, 5.0])
        outcome = self._persist(detect(frame))
        self.assertEqual(outcome.created, 2)
        with self._repo_read() as conn:
            cats = {a.category for a in Repository(conn).alerts.search()}
        self.assertEqual(cats, {C.CAT_SUSPICIOUS_RELAY,
                                C.CAT_SUSPICIOUS_CONVENTIONAL})

    def test_re_ingesting_the_same_capture_does_not_duplicate(self):
        frame = H.mock_frame(3, n_devices=1, **RELAY_HIT)
        self._persist(detect(frame))
        second = self._persist(detect(frame))
        self.assertEqual(second.created, 0)
        self.assertEqual(second.coalesced, 3)
        with self._repo_read() as conn:
            self.assertEqual(Repository(conn).alerts.count(), 1)

    def _relay_severity(self) -> str:
        with self._repo_read() as conn:
            alerts = {a.category: a for a in Repository(conn).alerts.search()}
        return alerts[C.CAT_SUSPICIOUS_RELAY].severity

    def test_recurrence_raises_severity_but_never_lowers_it(self):
        one_vote = H.mock_frame(1, n_devices=1, **RELAY_HIT)
        # Same device, same bucket, same CATEGORY, but broader evidence: one
        # relay rule becomes two relay rules plus a beacon, i.e. 3 votes across
        # 2 groups. It coalesces into the existing alert and must escalate it.
        broader = H.mock_frame(1, n_devices=1, beacon_interval=60.0,
                               upnp_addportmapping=1.0, updownlink_ratio=0.9)

        self._persist(detect(one_vote))
        self.assertEqual(self._relay_severity(), "LOW")

        self._persist(detect(broader))
        self.assertEqual(self._relay_severity(), "HIGH")

        # The quiet-again window must not downgrade evidence already triaged.
        self._persist(detect(one_vote))
        self.assertEqual(self._relay_severity(), "HIGH")

    def test_evidence_rows_land_with_the_alert(self):
        self._persist(detect(H.mock_frame(1, **RELAY_HIT)))
        with self._repo_read() as conn:
            repo = Repository(conn)
            alert = repo.alerts.search()[0]
            evidence = repo.evidence.for_alert(alert.id)
        kinds = {r["kind"] for r in evidence}
        self.assertEqual(kinds, {B.EV_RULE, B.EV_FEATURE})

    def test_the_run_is_recorded_and_finished(self):
        outcome = self._persist(detect(H.mock_frame(2, **RELAY_HIT)))
        with self._repo_read() as conn:
            run = Repository(conn).runs.by_id(outcome.run_id)
        self.assertEqual(run["mode"], "rule")
        self.assertEqual(run["windows_scored"], 2)
        self.assertIsNotNone(run["finished_at"])

    def test_a_run_is_capped_and_says_so(self):
        data = self.cfg.as_dict()
        data["alerts"]["max_alerts_per_run"] = 2
        self.cfg = ConfigNode(data)
        frame = H.mock_frame(6, n_devices=6, **RELAY_HIT)
        outcome = self._persist(detect(frame))
        self.assertTrue(outcome.truncated)
        self.assertEqual(outcome.created, 2)

    def test_alerts_link_to_their_observation_window_when_known(self):
        result = detect(H.mock_frame(1, **RELAY_HIT))
        obs_id = result.verdicts[0].observation_id
        with self.db.transaction() as conn:
            repo = Repository(conn)
            dev = repo.devices.get_or_create(
                "placeholder", is_pseudonymised=False, seen_at=utcnow_iso())
            wid = repo.windows.upsert(
                observation_id=obs_id, ingestion_job_id=None, device_id=dev,
                window_start="2026-01-06T00:00:00", window_seconds=300,
                source_dataset=K.SOURCE_MOCK_LOCAL, research_class="benign_mock",
                quality_flags=None, n_features_missing=0,
                created_at=utcnow_iso())
        self._persist(result, window_ids={obs_id: wid})
        with self._repo_read() as conn:
            alert = Repository(conn).alerts.search()[0]
        self.assertEqual(alert.observation_window_id, wid)


class Pseudonymisation(_WriterCase):
    def test_raw_device_ids_never_reach_the_database_when_enabled(self):
        data = load_config().as_dict()
        data["storage"]["pseudonymise_devices"] = True
        self.cfg = ConfigNode(data)
        frame = H.mock_frame(1, n_devices=1, device_prefix="192.168.1.77",
                             **RELAY_HIT)
        raw = frame[K.DEVICE_ID].iloc[0]
        self._persist(detect(frame))
        with self._repo_read() as conn:
            alert = Repository(conn).alerts.search()[0]
        self.assertNotEqual(alert.device_key, raw)
        self.assertNotIn("192.168", alert.device_key)


class Workflow(_WriterCase):
    def setUp(self):
        super().setUp()
        self._persist(detect(H.mock_frame(1, **RELAY_HIT)))
        with self._repo_read() as conn:
            self.alert_id = Repository(conn).alerts.search()[0].id

    def _transition(self, target, **kwargs):
        with self.db.transaction() as conn:
            writer = B.AlertWriter(Repository(conn), cfg=self.cfg)
            return writer.transition(self.alert_id, target, **kwargs)

    def test_a_legal_transition_updates_the_head(self):
        alert = self._transition(L.STATUS_INVESTIGATING)
        self.assertEqual(alert.status, L.STATUS_INVESTIGATING)

    def test_an_illegal_transition_is_refused_and_changes_nothing(self):
        with self.assertRaises(L.TransitionError):
            self._transition(L.STATUS_CLOSED)
        with self._repo_read() as conn:
            self.assertEqual(Repository(conn).alerts.by_id(self.alert_id).status,
                             L.STATUS_OPEN)

    def test_every_transition_writes_history_and_audit(self):
        self._transition(L.STATUS_INVESTIGATING, comment="picked up")
        self._transition(L.STATUS_BENIGN,
                         disposition=L.DISPOSITION_FALSE_POSITIVE,
                         comment="vendor polling, documented")
        with self._repo_read() as conn:
            repo = Repository(conn)
            history = repo.feedback.for_alert(self.alert_id)
            audit = repo.audit.recent(limit=20)
        self.assertEqual([(r["from_status"], r["to_status"]) for r in history],
                         [(L.STATUS_OPEN, L.STATUS_INVESTIGATING),
                          (L.STATUS_INVESTIGATING, L.STATUS_BENIGN)])
        self.assertEqual(history[1]["disposition"],
                         L.DISPOSITION_FALSE_POSITIVE)
        actions = [r["action"] for r in audit]
        self.assertEqual(actions.count("alert.status"), 2)
        self.assertIn("detection.run", actions)

    def test_the_full_documented_path_to_closed(self):
        self._transition(L.STATUS_INVESTIGATING)
        self._transition(L.STATUS_CONFIRMED_SUSPICIOUS,
                         disposition=L.DISPOSITION_TRUE_POSITIVE)
        alert = self._transition(L.STATUS_CLOSED)
        self.assertEqual(alert.status, L.STATUS_CLOSED)
        with self._repo_read() as conn:
            self.assertEqual(
                len(Repository(conn).feedback.for_alert(self.alert_id)), 3)

    def test_an_unknown_disposition_is_refused(self):
        with self.assertRaises(L.TransitionError):
            self._transition(L.STATUS_BENIGN, disposition="seemed ok")

    def test_a_comment_can_be_recorded_without_changing_status(self):
        with self.db.transaction() as conn:
            writer = B.AlertWriter(Repository(conn), cfg=self.cfg)
            writer.add_feedback(self.alert_id, comment="asked the device owner")
        with self._repo_read() as conn:
            repo = Repository(conn)
            history = repo.feedback.for_alert(self.alert_id)
            self.assertEqual(repo.alerts.by_id(self.alert_id).status,
                             L.STATUS_OPEN)
        self.assertEqual(history[0]["from_status"], history[0]["to_status"])
        self.assertEqual(history[0]["comment"], "asked the device owner")

    def test_transitioning_a_missing_alert_raises(self):
        with self.db.transaction() as conn:
            writer = B.AlertWriter(Repository(conn), cfg=self.cfg)
            with self.assertRaises(B.AlertError):
                writer.transition(99999, L.STATUS_INVESTIGATING)


if __name__ == "__main__":
    unittest.main()
