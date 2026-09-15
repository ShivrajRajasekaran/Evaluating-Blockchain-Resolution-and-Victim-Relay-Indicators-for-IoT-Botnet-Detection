"""
tests/test_e2e — the whole product, once, through HTTP.

    sign in -> upload an authorised conn.log -> ingest -> detect -> alerts
            -> triage -> audit -> export

Every other test module checks one layer in isolation. This one checks that the
layers agree: that the category the engine decided is the category the database
stored and the dashboard renders and the CSV exports; that a window the
telemetry could not judge never becomes an alert; and that the honesty
statements survive the whole journey from the rule table to a downloaded file.

The fixture is a real Zeek conn.log written to a temp directory — the same
fixture builder the ingest adapter's own tests use, so this exercises the real
parser rather than a mock of it.
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from src.api import create_app
from src.auth import UserService
from src.detection import categories as C
from src.storage import Database, Repository, migrate, utcnow_iso

from tests.asgi_shim import Client
from tests.test_iot23_adapter import standard_rows, write_log
from tests.test_operational_zeek import PLAIN_FIELDS

PASSWORD = "correct-horse-battery-staple"
_CSRF_RE = re.compile(r'name="csrf_token" value="([a-f0-9]+)"')
BANNER = ("Alerts indicate suspicious behavioural patterns and require "
          "analyst review. They are not confirmation of compromise.")
MARKER = "Rule-based detection; not ML-validated."


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._prev = os.environ.get("PRODUCT_SESSION_SECRET")
        os.environ["PRODUCT_SESSION_SECRET"] = "als-e2e-signing-secret-0123456"

    @classmethod
    def tearDownClass(cls):
        if cls._prev is None:
            os.environ.pop("PRODUCT_SESSION_SECRET", None)
        else:
            os.environ["PRODUCT_SESSION_SECRET"] = cls._prev

    def setUp(self):
        self._dir = Path(tempfile.mkdtemp(prefix="als_e2e_"))
        self.db = Database(self._dir / "app.db")
        migrate(self.db)
        with self.db.transaction() as conn:
            users = UserService(Repository(conn), iterations=1000)
            users.create_user(username="ana", password=PASSWORD,
                              role_name="Analyst", created_at=utcnow_iso())
            users.create_user(username="adm", password=PASSWORD,
                              role_name="Admin", created_at=utcnow_iso())
        self.app = create_app(db=self.db)
        self.app.state.jobs_dir = self._dir / "uploads"
        self.capture = write_log(self._dir / "conn.log", standard_rows(),
                                 fields=PLAIN_FIELDS)

    def tearDown(self):
        shutil.rmtree(self._dir, ignore_errors=True)

    # -- helpers ---------------------------------------------------------
    def sign_in(self, username="ana") -> Client:
        c = Client(self.app)
        r = c.post("/login", data={"username": username, "password": PASSWORD})
        self.assertEqual(r.status_code, 303)
        return c

    def csrf(self, client, path) -> str:
        match = _CSRF_RE.search(client.get(path).text)
        self.assertIsNotNone(match, f"no CSRF token on {path}")
        return match.group(1)

    def upload(self, client, *, name="conn.log", source="op_zeek",
               content=None):
        token = self.csrf(client, "/upload")
        body = content if content is not None else self.capture.read_bytes()
        return client.post("/upload",
                           data={"csrf_token": token, "source": source},
                           files={"file": (name, body)})

    # -- the journey -----------------------------------------------------
    def test_the_full_journey(self):
        analyst = self.sign_in()

        # 1. upload -> ingest -> detect, reported on the page
        page = self.upload(analyst)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Ingest complete", page.text)
        self.assertIn(BANNER, page.text)

        # 2. the job is recorded as succeeded
        jobs = analyst.get("/api/ingestion-jobs").json()["items"]
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["status"], "succeeded")
        self.assertGreater(jobs[0]["windows_emitted"], 0)

        # 3. windows and feature snapshots were persisted, NaN kept as null
        with self.db.connection() as conn:
            windows = conn.execute(
                "SELECT COUNT(*) AS n FROM observation_windows").fetchone()["n"]
            snapshot = conn.execute(
                "SELECT features_json FROM feature_snapshots LIMIT 1"
            ).fetchone()["features_json"]
        self.assertEqual(windows, jobs[0]["windows_emitted"])
        features = json.loads(snapshot)
        self.assertIn(None, features.values(),
                      "an unmeasurable feature must persist as null, not 0")
        self.assertIsNone(features["ens_query_rate"])

        # 4. an alert exists, and it is a review-only category
        listing = analyst.get("/api/alerts").json()
        self.assertGreaterEqual(listing["total"], 1)
        alert = listing["items"][0]
        self.assertIn(alert["category"], C.ALERTING_CATEGORIES)
        self.assertTrue(alert["explanation"].endswith(MARKER))
        self.assertTrue(alert["review_only"])
        self.assertEqual(alert["status"], "Open")

        # 5. the detail page shows the evidence and the blind spot
        detail = analyst.get(f"/alerts/{alert['id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("This is not a confirmed incident", detail.text)
        self.assertIn("no resolution judgement can be made", detail.text)
        self.assertIn("not measurable", detail.text)

        # 6. triage it through the lifecycle
        token = self.csrf(analyst, f"/alerts/{alert['id']}")
        moved = analyst.post(f"/alerts/{alert['id']}/status",
                             data={"csrf_token": token,
                                   "status": "Investigating",
                                   "comment": "checking the device owner"})
        self.assertEqual(moved.status_code, 303)
        token = self.csrf(analyst, f"/alerts/{alert['id']}")
        analyst.post(f"/alerts/{alert['id']}/status",
                     data={"csrf_token": token, "status": "Benign",
                           "disposition": "benign_explained",
                           "comment": "vendor heartbeat, documented"})

        after = analyst.get(f"/api/alerts/{alert['id']}").json()
        self.assertEqual(after["status"], "Benign")
        self.assertEqual([f["to_status"] for f in after["feedback"]],
                         ["Investigating", "Benign"])

        # 7. every step left an audit trail, visible to an Admin
        audit = self.sign_in("adm").get("/api/audit").json()
        actions = [row["action"] for row in audit["items"]]
        for expected in ("auth.login", "file.upload", "ingest.start",
                         "detection.run", "ingest.succeed", "alert.status"):
            self.assertIn(expected, actions, f"{expected} was not audited")

        # 8. the export carries the banner and the provenance note
        csv_export = analyst.get("/reports/export?fmt=csv")
        self.assertEqual(csv_export.status_code, 200)
        self.assertIn("attachment", csv_export.headers["content-disposition"])
        self.assertIn(BANNER, csv_export.text)
        self.assertIn("UNLABELLED", csv_export.text)
        rows = list(csv.DictReader(
            io.StringIO("\n".join(line for line in csv_export.text.splitlines()
                                  if not line.startswith("#")))))
        self.assertEqual(rows[0]["category"], after["category"])
        self.assertIn(MARKER, rows[0]["explanation"])

        json_export = analyst.get("/reports/export?fmt=json").json()
        self.assertEqual(json_export["review_banner"], BANNER)
        self.assertIn("UNLABELLED", json_export["provenance_note"])

    def test_unjudgeable_windows_never_become_alerts(self):
        """The central honesty property, end to end.

        A Zeek conn.log cannot evaluate either resolution rule, so windows that
        fire nothing are INSUFFICIENT_TELEMETRY. They are counted, and they do
        not reach the analyst queue.
        """
        analyst = self.sign_in()
        page = self.upload(analyst)
        self.assertIn("INSUFFICIENT_TELEMETRY", page.text)

        listing = analyst.get("/api/alerts").json()
        categories = {a["category"] for a in listing["items"]}
        self.assertNotIn(C.CAT_INSUFFICIENT_TELEMETRY, categories)
        self.assertNotIn(C.CAT_BENIGN_OR_NO_ALERT, categories)
        self.assertNotIn(C.CAT_ABSTAIN, categories)

    def test_every_raised_alert_discloses_what_could_not_be_measured(self):
        analyst = self.sign_in()
        self.upload(analyst)
        for alert in analyst.get("/api/alerts").json()["items"]:
            with self.subTest(uid=alert["alert_uid"]):
                self.assertIn("resolution", alert["coverage_note"].lower())

    def test_re_uploading_the_same_capture_coalesces(self):
        analyst = self.sign_in()
        self.upload(analyst)
        first = analyst.get("/api/alerts").json()["total"]
        second = self.upload(analyst)
        self.assertIn("Ingest complete", second.text)
        self.assertEqual(analyst.get("/api/alerts").json()["total"], first)
        alert = analyst.get("/api/alerts").json()["items"][0]
        self.assertGreaterEqual(alert["occurrence_count"], 2)

    def test_a_rejected_upload_creates_no_job_and_no_alert(self):
        analyst = self.sign_in()
        rejected = self.upload(analyst, name="payload.exe",
                               content=b"MZ\x90\x00" * 100)
        self.assertEqual(rejected.status_code, 400)
        with self.db.connection() as conn:
            repo = Repository(conn)
            self.assertEqual(repo.jobs.recent(limit=10), [])
            self.assertEqual(repo.alerts.count(), 0)
            self.assertEqual(repo.files.recent(limit=10), [])

    def test_an_unreadable_capture_fails_the_job_without_alerting(self):
        """A file that passes the sniffer but the parser cannot use.

        A Zeek header declaring the wrong columns is exactly what a mis-selected
        log type looks like: the job must fail with a clear reason, not raise a
        500 and not produce a partial ingest.
        """
        analyst = self.sign_in()
        wrong = ("#separator \\x09\n"
                 "#fields\tts\tsomething\telse\n"
                 "1546300800.0\tx\ty\n").encode("utf-8")
        page = self.upload(analyst, name="conn.log", content=wrong)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Ingest failed", page.text)
        with self.db.connection() as conn:
            repo = Repository(conn)
            self.assertEqual(repo.jobs.recent(limit=1)[0].status, "failed")
            self.assertEqual(repo.alerts.count(), 0)

    def test_the_printable_report_is_self_contained_and_honest(self):
        analyst = self.sign_in()
        self.upload(analyst)
        alert_id = analyst.get("/api/alerts").json()["items"][0]["id"]
        report = analyst.get(f"/alerts/{alert_id}/print")
        self.assertEqual(report.status_code, 200)
        self.assertIn(BANNER, report.text)
        self.assertIn(MARKER, report.text)
        self.assertIn("UNLABELLED", report.text)
        self.assertIn("Telemetry limitations", report.text)

    def test_operational_windows_are_stored_unmapped_and_never_trainable(self):
        """Nothing ingested here can be mistaken for labelled training data."""
        analyst = self.sign_in()
        self.upload(analyst)
        with self.db.connection() as conn:
            classes = {r["research_class"] for r in conn.execute(
                "SELECT research_class FROM observation_windows").fetchall()}
        self.assertEqual(classes, {"unmapped"})


if __name__ == "__main__":
    unittest.main()
