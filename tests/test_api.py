"""
tests/test_api — the HTTP layer: authentication, RBAC, CSRF, headers, rate
limiting, the route declarations, and the published description.

NO httpx, NO SOCKET
    The tests drive the ASGI application directly through tests/asgi_shim.py.
    Starlette's own TestClient needs httpx, which is not installed and whose
    installation was not approved — and which is an outbound HTTP client, the
    one kind of library the containment rules keep out of this tree.

THE STRUCTURAL TEST
    ``RouteDeclarations`` walks the real route table and asserts that every
    route which changes state declares both a permission and CSRF protection.
    That is the test that keeps working as the product grows: a new POST added
    without a guard fails the suite rather than shipping unprotected.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from src.api import create_app
from src.api.ratelimit import RateLimiter, request_key
from src.api.routes import all_routes
from src.api.security import SECURITY_HEADERS
from src.auth import UserService, rbac
from src.storage import Database, Repository, migrate, utcnow_iso

from tests.asgi_shim import Client

PASSWORD = "correct-horse-battery-staple"
_CSRF_RE = re.compile(r'name="csrf_token" value="([a-f0-9]+)"')

# Deterministic and long enough for SessionManager; set before create_app so the
# app does not warn about an ephemeral key.
_TEST_SECRET = "als-test-signing-secret-0123456789"


class _AppCase(unittest.TestCase):
    """A migrated temp database, one app, and a client per role."""

    @classmethod
    def setUpClass(cls):
        cls._prev_secret = os.environ.get("PRODUCT_SESSION_SECRET")
        os.environ["PRODUCT_SESSION_SECRET"] = _TEST_SECRET

    @classmethod
    def tearDownClass(cls):
        if cls._prev_secret is None:
            os.environ.pop("PRODUCT_SESSION_SECRET", None)
        else:
            os.environ["PRODUCT_SESSION_SECRET"] = cls._prev_secret

    def setUp(self):
        self._dir = Path(tempfile.mkdtemp(prefix="als_api_"))
        self.db = Database(self._dir / "app.db")
        migrate(self.db)
        with self.db.transaction() as conn:
            # Low iteration count: these tests exercise routing, not PBKDF2.
            users = UserService(Repository(conn), iterations=1000)
            for name, role in (("adm", "Admin"), ("ana", "Analyst"),
                               ("vie", "Viewer")):
                users.create_user(username=name, password=PASSWORD,
                                  role_name=role, created_at=utcnow_iso())
        self.app = create_app(db=self.db)
        self.app.state.jobs_dir = self._dir / "uploads"

    def tearDown(self):
        shutil.rmtree(self._dir, ignore_errors=True)

    def client(self, username: str | None = None) -> Client:
        c = Client(self.app)
        if username:
            r = c.post("/login", data={"username": username,
                                       "password": PASSWORD})
            self.assertEqual(r.status_code, 303, "login should redirect")
        return c

    def csrf(self, client: Client, path: str = "/upload") -> str:
        match = _CSRF_RE.search(client.get(path).text)
        self.assertIsNotNone(match, f"no CSRF token rendered on {path}")
        return match.group(1)


# ===========================================================================
# route declarations — the structural guarantee
# ===========================================================================
class RouteDeclarations(unittest.TestCase):
    def test_every_route_declares_a_guard(self):
        for route in all_routes():
            with self.subTest(path=route.path):
                self.assertTrue(
                    hasattr(route.endpoint, "route_guard"),
                    f"{route.path} has no @guard declaration")

    def test_every_mutating_route_requires_a_permission_and_csrf(self):
        # The login and logout routes are the documented exceptions and are
        # asserted by name, so adding a third exception is a visible edit.
        exempt = {"/login", "/logout"}
        for route in all_routes():
            if "POST" not in (route.methods or ()):
                continue
            if route.path in exempt:
                continue
            with self.subTest(path=route.path):
                g = route.endpoint.route_guard
                self.assertIsNotNone(g.permission,
                                     f"{route.path} declares no permission")
                self.assertTrue(g.require_csrf,
                                f"{route.path} does not require CSRF")
                self.assertFalse(g.anonymous)

    def test_only_meta_and_auth_routes_are_anonymous(self):
        anonymous = {r.path for r in all_routes()
                     if r.endpoint.route_guard.anonymous}
        self.assertEqual(anonymous,
                         {"/login", "/logout", "/health", "/openapi.json",
                          "/docs"})

    def test_read_routes_require_at_least_view(self):
        for route in all_routes():
            g = route.endpoint.route_guard
            if g.anonymous or "GET" not in (route.methods or ()):
                continue
            with self.subTest(path=route.path):
                self.assertIn(g.permission, rbac.ALL_PERMISSIONS)


# ===========================================================================
# authentication
# ===========================================================================
class Authentication(_AppCase):
    def test_anonymous_dashboard_request_redirects_to_login(self):
        r = self.client().get("/alerts")
        self.assertEqual(r.status_code, 303)
        self.assertEqual(r.location, "/login?next=/alerts")

    def test_anonymous_api_request_is_401_json(self):
        r = self.client().get("/api/alerts")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.json()["error"], "authentication required")

    def test_login_sets_a_session_cookie_and_grants_access(self):
        c = self.client("ana")
        self.assertIn("als_session", c.cookies)
        self.assertEqual(c.get("/alerts").status_code, 200)

    def test_a_bad_password_and_an_unknown_user_are_indistinguishable(self):
        c = Client(self.app)
        wrong = c.post("/login", data={"username": "ana", "password": "nope"})
        unknown = c.post("/login", data={"username": "nobody",
                                         "password": "nope"})
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        self.assertIn("Incorrect username or password.", wrong.text)
        self.assertIn("Incorrect username or password.", unknown.text)
        self.assertNotIn("als_session", c.cookies)

    def test_a_disabled_account_gets_the_same_message(self):
        with self.db.transaction() as conn:
            repo = Repository(conn)
            UserService(repo, iterations=1000).set_active(
                repo.users.by_username("ana").id, False)
        r = Client(self.app).post("/login",
                                  data={"username": "ana", "password": PASSWORD})
        self.assertEqual(r.status_code, 401)
        self.assertIn("Incorrect username or password.", r.text)

    def test_both_outcomes_are_audited(self):
        c = Client(self.app)
        c.post("/login", data={"username": "ana", "password": "nope"})
        c.post("/login", data={"username": "ana", "password": PASSWORD})
        with self.db.connection() as conn:
            actions = [r["action"] for r in Repository(conn).audit.recent(10)]
        self.assertIn("auth.login_failed", actions)
        self.assertIn("auth.login", actions)

    def test_the_password_is_never_written_to_the_audit_trail(self):
        c = Client(self.app)
        c.post("/login", data={"username": "ana", "password": PASSWORD})
        with self.db.connection() as conn:
            rows = Repository(conn).audit.recent(10)
        blob = " ".join(str(dict(r)) for r in rows)
        self.assertNotIn(PASSWORD, blob)

    def test_logout_clears_the_session(self):
        c = self.client("ana")
        c.post("/logout")
        self.assertEqual(c.get("/alerts").status_code, 303)

    def test_a_forged_cookie_is_simply_anonymous(self):
        c = Client(self.app)
        c.cookies["als_session"] = "not.a.valid.token"
        r = c.get("/api/alerts")
        self.assertEqual(r.status_code, 401)

    def test_the_next_parameter_cannot_bounce_off_site(self):
        for hostile in ("https://evil.example/x", "//evil.example",
                        "/\\evil.example", "http://evil.example"):
            with self.subTest(next=hostile):
                c = Client(self.app)
                r = c.post("/login", data={"username": "ana",
                                           "password": PASSWORD,
                                           "next": hostile})
                self.assertEqual(r.location, "/")

    def test_a_local_next_is_honoured(self):
        c = Client(self.app)
        r = c.post("/login", data={"username": "ana", "password": PASSWORD,
                                   "next": "/devices"})
        self.assertEqual(r.location, "/devices")


# ===========================================================================
# RBAC
# ===========================================================================
class RoleAccess(_AppCase):
    #                     viewer  analyst  admin
    MATRIX = {
        "/": (200, 200, 200),
        "/alerts": (200, 200, 200),
        "/devices": (200, 200, 200),
        "/ingestion": (200, 200, 200),
        "/reports": (200, 200, 200),
        "/upload": (403, 200, 200),
        "/detection": (403, 403, 200),
        "/audit": (403, 403, 200),
        "/api/audit": (403, 403, 200),
    }

    def test_the_role_matrix_is_enforced_on_every_page(self):
        clients = {"vie": self.client("vie"), "ana": self.client("ana"),
                   "adm": self.client("adm")}
        for path, (viewer, analyst, admin) in self.MATRIX.items():
            for user, expected in (("vie", viewer), ("ana", analyst),
                                   ("adm", admin)):
                with self.subTest(path=path, role=user):
                    self.assertEqual(clients[user].get(path).status_code,
                                     expected)

    def test_a_viewer_cannot_triage(self):
        alert_id = _seed_alert(self.db)
        c = self.client("vie")
        r = c.post(f"/alerts/{alert_id}/status",
                   data={"status": "Investigating"})
        self.assertEqual(r.status_code, 403)
        with self.db.connection() as conn:
            self.assertEqual(Repository(conn).alerts.by_id(alert_id).status,
                             "Open")

    def test_a_403_does_not_name_the_missing_permission(self):
        # Matched inside <main> only: the <head> carries `name="viewport"`,
        # which contains "view" and is not a permission leak.
        body = self.client("vie").get("/audit").text
        main = body.split("<main", 1)[-1]
        for permission in rbac.ALL_PERMISSIONS:
            self.assertNotIn(permission, main)
        for role in rbac.ROLE_PERMISSIONS:
            self.assertNotIn(role, main)


# ===========================================================================
# CSRF
# ===========================================================================
class Csrf(_AppCase):
    def test_a_post_without_a_token_is_refused(self):
        alert_id = _seed_alert(self.db)
        r = self.client("ana").post(f"/alerts/{alert_id}/status",
                                    data={"status": "Investigating"})
        self.assertEqual(r.status_code, 403)

    def test_a_post_with_a_wrong_token_is_refused(self):
        alert_id = _seed_alert(self.db)
        r = self.client("ana").post(
            f"/alerts/{alert_id}/status",
            data={"status": "Investigating", "csrf_token": "0" * 64})
        self.assertEqual(r.status_code, 403)

    def test_a_post_with_the_rendered_token_succeeds(self):
        alert_id = _seed_alert(self.db)
        c = self.client("ana")
        token = self.csrf(c, f"/alerts/{alert_id}")
        r = c.post(f"/alerts/{alert_id}/status",
                   data={"status": "Investigating", "csrf_token": token})
        self.assertEqual(r.status_code, 303)

    def test_another_session_token_does_not_work(self):
        """The token is bound to the session cookie, so one user's token is
        useless in another user's session."""
        alert_id = _seed_alert(self.db)
        analyst = self.client("ana")
        admin = self.client("adm")
        stolen = self.csrf(admin, f"/alerts/{alert_id}")
        r = analyst.post(f"/alerts/{alert_id}/status",
                         data={"status": "Investigating",
                               "csrf_token": stolen})
        self.assertEqual(r.status_code, 403)

    def test_the_json_api_accepts_the_header_form(self):
        alert_id = _seed_alert(self.db)
        c = self.client("ana")
        token = self.csrf(c, f"/alerts/{alert_id}")
        r = c.post(f"/api/alerts/{alert_id}/status",
                   json={"status": "Investigating"},
                   headers={"X-CSRF-Token": token})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "Investigating")


# ===========================================================================
# headers, errors, rate limit
# ===========================================================================
class ResponseHeaders(_AppCase):
    def test_security_headers_are_on_every_response(self):
        for path in ("/login", "/health", "/api/alerts"):
            with self.subTest(path=path):
                headers = self.client().get(path).headers
                for name in SECURITY_HEADERS:
                    self.assertIn(name.lower(), headers)

    def test_the_csp_allows_no_external_origin(self):
        csp = self.client().get("/login").headers["content-security-policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("http://", csp)
        self.assertNotIn("https://", csp)
        self.assertNotIn("unsafe-inline", csp.split("style-src")[0])

    def test_a_request_id_is_echoed(self):
        r = self.client().get("/health", headers={"X-Request-ID": "abc123"})
        self.assertEqual(r.headers["x-request-id"], "abc123")

    def test_one_is_generated_when_the_client_sends_none(self):
        self.assertTrue(self.client().get("/health").headers["x-request-id"])


class Errors(_AppCase):
    def test_an_unknown_page_is_a_clean_404(self):
        r = self.client("ana").get("/no-such-page")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("Traceback", r.text)

    def test_an_unknown_alert_is_404_on_both_surfaces(self):
        c = self.client("ana")
        self.assertEqual(c.get("/alerts/99999").status_code, 404)
        self.assertEqual(c.get("/api/alerts/99999").status_code, 404)

    def test_a_non_numeric_id_is_404_not_500(self):
        self.assertEqual(self.client("ana").get("/alerts/abc").status_code, 404)


class RateLimiting(unittest.TestCase):
    """The bucket itself, at a controlled clock."""

    def setUp(self):
        self.now = 1000.0
        self.limiter = RateLimiter(capacity=3, refill_per_second=1.0,
                                   clock=lambda: self.now)

    def test_a_burst_up_to_capacity_is_allowed(self):
        for _ in range(3):
            self.assertTrue(self.limiter.check("k").allowed)
        self.assertFalse(self.limiter.check("k").allowed)

    def test_it_refills_over_time(self):
        for _ in range(3):
            self.limiter.check("k")
        self.now += 2.0
        self.assertTrue(self.limiter.check("k").allowed)
        self.assertTrue(self.limiter.check("k").allowed)
        self.assertFalse(self.limiter.check("k").allowed)

    def test_keys_are_independent(self):
        for _ in range(3):
            self.limiter.check("a")
        self.assertFalse(self.limiter.check("a").allowed)
        self.assertTrue(self.limiter.check("b").allowed)

    def test_a_refusal_says_when_to_retry(self):
        for _ in range(3):
            self.limiter.check("k")
        decision = self.limiter.check("k")
        self.assertFalse(decision.allowed)
        self.assertGreaterEqual(decision.retry_after, 1)
        self.assertIn("Retry-After", decision.headers(3))

    def test_users_are_keyed_by_name_and_anonymous_by_host(self):
        signed_in = request_key(route="/alerts", username="ana",
                                client_host="10.0.0.1")
        moved = request_key(route="/alerts", username="ana",
                            client_host="10.0.0.2")
        anonymous = request_key(route="/login", username=None,
                                client_host="10.0.0.1")
        self.assertEqual(signed_in, moved)   # cannot escape by changing address
        self.assertNotEqual(signed_in, anonymous)

    def test_routes_get_separate_buckets(self):
        self.assertNotEqual(request_key(route="/upload", username="a",
                                        client_host=None),
                            request_key(route="/alerts", username="a",
                                        client_host=None))

    def test_bad_configuration_is_refused(self):
        with self.assertRaises(ValueError):
            RateLimiter(capacity=0)
        with self.assertRaises(ValueError):
            RateLimiter(refill_per_second=0)


class RateLimitInTheApp(_AppCase):
    def test_an_over_rate_client_gets_429_not_a_crash(self):
        self.app.state.limiter = RateLimiter(capacity=2, refill_per_second=0.001)
        c = self.client()
        self.assertEqual(c.get("/health").status_code, 200)
        self.assertEqual(c.get("/health").status_code, 200)
        r = c.get("/health")
        self.assertEqual(r.status_code, 429)
        self.assertIn("retry-after", r.headers)

    def test_static_assets_are_not_rate_limited(self):
        self.app.state.limiter = RateLimiter(capacity=1, refill_per_second=0.001)
        c = self.client()
        c.get("/health")
        for _ in range(5):
            self.assertEqual(c.get("/static/app.css").status_code, 200)


# ===========================================================================
# meta routes
# ===========================================================================
class MetaRoutes(_AppCase):
    def test_health_is_anonymous_and_says_little(self):
        payload = self.client().get("/health").json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["detection_mode"], "rule")
        self.assertEqual(set(payload),
                         {"status", "product", "detection_mode",
                          "detection_version", "session_secret_from_env"})

    def test_the_spec_documents_exactly_the_routes_that_exist(self):
        spec = self.client().get("/openapi.json").json()
        documented = set()
        for path, ops in spec["paths"].items():
            for method in ops:
                documented.add((method.upper(), path))
        served = set()
        for route in all_routes():
            for method in route.methods or ():
                if method in ("HEAD", "OPTIONS"):
                    continue
                served.add((method, route.path))
        self.assertEqual(documented, served)

    def test_the_spec_records_each_route_permission(self):
        spec = self.client().get("/openapi.json").json()
        alerts = spec["paths"]["/api/alerts"]["get"]
        self.assertEqual(alerts["x-permission"], rbac.VIEW)
        status = spec["paths"]["/api/alerts/{alert_id}/status"]["post"]
        self.assertEqual(status["x-permission"], rbac.TRIAGE)
        self.assertTrue(status["x-requires-csrf"])

    def test_the_spec_carries_the_review_banner(self):
        spec = self.client().get("/openapi.json").json()
        self.assertIn("not confirmation of compromise",
                      spec["info"]["description"])

    def test_the_docs_page_loads_no_external_resource(self):
        # Checks what the browser would actually FETCH, not prose: the page
        # legitimately contains the sentence "no Swagger CDN, no outbound
        # fetch", and a naive substring search would flag its own disclaimer.
        body = self.client().get("/docs").text
        fetched = re.findall(r'(?:src|href)\s*=\s*"([^"]*)"', body)
        self.assertTrue(fetched, "the page should reference at least its CSS")
        for url in fetched:
            with self.subTest(url=url):
                self.assertFalse(url.startswith(("http://", "https://", "//")),
                                 f"{url} is an external resource")


# ===========================================================================
# the honesty surface
# ===========================================================================
class HonestyOnEveryPage(_AppCase):
    BANNER = ("Alerts indicate suspicious behavioural patterns and require "
              "analyst review. They are not confirmation of compromise.")

    def test_the_review_banner_is_verbatim_on_every_dashboard_page(self):
        c = self.client("adm")
        for path in ("/", "/alerts", "/devices", "/ingestion", "/upload",
                     "/detection", "/audit", "/reports"):
            with self.subTest(path=path):
                self.assertIn(self.BANNER, c.get(path).text)

    def test_the_login_page_carries_it_too(self):
        self.assertIn(self.BANNER, self.client().get("/login").text)

    def test_the_rule_marker_is_shown(self):
        body = self.client("ana").get("/alerts").text
        self.assertIn("Rule-based detection; not ML-validated.", body)

    def test_no_page_claims_a_confirmed_compromise(self):
        c = self.client("adm")
        for path in ("/", "/alerts", "/detection", "/reports"):
            body = c.get(path).text.lower()
            with self.subTest(path=path):
                for phrase in ("confirmed malware", "confirmed blockchain",
                               "confirmed victim relay", "confirmed c2",
                               "confirmed compromise"):
                    self.assertNotIn(phrase, body)

    def test_the_detection_page_explains_why_ml_is_off(self):
        body = self.client("adm").get("/detection").text
        self.assertIn("Why ML mode is not active", body)
        self.assertIn("disabled in configuration", body)

    def test_no_template_references_an_external_origin(self):
        """The CSP is only honest if the pages really are self-contained.

        Every src/href a browser would follow must be a local path — no CDN, no
        web font, no analytics beacon. If this fails, the strict
        Content-Security-Policy in api/security.py has become a claim the
        product cannot back up.
        """
        c = self.client("adm")
        for path in ("/", "/alerts", "/upload", "/detection", "/login",
                     "/reports", "/ingestion", "/devices", "/audit"):
            body = c.get(path).text
            for url in re.findall(r'(?:src|href)\s*=\s*"([^"]*)"', body):
                with self.subTest(path=path, url=url):
                    self.assertFalse(
                        url.startswith(("http://", "https://", "//")),
                        f"{path} loads {url} from outside this deployment")


# ---------------------------------------------------------------------------
def _seed_alert(db, *, category="SUSPICIOUS_RELAY_PATTERN") -> int:
    """One Open alert, written directly so a test can start from triage."""
    now = utcnow_iso()
    with db.transaction() as conn:
        repo = Repository(conn)
        device = repo.devices.get_or_create("dev_seed", is_pseudonymised=False,
                                            seen_at=now)
        return repo.alerts.create(
            alert_uid="al_seed", detection_run_id=None, ingestion_job_id=None,
            device_id=device, observation_window_id=None, category=category,
            severity="MEDIUM", confidence="medium",
            explanation="seeded for a routing test", coverage_note=None,
            provenance="rule-engine", detection_version="ruleset-1",
            source_file="conn.log", dedup_key="seed", status="Open",
            first_seen=now, last_seen=now, created_at=now)


if __name__ == "__main__":
    unittest.main()
