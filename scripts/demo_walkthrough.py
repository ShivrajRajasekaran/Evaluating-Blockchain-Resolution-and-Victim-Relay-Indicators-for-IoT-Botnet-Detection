"""
scripts/demo_walkthrough.py — generate a visual walkthrough of the product.

    python -m scripts.demo_walkthrough
    python -m scripts.demo_walkthrough --open        # open it when finished
    python -m scripts.demo_walkthrough --out docs/walkthrough

WHAT IT PRODUCES
    A single self-contained HTML page — screenshots of the real dashboard, in
    the order you would show them, each with the sentence that explains what to
    look at. Nothing is embedded by hand: every image is a render of the actual
    page the application served for that step.

WHAT IT DOES NOT DO
    It does not fabricate anything. There is no demo mode inside the product,
    no seeded fake alert, and no invented number. The walkthrough runs the real
    ingest pipeline over the repository's Zeek TEST FIXTURE — synthetic traffic
    from the test suite, labelled as such on the page — and photographs whatever
    the product genuinely does with it. If the detection logic changes, the
    walkthrough changes with it, because it is regenerated rather than written.

IT DOES NOT TOUCH YOUR DATABASE
    Everything happens in a temporary directory that is deleted afterwards, so
    running this never disturbs a live deployment, never creates a real user,
    and never adds a row an analyst might mistake for a finding.

NO SOCKET IS OPENED
    The application is driven IN-PROCESS through tests/asgi_shim.py — the same
    shim the HTTP tests use — rather than over the network. That keeps this tool
    free of any HTTP client, which matters: the product tree is guaranteed to
    contain no outbound network primitive, and a demo generator that imported
    one would sit awkwardly beside that guarantee even though it lives outside
    the scanned packages.

    Screenshots are taken by a headless browser if one is present. Without it,
    the page still builds, using the live markup instead of images.
"""
from __future__ import annotations

import argparse
import base64
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEMO_PASSWORD = "walkthrough-demo-password"
_CSRF_RE = re.compile(r'name="csrf_token" value="([a-f0-9]+)"')

# Headless browsers this will use if it finds one, in preference order.
_BROWSERS = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/chromium", "/usr/bin/google-chrome", "/usr/bin/microsoft-edge",
)


@dataclass
class Step:
    """One frame of the walkthrough."""

    key: str
    title: str
    path: str
    say: str
    look_for: list[str] = field(default_factory=list)
    height: int = 1200
    html_text: str = ""
    png: bytes | None = None


# The running order. This is the argument the walkthrough makes, in sequence:
# there is no default credential -> here is what the source cannot see -> here
# is a finding -> here is exactly why it is not a confirmation -> here are the
# rules -> here is the record.
STEPS: list[Step] = [
    Step("login", "1. Signing in", "/login",
         "There is no default administrator and no default password — an "
         "account exists only because an operator created one. The review "
         "banner is already visible, before anyone has logged in.",
         ["No self-registration", "not confirmation of compromise"],
         height=700),
    Step("overview", "2. What this deployment can and cannot judge", "/",
         "Before any alert, the product states its own blind spots. The "
         "coverage table reads from the schema, not from data: on every "
         "supported flow format, the resolution group is unjudgeable, because "
         "a flow log carries no DNS or HTTP.",
         ["resolution", "Blind to"], height=1250),
    Step("alerts", "3. The queue", "/alerts",
         "One row, not one per five-minute window. Repeated windows showing "
         "the same pattern on the same device coalesce into a single alert "
         "with an occurrence count — a device beaconing all day is one thing "
         "to triage, not 288.",
         ["Windows", "Suspicious"], height=950),
    Step("detail", "4. The alert itself", "/alerts/1",
         "The centrepiece. It opens by saying it is NOT a confirmed incident. "
         "It discloses the telemetry it could not read. The evidence is split "
         "into the rule applied, the value measured, and the blind spot — you "
         "need the second to argue with the first. And unmeasurable features "
         "read 'not measurable', never 0.",
         ["not a confirmed incident", "Partial telemetry", "not measurable"],
         height=1500),
    Step("detection", "5. The rules, in the open", "/detection",
         "Every threshold is shown, with a fingerprint of the rule table. "
         "These are the same thresholds the research baseline votes on — the "
         "engine reads them rather than restating them, and refuses to run if "
         "the two ever disagree. Note the section explaining why ML mode is "
         "switched off.",
         ["Why ML mode is not active", "fingerprint"], height=1400),
    Step("audit", "6. The record", "/audit",
         "Every login, upload, ingest, detection run and status change. "
         "Append-only by construction: the repository exposes no update or "
         "delete method, so history cannot be rewritten through the product.",
         ["Append-only"], height=900),
]


# ===========================================================================
# Driving the application
# ===========================================================================
def build_environment(tmp: Path):
    """A throwaway database with users and one ingested capture."""
    from src.api import create_app
    from src.api.pipeline import run_pipeline
    from src.auth import UserService
    from src.schema import columns as K
    from src.storage import Database, Repository, migrate, utcnow_iso

    os.environ.setdefault("PRODUCT_SESSION_SECRET",
                          "walkthrough-only-signing-secret-000000")

    db = Database(tmp / "app.db")
    migrate(db)
    with db.transaction() as conn:
        # Low iteration count: this database is deleted in a moment, and 600k
        # PBKDF2 rounds would add seconds to a screenshot run for no security.
        UserService(Repository(conn), iterations=1000).create_user(
            username="analyst", password=DEMO_PASSWORD, role_name="Admin",
            created_at=utcnow_iso())

    capture = fixture_capture(tmp)
    with db.transaction() as conn:
        outcome = run_pipeline(capture, source=K.SOURCE_OP_ZEEK,
                               repo=Repository(conn),
                               source_file=capture.name)
    app = create_app(db=db)
    app.state.jobs_dir = tmp / "uploads"
    return app, outcome


def fixture_capture(tmp: Path) -> Path:
    """The Zeek fixture the test suite uses. Synthetic, and labelled as such.

    Preferring the repository's authorised-input sample when one is present
    means an operator who has dropped a real capture there gets a walkthrough of
    their own data instead.
    """
    existing = ROOT / "data" / "authorised_input" / "sample-conn.log"
    if existing.is_file():
        return existing
    from tests.test_iot23_adapter import standard_rows, write_log
    from tests.test_operational_zeek import PLAIN_FIELDS
    return Path(write_log(tmp / "sample-conn.log", standard_rows(),
                          fields=PLAIN_FIELDS))


def capture_pages(app, steps: list[Step]) -> None:
    """Sign in and fetch each page, in order, through the ASGI shim."""
    from tests.asgi_shim import Client

    client = Client(app)
    for step in steps:
        if step.key == "login":
            step.html_text = client.get("/login").text
            client.post("/login", data={"username": "analyst",
                                        "password": DEMO_PASSWORD})
            continue
        response = client.get(step.path)
        if response.status_code != 200:
            raise SystemExit(
                f"{step.path} returned {response.status_code}; the walkthrough "
                "expects a working application")
        step.html_text = response.text


def inline_assets(app, steps: list[Step]) -> None:
    """Fold the stylesheet into each page so it renders from a local file."""
    css = (ROOT / "src" / "api" / "static" / "app.css").read_text(
        encoding="utf-8")
    for step in steps:
        page = re.sub(r'<link rel="stylesheet"[^>]*>', f"<style>{css}</style>",
                      step.html_text)
        # Drop the script tag: it only adds confirm prompts and filter
        # auto-submit, neither of which a screenshot benefits from.
        page = re.sub(r'<script src="/static/app\.js[^>]*></script>', "", page)
        step.html_text = page


# ===========================================================================
# Screenshots
# ===========================================================================
def find_browser() -> str | None:
    for candidate in _BROWSERS:
        if Path(candidate).exists():
            return candidate
    return shutil.which("chromium") or shutil.which("google-chrome")


def shoot(browser: str, steps: list[Step], work: Path) -> int:
    """Render each page to PNG. Returns how many succeeded.

    Chromium-family browsers in ``--headless=new`` mode DETACH: the command
    returns 0 within about a tenth of a second and the renderer writes the file
    roughly a second later. Checking for the image as soon as the process exits
    therefore finds nothing every time, silently, with a success exit code — so
    the file is waited for rather than assumed.
    """
    taken = 0
    for step in steps:
        page = work / f"{step.key}.html"
        page.write_text(step.html_text, encoding="utf-8")
        png = work / f"{step.key}.png"
        try:
            subprocess.run(
                [browser, "--headless=new", "--disable-gpu",
                 "--hide-scrollbars", f"--window-size=1280,{step.height}",
                 f"--screenshot={png}", page.as_uri()],
                check=False, capture_output=True, timeout=90)
        except (OSError, subprocess.TimeoutExpired):
            continue
        data = _await_file(png)
        if data:
            step.png = data
            taken += 1
    return taken


def _await_file(path: Path, *, timeout: float = 20.0) -> bytes | None:
    """Wait for a detached renderer to finish writing, then read it.

    Requires the size to hold steady across two polls: a partially written PNG
    exists on disk and would otherwise be embedded truncated.
    """
    import time

    deadline = time.monotonic() + timeout
    last = -1
    while time.monotonic() < deadline:
        if path.exists():
            size = path.stat().st_size
            if size > 0 and size == last:
                return path.read_bytes()
            last = size
        time.sleep(0.25)
    return None


# ===========================================================================
# The walkthrough page
# ===========================================================================
def render_walkthrough(steps: list[Step], outcome, *, shot_count: int) -> str:
    summary = outcome.summary or {}
    counts = summary.get("by_category", {})
    interesting = {k: v for k, v in counts.items() if v}

    frames = []
    for step in steps:
        if step.png:
            src = "data:image/png;base64," + base64.b64encode(
                step.png).decode("ascii")
            visual = (f'<img src="{src}" alt="{html.escape(step.title)}" '
                      f'loading="lazy">')
        else:
            visual = ('<p class="nofig">No headless browser was available, so '
                      'this frame has no screenshot. The page markup is in the '
                      'output directory.</p>')
        looks = "".join(f"<li><code>{html.escape(t)}</code></li>"
                        for t in step.look_for)
        frames.append(f"""
      <section class="frame">
        <h2>{html.escape(step.title)}</h2>
        <p class="say">{html.escape(step.say)}</p>
        {f'<ul class="look"><li class="lbl">On screen, look for:</li>{looks}</ul>' if looks else ''}
        <figure>{visual}<figcaption><code>{html.escape(step.path)}</code></figcaption></figure>
      </section>""")

    rows = "".join(
        f"<tr><td><code>{html.escape(k)}</code></td><td class='num'>{v}</td>"
        f"<td>{'raises an alert' if k.startswith('SUSPICIOUS_') else 'recorded, not queued'}</td></tr>"
        for k, v in interesting.items())

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Product walkthrough — Authorised Log Analytics</title>
<style>
 :root {{ --ink:#15181d; --soft:#5b6472; --line:#dfe3e9; --bg:#f6f7f9;
          --panel:#fff; --accent:#1b4d8f; --warn-bg:#fdf2dc; --warn:#7a5310;
          --mono: ui-monospace, SFMono-Regular, Consolas, monospace; }}
 * {{ box-sizing:border-box; }}
 body {{ margin:0; background:var(--bg); color:var(--ink);
         font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }}
 .wrap {{ max-width:1000px; margin:0 auto; padding:32px 20px 64px; }}
 h1 {{ font-size:28px; margin:0 0 6px; }}
 .sub {{ color:var(--soft); margin:0 0 20px; }}
 .banner {{ background:var(--warn-bg); color:var(--warn); padding:12px 16px;
            border-radius:6px; font-weight:550; margin:16px 0; }}
 .note {{ background:var(--panel); border:1px solid var(--line);
          border-left:4px solid var(--accent); border-radius:6px;
          padding:14px 16px; margin:16px 0; }}
 .frame {{ background:var(--panel); border:1px solid var(--line);
           border-radius:8px; padding:20px; margin:22px 0; }}
 .frame h2 {{ margin:0 0 8px; font-size:19px; }}
 .say {{ margin:0 0 12px; }}
 ul.look {{ margin:0 0 14px; padding-left:18px; color:var(--soft);
            font-size:14px; }}
 ul.look .lbl {{ list-style:none; margin-left:-18px; font-weight:600; }}
 figure {{ margin:0; }}
 figure img {{ width:100%; border:1px solid var(--line); border-radius:6px;
               display:block; }}
 figcaption {{ color:var(--soft); font-size:13px; margin-top:6px; }}
 .nofig {{ color:var(--soft); font-style:italic; }}
 table {{ width:100%; border-collapse:collapse; background:var(--panel);
          border:1px solid var(--line); border-radius:6px; overflow:hidden; }}
 th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }}
 th {{ background:var(--bg); font-size:12px; text-transform:uppercase;
       letter-spacing:.03em; color:var(--soft); }}
 td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
 code {{ font-family:var(--mono); font-size:.92em; }}
 footer {{ color:var(--soft); font-size:13px; margin-top:28px;
           border-top:1px solid var(--line); padding-top:14px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Authorised Log Analytics — product walkthrough</h1>
  <p class="sub">Generated by <code>scripts/demo_walkthrough.py</code>.
     Every screenshot is a render of a page the application actually served.</p>

  <p class="banner">Alerts indicate suspicious behavioural patterns and require
     analyst review. They are not confirmation of compromise.</p>

  <div class="note">
    <strong>What this run analysed.</strong> The repository's Zeek
    <em>test fixture</em> — synthetic traffic from the test suite, not a real
    capture. It produced {outcome.windows} device-window(s) from
    {outcome.devices} device(s), and
    <strong>{outcome.alerts_created}</strong> alert(s) after deduplication.
    No accuracy is claimed here and no model was used; detection is the
    transparent rule baseline.
  </div>

  {f'<table><thead><tr><th>Verdict</th><th class="num">Windows</th><th>Queued?</th></tr></thead><tbody>{rows}</tbody></table>' if rows else ''}

  <div class="note">
    <strong>The point of the walkthrough.</strong> Watch for the windows the
    product declines to judge. A rule whose feature is missing does not fire, so
    a detector that only counts fired rules reports an unmeasurable device and a
    genuinely quiet one identically — and calls both benign. This one reports
    <code>INSUFFICIENT_TELEMETRY</code> instead, with the reason attached.
  </div>
{''.join(frames)}
  <footer>
    Rule-based detection; not ML-validated. ·
    {shot_count} of {len(steps)} frames captured ·
    Local-only deployment; no outbound network calls.
  </footer>
</div>
</body>
</html>
"""


# ===========================================================================
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a visual walkthrough of the product from a real "
                    "run. Uses a temporary database and leaves your "
                    "deployment untouched.")
    parser.add_argument("--out", default="results/walkthrough",
                        help="output directory (default: results/walkthrough)")
    parser.add_argument("--open", action="store_true", dest="open_after",
                        help="open the page when it is finished")
    parser.add_argument("--keep-html", action="store_true",
                        help="also write each page's markup next to the page")
    args = parser.parse_args(argv)

    out_dir = (ROOT / args.out) if not Path(args.out).is_absolute() \
        else Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    tmp = Path(tempfile.mkdtemp(prefix="als_walkthrough_"))
    try:
        print("building a temporary deployment...")
        app, outcome = build_environment(tmp)
        if not outcome.ok:
            raise SystemExit(f"the demo ingest failed: {outcome.error}")
        print(f"  ingested {outcome.windows} window(s), "
              f"{outcome.alerts_created} alert(s) raised")

        print("driving the application through the walkthrough...")
        capture_pages(app, STEPS)
        inline_assets(app, STEPS)

        browser = find_browser()
        shots = 0
        if browser:
            print(f"rendering screenshots with {Path(browser).name}...")
            shots = shoot(browser, STEPS, tmp)
            print(f"  captured {shots}/{len(STEPS)}")
        else:
            print("no headless browser found — building the page without "
                  "screenshots")

        page = out_dir / "walkthrough.html"
        page.write_text(render_walkthrough(STEPS, outcome, shot_count=shots),
                        encoding="utf-8")
        print(f"\nwalkthrough -> {page}")

        if args.keep_html:
            for step in STEPS:
                (out_dir / f"{step.key}.html").write_text(step.html_text,
                                                          encoding="utf-8")
            print(f"page markup -> {out_dir}")

        if args.open_after:
            _open(page)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _open(path: Path) -> None:
    """Open the finished page in the desktop's default browser."""
    try:
        if sys.platform == "win32":
            os.startfile(str(path))          # noqa: S606 - a local file
        else:
            subprocess.run(
                ["open" if sys.platform == "darwin" else "xdg-open", str(path)],
                check=False)
    except OSError:
        print("(could not open it automatically)")


if __name__ == "__main__":
    sys.exit(main())
