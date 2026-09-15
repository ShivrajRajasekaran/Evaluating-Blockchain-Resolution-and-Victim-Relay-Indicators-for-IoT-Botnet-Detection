"""
scripts/share_local.py — put the local dashboard behind a temporary public URL.

    python -m scripts.share_local --check          # preflight only, no tunnel
    python -m scripts.share_local --i-accept-the-risk-of-publishing-this-instance

WHAT IT DOES
    Starts the product on 127.0.0.1 (as always) and runs `cloudflared tunnel`
    alongside it. Cloudflare opens an OUTBOUND connection from this machine and
    hands back an ``https://<random>.trycloudflare.com`` address that forwards
    to it. Your machine opens no inbound port and needs no firewall change; the
    URL dies when you stop the process.

WHY IT IS THE ONLY HOSTING PATH THAT IS TRULY "LIKE LOCALHOST"
    Because it IS localhost. Same process, same SQLite file, same speed, same
    data. There is no deploy step, no ephemeral disk, and nothing to drift out
    of sync with what you tested. The cost is that it lives only while this
    command runs.

WHY IT DEMANDS AN EXPLICIT FLAG
    The same reason the server refuses a non-loopback bind without one. This
    product reads an organisation's network telemetry and stores alerts about
    its devices, and it ships no TLS, no reverse proxy and no IP allowlist of
    its own. Publishing it is a decision, and a decision should take a
    different keystroke from an accident.

THE PREFLIGHT IS THE POINT
    Before anything is published this checks the things that actually get
    people burned: a weak or well-known admin password, real captures sitting
    in the database, and a missing session secret. It refuses on the first two
    unless you override them deliberately.

CONTAINMENT NOTE
    This script is the one place in the repository that deliberately arranges
    inbound public access, which is why it lives in scripts/ and not in src/.
    The product tree itself still contains no network primitive at all — see
    tests/test_containment_outbound.py. Nothing here changes that: cloudflared
    is a separate process, and the application still only ever binds loopback.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import load_config                             # noqa: E402

ACCEPT_FLAG = "--i-accept-the-risk-of-publishing-this-instance"

# Passwords that must never be reachable from the public internet. The first is
# what the local setup guide uses, so it is the one most likely to still be set.
#
# Password verification is case-SENSITIVE, so a lowercase list silently matches
# nothing — the first version of this check missed the very password it was
# written for. Each candidate is therefore expanded into the case variants a
# person actually types.
_WEAK_SEEDS = (
    "ChangeMe-Local-2026", "changeme", "password", "admin", "demo",
    "walkthrough-demo-password", "correct-horse-battery-staple",
    "demo-password-1234", "Password123", "letmein",
)


def _weak_candidates() -> set[str]:
    out: set[str] = set()
    for seed in _WEAK_SEEDS:
        out.update({seed, seed.lower(), seed.upper(), seed.capitalize()})
    return out


_WEAK = _weak_candidates()

# Captures that came with the repository. Anything else in uploaded_files is
# telemetry the operator brought, and is treated as real.
_FIXTURES = {"sample-conn.log", "conn.log.labeled.sample"}

_URL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def find_cloudflared() -> str | None:
    found = shutil.which("cloudflared")
    if found:
        return found
    for candidate in (
            r"C:\Program Files (x86)\cloudflared\cloudflared.exe",
            r"C:\Program Files\cloudflared\cloudflared.exe",
            "/usr/local/bin/cloudflared", "/usr/bin/cloudflared"):
        if Path(candidate).exists():
            return candidate
    return None


# ===========================================================================
# Preflight
# ===========================================================================
def preflight(cfg, *, force: bool) -> list[str]:
    """Everything that should stop you. Returns the blocking problems."""
    from src.auth.passwords import verify_password
    from src.storage import Database, Repository

    blocking: list[str] = []
    db_path = (ROOT / str(cfg.storage.sqlite_path)).resolve()

    print(f"database        {db_path}")
    if not db_path.exists():
        blocking.append("the database does not exist — run "
                        "`python -m scripts.init_db` first")
        return blocking

    db = Database(db_path)
    with db.connection() as conn:
        repo = Repository(conn)
        users = repo.users.all()
        devices = repo.devices.count()
        alerts = repo.alerts.count()
        uploads = [r["original_filename"] for r in repo.files.recent(limit=50)]

    # --- 1. accounts -----------------------------------------------------
    print(f"accounts        {len(users)}")
    if not users:
        blocking.append("no accounts exist — nobody could sign in")
    weak = []
    for user in users:
        if not user.is_active:
            continue
        for guess in _WEAK:
            if verify_password(guess, user.password_hash, user.password_salt,
                               user.iterations):
                weak.append((user.username, guess))
                break
    for username, guess in weak:
        print(f"  {username:<14} *** WEAK PASSWORD ({guess!r}) ***")
    if weak and not force:
        blocking.append(
            f"{len(weak)} account(s) use a well-known password. Change them "
            "first:\n      python -m scripts.create_user --username "
            f"{weak[0][0]} --set-password")

    # --- 2. real telemetry ----------------------------------------------
    real = [f for f in uploads if f not in _FIXTURES]
    print(f"devices         {devices}")
    print(f"alerts          {alerts}")
    print(f"captures        {len(uploads)}"
          + (f"  ({len(real)} look like REAL telemetry)" if real else ""))
    for name in real:
        print(f"  {name}  <- your own capture")
    if real and not force:
        blocking.append(
            "this database holds real captures and alerts about real devices. "
            "Publishing puts that behind one login form on the open internet.\n"
            "      Demo from a clean database instead:\n"
            "        move data\\product\\app.db aside, then init_db + "
            "create_user + ingest the sample fixture")

    # --- 3. session secret ----------------------------------------------
    secret_env = str(cfg.auth.session_secret_env)
    has_secret = bool(os.environ.get(secret_env, ""))
    print(f"session secret  {'set' if has_secret else 'NOT SET'}")
    if not has_secret:
        print("  an ephemeral key will be used; everyone is signed out on "
              "restart (not blocking)")

    # --- 4. advisory ------------------------------------------------------
    if not bool(cfg.auth.cookie_secure):
        print("cookie_secure   false — fine here: the browser reaches "
              "Cloudflare over HTTPS,\n"
              "                and Cloudflare reaches this app over loopback")
    return blocking


# ===========================================================================
# Running
# ===========================================================================
def stream(proc, prefix: str, url_box: list[str]) -> None:
    """Echo a child's output, watching for the public URL."""
    for raw in iter(proc.stdout.readline, ""):
        line = raw.rstrip()
        if not line:
            continue
        match = _URL_RE.search(line)
        if match and not url_box:
            url_box.append(match.group(0))
        if prefix == "tunnel" and not match:
            # cloudflared is chatty; keep only what an operator would act on.
            if not re.search(r"ERR|error|failed|Thank you", line):
                continue
        print(f"  [{prefix}] {line}")


def main(argv=None) -> int:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        description="Publish the local dashboard on a temporary Cloudflare "
                    "URL. Your machine opens no inbound port.")
    parser.add_argument("--port", type=int, default=int(cfg.api.port))
    parser.add_argument("--check", action="store_true",
                        help="run the preflight and exit without publishing")
    parser.add_argument("--force", action="store_true",
                        help="proceed despite weak passwords or real data "
                             "(you are on your own)")
    parser.add_argument(ACCEPT_FLAG, dest="accepted", action="store_true",
                        help="acknowledge that this instance becomes reachable "
                             "from the public internet")
    args = parser.parse_args(argv)

    print("=" * 66)
    print("PREFLIGHT")
    print("=" * 66)
    blocking = preflight(cfg, force=args.force)

    if blocking:
        print("\n" + "=" * 66)
        print("REFUSING TO PUBLISH")
        print("=" * 66)
        for problem in blocking:
            print(f"  * {problem}")
        print("\n  Override with --force once you have read the above.")
        return 1

    print("\n  preflight clean")
    if args.check:
        print("\n(--check: nothing was published)")
        return 0

    if not args.accepted:
        print(f"\nThis will make the dashboard reachable from the internet.\n"
              f"If that is what you intend, re-run with:\n\n"
              f"  python -m scripts.share_local {ACCEPT_FLAG}\n")
        return 1

    tunnel_bin = find_cloudflared()
    if not tunnel_bin:
        print("\ncloudflared is not installed. Install it with:\n"
              "  winget install --id Cloudflare.cloudflared\n")
        return 2

    print("\n" + "=" * 66)
    print("PUBLISHING")
    print("=" * 66)

    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.api.app:app",
         "--host", "127.0.0.1", "--port", str(args.port)],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1)
    url_box: list[str] = []
    threading.Thread(target=stream, args=(server, "server", url_box),
                     daemon=True).start()
    time.sleep(3)

    tunnel = subprocess.Popen(
        [tunnel_bin, "tunnel", "--url", f"http://127.0.0.1:{args.port}"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    threading.Thread(target=stream, args=(tunnel, "tunnel", url_box),
                     daemon=True).start()

    for _ in range(60):
        if url_box:
            break
        time.sleep(0.5)

    if url_box:
        print("\n" + "=" * 66)
        print(f"  PUBLIC URL:  {url_box[0]}")
        print("=" * 66)
        print("  Anyone with this link reaches your login form.")
        print("  It stops existing the moment you press Ctrl+C.\n")
    else:
        print("\n  (the tunnel did not report a URL — see the output above)\n")

    try:
        tunnel.wait()
    except KeyboardInterrupt:
        print("\nshutting down...")
    finally:
        for proc in (tunnel, server):
            if proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGTERM)
                    proc.wait(timeout=10)
                except Exception:
                    proc.kill()
        print("the public URL is gone; the app is back to localhost only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
