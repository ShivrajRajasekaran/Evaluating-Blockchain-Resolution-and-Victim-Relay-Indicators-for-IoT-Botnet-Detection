"""
api/server.py — run the dashboard locally.

    python -m src.api.server                    # 127.0.0.1:8000 from config
    python -m src.api.server --port 8123
    python -m src.api.server --host 0.0.0.0     # refused without --i-accept-...

THE BIND IS THE SECURITY BOUNDARY
    This product reads an organisation's network telemetry and stores alerts
    about its devices. On loopback, the operating system is the access control.
    On 0.0.0.0 it is whatever is in front of the port — and by default there is
    nothing in front of it, because the product has no TLS, no reverse proxy and
    no IP allowlist of its own.

    So a non-loopback host requires an explicit acknowledgement flag. Not
    because the code cannot do it, but because "I typed --host 0.0.0.0 to make
    it reachable from my laptop" and "I have decided to expose this service"
    should not be the same keystroke.

STARTUP CHECKS
    The database must exist and be migrated (run ``scripts/init_db.py`` first),
    and the session secret should come from the environment. Both are reported
    at startup rather than surfacing later as "the login is broken".
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import sys
from pathlib import Path

from src.config import ROOT, load_config

_log = logging.getLogger("als.server")

EXPOSE_FLAG = "--i-accept-the-risk-of-exposing-this-service"


def is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def configure_logging(cfg) -> None:
    level = getattr(logging, str(cfg.api.log.level).upper(), logging.INFO)
    logging.basicConfig(
        level=level, stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s")


def preflight(cfg, db_path: Path) -> list[str]:
    """Warnings worth printing before the first request, not after."""
    import os

    problems: list[str] = []
    if not db_path.exists():
        problems.append(
            f"the database {db_path} does not exist — run "
            "`python -m scripts.init_db` first")
    if not os.environ.get(str(cfg.auth.session_secret_env), ""):
        problems.append(
            f"{cfg.auth.session_secret_env} is not set — an ephemeral signing "
            "key will be used and every session will be invalidated on restart")
    return problems


def main(argv=None) -> int:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        description="Run the Authorised Log Analytics dashboard locally. "
                    "Binds 127.0.0.1 by default and makes no outbound "
                    "connections.")
    parser.add_argument("--host", default=str(cfg.api.host))
    parser.add_argument("--port", type=int, default=int(cfg.api.port))
    parser.add_argument("--reload", action="store_true",
                        help="auto-reload on source changes (development only)")
    parser.add_argument(
        EXPOSE_FLAG, dest="accept_exposure", action="store_true",
        help="acknowledge binding to a non-loopback address. The product has "
             "no TLS and no reverse proxy of its own; anything that can reach "
             "the port can reach the login form.")
    args = parser.parse_args(argv)

    configure_logging(cfg)

    if not is_loopback(args.host) and not args.accept_exposure:
        parser.error(
            f"--host {args.host} is not a loopback address. This product is "
            "designed for local-only operation and ships no TLS. If you have "
            f"decided to expose it anyway, pass {EXPOSE_FLAG}.")

    db_path = ROOT / str(cfg.storage.sqlite_path)
    for problem in preflight(cfg, db_path):
        _log.warning("%s", problem)

    try:
        import uvicorn
    except ImportError:       # pragma: no cover - uvicorn is a declared dep
        print("uvicorn is not installed; install it or run the app with "
              "another ASGI server.", file=sys.stderr)
        return 2

    if not is_loopback(args.host):
        _log.warning("binding %s:%s — this service is reachable off-host",
                     args.host, args.port)
    else:
        _log.info("serving on http://%s:%s (local only)", args.host, args.port)

    uvicorn.run("src.api.app:app", host=args.host, port=args.port,
                reload=args.reload, log_level=str(cfg.api.log.level).lower())
    return 0


if __name__ == "__main__":
    sys.exit(main())
