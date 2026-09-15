"""
scripts/run_server.py — start the local dashboard.

    python -m scripts.run_server
    python -m scripts.run_server --port 8123
    python -m scripts.run_server --check       # preflight only, do not serve

A THIN WRAPPER, ON PURPOSE
    The real entrypoint is :mod:`src.api.server`, which is also what
    ``uvicorn src.api.app:app`` reaches. This script exists so the four
    operator commands sit together in ``scripts/`` and are discoverable as a
    set — ``init_db``, ``create_user``, ``ingest_file``, ``run_server`` — not
    because it adds behaviour.

BEFORE IT SERVES
    It reports whether the database exists and whether the session-signing
    secret comes from the environment. Both are things that otherwise surface
    later as "the login is broken": an unset secret means a new random signing
    key on every restart, which invalidates every session silently.

THE BIND
    127.0.0.1 by default. A non-loopback host requires an explicit
    acknowledgement flag, because this product ships no TLS and no reverse
    proxy — see src/api/server.py for the reasoning.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.api import server as S                                # noqa: E402
from src.config import load_config                             # noqa: E402


def preflight_report(cfg, *, host: str, port: int,
                     accept_exposure: bool = False) -> int:
    """Print what an operator needs to know before serving. 0 if ready.

    Reports the host and port that will ACTUALLY be used, not the configured
    defaults: an operator running ``--check --host 0.0.0.0`` is asking about
    that bind, and showing them 127.0.0.1 would answer a different question.
    """
    db_path = (ROOT / str(cfg.storage.sqlite_path)).resolve()
    secret_env = str(cfg.auth.session_secret_env)
    has_secret = bool(os.environ.get(secret_env, ""))
    loopback = S.is_loopback(host)

    print(f"product         {cfg.product.name}")
    print(f"bind            http://{host}:{port}"
          f"{'  (local only)' if loopback else '  ** REACHABLE OFF-HOST **'}")
    print(f"database        {db_path}")
    print(f"  exists        {'yes' if db_path.exists() else 'NO'}")
    print(f"session secret  {secret_env}")
    print(f"  from env      {'yes' if has_secret else 'NO (ephemeral)'}")
    print(f"cookie secure   {bool(cfg.auth.cookie_secure)}")
    print(f"input dir       {ROOT / str(cfg.product.input_dir)}")
    print(f"upload cap      {int(cfg.api.max_upload_bytes) // (1024 * 1024)} MiB")
    print(f"detection mode  {cfg.detection.mode}")

    ready = 0
    if not db_path.exists():
        print("\n  The database does not exist. Run:")
        print("    python -m scripts.init_db")
        ready = 1
    if not loopback and not accept_exposure:
        print(f"\n  {host} is not a loopback address, and this product ships "
              "no TLS.\n  Starting will be refused unless you pass:")
        print(f"    {S.EXPOSE_FLAG}")
        ready = 1
    if not has_secret:
        print(f"\n  {secret_env} is not set. Sessions will not survive a "
              "restart.\n  Set it before any real use, for example:")
        print(f'    export {secret_env}="$(python -c '
              "\"import secrets;print(secrets.token_urlsafe(48))\")\"")
    return ready


def main(argv=None) -> int:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        description="Start the local Authorised Log Analytics dashboard.",
        add_help=True)
    parser.add_argument("--host", default=str(cfg.api.host))
    parser.add_argument("--port", type=int, default=int(cfg.api.port))
    parser.add_argument("--reload", action="store_true",
                        help="auto-reload on source changes (development only)")
    parser.add_argument("--check", action="store_true",
                        help="run the preflight checks and exit")
    parser.add_argument(S.EXPOSE_FLAG, dest="accept_exposure",
                        action="store_true",
                        help="acknowledge binding a non-loopback address")
    args = parser.parse_args(argv)

    status = preflight_report(cfg, host=args.host, port=args.port,
                              accept_exposure=args.accept_exposure)
    if args.check:
        return status
    if status:
        print("\nrefusing to start — see the preflight output above",
              file=sys.stderr)
        return status

    forwarded = ["--host", args.host, "--port", str(args.port)]
    if args.reload:
        forwarded.append("--reload")
    if args.accept_exposure:
        forwarded.append(S.EXPOSE_FLAG)
    print()
    return S.main(forwarded)


if __name__ == "__main__":
    sys.exit(main())
