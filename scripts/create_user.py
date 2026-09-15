"""
scripts/create_user.py — create an account, or change a password.

    python -m scripts.create_user --username alice --role Admin
    python -m scripts.create_user --username bob --role Analyst --password-stdin
    python -m scripts.create_user --username bob --set-password
    python -m scripts.create_user --list
    python -m scripts.create_user --username bob --disable

THE PASSWORD IS NEVER AN ARGUMENT
    There is no ``--password VALUE`` option, deliberately. A password on a
    command line lands in the shell history, in ``ps`` output, and in any
    process-accounting log — all of them readable by other users on the host.
    So the password is prompted for (hidden, and confirmed), or piped in with
    ``--password-stdin`` for a provisioning script.

WHAT IT COSTS, ON PURPOSE
    Hashing uses PBKDF2-HMAC-SHA256 at the configured iteration count (600,000
    by default). Creating a user therefore takes a noticeable moment. That cost
    is the point: it is the same cost an attacker pays per guess offline.

EVERY ACTION IS AUDITED
    Account creation, password change, enable and disable all write an
    ``audit_events`` row with the operating user recorded as the actor where
    one is known, and "console" where the action came from this script.

CONTAINMENT
    Touches one local SQLite file. No network I/O, no email, no directory
    service.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.audit import events as A                              # noqa: E402
from src.auth import UserService                               # noqa: E402
from src.auth.passwords import (MIN_PASSWORD_LENGTH,           # noqa: E402
                                check_password_policy)
from src.config import load_config                             # noqa: E402
from src.storage import Database, Repository, utcnow_iso       # noqa: E402

CONSOLE_ACTOR = "console"


def read_password(*, from_stdin: bool, confirm: bool = True) -> str:
    """Obtain a password without it ever appearing in a process listing."""
    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            raise SystemExit("no password was supplied on stdin")
        return password
    password = getpass.getpass("Password: ")
    if confirm and password != getpass.getpass("Confirm password: "):
        raise SystemExit("the passwords did not match")
    return password


def service(repo, cfg) -> UserService:
    return UserService(repo, iterations=int(cfg.auth.pbkdf2_iterations),
                       salt_bytes=int(cfg.auth.salt_bytes))


def db_for(cfg, override: str | None) -> Database:
    path = (Path(override).expanduser().resolve() if override
            else (ROOT / str(cfg.storage.sqlite_path)).resolve())
    if not path.exists():
        raise SystemExit(
            f"{path} does not exist — run `python -m scripts.init_db` first")
    return Database(path)


def cmd_list(db) -> int:
    with db.connection() as conn:
        users = Repository(conn).users.all()
    if not users:
        print("no user accounts exist")
        return 0
    width = max(len(u.username) for u in users)
    print(f"{'USERNAME'.ljust(width)}  ROLE      ACTIVE  LAST LOGIN")
    for user in users:
        print(f"{user.username.ljust(width)}  {user.role:<8}  "
              f"{'yes' if user.is_active else 'no ':<6}  "
              f"{user.last_login_at or 'never'}")
    return 0


def cmd_create(db, cfg, args) -> int:
    password = read_password(from_stdin=args.password_stdin)
    check_password_policy(password)     # fail before the expensive hash
    now = utcnow_iso()
    with db.transaction() as conn:
        repo = Repository(conn)
        if repo.users.by_username(args.username) is not None:
            raise SystemExit(
                f"user {args.username!r} already exists; use --set-password to "
                "change their password")
        print(f"hashing with {cfg.auth.pbkdf2_iterations:,} PBKDF2 "
              "iterations...")
        user_id = service(repo, cfg).create_user(
            username=args.username, password=password, role_name=args.role,
            created_at=now)
        A.AuditLog(repo).record(
            A.USER_CREATE, actor_username=CONSOLE_ACTOR, target_type="user",
            target_id=user_id, created_at=now,
            detail={"username": args.username, "role": args.role})
    print(f"created {args.username!r} with role {args.role}")
    return 0


def cmd_set_password(db, cfg, args) -> int:
    password = read_password(from_stdin=args.password_stdin)
    check_password_policy(password)
    now = utcnow_iso()
    with db.transaction() as conn:
        repo = Repository(conn)
        user = _require_user(repo, args.username)
        service(repo, cfg).set_password(user.id, password)
        A.AuditLog(repo).record(
            A.USER_PASSWORD_CHANGE, actor_username=CONSOLE_ACTOR,
            target_type="user", target_id=user.id, created_at=now,
            detail={"username": args.username})
    print(f"password changed for {args.username!r}")
    return 0


def cmd_set_active(db, cfg, args, *, active: bool) -> int:
    now = utcnow_iso()
    with db.transaction() as conn:
        repo = Repository(conn)
        user = _require_user(repo, args.username)
        service(repo, cfg).set_active(user.id, active)
        A.AuditLog(repo).record(
            A.USER_ENABLE if active else A.USER_DISABLE,
            actor_username=CONSOLE_ACTOR, target_type="user",
            target_id=user.id, created_at=now,
            detail={"username": args.username})
    print(f"{args.username!r} is now {'enabled' if active else 'disabled'}")
    return 0


def _require_user(repo, username: str):
    user = repo.users.by_username(username)
    if user is None:
        raise SystemExit(f"no such user: {username!r}")
    return user


def main(argv=None) -> int:
    cfg = load_config()
    roles = list(cfg.auth.roles)
    parser = argparse.ArgumentParser(
        description="Manage local product accounts. The password is prompted "
                    "for or read from stdin — never passed as an argument.")
    parser.add_argument("--db", default=None)
    parser.add_argument("--username")
    parser.add_argument("--role", choices=roles, default="Viewer")
    parser.add_argument("--password-stdin", action="store_true",
                        help="read the password from stdin (for provisioning)")
    parser.add_argument("--set-password", action="store_true",
                        help="change an existing user's password")
    parser.add_argument("--disable", action="store_true")
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)

    db = db_for(cfg, args.db)

    if args.list:
        return cmd_list(db)
    if not args.username:
        parser.error("--username is required (or use --list)")
    if args.disable:
        return cmd_set_active(db, cfg, args, active=False)
    if args.enable:
        return cmd_set_active(db, cfg, args, active=True)
    if args.set_password:
        return cmd_set_password(db, cfg, args)

    print(f"Creating {args.username!r} with role {args.role}. "
          f"Minimum password length {MIN_PASSWORD_LENGTH}.")
    return cmd_create(db, cfg, args)


if __name__ == "__main__":
    sys.exit(main())
