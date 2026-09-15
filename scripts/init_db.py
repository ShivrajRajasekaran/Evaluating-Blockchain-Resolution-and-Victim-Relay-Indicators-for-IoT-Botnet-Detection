"""
scripts/init_db.py — create or upgrade the product database.

    python -m scripts.init_db
    python -m scripts.init_db --db /path/to/app.db
    python -m scripts.init_db --check          # report, change nothing

SAFE TO RUN REPEATEDLY
    Migrations are tracked in ``schema_migrations`` and applied once; role
    seeding uses INSERT OR IGNORE. Running this after every deployment is the
    intended workflow, and a second run reports "already current" rather than
    doing anything.

WHAT IT CREATES
    The 13 domain tables, the three roles (Admin / Analyst / Viewer), and the
    pseudonymisation salt. The salt is generated once and then never changes:
    it is what makes a device pseudonym stable across ingests, so regenerating
    it would silently split one device's history into two.

    It creates NO user. There is no default administrator and no default
    password — an account exists only because an operator ran
    ``scripts/create_user.py``. A shipped default credential is a backdoor
    whether or not anyone intended it as one.

CONTAINMENT
    Touches one local SQLite file. No network I/O.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import load_config                             # noqa: E402
from src.storage import Database, Repository, migrate          # noqa: E402
from src.storage.migrate import DEFAULT_ROLES                  # noqa: E402


def resolve_db_path(cfg, override: str | None) -> Path:
    if override:
        return Path(override).expanduser().resolve()
    return (ROOT / str(cfg.storage.sqlite_path)).resolve()


def describe(db: Database) -> dict:
    """What currently exists, for --check and for the closing summary."""
    with db.connection() as conn:
        repo = Repository(conn)
        version = conn.execute(
            "SELECT MAX(version) AS v FROM schema_migrations").fetchone()["v"]
        return {
            "schema_version": version,
            "roles": [r.name for r in repo.roles.all()],
            "users": repo.users.count(),
            "devices": repo.devices.count(),
            "alerts": repo.alerts.count(),
            "audit_events": repo.audit.count(),
        }


def main(argv=None) -> int:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        description="Create or upgrade the local product database. Safe to run "
                    "repeatedly; creates no user account.")
    parser.add_argument("--db", default=None,
                        help="database path (default: storage.sqlite_path)")
    parser.add_argument("--check", action="store_true",
                        help="report the current state and exit without "
                             "applying anything")
    args = parser.parse_args(argv)

    path = resolve_db_path(cfg, args.db)

    if args.check:
        if not path.exists():
            print(f"{path} does not exist — run without --check to create it.")
            return 1
        state = describe(Database(path))
        print(f"database        {path}")
        print(f"  schema        v{state['schema_version']}")
        print(f"  roles         {', '.join(state['roles'])}")
        print(f"  users         {state['users']}")
        print(f"  devices       {state['devices']}")
        print(f"  alerts        {state['alerts']}")
        print(f"  audit events  {state['audit_events']}")
        if state["users"] == 0:
            print("\n  No users yet. Create one with:")
            print("    python -m scripts.create_user --username <name> "
                  "--role Admin")
        return 0

    existed = path.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = Database(path)
    applied = migrate(db)
    state = describe(db)

    print(f"database        {path}")
    print(f"  {'opened' if existed else 'created'}")
    if applied:
        print(f"  applied       {applied} migration"
              f"{'' if applied == 1 else 's'} -> schema v{state['schema_version']}")
    else:
        print(f"  already current at schema v{state['schema_version']}")
    print(f"  roles         {', '.join(state['roles'])} "
          f"({len(DEFAULT_ROLES)} seeded)")
    print(f"  users         {state['users']}")

    if state["users"] == 0:
        print("\nNo user accounts exist. This product ships no default "
              "credential.\nCreate the first administrator with:\n"
              "  python -m scripts.create_user --username <name> --role Admin")
    return 0


if __name__ == "__main__":
    sys.exit(main())
