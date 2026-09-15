"""
storage.migrate — apply SQL migrations and seed a fresh install.

A migration is a numbered ``NNNN_*.sql`` file. The runner records each applied
version in ``schema_migrations`` and skips anything already applied, so calling
:func:`migrate` on an up-to-date database is a no-op — ``scripts/init_db.py`` can
be run repeatedly without harm.

Each migration file plus its version row is applied inside a *single*
transaction, so a migration is all-or-nothing even if the process is killed
mid-run. That is why the runner splits the file into statements itself rather
than using ``executescript`` (which force-commits before it starts).
"""
from __future__ import annotations

import secrets
from pathlib import Path

from .db import Database, utcnow_iso

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

# app_meta key holding the per-install device-pseudonymisation salt.
PSEUDONYM_SALT_KEY = "pseudonymisation_salt"

# Seeded on every install. The three-role model is fixed (Admin/Analyst/Viewer);
# adding a role is a code+migration change, not a runtime action, because RBAC
# checks are written against these names.
DEFAULT_ROLES: tuple[tuple[str, str], ...] = (
    ("Admin", "Full access: users, configuration, audit log, data purge."),
    ("Analyst", "Triage: review alerts, change status, record feedback."),
    ("Viewer", "Read-only: view alerts, devices, ingestion status."),
)


def _statements(sql: str) -> list[str]:
    """Split a migration file into executable statements.

    Full-line ``--`` comments and blank lines are dropped; a statement ends at a
    line whose code ends with ``;``. Inline ``-- ...`` comments are kept (SQLite
    understands them). This is deliberately simple and relies on the project's
    migration files never placing a ``;`` inside a string literal or comment.
    """
    statements: list[str] = []
    buf: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        buf.append(line)
        if stripped.endswith(";"):
            statements.append("\n".join(buf))
            buf = []
    if any(l.strip() for l in buf):
        statements.append("\n".join(buf))
    return statements


def _has_table(conn, name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (name,),
    ).fetchone()
    return row is not None


def _current_version(conn) -> int:
    if not _has_table(conn, "schema_migrations"):
        return 0
    row = conn.execute("SELECT MAX(version) AS v FROM schema_migrations").fetchone()
    return row["v"] or 0


def _migration_files() -> list[tuple[int, Path]]:
    files: list[tuple[int, Path]] = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        try:
            version = int(path.name.split("_", 1)[0])
        except ValueError:
            raise ValueError(f"migration filename must start NNNN_: {path.name}")
        files.append((version, path))
    return files


def _seed_roles(conn) -> None:
    for name, description in DEFAULT_ROLES:
        conn.execute(
            "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)",
            (name, description),
        )


def _seed_salt(conn) -> None:
    # INSERT OR IGNORE keeps the first salt forever: a later init must not
    # rotate it, or every existing device pseudonym would stop matching.
    conn.execute(
        "INSERT OR IGNORE INTO app_meta (key, value) VALUES (?, ?)",
        (PSEUDONYM_SALT_KEY, secrets.token_hex(32)),
    )


def migrate(db: Database) -> int:
    """Apply pending migrations and seed roles + salt. Returns the number of
    migrations applied (0 when already current)."""
    applied = 0
    with db.transaction() as conn:
        current = _current_version(conn)
        for version, path in _migration_files():
            if version <= current:
                continue
            for statement in _statements(path.read_text(encoding="utf-8")):
                conn.execute(statement)
            conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) "
                "VALUES (?, ?)",
                (version, utcnow_iso()),
            )
            applied += 1
        _seed_roles(conn)
        _seed_salt(conn)
    return applied
