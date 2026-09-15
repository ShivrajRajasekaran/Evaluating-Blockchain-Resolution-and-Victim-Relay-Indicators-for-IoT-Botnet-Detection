"""
storage.db — the SQLite connection factory and transaction scope.

One connection per unit of work, opened and closed by a context manager, rather
than a long-lived shared connection. At this scale that costs nothing and buys
two things: a SQLite connection never crosses the thread it was created on (so
the product is safe under Starlette's threadpool), and a failed request can
never leak an open transaction into the next one.

Timestamps come from :func:`utcnow_iso`, never a database clock function, so a
stored row's provenance does not depend on the server's timezone.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


def utcnow_iso() -> str:
    """Current UTC instant as an ISO-8601 string, microseconds included so the
    text sorts in true chronological order."""
    return datetime.now(timezone.utc).isoformat()


class Database:
    """A SQLite database at a fixed path. Hands out configured connections."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _configure(self, conn: sqlite3.Connection) -> sqlite3.Connection:
        conn.row_factory = sqlite3.Row
        # Foreign keys are OFF by default in SQLite and must be re-enabled on
        # every connection, or the REFERENCES clauses in the schema are inert.
        conn.execute("PRAGMA foreign_keys = ON")
        # Wait rather than fail immediately if another connection holds a write
        # lock (matters once the server and a script touch the DB at once).
        conn.execute("PRAGMA busy_timeout = 5000")
        # WAL lets readers proceed during a write — the dashboard stays
        # responsive while an ingest is committing.
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def connect(self) -> sqlite3.Connection:
        """Open and configure a raw connection. Caller owns closing it."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path))
        return self._configure(conn)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """A write scope: commit on clean exit, roll back on any exception, and
        always close. Multi-table operations (an ingest writing job, devices,
        windows, features, run and alerts) run inside one of these so they are
        all-or-nothing."""
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """A read scope: no implicit commit, always closes. Use for queries."""
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()
