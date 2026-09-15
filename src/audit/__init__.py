"""
audit — the append-only security audit trail.

    from src.audit import AuditLog
    from src.audit import events   # action-string constants

``AuditLog`` records each security-relevant action as a durable row plus a
structured log line, and exposes only append + read — never update or delete.
"""
from __future__ import annotations

from . import events
from .events import AuditLog

__all__ = ["AuditLog", "events"]
