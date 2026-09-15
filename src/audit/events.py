"""
audit.events — the append-only audit trail.

Every security-relevant action (login, upload, ingest, detection run, alert
status change, feedback, user management, data purge) is recorded two ways: a
durable row in ``audit_events`` via the storage repository, and a structured
line on the ``als.audit`` logger. The row is the tamper-evident record; the log
line is for live operational visibility.

"Append-only" is structural, not a convention: :class:`AuditLog` exposes
``record`` and reads, and there is deliberately no update or delete method — and
the underlying :class:`~src.storage.repository.AuditRepo` has none either. There
is no code path through which an audit entry can be altered or removed.

Callers must not place secrets (passwords, session tokens, signing keys) in
``detail``; the audit trail is not an appropriate sink for them.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from ..storage.repository import Repository

_log = logging.getLogger("als.audit")

# Action vocabulary — dotted, stable strings (stored verbatim, filtered on in
# the audit view). Keep new actions here so the set is discoverable in one place.
LOGIN = "auth.login"
LOGIN_FAILED = "auth.login_failed"
LOGOUT = "auth.logout"

USER_CREATE = "user.create"
USER_DISABLE = "user.disable"
USER_ENABLE = "user.enable"
USER_PASSWORD_CHANGE = "user.password_change"

FILE_UPLOAD = "file.upload"
INGEST_START = "ingest.start"
INGEST_SUCCEED = "ingest.succeed"
INGEST_FAIL = "ingest.fail"

DETECTION_RUN = "detection.run"
ALERT_STATUS = "alert.status"
ALERT_FEEDBACK = "alert.feedback"

DATA_PURGE = "data.purge"


def _actor_fields(actor: Any) -> tuple[int | None, str | None]:
    """Pull ``(user_id, username)`` from a Session (user_id/username) or a User
    (id/username) or anything with those attributes; ``(None, None)`` for a
    system/anonymous actor."""
    if actor is None:
        return None, None
    uid = getattr(actor, "user_id", None)
    if uid is None:
        uid = getattr(actor, "id", None)
    return uid, getattr(actor, "username", None)


class AuditLog:
    """Bound to a ``Repository`` (a live connection) so an audit write commits in
    the same transaction as the action it records."""

    def __init__(self, repo: Repository, logger: logging.Logger | None = None):
        self.repo = repo
        self._log = logger or _log

    def record(self, action: str, *, actor: Any = None,
               actor_user_id: int | None = None,
               actor_username: str | None = None,
               target_type: str | None = None, target_id: Any = None,
               request_id: str | None = None,
               detail: dict | None = None, created_at: str) -> int:
        if actor is not None:
            aid, aname = _actor_fields(actor)
            actor_user_id = actor_user_id if actor_user_id is not None else aid
            actor_username = (actor_username if actor_username is not None
                              else aname)
        detail_json = (json.dumps(detail, sort_keys=True, default=str)
                       if detail is not None else None)
        target_id_str = None if target_id is None else str(target_id)
        event_id = self.repo.audit.append(
            action=action, actor_user_id=actor_user_id,
            actor_username=actor_username, target_type=target_type,
            target_id=target_id_str, request_id=request_id,
            detail_json=detail_json, created_at=created_at)
        self._log.info(
            "audit action=%s actor=%s target=%s/%s req=%s",
            action, actor_username or "-", target_type or "-",
            target_id_str or "-", request_id or "-")
        return event_id

    def recent(self, limit: int = 100, offset: int = 0):
        return self.repo.audit.recent(limit=limit, offset=offset)

    def count(self) -> int:
        return self.repo.audit.count()
