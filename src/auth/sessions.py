"""
auth.sessions — signed, time-limited session tokens (itsdangerous).

A session is a tiny signed payload (user id, username, role) carried in an
``HttpOnly`` cookie. There is no server-side session store: the signature proves
authenticity and the embedded timestamp bounds the lifetime, so a stolen cookie
expires and a tampered cookie fails to verify. This is the standard signed-cookie
pattern — no JWT library, no database round-trip per request.

The signing secret is read from the environment (never the config file or
source). :func:`resolve_session_secret` returns a per-process ephemeral secret
when the env var is unset, so a dev instance still runs — but sessions do not
survive a restart, and the API logs a warning. Production must set the env var.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from itsdangerous import (BadSignature, SignatureExpired,
                          URLSafeTimedSerializer)

# Namespacing salt for the serializer — not a secret, just domain separation so
# a token for this purpose can never validate for another itsdangerous use.
_SALT = "als.session.v1"

# Below this the signing secret is too weak to bother with.
_MIN_SECRET_LEN = 16


@dataclass(frozen=True)
class Session:
    user_id: int
    username: str
    role: str


def resolve_session_secret(env_name: str) -> tuple[str, bool]:
    """Return ``(secret, from_env)``. When the env var is missing or too short a
    random ephemeral secret is generated (dev convenience) and ``from_env`` is
    False so the caller can warn."""
    val = os.environ.get(env_name, "")
    if val and len(val) >= _MIN_SECRET_LEN:
        return val, True
    return secrets.token_urlsafe(48), False


class SessionManager:
    def __init__(self, secret: str, *, max_age: int = 28800,
                 cookie_name: str = "als_session", secure: bool = False):
        if not secret or len(secret) < _MIN_SECRET_LEN:
            raise ValueError(
                f"session secret must be at least {_MIN_SECRET_LEN} characters")
        self._serializer = URLSafeTimedSerializer(secret, salt=_SALT)
        self.max_age = int(max_age)
        self.cookie_name = cookie_name
        self.secure = bool(secure)

    def issue(self, session: Session) -> str:
        return self._serializer.dumps(
            {"uid": session.user_id, "u": session.username, "r": session.role})

    def read(self, token: str | None) -> Session | None:
        """Return the Session if the token is authentic and unexpired, else
        None. Never raises on a bad token — an attacker-supplied cookie is just
        an anonymous request."""
        if not token:
            return None
        try:
            data = self._serializer.loads(token, max_age=self.max_age)
        except (BadSignature, SignatureExpired):
            return None
        try:
            return Session(user_id=int(data["uid"]), username=data["u"],
                           role=data["r"])
        except (KeyError, TypeError, ValueError):
            return None

    def set_cookie_kwargs(self) -> dict:
        """Keyword args for Starlette's ``response.set_cookie`` — HttpOnly and
        SameSite=Lax always; Secure follows config (off for local http dev)."""
        return {
            "key": self.cookie_name,
            "max_age": self.max_age,
            "httponly": True,
            "samesite": "lax",
            "secure": self.secure,
            "path": "/",
        }
