"""
auth — authentication, sessions, and role-based access control.

    from src.auth import (hash_password, verify_password, UserService,
                          SessionManager, Session, resolve_session_secret,
                          rbac)

Password hashing (PBKDF2, stdlib), signed-cookie sessions (itsdangerous), and a
fixed three-role permission matrix. No third-party auth stack; no outbound calls.
"""
from __future__ import annotations

from . import rbac
from .passwords import (DEFAULT_ITERATIONS, DEFAULT_SALT_BYTES,
                        MIN_PASSWORD_LENGTH, check_password_policy,
                        hash_password, verify_password)
from .rbac import (PermissionDenied, ROLE_PERMISSIONS, has_permission,
                   permissions_for, require)
from .sessions import Session, SessionManager, resolve_session_secret
from .users import UserService

__all__ = [
    "hash_password",
    "verify_password",
    "check_password_policy",
    "DEFAULT_ITERATIONS",
    "DEFAULT_SALT_BYTES",
    "MIN_PASSWORD_LENGTH",
    "UserService",
    "Session",
    "SessionManager",
    "resolve_session_secret",
    "rbac",
    "PermissionDenied",
    "ROLE_PERMISSIONS",
    "has_permission",
    "permissions_for",
    "require",
]
