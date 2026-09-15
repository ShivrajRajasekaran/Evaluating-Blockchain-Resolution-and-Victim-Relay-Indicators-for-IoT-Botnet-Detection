"""
auth.users — user creation and authentication over a storage Repository.

The service is bound to a ``Repository`` (i.e. a live connection), not to a
``Database``: the caller owns the transaction, so a route can create a user and
write the matching audit event in one atomic unit, and a script can do the same.

Authentication is written to resist username enumeration: a login attempt for a
non-existent user still runs one PBKDF2 computation against a dummy hash, so the
response time does not reveal whether the username exists.
"""
from __future__ import annotations

from ..storage import User
from ..storage.repository import Repository
from .passwords import (DEFAULT_ITERATIONS, DEFAULT_SALT_BYTES,
                        check_password_policy, hash_password, verify_password)

# A well-formed but unmatchable stored credential. authenticate() verifies
# against this when the username is unknown, so both paths pay the same PBKDF2
# cost. The salt is fixed and public; it protects nothing — its only job is to
# make the dummy path do the same work as the real one.
_DUMMY_HASH = "00" * 32
_DUMMY_SALT = "00" * DEFAULT_SALT_BYTES


class UserService:
    def __init__(self, repo: Repository, *, iterations: int = DEFAULT_ITERATIONS,
                 salt_bytes: int = DEFAULT_SALT_BYTES,
                 min_password_length: int = 12):
        self.repo = repo
        self.iterations = int(iterations)
        self.salt_bytes = int(salt_bytes)
        self.min_password_length = int(min_password_length)

    def create_user(self, *, username: str, password: str, role_name: str,
                    created_at: str) -> int:
        username = (username or "").strip()
        if not username:
            raise ValueError("username must not be empty")
        check_password_policy(password, min_length=self.min_password_length)
        role = self.repo.roles.by_name(role_name)
        if role is None:
            raise ValueError(f"unknown role: {role_name!r}")
        h, s, iters = hash_password(
            password, iterations=self.iterations, salt_bytes=self.salt_bytes)
        return self.repo.users.create(
            username=username, password_hash=h, password_salt=s,
            iterations=iters, role_id=role.id, created_at=created_at)

    def authenticate(self, username: str, password: str, *,
                     now: str | None = None) -> User | None:
        """Return the User on success, else None. On success and when ``now`` is
        given, records last-login. Distinguishes nothing to the caller — a bad
        password, unknown user, or disabled account all return None, so the
        route can only ever show one generic message."""
        user = self.repo.users.by_username((username or "").strip())
        if user is None:
            # Equalise timing against the dummy credential.
            verify_password(password or "", _DUMMY_HASH, _DUMMY_SALT,
                            self.iterations)
            return None
        if not verify_password(password or "", user.password_hash,
                               user.password_salt, user.iterations):
            return None
        if not user.is_active:
            return None
        if now is not None:
            self.repo.users.set_last_login(user.id, now)
            # Re-read so the returned object reflects the recorded login.
            return self.repo.users.by_id(user.id)
        return user

    def set_password(self, user_id: int, new_password: str) -> None:
        check_password_policy(new_password, min_length=self.min_password_length)
        h, s, iters = hash_password(
            new_password, iterations=self.iterations, salt_bytes=self.salt_bytes)
        self.repo.users.set_password(
            user_id, password_hash=h, password_salt=s, iterations=iters)

    def set_active(self, user_id: int, active: bool) -> None:
        self.repo.users.set_active(user_id, active)
