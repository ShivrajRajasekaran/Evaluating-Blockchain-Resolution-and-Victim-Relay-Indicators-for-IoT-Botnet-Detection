"""
auth.passwords — password hashing and policy, stdlib only.

PBKDF2-HMAC-SHA256 with a per-user random salt and a per-row iteration count, so
the work factor can be raised over time without invalidating existing hashes
(the count is stored alongside each hash). Verification compares in constant time
with :func:`hmac.compare_digest`. No third-party password library is used — this
is deliberately the standard-library primitive the platform ships and audits.

Nothing here touches the database or the network; these are pure functions.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ALGO = "sha256"

# OWASP's floor for PBKDF2-HMAC-SHA256 is well below this; 600k is a comfortable
# 2024-era default. Tests pass a tiny count so the suite stays fast — the count
# is a parameter precisely so callers (and tests) choose their own cost.
DEFAULT_ITERATIONS = 600_000
DEFAULT_SALT_BYTES = 16

# A security tool should not ship weak-password defaults. Enforced when a user is
# created or a password changed; not applied at hash time (hashing must be able
# to reproduce any historical hash).
MIN_PASSWORD_LENGTH = 12


def check_password_policy(password: str, *,
                          min_length: int = MIN_PASSWORD_LENGTH) -> None:
    """Raise ``ValueError`` if ``password`` fails policy. Returns None on pass."""
    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if len(password) < min_length:
        raise ValueError(
            f"password must be at least {min_length} characters")


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS,
                  salt_bytes: int = DEFAULT_SALT_BYTES) -> tuple[str, str, int]:
    """Return ``(hash_hex, salt_hex, iterations)`` for a fresh random salt."""
    if not isinstance(password, str) or password == "":
        raise ValueError("password must be a non-empty string")
    if iterations < 1:
        raise ValueError("iterations must be positive")
    salt = secrets.token_bytes(salt_bytes)
    dk = hashlib.pbkdf2_hmac(_ALGO, password.encode("utf-8"), salt, iterations)
    return dk.hex(), salt.hex(), iterations


def verify_password(password: str, password_hash_hex: str, salt_hex: str,
                    iterations: int) -> bool:
    """Constant-time verification. Malformed stored values return False rather
    than raising, so a corrupt row cannot crash a login attempt."""
    if password is None or password_hash_hex is None or salt_hex is None:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(password_hash_hex)
        iters = int(iterations)
    except (ValueError, TypeError):
        return False
    if iters < 1:
        return False
    dk = hashlib.pbkdf2_hmac(_ALGO, password.encode("utf-8"), salt, iters)
    return hmac.compare_digest(dk, expected)
