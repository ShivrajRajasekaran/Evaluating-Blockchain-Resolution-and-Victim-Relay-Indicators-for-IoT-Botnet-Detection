"""
storage.pseudonymise — stable, salted device pseudonyms.

When ``storage.pseudonymise_devices`` is on, a device's raw address never
reaches disk: it is replaced by an HMAC-SHA256 pseudonym keyed by a per-install
salt. The mapping is deterministic within an install (the same device yields the
same pseudonym across ingests, so its windows and alerts group correctly) and
differs between installs (the salt is generated once at DB init and stored in
``app_meta``, so two deployments never share a device→pseudonym table).

Honest limitation: this is *pseudonymisation*, not anonymisation. An adversary
who holds both the salt and a small candidate space (e.g. an RFC 1918 /24) can
recover addresses by brute force. It removes casual linkability and keeps raw
addresses out of the store; it is not a cryptographic guarantee of
irreversibility. Documented in docs/product-operation.md.
"""
from __future__ import annotations

import hashlib
import hmac

_PREFIX = "dev_"


def device_pseudonym(raw_id: str, salt: str, *, length: int = 32) -> str:
    """A stable pseudonym for ``raw_id`` under ``salt``. ``length`` is the number
    of hex characters kept from the digest (default 32 = 128 bits, ample to
    avoid collisions at device scale)."""
    if not raw_id:
        raise ValueError("cannot pseudonymise an empty device id")
    mac = hmac.new(salt.encode("utf-8"), raw_id.encode("utf-8"), hashlib.sha256)
    return _PREFIX + mac.hexdigest()[:length]


def resolve_device_key(raw_id: str, salt: str, *, enabled: bool) -> tuple[str, bool]:
    """Return ``(device_key, is_pseudonymised)``.

    The device_key is what every downstream table stores and joins on, so the
    rest of the product is identical whether pseudonymisation is on or off.
    """
    if enabled:
        return device_pseudonym(raw_id, salt), True
    return raw_id, False
