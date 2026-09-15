"""
storage — the product's persistence layer.

A local SQLite database (Postgres-ready: the repository speaks only
parameterised SQL) holding the 13 domain entities plus migration/meta
bookkeeping. Import surface:

    from src.storage import Database, migrate, Repository, utcnow_iso

``Database`` hands out configured connections; ``migrate`` brings a fresh or
existing file up to the current schema and seeds roles + the pseudonym salt;
``Repository`` wraps a connection with one thin, parameterised accessor per
entity. The dataclass row-views (User, Alert, …) are re-exported for callers
that pass them around (auth, lifecycle, the model gate).
"""
from __future__ import annotations

from .db import Database, utcnow_iso
from .migrate import (DEFAULT_ROLES, PSEUDONYM_SALT_KEY, migrate)
from .models import (Alert, Device, DetectionModel, IngestionJob, Role, User)
from .pseudonymise import device_pseudonym, resolve_device_key
from .repository import Repository

__all__ = [
    "Database",
    "utcnow_iso",
    "migrate",
    "PSEUDONYM_SALT_KEY",
    "DEFAULT_ROLES",
    "Repository",
    "device_pseudonym",
    "resolve_device_key",
    "Role",
    "User",
    "Device",
    "IngestionJob",
    "DetectionModel",
    "Alert",
]
