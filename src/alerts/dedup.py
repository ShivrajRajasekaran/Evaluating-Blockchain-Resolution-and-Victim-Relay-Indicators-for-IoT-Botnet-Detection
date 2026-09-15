"""
alerts/dedup.py — one row per device-and-pattern, not one per five minutes.

THE PROBLEM
    Detection works on 5-minute device-windows. A device that beacons steadily
    for a day produces 288 windows that all fire the same rule for the same
    reason. Written out naively that is 288 alerts describing one situation, and
    a queue in that state is not triaged, it is abandoned.

THE KEY
    An alert's identity is (device, category, detection version, time bucket).
    A second window matching an existing key does not create a row; it bumps
    ``occurrence_count`` and advances ``last_seen``, so the analyst sees "this
    device, this pattern, 288 windows, first seen 00:02, last seen 23:57" — one
    row carrying strictly more information than 288 would have.

    Each component earns its place:

    device           an alert is about a device, and the key uses the stored
                     device key, so a pseudonymised deployment dedups on the
                     pseudonym without ever reconstructing the raw address.
    category         the triage unit. A device that starts relaying as well as
                     beaconing gets a NEW alert, because the change of pattern
                     is the thing worth noticing.
    detection version a ruleset change starts a fresh alert rather than letting
                     an old row silently absorb hits produced by different
                     logic. Without this, "first seen" would span two detectors.
    time bucket      coarse (default 24h) and computed by flooring, not by a
                     rolling window from first sight. Flooring is idempotent:
                     re-ingesting the same capture produces the same keys, so
                     a replayed file coalesces instead of duplicating.

WHY A HASH RATHER THAN THE TUPLE ITSELF
    The key goes in a UNIQUE index and is shown in URLs. A device key can be a
    raw IPv6 address or an operator-supplied label of any length and character
    set; hashing gives a fixed-width, URL-safe, injection-free token. The inputs
    are joined with a separator that cannot appear in a hex digest, so two
    different tuples cannot collide by concatenation.

CONTAINMENT
    Pure hashing. No I/O.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

# Chosen because a device key, a category and a version string can all contain
# almost anything else. Ambiguity here would let two distinct alerts share a key.
_SEP = "\x1f"

DEFAULT_BUCKET_HOURS = 24


class DedupError(ValueError):
    """The inputs cannot produce a stable dedup key."""


def bucket_for(window_start, *, hours: int = DEFAULT_BUCKET_HOURS) -> str:
    """The time bucket a window falls in, as a stable ISO-ish label.

    Floors the window's UTC timestamp to a multiple of ``hours`` since the
    epoch. Flooring rather than measuring from an alert's own first sighting is
    what makes re-ingesting a capture idempotent — a rolling window would key
    differently depending on which file arrived first.
    """
    if hours <= 0:
        raise DedupError(f"dedup_window_hours must be positive, got {hours!r}")
    ts = _to_datetime(window_start)
    span = hours * 3600
    floored = (int(ts.timestamp()) // span) * span
    return datetime.fromtimestamp(floored, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def dedup_key(*, device_key: str, category: str, detection_version: str,
              window_start, hours: int = DEFAULT_BUCKET_HOURS) -> str:
    """The stable identity of one alert. Same inputs, same key, always."""
    if not device_key:
        raise DedupError("device_key is required to identify an alert")
    if not category:
        raise DedupError("category is required to identify an alert")
    payload = _SEP.join((
        str(device_key), str(category), str(detection_version),
        bucket_for(window_start, hours=hours)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def alert_uid(dedup_key_value: str) -> str:
    """The public, human-quotable id for an alert.

    Derived from the dedup key so it is stable across a re-ingest of the same
    capture, and prefixed so it is recognisable in a log line or a URL.
    """
    if not dedup_key_value:
        raise DedupError("cannot build an alert uid from an empty dedup key")
    return f"al_{dedup_key_value[:24]}"


def _to_datetime(value) -> datetime:
    """Coerce a window start to an aware UTC datetime.

    Accepts a datetime, a pandas Timestamp, or an ISO-8601 string — the three
    shapes a window start actually arrives in (in-memory frame, stored row, form
    post). A naive value is read as UTC rather than as local time: the product
    may be operated from anywhere, and a key that depended on the server's
    timezone would not be reproducible.
    """
    if value is None:
        raise DedupError("window_start is required to identify an alert")
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            raise DedupError("window_start is required to identify an alert")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise DedupError(
                f"window_start {value!r} is not an ISO-8601 timestamp") from exc
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
