"""
alerts/lifecycle.py — the analyst workflow, as an enforced state machine.

THE STATES
    Open                  raised by a detection run, nobody has looked yet
    Investigating          an analyst has picked it up
    Benign                 reviewed: the pattern has an innocent explanation
    Confirmed suspicious   reviewed: the pattern is real and warrants action
    Closed                 triage finished and the alert is filed

WHAT "CONFIRMED SUSPICIOUS" DOES AND DOES NOT MEAN
    It records that a HUMAN reviewed the evidence and agrees the pattern is
    genuinely suspicious. It is not, and must never be rendered as, confirmation
    of compromise, of malware, or of blockchain-anchored C2 — the product reads
    metadata and classifies shapes, and no amount of analyst agreement turns
    that into an incident finding. The word "confirmed" qualifies *suspicious*,
    which is why the status is spelled out in full everywhere it appears.

WHY A MACHINE AND NOT A FREE-TEXT COLUMN
    Three properties are worth enforcing rather than hoping for:

      * An alert cannot be Closed without a disposition. Open -> Closed is not
        a legal move; something has to be said about it first. A queue that can
        be emptied without judgement measures nothing.
      * Every move is recorded. `analyst_feedback` holds the history and the
        alerts row holds only the head, so "who called this benign, and when"
        survives a later reopen.
      * Reopening is legal and explicit. Triage is revisable; a state machine
        that pretends otherwise gets worked around by editing the database.

CONTAINMENT
    Pure logic over strings. Persistence is :mod:`alerts.builder`'s job.
"""
from __future__ import annotations

STATUS_OPEN = "Open"
STATUS_INVESTIGATING = "Investigating"
STATUS_BENIGN = "Benign"
STATUS_CONFIRMED_SUSPICIOUS = "Confirmed suspicious"
STATUS_CLOSED = "Closed"

STATUSES: tuple[str, ...] = (
    STATUS_OPEN,
    STATUS_INVESTIGATING,
    STATUS_BENIGN,
    STATUS_CONFIRMED_SUSPICIOUS,
    STATUS_CLOSED,
)

# The statuses that represent a reviewed judgement. An alert must pass through
# one of these before it can be Closed.
DISPOSITION_STATUSES: tuple[str, ...] = (
    STATUS_BENIGN, STATUS_CONFIRMED_SUSPICIOUS)

# Statuses still demanding attention — the "open queue" the dashboard counts.
ACTIVE_STATUSES: tuple[str, ...] = (STATUS_OPEN, STATUS_INVESTIGATING)

# The allowed moves. Note what is absent: Open -> Closed, and Benign ->
# Confirmed suspicious (a change of mind goes back through Investigating, so the
# history shows a re-review rather than a silent flip).
_TRANSITIONS: dict[str, tuple[str, ...]] = {
    STATUS_OPEN: (STATUS_INVESTIGATING, STATUS_BENIGN,
                  STATUS_CONFIRMED_SUSPICIOUS),
    STATUS_INVESTIGATING: (STATUS_BENIGN, STATUS_CONFIRMED_SUSPICIOUS,
                           STATUS_OPEN),
    STATUS_BENIGN: (STATUS_CLOSED, STATUS_INVESTIGATING),
    STATUS_CONFIRMED_SUSPICIOUS: (STATUS_CLOSED, STATUS_INVESTIGATING),
    STATUS_CLOSED: (STATUS_INVESTIGATING,),
}

# Optional free-form-but-controlled reasons an analyst may attach to a move.
# Recorded alongside the transition; never used to compute anything, because a
# detector that learned from its own triage labels would be measuring the
# analysts rather than the traffic.
DISPOSITION_FALSE_POSITIVE = "false_positive"
DISPOSITION_TRUE_POSITIVE = "true_positive"
DISPOSITION_BENIGN_EXPLAINED = "benign_explained"
DISPOSITION_NEEDS_TELEMETRY = "needs_more_telemetry"
DISPOSITION_DUPLICATE = "duplicate"

DISPOSITIONS: tuple[str, ...] = (
    DISPOSITION_FALSE_POSITIVE,
    DISPOSITION_TRUE_POSITIVE,
    DISPOSITION_BENIGN_EXPLAINED,
    DISPOSITION_NEEDS_TELEMETRY,
    DISPOSITION_DUPLICATE,
)


class TransitionError(ValueError):
    """The requested status change is not a legal move."""


def is_status(value: str) -> bool:
    return value in STATUSES


def allowed_from(status: str) -> tuple[str, ...]:
    """The statuses reachable from ``status``, for rendering the UI's buttons.

    The dashboard builds its controls from this, so an illegal move is not
    merely rejected on submit — it is never offered.
    """
    if status not in _TRANSITIONS:
        raise TransitionError(f"unknown alert status: {status!r}")
    return _TRANSITIONS[status]


def can_transition(current: str, target: str) -> bool:
    return target in allowed_from(current)


def check_transition(current: str, target: str) -> None:
    """Raise unless ``current -> target`` is legal. The single enforcement point.

    Every write path — API route, script, bulk action — goes through here, so
    there is one definition of a legal move rather than one per caller.
    """
    if target not in STATUSES:
        raise TransitionError(
            f"unknown target status {target!r}; expected one of {list(STATUSES)}")
    if current == target:
        raise TransitionError(
            f"alert is already {current!r}; a no-op transition would add a "
            "history row recording that nothing happened")
    if not can_transition(current, target):
        extra = ""
        if target == STATUS_CLOSED and current == STATUS_OPEN:
            extra = (" An alert must be reviewed as "
                     f"{STATUS_BENIGN!r} or {STATUS_CONFIRMED_SUSPICIOUS!r} "
                     "before it can be closed.")
        raise TransitionError(
            f"{current!r} -> {target!r} is not a legal transition; from "
            f"{current!r} the allowed moves are "
            f"{list(allowed_from(current))}.{extra}")


def check_disposition(disposition: str | None) -> None:
    """Raise on a disposition that is not in the controlled vocabulary."""
    if disposition is None or disposition == "":
        return
    if disposition not in DISPOSITIONS:
        raise TransitionError(
            f"unknown disposition {disposition!r}; expected one of "
            f"{list(DISPOSITIONS)}")


def is_active(status: str) -> bool:
    """Whether this alert is still in the analyst's queue."""
    if status not in STATUSES:
        raise TransitionError(f"unknown alert status: {status!r}")
    return status in ACTIVE_STATUSES
