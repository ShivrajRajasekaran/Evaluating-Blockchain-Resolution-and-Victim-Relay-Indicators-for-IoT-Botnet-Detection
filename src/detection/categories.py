"""
detection/categories.py — the seven operational verdict categories.

WHY THESE LIVE HERE AND NOT IN schema/columns.py
------------------------------------------------
`schema/columns.py` is the single source of truth for the *research* data model
— the 16 features, the 7-class research taxonomy, the two tracks. It says
nothing about verdicts, because the offline pipeline does not raise any: it
scores frames and reports metrics.

An *operational verdict category* is a different kind of thing. It is a triage
label a human analyst reads, attached to a review-only finding the product
raises over UNLABELLED enterprise telemetry. It is deliberately NOT one of the
research classes: the product never claims a device is
`blockchain_resolution_mock` (a synthetic ground-truth label it could only know
in the lab). It says "resolution-like indicators fired on this window; review
it". So the categories live with the thing that produces them — the rule engine
— grounded in, but distinct from, the research schema.

WHY EVERY NAME BEGINS "SUSPICIOUS_"
-----------------------------------
The product reads metadata and classifies shapes. That can never establish
compromise, so no category may read as a confirmation. The four alerting names
all say SUSPICIOUS_…_PATTERN, and the three non-alerting ones name a state of
knowledge rather than a verdict about the device. There is no "MALICIOUS",
no "CONFIRMED", and no "CLEAN".

THE MAPPING (grounded in the canonical rule set + research feature groups)
--------------------------------------------------------------------------
The transparent rule baseline (src/models/heuristic.py) has exactly seven
rules, each on one feature, and each feature belongs to one of the four
research feature groups (schema.columns.GROUP_OF_FEATURE):

    resolution rules  (ens_query_rate, serverlist_pull)        -> RESOLUTION
    relay rules       (upnp_addportmapping, updownlink_ratio)  -> RELAY
    both novel groups fire                                     -> COMBINED
    infection / payload rules only                             -> CONVENTIONAL
      (login_burst_count, beacon_interval, rc4_string_score)

SUSPICIOUS_COMBINED_PATTERN is a category of its own because a device showing
BOTH a resolution and a relay indicator in the same window is precisely this
project's signal of interest. The config floors its severity
(detection.severity.combined_floor) so it is never buried under a single-vote
LOW.

The three remaining categories are states of knowledge, not findings:

    BENIGN_OR_NO_ALERT    every indicator group was measurable and none fired.
                          Named "…_OR_NO_ALERT" because a rule baseline that
                          stays quiet has not established innocence.
    INSUFFICIENT_TELEMETRY at least one indicator group could not be measured
                          from this source, so a quiet window is NOT evidence
                          of benign behaviour. This is the honest answer for a
                          Zeek conn.log, which carries no DNS/HTTP and so can
                          say nothing at all about resolution behaviour.
    ABSTAIN               the input could not be read as an observation window
                          at all. Mirrors the offline service's abstention
                          channel (services/score.py) rather than guessing.

PRECEDENCE, when several groups fire at once
--------------------------------------------
The novel groups outrank the conventional ones in the LABEL shown, because they
are the pattern the project exists to surface; the conventional evidence is
still carried on the alert in full. Severity is computed separately from the
vote and group counts, so an outranked group never loses weight — only the
headline name is chosen here.
"""
from __future__ import annotations

from src.models.heuristic import RULES
from src.schema import columns as K

# ---- the seven categories, verbatim ----------------------------------------
# These exact strings are persisted in the alerts table, filtered on in the API
# and rendered in the dashboard. Changing one is a data migration, not an edit.
CAT_BENIGN_OR_NO_ALERT = "BENIGN_OR_NO_ALERT"
CAT_SUSPICIOUS_RESOLUTION = "SUSPICIOUS_RESOLUTION_PATTERN"
CAT_SUSPICIOUS_RELAY = "SUSPICIOUS_RELAY_PATTERN"
CAT_SUSPICIOUS_COMBINED = "SUSPICIOUS_COMBINED_PATTERN"
CAT_SUSPICIOUS_CONVENTIONAL = "SUSPICIOUS_CONVENTIONAL_BOTNET_PATTERN"
CAT_INSUFFICIENT_TELEMETRY = "INSUFFICIENT_TELEMETRY"
CAT_ABSTAIN = "ABSTAIN"

CATEGORIES: tuple[str, ...] = (
    CAT_BENIGN_OR_NO_ALERT,
    CAT_SUSPICIOUS_RESOLUTION,
    CAT_SUSPICIOUS_RELAY,
    CAT_SUSPICIOUS_COMBINED,
    CAT_SUSPICIOUS_CONVENTIONAL,
    CAT_INSUFFICIENT_TELEMETRY,
    CAT_ABSTAIN,
)

# The categories that put a row in front of an analyst. The other three are
# recorded on the window for coverage accounting and never raise an alert —
# INSUFFICIENT_TELEMETRY in particular must not flood a queue, it exists so a
# quiet window is not silently miscounted as a clean one.
ALERTING_CATEGORIES: tuple[str, ...] = (
    CAT_SUSPICIOUS_COMBINED,
    CAT_SUSPICIOUS_RESOLUTION,
    CAT_SUSPICIOUS_RELAY,
    CAT_SUSPICIOUS_CONVENTIONAL,
)

# ---- group -> category, and the precedence between them --------------------
# The novel signal-of-interest combination first, then each novel group alone,
# then the conventional base groups.
_GROUP_CATEGORY: dict[str, str] = {
    "resolution": CAT_SUSPICIOUS_RESOLUTION,
    "relay": CAT_SUSPICIOUS_RELAY,
    "infection": CAT_SUSPICIOUS_CONVENTIONAL,
    "payload": CAT_SUSPICIOUS_CONVENTIONAL,
}

_CATEGORY_PRECEDENCE: tuple[str, ...] = (
    CAT_SUSPICIOUS_COMBINED,
    CAT_SUSPICIOUS_RESOLUTION,
    CAT_SUSPICIOUS_RELAY,
    CAT_SUSPICIOUS_CONVENTIONAL,
)


def _validate_mapping() -> None:
    """Fail loudly at import if the rule set and this map ever drift apart.

    Every rule's feature must belong to a research group, and every research
    group must map to an alerting category. If a future edit adds a rule on a
    feature from an unmapped group, the product refuses to start rather than
    raising uncategorised alerts.
    """
    for feat, _op, _thr, _reason in RULES:
        group = K.GROUP_OF_FEATURE.get(feat)
        if group is None:
            raise RuntimeError(
                f"rule feature {feat!r} is not a known research feature")
        if group not in _GROUP_CATEGORY:
            raise RuntimeError(
                f"rule feature {feat!r} is in group {group!r}, which has no "
                "operational category")
    unknown = set(_GROUP_CATEGORY) - set(K.FEATURE_GROUPS)
    if unknown:
        raise RuntimeError(f"unknown feature group(s) mapped: {sorted(unknown)}")
    for cat in _GROUP_CATEGORY.values():
        if cat not in ALERTING_CATEGORIES:
            raise RuntimeError(f"{cat!r} is not an alerting category")


_validate_mapping()


def category_for_groups(fired_groups) -> str | None:
    """The single headline category for the groups whose rules fired.

    ``resolution`` and ``relay`` together outrank either alone — that
    co-occurrence is the project's signal of interest. Returns ``None`` when no
    group fired, which is not the same as a benign verdict: the caller decides
    between BENIGN_OR_NO_ALERT and INSUFFICIENT_TELEMETRY from coverage.
    """
    fired = set(fired_groups)
    if not fired:
        return None
    unknown = fired - set(_GROUP_CATEGORY)
    if unknown:
        raise KeyError(f"unknown feature group(s): {sorted(unknown)}")
    if {"resolution", "relay"} <= fired:
        return CAT_SUSPICIOUS_COMBINED
    candidates = {_GROUP_CATEGORY[g] for g in fired}
    for cat in _CATEGORY_PRECEDENCE:
        if cat in candidates:
            return cat
    return None  # unreachable: _validate_mapping covers every group


def category_for_feature(feature: str) -> str:
    """The alerting category a single fired rule contributes to."""
    group = K.GROUP_OF_FEATURE.get(feature)
    if group is None or group not in _GROUP_CATEGORY:
        raise KeyError(f"no operational category for feature {feature!r}")
    return _GROUP_CATEGORY[group]


def raises_alert(category: str) -> bool:
    """Whether this category should be put in front of an analyst."""
    if category not in CATEGORIES:
        raise KeyError(f"unknown category: {category!r}")
    return category in ALERTING_CATEGORIES


def rule_groups() -> tuple[str, ...]:
    """Research feature groups that the rule set can actually fire on.

    All four, as it happens — but read from the rule table rather than asserted,
    so the coverage report and the category map stay in step with the rules.
    """
    seen = {K.GROUP_OF_FEATURE[f] for f, _o, _t, _r in RULES}
    return tuple(g for g in K.FEATURE_GROUPS if g in seen)
