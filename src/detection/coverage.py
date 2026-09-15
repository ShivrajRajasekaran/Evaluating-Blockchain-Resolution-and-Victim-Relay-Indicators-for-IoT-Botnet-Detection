"""
detection/coverage.py — "could this window be judged at all?"

THE PROBLEM THIS SOLVES
-----------------------
A rule that cannot be evaluated does not fire. A detector that only counts
fired rules therefore reports an unmeasurable device and a genuinely quiet
device identically — and calls both of them benign. On the telemetry this
product actually ingests that is not a corner case, it is the normal case: a
Zeek conn.log carries no DNS, no HTTP and no payload, so BOTH resolution rules
(`ens_query_rate`, `serverlist_pull`) are NaN on every single window. Counting
their silence as evidence of innocence would manufacture a clean bill of health
out of an absent log file.

So before any verdict is formed, each research feature group is measured:

    feature_coverage   fraction of the group's features that are non-NaN in
                       this window. The operator-tunable gate
                       (detection.coverage.min_group_coverage) applies to this.
    rule_coverage      fraction of the group's RULES whose feature is non-NaN
                       in this window. This is the one that decides whether a
                       silence means anything, and it is deliberately NOT
                       tunable: zero evaluable rules is zero evidence, at any
                       threshold an operator might prefer.

A gated group yields INSUFFICIENT_TELEMETRY with an explicit, configured reason
rather than a benign verdict. Missing data is never converted to zero, and
never to reassurance.

WHY COVERAGE IS MEASURED FROM VALUES, NOT FROM THE SOURCE NAME
--------------------------------------------------------------
`schema.columns.FEATURE_AVAILABILITY` already says what each source *should* be
able to supply, and :func:`source_coverage` reports exactly that for the
dashboard's per-source coverage screen. But the per-window gate reads the actual
NaNs in the row. The two agree when ingest behaved; when they disagree — a
truncated capture, a vendor export missing a column — the row's own NaNs are the
truth, and trusting the source label instead would judge a window on telemetry
it did not actually contain.

CONTAINMENT
    Pure arithmetic over a DataFrame. No I/O of any kind.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from src.models.heuristic import RULES
from src.schema import columns as K

# Rule features grouped by the research group they belong to, computed once from
# the canonical rule table so this module cannot drift from the baseline.
RULE_FEATURES_BY_GROUP: dict[str, tuple[str, ...]] = {}
for _feat, _op, _thr, _reason in RULES:
    _g = K.GROUP_OF_FEATURE[_feat]
    RULE_FEATURES_BY_GROUP[_g] = RULE_FEATURES_BY_GROUP.get(_g, ()) + (_feat,)
del _feat, _op, _thr, _reason, _g


@dataclass(frozen=True)
class GroupCoverage:
    """What could be measured for one research feature group, in one window."""

    group: str
    n_features: int
    n_features_present: int
    n_rules: int
    n_rules_evaluable: int
    gated: bool
    reason: str

    @property
    def feature_coverage(self) -> float:
        """Fraction of the group's features that carry a value."""
        return (self.n_features_present / self.n_features
                if self.n_features else 0.0)

    @property
    def rule_coverage(self) -> float:
        """Fraction of the group's rules that could be evaluated."""
        return (self.n_rules_evaluable / self.n_rules if self.n_rules else 0.0)

    def as_dict(self) -> dict:
        return {
            "group": self.group,
            "n_features": self.n_features,
            "n_features_present": self.n_features_present,
            "feature_coverage": round(self.feature_coverage, 4),
            "n_rules": self.n_rules,
            "n_rules_evaluable": self.n_rules_evaluable,
            "rule_coverage": round(self.rule_coverage, 4),
            "gated": self.gated,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CoverageReport:
    """Per-group coverage for a single observation window."""

    groups: tuple[GroupCoverage, ...]

    def __getitem__(self, group: str) -> GroupCoverage:
        for g in self.groups:
            if g.group == group:
                return g
        raise KeyError(f"no coverage for group {group!r}")

    @property
    def gated_groups(self) -> tuple[str, ...]:
        """Groups this window cannot be judged on, in canonical order."""
        return tuple(g.group for g in self.groups if g.gated)

    @property
    def n_rules_evaluable(self) -> int:
        """Rules that could be evaluated anywhere in this window."""
        return sum(g.n_rules_evaluable for g in self.groups)

    def note(self, exclude: tuple[str, ...] = ()) -> str:
        """One analyst-readable sentence per gated group, or ``""``.

        ``exclude`` drops groups that did fire after all — a group cannot be
        both unjudgeable and the source of an alert, and when an operator raises
        `min_group_coverage` above the structural floor the two can otherwise
        collide.
        """
        parts = [g.reason for g in self.groups
                 if g.gated and g.group not in exclude and g.reason]
        return " ".join(parts)

    def as_dict(self) -> dict:
        return {g.group: g.as_dict() for g in self.groups}


def _generic_reason(group: str, n_present: int, n_features: int,
                    n_evaluable: int, n_rules: int) -> str:
    return (f"{group.capitalize()} indicators could not be measured in this "
            f"window ({n_present} of {n_features} features present, "
            f"{n_evaluable} of {n_rules} rules evaluable), so no judgement can "
            "be made about them.")


def _configured_reason(group: str, cov_cfg) -> str | None:
    """The operator-authored explanation for a gated group, if there is one.

    Read by convention (`<group>_reason`) so adding a reason for a group is a
    config edit, not a code change. Absent keys fall back to a generated
    sentence that carries the measured numbers instead of prose.
    """
    if cov_cfg is None:
        return None
    key = f"{group}_reason"
    value = cov_cfg.get(key) if hasattr(cov_cfg, "get") else None
    if isinstance(value, str) and value.strip():
        return " ".join(value.split())
    return None


def assess_window(values: dict[str, float], *, cov_cfg=None) -> CoverageReport:
    """Coverage for one window, from its feature values.

    ``values`` maps feature name to value; a feature that is absent from the
    mapping counts exactly like one present as NaN — "not measurable" either
    way, never zero.
    """
    min_cov = 0.0
    if cov_cfg is not None and hasattr(cov_cfg, "get"):
        min_cov = float(cov_cfg.get("min_group_coverage", 0.0) or 0.0)

    out: list[GroupCoverage] = []
    for group, features in K.FEATURE_GROUPS.items():
        present = [f for f in features if _is_present(values.get(f))]
        rules = RULE_FEATURES_BY_GROUP.get(group, ())
        evaluable = [f for f in rules if _is_present(values.get(f))]

        n_features, n_present = len(features), len(present)
        n_rules, n_evaluable = len(rules), len(evaluable)
        feature_cov = n_present / n_features if n_features else 0.0

        # Two independent grounds for "cannot judge". The first is the operator's
        # tunable floor on how much of a group must be visible; the second is
        # structural — a group whose rules are all NaN produces silence that
        # carries no information, whatever the operator set.
        gated = feature_cov <= min_cov or (n_rules > 0 and n_evaluable == 0)

        reason = ""
        if gated:
            reason = _configured_reason(group, cov_cfg) or _generic_reason(
                group, n_present, n_features, n_evaluable, n_rules)
        out.append(GroupCoverage(
            group=group, n_features=n_features, n_features_present=n_present,
            n_rules=n_rules, n_rules_evaluable=n_evaluable, gated=gated,
            reason=reason))
    return CoverageReport(tuple(out))


def assess_frame(frame: pd.DataFrame, *, cov_cfg=None) -> list[CoverageReport]:
    """Coverage for every row of a feature frame, order preserved."""
    cols = [c for c in K.FEATURE_COLS if c in frame.columns]
    if cols:
        numeric = frame[cols].apply(pd.to_numeric, errors="coerce")
        records = numeric.to_dict("records")
    else:
        # No feature columns at all: every feature is "not measurable".
        records = [{} for _ in range(len(frame))]
    return [assess_window(r, cov_cfg=cov_cfg) for r in records]


def source_coverage(source: str) -> dict[str, dict]:
    """Per-group coverage a source can supply AT BEST, from the schema.

    Reads ``schema.columns.FEATURE_AVAILABILITY`` rather than any data, so the
    dashboard can tell an analyst what a Zeek conn.log will and will not be able
    to say before a single file is uploaded. ``unavailable`` features are NaN by
    construction; ``proxy`` ones carry a value but an approximate one, and are
    counted as present because a rule can in fact be evaluated against them.
    """
    table = K.FEATURE_AVAILABILITY[source]
    out: dict[str, dict] = {}
    for group, features in K.FEATURE_GROUPS.items():
        rules = RULE_FEATURES_BY_GROUP.get(group, ())
        present = [f for f in features
                   if table[f] != K.AVAIL_UNAVAILABLE]
        evaluable = [f for f in rules if table[f] != K.AVAIL_UNAVAILABLE]
        proxy = [f for f in features if table[f] == K.AVAIL_PROXY]
        out[group] = {
            "group": group,
            "n_features": len(features),
            "n_features_present": len(present),
            "feature_coverage": round(len(present) / len(features), 4),
            "n_rules": len(rules),
            "n_rules_evaluable": len(evaluable),
            "rule_coverage": (round(len(evaluable) / len(rules), 4)
                              if rules else 0.0),
            "proxy_features": tuple(proxy),
            "unavailable_features": tuple(
                f for f in features if table[f] == K.AVAIL_UNAVAILABLE),
            # A group no rule can be evaluated on is one this source can say
            # nothing about, however many of its features happen to carry values.
            "judgeable": bool(evaluable) if rules else False,
        }
    return out


def _is_present(value) -> bool:
    """A value counts as measured when it is a real, finite number.

    NaN is "not measurable" and never becomes zero; so are None, an infinity
    from a division that should not have happened, and a string that failed to
    parse. Being strict here is what keeps a broken cell from silently becoming
    evidence.
    """
    if value is None:
        return False
    try:
        f = float(value)
    except (TypeError, ValueError):
        return False
    return not (np.isnan(f) or np.isinf(f))
