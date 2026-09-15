"""
detection/severity.py — how loud an indicator pattern gets to be.

TWO SEPARATE QUESTIONS, DELIBERATELY NOT CONFLATED
--------------------------------------------------
    SEVERITY    how much analyst attention this window deserves. Derived from
                the BREADTH of the evidence: how many rules fired, across how
                many distinct indicator groups. Two independent groups agreeing
                is a stronger signal than two rules inside one group, so the
                config table takes both numbers.
    CONFIDENCE  how much of the available evidence pointed the same way.
                Derived from the vote FRACTION — fired rules over rules that
                could actually be evaluated in this window.

Keeping them apart matters because they can disagree in a way an analyst needs
to see. On a Zeek conn.log only three of the seven rules are evaluable, so one
rule firing is a third of everything the telemetry could say ("high" confidence
in a weak signal) while remaining a single vote in a single group (LOW
severity). Collapsing the two into one number would hide exactly that.

THE CONFIDENCE DENOMINATOR IS EVALUABLE RULES, NOT SEVEN
--------------------------------------------------------
`HeuristicDetector.predict_proba` normalises by the rules whose COLUMN exists,
which for a full observation frame is always seven. Here the denominator is the
rules whose VALUE exists in this window. Dividing by seven on a conn.log would
cap every possible confidence at 3/7 and quietly report "low" for a window in
which every measurable indicator fired. The bands are coarse on purpose: a rule
baseline has no calibrated probability, and a precise-looking number would
overstate what it knows.

Both tables are config-driven (detection.severity, detection.confidence_bands)
so an operator retunes them without touching code, and both are validated on
load — a typo in a severity name fails at startup rather than mislabelling
alerts in production.
"""
from __future__ import annotations

from dataclasses import dataclass

# Ordered least- to most-urgent. The ordering is the comparison operator for
# `combined_floor`, so it lives in code rather than config: an operator may
# retune which counts earn which severity, but not that HIGH outranks LOW.
SEVERITIES: tuple[str, ...] = ("INFO", "LOW", "MEDIUM", "HIGH")
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}

# Coarse, deliberately unnumbered confidence labels. Lowercase because that is
# what the alerts table stores.
CONF_LOW = "low"
CONF_MEDIUM = "medium"
CONF_HIGH = "high"
CONFIDENCES: tuple[str, ...] = (CONF_LOW, CONF_MEDIUM, CONF_HIGH)


class SeverityConfigError(ValueError):
    """The configured severity or confidence table is not usable."""


@dataclass(frozen=True)
class SeverityRule:
    """One row of the configured table: thresholds that earn a severity."""

    min_votes: int
    min_groups: int
    severity: str


@dataclass(frozen=True)
class SeverityPolicy:
    """The whole severity + confidence policy, validated once at load.

    Built from config by :meth:`from_config` and then applied per window, so a
    malformed table fails at startup — where an operator sees it — instead of
    silently downgrading an alert hours later.
    """

    default: str
    rules: tuple[SeverityRule, ...]
    combined_floor: str | None
    medium_at: float
    high_at: float

    # -- construction ----------------------------------------------------
    @classmethod
    def from_config(cls, detection_cfg) -> "SeverityPolicy":
        sev = detection_cfg.severity
        default = _check_severity(sev.get("default", "INFO"), "severity.default")

        raw_rules = sev.get("rules") or []
        if not isinstance(raw_rules, (list, tuple)):
            raise SeverityConfigError(
                "detection.severity.rules must be a list of "
                "{min_votes, min_groups, severity} mappings")
        rules: list[SeverityRule] = []
        for i, row in enumerate(raw_rules):
            if not isinstance(row, dict):
                raise SeverityConfigError(
                    f"detection.severity.rules[{i}] is not a mapping: {row!r}")
            try:
                rules.append(SeverityRule(
                    min_votes=int(row["min_votes"]),
                    min_groups=int(row["min_groups"]),
                    severity=_check_severity(
                        row["severity"], f"severity.rules[{i}].severity")))
            except KeyError as exc:
                raise SeverityConfigError(
                    f"detection.severity.rules[{i}] is missing {exc}") from exc

        floor = sev.get("combined_floor")
        floor = _check_severity(floor, "severity.combined_floor") if floor \
            else None

        bands = detection_cfg.confidence_bands
        medium_at = float(bands.get("medium_at", 0.34))
        high_at = float(bands.get("high_at", 0.67))
        if not 0.0 <= medium_at <= high_at <= 1.0:
            raise SeverityConfigError(
                "detection.confidence_bands must satisfy "
                f"0 <= medium_at <= high_at <= 1; got {medium_at} / {high_at}")
        return cls(default=default, rules=tuple(rules), combined_floor=floor,
                   medium_at=medium_at, high_at=high_at)

    # -- application -----------------------------------------------------
    def severity_for(self, *, votes: int, n_groups: int,
                     floor: str | None = None) -> str:
        """The severity earned by ``votes`` rules across ``n_groups`` groups.

        The highest-severity row whose thresholds are ALL met wins; if none is
        met, the configured default. ``floor`` raises the result but never
        lowers it — a combined resolution+relay pattern is floored at
        `combined_floor` so the project's signal of interest cannot be buried
        under a single-vote LOW, but a genuinely broader pattern keeps its
        higher severity.
        """
        best = self.default
        for rule in self.rules:
            if votes >= rule.min_votes and n_groups >= rule.min_groups:
                if SEVERITY_RANK[rule.severity] > SEVERITY_RANK[best]:
                    best = rule.severity
        if floor and SEVERITY_RANK[floor] > SEVERITY_RANK[best]:
            best = floor
        return best

    def confidence_for(self, fraction: float) -> str:
        """The coarse confidence band for a vote fraction in [0, 1]."""
        if fraction >= self.high_at:
            return CONF_HIGH
        if fraction >= self.medium_at:
            return CONF_MEDIUM
        return CONF_LOW

    def vote_fraction(self, votes: int, n_evaluable: int) -> float:
        """Fired rules over rules that could be evaluated in this window.

        Zero evaluable rules yields 0.0 rather than a division error — a window
        nothing could be evaluated on gets no confidence at all, and the
        coverage gate has already turned it into INSUFFICIENT_TELEMETRY.
        """
        if n_evaluable <= 0:
            return 0.0
        return min(1.0, max(0.0, votes / n_evaluable))


def _check_severity(value, where: str) -> str:
    if value not in SEVERITIES:
        raise SeverityConfigError(
            f"detection.{where} = {value!r} is not one of {list(SEVERITIES)}")
    return value


def max_severity(a: str, b: str) -> str:
    """The more urgent of two severities. Used when alerts coalesce."""
    for s in (a, b):
        if s not in SEVERITY_RANK:
            raise SeverityConfigError(f"unknown severity: {s!r}")
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b
