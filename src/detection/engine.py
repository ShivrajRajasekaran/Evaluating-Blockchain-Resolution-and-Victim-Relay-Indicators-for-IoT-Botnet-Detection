"""
detection/engine.py — device-window observations in, review verdicts out.

WHAT IT DOES
    Takes a schema-valid observation frame (typically straight from an
    operational ingest adapter) and returns one :class:`WindowVerdict` per row:
    a category, a severity, a confidence band, the exact rules that fired with
    their values and thresholds, and a coverage statement about what could not
    be judged at all.

WHAT IT DOES NOT DO
    It does not touch a database, a socket or a device. It is a pure function
    over a DataFrame, which is why every property below can be tested without
    standing anything up. Persisting a verdict is the alert layer's job
    (src/alerts), and it is a separate module precisely so detection stays
    replayable: the same frame always yields the same verdicts.

THE RULES ARE NOT REDECLARED HERE
    They are read from ``src.models.heuristic.RULES`` — the same seven
    (feature, comparator, threshold, reason) tuples the research baseline votes
    on, with the same comparators from ``OPS``. The engine adds attribution
    (which group, which value) rather than thresholds of its own, so a product
    alert and a research vote can never disagree about whether a rule fired.
    ``tests/test_detection_engine.py`` pins that agreement against
    ``HeuristicDetector.votes`` directly.

THE FOUR OUTCOMES, AND WHY "QUIET" IS NOT ONE OF THEM
    rules fired                -> SUSPICIOUS_… (severity from breadth)
    nothing fired, all groups
      measurable               -> BENIGN_OR_NO_ALERT
    nothing fired, some group
      unmeasurable             -> INSUFFICIENT_TELEMETRY
    window unreadable          -> ABSTAIN

    The third case is the one that matters. On a Zeek conn.log both resolution
    rules are NaN on every window, so their silence is the absence of a log
    file, not the absence of behaviour. Reporting that as benign would be the
    single most misleading thing this product could do, so it does not exist as
    an output.

ML MODE
    Requested through :class:`~src.detection.model_gate`, which refuses in this
    build. A refusal is not an error: the engine runs the rule baseline and
    carries the gate's notice on the result, so the UI can say why no model was
    used instead of implying one was.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import numpy as np
import pandas as pd

from src.config import load_config, operational_data_note
from src.models.heuristic import OPS, RULES, HeuristicDetector
from src.schema import columns as K

from . import categories as C
from . import coverage as COV
from .model_gate import MODE_MODEL, GateDecision, evaluate_gate
from .severity import SeverityPolicy

# Recorded on every alert as `detection_version`. Bumped by hand when the rule
# TABLE changes meaning; `ruleset_digest` below is the machine-checkable
# companion, so a silent edit to a threshold is visible in the evidence even if
# someone forgets to bump this.
RULESET_VERSION = "ruleset-1"

# Recorded as `provenance`: which kind of detector produced the row.
PROV_RULE_ENGINE = "rule-engine"
PROV_ML_MODEL = "ml-model"

# Why a window was not given a suspicion verdict. Mirrors the offline service's
# reason vocabulary (services/score.py) so an operator reading both sees one set
# of words.
REASON_OK = ""
REASON_SCHEMA = "schema_invalid"
REASON_COVERAGE = "insufficient_coverage"
REASON_NO_EVALUABLE_RULES = "no_evaluable_rules"

# Meta columns a row needs before it can be called an observation window at all.
_REQUIRED_META: tuple[str, ...] = (
    K.OBSERVATION_ID, K.DEVICE_ID, K.WINDOW_START)


class DetectionError(RuntimeError):
    """The frame could not be detected on, and abstention was not configured."""


@dataclass(frozen=True)
class RuleHit:
    """One rule that fired on one window, with everything needed to audit it."""

    feature: str
    group: str
    op: str
    threshold: float
    value: float
    reason: str

    def as_dict(self) -> dict:
        return {"feature": self.feature, "group": self.group, "op": self.op,
                "threshold": self.threshold, "value": self.value,
                "reason": self.reason}

    def __str__(self) -> str:
        return (f"{self.reason} ({self.feature} = {self.value:g} "
                f"{self.op} {self.threshold:g})")


@dataclass(frozen=True)
class WindowVerdict:
    """The product's judgement on one device-window. Never a confirmation."""

    observation_id: str
    device_id: str
    window_start: str
    source_dataset: str
    category: str
    severity: str
    confidence: str
    confidence_fraction: float
    votes: int
    n_evaluable_rules: int
    fired_groups: tuple[str, ...]
    hits: tuple[RuleHit, ...]
    coverage: COV.CoverageReport
    coverage_note: str
    reason: str
    mode: str
    provenance: str
    detection_version: str
    marker: str
    quality_flags: str = ""

    @property
    def raises_alert(self) -> bool:
        return C.raises_alert(self.category)

    @property
    def explanation(self) -> str:
        """The evidence, in the analyst's words. Empty when nothing fired."""
        return "; ".join(str(h) for h in self.hits)

    @property
    def explanation_with_marker(self) -> str:
        """The evidence plus the honesty marker, for anything user-facing.

        Every surface that shows an explanation shows this one, so there is no
        rendering path on which a rule-based finding can appear without saying
        it is rule-based.

        The coverage note is deliberately NOT folded in here. It travels as its
        own field on the verdict, the alert row, the JSON payload and the CSV
        column, and every surface renders it in its own right — inlining it too
        would state the same sentence three times on one page and turn the
        evidence line into a run-on.
        """
        parts = [p for p in (self.explanation, self.marker) if p]
        return " — ".join(parts)

    def as_dict(self) -> dict:
        return {
            K.OBSERVATION_ID: self.observation_id,
            K.DEVICE_ID: self.device_id,
            K.WINDOW_START: self.window_start,
            K.SOURCE_DATASET: self.source_dataset,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_fraction": round(self.confidence_fraction, 4),
            "votes": self.votes,
            "n_evaluable_rules": self.n_evaluable_rules,
            "fired_groups": list(self.fired_groups),
            "hits": [h.as_dict() for h in self.hits],
            "coverage": self.coverage.as_dict(),
            "coverage_note": self.coverage_note,
            "reason": self.reason,
            "mode": self.mode,
            "provenance": self.provenance,
            "detection_version": self.detection_version,
            "explanation": self.explanation,
            "marker": self.marker,
            "raises_alert": self.raises_alert,
        }


@dataclass(frozen=True)
class DetectionResult:
    """Every verdict from one run, plus how the run was configured."""

    verdicts: tuple[WindowVerdict, ...]
    mode: str
    gate: GateDecision
    detection_version: str
    ruleset_digest: str
    marker: str
    provenance_note: str
    notice: str = ""
    config_digest: str = ""

    def __len__(self) -> int:
        return len(self.verdicts)

    def __iter__(self):
        return iter(self.verdicts)

    @property
    def alerting(self) -> tuple[WindowVerdict, ...]:
        """The verdicts an analyst should see."""
        return tuple(v for v in self.verdicts if v.raises_alert)

    def summary(self) -> dict:
        """Counts per category and severity, for the run report and dashboard.

        Includes the non-alerting categories on purpose: "1,204 windows, 0
        alerts, 1,204 with resolution telemetry absent" is a far more honest
        headline than "0 alerts", and the second number is only available if it
        is counted here.
        """
        by_cat = {c: 0 for c in C.CATEGORIES}
        by_sev: dict[str, int] = {}
        for v in self.verdicts:
            by_cat[v.category] = by_cat.get(v.category, 0) + 1
            if v.raises_alert:
                by_sev[v.severity] = by_sev.get(v.severity, 0) + 1
        gated: dict[str, int] = {}
        for v in self.verdicts:
            for g in v.coverage.gated_groups:
                gated[g] = gated.get(g, 0) + 1
        return {
            "n_windows": len(self.verdicts),
            "n_alerting": len(self.alerting),
            "by_category": by_cat,
            "by_severity": by_sev,
            "windows_with_group_ungradeable": gated,
            "mode": self.mode,
            "detection_version": self.detection_version,
            "ruleset_digest": self.ruleset_digest,
            "marker": self.marker,
            "notice": self.notice,
            "provenance_note": self.provenance_note,
        }


def ruleset_digest() -> str:
    """A short stable fingerprint of the rule table.

    Stamped on every run so two alerts raised weeks apart can be compared
    knowing whether the rules moved underneath them — a bumped
    RULESET_VERSION is a human promise, this is the arithmetic.
    """
    payload = "|".join(f"{f}{o}{t!r}" for f, o, t, _r in RULES)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


class DetectionEngine:
    """Applies the transparent rule baseline to observation frames.

    One engine is reusable across frames and threads-of-work: it holds only the
    validated policy and the gate decision, never per-frame state.
    """

    def __init__(self, *, cfg=None, repo=None, mode: str | None = None):
        self.cfg = cfg or load_config()
        self.policy = SeverityPolicy.from_config(self.cfg.detection)
        self.marker = str(self.cfg.detection.get("rule_marker", ""))
        self.gate = evaluate_gate(self.cfg, repo=repo, requested_mode=mode)
        # The research baseline, kept as the reference implementation of the
        # SAME rules. The engine does not consume its malicious/benign verdict —
        # `vote_threshold` (3) is the research operating point, whereas the
        # product surfaces a single vote at LOW severity rather than discarding
        # it — but it does check its own firing against this detector's vote
        # count on every frame, so the two can never silently diverge.
        self.detector = HeuristicDetector(
            vote_threshold=int(self.cfg.models.heuristic.vote_threshold))
        self._cov_cfg = self.cfg.detection.get("coverage")

    @property
    def mode(self) -> str:
        """The mode actually in force — rule, unless the gate allowed a model."""
        return self.gate.mode

    def detect_frame(self, obs: pd.DataFrame) -> DetectionResult:
        """One verdict per row of ``obs``, order preserved."""
        if self.mode == MODE_MODEL:      # pragma: no cover - gated off in this build
            raise DetectionError(
                "model mode was permitted by the gate but no validated model "
                "scoring path is built in this release; register the model and "
                "enable it explicitly")

        obs = obs.reset_index(drop=True)
        schema_problem = self._schema_problem(obs)
        if schema_problem is not None:
            return self._all_abstain(obs, schema_problem)

        feats = self._numeric_features(obs)
        covers = COV.assess_frame(feats, cov_cfg=self._cov_cfg)
        fired = self._fired_matrix(feats)
        self._check_baseline_agreement(feats, fired)

        verdicts = [self._verdict(obs, feats, i, covers[i], fired)
                    for i in range(len(obs))]
        return self._result(tuple(verdicts))

    # -- internals -------------------------------------------------------
    def _schema_problem(self, obs: pd.DataFrame) -> str | None:
        """Why this frame is not an observation frame, or ``None``.

        Only two things make a frame unreadable: no identity columns, so a
        verdict could not be attached to anything, and no feature columns at
        all, so there is nothing to evaluate. A frame missing SOME features is
        readable — those features are simply not measurable, which the coverage
        report already models correctly and honestly.
        """
        missing_meta = [c for c in _REQUIRED_META if c not in obs.columns]
        if missing_meta:
            return f"input is missing identity column(s) {missing_meta}"
        if not any(c in obs.columns for c in K.FEATURE_COLS):
            return "input carries none of the 16 feature columns"
        return None

    def _numeric_features(self, obs: pd.DataFrame) -> pd.DataFrame:
        """The feature block as floats, with absent columns present as NaN.

        Coercion is `errors="coerce"`, so a cell that does not parse becomes
        NaN — "not measurable" — rather than raising or, far worse, being
        imputed. Zero is a real value for most of these features and is the most
        suspicious one several of them can take.
        """
        data = {}
        for c in K.FEATURE_COLS:
            if c in obs.columns:
                data[c] = pd.to_numeric(obs[c], errors="coerce")
            else:
                data[c] = pd.Series(np.nan, index=obs.index, dtype="float64")
        return pd.DataFrame(data, index=obs.index)

    def _fired_matrix(self, feats: pd.DataFrame) -> dict[str, np.ndarray]:
        """Per-rule boolean firing, keyed by feature name.

        NaN compares False in every comparator, so an unmeasurable feature
        contributes no vote — the correct reading of "no evidence" and never a
        spurious one.
        """
        out: dict[str, np.ndarray] = {}
        for feat, op, thr, _reason in RULES:
            col = feats[feat]
            out[feat] = OPS[op](col, thr).fillna(False).to_numpy(dtype=bool)
        return out

    def _check_baseline_agreement(self, feats: pd.DataFrame,
                                  fired: dict[str, np.ndarray]) -> None:
        """Refuse to emit verdicts that disagree with the research baseline.

        The engine attributes each rule to a group and records its value, which
        the baseline does not; but the set of rules it counts as fired must be
        exactly the baseline's. Enforcing that at runtime — not only in a test —
        means a future edit to either side stops the product rather than
        producing alerts the published baseline would not have raised.
        """
        mine = np.zeros(len(feats), dtype=int)
        for arr in fired.values():
            mine += arr.astype(int)
        theirs = self.detector.votes(feats)
        if not np.array_equal(mine, theirs):
            bad = int(np.flatnonzero(mine != theirs)[0])
            raise DetectionError(
                "rule engine disagrees with the heuristic baseline on row "
                f"{bad} ({mine[bad]} vs {theirs[bad]} votes); the product and "
                "the research baseline must evaluate identical rules")

    def _verdict(self, obs: pd.DataFrame, feats: pd.DataFrame, i: int,
                 cover: COV.CoverageReport,
                 fired: dict[str, np.ndarray]) -> WindowVerdict:
        hits = tuple(
            RuleHit(feature=feat, group=K.GROUP_OF_FEATURE[feat], op=op,
                    threshold=float(thr), value=float(feats.at[i, feat]),
                    reason=reason)
            for feat, op, thr, reason in RULES if fired[feat][i])
        fired_groups = tuple(
            g for g in K.FEATURE_GROUPS if any(h.group == g for h in hits))
        votes = len(hits)
        n_evaluable = cover.n_rules_evaluable

        # A group that produced a hit is manifestly judgeable, whatever a raised
        # min_group_coverage would otherwise say about it. Excluding it from the
        # note stops an alert from carrying a sentence denying its own evidence.
        note = cover.note(exclude=fired_groups)
        gated = tuple(g for g in cover.gated_groups if g not in fired_groups)

        category = C.category_for_groups(fired_groups)
        if category is not None:
            reason = REASON_OK
            floor = (self.policy.combined_floor
                     if category == C.CAT_SUSPICIOUS_COMBINED else None)
            severity = self.policy.severity_for(
                votes=votes, n_groups=len(fired_groups), floor=floor)
        elif n_evaluable == 0:
            # Nothing at all could be evaluated: this is not a quiet window, it
            # is an unobserved one.
            category = C.CAT_INSUFFICIENT_TELEMETRY
            reason = REASON_NO_EVALUABLE_RULES
            severity = self.policy.default
        elif gated:
            category = C.CAT_INSUFFICIENT_TELEMETRY
            reason = REASON_COVERAGE
            severity = self.policy.default
        else:
            category = C.CAT_BENIGN_OR_NO_ALERT
            reason = REASON_OK
            severity = self.policy.default

        fraction = self.policy.vote_fraction(votes, n_evaluable)
        return WindowVerdict(
            observation_id=_cell(obs, K.OBSERVATION_ID, i),
            device_id=_cell(obs, K.DEVICE_ID, i),
            window_start=_cell(obs, K.WINDOW_START, i),
            source_dataset=_cell(obs, K.SOURCE_DATASET, i),
            category=category,
            severity=severity,
            confidence=self.policy.confidence_for(fraction),
            confidence_fraction=fraction,
            votes=votes,
            n_evaluable_rules=n_evaluable,
            fired_groups=fired_groups,
            hits=hits,
            coverage=cover,
            coverage_note=note,
            reason=reason,
            mode=self.mode,
            provenance=PROV_RULE_ENGINE,
            detection_version=RULESET_VERSION,
            marker=self.marker,
            quality_flags=_cell(obs, K.QUALITY_FLAGS, i),
        )

    def _all_abstain(self, obs: pd.DataFrame, problem: str) -> DetectionResult:
        """Abstain on every row of a frame that could not be read.

        Honours ``service.abstain_on_schema_failure`` — the same switch the
        offline scoring service uses — rather than inventing a second, divergent
        policy for the same question.
        """
        if not bool(self.cfg.service.abstain_on_schema_failure):
            raise DetectionError(
                f"{problem} and service.abstain_on_schema_failure is off")
        empty = COV.assess_window({}, cov_cfg=self._cov_cfg)
        verdicts = tuple(
            WindowVerdict(
                observation_id=_cell(obs, K.OBSERVATION_ID, i),
                device_id=_cell(obs, K.DEVICE_ID, i),
                window_start=_cell(obs, K.WINDOW_START, i),
                source_dataset=_cell(obs, K.SOURCE_DATASET, i),
                category=C.CAT_ABSTAIN, severity=self.policy.default,
                confidence=self.policy.confidence_for(0.0),
                confidence_fraction=0.0, votes=0, n_evaluable_rules=0,
                fired_groups=(), hits=(), coverage=empty,
                coverage_note=problem, reason=REASON_SCHEMA, mode=self.mode,
                provenance=PROV_RULE_ENGINE,
                detection_version=RULESET_VERSION, marker=self.marker,
                quality_flags=_cell(obs, K.QUALITY_FLAGS, i))
            for i in range(len(obs)))
        return self._result(verdicts, notice=problem)

    def _result(self, verdicts: tuple[WindowVerdict, ...],
                notice: str = "") -> DetectionResult:
        return DetectionResult(
            verdicts=verdicts, mode=self.mode, gate=self.gate,
            detection_version=RULESET_VERSION, ruleset_digest=ruleset_digest(),
            marker=self.marker, provenance_note=operational_data_note(),
            notice=notice or self.gate.notice)


def detect(obs: pd.DataFrame, *, cfg=None, repo=None,
           mode: str | None = None) -> DetectionResult:
    """Convenience wrapper: build an engine and run one frame through it."""
    return DetectionEngine(cfg=cfg, repo=repo, mode=mode).detect_frame(obs)


def _cell(df: pd.DataFrame, col: str, i: int) -> str:
    """A metadata cell as a string, or ``""`` when the column is absent.

    Verdicts are rendered and persisted as text, and a missing identity column
    has already been rejected by the schema check for every column that matters.
    """
    if col not in df.columns:
        return ""
    value = df.at[i, col]
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return ""
    return str(value)
