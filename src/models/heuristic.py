"""
models/heuristic.py — the transparent, rule-voting baseline.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

WHY A RULE DETECTOR AT ALL
--------------------------
It is the "can a human explain every alert?" baseline the tree models are
measured against. Its rules and thresholds are carried over UNCHANGED from the
prototype so the enterprise build's numbers stay comparable to the published
ones — re-tuning them would silently move the baseline and make the comparison
meaningless.

TWO ROBUSTNESS PROPERTIES the prototype did not need, but this build does:

  * MISSING COLUMNS. The incremental-value experiment fits detectors on feature
    SUBSETS ("base only" has no resolution or relay columns). A rule whose column
    is absent contributes no vote and is not counted in the denominator, so the
    detector degrades to "the rules it can still evaluate" instead of raising.

  * NaN AS NO-EVIDENCE. On real captures a feature can be NaN (not measurable).
    A comparison against NaN is False, so the rule simply does not fire — the
    correct reading of "no evidence", never a spurious vote. A NaN is never
    imputed to a number here; doing so (e.g. jitter NaN -> 0.0) would turn "not
    measurable" into the most malicious-looking value the feature can take.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.schema import columns as K

# Each rule is (feature, comparator, threshold, human-readable reason).
# The comparator is applied as `feature <op> threshold`; NaN compares False.
# These are the prototype's published rules, verbatim in threshold and column.
_RULES: tuple[tuple[str, str, float, str], ...] = (
    ("serverlist_pull",     ">=", 1.0, "server-list pull seen after resolution"),
    ("upnp_addportmapping", ">=", 1.0, "UPnP AddPortMapping observed"),
    ("beacon_interval",     ">",  20.0, "periodic beacon rhythm > 20s"),
    ("updownlink_ratio",    ">",  0.7, "up/down byte symmetry near 1 (relay-like)"),
    ("login_burst_count",   ">=", 3.0, "Telnet/SSH login burst"),
    ("rc4_string_score",    ">",  0.5, "RC4-like payload string score"),
    ("ens_query_rate",      ">",  3.0, "high blockchain-name query rate"),
)

_OPS = {
    ">":  lambda s, t: s > t,
    ">=": lambda s, t: s >= t,
    "<":  lambda s, t: s < t,
    "<=": lambda s, t: s <= t,
}

# Public, read-only view of the rule table and comparators. The operational
# product's rule engine (src/detection) evaluates the SAME rules so its alerts
# and this baseline never diverge in threshold or column; it must not re-declare
# them. Exposing the tuple changes nothing here — the thresholds stay verbatim.
RULES = _RULES
OPS = _OPS


class HeuristicDetector:
    """Flags a device-window malicious when enough rules fire.

    ``vote_threshold`` is the number of rules that must agree. It comes from
    ``configs`` (``models.heuristic.vote_threshold``), the one tunable here; the
    rules themselves are fixed in code because they define the baseline rather
    than parameterise a result.
    """

    name = "Heuristic"
    # A NaN feature compares False in every rule, i.e. it is read as "no
    # evidence" rather than crashing. The detection service inspects this flag to
    # decide whether a not-measurable feature can be scored at all (a tree cannot
    # consume NaN, and imputing one is forbidden).
    tolerates_nan = True

    def __init__(self, vote_threshold: int = 3):
        self.vote_threshold = int(vote_threshold)
        self.active_rules_: list[tuple[str, str, float, str]] = []

    def fit(self, X: pd.DataFrame, y=None) -> "HeuristicDetector":
        # "Fitting" a rule detector only records which rules are evaluable given
        # the columns present, so predict/predict_proba agree on the denominator.
        self.active_rules_ = [r for r in _RULES if r[0] in X.columns]
        return self

    def _require_fit(self, X: pd.DataFrame) -> None:
        if not self.active_rules_:
            # Allow predict without an explicit fit by inferring active rules,
            # so the detector is usable as a bare object in a quick check.
            self.active_rules_ = [r for r in _RULES if r[0] in X.columns]

    def votes(self, X: pd.DataFrame) -> np.ndarray:
        """Integer vote count per row over the rules evaluable on ``X``."""
        self._require_fit(X)
        v = np.zeros(len(X), dtype=int)
        for feat, op, thr, _reason in self.active_rules_:
            col = pd.to_numeric(X[feat], errors="coerce")
            v += _OPS[op](col, thr).fillna(False).astype(int).to_numpy()
        return v

    def n_active_rules(self) -> int:
        return len(self.active_rules_)

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return (self.votes(X) >= self.vote_threshold).astype(int)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Pseudo-probability = fraction of evaluable rules that fired.

        Normalised by the number of ACTIVE rules, not a hard-coded 7, so a
        feature-subset run still yields scores in [0, 1]. ROC-AUC is invariant to
        this monotone rescaling; the normalisation only keeps the score
        interpretable and comparable across subsets. Note the score is coarse —
        with k active rules it takes only k+1 distinct values — which is why
        detector comparison uses threshold matching, not AUC (see
        docs/evaluation-protocol.md).
        """
        self._require_fit(X)
        denom = max(1, self.n_active_rules())
        p = self.votes(X).astype(float) / denom
        return np.column_stack([1.0 - p, p])

    def explain(self, X: pd.DataFrame) -> list[list[str]]:
        """Per-row list of the human-readable reasons that fired.

        The reason a rule detector earns its place: every alert can be shown as
        the exact conditions that produced it. Used by the detection service's
        report and the mentor demo.
        """
        self._require_fit(X)
        reasons: list[list[str]] = [[] for _ in range(len(X))]
        for feat, op, thr, reason in self.active_rules_:
            col = pd.to_numeric(X[feat], errors="coerce")
            fired = _OPS[op](col, thr).fillna(False).to_numpy()
            for i in np.flatnonzero(fired):
                reasons[i].append(reason)
        return reasons
