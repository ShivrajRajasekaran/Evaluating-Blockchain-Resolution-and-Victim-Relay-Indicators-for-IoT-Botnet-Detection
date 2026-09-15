"""
detection — the product's transparent rule engine.

    from src.detection import DetectionEngine, detect, categories as C

    result = detect(observations)                # one verdict per device-window
    for v in result.alerting:                    # the ones an analyst sees
        print(v.category, v.severity, v.explanation_with_marker)

WHAT THIS PACKAGE IS ALLOWED TO CLAIM
    Nothing about compromise. It reads device-window features derived from
    authorised local telemetry and reports which transparent rules fired, how
    broad that evidence was, and — just as importantly — which indicator groups
    the telemetry could not speak to at all. Every finding is a *suspicious
    indicator pattern requiring analyst review*, tagged
    "Rule-based detection; not ML-validated."

    ML mode exists as a gate, not as a feature. :mod:`model_gate` refuses it
    until an authorised labelled dataset and a registered, validated model are
    present, and refuses it permanently for any model whose recorded training
    provenance is synthetic.

MODULE MAP
    categories   the seven verdict names and the group -> category mapping
    coverage     what each window could be judged on (the honesty gate)
    severity     config-driven severity table and confidence bands
    model_gate   whether a model may score at all (it may not, in this build)
    engine       observations in, verdicts out

CONTAINMENT
    Pure computation over DataFrames and configuration. Nothing in this package
    opens a socket, resolves a name, reads a device or writes to a database;
    persistence is the alert layer's job. See docs/ethics-and-containment.md.
"""
from __future__ import annotations

from . import categories, coverage, model_gate, severity
from .categories import (ALERTING_CATEGORIES, CAT_ABSTAIN,
                         CAT_BENIGN_OR_NO_ALERT, CAT_INSUFFICIENT_TELEMETRY,
                         CAT_SUSPICIOUS_COMBINED, CAT_SUSPICIOUS_CONVENTIONAL,
                         CAT_SUSPICIOUS_RELAY, CAT_SUSPICIOUS_RESOLUTION,
                         CATEGORIES, category_for_groups, raises_alert)
from .coverage import CoverageReport, GroupCoverage, source_coverage
from .engine import (PROV_ML_MODEL, PROV_RULE_ENGINE, REASON_COVERAGE,
                     REASON_NO_EVALUABLE_RULES, REASON_OK, REASON_SCHEMA,
                     RULESET_VERSION, DetectionEngine, DetectionError,
                     DetectionResult, RuleHit, WindowVerdict, detect,
                     ruleset_digest)
from .model_gate import MODE_MODEL, MODE_RULE, GateDecision, evaluate_gate
from .severity import (CONFIDENCES, SEVERITIES, SeverityConfigError,
                       SeverityPolicy, max_severity)

__all__ = [
    # submodules
    "categories", "coverage", "model_gate", "severity",
    # categories
    "CATEGORIES", "ALERTING_CATEGORIES", "CAT_BENIGN_OR_NO_ALERT",
    "CAT_SUSPICIOUS_RESOLUTION", "CAT_SUSPICIOUS_RELAY",
    "CAT_SUSPICIOUS_COMBINED", "CAT_SUSPICIOUS_CONVENTIONAL",
    "CAT_INSUFFICIENT_TELEMETRY", "CAT_ABSTAIN", "category_for_groups",
    "raises_alert",
    # coverage
    "CoverageReport", "GroupCoverage", "source_coverage",
    # severity
    "SEVERITIES", "CONFIDENCES", "SeverityPolicy", "SeverityConfigError",
    "max_severity",
    # model gate
    "MODE_RULE", "MODE_MODEL", "GateDecision", "evaluate_gate",
    # engine
    "DetectionEngine", "DetectionResult", "DetectionError", "WindowVerdict",
    "RuleHit", "detect", "ruleset_digest", "RULESET_VERSION",
    "PROV_RULE_ENGINE", "PROV_ML_MODEL", "REASON_OK", "REASON_SCHEMA",
    "REASON_COVERAGE", "REASON_NO_EVALUABLE_RULES",
]
