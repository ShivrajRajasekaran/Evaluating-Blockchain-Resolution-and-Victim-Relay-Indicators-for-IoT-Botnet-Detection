"""
detection/model_gate.py — the control that keeps ML mode switched off.

WHAT THIS ENFORCES
------------------
"Never trains a model or claims accuracy unless an authorised labelled dataset
is supplied." That sentence is a policy until something refuses to run, so this
module is the refusal. Every path that could put a model's output in front of
an analyst passes through :func:`evaluate_gate` first, and the gate answers with
a decision plus the reasons behind it — reasons that are shown in the UI, not
swallowed.

The gate is deliberately a WHITELIST: it starts at "refused" and requires every
condition to be positively satisfied. A missing database, an empty registry, a
model row with a NULL threshold and an unreachable config key all land in the
same place — rule mode, with an explanation. There is no code path in which an
unexamined model scores anything.

THE CONDITIONS
--------------
1.  detection.model.enabled must be true. It ships false.
2.  A model registry must be reachable (the product may be running before the
    database exists at all).
3.  At least one detection_models row must be kind='ml' AND is_validated=1.
4.  That row must record where its training data came from — and that
    provenance must not be synthetic. This project HAS a synthetic track, whose
    generator exists to characterise the pipeline, not to produce a production
    detector. A model trained on it would report a number that measures the
    generator's assumptions; presenting that as operational accuracy is the
    precise failure this gate exists to prevent.
5.  Validation metrics, a calibrated threshold, and a feature schema matching
    the product's own must each be present when their config flag requires them
    (all three default to required).

Failing any of these is NOT an error. It is the expected state of this build,
and the product continues in transparent rule mode with the notice attached.

CONTAINMENT
    Reads configuration and, if given one, a local repository. No network, no
    filesystem, no model loading — the gate decides whether loading is even
    permissible, and in this build the answer is always no.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from src.schema import columns as K

MODE_RULE = "rule"
MODE_MODEL = "model"
MODES: tuple[str, ...] = (MODE_RULE, MODE_MODEL)

# Substrings in a model's recorded training provenance that disqualify it from
# operational use outright. Matched case-insensitively against the free-text
# provenance column.
_SYNTHETIC_MARKERS: tuple[str, ...] = ("synthetic", "mock", "generated")


@dataclass(frozen=True)
class GateDecision:
    """Whether model mode may be used, and why not when it may not."""

    mode: str
    allowed: bool
    reasons: tuple[str, ...] = ()
    model_id: int | None = None
    model_version: str | None = None
    notice: str = ""

    @property
    def refused(self) -> bool:
        return not self.allowed

    def as_dict(self) -> dict:
        return {
            "mode": self.mode,
            "allowed": self.allowed,
            "reasons": list(self.reasons),
            "model_id": self.model_id,
            "model_version": self.model_version,
            "notice": self.notice,
        }


def _notice(reasons: tuple[str, ...], rule_marker: str) -> str:
    """The sentence shown wherever a model result would otherwise appear."""
    why = "; ".join(reasons) if reasons else "model mode is not available"
    return (f"ML-based detection is not active: {why}. Detection ran in "
            f"transparent rule mode. {rule_marker}")


def evaluate_gate(cfg, *, repo=None, requested_mode: str | None = None,
                  feature_names=None) -> GateDecision:
    """Decide whether this run may use a model. Defaults to refusing.

    ``repo`` is a :class:`src.storage.Repository` or ``None``; passing ``None``
    is normal (scripts and tests detect without a database) and simply means
    there is no registry to satisfy condition 3.
    """
    detection = cfg.detection
    rule_marker = str(detection.get("rule_marker", ""))
    configured = str(detection.get("mode", MODE_RULE))
    wanted = requested_mode or configured
    if wanted not in MODES:
        raise ValueError(f"unknown detection mode {wanted!r}; "
                         f"expected one of {list(MODES)}")

    if wanted == MODE_RULE:
        # Nothing to gate: the rule baseline is always available and needs no
        # trained artefact. It is tagged as not ML-validated wherever it shows.
        return GateDecision(mode=MODE_RULE, allowed=True)

    reasons = tuple(_refusal_reasons(detection, repo, feature_names))
    if reasons:
        return GateDecision(mode=MODE_RULE, allowed=False, reasons=reasons,
                            notice=_notice(reasons, rule_marker))

    model = _candidate(repo)
    return GateDecision(mode=MODE_MODEL, allowed=True, model_id=model.id,
                        model_version=model.version)


def _refusal_reasons(detection, repo, feature_names) -> list[str]:
    """Every reason model mode cannot run, in the order they are checked."""
    model_cfg = detection.get("model")
    if model_cfg is None:
        return ["no detection.model configuration block is present"]
    if not bool(model_cfg.get("enabled", False)):
        return ["model mode is disabled in configuration "
                "(detection.model.enabled = false)"]
    if repo is None:
        return ["no model registry is available in this context"]

    model = _candidate(repo)
    if model is None:
        return ["no registered detection model is marked validated; a model "
                "becomes available only once an authorised labelled dataset "
                "has been supplied and the resulting model registered"]

    reasons: list[str] = []
    provenance = (model.training_provenance or "").strip()
    if not provenance:
        reasons.append(f"model {model.version!r} does not record where its "
                       "training data came from")
    elif any(m in provenance.lower() for m in _SYNTHETIC_MARKERS):
        reasons.append(
            f"model {model.version!r} records synthetic training provenance "
            f"({provenance!r}); a model trained on generated data measures the "
            "generator's assumptions and is never presented as operational")

    if bool(model_cfg.get("require_validation_metrics", True)) and \
            not _has_json(model.validation_metrics_json):
        reasons.append(f"model {model.version!r} carries no validation metrics")

    if bool(model_cfg.get("require_calibrated_threshold", True)) and \
            model.calibrated_threshold is None:
        reasons.append(
            f"model {model.version!r} has no calibrated decision threshold")

    if bool(model_cfg.get("require_schema_match", True)):
        mismatch = _schema_mismatch(model, feature_names)
        if mismatch:
            reasons.append(mismatch)
    return reasons


def _candidate(repo):
    """The newest validated ML model, or ``None``.

    Tolerant of a repository that predates the models accessor so the gate
    refuses rather than raising on an older database.
    """
    if repo is None:
        return None
    models = getattr(repo, "models", None)
    if models is None or not hasattr(models, "validated_ml_models"):
        return None
    rows = models.validated_ml_models()
    return rows[0] if rows else None


def _has_json(raw: str | None) -> bool:
    """Whether a JSON column holds something an auditor could actually read."""
    if not raw or not str(raw).strip():
        return False
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return False
    return bool(parsed)


def _schema_mismatch(model, feature_names) -> str | None:
    """Why the model's feature schema does not match ours, or ``None``.

    A model scored against a differently-ordered or differently-populated
    feature vector produces numbers that look plausible and mean nothing, so the
    comparison is exact on both membership and order.
    """
    expected = list(feature_names) if feature_names else list(K.FEATURE_COLS)
    raw = model.feature_schema_json
    if not raw or not str(raw).strip():
        return f"model {model.version!r} records no feature schema"
    try:
        declared = json.loads(raw)
    except (TypeError, ValueError):
        return f"model {model.version!r} has an unreadable feature schema"
    if isinstance(declared, dict):
        declared = declared.get("features", [])
    if not isinstance(declared, list):
        return f"model {model.version!r} has a feature schema of unexpected shape"
    if list(declared) != expected:
        missing = [c for c in expected if c not in declared]
        extra = [c for c in declared if c not in expected]
        detail = []
        if missing:
            detail.append(f"missing {missing}")
        if extra:
            detail.append(f"unexpected {extra}")
        if not detail:
            detail.append("feature order differs")
        return (f"model {model.version!r} feature schema does not match the "
                f"product's ({'; '.join(detail)})")
    return None
