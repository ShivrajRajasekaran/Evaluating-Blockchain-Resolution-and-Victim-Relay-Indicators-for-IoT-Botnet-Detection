"""
models/registry.py — construct detectors by name, without importing classes.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

Callers (the incremental experiment, the model-comparison table, the detection
service) ask for detectors by name and never import a concrete model class.
That keeps one list — here — of what "all detectors" means, and lets XGBoost
drop out of that list silently when its library is missing, without any caller
knowing or caring.

``positive_score`` is the single place the "column 1 is the malicious class"
convention lives. Every threshold, metric and bootstrap call takes its 1-D
score from here, so a detector whose ``predict_proba`` column order differed
could never quietly invert a result.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.config import load_config
from src.models.heuristic import HeuristicDetector
from src.models import trees

# The canonical detector names, in report order (baseline first).
HEURISTIC = "Heuristic"
RANDOM_FOREST = "RandomForest"
XGBOOST = "XGBoost"
ALL_NAMES = (HEURISTIC, RANDOM_FOREST, XGBOOST)


def by_name(name: str, cfg=None, *, seed: int = 42, **kwargs):
    """Build one detector by canonical name.

    Raises for an unknown name, and re-raises
    :class:`~src.models.trees.ModelUnavailableError` for XGBoost when its
    library is missing — a caller wanting graceful omission uses
    :func:`build_all` instead.
    """
    cfg = cfg or load_config()
    if name == HEURISTIC:
        return HeuristicDetector(
            vote_threshold=cfg.models.heuristic.vote_threshold)
    if name == RANDOM_FOREST:
        return trees.make_random_forest(cfg, seed=seed, **kwargs)
    if name == XGBOOST:
        return trees.make_xgboost(cfg, seed=seed, **kwargs)
    raise ValueError(f"unknown detector {name!r}; known: {ALL_NAMES}")


def build_all(cfg=None, *, seed: int = 42, include_heuristic: bool = True,
              **kwargs) -> dict:
    """Build every available detector, keyed by name, in report order.

    XGBoost is omitted (with no error) when its library is unimportable, so a
    machine without a working XGBoost still produces a complete Heuristic +
    RandomForest comparison. The omission is discoverable: the returned dict's
    keys are exactly the detectors that will run.
    """
    cfg = cfg or load_config()
    built: dict = {}
    if include_heuristic:
        built[HEURISTIC] = by_name(HEURISTIC, cfg)
    built[RANDOM_FOREST] = by_name(RANDOM_FOREST, cfg, seed=seed, **kwargs)
    if trees.xgboost_available():
        built[XGBOOST] = by_name(XGBOOST, cfg, seed=seed, **kwargs)
    return built


def positive_score(detector, X: pd.DataFrame) -> np.ndarray:
    """Malicious-class probability as a 1-D array, for thresholding.

    The one place the ``predict_proba``-column-1 convention is applied. A
    single-column proba (a degenerate model that saw one class in training) is
    handled: its only column is returned as-is rather than indexed out of range.
    """
    p = np.asarray(detector.predict_proba(X), float)
    if p.ndim == 1:
        return p
    if p.shape[1] == 1:
        return p[:, 0]
    return p[:, 1]
