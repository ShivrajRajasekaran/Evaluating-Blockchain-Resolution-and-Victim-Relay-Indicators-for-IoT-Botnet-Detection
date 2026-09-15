"""
models/trees.py — the two learned detectors, behind the same interface.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

RandomForest and XGBoost, with hyperparameters read from ``configs`` (never
hard-coded here) so a run's model settings travel with the run's config file.
Both are wrapped in one thin adapter, ``_TreeDetector``, that gives them the
same fit / predict / predict_proba contract as the heuristic and pins two
things the raw estimators leave loose:

  * COLUMN ORDER. The adapter records the training column order and reindexes
    every later matrix to it. The incremental experiment fits the SAME model
    class on many feature subsets; a caller passing columns in a different
    order would otherwise get silently wrong predictions with no error.

  * NaN POLICY. Default is to RAISE, naming the offending columns — not to
    impute. Imputing a "not measurable" NaN to 0.0 turns absence of evidence
    into the most malicious-looking value a feature can take (jitter 0.0 =
    perfectly periodic). Track B, the headline experiment, has no NaN at all;
    the cross-track FPR run (real benign traffic, where novel features are
    genuinely absent) abstains on incomplete rows in the service layer BEFORE
    the model sees them. So the model itself never needs to guess, and a NaN
    reaching it means an upstream bug worth stopping for. Both trees keep the
    same policy so the comparison between them is on identical inputs.

XGBOOST DEGRADES TO ABSENT
--------------------------
On Windows the XGBoost native library is the most fragile dependency in the
stack. A failed import must not take the pipeline down: :func:`xgboost_available`
reports the truth and :func:`make_xgboost` raises a clear, catchable error, so
the registry can simply omit XGBoost and every other detector still runs.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.config import load_config


class ModelUnavailableError(RuntimeError):
    """A model's backing library is not importable in this environment."""


class NaNInFeaturesError(ValueError):
    """A feature matrix carried NaN where a complete matrix was required."""


NAN_RAISE = "raise"
NAN_ALLOW = "allow"   # trust the estimator's native handling (XGBoost only)


def xgboost_available() -> bool:
    """True if XGBoost can be imported here. Cheap, so callers can gate on it."""
    try:
        import xgboost  # noqa: F401
        return True
    except Exception:
        return False


class _TreeDetector:
    """Uniform wrapper over an sklearn-style classifier.

    Holds the estimator, its display ``name``, and — after fit — the training
    column order, so predictions are always taken on the same layout the model
    learned. ``predict_proba`` returns the sklearn-shaped ``(n, 2)`` array;
    callers take column 1 (via :func:`src.models.registry.positive_score`) as
    the malicious-class score fed to thresholding.
    """

    def __init__(self, estimator, name: str, *, nan_policy: str = NAN_RAISE):
        self.estimator = estimator
        self.name = name
        self.nan_policy = nan_policy
        self.feature_names_: list[str] | None = None

    # -- internals ---------------------------------------------------------
    def _check_nan(self, X: pd.DataFrame) -> None:
        if self.nan_policy == NAN_ALLOW:
            return
        na_cols = [c for c in X.columns if X[c].isna().any()]
        if na_cols:
            raise NaNInFeaturesError(
                f"{self.name}: feature matrix has NaN in {na_cols}. This model "
                "requires complete rows; a NaN means 'not measurable' and must "
                "not be imputed to a number. Drop or abstain on incomplete rows "
                "upstream (see src/services/score.py) before scoring.")

    def _align(self, X: pd.DataFrame) -> pd.DataFrame:
        if self.feature_names_ is None:
            return X
        missing = [c for c in self.feature_names_ if c not in X.columns]
        if missing:
            raise ValueError(
                f"{self.name}: matrix is missing trained feature(s) {missing}")
        # Reindex to the exact trained order; ignore any extra columns.
        return X[self.feature_names_]

    # -- contract ----------------------------------------------------------
    def fit(self, X: pd.DataFrame, y) -> "_TreeDetector":
        if not isinstance(X, pd.DataFrame):
            raise TypeError(f"{self.name}.fit expects a DataFrame, not "
                            f"{type(X).__name__}")
        self.feature_names_ = list(X.columns)
        self._check_nan(X)
        self.estimator.fit(X, np.asarray(y).astype(int))
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        Xa = self._align(X)
        self._check_nan(Xa)
        return self.estimator.predict(Xa).astype(int)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        Xa = self._align(X)
        self._check_nan(Xa)
        return np.asarray(self.estimator.predict_proba(Xa), float)

    def feature_importances_gain(self) -> np.ndarray | None:
        """Impurity/gain importances if the estimator exposes them.

        Reported only for contrast — gain importance is computed on training
        data and biased toward continuous, high-cardinality features. The
        finding-grade importance is permutation importance on validation (see
        src/evaluate and docs/evaluation-protocol.md); this is never cited as a
        result on its own.
        """
        imp = getattr(self.estimator, "feature_importances_", None)
        return None if imp is None else np.asarray(imp, float)


def make_random_forest(cfg=None, *, seed: int = 42,
                       nan_policy: str = NAN_RAISE) -> _TreeDetector:
    """RandomForest detector configured from ``cfg.models.random_forest``."""
    from sklearn.ensemble import RandomForestClassifier

    cfg = cfg or load_config()
    rf = cfg.models.random_forest
    est = RandomForestClassifier(
        n_estimators=rf.n_estimators,
        max_depth=rf.get("max_depth", None),   # yaml null -> None
        class_weight=rf.get("class_weight", "balanced"),
        random_state=seed,
        n_jobs=-1,
    )
    return _TreeDetector(est, "RandomForest", nan_policy=nan_policy)


def make_xgboost(cfg=None, *, seed: int = 42,
                 nan_policy: str = NAN_RAISE) -> _TreeDetector:
    """XGBoost detector configured from ``cfg.models.xgboost``.

    Raises :class:`ModelUnavailableError` if XGBoost cannot be imported, so the
    registry can omit it cleanly rather than crash. ``nan_policy`` defaults to
    ``raise`` — matching RandomForest — so the two trees are compared on
    identical complete inputs; XGBoost's native NaN handling is available via
    ``nan_policy="allow"`` when a caller deliberately wants it.
    """
    if not xgboost_available():
        raise ModelUnavailableError(
            "xgboost is not importable in this environment; the registry will "
            "omit it and the remaining detectors will still run")
    from xgboost import XGBClassifier

    cfg = cfg or load_config()
    xg = cfg.models.xgboost
    est = XGBClassifier(
        n_estimators=xg.n_estimators,
        max_depth=xg.max_depth,
        learning_rate=xg.learning_rate,
        subsample=xg.get("subsample", 0.9),
        colsample_bytree=xg.get("colsample_bytree", 0.9),
        tree_method="hist",
        eval_metric="logloss",
        random_state=seed,
        n_jobs=-1,
        verbosity=0,
    )
    return _TreeDetector(est, "XGBoost", nan_policy=nan_policy)
