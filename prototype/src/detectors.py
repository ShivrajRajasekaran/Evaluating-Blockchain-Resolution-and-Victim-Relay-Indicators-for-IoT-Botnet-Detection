"""
detectors.py — the three detection models benchmarked in the prototype.

    1. HeuristicDetector : transparent threshold rules on the strongest
                           indicators (the explainable baseline).
    2. RandomForest      : scikit-learn, class-weight balanced.
    3. XGBoost           : gradient boosting, scale_pos_weight for imbalance.
                           Degrades gracefully to None if xgboost isn't installed
                           yet, so the pipeline still runs.

All models expose fit(X, y) / predict(X) / predict_proba(X) so evaluate.py can
treat them uniformly.
"""
import numpy as np
from sklearn.ensemble import RandomForestClassifier

import config as C

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except Exception:                      # ImportError or broken native lib
    HAS_XGB = False


# ----------------------------------------------------------------------------
# 1. Heuristic baseline
# ----------------------------------------------------------------------------
class HeuristicDetector:
    """
    Rule-based detector. Flags a flow as malicious when it accumulates enough
    evidence across the four feature groups. Deliberately simple and readable —
    this is the 'can a human explain every decision?' baseline.
    """
    name = "Heuristic"

    def __init__(self, vote_threshold=3):
        self.vote_threshold = vote_threshold
        self._cols = None

    def fit(self, X, y=None):
        self._cols = list(X.columns)
        return self

    def _score(self, X):
        v = np.zeros(len(X), dtype=int)
        v += (X["serverlist_pull"] == 1).astype(int)
        v += (X["upnp_addportmapping"] == 1).astype(int)
        v += (X["beacon_interval"] > 20).astype(int)
        v += (X["updownlink_ratio"] > 0.7).astype(int)
        v += (X["login_burst_count"] >= 3).astype(int)
        v += (X["rc4_string_score"] > 0.5).astype(int)
        v += (X["ens_query_rate"] > 3.0).astype(int)
        return v

    def predict(self, X):
        return (self._score(X) >= self.vote_threshold).astype(int)

    def predict_proba(self, X):
        # normalise the vote count to a pseudo-probability for ROC/PR curves
        v = self._score(X).astype(float)
        p = v / 7.0
        return np.column_stack([1 - p, p])


# ----------------------------------------------------------------------------
# 2 & 3. Model factories
# ----------------------------------------------------------------------------
def make_random_forest(seed=C.RANDOM_SEED):
    return RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        class_weight="balanced",
        n_jobs=-1,
        random_state=seed,
    )


def make_xgboost(seed=C.RANDOM_SEED, scale_pos_weight=None):
    if not HAS_XGB:
        return None
    return XGBClassifier(
        n_estimators=400,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight if scale_pos_weight else 1.0,
        random_state=seed,
        n_jobs=-1,
        tree_method="hist",
    )


def build_all(seed=C.RANDOM_SEED, scale_pos_weight=None):
    """Return an ordered dict of {name: estimator} available in this env."""
    models = {
        "Heuristic": HeuristicDetector(),
        "RandomForest": make_random_forest(seed),
    }
    xgb = make_xgboost(seed, scale_pos_weight)
    if xgb is not None:
        models["XGBoost"] = xgb
    return models
