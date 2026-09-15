"""
models — the three detectors, behind one interface.

    heuristic.py    transparent threshold-vote rules; the explainable baseline
    trees.py        RandomForest and XGBoost factories
    registry.py     build_all() / by_name(), so callers never import a concrete
                    model class

All detectors expose fit(X, y) / predict(X) / predict_proba(X) on pandas
DataFrames, so the evaluation code treats them uniformly and the heuristic can
still address its columns by name.

XGBoost degrades to absent rather than crashing: on Windows its native library
is the most fragile dependency in the stack, and a broken import must not take
the whole pipeline down with it.
"""
