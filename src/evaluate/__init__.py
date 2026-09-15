"""
evaluate — splits, metrics, thresholds, uncertainty, experiments.

    splits.py       grouped / temporal / random splits with a LOCKED test set
    metrics.py      precision, recall, F1, ROC-AUC, FPR, confusion counts
    thresholds.py   pin every detector to a common false-positive budget
    bootstrap.py    confidence intervals, resampled BY GROUP
    experiments.py  the incremental-value protocol and its supporting runs

THREE PROTOCOL RULES, each fixing a specific way this project could mislead:

1. LOCKED TEST SET. The test split is carved off first and scored once. Model
   choice, threshold calibration and feature importance all use a separate
   validation split. Otherwise the reported number is the best of many peeks.

2. THRESHOLD MATCHING. Comparing a rule detector at "vote >= 3" against a tree
   at "p >= 0.5" compares two arbitrary constants, and the winner is partly an
   artefact of that choice. Every detector is pinned to the same FPR budget on
   validation data, then scored on the locked test set at that threshold.

3. GROUP-LEVEL BOOTSTRAP. Under a grouped split, windows from one device are
   correlated. Resampling rows independently understates the interval — which
   would make this project's null result look more decisive than the data
   supports, an error in the direction of overclaiming.
"""
