"""
Evaluating Blockchain-Resolution and Victim-Relay Indicators for IoT Botnet
Detection — defensive detection research pipeline.

SCOPE (binding — see docs/ethics-and-containment.md)
    This package builds detection, analysis, measurement and visualisation code
    only. It does not create, operate or improve any attack capability, sends no
    packets, opens no listening socket, contacts no external service, and
    resolves no blockchain or DNS name. All "mock" data is numeric event
    metadata generated locally.

LAYOUT
    src/schema      the observation data model and its validator (start here)
    src/ingest      producers: local mock generator (Track B), IoT-23 (Track A)
    src/features    windowing and feature derivation from flow records
    src/models      detectors: heuristic baseline, RandomForest, XGBoost
    src/evaluate    splits, metrics, thresholds, bootstrap, experiments
    src/reports     tables, figures and generated documentation
    src/services    offline scoring service (local CSV in, local CSV out)
"""

__version__ = "1.0.0"
PROJECT_TITLE = (
    "Evaluating Blockchain-Resolution and Victim-Relay Indicators "
    "for IoT Botnet Detection"
)
