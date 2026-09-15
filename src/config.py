"""
config.py — paths and the YAML-backed configuration object.

Split of responsibility, kept strict on purpose:

  src/schema/columns.py   WHAT a column means. Not tunable. Changing it changes
                          the meaning of stored data, so it lives in code where
                          a diff is visible in review.
  configs/*.yaml          WHAT NUMBER to use. Tunable. Changing it changes a
                          result, so it lives in a file that can be attached to
                          a result for provenance.
  src/config.py (here)    the bridge, plus filesystem layout.

Access is attribute-style and fails loudly on typos:

    from src.config import load_config
    cfg = load_config()
    cfg.evaluation.target_fpr      -> 0.01
    cfg.evaluation.target_fpr_typo -> ConfigError, not None
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Filesystem layout
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]          # -> Entreprise/

CONFIG_DIR = ROOT / "configs"
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"                # untouched inputs (never written to)
PROCESSED_DIR = DATA_DIR / "processed"    # schema-valid observation frames
RESULTS_DIR = ROOT / "results"
TABLE_DIR = RESULTS_DIR / "tables"
FIGURE_DIR = RESULTS_DIR / "figures"
MODEL_DIR = RESULTS_DIR / "models"
REPORT_DIR = RESULTS_DIR / "reports"
DOCS_DIR = ROOT / "docs"

DEFAULT_CONFIG = CONFIG_DIR / "default.yaml"

# Canonical processed-dataset paths. Two files, never one — the filenames are
# the first line of defence against pooling the tracks by accident.
TRACK_B_MOCK_CSV = PROCESSED_DIR / "track_b_mock_observations.csv"
TRACK_A_IOT23_CSV = PROCESSED_DIR / "track_a_iot23_observations.csv"

_OUTPUT_DIRS = (
    RAW_DIR, PROCESSED_DIR, TABLE_DIR, FIGURE_DIR, MODEL_DIR, REPORT_DIR,
)


def ensure_dirs() -> None:
    """Create output directories. Called by every entry point, not at import —
    importing a module should not have filesystem side effects."""
    for d in _OUTPUT_DIRS:
        d.mkdir(parents=True, exist_ok=True)


class ConfigError(KeyError):
    """Raised on access to a configuration key that does not exist."""


class ConfigNode:
    """Read-only attribute view over a nested dict.

    Attribute access rather than ``cfg["evaluation"]["target_fpr"]`` because a
    mistyped string key returns a KeyError deep inside a computation, whereas a
    mistyped attribute fails at the point of use with the available keys listed.
    """

    __slots__ = ("_data", "_path")

    def __init__(self, data: dict[str, Any], path: str = ""):
        self._data = data
        self._path = path

    def __getattr__(self, name: str) -> Any:
        if name not in self._data:
            where = self._path or "<root>"
            raise ConfigError(
                f"no config key {name!r} under {where}; "
                f"available: {sorted(self._data)}"
            )
        value = self._data[name]
        if isinstance(value, dict):
            return ConfigNode(value, f"{self._path}.{name}".lstrip("."))
        return value

    def __getitem__(self, name: str) -> Any:
        return self.__getattr__(name)

    def __contains__(self, name: str) -> bool:
        return name in self._data

    def get(self, name: str, default: Any = None) -> Any:
        return self._data.get(name, default)

    def keys(self):
        return self._data.keys()

    def as_dict(self) -> dict[str, Any]:
        """Deep copy, safe to mutate. Used when recording a config alongside a
        result so the result can be reproduced later."""
        import copy
        return copy.deepcopy(self._data)

    def __repr__(self) -> str:
        return f"ConfigNode({self._path or '<root>'}: {sorted(self._data)})"


_CACHE: dict[str, ConfigNode] = {}


def load_config(path: str | Path | None = None, *, use_cache: bool = True) -> ConfigNode:
    """Load a YAML config. Defaults to ``configs/default.yaml``."""
    p = Path(path) if path is not None else DEFAULT_CONFIG
    key = str(p.resolve())
    if use_cache and key in _CACHE:
        return _CACHE[key]
    if not p.exists():
        raise FileNotFoundError(f"config file not found: {p}")
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ConfigError(f"{p} did not parse to a mapping")
    node = ConfigNode(data)
    _CACHE[key] = node
    return node


def provenance_note(cfg: ConfigNode | None = None) -> str:
    """The disclaimer string attached to every synthetic-derived artefact.

    Kept here so it is impossible for one table to carry a softer wording than
    another. Any result touching Track B carries this verbatim.
    """
    return (
        "SYNTHETIC (Track B): produced from locally generated mock observations. "
        "No packets were captured, sent, or forwarded; no real device, C2 "
        "endpoint, blockchain name, or RPC service was contacted. These numbers "
        "characterise the detection pipeline under the generator's assumptions "
        "and are NOT evidence of real-world detection performance."
    )


def real_data_note() -> str:
    """The disclaimer for Track A artefacts."""
    return (
        "REAL CAPTURE (Track A): derived from a locally held IoT-23 Zeek "
        "conn.log.labeled. Labels are the dataset authors' annotations, not "
        "independently verified. IoT-23 predates blockchain-anchored C2 and "
        "contains no blockchain-resolution or victim-relay behaviour, so these "
        "numbers measure false alarms on real benign IoT traffic and "
        "conventional-botnet separability — NOT this project's thesis."
    )


def operational_data_note() -> str:
    """The disclaimer for operational (product-ingest) artefacts.

    Kept beside the two research notes for the same reason they are: one home,
    so no producer can quietly attach a softer wording. This is the string every
    operational observation frame and alert carries, and it encodes the two
    facts the security posture depends on — the telemetry is unlabelled, and any
    finding is a rule-based indicator for review, never a confirmed incident.
    """
    return (
        "OPERATIONAL CAPTURE: derived from authorised local telemetry placed in "
        "the product's input directory or uploaded by an authenticated user. The "
        "traffic is real but UNLABELLED — no ground truth exists — so every "
        "window is review-only and no class is confirmed. Any resulting alert is "
        "a suspicious indicator pattern requiring analyst review, produced by "
        "transparent rules; it is rule-based and not ML-validated."
    )
