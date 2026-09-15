"""
schema/build.py — the ONE way to construct a valid observation frame.

Both producers use this: the local mock generator (Track B) and the IoT-23
adapter (Track A). Neither is allowed to assemble metadata columns by hand.

The reason is drift. Two producers writing their own `label_binary` logic, or
their own `quality_flags` strings, will agree at first and diverge after the
third edit — and the divergence shows up as an unexplained metric difference
between tracks weeks later. Everything derivable is derived here, once.

Derived automatically, never passed in:
  observation_id       deterministic from (source, scenario, device, window)
  window_seconds       the project constant
  capture_provenance   implied by source_dataset
  label_confidence     implied by source_dataset
  label_binary         implied by research_class
  n_features_missing   counted from the feature cells
  quality_flags        missing_features + proxy_features + caller's extras
"""
from __future__ import annotations

from collections.abc import Sequence

import numpy as np
import pandas as pd

from . import columns as K

# source_dataset fully determines these two. Passing them in would create a
# second place they could be set inconsistently.
_PROVENANCE_OF_SOURCE = {
    K.SOURCE_MOCK_LOCAL: K.PROV_SYNTHETIC,
    K.SOURCE_IOT23: K.PROV_REAL_CAPTURE,
    # A Zeek bundle is the SAME packets as its IoT-23 scenario, replayed locally
    # to regenerate logs the dataset does not ship. Real capture, and its labels
    # are the dataset authors' own, so both fields match SOURCE_IOT23 exactly.
    K.SOURCE_ZEEK_BUNDLE: K.PROV_REAL_CAPTURE,
    # Operational captures are real wire traffic — just unlabelled.
    **{s: K.PROV_REAL_CAPTURE for s in K.OPERATIONAL_SOURCES},
}
_CONFIDENCE_OF_SOURCE = {
    K.SOURCE_MOCK_LOCAL: K.CONF_SYNTHETIC_GROUND_TRUTH,
    K.SOURCE_IOT23: K.CONF_DATASET_ANNOTATED,
    K.SOURCE_ZEEK_BUNDLE: K.CONF_DATASET_ANNOTATED,
    # No annotator ever inspected operational telemetry: it has no label, and
    # marking it CONF_UNLABELLED is what keeps it out of any training set.
    **{s: K.CONF_UNLABELLED for s in K.OPERATIONAL_SOURCES},
}


def make_observation_id(source: str, scenario: str, device: str,
                        window_start: pd.Timestamp) -> str:
    """A deterministic, human-readable, collision-resistant row id.

    Deterministic on purpose: a UUID would make every regeneration produce a
    different CSV, which destroys byte-level reproducibility checks and makes
    diffs useless. The four components are exactly the natural key of the unit
    of analysis, so a collision means a genuine duplicate observation.
    """
    ts = pd.Timestamp(window_start).strftime("%Y%m%dT%H%M%S")
    return f"{source}|{scenario}|{device}|{ts}"


def build_observations(
    features: pd.DataFrame,
    *,
    source_dataset: str,
    device_id: Sequence[str],
    window_start: Sequence,
    research_class: Sequence[str],
    original_label: Sequence[str],
    scenario_id: str | Sequence[str],
    extra_flags: Sequence[dict[str, list[str] | None]] | None = None,
) -> pd.DataFrame:
    """Assemble a schema-valid observation frame.

    Parameters
    ----------
    features
        One row per observation. Columns not in :data:`K.FEATURE_COLS` are
        dropped; feature columns absent from the frame are created as NaN.
    source_dataset
        One of :data:`K.SOURCE_DATASETS`. Determines capture_provenance,
        label_confidence, and which features are forced to NaN.
    extra_flags
        Per-row quality flags to merge in, e.g. ``{"low_flow_count": None}``.

    Notes
    -----
    Features listed as ``unavailable`` for ``source_dataset`` are overwritten
    with NaN even if the caller supplied values. That is not defensive
    paranoia — it is the single most consequential rule in the project. A
    number in a cell the capture never recorded is fabricated evidence, and
    any importance later attributed to that feature is an artefact of whoever
    filled it in.
    """
    if source_dataset not in K.SOURCE_DATASETS:
        raise ValueError(
            f"unknown source_dataset {source_dataset!r}; "
            f"expected one of {list(K.SOURCE_DATASETS)}"
        )

    n = len(features)
    if n == 0:
        raise ValueError("cannot build an observation frame from zero rows")

    feats = features.reset_index(drop=True).copy()
    feats = feats[[c for c in feats.columns if c in K.FEATURE_COLS]]
    for c in K.FEATURE_COLS:
        if c not in feats.columns:
            feats[c] = np.nan
    feats = feats[K.FEATURE_COLS].astype("float64")

    # Enforce per-source availability. See the note in the docstring.
    unavailable = K.unavailable_features(source_dataset)
    for c in unavailable:
        feats[c] = np.nan

    device = pd.Series(list(device_id), dtype=object).reset_index(drop=True)
    starts = pd.to_datetime(pd.Series(list(window_start))).reset_index(drop=True)
    rclass = pd.Series(list(research_class), dtype=object).reset_index(drop=True)
    olabel = pd.Series(list(original_label), dtype=object).reset_index(drop=True)
    if isinstance(scenario_id, str):
        scen = pd.Series([scenario_id] * n, dtype=object)
    else:
        scen = pd.Series(list(scenario_id), dtype=object).reset_index(drop=True)

    for name, s in (("device_id", device), ("window_start", starts),
                    ("research_class", rclass), ("original_label", olabel),
                    ("scenario_id", scen)):
        if len(s) != n:
            raise ValueError(
                f"{name} has length {len(s)} but features has {n} row(s)"
            )

    # ---- derived label view ------------------------------------------------
    label_bin = np.empty(n, dtype="int64")
    for i, c in enumerate(rclass):
        if c == K.CLS_UNMAPPED:
            label_bin[i] = K.LABEL_BINARY_UNMAPPED
        else:
            label_bin[i] = K.binary_label_for(c)   # raises on anything unknown

    # ---- quality flags -----------------------------------------------------
    proxies = K.proxy_features(source_dataset)
    nan_mask = feats.isna()
    nan_arr = nan_mask.to_numpy()
    flag_strings: list[str] = []
    for i in range(n):
        flags: dict[str, list[str] | None] = {}
        if extra_flags is not None and extra_flags[i]:
            flags.update(extra_flags[i])
        missing_here = [c for j, c in enumerate(K.FEATURE_COLS) if nan_arr[i, j]]
        if missing_here:
            flags[K.FLAG_MISSING_FEATURES] = missing_here
        if proxies:
            flags[K.FLAG_PROXY_FEATURES] = list(proxies)
        if rclass.iat[i] == K.CLS_UNMAPPED:
            flags[K.FLAG_UNMAPPED_LABEL] = None
        flag_strings.append(K.make_flags(flags))

    meta = pd.DataFrame({
        K.OBSERVATION_ID: [
            make_observation_id(source_dataset, scen.iat[i], device.iat[i],
                                starts.iat[i])
            for i in range(n)
        ],
        K.DEVICE_ID: device,
        K.WINDOW_START: starts,
        K.WINDOW_SECONDS: np.full(n, K.WINDOW_SECONDS_VALUE, dtype="int64"),
        K.SOURCE_DATASET: source_dataset,
        K.SCENARIO_ID: scen,
        K.CAPTURE_PROVENANCE: _PROVENANCE_OF_SOURCE[source_dataset],
        K.RESEARCH_CLASS: rclass,
        K.ORIGINAL_LABEL: olabel,
        K.LABEL_BINARY: label_bin,
        K.LABEL_CONFIDENCE: _CONFIDENCE_OF_SOURCE[source_dataset],
        K.QUALITY_FLAGS: flag_strings,
        K.N_FEATURES_MISSING: nan_mask.sum(axis=1).to_numpy(dtype="int64"),
    })

    return pd.concat([meta, feats], axis=1)[K.ALL_COLS]
