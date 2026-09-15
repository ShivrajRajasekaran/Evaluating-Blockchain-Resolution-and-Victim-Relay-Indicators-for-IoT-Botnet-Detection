"""
ingest/zeek_bundle.py — the adapter that makes this project's thesis measurable.

WHAT IS DIFFERENT ABOUT THIS ADAPTER
    ``ingest/iot23.py`` reads one file: conn.log.labeled. It is correct and it is
    limited by its input — a connection record cannot say what name was resolved
    or which server a TLS session asked for, so four of the sixteen features are
    NaN for every row it produces and the two resolution alert categories can
    never fire.

    This adapter reads a DIRECTORY: conn.log.labeled for flows and ground truth,
    plus the dns.log, http.log and ssl.log regenerated from the same capture by
    scripts/run_zeek.py. Those three carry the resolution and relay evidence, so
    on this source ``unavailable_features()`` returns exactly one entry
    (rc4_string_score, which needs plaintext payload) instead of five.

TWO SOURCES OF TRUTH, JOINED BY TIME NOT BY UID
    The labels live in the conn.log.labeled the dataset ships. The app-layer logs
    come from a local Zeek run. Zeek mints fresh uids on every run, so the two
    cannot be joined by uid and must not be. They do not need to be: both carry a
    timestamp and an originating address, which is precisely the
    (device, 300 s window) key every feature in this project is defined over.
    Records are floored onto the same grid and aggregated per device-window.

WHAT IS REUSED, VERBATIM
    Device identification, the device-relative orientation transform, label
    resolution and windowing all come from ingest.iot23 and features.windowing
    unchanged. There is one home for "which end is the device" and this adapter
    does not fork it. Only the app-layer half is new.

CONTAINMENT
    Reads local log files, returns a DataFrame. No socket is opened, no name is
    resolved, no packet is sent. The RPC-gateway hostnames in the configuration
    are compared as strings against captured fields; none is ever contacted.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from src import config as cfg_mod
from src.config import load_config, real_data_note
from src.features import applayer as A
from src.features import derive as D
from src.features import windowing as W
from src.schema import assert_valid, build_observations, write_observations
from src.schema import columns as K

from . import zeek
# One home for orientation, device identification and label resolution.
from .iot23 import (IoT23Error, REQUIRED_FIELDS, OPTIONAL_FIELDS, Z_LABEL,
                    Z_DETAILED_LABEL, Z_DETAILED_LABEL_ALT, _class_of_raw,
                    _label_columns, identify_devices, normalise_orientation,
                    resolve_window_labels)
from . import iot23_labels as L

SOURCE = K.SOURCE_ZEEK_BUNDLE

# The labelled connection log, as IoT-23 ships it inside each scenario folder.
LABELLED_CONN = Path("bro") / "conn.log.labeled"


class BundleError(ValueError):
    """A Zeek bundle could not be turned into observations."""


def _find_labelled_conn(scenario_dir: Path) -> Path:
    """Locate conn.log.labeled inside a scenario folder.

    Looked up rather than assumed: the Somfy captures nest one level deeper, and
    guessing a fixed path would fail on them for no good reason.
    """
    direct = scenario_dir / LABELLED_CONN
    if direct.exists():
        return direct
    found = sorted(scenario_dir.rglob("conn.log.labeled"))
    if not found:
        raise BundleError(
            f"no conn.log.labeled under {scenario_dir}. This adapter needs the "
            "dataset's labelled connection log for ground truth; the Zeek "
            "bundle alone carries no labels.")
    return found[0]


# ===========================================================================
# Pipeline
# ===========================================================================
def ingest(bundle_dir: str | Path, scenario_dir: str | Path, *,
           scenario_id: str, device_ips: list[str] | None = None,
           max_flows: int | None = None,
           config_path: str | Path | None = None
           ) -> tuple[pd.DataFrame, dict]:
    """Build one observation frame from a Zeek bundle plus its labelled conn log.

    ``bundle_dir``   directory of regenerated logs (conn/dns/http/ssl)
    ``scenario_dir`` the original IoT-23 scenario folder, for conn.log.labeled

    Returns ``(observations, report)``. Nothing is written; the CLI does that.
    """
    cfg = load_config(config_path)
    params = D.DeriveParams.from_config(cfg.iot23)
    res_params = A.ResolutionParams.from_config(cfg.resolution)

    bundle_dir = Path(bundle_dir)
    scenario_dir = Path(scenario_dir)
    labelled = _find_labelled_conn(scenario_dir)

    # ---- flows and ground truth, from the dataset's own labelled log --------
    header = zeek.read_header(labelled)
    missing = [f for f in REQUIRED_FIELDS if f not in header.fields]
    if missing:
        raise BundleError(
            f"{labelled.name} does not declare required Zeek field(s) {missing}")
    # A fused field carries the labels inside it, so match on the names it
    # CONTAINS rather than on the column name itself.
    def _wanted(field: str) -> bool:
        names = field.split() or [field]
        return any(n in REQUIRED_FIELDS or n in OPTIONAL_FIELDS
                   or n in (Z_LABEL, Z_DETAILED_LABEL, Z_DETAILED_LABEL_ALT)
                   for n in names)

    usecols = [f for f in header.fields if _wanted(f)]

    raw, header, stats = zeek.read_log(labelled, usecols=usecols,
                                       max_rows=max_flows)
    if raw.empty:
        raise BundleError(f"{labelled.name} yielded no readable rows")

    # IoT-23 appends its label columns with SPACES rather than tabs, so they
    # arrive fused into one field named "tunnel_parents   label   detailed-label".
    # Tab count matches field count, so nothing upstream notices. Split them back
    # out before anything looks for a column called "label".
    raw = zeek.split_combined_fields(raw)

    coarse, detail = _label_columns(raw)
    raw = raw.assign(
        _flow_class=[L.map_flow_label(a, b) for a, b in zip(coarse, detail)],
        _raw_label=[L.raw_label_string(a, b) for a, b in zip(coarse, detail)],
    )

    try:
        scan = identify_devices(raw, explicit=device_ips)
        flows, orient = normalise_orientation(raw, scan.devices, stats)
    except IoT23Error as exc:
        raise BundleError(str(exc)) from exc

    windowed = W.assign_windows(flows[W.FLOW_COLS])

    # ---- app-layer features, from the regenerated logs ---------------------
    # window_index is pure, so the keys can be computed here and handed to both
    # halves. Both therefore describe the same windows in the same order, which
    # derive_features asserts rather than trusts.
    index = W.window_index(windowed)
    keys = pd.MultiIndex.from_frame(index[[W.F_DEVICE_ID, W.WINDOW_START]])

    bundle = A.read_bundle(bundle_dir, max_rows=max_flows)
    app = A.derive_applayer(bundle, keys, params=res_params,
                            windowed_flows=windowed)

    derived = D.derive_features(windowed, source=SOURCE, params=params,
                                applayer=app.features)

    # ---- labels, aligned window-for-window ---------------------------------
    labelled_windows = windowed.assign(
        _raw_label=windowed[W.F_LABEL].to_numpy(),
        _flow_class=[_class_of_raw(s) for s in windowed[W.F_LABEL]],
    )
    win_labels = resolve_window_labels(labelled_windows)

    key_cols = [W.F_DEVICE_ID, W.WINDOW_START]
    if not derived.index[key_cols].reset_index(drop=True).equals(
            win_labels[key_cols].reset_index(drop=True)):
        raise BundleError(
            "internal error: window label order does not match the feature "
            "index order; refusing to emit rows whose labels may be shuffled")

    flag_dicts = W.window_quality_flags(
        derived.index,
        min_flows=int(cfg.iot23.min_flows_per_window),
        min_span_seconds=float(cfg.iot23.min_span_seconds),
    )
    frac = win_labels["malicious_fraction"].to_numpy(dtype="float64")
    for i, f in enumerate(flag_dicts):
        if not np.isnan(frac[i]) and 0.0 < frac[i] < 1.0:
            f[K.FLAG_MIXED_LABEL_WINDOW] = [f"{frac[i]:.4f}"]

    obs = build_observations(
        derived.features,
        source_dataset=SOURCE,
        device_id=derived.index[W.F_DEVICE_ID].tolist(),
        window_start=derived.index[W.WINDOW_START].tolist(),
        research_class=win_labels["research_class"].tolist(),
        original_label=win_labels["original_label"].tolist(),
        scenario_id=scenario_id,
        extra_flags=flag_dicts,
    )
    assert_valid(obs)

    report = _report(bundle_dir, labelled, scenario_id, stats, scan, orient,
                     derived.diagnostics, app, obs, max_flows)
    return obs, report


def _report(bundle_dir, labelled, scenario_id, stats, scan, orient,
            diagnostics, app: A.AppLayer, obs, max_flows) -> dict:
    """Everything a reader needs to judge this ingest.

    The app-layer section is the part that distinguishes this adapter, so it
    states plainly which logs were present and what they yielded. A reader can
    tell an unmeasured feature from a measured-and-absent one without opening the
    observation frame.
    """
    n_missing = obs[K.N_FEATURES_MISSING]
    res_cols = [c for c in A.APPLAYER_FEATURES if c in obs.columns]
    return {
        "adapter": "zeek_bundle",
        "source_dataset": SOURCE,
        "bundle_dir": str(bundle_dir),
        "labelled_conn": str(labelled),
        "scenario_id": scenario_id,
        "read": stats.as_dict(),
        "devices": {"n": len(scan.devices), "basis": scan.basis},
        "orientation": orient.as_dict(),
        "observations": {
            "n_windows": int(len(obs)),
            "class_counts": obs[K.RESEARCH_CLASS].value_counts().to_dict(),
            "features_missing_mean": float(n_missing.mean()),
        },
        "app_layer": {
            "logs_present": list(app.available),
            "logs_absent": [l for l in A.BUNDLE_LOGS if l not in app.available],
            "diagnostics": app.diagnostics,
            # Per resolution feature: how many windows carry a real number, and
            # how many are NaN because the log that feeds it was absent. This is
            # the missing-is-not-zero rule made auditable.
            "coverage": {
                c: {"measured": int(obs[c].notna().sum()),
                    "not_measurable": int(obs[c].isna().sum())}
                for c in res_cols
            },
        },
        "unavailable_features": K.unavailable_features(SOURCE),
        "derive": diagnostics,
        "max_flows": max_flows,
        "provenance_note": real_data_note(),
    }


# ===========================================================================
# CLI
# ===========================================================================
def _default_out(scenario_id: str) -> Path:
    from .operational_zeek import _SAFE_NAME
    safe = scenario_id.translate(_SAFE_NAME) or "bundle"
    return cfg_mod.PROCESSED_DIR / f"zeek_bundle_{safe}.observations.csv"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Build observations from a Zeek log bundle (conn+dns+http+"
                    "ssl) plus the dataset's labelled connection log. Reads "
                    "local files only; no network access.")
    p.add_argument("--bundle", required=True,
                   help="directory of regenerated Zeek logs")
    p.add_argument("--scenario-dir", required=True,
                   help="original IoT-23 scenario folder (for conn.log.labeled)")
    p.add_argument("--scenario-id", required=True)
    p.add_argument("--device-ip", action="append", default=None)
    p.add_argument("--max-flows", type=int, default=None)
    p.add_argument("--out", default=None)
    p.add_argument("--config", default=None)
    args = p.parse_args(argv)

    cfg_mod.ensure_dirs()
    obs, report = ingest(args.bundle, args.scenario_dir,
                         scenario_id=args.scenario_id,
                         device_ips=args.device_ip,
                         max_flows=args.max_flows,
                         config_path=args.config)
    out = Path(args.out) if args.out else _default_out(args.scenario_id)
    write_observations(obs, out)

    print(json.dumps(report, indent=2, default=str))
    print(f"\nobservations -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
