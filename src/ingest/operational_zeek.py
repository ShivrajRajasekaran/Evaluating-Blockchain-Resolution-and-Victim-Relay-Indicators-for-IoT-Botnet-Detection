"""
ingest/operational_zeek.py — product adapter: a local Zeek conn.log (or
conn.log.labeled) -> UNLABELLED operational observations for analyst review.

    python -m src.ingest.operational_zeek --input <path> --scenario-id <id>

CONTAINMENT
    Reads one local file, writes one local CSV. No network access of any kind:
    nothing here resolves a name, opens a socket, probes a device, or downloads
    anything. See docs/ethics-and-containment.md.

THE TRACK-A PIPELINE, MINUS LABELS
    This is the IoT-23 adapter (ingest.iot23) with label resolution removed. A
    conn.log from an authorised sensor carries exactly the fields IoT-23 does,
    so header parsing, device identification and the safety-critical
    device-relative orientation transform are reused VERBATIM from ingest.iot23
    and ingest.zeek — there is one home for "which end is the device", and this
    adapter does not fork it.

    What removal must get exactly right, and what the tests pin down:
      * A PLAIN conn.log (no label columns) is ACCEPTED. Operational telemetry
        is unlabelled by nature; the research adapter refuses it, this one must
        not.
      * If the file happens to carry label columns, they are DROPPED at read
        (never in usecols) and the fact is reported, not honoured. Every window
        is research_class=unmapped with an empty original_label, so no
        attacker-supplied label string can ride into the analyst UI dressed as a
        confirmed class, and no operational row can ever enter a training set.

    Any downstream alert is therefore a transparent rule firing on an indicator
    pattern — review-only, not ML-validated.

SHARED WITH ingest.operational_csv
    OperationalIngestError and _SAFE_NAME live here and are imported by the CSV
    operational adapter, so the product has one error type and one filename
    sanitiser across every operational input format.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src import config as cfg_mod
from src.config import load_config, operational_data_note
from src.features import derive as D
from src.features import windowing as W
from src.schema import assert_valid, build_observations, write_observations
from src.schema import columns as K

from . import zeek
# One home for orientation and the Zeek field names; reused, never forked.
from .iot23 import (REQUIRED_FIELDS, OPTIONAL_FIELDS, Z_LABEL, Z_DETAILED_LABEL,
                    Z_DETAILED_LABEL_ALT, IoT23Error, identify_devices,
                    normalise_orientation)

SOURCE = K.SOURCE_OP_ZEEK

# The label columns IoT-23 appends. Detected only so their presence can be
# REPORTED as ignored; they are never read into the observation frame.
_LABEL_FIELDS: tuple[str, ...] = (Z_LABEL, Z_DETAILED_LABEL, Z_DETAILED_LABEL_ALT)

# Characters that must not reach a filename built from an analyst-supplied
# scenario id: path separators, drive/colon, wildcards and whitespace all become
# "_", so a scenario id like "a/b:c" cannot escape the processed directory.
_SAFE_NAME = str.maketrans({c: "_" for c in '/\\:*?"<>|\t\n\r '})


class OperationalIngestError(ValueError):
    """An authorised operational capture cannot be turned into observations.

    Distinct from IoT23Error so the product surfaces one error type regardless
    of which reused research primitive raised underneath. Shared with
    ingest.operational_csv.
    """


def _default_out(scenario_id: str) -> Path:
    """Default output path for the CLI, with the scenario id sanitised.

    A scenario id is analyst-supplied free text; translating the unsafe
    characters means a value like ``a/b:c`` yields a filename inside the
    processed directory rather than a path traversal out of it.
    """
    safe = scenario_id.translate(_SAFE_NAME) or "operational"
    return cfg_mod.PROCESSED_DIR / f"operational_zeek_{safe}.observations.csv"


# ===========================================================================
# Pipeline
# ===========================================================================
def ingest(input_path: str | Path, *, scenario_id: str,
           device_ips: list[str] | None = None,
           max_flows: int | None = None,
           config_path: str | Path | None = None
           ) -> tuple[pd.DataFrame, dict]:  # noqa: F821  (pandas via return)
    """Turn one local conn.log[.labeled] into an UNLABELLED observation frame.

    Returns ``(observations, report)``; nothing is written, so this is directly
    testable and callable from a notebook without side effects.
    """
    cfg = load_config(config_path)
    params = D.DeriveParams.from_config(cfg.iot23)

    header = zeek.read_header(input_path)
    missing = [f for f in REQUIRED_FIELDS if f not in header.fields]
    if missing:
        raise OperationalIngestError(
            f"{Path(input_path).name} does not declare required Zeek field(s) "
            f"{missing}. It declares {header.fields}. This adapter reads a Zeek "
            "conn.log / conn.log.labeled; a different log type has different "
            "columns and cannot be substituted.")

    # Label columns are detected for the report and then deliberately EXCLUDED
    # from usecols: operational output is unlabelled by policy, so a stray label
    # column must never be read, let alone become a class.
    labels_present = [f for f in _LABEL_FIELDS if f in header.fields]
    usecols = [f for f in header.fields
               if f in REQUIRED_FIELDS or f in OPTIONAL_FIELDS]

    raw, header, stats = zeek.read_log(input_path, usecols=usecols,
                                       max_rows=max_flows)
    if raw.empty:
        raise OperationalIngestError(
            f"{Path(input_path).name} yielded no readable rows")

    # Unlabelled by construction: the orientation transform carries one label
    # column by contract, and here it is empty and never becomes a class.
    raw = raw.assign(_raw_label="")

    try:
        scan = identify_devices(raw, explicit=device_ips)
        flows, orient = normalise_orientation(raw, scan.devices, stats)
    except IoT23Error as exc:
        raise OperationalIngestError(str(exc)) from exc

    windowed = W.assign_windows(flows[W.FLOW_COLS])
    derived = D.derive_features(windowed, source=SOURCE, params=params)
    index = derived.index
    m = len(index)

    flag_dicts = W.window_quality_flags(
        index,
        min_flows=int(cfg.iot23.min_flows_per_window),
        min_span_seconds=float(cfg.iot23.min_span_seconds),
    )

    obs = build_observations(
        derived.features,
        source_dataset=SOURCE,
        device_id=index[W.F_DEVICE_ID].tolist(),
        window_start=index[W.WINDOW_START].tolist(),
        research_class=[K.CLS_UNMAPPED] * m,
        original_label=[""] * m,
        scenario_id=scenario_id,
        extra_flags=flag_dicts,
    )
    assert_valid(obs)

    report = _report(input_path, scenario_id, stats, scan, orient,
                     derived.diagnostics, obs, labels_present, max_flows)
    return obs, report


def _report(input_path, scenario_id, stats, scan, orient, diagnostics, obs,
            labels_present, max_flows) -> dict:
    """Everything a reader needs to judge this ingest.

    Deliberately carries NO class_counts / mixed-label section: operational
    telemetry has no ground truth to count, and inventing a class breakdown
    would be the exact dishonesty this adapter exists to avoid.
    """
    n_missing = obs[K.N_FEATURES_MISSING]
    return {
        "adapter": "operational_zeek",
        "source_dataset": SOURCE,
        "input": str(input_path),
        "scenario_id": scenario_id,
        "label_columns_present_but_ignored": labels_present,
        "truncated_by_max_flows": bool(stats.truncated_by_max_flows),
        "max_flows": max_flows,
        "read": stats.as_dict(),
        "devices": scan.as_dict(),
        "orientation": orient.as_dict(),
        "windowing": diagnostics,
        "observations": {
            "rows": int(len(obs)),
            "all_unmapped": bool(
                (obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all()),
            "features_missing_min": int(n_missing.min()),
            "features_missing_median": float(n_missing.median()),
            "features_missing_max": int(n_missing.max()),
        },
        "features_unavailable_for_this_source": K.unavailable_features(SOURCE),
        "features_that_are_proxies": K.proxy_features(SOURCE),
        "detection_note": (
            "Unlabelled operational telemetry. Every window is review-only and "
            "carries research_class=unmapped; no class is asserted or confirmed. "
            "Any downstream alert is a rule-based suspicious-indicator pattern "
            "requiring analyst review, and is not ML-validated."
        ),
        "provenance_note": operational_data_note(),
    }


# ===========================================================================
# CLI
# ===========================================================================
def _parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="python -m src.ingest.operational_zeek",
        description=("Convert ONE authorised local Zeek conn.log into the "
                     "product's observation schema as UNLABELLED, review-only "
                     "windows. Reads a local file only; never downloads, probes, "
                     "or connects to anything."))
    ap.add_argument("--input", required=True, help="path to a local conn.log")
    ap.add_argument("--scenario-id", required=True,
                    help="capture identifier, e.g. site-sensor-2026-08-20")
    ap.add_argument("--device-ip", action="append", default=None,
                    help="address of a monitored device; repeatable")
    ap.add_argument("--max-flows", type=int, default=None,
                    help="read at most N flows (smoke tests)")
    ap.add_argument("--out", default=None,
                    help="output CSV (default: derived from --scenario-id)")
    ap.add_argument("--config", default=None, help="config YAML")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    cfg_mod.ensure_dirs()
    try:
        obs, report = ingest(
            args.input, scenario_id=args.scenario_id,
            device_ips=args.device_ip, max_flows=args.max_flows,
            config_path=args.config)
    except (zeek.ZeekLogError, OperationalIngestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = Path(args.out) if args.out else _default_out(args.scenario_id)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_observations(obs, out)
    report_path = out.with_suffix(".report.json")
    report_path.write_text(json.dumps(report, indent=2, default=str),
                           encoding="utf-8")

    r = report
    print(f"wrote {len(obs)} observations -> {out}")
    print(f"       report              -> {report_path}")
    if r["label_columns_present_but_ignored"]:
        print(f"  labels ignored  {r['label_columns_present_but_ignored']} "
              "(operational telemetry is unlabelled by policy)")
    print(f"  rows read       {r['read']['rows_read']} of "
          f"{r['read']['data_lines_total']} data lines")
    print(f"  devices         {r['devices']['n_devices']} "
          f"({r['devices']['basis']})")
    o = r["orientation"]
    print(f"  orientation     {o['device_is_originator']} outbound, "
          f"{o['device_is_responder']} inbound, "
          f"{o['no_device_involved_dropped']} dropped")
    print(f"  windows         {r['windowing']['windows']} "
          "(all review-only, research_class=unmapped)")
    print(f"  proxies         {r['features_that_are_proxies']}")
    print(f"  {operational_data_note()}")
    if r["truncated_by_max_flows"]:
        print("  WARNING: run truncated by --max-flows.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
