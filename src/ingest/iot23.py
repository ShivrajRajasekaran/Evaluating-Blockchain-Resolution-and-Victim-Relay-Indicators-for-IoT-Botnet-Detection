"""
ingest/iot23.py — Track A adapter: a local IoT-23 conn.log.labeled -> observations.

    python -m src.ingest.iot23 --input <local-path> --scenario-id <id>

CONTAINMENT
    Reads one local file, writes one local CSV. No network access of any kind:
    nothing here resolves a name, opens a socket, or downloads a dataset. The
    capture must already be on disk. See docs/ethics-and-containment.md.

WHAT TRACK A IS FOR, AND WHAT IT IS NOT FOR
    IoT-23 was captured in 2018-2019 and predates blockchain-anchored C2. It
    contains no ENS/SNS resolution and no victim-relay mesh, and its lightweight
    distribution ships conn.log.labeled only — no dns.log, no payload. Five of
    the sixteen features are therefore not derivable from it at all and are
    emitted as NaN (schema/columns.py, FEATURE_AVAILABILITY).

    So this track does NOT test the project's thesis and no number produced here
    may be presented as evidence for it. It answers the other half of the
    research question: what false-positive rate do these features produce on real
    benign IoT traffic, and can conventional botnet behaviour be detected from
    the base groups alone. See docs/evaluation-protocol.md.

THE HARD PART: WHICH END IS THE DEVICE
    A Zeek conn.log is written from the perspective of whoever opened the
    connection, not of the device under study. In an IoT-23 capture the monitored
    device is the originator of some flows and the responder of others, and
    ``orig_bytes`` always means "bytes from the originator". Reading the columns
    as-is therefore inverts updownlink_ratio and mean_pkt_size for every inbound
    flow — and inbound flows are exactly what a victim relay is characterised by,
    so the error would land hardest on the behaviour the project is about.

    Every flow is therefore normalised to DEVICE-RELATIVE orientation before any
    feature is computed: orig_* means device -> peer throughout. Which end
    initiated is preserved separately in the ``outbound`` column, because six
    features are statements about what the device CHOSE to do and would otherwise
    count the ambient inbound scanning of the internet as the device's own
    behaviour. See features/windowing.py.

    ONE APPROXIMATION IS UNAVOIDABLE HERE. Zeek's conn_state has no
    device-relative equivalent: it describes the originator's attempt. Flows are
    normalised, conn_state is not, so failed_conn_ratio is computed over outbound
    flows only and is silent about inbound ones. That is the honest reading — a
    REJ on an inbound flow says someone failed to reach the device, which is not
    a fact about the device — but it does mean this feature sees less of a
    responder-heavy device than of an originator-heavy one. Recorded in
    docs/limitations.md.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from src.features import derive as D
from src.features import windowing as W
from src import config as cfg_mod
from src.config import load_config
from src.schema import build_observations
from src.schema import columns as K
from src.schema import assert_valid, write_observations

from . import iot23_labels as L
from . import zeek

# ---------------------------------------------------------------------------
# Zeek conn.log field names
# ---------------------------------------------------------------------------
# Read from the file's own #fields header (see zeek.read_header); these are the
# names looked up in it. Zeek's odd ordering of the packet/byte block
# (orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes) is preserved for anyone
# comparing this list against a real header line.
Z_TS = "ts"
Z_ORIG_H = "id.orig_h"
Z_ORIG_P = "id.orig_p"
Z_RESP_H = "id.resp_h"
Z_RESP_P = "id.resp_p"
Z_PROTO = "proto"
Z_DURATION = "duration"
Z_ORIG_BYTES = "orig_bytes"
Z_RESP_BYTES = "resp_bytes"
Z_CONN_STATE = "conn_state"
Z_LOCAL_ORIG = "local_orig"
Z_LOCAL_RESP = "local_resp"
Z_ORIG_PKTS = "orig_pkts"
Z_ORIG_IP_BYTES = "orig_ip_bytes"
Z_RESP_PKTS = "resp_pkts"
Z_RESP_IP_BYTES = "resp_ip_bytes"

# IoT-23 appends these two. The corpus is inconsistent about the separator in
# the second name, so both spellings are accepted.
Z_LABEL = "label"
Z_DETAILED_LABEL = "detailed-label"
Z_DETAILED_LABEL_ALT = "detailed_label"

REQUIRED_FIELDS: tuple[str, ...] = (
    Z_TS, Z_ORIG_H, Z_ORIG_P, Z_RESP_H, Z_RESP_P, Z_PROTO, Z_DURATION,
    Z_ORIG_BYTES, Z_RESP_BYTES, Z_CONN_STATE, Z_ORIG_PKTS, Z_ORIG_IP_BYTES,
    Z_RESP_PKTS, Z_RESP_IP_BYTES,
)
# Present in most but not all IoT-23 files; absence is handled, not fatal.
OPTIONAL_FIELDS: tuple[str, ...] = (Z_LOCAL_ORIG, Z_LOCAL_RESP)

_ZEEK_TRUE = frozenset({"t", "true", "1"})


class IoT23Error(ValueError):
    """The capture cannot be turned into observations."""


# ===========================================================================
# Device identification
# ===========================================================================
@dataclass
class DeviceScan:
    """Which addresses were treated as monitored devices, and on what basis."""

    devices: set[str] = field(default_factory=set)
    basis: str = "unknown"
    candidates: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict:
        top = sorted(self.candidates.items(), key=lambda kv: (-kv[1], kv[0]))
        return {
            "basis": self.basis,
            "n_devices": len(self.devices),
            "devices": sorted(self.devices),
            "flows_originated_per_candidate": dict(top[:20]),
            "candidates_truncated": len(top) > 20,
        }


def _is_private(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def _zeek_bool(series: pd.Series) -> pd.Series:
    """Zeek's ``T``/``F``/``-`` -> real booleans. ``-`` becomes False."""
    return series.astype(str).str.strip().str.lower().isin(_ZEEK_TRUE)


def identify_devices(df: pd.DataFrame, *, explicit: list[str] | None = None
                     ) -> DeviceScan:
    """Decide which addresses in the capture are monitored devices.

    Three bases, in descending order of trustworthiness:

    1. ``--device-ip`` given explicitly. Always wins. This is the recommended
       path for a scenario whose device address is documented, because it makes
       the choice a recorded decision instead of an inference.
    2. Zeek's own ``local_orig`` / ``local_resp`` fields, when the capture
       actually populated them.
    3. RFC1918-style private addressing. Needed because IoT-23's logs very often
       carry ``-`` in the local_* fields — ``Site::local_nets`` was not
       configured when the captures were produced — and a run that silently found
       no devices would emit an empty observation table, which reads as "the
       adapter works, this capture is just quiet".

    The basis used and the per-candidate flow counts are returned so the ingest
    report can state them; a capture that yields 300 one-flow "devices" is a
    capture of a whole network and wants an explicit --device-ip.
    """
    scan = DeviceScan()
    orig = df[Z_ORIG_H].astype(str)
    resp = df[Z_RESP_H].astype(str)

    if explicit:
        scan.devices = set(explicit)
        scan.basis = "explicit --device-ip"
        present = scan.devices & (set(orig.unique()) | set(resp.unique()))
        if not present:
            raise IoT23Error(
                f"none of the addresses given with --device-ip {sorted(scan.devices)} "
                "appear in this capture; check the scenario's documented device "
                "address, or omit the flag to auto-detect"
            )
        missing = scan.devices - present
        if missing:
            print(f"[warn] --device-ip addresses not seen in this capture: "
                  f"{sorted(missing)}", file=sys.stderr)
        scan.devices = present
    else:
        hosts = pd.unique(pd.concat([orig, resp], ignore_index=True))
        if Z_LOCAL_ORIG in df.columns and Z_LOCAL_RESP in df.columns:
            lo, lr = _zeek_bool(df[Z_LOCAL_ORIG]), _zeek_bool(df[Z_LOCAL_RESP])
            local = set(orig[lo].unique()) | set(resp[lr].unique())
            if local:
                scan.devices = local
                scan.basis = "zeek local_orig/local_resp"
        if not scan.devices:
            scan.devices = {h for h in hosts if _is_private(h)}
            scan.basis = "private address range (local_* not populated)"

    if not scan.devices:
        raise IoT23Error(
            "no monitored device could be identified in this capture: its "
            "local_orig/local_resp fields are unset and no address is in a "
            "private range. Pass --device-ip with the device's address. "
            "Guessing would make every feature a property of an arbitrary "
            "endpoint."
        )

    counts = orig[orig.isin(scan.devices)].value_counts()
    scan.candidates = {str(k): int(v) for k, v in counts.items()}
    return scan


# ===========================================================================
# Orientation normalisation
# ===========================================================================
@dataclass
class OrientationStats:
    """How each flow was attributed. Every count is reported, none is silent."""

    device_is_originator: int = 0
    device_is_responder: int = 0
    both_ends_are_devices: int = 0
    no_device_involved: int = 0

    def as_dict(self) -> dict:
        total = (self.device_is_originator + self.device_is_responder
                 + self.both_ends_are_devices)
        return {
            "device_is_originator": self.device_is_originator,
            "device_is_responder": self.device_is_responder,
            "both_ends_are_devices": self.both_ends_are_devices,
            "no_device_involved_dropped": self.no_device_involved,
            "flows_kept": total,
            "responder_side_fraction": (
                self.device_is_responder / total if total else 0.0),
        }


def normalise_orientation(df: pd.DataFrame, devices: set[str],
                          stats: zeek.ReadStats
                          ) -> tuple[pd.DataFrame, OrientationStats]:
    """Build the device-relative flow table from raw Zeek columns.

    For each flow, one of four cases:

    * device originated       -> columns used as written, ``outbound=True``
    * device responded        -> orig/resp byte, packet and address columns
                                 SWAPPED so orig_* still means device -> peer,
                                 ``outbound=False``
    * both ends are devices   -> lateral traffic inside the monitored network.
                                 Attributed to the originator, and counted
                                 separately: on a NATed IoT capture this is
                                 usually device-to-gateway traffic, and if it
                                 dominates the capture the "peer" of most flows
                                 is the router rather than anything on the
                                 internet, which changes what flow_fanout means.
    * neither end is a device -> dropped and counted. Not silently: a capture
                                 where most flows were dropped is a capture
                                 whose device address was misidentified.
    """
    o = OrientationStats()
    orig_h = df[Z_ORIG_H].astype(str)
    resp_h = df[Z_RESP_H].astype(str)
    orig_is_dev = orig_h.isin(devices)
    resp_is_dev = resp_h.isin(devices)

    both = orig_is_dev & resp_is_dev
    neither = ~orig_is_dev & ~resp_is_dev
    o.both_ends_are_devices = int(both.sum())
    o.no_device_involved = int(neither.sum())

    keep = ~neither
    if not keep.any():
        raise IoT23Error(
            f"none of the {len(df)} flows involve an identified device "
            f"{sorted(devices)[:5]}... — the device address is wrong, or this is "
            "a capture of a different network"
        )
    df = df[keep].reset_index(drop=True)
    orig_is_dev = orig_is_dev[keep].reset_index(drop=True)
    resp_is_dev = resp_is_dev[keep].reset_index(drop=True)

    # Lateral flows are attributed to the originator, so "device originated" is
    # the fallback for anything that is not purely responder-side.
    device_responded = resp_is_dev & ~orig_is_dev
    o.device_is_originator = int((~device_responded).sum())
    o.device_is_responder = int(device_responded.sum())

    num = {name: zeek.to_numeric(df[name], name=name, stats=stats)
           for name in (Z_DURATION, Z_ORIG_BYTES, Z_RESP_BYTES, Z_ORIG_PKTS,
                        Z_ORIG_IP_BYTES, Z_RESP_PKTS, Z_RESP_IP_BYTES,
                        Z_ORIG_P, Z_RESP_P)}

    # ts is parsed here rather than through to_numeric because its unreadable
    # value must stay NaN, not become 0.0. A zero would be 1970-01-01, a
    # perfectly valid-looking timestamp that would create a window 56 years
    # before the capture and be silently included in the results.
    ts_raw = df[Z_TS].astype(str).str.strip()
    ts_num = pd.to_numeric(ts_raw.where(~ts_raw.isin(zeek.NULL_TOKENS)),
                           errors="coerce")

    def pick(when_originator: pd.Series, when_responder: pd.Series) -> pd.Series:
        """Choose per flow, so the swap is one vectorised expression."""
        return when_responder.where(device_responded, when_originator)

    o_h, r_h = df[Z_ORIG_H].astype(str), df[Z_RESP_H].astype(str)
    flows = pd.DataFrame({
        W.F_DEVICE_ID: pick(o_h, r_h),
        # Zeek's ts is Unix epoch seconds. Kept in UTC: the absolute window grid
        # in windowing.py is anchored at the epoch, and applying a local timezone
        # here would shift every window boundary by the offset of whichever
        # machine ran the ingest.
        W.F_TS: pd.to_datetime(ts_num, unit="s"),
        W.F_DURATION: num[Z_DURATION],
        W.F_DST_IP: pick(r_h, o_h),
        W.F_DST_PORT: pick(num[Z_RESP_P], num[Z_ORIG_P]),
        W.F_PROTO: df[Z_PROTO].astype(str),
        W.F_ORIG_BYTES: pick(num[Z_ORIG_BYTES], num[Z_RESP_BYTES]),
        W.F_RESP_BYTES: pick(num[Z_RESP_BYTES], num[Z_ORIG_BYTES]),
        W.F_ORIG_IP_BYTES: pick(num[Z_ORIG_IP_BYTES], num[Z_RESP_IP_BYTES]),
        W.F_RESP_IP_BYTES: pick(num[Z_RESP_IP_BYTES], num[Z_ORIG_IP_BYTES]),
        W.F_ORIG_PKTS: pick(num[Z_ORIG_PKTS], num[Z_RESP_PKTS]),
        W.F_RESP_PKTS: pick(num[Z_RESP_PKTS], num[Z_ORIG_PKTS]),
        # NOT swapped — see the module docstring. conn_state describes the
        # originator's attempt and has no device-relative equivalent.
        W.F_CONN_STATE: df[Z_CONN_STATE].astype(str).str.strip(),
        W.F_OUTBOUND: ~device_responded,
        W.F_LABEL: df["_raw_label"],
    })
    # A flow with no start time cannot be windowed. Dropped rather than placed
    # in an arbitrary window, and counted where the other coercions are counted.
    bad_ts = flows[W.F_TS].isna()
    if bad_ts.any():
        stats.coerced_cells["ts_unparseable_rows_dropped"] = int(bad_ts.sum())
        flows = flows[~bad_ts].reset_index(drop=True)
        if flows.empty:
            raise IoT23Error("every flow had an unreadable timestamp")
    return flows, o


# ===========================================================================
# Labels
# ===========================================================================
def _label_columns(df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    """The coarse and detailed label columns, whichever spelling the file used.

    A file with no label columns at all is a plain conn.log rather than the
    labelled variant. It is refused: silently treating unlabelled traffic as
    benign would fabricate a benign class out of unknown data and deflate the
    false-positive rate this track exists to measure.
    """
    if Z_LABEL not in df.columns:
        raise IoT23Error(
            f"this log has no {Z_LABEL!r} column, so it is a plain conn.log "
            "rather than IoT-23's conn.log.labeled. Unlabelled flows cannot be "
            "given a class, and defaulting them to benign would corrupt the "
            "false-positive measurement this track exists for."
        )
    for name in (Z_DETAILED_LABEL, Z_DETAILED_LABEL_ALT):
        if name in df.columns:
            return df[Z_LABEL], df[name]
    # Coarse labels only: usable, but every malicious flow becomes
    # traditional_botnet_activity with no C2 distinction available.
    print(f"[warn] no {Z_DETAILED_LABEL!r} column; malicious flows cannot be "
          f"separated into C2 vs other botnet activity", file=sys.stderr)
    return df[Z_LABEL], pd.Series(["-"] * len(df), index=df.index)


def resolve_window_labels(flows: pd.DataFrame) -> pd.DataFrame:
    """Per-window class, verbatim source label and malicious flow fraction.

    Returned as a frame keyed by (device_id, window_start) in the same sorted
    order ``window_index`` produces, so the caller can attach it positionally
    after checking the keys agree.
    """
    rows = []
    for (dev, win), sub in flows.groupby([W.F_DEVICE_ID, W.WINDOW_START],
                                         sort=True):
        classes = sub["_flow_class"].tolist()
        cls, frac = L.resolve_window_class(classes)
        # The verbatim label of the window is the most specific one present, so
        # a reader can see "Malicious|C&C-HeartBeat" rather than a count.
        raw = sub["_raw_label"]
        if cls == K.CLS_BENIGN_REAL:
            original = raw.iloc[0]
        else:
            mal = raw[[c in K.MALICIOUS_CLASSES or c == K.CLS_UNMAPPED
                       for c in classes]]
            original = mal.iloc[0] if len(mal) else raw.iloc[0]
        rows.append({W.F_DEVICE_ID: dev, W.WINDOW_START: win,
                     "research_class": cls, "original_label": str(original),
                     "malicious_fraction": frac})
    return pd.DataFrame(rows)


# ===========================================================================
# Pipeline
# ===========================================================================
def ingest(input_path: str | Path, *, scenario_id: str,
           device_ips: list[str] | None = None,
           max_flows: int | None = None,
           config_path: str | Path | None = None
           ) -> tuple[pd.DataFrame, dict]:
    """Turn one local conn.log.labeled into an observation frame plus a report.

    Returns ``(observations, report)``. Nothing is written; the CLI does that, so
    this function is directly testable and can be called from a notebook without
    side effects.
    """
    cfg = load_config(config_path)
    params = D.DeriveParams.from_config(cfg.iot23)

    header = zeek.read_header(input_path)
    missing = [f for f in REQUIRED_FIELDS if f not in header.fields]
    if missing:
        raise IoT23Error(
            f"{Path(input_path).name} does not declare required Zeek field(s) "
            f"{missing}. It declares {header.fields}. This adapter reads "
            "conn.log / conn.log.labeled; a different Zeek log type has "
            "different columns and cannot be substituted."
        )
    usecols = [f for f in header.fields
               if f in REQUIRED_FIELDS or f in OPTIONAL_FIELDS
               or f in (Z_LABEL, Z_DETAILED_LABEL, Z_DETAILED_LABEL_ALT)]

    raw, header, stats = zeek.read_log(input_path, usecols=usecols,
                                       max_rows=max_flows)
    if raw.empty:
        raise IoT23Error(f"{Path(input_path).name} yielded no readable rows")

    coarse, detail = _label_columns(raw)
    raw = raw.assign(
        _flow_class=[L.map_flow_label(a, b) for a, b in zip(coarse, detail)],
        _raw_label=[L.raw_label_string(a, b) for a, b in zip(coarse, detail)],
    )

    scan = identify_devices(raw, explicit=device_ips)
    flows, orient = normalise_orientation(raw, scan.devices, stats)

    windowed = W.assign_windows(flows[W.FLOW_COLS])
    derived = D.derive_features(windowed, source=K.SOURCE_IOT23, params=params)
    index = derived.index

    # The per-flow class rides along inside the flow table's one label column
    # rather than as a side frame: normalise_orientation drops rows, and a
    # parallel array would have to be filtered in lockstep with it. Recovering
    # the class from the label string keeps the two in step by construction.
    labelled = windowed.assign(
        _raw_label=windowed[W.F_LABEL].to_numpy(),
        _flow_class=[_class_of_raw(s) for s in windowed[W.F_LABEL]],
    )
    win_labels = resolve_window_labels(labelled)

    # The label frame and the feature index must describe the same windows in the
    # same order. Asserted rather than assumed: a mismatch here would attach one
    # window's label to another window's features and every metric downstream
    # would be computed on shuffled data with nothing raising.
    key_cols = [W.F_DEVICE_ID, W.WINDOW_START]
    if not index[key_cols].reset_index(drop=True).equals(
            win_labels[key_cols].reset_index(drop=True)):
        raise IoT23Error(
            "internal error: window label order does not match the feature "
            "index order; refusing to emit rows whose labels may be shuffled")

    flag_dicts = W.window_quality_flags(
        index,
        min_flows=int(cfg.iot23.min_flows_per_window),
        min_span_seconds=float(cfg.iot23.min_span_seconds),
    )
    frac = win_labels["malicious_fraction"].to_numpy(dtype="float64")
    for i, f in enumerate(flag_dicts):
        if not np.isnan(frac[i]) and 0.0 < frac[i] < 1.0:
            # The argument is the malicious flow share, so a 3%-malicious window
            # is distinguishable from an unambiguous one in the output CSV.
            f[K.FLAG_MIXED_LABEL_WINDOW] = [f"{frac[i]:.4f}"]

    obs = build_observations(
        derived.features,
        source_dataset=K.SOURCE_IOT23,
        device_id=index[W.F_DEVICE_ID].tolist(),
        window_start=index[W.WINDOW_START].tolist(),
        research_class=win_labels["research_class"].tolist(),
        original_label=win_labels["original_label"].tolist(),
        scenario_id=scenario_id,
        extra_flags=flag_dicts,
    )
    assert_valid(obs)

    report = _report(input_path, scenario_id, stats, scan, orient,
                     derived.diagnostics, obs, win_labels, max_flows)
    return obs, report


def _class_of_raw(raw_label: str) -> str:
    """Recover a flow class from the verbatim ``label|detailed`` string.

    The flow table carries one label column by contract, so the pair is
    round-tripped through it rather than threaded separately. Splitting on the
    same separator raw_label_string() joined with keeps the two functions
    obviously inverse.
    """
    s = str(raw_label)
    coarse, _, detail = s.partition("|")
    return L.map_flow_label(coarse, detail if detail else "-")


def _report(input_path, scenario_id, stats, scan, orient, diagnostics, obs,
            win_labels, max_flows) -> dict:
    """Everything a reader needs to judge whether this ingest is usable.

    Assembled in one place so the JSON file and the stdout summary cannot drift
    apart, and so no count that affects interpretation is left uncomputed.
    """
    cls_counts = obs[K.RESEARCH_CLASS].value_counts()
    unmapped = int(cls_counts.get(K.CLS_UNMAPPED, 0))
    mixed = win_labels["malicious_fraction"]
    n_missing = obs[K.N_FEATURES_MISSING]
    return {
        "adapter": "iot23",
        "input": str(input_path),
        "scenario_id": scenario_id,
        "truncated_by_max_flows": bool(stats.truncated_by_max_flows),
        "max_flows": max_flows,
        "read": stats.as_dict(),
        "devices": scan.as_dict(),
        "orientation": orient.as_dict(),
        "windowing": diagnostics,
        "observations": {
            "rows": int(len(obs)),
            "class_counts": {str(k): int(v) for k, v in cls_counts.items()},
            "unmapped_rows": unmapped,
            "unmapped_fraction": float(unmapped / len(obs)) if len(obs) else 0.0,
            "mixed_label_windows": int(((mixed > 0) & (mixed < 1)).sum()),
            "median_malicious_fraction_of_malicious_windows": (
                float(mixed[mixed > 0].median()) if (mixed > 0).any() else 0.0),
            # A range, not one number: 5 is the floor set by this source's
            # unavailable features, and anything above it is a window whose
            # beacon or ratio features were unmeasurable. Reporting only the
            # floor would hide that second, variable cause.
            "features_missing_min": int(n_missing.min()),
            "features_missing_median": float(n_missing.median()),
            "features_missing_max": int(n_missing.max()),
        },
        "features_unavailable_for_this_source": K.unavailable_features(
            K.SOURCE_IOT23),
        "features_that_are_proxies": K.proxy_features(K.SOURCE_IOT23),
        "provenance_note": cfg_mod.real_data_note(),
    }


# ===========================================================================
# CLI
# ===========================================================================
def _parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="python -m src.ingest.iot23",
        description=("Convert ONE local IoT-23 conn.log.labeled into the "
                     "project's observation schema. Reads a local file only; "
                     "never downloads anything."),
        epilog=("The capture must be obtained and extracted separately. See "
                "docs/iot23-integration-plan.md."),
    )
    ap.add_argument("--input", required=True,
                    help="path to a local, extracted conn.log.labeled")
    ap.add_argument("--scenario-id", required=True,
                    help="capture identifier, e.g. CTU-IoT-Malware-Capture-34-1")
    ap.add_argument("--device-ip", action="append", default=None,
                    help=("address of a monitored device; repeatable. "
                          "Recommended: makes device selection a recorded "
                          "decision instead of an inference."))
    ap.add_argument("--max-flows", type=int, default=None,
                    help=("read at most N flows (smoke tests). A truncated run "
                          "is marked as such in the report and its numbers are "
                          "not a result for the capture."))
    ap.add_argument("--out", default=None,
                    help=f"output CSV (default: {cfg_mod.TRACK_A_IOT23_CSV})")
    ap.add_argument("--config", default=None, help="config YAML")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)
    cfg_mod.ensure_dirs()
    try:
        obs, report = ingest(
            args.input,
            scenario_id=args.scenario_id,
            device_ips=args.device_ip,
            max_flows=args.max_flows,
            config_path=args.config,
        )
    except (zeek.ZeekLogError, IoT23Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = Path(args.out) if args.out else Path(cfg_mod.TRACK_A_IOT23_CSV)
    out.parent.mkdir(parents=True, exist_ok=True)
    # write_observations, not to_csv: it re-validates, fixes the column order and
    # formats window_start the one way the readers expect. A hand-rolled to_csv
    # here would produce a file that loads but sorts and joins differently.
    write_observations(obs, out)
    report_path = out.with_suffix(".report.json")
    report_path.write_text(json.dumps(report, indent=2, default=str),
                           encoding="utf-8")

    r = report
    print(f"wrote {len(obs)} observations -> {out}")
    print(f"       report              -> {report_path}")
    print(f"  flows read      {r['read']['rows_read']} of "
          f"{r['read']['data_lines_total']} data lines "
          f"({r['read']['separator_used']} separated)")
    if r["read"]["rows_skipped_malformed"]:
        print(f"  malformed lines {r['read']['rows_skipped_malformed']} "
              f"({r['read']['malformed_line_fraction']:.4%})")
    print(f"  devices         {r['devices']['n_devices']} "
          f"({r['devices']['basis']})")
    o = r["orientation"]
    print(f"  orientation     {o['device_is_originator']} outbound, "
          f"{o['device_is_responder']} inbound "
          f"({o['responder_side_fraction']:.1%} responder-side), "
          f"{o['no_device_involved_dropped']} dropped")
    print(f"  windows         {r['windowing']['windows']} over "
          f"{r['windowing']['capture_span_hours']:.2f} h")
    print(f"  classes         {r['observations']['class_counts']}")
    if r["observations"]["unmapped_rows"]:
        print(f"  unmapped        {r['observations']['unmapped_rows']} rows "
              f"({r['observations']['unmapped_fraction']:.2%}) — excluded from "
              f"training, retained for audit")
    print(f"  NaN features    {r['observations']['features_missing_min']}"
          f"–{r['observations']['features_missing_max']} of "
          f"{len(K.FEATURE_COLS)} per row "
          f"(median {r['observations']['features_missing_median']:.1f}); "
          f"always absent: {r['features_unavailable_for_this_source']}")
    print("  NOTE: Track A cannot test the blockchain/relay thesis — those "
          "features do not exist in this source. See docs/limitations.md.")
    print(f"  {cfg_mod.real_data_note()}")
    if r["truncated_by_max_flows"]:
        print("  WARNING: run truncated by --max-flows; not a result for this "
              "capture.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
