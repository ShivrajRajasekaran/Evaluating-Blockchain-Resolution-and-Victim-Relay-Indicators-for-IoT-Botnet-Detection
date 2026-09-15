"""
ingest/operational_csv.py — product adapter: a local flow-export CSV ->
UNLABELLED operational observations for analyst review.

    python -m src.ingest.operational_csv --input <path> --source op_netflow \\
        --scenario-id <id>

CONTAINMENT
    Reads one local CSV, writes one local CSV. No network access of any kind:
    nothing here resolves a name, opens a socket, probes a device, or downloads
    anything. See docs/ethics-and-containment.md.

THREE FORMATS, ONE PIPELINE
    Flow telemetry arrives in many shapes. This adapter targets three:

      op_flow_csv   a rich bidirectional flow CSV (a Zeek conn.log exported to
                    CSV, or an IPFIX/NetFlow-v9 bidirectional export). Carries
                    both directions' bytes and packets and a connection state,
                    so every base feature is computed for real.
      op_netflow    classic (v5-style) NetFlow: unidirectional records, no TCP
                    state, duration inferred from first/last. Direction, state
                    and duration are therefore APPROXIMATE — the schema marks
                    failed_conn_ratio, updownlink_ratio and bidir_flow_duration
                    as proxies for this source (schema/columns.py).
      op_firewall   a firewall connection log: an allow/deny action stands in
                    for connection state, and byte/packet counts are often
                    per-rule or absent, so mean_pkt_size is a proxy too.

    Rather than write three orientation routines, each CSV row is normalised into
    the SAME raw column shape a Zeek conn.log has, and the project's one device
    identification and device-relative orientation implementation
    (ingest.iot23.identify_devices / normalise_orientation) is reused verbatim.
    That is the whole point of the exercise: the subtle, safety-critical "which
    end is the device" logic has exactly one home for every input format.

WHY A STRICT, DOCUMENTED COLUMN CONTRACT
    A flow CSV has no self-describing header the way a Zeek TSV does, and vendors
    disagree on column names. Guessing a mapping is how orig and resp get
    swapped and every ratio inverts silently. So each format declares the
    columns it needs; a file missing a required column is REFUSED with the list
    of what it needs and what it had, and a caller with a non-standard export
    passes an explicit --column-map rather than having the adapter guess. Common
    vendor spellings are accepted as aliases, but only common ones.

LABELS
    Operational telemetry is unlabelled by nature. Every window is emitted
    research_class=unmapped with an empty original_label and
    label_confidence=unlabelled_operational, exactly as the Zeek product adapter
    does, which keeps it permanently out of any training set. Any downstream
    alert is a transparent rule firing on an indicator pattern — review-only,
    not ML-validated.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
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

from . import zeek
# One home for orientation, and one product error type, shared with the Zeek
# operational adapter. See that module's docstring.
from .iot23 import (
    Z_TS, Z_ORIG_H, Z_ORIG_P, Z_RESP_H, Z_RESP_P, Z_PROTO, Z_DURATION,
    Z_ORIG_BYTES, Z_RESP_BYTES, Z_CONN_STATE, Z_ORIG_PKTS, Z_ORIG_IP_BYTES,
    Z_RESP_PKTS, Z_RESP_IP_BYTES,
    IoT23Error, identify_devices, normalise_orientation,
)
from .operational_zeek import OperationalIngestError

# Tokens a CSV cell uses for "no value". Matched case-insensitively.
_UNSET = frozenset({"", "-", "(empty)", "nan", "none", "null", "na"})

# IANA protocol numbers seen in NetFlow/IPFIX exports -> Zeek's lowercase names.
_PROTO_NUM = {
    "1": "icmp", "2": "igmp", "6": "tcp", "17": "udp", "47": "gre",
    "50": "esp", "51": "ah", "58": "icmpv6", "89": "ospf", "132": "sctp",
}

# Firewall action -> a Zeek conn_state. A blocked/denied connection is a failed
# one (REJ is in the configured failed_conn_states), which is the whole reason a
# firewall log carries a usable, if approximate, failed_conn_ratio.
_ACTION_ALLOW = frozenset({"allow", "allowed", "accept", "accepted", "permit",
                           "permitted", "pass", "passed", "open", "ok"})
_ACTION_DENY = frozenset({"deny", "denied", "drop", "dropped", "block",
                          "blocked", "reject", "rejected", "close", "closed",
                          "fail", "failed"})

# Accepted source-column spellings per canonical field, lowercased. Only common
# vendor names — anything exotic goes through --column-map instead of a guess.
_ALIASES: dict[str, tuple[str, ...]] = {
    "ts": ("ts", "timestamp", "time", "start", "start_time", "starttime",
           "first", "first_switched", "stime", "flowstart", "flow_start",
           "date_first_seen", "ts_start", "@timestamp"),
    "end_ts": ("te", "last", "end", "end_time", "endtime", "last_switched",
               "etime", "flowend", "flow_end", "date_last_seen", "ts_end"),
    "src_ip": ("src_ip", "srcaddr", "src_addr", "source_ip", "src", "source",
               "sa", "orig_h", "id.orig_h", "ipv4_src_addr", "ip_src",
               "source_address", "srcip"),
    "src_port": ("src_port", "srcport", "source_port", "sp", "orig_p",
                 "id.orig_p", "sport", "l4_src_port", "spt", "srcpt"),
    "dst_ip": ("dst_ip", "dstaddr", "dst_addr", "dest_ip", "destination_ip",
               "dst", "dest", "destination", "da", "resp_h", "id.resp_h",
               "ipv4_dst_addr", "ip_dst", "dest_address", "dstip"),
    "dst_port": ("dst_port", "dstport", "dest_port", "destination_port", "dp",
                 "resp_p", "id.resp_p", "dport", "l4_dst_port", "dpt", "dstpt"),
    "proto": ("proto", "protocol", "pr", "prot", "ip_proto", "protocol_name",
              "l4_proto"),
    "duration": ("duration", "dur", "td", "flow_duration", "duration_seconds"),
    "src_bytes": ("src_bytes", "orig_bytes", "sbytes", "bytes_out", "out_bytes",
                  "ibyt", "bytes_src", "bytes_toserver", "tx_bytes"),
    "dst_bytes": ("dst_bytes", "resp_bytes", "dbytes", "bytes_in", "in_bytes",
                  "obyt", "bytes_dst", "bytes_toclient", "rx_bytes"),
    "bytes": ("bytes", "total_bytes", "byt", "octets", "doctets", "num_bytes"),
    "src_pkts": ("src_pkts", "orig_pkts", "spkts", "packets_out", "out_pkts",
                 "ipkt", "pkts_src", "pkts_toserver", "tx_pkts"),
    "dst_pkts": ("dst_pkts", "resp_pkts", "dpkts", "packets_in", "in_pkts",
                 "opkt", "pkts_dst", "pkts_toclient", "rx_pkts"),
    "pkts": ("pkts", "packets", "pkt", "num_packets", "flow_packets"),
    "src_ip_bytes": ("src_ip_bytes", "orig_ip_bytes"),
    "dst_ip_bytes": ("dst_ip_bytes", "resp_ip_bytes"),
    "state": ("conn_state", "state", "tcp_state", "connection_state"),
    "flags": ("tcp_flags", "flags", "flg", "tcp_flag"),
    "action": ("action", "act", "disposition", "filter_action", "fw_action",
               "rule_action", "verdict"),
}


@dataclass(frozen=True)
class FormatProfile:
    """What one CSV format is called, and the minimum it must contain.

    ``required`` lists the canonical fields without which the honest features
    for this source cannot be computed, so their absence is a refusal rather
    than a silent zero. ``state_from`` says where the connection state comes
    from: a Zeek-style state column, a firewall action, or nowhere (defaulted,
    which is exactly why such sources carry failed_conn_ratio as a proxy).
    """

    source: str
    required: tuple[str, ...]
    state_from: str  # "column" | "action" | "none"
    note: str


_PROFILES: dict[str, FormatProfile] = {
    K.SOURCE_OP_FLOW_CSV: FormatProfile(
        source=K.SOURCE_OP_FLOW_CSV,
        # Bidirectional and stateful: both byte directions, packets, a state,
        # and a duration are all needed because all base features are real here.
        required=("ts", "src_ip", "dst_ip", "dst_port", "proto", "duration",
                  "src_bytes", "dst_bytes", "src_pkts", "dst_pkts", "state"),
        state_from="column",
        note="rich bidirectional flow CSV; all base features computed for real",
    ),
    K.SOURCE_OP_NETFLOW: FormatProfile(
        source=K.SOURCE_OP_NETFLOW,
        # Unidirectional and stateless: a single byte/packet count and a start
        # time is the floor. Duration and the reverse direction are inferred or
        # absent, which is why three features are proxies for this source.
        required=("ts", "src_ip", "dst_ip", "dst_port", "proto"),
        state_from="none",
        note=("unidirectional NetFlow; state/direction/duration approximate "
              "(failed_conn_ratio, updownlink_ratio, bidir_flow_duration are "
              "proxies)"),
    ),
    K.SOURCE_OP_FIREWALL: FormatProfile(
        source=K.SOURCE_OP_FIREWALL,
        # An action stands in for state; bytes/packets are often absent.
        required=("ts", "src_ip", "dst_ip", "dst_port", "proto", "action"),
        state_from="action",
        note=("firewall connection log; action stands in for state and packet "
              "size is approximate (all of the above plus mean_pkt_size are "
              "proxies)"),
    ),
}

SUPPORTED_SOURCES: tuple[str, ...] = tuple(_PROFILES)


# ---------------------------------------------------------------------------
# Column resolution
# ---------------------------------------------------------------------------
def _lower_lookup(df: pd.DataFrame) -> dict[str, str]:
    """Map a lowercased/trimmed column name to the actual column name."""
    out: dict[str, str] = {}
    for c in df.columns:
        key = str(c).strip().lower().lstrip("#").strip()
        # First spelling wins, so a file with both "src_ip" and "srcip" keeps
        # the one the reader saw first rather than silently switching.
        out.setdefault(key, c)
    return out


def _resolve(canonical: str, df: pd.DataFrame, lut: dict[str, str],
             overrides: dict[str, str]) -> pd.Series | None:
    """The source column for a canonical field, or None if the file lacks it.

    An explicit override always wins and is validated: a --column-map naming a
    column the file does not contain is an error, not a silent miss.
    """
    if canonical in overrides:
        want = overrides[canonical]
        if want not in df.columns:
            raise OperationalIngestError(
                f"--column-map maps {canonical!r} to {want!r}, which is not a "
                f"column in the file; it has {list(df.columns)}")
        return df[want]
    for alias in _ALIASES.get(canonical, ()):  # first alias present wins
        if alias in lut:
            return df[lut[alias]]
    return None


def _clean(s: pd.Series) -> pd.Series:
    """Trim and blank out the CSV's various "no value" tokens."""
    out = s.astype(str).str.strip()
    return out.mask(out.str.lower().isin(_UNSET), "")


def _numeric_str(s: pd.Series | None, n: int, *, default: str = "0"
                 ) -> pd.Series:
    """A string column safe for zeek.to_numeric: unset cells become ``default``.

    Kept as strings because the shared orientation code expects raw Zeek-style
    string columns and does the counted numeric coercion itself.
    """
    if s is None:
        return pd.Series([default] * n, dtype=object)
    c = _clean(s)
    return c.mask(c == "", default)


def _to_epoch_seconds(s: pd.Series) -> pd.Series:
    """Parse a timestamp column to float epoch seconds (NaN where unreadable).

    Accepts numeric epochs (seconds or milliseconds) and ISO/date strings. A
    millisecond epoch is detected by magnitude and rescaled, because a flow
    stamped in ms read as s would land 50 000 years in the future and every
    window boundary with it.
    """
    c = _clean(s)
    num = pd.to_numeric(c.where(c != ""), errors="coerce")
    # Millisecond epochs (~1.7e12) rescaled to seconds (~1.7e9). 1e12 seconds is
    # the year 33658, so anything above it is not a plausible second-count.
    num = num.where(num < 1e12, num / 1000.0)
    # Whatever stayed non-numeric is tried as a datetime string.
    unresolved = num.isna() & (c != "")
    if unresolved.any():
        dt = pd.to_datetime(c.where(unresolved), errors="coerce", utc=True)
        secs = dt.map(lambda x: x.timestamp() if pd.notna(x) else np.nan)
        num = num.fillna(pd.Series(secs, index=num.index))
    return num


def _proto_series(s: pd.Series | None, n: int) -> pd.Series:
    if s is None:
        return pd.Series(["-"] * n, dtype=object)
    c = _clean(s).str.lower()
    return c.map(lambda v: _PROTO_NUM.get(v, v) if v else "-")


def _state_series(profile: FormatProfile, df: pd.DataFrame,
                  lut: dict[str, str], overrides: dict[str, str],
                  n: int) -> pd.Series:
    """The Zeek-style conn_state column for this profile."""
    if profile.state_from == "column":
        st = _resolve("state", df, lut, overrides)
        if st is None:
            raise OperationalIngestError(
                f"{profile.source} needs a connection-state column (one of "
                f"{_ALIASES['state']}) to compute failed_conn_ratio for real; "
                "none was found. Provide it, map it with --column-map, or use "
                "--source op_netflow if this export has no state.")
        c = _clean(st)
        return c.mask(c == "", "OTH")
    if profile.state_from == "action":
        act = _resolve("action", df, lut, overrides)
        if act is None:
            raise OperationalIngestError(
                f"{profile.source} needs an action column (one of "
                f"{_ALIASES['action']}); none was found.")
        a = _clean(act).str.lower()

        def to_state(v: str) -> str:
            if v in _ACTION_ALLOW:
                return "SF"
            if v in _ACTION_DENY:
                return "REJ"
            return "OTH"
        return a.map(to_state)
    # state_from == "none": no signal available. A non-failed default, honest
    # because failed_conn_ratio is a declared proxy for such sources.
    return pd.Series(["SF"] * n, dtype=object)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def _read_csv(path: Path, max_rows: int | None) -> tuple[pd.DataFrame, int]:
    """Read a local CSV as all-strings, skipping malformed lines and counting.

    Empty tokens are kept as-is (na_filter off) so "unset" stays distinguishable
    from a real zero, the same discipline the Zeek reader keeps.
    """
    try:
        df = pd.read_csv(path, dtype=str, keep_default_na=False,
                         skipinitialspace=True, on_bad_lines="skip",
                         nrows=max_rows)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as exc:
        raise OperationalIngestError(
            f"{path.name} is not a readable CSV: {exc}") from exc
    df.columns = [str(c).strip() for c in df.columns]
    data_lines = max(0, zeek.count_data_lines(path) - 1)  # minus the header row
    return df, data_lines


def ingest(input_path: str | Path, *, source: str, scenario_id: str,
           device_ips: list[str] | None = None,
           column_map: dict[str, str] | None = None,
           max_flows: int | None = None,
           config_path: str | Path | None = None
           ) -> tuple[pd.DataFrame, dict]:
    """Turn one local flow CSV into an UNLABELLED observation frame plus report.

    ``source`` selects the format profile (one of :data:`SUPPORTED_SOURCES`).
    ``column_map`` maps canonical field -> the file's column name, for exports
    whose spellings are not in the built-in alias table. Nothing is written.
    """
    if source not in _PROFILES:
        raise OperationalIngestError(
            f"unknown CSV source {source!r}; expected one of "
            f"{list(SUPPORTED_SOURCES)}")
    profile = _PROFILES[source]
    overrides = dict(column_map or {})
    bad_override = set(overrides) - set(_ALIASES)
    if bad_override:
        raise OperationalIngestError(
            f"--column-map uses unknown canonical field(s) {sorted(bad_override)}; "
            f"valid fields are {sorted(_ALIASES)}")

    cfg = load_config(config_path)
    params = D.DeriveParams.from_config(cfg.iot23)

    path = Path(input_path)
    if not path.exists():
        raise OperationalIngestError(f"file not found: {path}")
    if path.is_dir():
        raise OperationalIngestError(
            f"{path} is a directory; pass a single CSV file")

    df, data_lines = _read_csv(path, max_flows)
    if df.empty:
        raise OperationalIngestError(f"{path.name} yielded no rows")

    lut = _lower_lookup(df)
    resolved: dict[str, str] = {}

    def note_resolved(canonical: str, series: pd.Series | None) -> None:
        if canonical in overrides:
            resolved[canonical] = f"{overrides[canonical]} (--column-map)"
        elif series is not None:
            for alias in _ALIASES.get(canonical, ()):
                if alias in lut:
                    resolved[canonical] = lut[alias]
                    break

    # Refuse early with the full shopping list, rather than one missing column
    # at a time.
    missing = [f for f in profile.required
               if _resolve(f, df, lut, overrides) is None
               and not (f == "state" and profile.state_from != "column")]
    if missing:
        wanted = {f: _ALIASES.get(f, ()) for f in missing}
        raise OperationalIngestError(
            f"{path.name} is missing column(s) required for --source {source}: "
            f"{missing}. Accepted spellings: {wanted}. It has "
            f"{list(df.columns)}. Map non-standard names with --column-map.")

    n = len(df)

    ts_src = _resolve("ts", df, lut, overrides)
    note_resolved("ts", ts_src)
    epoch = _to_epoch_seconds(ts_src)

    # Duration: taken as given, else inferred from an end-time column, else 0.
    dur_src = _resolve("duration", df, lut, overrides)
    if dur_src is not None:
        note_resolved("duration", dur_src)
        duration = _numeric_str(dur_src, n)
    else:
        end_src = _resolve("end_ts", df, lut, overrides)
        if end_src is not None:
            note_resolved("end_ts", end_src)
            span = (_to_epoch_seconds(end_src) - epoch).clip(lower=0)
            duration = span.map(lambda v: "0" if pd.isna(v) else repr(float(v)))
            resolved["duration"] = "derived from end_ts - ts"
        else:
            duration = pd.Series(["0"] * n, dtype=object)
            resolved["duration"] = "default 0 (not provided)"

    # Bytes/packets: prefer split directions; fall back to a single total on the
    # originator side (unidirectional), reverse direction 0.
    src_bytes = _resolve("src_bytes", df, lut, overrides)
    dst_bytes = _resolve("dst_bytes", df, lut, overrides)
    if src_bytes is None and dst_bytes is None:
        src_bytes = _resolve("bytes", df, lut, overrides)  # single total
    note_resolved("src_bytes", src_bytes)
    note_resolved("dst_bytes", dst_bytes)

    src_pkts = _resolve("src_pkts", df, lut, overrides)
    dst_pkts = _resolve("dst_pkts", df, lut, overrides)
    if src_pkts is None and dst_pkts is None:
        src_pkts = _resolve("pkts", df, lut, overrides)
    note_resolved("src_pkts", src_pkts)
    note_resolved("dst_pkts", dst_pkts)

    src_ipb = _resolve("src_ip_bytes", df, lut, overrides)
    dst_ipb = _resolve("dst_ip_bytes", df, lut, overrides)

    src_port = _resolve("src_port", df, lut, overrides)
    note_resolved("src_port", src_port)
    dst_port = _resolve("dst_port", df, lut, overrides)
    note_resolved("dst_port", dst_port)
    src_ip = _resolve("src_ip", df, lut, overrides)
    note_resolved("src_ip", src_ip)
    dst_ip = _resolve("dst_ip", df, lut, overrides)
    note_resolved("dst_ip", dst_ip)
    proto_src = _resolve("proto", df, lut, overrides)
    note_resolved("proto", proto_src)

    # Assemble the Zeek raw column shape the shared pipeline consumes. ip_bytes
    # default to payload bytes when the wire count is absent (an approximation,
    # and mean_pkt_size is a proxy for the sources where it can happen).
    sb = _numeric_str(src_bytes, n)
    db = _numeric_str(dst_bytes, n)
    raw = pd.DataFrame({
        Z_TS: epoch.map(lambda v: "-" if pd.isna(v) else repr(float(v))),
        Z_ORIG_H: _clean(src_ip) if src_ip is not None else "",
        Z_RESP_H: _clean(dst_ip) if dst_ip is not None else "",
        Z_ORIG_P: _numeric_str(src_port, n),
        Z_RESP_P: _numeric_str(dst_port, n),
        Z_PROTO: _proto_series(proto_src, n),
        Z_DURATION: duration,
        Z_ORIG_BYTES: sb,
        Z_RESP_BYTES: db,
        Z_ORIG_PKTS: _numeric_str(src_pkts, n),
        Z_RESP_PKTS: _numeric_str(dst_pkts, n),
        Z_ORIG_IP_BYTES: _numeric_str(src_ipb, n) if src_ipb is not None else sb,
        Z_RESP_IP_BYTES: _numeric_str(dst_ipb, n) if dst_ipb is not None else db,
        Z_CONN_STATE: _state_series(profile, df, lut, overrides, n),
        "_raw_label": "",  # unlabelled, always
    })

    stats = zeek.ReadStats(rows_read=n, data_lines_total=data_lines,
                           truncated_by_max_flows=bool(max_flows and
                                                       n >= max_flows))
    if not stats.truncated_by_max_flows:
        stats.rows_skipped_malformed = max(0, data_lines - n)

    try:
        scan = identify_devices(raw, explicit=device_ips)
        flows, orient = normalise_orientation(raw, scan.devices, stats)
    except IoT23Error as exc:
        raise OperationalIngestError(str(exc)) from exc

    windowed = W.assign_windows(flows[W.FLOW_COLS])
    derived = D.derive_features(windowed, source=source, params=params)
    index = derived.index
    m = len(index)

    flag_dicts = W.window_quality_flags(
        index,
        min_flows=int(cfg.iot23.min_flows_per_window),
        min_span_seconds=float(cfg.iot23.min_span_seconds),
    )

    obs = build_observations(
        derived.features,
        source_dataset=source,
        device_id=index[W.F_DEVICE_ID].tolist(),
        window_start=index[W.WINDOW_START].tolist(),
        research_class=[K.CLS_UNMAPPED] * m,
        original_label=[""] * m,
        scenario_id=scenario_id,
        extra_flags=flag_dicts,
    )
    assert_valid(obs)

    report = _report(path, source, profile, scenario_id, stats, scan, orient,
                     derived.diagnostics, obs, resolved, max_flows)
    return obs, report


def _report(input_path, source, profile, scenario_id, stats, scan, orient,
            diagnostics, obs, resolved, max_flows) -> dict:
    n_missing = obs[K.N_FEATURES_MISSING]
    # ReadStats.as_dict() names the separator "tab"/"whitespace_runs" — true for
    # the Zeek reader it was written for, a silent falsehood in a CSV report. The
    # rest of the block (row counts, coercions, ts drops) is format-neutral and
    # kept verbatim.
    read = stats.as_dict()
    read["separator_used"] = "comma"
    return {
        "adapter": "operational_csv",
        "source_dataset": source,
        "format_note": profile.note,
        "input": str(input_path),
        "scenario_id": scenario_id,
        "truncated_by_max_flows": bool(stats.truncated_by_max_flows),
        "max_flows": max_flows,
        "resolved_columns": resolved,
        "read": read,
        "devices": scan.as_dict(),
        "orientation": orient.as_dict(),
        "windowing": diagnostics,
        "observations": {
            "rows": int(len(obs)),
            "all_unmapped": bool((obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all()),
            "features_missing_min": int(n_missing.min()),
            "features_missing_median": float(n_missing.median()),
            "features_missing_max": int(n_missing.max()),
        },
        "features_unavailable_for_this_source": K.unavailable_features(source),
        "features_that_are_proxies": K.proxy_features(source),
        "detection_note": (
            "Unlabelled operational telemetry. Every window is review-only and "
            "carries research_class=unmapped; no class is asserted or confirmed. "
            "Any downstream alert is a rule-based suspicious-indicator pattern "
            "requiring analyst review, and is not ML-validated."
        ),
        "provenance_note": cfg_mod.operational_data_note(),
    }


# ===========================================================================
# CLI
# ===========================================================================
def _parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="python -m src.ingest.operational_csv",
        description=("Convert ONE authorised local flow-export CSV into the "
                     "product's observation schema as UNLABELLED, review-only "
                     "windows. Reads a local file only; never downloads, probes, "
                     "or connects to anything."),
        epilog=("Non-standard column names are mapped with --column-map, e.g. "
                "--column-map '{\"src_ip\": \"SourceIP\", \"ts\": \"EventTime\"}'."),
    )
    ap.add_argument("--input", required=True, help="path to a local flow CSV")
    ap.add_argument("--source", required=True, choices=SUPPORTED_SOURCES,
                    help="which flow-export format the CSV is")
    ap.add_argument("--scenario-id", required=True,
                    help="capture identifier, e.g. site-netflow-2026-08-20")
    ap.add_argument("--device-ip", action="append", default=None,
                    help="address of a monitored device; repeatable")
    ap.add_argument("--column-map", default=None,
                    help="JSON mapping of canonical field -> CSV column name")
    ap.add_argument("--max-flows", type=int, default=None,
                    help="read at most N rows (smoke tests)")
    ap.add_argument("--out", default=None,
                    help="output CSV (default: derived from --scenario-id)")
    ap.add_argument("--config", default=None, help="config YAML")
    return ap.parse_args(argv)


def _default_out(source: str, scenario_id: str) -> Path:
    from .operational_zeek import _SAFE_NAME
    safe = scenario_id.translate(_SAFE_NAME) or "operational"
    return cfg_mod.PROCESSED_DIR / f"{source}_{safe}.observations.csv"


def main(argv=None) -> int:
    args = _parse_args(argv)
    cfg_mod.ensure_dirs()
    column_map = None
    if args.column_map:
        try:
            column_map = json.loads(args.column_map)
            if not isinstance(column_map, dict):
                raise ValueError("must be a JSON object")
        except ValueError as exc:
            print(f"error: --column-map is not valid JSON: {exc}",
                  file=sys.stderr)
            return 2
    try:
        obs, report = ingest(
            args.input,
            source=args.source,
            scenario_id=args.scenario_id,
            device_ips=args.device_ip,
            column_map=column_map,
            max_flows=args.max_flows,
            config_path=args.config,
        )
    except (zeek.ZeekLogError, OperationalIngestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out = Path(args.out) if args.out else _default_out(args.source,
                                                       args.scenario_id)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_observations(obs, out)
    report_path = out.with_suffix(".report.json")
    report_path.write_text(json.dumps(report, indent=2, default=str),
                           encoding="utf-8")

    r = report
    print(f"wrote {len(obs)} observations -> {out}")
    print(f"       report              -> {report_path}")
    print(f"  format          {args.source}: {r['format_note']}")
    print(f"  rows read       {r['read']['rows_read']} of "
          f"{r['read']['data_lines_total']} data lines")
    if r["read"]["rows_skipped_malformed"]:
        print(f"  malformed lines {r['read']['rows_skipped_malformed']}")
    print(f"  devices         {r['devices']['n_devices']} "
          f"({r['devices']['basis']})")
    o = r["orientation"]
    print(f"  orientation     {o['device_is_originator']} outbound, "
          f"{o['device_is_responder']} inbound, "
          f"{o['no_device_involved_dropped']} dropped")
    print(f"  windows         {r['windowing']['windows']} "
          "(all review-only, research_class=unmapped)")
    print(f"  proxies         {r['features_that_are_proxies']}")
    print(f"  {cfg_mod.operational_data_note()}")
    if r["truncated_by_max_flows"]:
        print("  WARNING: run truncated by --max-flows.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
