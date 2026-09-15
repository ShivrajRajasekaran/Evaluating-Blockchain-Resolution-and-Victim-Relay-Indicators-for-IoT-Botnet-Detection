"""
features/windowing.py — the flow table contract, and flow -> device-window mapping.

WHY THIS FILE IS SEPARATE FROM THE IoT-23 ADAPTER
    Windowing knows nothing about Zeek, IoT-23, or labels. It takes a NORMALISED
    flow table (the columns below) and produces device-window groups. The adapter's
    job is to translate one specific log format into that table; this module's job
    is to define the unit of analysis. Keeping them apart means a second real
    source can be added later by writing one reader, not by re-deriving features.

THE UNIT OF ANALYSIS
    One observation = ONE DEVICE over ONE 5-MINUTE WINDOW. This is not a
    presentation choice, it is what makes the feature set well defined:
    distinct_dst_ports is 1 by definition for a single flow, flow_fanout is 1,
    and beacon_jitter needs at least three timestamps to exist at all. A per-flow
    pipeline computing these would emit degenerate constants and report a metric
    over them without complaining.

WINDOW ALIGNMENT
    Windows are floored to an absolute 300-second grid anchored at the Unix
    epoch, NOT to the first flow in the file. Two consequences, both wanted:
      * prepending or trimming flows does not shift every window boundary, so
        observation_ids stay stable across partial re-runs
      * two captures of the same device align, so their windows can be
        concatenated instead of interleaved at arbitrary offsets

FLOWS THAT SPAN WINDOW BOUNDARIES
    A flow is assigned in full to the window containing its START. The
    alternative — splitting bytes and packets proportionally across the windows
    it covers — requires assuming traffic is uniform over the flow's lifetime,
    which is false for exactly the long-lived relay flows this project cares
    about. Assignment by start time makes no such assumption. It does mean a
    window's byte counts can include traffic that physically occurred later;
    that is recorded here rather than hidden, and it is why bidir_flow_duration
    is defined as a per-flow property rather than a per-window sum.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.schema import columns as K

# ---------------------------------------------------------------------------
# The normalised flow table
# ---------------------------------------------------------------------------
# These are the Zeek conn.log fields this project actually uses, renamed to be
# format-neutral. A reader for any other flow format must produce exactly these.
F_DEVICE_ID = "device_id"      # str   the device under observation
F_TS = "ts"                    # datetime64[ns]  flow start
F_DURATION = "duration"        # float seconds; 0.0 for a single-packet flow
F_DST_IP = "dst_ip"            # str   remote peer
F_DST_PORT = "dst_port"        # int   remote port
F_PROTO = "proto"              # str   tcp / udp / icmp
F_ORIG_BYTES = "orig_bytes"    # float payload bytes device -> peer
F_RESP_BYTES = "resp_bytes"    # float payload bytes peer -> device
F_ORIG_IP_BYTES = "orig_ip_bytes"   # float IP-layer bytes device -> peer
F_RESP_IP_BYTES = "resp_ip_bytes"   # float IP-layer bytes peer -> device
F_ORIG_PKTS = "orig_pkts"      # float packets device -> peer
F_RESP_PKTS = "resp_pkts"      # float packets peer -> device
F_CONN_STATE = "conn_state"    # str   Zeek connection-state summary
F_OUTBOUND = "outbound"        # bool  True if the DEVICE initiated the flow
F_LABEL = "label"              # str   VERBATIM source label for this flow

# NOTE ON ORIENTATION. orig_* always means DEVICE -> PEER, whichever end opened
# the connection. A reader for a real capture must swap Zeek's orig/resp columns
# for flows where the device is the responder; otherwise updownlink_ratio is
# inverted for exactly the inbound-heavy devices a relay detector cares about.
#
# WHY F_OUTBOUND IS A SEPARATE COLUMN AND NOT DISCARDED AFTER THE SWAP
# Once orientation is normalised, the direction of INITIATION is no longer
# recoverable — and six features depend on it, because they are statements about
# what the device CHOSE to do:
#   distinct_dst_ports, scan_rate, login_burst_count, rpc_endpoint_ratio,
#   failed_conn_ratio, beacon_interval / beacon_jitter
# For an inbound flow the remote port is the peer's ephemeral source port, which
# the device did not select, and conn_state describes someone else's failed
# attempt. Counting those would make a benign device that is merely BEING
# scanned show high distinct_dst_ports and a high failed-connection ratio — it
# would look infected. Since one half of this project's research question is the
# false-positive rate on real benign IoT traffic, that error would corrupt the
# headline result rather than merely add noise.
#
# Payload bytes and IP-layer bytes are both required, and they are not
# interchangeable. updownlink_ratio is a statement about DATA symmetry, so it
# uses payload bytes; header bytes would dilute it toward 1.0 for every device.
# mean_pkt_size is a statement about WIRE packet size, so it uses IP-layer
# bytes; payload-only would put a SYN-probe window below the schema's 40-byte
# floor and force a clip that invents 40 bytes of evidence.
FLOW_COLS: list[str] = [
    F_DEVICE_ID, F_TS, F_DURATION, F_DST_IP, F_DST_PORT, F_PROTO,
    F_ORIG_BYTES, F_RESP_BYTES, F_ORIG_IP_BYTES, F_RESP_IP_BYTES,
    F_ORIG_PKTS, F_RESP_PKTS, F_CONN_STATE, F_OUTBOUND, F_LABEL,
]

NUMERIC_FLOW_COLS: list[str] = [
    F_DURATION, F_ORIG_BYTES, F_RESP_BYTES, F_ORIG_IP_BYTES, F_RESP_IP_BYTES,
    F_ORIG_PKTS, F_RESP_PKTS,
]

# The window column added by assign_windows(). Same name as the schema's, because
# it becomes that column.
WINDOW_START = K.WINDOW_START


class FlowTableError(ValueError):
    """The flow table does not meet the contract above."""


def validate_flow_table(flows: pd.DataFrame) -> None:
    """Check the flow table contract. Raises rather than coercing.

    Coercing would hide the two failures that matter: a reader that silently
    produced strings where seconds were expected (making every duration-based
    feature 0), and a reader that dropped a column (making a feature NaN for the
    whole capture, which looks like a data limitation rather than a bug).
    """
    missing = [c for c in FLOW_COLS if c not in flows.columns]
    if missing:
        raise FlowTableError(
            f"flow table is missing required column(s): {missing}; "
            f"expected all of {FLOW_COLS}"
        )
    if len(flows) == 0:
        raise FlowTableError("flow table is empty")

    if not pd.api.types.is_datetime64_any_dtype(flows[F_TS]):
        raise FlowTableError(
            f"{F_TS} must be datetime64, got {flows[F_TS].dtype}; "
            "string timestamps would sort lexicographically and silently "
            "produce the wrong window assignment"
        )
    if flows[F_TS].isna().any():
        raise FlowTableError(f"{F_TS} contains NaT; a flow with no start time "
                             "cannot be assigned to a window")

    for c in NUMERIC_FLOW_COLS:
        if not pd.api.types.is_numeric_dtype(flows[c]):
            raise FlowTableError(f"{c} must be numeric, got {flows[c].dtype}")
    if not pd.api.types.is_numeric_dtype(flows[F_DST_PORT]):
        raise FlowTableError(
            f"{F_DST_PORT} must be numeric, got {flows[F_DST_PORT].dtype}")

    for c in NUMERIC_FLOW_COLS:
        neg = flows[c] < 0
        if neg.any():
            raise FlowTableError(
                f"{c} has {int(neg.sum())} negative value(s); byte, packet and "
                "duration counts cannot be negative"
            )
    if flows[F_DEVICE_ID].isna().any():
        raise FlowTableError(f"{F_DEVICE_ID} contains nulls")

    if not pd.api.types.is_bool_dtype(flows[F_OUTBOUND]):
        raise FlowTableError(
            f"{F_OUTBOUND} must be bool dtype, got {flows[F_OUTBOUND].dtype}. "
            "Zeek writes 'T'/'F' strings for its boolean fields, and both are "
            "truthy — an object column here would mark every flow outbound and "
            "silently attribute a device's inbound traffic to its own choices."
        )


def assign_windows(flows: pd.DataFrame) -> pd.DataFrame:
    """Add the ``window_start`` column: each flow floored to the 300 s grid.

    Returns a new frame; the input is not modified.
    """
    validate_flow_table(flows)
    out = flows.copy()
    out[WINDOW_START] = out[F_TS].dt.floor(f"{K.WINDOW_SECONDS_VALUE}s")
    return out


def window_index(windowed: pd.DataFrame) -> pd.DataFrame:
    """Per-window diagnostics, one row per (device_id, window_start).

    Columns
    -------
    n_flows          flows assigned to the window
    n_outbound       flows the DEVICE initiated (see F_OUTBOUND)
    n_peers          distinct remote IPs contacted
    span_seconds     first-to-last flow start within the window (0 for one flow)
    n_bidir          flows where both directions carried payload bytes

    These are diagnostics, not features. They decide quality flags and appear in
    the adapter's coverage report; no model sees them. ``n_outbound`` is the one
    exception in spirit — scan_rate is derived from it — because the alternative
    is a second groupby computing the same number.
    """
    if WINDOW_START not in windowed.columns:
        raise FlowTableError(
            f"{WINDOW_START} not present; call assign_windows() first")

    g = windowed.groupby([F_DEVICE_ID, WINDOW_START], sort=True)
    idx = g.agg(
        n_flows=(F_TS, "size"),
        n_peers=(F_DST_IP, "nunique"),
        first_ts=(F_TS, "min"),
        last_ts=(F_TS, "max"),
    )
    idx["span_seconds"] = (
        idx.pop("last_ts") - idx.pop("first_ts")).dt.total_seconds()

    flags = windowed.assign(
        _b=(windowed[F_ORIG_BYTES] > 0) & (windowed[F_RESP_BYTES] > 0),
        _o=windowed[F_OUTBOUND].astype(bool),
    ).groupby([F_DEVICE_ID, WINDOW_START], sort=True)[["_b", "_o"]].sum()
    idx["n_bidir"] = flags["_b"].astype("int64")
    idx["n_outbound"] = flags["_o"].astype("int64")
    return idx.reset_index()


def window_quality_flags(index: pd.DataFrame, *, min_flows: int,
                         min_span_seconds: float) -> list[dict[str, None]]:
    """One flag dict per row of ``index``, ready for ``build_observations``.

    low_flow_count   Below ``min_flows``, per-window rates and entropies are
                     dominated by sampling noise rather than behaviour. The row
                     is kept — dropping thin windows would bias the sample
                     toward busy devices — but the reader is told.
    single_peer      Only one remote peer, so flow_fanout is 1 by construction
                     and carries no information for this row.
    short_window     All flows arrived within a burst much shorter than the
                     window, so a per-minute rate extrapolates a burst to five
                     minutes and understates the instantaneous rate.
    """
    flags: list[dict[str, None]] = []
    n_flows = index["n_flows"].to_numpy()
    n_peers = index["n_peers"].to_numpy()
    span = index["span_seconds"].to_numpy()
    for i in range(len(index)):
        f: dict[str, None] = {}
        if n_flows[i] < min_flows:
            f[K.FLAG_LOW_FLOW_COUNT] = None
        if n_peers[i] <= 1:
            f[K.FLAG_SINGLE_PEER] = None
        if n_flows[i] > 1 and span[i] < min_span_seconds:
            f[K.FLAG_SHORT_WINDOW] = None
        flags.append(f)
    return flags


def coverage_report(windowed: pd.DataFrame, index: pd.DataFrame) -> dict:
    """Summary of what windowing did, for the adapter's stdout and the docs.

    Reported rather than computed silently because the flow-to-window ratio is
    the first thing to check when a real capture produces surprising features:
    a capture of 2 million flows that yields 40 windows is one busy device, not
    a population.
    """
    return {
        "flows": int(len(windowed)),
        "devices": int(windowed[F_DEVICE_ID].nunique()),
        "windows": int(len(index)),
        "flows_per_window_median": float(index["n_flows"].median()),
        "flows_per_window_max": int(index["n_flows"].max()),
        "windows_per_device_median": float(
            index.groupby(F_DEVICE_ID).size().median()),
        "capture_span_hours": float(
            (windowed[F_TS].max() - windowed[F_TS].min()).total_seconds() / 3600),
        "single_flow_windows": int((index["n_flows"] == 1).sum()),
        "windows_with_no_bidir_flow": int((index["n_bidir"] == 0).sum()),
        # A capture dominated by inbound flows is a capture of a device being
        # talked AT, and six of the eleven derivable features are statements
        # about what the device initiated. If this is near 1.0, those six are
        # near-empty for most windows and the reader needs to know before
        # interpreting any of them.
        "inbound_flow_fraction": float(
            1.0 - index["n_outbound"].sum() / index["n_flows"].sum()),
        "windows_with_no_outbound_flow": int((index["n_outbound"] == 0).sum()),
    }
