"""
features/derive.py — the 16 features, computed from a windowed flow table.

This file and src/schema/columns.py are the two places where the project's
measurement decisions actually live. Every definition below is a choice with a
defensible alternative, so each one carries its reasoning.

THREE RULES THAT APPLY TO EVERY FEATURE
---------------------------------------
1. NOT MEASURABLE IS NaN, NEVER ZERO.
   A window with two flows to its busiest peer has one inter-arrival gap, so its
   beacon jitter does not exist. Writing 0.0 there would claim perfectly regular
   beaconing — the single most malicious-looking value the feature can take —
   on the basis of no evidence. NaN says "unknown", is counted in
   n_features_missing, and raises FLAG_MISSING_FEATURES on the row.

   This differs from the mock generator, where 0.0 for beacon_interval means
   "this device does not beacon", a fact the generator knows. Two different
   states, deliberately two different encodings. Any model scored across both
   sources must therefore have an explicit NaN policy; see
   docs/evaluation-protocol.md. It is not decided here.

2. GROUP BOUNDARIES ARE KEPT CLEAN.
   Several natural definitions would let scanning behaviour bleed into the relay
   group (see bidir_flow_duration and flow_fanout). If a relay feature rises
   whenever a device scans, then "relay features add value" becomes
   unfalsifiable — the feature is just measuring infection again under another
   name, and the project's central question cannot be answered.

3. PROXIES ARE NAMED AS PROXIES.
   Two features are approximations on real capture data. They are declared
   AVAIL_PROXY in the schema, flagged on every row, and defined here so a
   reviewer can judge how good the approximation is rather than take it on trust.

DIRECTION OF INITIATION
-----------------------
Six of the eleven derivable features are computed over OUTBOUND flows only —
flows the device itself opened (``windowing.F_OUTBOUND``):

    rpc_endpoint_ratio, login_burst_count, scan_rate, distinct_dst_ports,
    failed_conn_ratio, beacon_interval / beacon_jitter

Each is a statement about a CHOICE the device made: which port it dialled, how
often it dialled, whether its own attempts failed. For an inbound flow the
remote port is the peer's ephemeral source port and conn_state describes someone
else's failed attempt, so including inbound flows would make a benign device
that is merely being port-scanned show high port variety and a high failure
ratio — indistinguishable from an infected one. The remaining five
(bidir_flow_duration, flow_fanout, updownlink_ratio, mean_pkt_size) are
statements about traffic that occurred, and use every flow: a relay's whole
point is that it accepts inbound connections.

When a window has no outbound flow at all, the counts are 0.0 (a measurement:
the device initiated nothing) and the ratios are NaN (no denominator). That
split follows rule 1, not convenience.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from src.schema import columns as K

from . import windowing as W

# Minutes per window, for the per-minute rate features.
_WINDOW_MINUTES = K.WINDOW_SECONDS_VALUE / 60.0


@dataclass
class DeriveParams:
    """Everything the derivation needs that is not in the flow table.

    Passed explicitly rather than read from the config here, so this module has
    no opinion about config file shape and can be tested with plain literals.
    """

    # Zeek conn_state values counted as failed outbound connections.
    failed_conn_states: tuple[str, ...] = (
        "S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR")
    # Ports treated as credential-attack targets (login_burst_count proxy).
    login_ports: tuple[int, ...] = (22, 23, 2323, 5555)
    # Standard name-resolution ports: the denominator baseline for the
    # rpc_endpoint_ratio proxy.
    resolver_ports: tuple[int, ...] = (53, 5353)
    # JSON-RPC ports: the numerator of the rpc_endpoint_ratio proxy.
    rpc_proxy_ports: tuple[int, ...] = (8545, 8546)

    @classmethod
    def from_config(cls, node) -> "DeriveParams":
        return cls(
            failed_conn_states=tuple(node.failed_conn_states),
            login_ports=tuple(node.login_ports),
            resolver_ports=tuple(node.resolver_ports),
            rpc_proxy_ports=tuple(node.rpc_proxy_ports),
        )


@dataclass
class Derived:
    features: pd.DataFrame          # one row per window, aligned to `index`
    index: pd.DataFrame             # device_id, window_start, n_flows, ...
    diagnostics: dict = field(default_factory=dict)


# ===========================================================================
# Helpers
# ===========================================================================
def _keys(index: pd.DataFrame) -> pd.MultiIndex:
    return pd.MultiIndex.from_frame(index[[W.F_DEVICE_ID, W.WINDOW_START]])


def _align(series: pd.Series, keys: pd.MultiIndex,
           fill: float | None = None) -> np.ndarray:
    """Reindex a groupby result onto the canonical window order.

    Explicit reindexing rather than relying on two groupby calls producing the
    same row order: a silent misalignment here would attach one window's
    features to another window's label, and every downstream metric would be
    computed on shuffled data without any error being raised.
    """
    out = series.reindex(keys)
    if fill is not None:
        out = out.fillna(fill)
    return out.to_numpy(dtype="float64")


def _group(df: pd.DataFrame):
    return df.groupby([W.F_DEVICE_ID, W.WINDOW_START], sort=False)


def _outbound(windowed: pd.DataFrame) -> pd.DataFrame:
    """The subset of flows the device itself opened. See the module docstring."""
    return windowed[windowed[W.F_OUTBOUND].astype(bool)]


def _zeros(keys: pd.MultiIndex) -> np.ndarray:
    return np.zeros(len(keys), dtype="float64")


def _nans(keys: pd.MultiIndex) -> np.ndarray:
    return np.full(len(keys), np.nan, dtype="float64")


# ===========================================================================
# Resolution group
# ===========================================================================
def _rpc_endpoint_ratio(out_flows: pd.DataFrame, keys: pd.MultiIndex,
                        p: DeriveParams) -> np.ndarray:
    """PROXY. Share of name-resolution-like traffic going to a JSON-RPC port.

    OUTBOUND flows only: the feature is about which resolver the device chose.

    The real feature is "fraction of lookups directed at non-standard
    resolvers", which needs dns.log. Here the denominator is flows to a standard
    resolver port or a JSON-RPC port, and the numerator is the JSON-RPC part.

    443 AND 8443 ARE DELIBERATELY EXCLUDED, although public Ethereum RPC
    providers do serve on 443. Without SNI or payload — neither of which
    conn.log.labeled carries — RPC-over-HTTPS is indistinguishable from ordinary
    HTTPS. Including 443 would put nearly every device's ratio at ~1.0 and
    manufacture a strong-looking feature that actually measures "this device
    uses TLS". A near-constant 0.0 across a real capture is the honest result and
    is itself the finding: IoT-23 contains no observable blockchain-RPC traffic.

    NaN when the device made no resolver-like connection at all in the window —
    the ratio has no denominator, so it has no value.
    """
    if out_flows.empty:
        return _nans(keys)
    port = out_flows[W.F_DST_PORT]
    is_rpc = port.isin(p.rpc_proxy_ports)
    is_resolver = port.isin(p.resolver_ports)
    denom = _align(_group(out_flows.assign(_d=is_rpc | is_resolver))["_d"].sum(),
                   keys, fill=0.0)
    numer = _align(_group(out_flows.assign(_n=is_rpc))["_n"].sum(), keys,
                   fill=0.0)
    return np.divide(numer, denom, out=_nans(keys), where=denom > 0)


# ===========================================================================
# Relay group
# ===========================================================================
def _bidir_mask(windowed: pd.DataFrame) -> pd.Series:
    """A flow is bidirectional when both directions carried payload bytes.

    Payload, not IP bytes: a TCP handshake plus RST moves IP bytes in both
    directions while exchanging no data, and counting that as an exchange would
    make every refused scan attempt look like a conversation.
    """
    return (windowed[W.F_ORIG_BYTES] > 0) & (windowed[W.F_RESP_BYTES] > 0)


def _bidir_flow_duration(windowed: pd.DataFrame, keys: pd.MultiIndex
                         ) -> np.ndarray:
    """MEAN duration of the window's bidirectional flows.

    Mean, not max: the maximum is set by one flow and is highly sensitive to the
    assignment-by-start-time rule, so it would vary with where a capture happens
    to be cut.

    Bidirectional only, and this is the important part. A scanning device emits
    hundreds of one-way flows with duration 0. Averaging over all flows would
    drive this toward 0 exactly when the device is scanning, so the feature would
    become an inverted scan detector living in the relay group. See rule 2.

    0.0 when the window contains no bidirectional flow. That is a measurement,
    not a gap: the device demonstrably held no two-way conversation.
    """
    bidir = windowed[_bidir_mask(windowed)]
    if bidir.empty:
        return _zeros(keys)
    return _align(_group(bidir)[W.F_DURATION].mean(), keys, fill=0.0)


def _flow_fanout(windowed: pd.DataFrame, keys: pd.MultiIndex) -> np.ndarray:
    """Distinct peers the device EXCHANGED data with (bidirectional only).

    Counting every contacted address instead would put a scanning device in the
    hundreds while the mock generator's relay devices sit near 8, so the two
    sources would not be on the same scale — and, again by rule 2, the relay
    group would be measuring scanning.

    All flows, not outbound only: a relay accepts inbound connections, and a peer
    that opened a two-way conversation with the device is a peer of the device.
    """
    bidir = windowed[_bidir_mask(windowed)]
    if bidir.empty:
        return _zeros(keys)
    return _align(_group(bidir)[W.F_DST_IP].nunique(), keys, fill=0.0)


def _updownlink_ratio(windowed: pd.DataFrame, keys: pd.MultiIndex
                      ) -> tuple[np.ndarray, float]:
    """Uplink payload bytes / downlink payload bytes, capped at the schema max.

    Returns the feature and the fraction of windows that hit the cap, because
    that fraction is a distribution-shift warning that must be reported rather
    than absorbed. A window with uplink but no downlink (a pure scan or probe
    burst) has an infinite ratio and lands on the cap; the mock generator never
    produces values above ~1.8, so a real capture full of capped windows is NOT
    comparable to mock-trained scores. See docs/limitations.md.

    NaN when neither direction moved any payload at all.
    """
    up = _align(_group(windowed)[W.F_ORIG_BYTES].sum(), keys, fill=0.0)
    down = _align(_group(windowed)[W.F_RESP_BYTES].sum(), keys, fill=0.0)
    hi = K.FEATURE_RANGES["updownlink_ratio"][1]

    ratio = _nans(keys)
    both_zero = (up == 0) & (down == 0)
    np.divide(up, down, out=ratio, where=down > 0)
    ratio[(down == 0) & (up > 0)] = hi          # infinite -> the cap
    ratio[both_zero] = np.nan
    capped = ratio >= hi
    ratio = np.clip(ratio, 0.0, hi)
    n_valid = int((~np.isnan(ratio)).sum())
    cap_rate = float(np.nansum(capped) / n_valid) if n_valid else 0.0
    return ratio, cap_rate


# ===========================================================================
# Infection group
# ===========================================================================
def _login_burst_count(out_flows: pd.DataFrame, keys: pd.MultiIndex,
                       p: DeriveParams) -> np.ndarray:
    """PROXY. OUTBOUND connection attempts to Telnet/SSH-family ports.

    The real feature counts login ATTEMPTS. conn.log has no authentication
    visibility, so this counts connections to the configured ports instead. It
    therefore overcounts (a legitimate SSH session is one "attempt") and
    undercounts (many attempts inside one connection are one flow). The
    direction of the error is not knowable per row, which is exactly why the
    feature is flagged as a proxy on every row it appears on.

    Outbound only: this feature exists to detect a device SPREADING an infection.
    Inbound attempts to port 23 mean the device is a target, which is the normal
    background condition of any internet-exposed IoT device and would swamp the
    signal with the ambient scanning of the internet.
    """
    if out_flows.empty:
        return _zeros(keys)
    hit = out_flows[W.F_DST_PORT].isin(p.login_ports)
    return _align(_group(out_flows.assign(_l=hit))["_l"].sum(), keys, fill=0.0)


def _failed_conn_ratio(out_flows: pd.DataFrame, keys: pd.MultiIndex,
                       p: DeriveParams) -> np.ndarray:
    """Fraction of the device's OWN connection attempts that failed.

    Outbound only, and this is not a refinement — it is the difference between
    two opposite meanings. Zeek's conn_state describes the ORIGINATOR's attempt.
    On an outbound flow, S0 or REJ means the device dialled something that was
    not there, the classic signature of scanning a random address space. On an
    inbound flow the same value means someone else failed to reach the device,
    which says nothing about the device at all.

    NaN when the device initiated nothing: a ratio with no denominator.
    """
    if out_flows.empty:
        return _nans(keys)
    failed = out_flows[W.F_CONN_STATE].isin(p.failed_conn_states)
    return _align(_group(out_flows.assign(_f=failed))["_f"].mean(), keys)


# ===========================================================================
# Payload group
# ===========================================================================
def _modal_peer_gaps(out_flows: pd.DataFrame) -> pd.DataFrame:
    """Inter-arrival gaps to each window's most-contacted peer.

    Beaconing is periodic contact with ONE endpoint. Pooling gaps across all
    peers would interleave several independent schedules and destroy the
    periodicity the feature exists to detect — a device beaconing every 60 s to
    its C2 while also talking to an NTP server would show a jitter driven by the
    interleaving, not by the beacon.

    Ties on flow count are broken by the lowest dst_ip so the choice is
    deterministic and a re-run produces identical values.
    """
    counts = (out_flows.groupby([W.F_DEVICE_ID, W.WINDOW_START, W.F_DST_IP],
                                sort=False)
              .size().rename("n").reset_index())
    counts = counts.sort_values(
        [W.F_DEVICE_ID, W.WINDOW_START, "n", W.F_DST_IP],
        ascending=[True, True, False, True], kind="mergesort")
    modal = counts.drop_duplicates(
        [W.F_DEVICE_ID, W.WINDOW_START])[
            [W.F_DEVICE_ID, W.WINDOW_START, W.F_DST_IP]]

    sub = out_flows.merge(modal,
                          on=[W.F_DEVICE_ID, W.WINDOW_START, W.F_DST_IP],
                          how="inner")
    sub = sub.sort_values([W.F_DEVICE_ID, W.WINDOW_START, W.F_TS],
                          kind="mergesort")
    gaps = _group(sub)[W.F_TS].diff().dt.total_seconds()
    return sub.assign(_gap=gaps)


def _beaconing(out_flows: pd.DataFrame, keys: pd.MultiIndex
               ) -> tuple[np.ndarray, np.ndarray]:
    """beacon_interval (median gap) and beacon_jitter (sd of gaps).

    OUTBOUND flows only: a beacon is the device calling home on a schedule.
    Inbound arrivals are the peer's schedule, not the device's, and mixing them
    in would measure the interleaving of the two.

    Jitter is a standard deviation in seconds, not a variance, matching the mock
    generator's scale (benign ~15 s around a ~90 s interval; malicious ~1.9 s
    around a ~55 s one).

    Both are NaN when unmeasurable — interval needs 2 timestamps to the modal
    peer, jitter needs 3. Rule 1: a jitter of 0.0 is the most malicious-looking
    value in the feature's range, and asserting it from a single gap would be
    fabricated evidence of a perfectly regular beacon.
    """
    if out_flows.empty:
        return _nans(keys), _nans(keys)
    gapped = _modal_peer_gaps(out_flows)
    agg = _group(gapped)["_gap"].agg(["median", "std", "count"])
    interval = _align(agg["median"], keys)
    # pandas std uses ddof=1, so a single gap already yields NaN. Made explicit
    # rather than relied upon.
    jitter = _align(agg["std"], keys)
    n_gaps = _align(agg["count"], keys, fill=0.0)
    interval[n_gaps < 1] = np.nan
    jitter[n_gaps < 2] = np.nan
    return interval, jitter


def _mean_pkt_size(windowed: pd.DataFrame, keys: pd.MultiIndex) -> np.ndarray:
    """Mean wire packet size: IP-layer bytes / packets, both directions.

    IP-layer bytes because this is a statement about packets on the wire.
    Payload-only would make a SYN-probe window average 0 bytes per packet, which
    is below the schema's 40-byte floor and would be clipped up to 40 — inventing
    a header the measurement never saw.

    NaN when no packets, or when the source reported no IP bytes for a window
    that did have packets (some Zeek protocol analysers leave the field at 0).
    """
    ip_bytes = _align(
        _group(windowed.assign(
            _b=windowed[W.F_ORIG_IP_BYTES] + windowed[W.F_RESP_IP_BYTES]))["_b"]
        .sum(), keys, fill=0.0)
    pkts = _align(
        _group(windowed.assign(
            _p=windowed[W.F_ORIG_PKTS] + windowed[W.F_RESP_PKTS]))["_p"]
        .sum(), keys, fill=0.0)
    out = np.full(len(keys), np.nan, dtype="float64")
    ok = (pkts > 0) & (ip_bytes > 0)
    np.divide(ip_bytes, pkts, out=out, where=ok)
    lo, hi = K.FEATURE_RANGES["mean_pkt_size"]
    return np.where(ok, np.clip(out, lo, hi), np.nan)

# ===========================================================================
# Entry point
# ===========================================================================
# Sources that have a flow log to derive from. Track B is absent on purpose:
# the mock generator emits the 16 features directly and never produces a flow
# table, so FEATURE_AVAILABILITY marks all 16 "computable" for it as a statement
# about the GENERATOR's output, not about any log this module could read.
# Calling derive_features() on it would silently return 11 of 16 features.
#
# The operational sources (authorised Zeek/CSV/NetFlow/firewall captures the
# product ingests) DO produce a flow table in FLOW_COLS, so the same eleven
# features are derived from them. They are unlabelled — every row is unmapped —
# but feature derivation is label-agnostic, and each carries a FEATURE_AVAILABILITY
# entry whose computable+proxy union is exactly these eleven.
FLOW_DERIVED_SOURCES: tuple[str, ...] = (
    (K.SOURCE_IOT23, K.SOURCE_ZEEK_BUNDLE) + K.OPERATIONAL_SOURCES)


def derive_features(windowed: pd.DataFrame, *, source: str,
                    params: DeriveParams | None = None,
                    applayer: pd.DataFrame | None = None) -> Derived:
    """Compute the feature table for a windowed flow frame.

    Only features the schema declares COMPUTABLE or PROXY for ``source`` are
    calculated; the rest are left absent and become NaN in
    ``build_observations``. The declaration in
    :data:`K.FEATURE_AVAILABILITY` is the authority, not this function — so
    adding a real dns.log reader later means changing the availability table and
    adding a formula, and forgetting either half fails the agreement check below.
    """
    if source not in K.SOURCE_DATASETS:
        raise ValueError(f"unknown source {source!r}")
    if source not in FLOW_DERIVED_SOURCES:
        raise ValueError(
            f"{source!r} has no flow log to derive from; features for it are "
            f"produced at their origin. Flow-derived sources: "
            f"{list(FLOW_DERIVED_SOURCES)}"
        )
    p = params or DeriveParams()

    index = W.window_index(windowed)
    keys = _keys(index)
    # Flows the device opened. Six features are computed over this subset only;
    # see DIRECTION OF INITIATION in the module docstring.
    out_flows = _outbound(windowed)
    n_outbound = index["n_outbound"].to_numpy(dtype="float64")

    ratio, cap_rate = _updownlink_ratio(windowed, keys)
    interval, jitter = _beaconing(out_flows, keys)

    computed: dict[str, np.ndarray] = {
        # resolution
        "rpc_endpoint_ratio": _rpc_endpoint_ratio(out_flows, keys, p),
        # relay
        "bidir_flow_duration": _bidir_flow_duration(windowed, keys),
        "flow_fanout": _flow_fanout(windowed, keys),
        "updownlink_ratio": ratio,
        # infection
        "login_burst_count": _login_burst_count(out_flows, keys, p),
        "scan_rate": n_outbound / _WINDOW_MINUTES,
        "distinct_dst_ports": (
            _zeros(keys) if out_flows.empty else
            _align(_group(out_flows)[W.F_DST_PORT].nunique(), keys, fill=0.0)),
        "failed_conn_ratio": _failed_conn_ratio(out_flows, keys, p),
        # payload
        "beacon_interval": interval,
        "beacon_jitter": jitter,
        "mean_pkt_size": _mean_pkt_size(windowed, keys),
    }

    # Features this module cannot compute from a flow table, supplied by the
    # caller. Only src/features/applayer.py produces them, and only for a source
    # whose telemetry actually contains dns/http/ssl. They are merged BEFORE the
    # agreement check so the same check governs both halves: a source that
    # declares ens_query_rate computable but is handed no applayer frame fails
    # here rather than silently emitting eleven of sixteen features.
    if applayer is not None:
        if len(applayer) != len(index):
            raise RuntimeError(
                f"applayer has {len(applayer)} rows but the window index has "
                f"{len(index)}; refusing to attach features to the wrong windows")
        for name in applayer.columns:
            computed[name] = applayer[name].to_numpy(dtype="float64")

    # The availability table decides what may be emitted, so a formula added
    # here without updating the table has no effect, and a table entry promoted
    # to computable without a formula fails loudly instead of emitting zeros.
    expected = set(K.features_by_availability(source, K.AVAIL_COMPUTABLE)) | \
        set(K.features_by_availability(source, K.AVAIL_PROXY))
    if set(computed) != expected:
        raise RuntimeError(
            "derive_features and FEATURE_AVAILABILITY disagree for "
            f"{source}: no formula for {sorted(expected - set(computed))}, "
            f"formula but declared unavailable for "
            f"{sorted(set(computed) - expected)}"
        )

    features = pd.DataFrame(computed)
    diagnostics = {
        **W.coverage_report(windowed, index),
        "updownlink_ratio_capped_fraction": cap_rate,
        "beacon_interval_unmeasurable_fraction": float(
            np.isnan(interval).mean()),
        "beacon_jitter_unmeasurable_fraction": float(np.isnan(jitter).mean()),
        "rpc_endpoint_ratio_undefined_fraction": float(
            np.isnan(computed["rpc_endpoint_ratio"]).mean()),
        "rpc_endpoint_ratio_nonzero_fraction": float(
            np.nanmean(computed["rpc_endpoint_ratio"] > 0)
            if not np.isnan(computed["rpc_endpoint_ratio"]).all() else 0.0),
        "failed_conn_ratio_undefined_fraction": float(
            np.isnan(computed["failed_conn_ratio"]).mean()),
    }
    return Derived(features=features, index=index, diagnostics=diagnostics)
