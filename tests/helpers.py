"""
tests/helpers.py — frame builders shared by the test modules.

Every test that needs an observation frame gets it from here. Writing the
metadata columns by hand inside each test would mean 17 test modules each
encoding their own idea of a valid row, and the first schema change would break
all of them in slightly different ways.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from src.schema import build_observations
from src.schema import columns as K

# Midpoint of each feature's declared range, so a default row is valid by
# construction and a test that cares about one feature only has to set that one.
_DEFAULTS: dict[str, float] = {
    "ens_query_rate": 1.0,
    "rpc_endpoint_ratio": 0.1,
    "resolution_entropy": 2.5,
    "serverlist_pull": 0.0,
    "bidir_flow_duration": 40.0,
    "flow_fanout": 3.0,
    "upnp_addportmapping": 0.0,
    "updownlink_ratio": 0.45,
    "login_burst_count": 1.0,
    "scan_rate": 1.0,
    "distinct_dst_ports": 3.0,
    "failed_conn_ratio": 0.1,
    "beacon_interval": 60.0,
    "beacon_jitter": 10.0,
    "rc4_string_score": 0.1,
    "mean_pkt_size": 300.0,
}


def feature_frame(n: int = 4, **overrides) -> pd.DataFrame:
    """``n`` rows of in-range feature values. ``feature_frame(2, scan_rate=9)``
    overrides one column for every row."""
    data = {c: np.full(n, _DEFAULTS[c], dtype="float64") for c in K.FEATURE_COLS}
    for col, val in overrides.items():
        if col not in K.FEATURE_COLS:
            raise KeyError(f"{col!r} is not a feature column")
        data[col] = np.asarray(
            val if np.ndim(val) else np.full(n, val), dtype="float64")
    return pd.DataFrame(data)


def windows(n: int, start: str = "2026-01-06T00:00:00") -> list[pd.Timestamp]:
    """``n`` consecutive 5-minute window starts."""
    t0 = pd.Timestamp(start)
    return [t0 + pd.Timedelta(seconds=K.WINDOW_SECONDS_VALUE * i)
            for i in range(n)]


def mock_frame(n: int = 4,
               research_class: str = K.CLS_BENIGN_MOCK,
               device_prefix: str = "mockdev",
               scenario_id: str = "mock-test-01",
               n_devices: int = 2,
               **feature_overrides) -> pd.DataFrame:
    """A valid Track B (mock) observation frame."""
    feats = feature_frame(n, **feature_overrides)
    devices = [f"{device_prefix}-{i % n_devices:02d}" for i in range(n)]
    return build_observations(
        feats,
        source_dataset=K.SOURCE_MOCK_LOCAL,
        device_id=devices,
        window_start=windows(n),
        research_class=[research_class] * n,
        original_label=[research_class] * n,
        scenario_id=scenario_id,
    )


def iot23_frame(n: int = 4,
                research_class: str = K.CLS_BENIGN_REAL,
                original_label: str = "Benign",
                scenario_id: str = "CTU-IoT-Malware-Capture-TEST-1",
                n_devices: int = 2,
                **feature_overrides) -> pd.DataFrame:
    """A valid Track A (IoT-23) observation frame.

    build_observations forces the five IoT-23-unavailable features to NaN, so
    passing values for them here is harmless — which is itself worth asserting,
    and test_schema_build does.
    """
    feats = feature_frame(n, **feature_overrides)
    devices = [f"192.168.1.{100 + (i % n_devices)}" for i in range(n)]
    return build_observations(
        feats,
        source_dataset=K.SOURCE_IOT23,
        device_id=devices,
        window_start=windows(n),
        research_class=[research_class] * n,
        original_label=[original_label] * n,
        scenario_id=scenario_id,
    )


def op_frame(n: int = 4,
             source_dataset: str = K.SOURCE_OP_ZEEK,
             device_prefix: str = "opdev",
             scenario_id: str = "op-ingest-TEST-1",
             n_devices: int = 2,
             **feature_overrides) -> pd.DataFrame:
    """A valid operational (product-ingest) observation frame.

    Operational telemetry is UNLABELLED, so every row is research_class=unmapped
    with a verbatim empty original_label. build_observations forces the source's
    unavailable features to NaN and adds the proxy and unmapped-label flags, so a
    frame from here validates for any of K.OPERATIONAL_SOURCES.
    """
    feats = feature_frame(n, **feature_overrides)
    devices = [f"{device_prefix}-{i % n_devices:02d}" for i in range(n)]
    return build_observations(
        feats,
        source_dataset=source_dataset,
        device_id=devices,
        window_start=windows(n),
        research_class=[K.CLS_UNMAPPED] * n,
        original_label=[""] * n,
        scenario_id=scenario_id,
    )


# ---------------------------------------------------------------------------
# Flow tables (for src/features/windowing.py and derive.py)
# ---------------------------------------------------------------------------
# Defaults describe one unremarkable bidirectional TCP conversation, so a test
# that cares about one column sets only that column and every other value stays
# valid. Every default is deliberately non-zero where zero would be a special
# case in the derivation (bytes, packets), so an accidental zero in a test is
# the test's own doing and not inherited noise.
_FLOW_DEFAULTS: dict[str, object] = {
    "duration": 10.0,
    "dst_ip": "203.0.113.10",     # RFC 5737 documentation range
    "dst_port": 443,
    "proto": "tcp",
    "orig_bytes": 500.0,
    "resp_bytes": 1500.0,
    "orig_ip_bytes": 800.0,
    "resp_ip_bytes": 1900.0,
    "orig_pkts": 6.0,
    "resp_pkts": 8.0,
    "conn_state": "SF",
    # The device opened the connection. Default True because the features that
    # depend on it are all about what the device chose to do, so a test about
    # those features should not have to opt in to being measured at all.
    "outbound": True,
    "label": "Benign",
}


def flow_table(n: int = 6, *, device_id="dev-00",
               ts="2026-01-06T00:00:00", gap_seconds: float = 30.0,
               **overrides) -> pd.DataFrame:
    """``n`` flows for one device, ``gap_seconds`` apart.

    Any flow column can be overridden with a scalar or a length-``n`` sequence.
    ``ts`` takes either a single start time (flows are then spaced evenly) or a
    sequence of ``n`` timestamps, for tests that need irregular arrivals.

    The default start is on a window boundary, so a table stays inside ONE
    window whenever ``(n - 1) * gap_seconds < 300``. Tests that assert a
    single-window value depend on that; tests about the grid itself pass ``ts``
    explicitly.
    """
    from src.features import windowing as W

    if isinstance(ts, (list, tuple, pd.Series, np.ndarray)):
        stamps = pd.to_datetime(pd.Series(list(ts)))
        if len(stamps) != n:
            raise ValueError(f"ts has {len(stamps)} entries, expected n={n}")
    else:
        t0 = pd.Timestamp(ts)
        stamps = pd.Series(
            [t0 + pd.Timedelta(seconds=gap_seconds * i) for i in range(n)])

    data: dict[str, object] = {
        W.F_DEVICE_ID: (list(device_id) if isinstance(device_id, (list, tuple))
                        else [device_id] * n),
        W.F_TS: stamps,
    }
    for col, default in _FLOW_DEFAULTS.items():
        val = overrides.pop(col, default)
        data[col] = list(val) if isinstance(val, (list, tuple, np.ndarray)) \
            else [val] * n
    if overrides:
        raise KeyError(f"not flow columns: {sorted(overrides)}")
    df = pd.DataFrame(data, columns=W.FLOW_COLS)
    # The validator requires real bool dtype here, so a test passing a list of
    # Python bools gets the same dtype as one taking the default.
    df[W.F_OUTBOUND] = df[W.F_OUTBOUND].astype(bool)
    return df
