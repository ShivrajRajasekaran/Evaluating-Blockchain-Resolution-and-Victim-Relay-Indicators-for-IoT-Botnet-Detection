"""
features/applayer.py — the four features a connection log cannot express.

WHY THIS MODULE EXISTS
    ``derive.py`` computes eleven features from a flow table. The other five are
    marked ``unavailable`` for every flow-derived source, because a connection
    record says who talked to whom and how much, never what was said. Four of
    those five live one layer up, in Zeek's dns.log, http.log and ssl.log:

        ens_query_rate      contact with a blockchain RPC gateway
        rpc_endpoint_ratio  what share of a device's sessions go to one
        resolution_entropy  randomness of the names a device resolves
        serverlist_pull     an infrastructure list fetched after resolution
        upnp_addportmapping a port mapping requested of the local gateway

    (The fifth, rc4_string_score, needs plaintext payload and stays unavailable.
    It is not approximated here or anywhere.)

THE DESIGN CORRECTION THIS ENCODES
    The intuitive implementation looks for ``.eth`` names in dns.log. That finds
    nothing, and the primary sources explain why: ENS resolution never uses DNS.
    The malware POSTs JSON-RPC over HTTPS to a commercial gateway, so what appears
    on the wire is an ordinary TLS session whose SNI is one of a short, enumerable
    list. Reading ssl.log's ``server_name`` finds it without decrypting anything.
    See ``configs/default.yaml`` -> ``resolution`` for the list and its citation.

WINDOWING WITHOUT UIDS
    Zeek mints fresh uids on every run, so logs regenerated here cannot be joined
    by uid to the conn.log.labeled the dataset ships. They do not need to be:
    every record carries a timestamp and an originator, which is exactly the
    (device, window) key the rest of the pipeline uses. Records are floored onto
    the same 300 s grid as flows and aggregated per device-window.

MISSING IS NOT ZERO
    A log type absent from the bundle yields NaN for the features that depend on
    it, never 0.0. The distinction is load-bearing: 0.0 means "measured, none
    seen" and NaN means "could not be measured". Collapsing them would let a
    capture with no ssl.log look identical to a device that made no gateway
    contact at all.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from src.schema import columns as K

from . import windowing as W

# Zeek field names, per log type. Verified against Zeek 8.0.10 output.
DNS_TS, DNS_ORIG, DNS_QUERY = "ts", "id.orig_h", "query"
HTTP_TS, HTTP_ORIG, HTTP_HOST = "ts", "id.orig_h", "host"
HTTP_METHOD, HTTP_URI = "method", "uri"
SSL_TS, SSL_ORIG, SSL_SNI = "ts", "id.orig_h", "server_name"

# The log types this module reads. conn.log is handled by the flow path.
BUNDLE_LOGS = ("dns.log", "http.log", "ssl.log")

# Features produced here, in schema order.
APPLAYER_FEATURES = ("ens_query_rate", "rpc_endpoint_ratio",
                     "resolution_entropy", "serverlist_pull",
                     "upnp_addportmapping")

_WINDOW_MINUTES = K.WINDOW_SECONDS_VALUE / 60.0


@dataclass
class ResolutionParams:
    """Everything the app-layer derivation needs, passed explicitly.

    Held as plain data rather than read from config in here, so the module has no
    opinion about config shape and can be tested with literals.
    """

    rpc_gateways: tuple[str, ...] = ()
    blockchain_tlds: tuple[str, ...] = (".eth", ".sol", ".crypto", ".bit")
    serverlist_window_seconds: float = 120.0
    serverlist_query_keys: tuple[str, ...] = ("key", "token", "auth", "id")
    ssdp_port: int = 1900
    upnp_soap_markers: tuple[str, ...] = ("AddPortMapping", "WANIPConnection",
                                          "WANPPPConnection")

    @classmethod
    def from_config(cls, node) -> "ResolutionParams":
        gw = node.rpc_gateways
        flat: list[str] = []
        for chain in ("ethereum", "solana"):
            if chain in gw:
                flat.extend(gw[chain])
        return cls(
            rpc_gateways=tuple(h.lower() for h in flat),
            blockchain_tlds=tuple(node.blockchain_tlds),
            serverlist_window_seconds=float(node.serverlist_window_seconds),
            serverlist_query_keys=tuple(node.serverlist_query_keys),
            ssdp_port=int(node.ssdp_port),
            upnp_soap_markers=tuple(node.upnp_soap_markers),
        )


@dataclass
class AppLayer:
    """Per-(device, window) app-layer features, plus what produced them."""

    features: pd.DataFrame                      # index-aligned to `keys`
    available: tuple[str, ...] = ()             # log types actually present
    diagnostics: dict = field(default_factory=dict)


# ===========================================================================
# Reading
# ===========================================================================
def read_bundle(bundle_dir: str | Path, *, max_rows: int | None = None
                ) -> dict[str, pd.DataFrame]:
    """Read the app-layer logs present in a Zeek output directory.

    Absent log types are simply absent from the returned mapping — a capture with
    no TLS produces no ssl.log, and that is information, not an error.
    """
    from src.ingest import zeek           # local import: keeps features/ leaf-ish

    out: dict[str, pd.DataFrame] = {}
    d = Path(bundle_dir)
    for name in BUNDLE_LOGS:
        p = d / name
        if not p.exists() or p.stat().st_size == 0:
            continue
        try:
            frame, _header, _stats = zeek.read_log(p, max_rows=max_rows)
        except zeek.ZeekLogError:
            continue                      # malformed log: treated as absent
        if not frame.empty:
            out[name] = frame
    return out


# ===========================================================================
# Helpers
# ===========================================================================
def _windowed(frame: pd.DataFrame, ts_col: str, orig_col: str) -> pd.DataFrame:
    """Floor timestamps onto the 300 s grid and keep the (device, window) key.

    Uses the same flooring as ``windowing.assign_windows`` so app-layer records
    land in exactly the windows the flow table produced.
    """
    ts = pd.to_datetime(pd.to_numeric(frame[ts_col], errors="coerce"),
                        unit="s", errors="coerce")
    out = frame.copy()
    out["_ts"] = ts
    out[W.F_DEVICE_ID] = frame[orig_col].astype(str)
    out[W.WINDOW_START] = ts.dt.floor(f"{K.WINDOW_SECONDS_VALUE}s")
    return out.dropna(subset=["_ts"])


def _matches_gateway(host: pd.Series, gateways: tuple[str, ...]) -> pd.Series:
    """True where the hostname is, or is a subdomain of, a listed gateway."""
    h = host.astype(str).str.lower().str.rstrip(".")
    if not gateways:
        return pd.Series(False, index=host.index)
    hit = pd.Series(False, index=host.index)
    for g in gateways:
        hit |= (h == g) | h.str.endswith("." + g)
    return hit


def _align(series: pd.Series, keys: pd.MultiIndex, fill: float) -> np.ndarray:
    """Project a grouped result onto the canonical window keys."""
    return series.reindex(keys).fillna(fill).to_numpy(dtype="float64")


def _shannon(names: list[str]) -> float:
    """Character-level Shannon entropy of a window's queried names.

    Character level rather than name level because the signal of interest is
    algorithmically generated names, whose randomness shows in their spelling.
    A window with one short name has little to measure; the value is still
    defined, and the low flow count is already flagged separately.
    """
    text = "".join(n.lower() for n in names if n)
    if not text:
        return float("nan")
    counts = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


# ===========================================================================
# Derivation
# ===========================================================================
def derive_applayer(bundle: dict[str, pd.DataFrame], keys: pd.MultiIndex,
                    *, params: ResolutionParams,
                    windowed_flows: pd.DataFrame | None = None) -> AppLayer:
    """Compute the app-layer features for every window in ``keys``.

    ``keys`` is the (device_id, window_start) index the flow path produced, so
    the result lines up row-for-row with the eleven flow-derived features.

    Every feature is NaN where the log it needs is absent, and a real number
    (including 0.0) where the log is present and simply shows nothing.
    """
    n = len(keys)
    nan = lambda: np.full(n, np.nan, dtype="float64")   # noqa: E731
    feats: dict[str, np.ndarray] = {f: nan() for f in APPLAYER_FEATURES}
    diag: dict = {}

    dns = bundle.get("dns.log")
    http = bundle.get("http.log")
    ssl = bundle.get("ssl.log")

    # THE MISSING-IS-NOT-ZERO RULE, made explicit.
    #
    # A window gets 0.0 for a feature only when the log that feature reads was
    # PRESENT and simply showed nothing in that window. When the log is absent
    # from the capture entirely, the feature stays NaN — "not measurable" — and
    # the detector must abstain rather than read it as "no gateway contact".
    #
    # This is not a formality. CTU-IoT-Malware-Capture-8-1 has no dns.log, no
    # http.log and no ssl.log at all: every one of its flows is unrecognised by
    # Zeek. Filling zeros there would make a capture we cannot assess look
    # identical to one we assessed and found clean, and the resolution rules
    # would silently vote "benign" on evidence that does not exist.
    def fill_if(present: bool) -> float:
        return 0.0 if present else float("nan")

    # -- resolution_entropy : needs dns.log ------------------------------
    if dns is not None and DNS_QUERY in dns.columns:
        d = _windowed(dns, DNS_TS, DNS_ORIG)
        ent = (d.groupby([W.F_DEVICE_ID, W.WINDOW_START])[DNS_QUERY]
                 .apply(lambda s: _shannon(list(s))))
        feats["resolution_entropy"] = ent.reindex(keys).to_numpy(dtype="float64")
        tlds = tuple(t.lower() for t in params.blockchain_tlds)
        q = d[DNS_QUERY].astype(str).str.lower().str.rstrip(".")
        diag["dns_rows"] = int(len(d))
        diag["dns_blockchain_tld_queries"] = int(
            sum(q.str.endswith(t).sum() for t in tlds))

    # -- ens_query_rate / rpc_endpoint_ratio : ssl.log SNI, http Host as
    #    fallback. Counted together because a device may reach a gateway over
    #    either, and the ratio's denominator must span both.
    sessions: list[pd.DataFrame] = []
    if ssl is not None and SSL_SNI in ssl.columns:
        s = _windowed(ssl, SSL_TS, SSL_ORIG)
        s["_host"] = s[SSL_SNI]
        sessions.append(s[[W.F_DEVICE_ID, W.WINDOW_START, "_ts", "_host"]])
    if http is not None and HTTP_HOST in http.columns:
        h = _windowed(http, HTTP_TS, HTTP_ORIG)
        h["_host"] = h[HTTP_HOST]
        sessions.append(h[[W.F_DEVICE_ID, W.WINDOW_START, "_ts", "_host"]])

    if sessions:
        allsess = pd.concat(sessions, ignore_index=True)
        # Zeek writes "-" for an absent SNI; it is not a hostname.
        allsess = allsess[~allsess["_host"].isin(["-", "(empty)", ""])]
        allsess["_gw"] = _matches_gateway(allsess["_host"], params.rpc_gateways)

        grp = allsess.groupby([W.F_DEVICE_ID, W.WINDOW_START])
        hits = grp["_gw"].sum()
        total = grp["_gw"].size()

        # ssl.log or http.log was present, so a window with no gateway contact
        # is a measured zero. Windows with no session at all in this capture stay
        # NaN via fill_if below only when neither log existed.
        seen = fill_if(ssl is not None or http is not None)
        feats["ens_query_rate"] = _align(hits, keys, seen) / _WINDOW_MINUTES
        ratio = (hits / total).replace([np.inf, -np.inf], np.nan)
        feats["rpc_endpoint_ratio"] = _align(ratio, keys, seen)

        diag["session_rows"] = int(len(allsess))
        diag["gateway_matches"] = int(allsess["_gw"].sum())
        diag["distinct_hosts"] = int(allsess["_host"].nunique())

        # -- serverlist_pull : an HTTP GET with a key-like parameter shortly
        #    after a gateway contact, in the same window.
        if http is not None and HTTP_URI in http.columns:
            h = _windowed(http, HTTP_TS, HTTP_ORIG)
            uri = h[HTTP_URI].astype(str).str.lower()
            keyed = pd.Series(False, index=h.index)
            for k in params.serverlist_query_keys:
                keyed |= uri.str.contains(rf"[?&]{k}=", regex=True, na=False)
            h["_keyed"] = keyed
            pulled = _serverlist_flag(h, allsess, params)
            feats["serverlist_pull"] = _align(pulled, keys, fill_if(True))
            diag["keyed_get_requests"] = int(keyed.sum())

    # -- upnp_addportmapping : SOAP control request to the local gateway ---
    if http is not None and HTTP_URI in http.columns:
        h = _windowed(http, HTTP_TS, HTTP_ORIG)
        blob = (h[HTTP_URI].astype(str) + " " + h.get(
            HTTP_HOST, pd.Series("", index=h.index)).astype(str))
        marker = pd.Series(False, index=h.index)
        for m in params.upnp_soap_markers:
            marker |= blob.str.contains(m, case=False, na=False)
        h["_upnp"] = marker
        flag = (h.groupby([W.F_DEVICE_ID, W.WINDOW_START])["_upnp"].max()
                 .astype(float))
        feats["upnp_addportmapping"] = _align(flag, keys, fill_if(True))
        diag["upnp_soap_requests"] = int(marker.sum())

    # SSDP discovery corroborates UPnP and is visible in the flow table, so it is
    # read from there when available rather than requiring another log.
    if windowed_flows is not None and not windowed_flows.empty:
        ssdp = windowed_flows[
            pd.to_numeric(windowed_flows[W.F_DST_PORT], errors="coerce")
            == params.ssdp_port]
        if not ssdp.empty:
            seen = (ssdp.groupby([W.F_DEVICE_ID, W.WINDOW_START]).size() > 0)
            extra = _align(seen.astype(float), keys, 0.0)  # flow table present
            base = feats["upnp_addportmapping"]
            # A window with SSDP but no SOAP is discovery without a mapping
            # request; recorded as 0.0 rather than promoted, and counted here.
            feats["upnp_addportmapping"] = np.where(
                np.isnan(base), np.where(extra > 0, 0.0, np.nan), base)
            diag["ssdp_windows"] = int((extra > 0).sum())

    available = tuple(k for k in BUNDLE_LOGS if k in bundle)
    frame = pd.DataFrame(feats, index=keys)
    return AppLayer(features=frame, available=available, diagnostics=diag)


def _serverlist_flag(http_w: pd.DataFrame, sessions: pd.DataFrame,
                     params: ResolutionParams) -> pd.Series:
    """1.0 for windows holding a keyed GET soon after a gateway contact.

    Both events must belong to the same device and the same window, and the GET
    must follow the contact within ``serverlist_window_seconds``. Ordering is
    what makes this a *pull after resolution* rather than two unrelated events
    that happen to share a window.
    """
    gw = sessions[sessions["_gw"]]
    if gw.empty:
        return pd.Series(dtype="float64")

    first_gw = gw.groupby([W.F_DEVICE_ID, W.WINDOW_START])["_ts"].min()
    keyed = http_w[http_w["_keyed"]]
    if keyed.empty:
        return pd.Series(dtype="float64")

    last_get = keyed.groupby([W.F_DEVICE_ID, W.WINDOW_START])["_ts"].max()
    joined = pd.concat({"gw": first_gw, "get": last_get}, axis=1).dropna()
    if joined.empty:
        return pd.Series(dtype="float64")

    delta = (joined["get"] - joined["gw"]).dt.total_seconds()
    return ((delta >= 0) & (delta <= params.serverlist_window_seconds)
            ).astype(float)
