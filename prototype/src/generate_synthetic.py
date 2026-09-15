"""
generate_synthetic.py — produce a LOCAL, SYNTHETIC labelled feature dataset.

UNIT OF ANALYSIS: one row = one DEVICE observed over one 5-MINUTE WINDOW.
    Not one flow. Features such as distinct_dst_ports, flow_fanout, scan_rate
    and login_burst_count are undefined for a single flow — they only exist as
    per-device aggregates over a window.

WHAT THIS IS:
    A statistical generator that samples plausible *feature values* for two
    classes (benign IoT behaviour vs. blockchain-C2 / victim-relay behaviour) so
    the detection pipeline can be built and evaluated before any real capture
    exists.

WHAT THIS IS NOT:
    It does NOT emulate, contact, or resolve any real network, blockchain name,
    C2 server, or device. No packets are sent. It only writes numbers to a CSV.
    Real public datasets (IoT-23, Bot-IoT, N-BaIoT, CIC-IDS) replace this later.

    It is also NOT VALIDATED. The distributions below are plausible-by-design,
    not fitted to measured traffic. Nothing produced from this file is evidence
    that the detection method works on real IoT traffic — only that the pipeline
    runs and that the feature groups are or are not separable UNDER THESE
    ASSUMPTIONS. See LIMITATIONS.md.

DESIGN GOAL — HONEST DIFFICULTY:
    Earlier versions made the classes trivially separable (perfect F1, useless
    ablation). Real detection is hard because benign and malicious traffic
    OVERLAP. So here:
      * Benign devices ALSO do "suspicious-looking" things: cloud heartbeats
        (periodic beacons), UPnP mappings, occasional server-list-like pulls,
        failed connections. A minority of benign devices are "chatty".
      * Malicious hosts are STEALTHY: each infected host only strongly expresses
        a SUBSET of the four behaviour groups (partial evasion), and some groups
        are dialled down to blend in.
      * A small amount of LABEL NOISE is injected (mislabelled rows), as in any
        real annotated capture.
    Result: no single feature separates the classes; the models must combine
    weak signals.

STANDING RULE — DO NOT "FIX" A NULL RESULT BY WIDENING CLASS SEPARATION:
    If the resolution/relay groups show no independent value, the correct
    response is to ground those features in observable events and build better
    benign controls — NOT to increase the distance between the class
    distributions here. Tuning these constants until the thesis is confirmed is
    fabrication-by-design.
"""
import numpy as np
import pandas as pd

import config as C


def _clip(a, lo, hi):
    return np.clip(a, lo, hi)


def _benign(n, rng):
    """
    Benign IoT devices. Most are quiet, but a realistic minority are 'chatty':
    they run periodic cloud heartbeats (look like beacons), open UPnP mappings
    (smart-TV / console / camera), and occasionally pull config lists.
    """
    chatty = rng.random(n) < 0.35          # 35% of benign devices are chatty
    heartbeat = rng.random(n) < 0.45       # many benign devices beacon to cloud

    beacon_iv = np.where(
        heartbeat,
        _clip(rng.normal(90, 40, n), 5, None),   # legit heartbeat, broad spread
        0.0,
    )
    return pd.DataFrame({
        # resolution
        "ens_query_rate":      _clip(rng.gamma(1.6, 0.7, n) + chatty * rng.gamma(1.5, 0.9, n), 0, None),
        "rpc_endpoint_ratio":  _clip(rng.beta(1.5, 9, n) + chatty * rng.beta(2, 8, n), 0, 1),
        "resolution_entropy":  _clip(rng.normal(2.6, 0.9, n) + chatty * 0.8, 0, 8),
        "serverlist_pull":     ((rng.random(n) < 0.03) | (chatty & (rng.random(n) < 0.20))).astype(int),
        # relay
        "bidir_flow_duration": _clip(rng.gamma(2.4, 18, n) + chatty * rng.gamma(2, 40, n), 0, None),
        "flow_fanout":         _clip(rng.poisson(2.5, n) + chatty * rng.poisson(3.0, n), 0, None),
        "upnp_addportmapping": ((rng.random(n) < 0.10) | (chatty & (rng.random(n) < 0.35))).astype(int),
        "updownlink_ratio":    _clip(rng.normal(0.45, 0.28, n), 0, 5),
        # infection
        "login_burst_count":   _clip(rng.poisson(0.6, n), 0, None),
        "scan_rate":           _clip(rng.gamma(1.3, 1.0, n), 0, None),
        "distinct_dst_ports":  _clip(rng.poisson(3.0, n) + chatty * rng.poisson(4.0, n), 0, None),
        "failed_conn_ratio":   _clip(rng.beta(1.6, 8, n), 0, 1),
        # payload
        "beacon_interval":     beacon_iv,
        "beacon_jitter":       _clip(rng.gamma(2.5, 6.0, n), 0, None),   # benign = high jitter
        "rc4_string_score":    _clip(rng.beta(1.3, 12, n), 0, 1),
        "mean_pkt_size":       _clip(rng.normal(330, 130, n), 40, 1500),
        C.LABEL_COL:           0,
    })


def _malicious(n, rng):
    """
    Blockchain-C2 / victim-relay hosts, STEALTHY. Each host samples which
    behaviour groups it strongly expresses (partial evasion), so the malicious
    class is heterogeneous and overlaps benign traffic.
    """
    # Per-host expression strength for each behaviour group in [0,1].
    # Many hosts express only 1-2 groups strongly.
    e_res = rng.beta(1.6, 1.8, n)
    e_rel = rng.beta(1.6, 1.8, n)
    e_inf = rng.beta(1.4, 2.0, n)
    e_pay = rng.beta(1.8, 1.6, n)

    beacon_on = rng.random(n) < (0.55 + 0.4 * e_pay)     # not all beacon
    beacon_iv = np.where(
        beacon_on,
        _clip(rng.normal(55, 18, n), 5, None),           # tighter than benign heartbeat
        0.0,
    )
    return pd.DataFrame({
        # resolution (elevated only when e_res high)
        "ens_query_rate":      _clip(rng.gamma(2.0, 1.0, n) + e_res * rng.gamma(3.0, 1.4, n), 0, None),
        "rpc_endpoint_ratio":  _clip(rng.beta(2, 6, n) + e_res * rng.beta(4, 3, n), 0, 1),
        "resolution_entropy":  _clip(rng.normal(3.2, 1.0, n) + e_res * 2.2, 0, 8),
        "serverlist_pull":     (rng.random(n) < (0.25 + 0.55 * e_res)).astype(int),
        # relay
        "bidir_flow_duration": _clip(rng.gamma(3.0, 30, n) + e_rel * rng.gamma(5.0, 60, n), 0, None),
        "flow_fanout":         _clip(rng.poisson(3.5, n) + (e_rel * 10).astype(int), 0, None),
        "upnp_addportmapping": (rng.random(n) < (0.20 + 0.55 * e_rel)).astype(int),
        "updownlink_ratio":    _clip(rng.normal(0.6, 0.25, n) + e_rel * 0.4, 0, 5),
        # infection
        "login_burst_count":   _clip(rng.poisson(1.0, n) + (e_inf * 8).astype(int), 0, None),
        "scan_rate":           _clip(rng.gamma(1.6, 1.2, n) + e_inf * rng.gamma(4.0, 2.0, n), 0, None),
        "distinct_dst_ports":  _clip(rng.poisson(4.0, n) + (e_inf * 12).astype(int), 0, None),
        "failed_conn_ratio":   _clip(rng.beta(2, 6, n) + e_inf * rng.beta(5, 3, n), 0, 1),
        # payload
        "beacon_interval":     beacon_iv,
        "beacon_jitter":       _clip(rng.gamma(1.3, 2.0, n) * (1 - 0.5 * e_pay), 0, None),  # low jitter when stealthy-periodic
        "rc4_string_score":    _clip(rng.beta(2, 5, n) + e_pay * rng.beta(6, 2.5, n), 0, 1),
        "mean_pkt_size":       _clip(rng.normal(250, 90, n), 40, 1500),
        C.LABEL_COL:           1,
    })


def generate(seed=C.RANDOM_SEED, n_benign=C.N_BENIGN, n_malicious=C.N_MALICIOUS,
             label_noise=C.LABEL_NOISE):
    rng = np.random.default_rng(seed)
    df = pd.concat([_benign(n_benign, rng), _malicious(n_malicious, rng)],
                   ignore_index=True)

    # Inject label noise: flip a small fraction of labels (annotation error).
    # NOTE: this changes the realised class counts away from n_benign /
    # n_malicious. Always report the counts measured from the resulting frame.
    if label_noise > 0:
        k = int(round(label_noise * len(df)))
        idx = rng.choice(len(df), size=k, replace=False)
        df.loc[idx, C.LABEL_COL] = 1 - df.loc[idx, C.LABEL_COL].values

    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df = df[C.FEATURE_COLS + [C.LABEL_COL]]
    return df


if __name__ == "__main__":
    df = generate()
    df.to_csv(C.DATASET_CSV, index=False)
    n_pos = int(df[C.LABEL_COL].sum())
    n_neg = len(df) - n_pos
    print(f"Wrote {C.DATASET_CSV}")
    print(f"  rows={len(df)}  benign={n_neg}  malicious={n_pos}  "
          f"imbalance={n_neg / max(n_pos,1):.1f}:1")
    print(f"  features={len(C.FEATURE_COLS)}  groups={list(C.FEATURE_GROUPS)}")
