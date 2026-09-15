"""
ingest/mock_generator.py — Track B: locally generated mock observations.

    python -m src.ingest.mock_generator                    # default config
    python -m src.ingest.mock_generator --seed 7
    python -m src.ingest.mock_generator --class-model parity

WHAT THIS IS
    A statistical generator that samples plausible FEATURE VALUES for benign IoT
    behaviour and for three mock malicious behaviour classes, so the detection
    pipeline can be built and evaluated before any real capture of
    blockchain-anchored C2 exists.

WHAT THIS IS NOT
    It does not emulate, contact, or resolve any real network, blockchain name,
    RPC endpoint, C2 server or device. It sends no packets, opens no socket, and
    forwards nothing. It writes numbers to a CSV. It is also NOT VALIDATED: the
    distributions are plausible-by-design, not fitted to measured traffic.
    Nothing produced here is evidence that detection works on real IoT traffic.

STANDING RULE — DO NOT "FIX" A NULL RESULT BY WIDENING CLASS SEPARATION
    If the resolution and relay groups show no independent value, the correct
    response is to ground those features in observable events and build better
    benign controls — NOT to move the class distributions further apart. Tuning
    these constants until the thesis is confirmed is fabrication-by-design.
    tests/test_mock_generator.py pins every constant below for that reason.

WHAT CHANGED FROM THE PROTOTYPE, AND WHY IT IS NOT A DISTRIBUTION CHANGE
    The prototype drew the per-host "expression strengths" (e_res, e_rel, ...)
    independently for every ROW. A row was therefore its own device, and no
    device identity existed at all — which is exactly why grouped and temporal
    splits were impossible.

    Here the strengths are drawn once per DEVICE and shared by that device's
    windows. The per-window marginal distribution of every feature is unchanged
    — same families, same constants. What is added is WITHIN-DEVICE CORRELATION,
    which is a property real traffic has and the prototype lacked.

    Two consequences, both honest and both in the conservative direction:
      * A grouped split is now genuinely harder than a random split, because the
        model can no longer see the same device in training and test.
      * Bootstrap intervals must resample by device, not by row. Row-level
        resampling would treat correlated windows as independent evidence and
        report intervals that are too narrow — which for this project would make
        a null result look more decisive than the data supports.

    Because RNG consumption order differs from the prototype's, the numbers will
    not match it digit for digit. That is expected. What must be compared is the
    CONCLUSION, not the digits.

TWO CLASS MODELS
    scenario (default)  Mirrors how a real isolated testbed would be run: three
                        capture scenarios, one with a mock resolver active, one
                        with a mock relay active, one with both. A device in the
                        resolver-only scenario genuinely is not relaying, so its
                        relay features are drawn from the BENIGN distribution —
                        not zeroed, which would be a giveaway no real capture
                        would contain. This makes the malicious class HARDER to
                        separate on the novel groups, not easier.

    parity              All malicious devices express all four groups, as in the
                        prototype. Retained as a regression check that the
                        enterprise pipeline reproduces the prototype's finding
                        rather than quietly changing the science.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass

import numpy as np
import pandas as pd

from src import config as cfg_mod
from src.config import load_config
from src.schema import build_observations, columns as K, write_observations

# Mapping from a Track B malicious class to which novel groups it expresses.
# infection and payload are expressed by every malicious class: a device running
# blockchain-anchored C2 is still malware, and still spreads and beacons.
_EXPRESSES = {
    K.CLS_BLOCKCHAIN_RESOLUTION_MOCK: {"resolution": True, "relay": False},
    K.CLS_VICTIM_RELAY_MOCK: {"resolution": False, "relay": True},
    K.CLS_COMBINED_MOCK: {"resolution": True, "relay": True},
}

# Scenario id per class — the identifier a real testbed capture would carry.
_SCENARIO_OF_CLASS = {
    K.CLS_BENIGN_MOCK: "mock-benign-controls",
    K.CLS_BLOCKCHAIN_RESOLUTION_MOCK: "mock-resolver-only",
    K.CLS_VICTIM_RELAY_MOCK: "mock-relay-only",
    K.CLS_COMBINED_MOCK: "mock-resolver-and-relay",
}


def _clip(a, lo, hi):
    return np.clip(a, lo, hi)


# ===========================================================================
# Per-group samplers
# ===========================================================================
# Each returns a dict of arrays of length n. Constants are transcribed verbatim
# from prototype/src/generate_synthetic.py; see the standing rule above.

def _resolution_benign(n, rng, chatty):
    """Benign resolution behaviour. Chatty devices legitimately do periodic
    name lookups and occasionally pull a config/server list — without that
    overlap the resolution group would be a giveaway and every metric built on
    it would be meaningless."""
    return {
        "ens_query_rate": _clip(
            rng.gamma(1.6, 0.7, n) + chatty * rng.gamma(1.5, 0.9, n), 0, None),
        "rpc_endpoint_ratio": _clip(
            rng.beta(1.5, 9, n) + chatty * rng.beta(2, 8, n), 0, 1),
        "resolution_entropy": _clip(
            rng.normal(2.6, 0.9, n) + chatty * 0.8, 0, 8),
        "serverlist_pull": (
            (rng.random(n) < 0.03) | (chatty & (rng.random(n) < 0.20))
        ).astype(float),
    }


def _resolution_malicious(n, rng, e_res):
    return {
        "ens_query_rate": _clip(
            rng.gamma(2.0, 1.0, n) + e_res * rng.gamma(3.0, 1.4, n), 0, None),
        "rpc_endpoint_ratio": _clip(
            rng.beta(2, 6, n) + e_res * rng.beta(4, 3, n), 0, 1),
        "resolution_entropy": _clip(
            rng.normal(3.2, 1.0, n) + e_res * 2.2, 0, 8),
        "serverlist_pull": (
            rng.random(n) < (0.25 + 0.55 * e_res)).astype(float),
    }


def _relay_benign(n, rng, chatty):
    """Benign relay-shaped behaviour: smart TVs, consoles and cameras open UPnP
    mappings and hold long-lived bidirectional connections as a matter of normal
    operation."""
    return {
        "bidir_flow_duration": _clip(
            rng.gamma(2.4, 18, n) + chatty * rng.gamma(2, 40, n), 0, None),
        "flow_fanout": _clip(
            rng.poisson(2.5, n) + chatty * rng.poisson(3.0, n), 0, None
        ).astype(float),
        "upnp_addportmapping": (
            (rng.random(n) < 0.10) | (chatty & (rng.random(n) < 0.35))
        ).astype(float),
        "updownlink_ratio": _clip(rng.normal(0.45, 0.28, n), 0, 5),
    }


def _relay_malicious(n, rng, e_rel):
    return {
        "bidir_flow_duration": _clip(
            rng.gamma(3.0, 30, n) + e_rel * rng.gamma(5.0, 60, n), 0, None),
        "flow_fanout": _clip(
            rng.poisson(3.5, n) + (e_rel * 10).astype(int), 0, None
        ).astype(float),
        "upnp_addportmapping": (
            rng.random(n) < (0.20 + 0.55 * e_rel)).astype(float),
        "updownlink_ratio": _clip(
            rng.normal(0.6, 0.25, n) + e_rel * 0.4, 0, 5),
    }


def _infection_benign(n, rng, chatty):
    return {
        "login_burst_count": _clip(rng.poisson(0.6, n), 0, None).astype(float),
        "scan_rate": _clip(rng.gamma(1.3, 1.0, n), 0, None),
        "distinct_dst_ports": _clip(
            rng.poisson(3.0, n) + chatty * rng.poisson(4.0, n), 0, None
        ).astype(float),
        "failed_conn_ratio": _clip(rng.beta(1.6, 8, n), 0, 1),
    }


def _infection_malicious(n, rng, e_inf):
    return {
        "login_burst_count": _clip(
            rng.poisson(1.0, n) + (e_inf * 8).astype(int), 0, None
        ).astype(float),
        "scan_rate": _clip(
            rng.gamma(1.6, 1.2, n) + e_inf * rng.gamma(4.0, 2.0, n), 0, None),
        "distinct_dst_ports": _clip(
            rng.poisson(4.0, n) + (e_inf * 12).astype(int), 0, None
        ).astype(float),
        "failed_conn_ratio": _clip(
            rng.beta(2, 6, n) + e_inf * rng.beta(5, 3, n), 0, 1),
    }


def _payload_benign(n, rng, heartbeat):
    """Benign payload shape. Many IoT devices beacon to a cloud endpoint on a
    schedule, so periodicity alone is not evidence of C2 — the benign heartbeat
    is simply less regular (higher jitter, broader interval spread)."""
    beacon_iv = np.where(
        heartbeat, _clip(rng.normal(90, 40, n), 5, None), 0.0)
    return {
        "beacon_interval": beacon_iv,
        "beacon_jitter": _clip(rng.gamma(2.5, 6.0, n), 0, None),
        "rc4_string_score": _clip(rng.beta(1.3, 12, n), 0, 1),
        "mean_pkt_size": _clip(rng.normal(330, 130, n), 40, 1500),
    }


def _payload_malicious(n, rng, e_pay):
    beacon_on = rng.random(n) < (0.55 + 0.4 * e_pay)
    beacon_iv = np.where(
        beacon_on, _clip(rng.normal(55, 18, n), 5, None), 0.0)
    return {
        "beacon_interval": beacon_iv,
        "beacon_jitter": _clip(
            rng.gamma(1.3, 2.0, n) * (1 - 0.5 * e_pay), 0, None),
        "rc4_string_score": _clip(
            rng.beta(2, 5, n) + e_pay * rng.beta(6, 2.5, n), 0, 1),
        "mean_pkt_size": _clip(rng.normal(250, 90, n), 40, 1500),
    }


# ===========================================================================
# Device model
# ===========================================================================
@dataclass
class DeviceTable:
    """One row per simulated device. Latents are fixed for the device's whole
    observation period — that is what gives a device a persistent character and
    makes its windows correlated."""

    device_id: np.ndarray
    true_class: np.ndarray
    chatty: np.ndarray        # benign-style latent, used for benign-drawn groups
    heartbeat: np.ndarray
    e_res: np.ndarray
    e_rel: np.ndarray
    e_inf: np.ndarray
    e_pay: np.ndarray

    def __len__(self) -> int:
        return len(self.device_id)


def _assign_malicious_classes(n, rng, class_mix, class_model) -> np.ndarray:
    """Assign a Track B malicious class to each malicious device.

    Deterministic counts rather than per-device multinomial draws: with 120
    devices a multinomial draw wobbles the class balance by several devices
    between seeds, and that wobble would show up in results as if it were a
    finding.
    """
    if class_model == "parity":
        return np.array([K.CLS_COMBINED_MOCK] * n, dtype=object)

    classes = list(_EXPRESSES)
    weights = np.array([float(class_mix[c]) for c in classes])
    if not np.isclose(weights.sum(), 1.0):
        raise ValueError(
            f"mock.class_mix must sum to 1.0, got {weights.sum():.4f}")

    counts = np.floor(weights * n).astype(int)
    counts[-1] += n - counts.sum()          # give the remainder to the last
    out = np.concatenate([np.full(k, c, dtype=object)
                          for k, c in zip(counts, classes)])
    rng.shuffle(out)
    return out


def _build_device_table(rng, n_benign, n_malicious, class_mix,
                        class_model, chatty_frac, heartbeat_frac) -> DeviceTable:
    n = n_benign + n_malicious
    true_class = np.concatenate([
        np.full(n_benign, K.CLS_BENIGN_MOCK, dtype=object),
        _assign_malicious_classes(n_malicious, rng, class_mix, class_model),
    ])
    device_id = np.array(
        [f"mockdev-{i:05d}" for i in range(n)], dtype=object)

    return DeviceTable(
        device_id=device_id,
        true_class=true_class,
        chatty=rng.random(n) < chatty_frac,
        heartbeat=rng.random(n) < heartbeat_frac,
        # Same beta families and constants as the prototype, drawn per device.
        e_res=rng.beta(1.6, 1.8, n),
        e_rel=rng.beta(1.6, 1.8, n),
        e_inf=rng.beta(1.4, 2.0, n),
        e_pay=rng.beta(1.8, 1.6, n),
    )


def _window_starts(n_devices, windows_per_device, start_time,
                   stride_seconds, stagger_seconds) -> list[pd.Timestamp]:
    """Window start timestamps, device-major order.

    Devices are staggered by a few minutes but each is then sampled once per
    `stride_seconds` over many hours. That decoupling is deliberate: if every
    device were observed in one short contiguous burst, a temporal split would
    cut between devices and be indistinguishable from a grouped split. Here the
    two protocols genuinely differ — grouped tests generalisation to unseen
    devices, temporal tests generalisation to a later period on known devices.
    """
    t0 = pd.Timestamp(start_time)
    out: list[pd.Timestamp] = []
    for d in range(n_devices):
        base = t0 + pd.Timedelta(seconds=(d % 12) * stagger_seconds)
        for w in range(windows_per_device):
            out.append(base + pd.Timedelta(seconds=w * stride_seconds))
    return out


# ===========================================================================
# Generation
# ===========================================================================
def generate(seed: int | None = None, cfg=None,
             class_model: str | None = None) -> pd.DataFrame:
    """Generate a schema-valid Track B observation frame."""
    cfg = cfg or load_config()
    m = cfg.mock
    seed = cfg.seeds.primary if seed is None else seed
    class_model = class_model or m.get("class_model", "scenario")
    if class_model not in ("scenario", "parity"):
        raise ValueError(
            f"class_model must be 'scenario' or 'parity', got {class_model!r}")

    rng = np.random.default_rng(seed)
    W = int(m.windows_per_device)

    devices = _build_device_table(
        rng,
        n_benign=int(m.n_devices_benign),
        n_malicious=int(m.n_devices_malicious),
        class_mix=m.class_mix,
        class_model=class_model,
        chatty_frac=float(m.benign_chatty_fraction),
        heartbeat_frac=float(m.benign_heartbeat_fraction),
    )

    # ---- expand device latents to one entry per window ---------------------
    rep = lambda a: np.repeat(a, W)                       # noqa: E731
    n = len(devices) * W
    true_class = rep(devices.true_class)
    chatty = rep(devices.chatty)
    heartbeat = rep(devices.heartbeat)
    e_res, e_rel = rep(devices.e_res), rep(devices.e_rel)
    e_inf, e_pay = rep(devices.e_inf), rep(devices.e_pay)

    is_malicious = np.array(
        [c in K.MALICIOUS_CLASSES for c in true_class], dtype=bool)
    express_res = np.array(
        [_EXPRESSES[c]["resolution"] if c in _EXPRESSES else False
         for c in true_class], dtype=bool)
    express_rel = np.array(
        [_EXPRESSES[c]["relay"] if c in _EXPRESSES else False
         for c in true_class], dtype=bool)

    # ---- sample each group, then select per window -------------------------
    # Both variants are drawn for every window and one is chosen. A device that
    # is not relaying gets benign-range relay values rather than zeros: zeros
    # would be a separator that no real capture could contain, and the model
    # would learn it instead of the behaviour.
    def pick(mask, mal, ben):
        return {k: np.where(mask, mal[k], ben[k]) for k in mal}

    feats: dict[str, np.ndarray] = {}
    feats.update(pick(express_res,
                      _resolution_malicious(n, rng, e_res),
                      _resolution_benign(n, rng, chatty)))
    feats.update(pick(express_rel,
                      _relay_malicious(n, rng, e_rel),
                      _relay_benign(n, rng, chatty)))
    feats.update(pick(is_malicious,
                      _infection_malicious(n, rng, e_inf),
                      _infection_benign(n, rng, chatty)))
    feats.update(pick(is_malicious,
                      _payload_malicious(n, rng, e_pay),
                      _payload_benign(n, rng, heartbeat)))

    features = pd.DataFrame(feats)[K.FEATURE_COLS]

    # ---- annotation error --------------------------------------------------
    # Modelled at the WINDOW level, because a human mislabels an observation,
    # not a device. The recorded research_class is changed; original_label keeps
    # the true generating class, so every injected error stays auditable.
    recorded = true_class.copy()
    noise = float(m.label_noise)
    flipped = np.zeros(n, dtype=bool)
    if noise > 0:
        k = int(round(noise * n))
        idx = rng.choice(n, size=k, replace=False)
        # Which malicious class a mislabelled benign window is recorded as. In
        # parity mode there is only one, so the choice is forced.
        malicious_pool = (list(_EXPRESSES) if class_model == "scenario"
                          else [K.CLS_COMBINED_MOCK])
        for i in idx:
            if recorded[i] == K.CLS_BENIGN_MOCK:
                recorded[i] = malicious_pool[rng.integers(len(malicious_pool))]
            else:
                recorded[i] = K.CLS_BENIGN_MOCK
        flipped[idx] = True

    # scenario_id follows the TRUE class: which capture a window came from is a
    # fact about the testbed, not about what the annotator wrote down. Keeping it
    # unflipped is what makes every injected error auditable after the fact.
    scenario = np.array([_SCENARIO_OF_CLASS[c] for c in true_class], dtype=object)
    starts = _window_starts(
        len(devices), W, m.start_time,
        int(m.get("window_stride_seconds", 3600)),
        int(m.get("device_stagger_seconds", 300)),
    )

    df = build_observations(
        features,
        source_dataset=K.SOURCE_MOCK_LOCAL,
        device_id=rep(devices.device_id),
        window_start=starts,
        research_class=recorded,
        original_label=true_class,          # the TRUE class, before annotation error
        scenario_id=scenario,
        extra_flags=[
            {K.FLAG_LABEL_NOISE_INJECTED: None} if flipped[i] else {}
            for i in range(n)
        ],
    )
    # Shuffle so no downstream code can depend on device-major ordering.
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


# ===========================================================================
# CLI
# ===========================================================================
def _summarise(df: pd.DataFrame) -> str:
    n_pos = int((df[K.LABEL_BINARY] == 1).sum())
    n_neg = int((df[K.LABEL_BINARY] == 0).sum())
    lines = [
        f"  rows={len(df)}  devices={df[K.DEVICE_ID].nunique()}  "
        f"windows/device={len(df) / df[K.DEVICE_ID].nunique():.1f}",
        f"  benign={n_neg}  malicious={n_pos}  "
        f"imbalance={n_neg / max(n_pos, 1):.1f}:1",
        f"  window span: {df[K.WINDOW_START].min()} .. "
        f"{df[K.WINDOW_START].max()}",
        "  recorded research_class:",
    ]
    for cls, cnt in df[K.RESEARCH_CLASS].value_counts().items():
        lines.append(f"    {cls:32s} {cnt:6d}")
    n_flipped = int(df[K.QUALITY_FLAGS].str.contains(
        K.FLAG_LABEL_NOISE_INJECTED, regex=False).sum())
    lines.append(f"  annotation errors injected: {n_flipped} "
                 f"({n_flipped / len(df):.2%})")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m src.ingest.mock_generator",
        description="Generate Track B mock observations (local, no network).",
    )
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--config", default=None, help="path to a YAML config")
    p.add_argument("--class-model", choices=("scenario", "parity"), default=None,
                   help="'scenario' (default) or 'parity' for prototype "
                        "comparability")
    p.add_argument("--out", default=None, help="output CSV path")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    cfg_mod.ensure_dirs()

    df = generate(seed=args.seed, cfg=cfg, class_model=args.class_model)

    out = args.out
    if out is None:
        out = cfg_mod.TRACK_B_MOCK_CSV
        if (args.class_model or cfg.mock.get("class_model", "scenario")) == "parity":
            out = cfg_mod.PROCESSED_DIR / "track_b_mock_observations_parity.csv"
    write_observations(df, out)

    print(f"Wrote {out}")
    print(_summarise(df))
    print()
    print(cfg_mod.provenance_note())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
