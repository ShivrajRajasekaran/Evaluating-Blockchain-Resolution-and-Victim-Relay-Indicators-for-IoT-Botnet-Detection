"""
evaluate/cross_track.py — the one permitted crossing: real-benign false alarms.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

WHY THIS IS THE ONLY CROSSING ALLOWED
-------------------------------------
Track A (IoT-23, real) and Track B (mock) are trained and evaluated separately,
always. Pooling them lets a model separate the classes by capture provenance
(TTL, MTU, clock resolution) instead of behaviour, which manufactures a
meaningless high score. Every other part of this project refuses to mix them.

The research question, however, has a second clause: "...while maintaining a low
false-positive rate on REAL benign IoT traffic." Mock benign cannot answer that —
only real benign can. So exactly one crossing is sanctioned, and it is
deliberately one-directional and benign-only:

    take the Track-B-trained detector, and score it on IoT-23 BENIGN windows.

No IoT-23 malicious row is ever scored here. Scoring real malicious against a
mock-trained model would re-open the disjoint-label shortcut (the two malicious
sets come from different pipelines), so this function REFUSES a frame that
contains any non-benign real row. What it measures is only this: how often does a
detector tuned on mock traffic cry wolf on genuine benign traffic it has never
seen?

WHAT THE NUMBER MEANS, AND WHAT IT DOES NOT
-------------------------------------------
* Only features computable on BOTH tracks are used. IoT-23 ships conn.log.labeled
  only, so the features that DEFINE the thesis (ens_query_rate, resolution
  entropy, server-list pull, UPnP, RC4 score) do not exist there. They are
  excluded from the model, not imputed. Proxy features (rpc_endpoint_ratio,
  login_burst_count) are excluded by default too, because their Track-A meaning
  differs from their Track-B meaning and would import a definitional mismatch
  into the score.
* A real window missing any used feature is ABSTAINED on, never guessed. The
  abstention count and coverage are first-class outputs: an FPR measured over 40%
  of windows is a different claim from one over 99%, and hiding the denominator
  would be the lie.
* The resulting FPR is dominated by cross-pipeline DISTRIBUTION SHIFT (mock
  generator vs Zeek), not by any malicious signal. It is an honest upper-ish
  bound on real-world false alarms for the transferable features — reported as
  such, never as a validation of the thesis.
"""
from __future__ import annotations

import argparse
import json
import sys

import numpy as np
import pandas as pd

from src.config import load_config, provenance_note
from src.evaluate import metrics as M
from src.evaluate import splits as S
from src.evaluate import thresholds as T
from src.models import registry as R
from src.schema import columns as K
from src.schema.validate import read_observations, trainable


class CrossTrackError(ValueError):
    """The benign-only, one-directional crossing was given the wrong inputs."""


def cross_track_features(*, include_proxies: bool = False) -> list[str]:
    """Features usable on BOTH tracks, in canonical order.

    Drops every IoT-23-unavailable feature (they are NaN there by definition).
    Proxy features are dropped as well unless explicitly opted in, because a
    proxy is a different measurement on each track.
    """
    unavailable = set(K.unavailable_features(K.SOURCE_IOT23))
    usable = [c for c in K.FEATURE_COLS if c not in unavailable]
    if not include_proxies:
        proxies = set(K.proxy_features(K.SOURCE_IOT23))
        usable = [c for c in usable if c not in proxies]
    return usable


def _require_single_source(df: pd.DataFrame, source: str, what: str) -> None:
    if df.empty:
        raise CrossTrackError(f"{what} is empty")
    seen = set(df[K.SOURCE_DATASET].astype(str).unique())
    if seen != {source}:
        raise CrossTrackError(
            f"{what} must be exactly source {source!r}; saw {sorted(seen)}. "
            "This crossing never pools tracks.")


def _require_benign_only(df: pd.DataFrame) -> None:
    """Refuse any non-benign real row: this crossing measures false alarms only."""
    classes = set(df[K.RESEARCH_CLASS].astype(str).unique())
    if classes != {K.CLS_BENIGN_REAL}:
        offending = sorted(classes - {K.CLS_BENIGN_REAL})
        raise CrossTrackError(
            "IoT-23 frame for the cross-track FPR check must be benign only "
            f"(research_class == {K.CLS_BENIGN_REAL!r}); found {offending}. "
            "Scoring real malicious against a mock-trained model would re-open "
            "the capture-provenance shortcut and is refused by design.")


def cross_track_fpr(track_b_df: pd.DataFrame, iot23_benign_df: pd.DataFrame, *,
                    cfg=None, seed: int = 42,
                    model_name: str = R.RANDOM_FOREST,
                    include_proxies: bool = False) -> dict:
    """Score a Track-B-trained detector on IoT-23 benign; report real-world FPR.

    The detector is trained and calibrated entirely on Track B (mock): fit on the
    grouped train split, threshold pinned to the FPR budget on the mock
    validation split. That fixed operating point is then applied, unchanged, to
    real benign windows. Rows missing any used feature abstain. Returns the FPR
    on real benign traffic, the abstention accounting, and the mock-vs-real gap.
    """
    cfg = cfg or load_config()
    _require_single_source(track_b_df, K.SOURCE_MOCK_LOCAL, "track_b_df")
    _require_single_source(iot23_benign_df, K.SOURCE_IOT23, "iot23_benign_df")
    _require_benign_only(iot23_benign_df)

    feats = cross_track_features(include_proxies=include_proxies)
    target = cfg.evaluation.target_fpr

    # --- Train + calibrate on Track B only -------------------------------
    split = S.make_split(
        trainable(track_b_df), strategy=cfg.evaluation.split_strategy, seed=seed,
        test_size=cfg.evaluation.test_size, val_size=cfg.evaluation.val_size,
        min_windows_per_device=cfg.evaluation.min_windows_per_device)
    Xtr, ytr, Xval, yval, _Xte, _yte = split.matrices(feats)
    det = R.by_name(model_name, cfg, seed=seed).fit(Xtr, ytr)
    cal = T.calibrate(yval, R.positive_score(det, Xval), target_fpr=target)
    thr = cal["threshold"]

    # --- Score real benign, abstaining on any missing used feature -------
    real = iot23_benign_df.reset_index(drop=True)
    Xreal = real[feats].apply(pd.to_numeric, errors="coerce")
    nan_row = Xreal.isna().any(axis=1).to_numpy()
    n_total = len(real)
    n_abstain = int(nan_row.sum())
    n_scored = n_total - n_abstain

    per_feature_nan = {c: int(Xreal[c].isna().sum()) for c in feats
                       if int(Xreal[c].isna().sum()) > 0}

    if n_scored == 0:
        fpr_real = None
        n_fp = 0
    else:
        s_real = R.positive_score(det, Xreal.loc[~nan_row])
        pred = (np.asarray(s_real, float) >= thr).astype(int)
        n_fp = int(pred.sum())              # every scored row is truly benign
        fpr_real = round(n_fp / n_scored, 6)

    return {
        "crossing": "Track-B-trained detector -> IoT-23 benign (false alarms only)",
        "model": model_name,
        "seed": seed,
        "fpr_budget": target,
        "feature_set": feats,
        "n_features": len(feats),
        "include_proxies": include_proxies,
        "excluded_unavailable": K.unavailable_features(K.SOURCE_IOT23),
        "excluded_proxies": ([] if include_proxies
                             else K.proxy_features(K.SOURCE_IOT23)),
        "threshold": thr,
        "mock_val_fpr_calibrated": cal["val_fpr_achieved"],
        "n_real_total": n_total,
        "n_scored": n_scored,
        "n_abstained": n_abstain,
        "coverage": round(n_scored / n_total, 6) if n_total else 0.0,
        "abstain_reason_feature_nan_counts": per_feature_nan,
        "n_false_positive": n_fp,
        "fpr_real_benign": fpr_real,
        "reading": _reading(fpr_real, target, n_scored, n_total, cal),
        "provenance": provenance_note(cfg),
    }


def _reading(fpr_real, target, n_scored, n_total, cal) -> str:
    if n_scored == 0:
        return ("Every real benign window abstained (a used feature was missing "
                "on all of them); no FPR could be measured. Check the IoT-23 "
                "windowing / min-flow settings.")
    cov = n_scored / n_total if n_total else 0.0
    gap = "at or below" if (fpr_real is not None and fpr_real <= target) else "above"
    return (
        f"On {n_scored}/{n_total} real benign windows ({cov:.0%} coverage), the "
        f"mock-calibrated detector (mock-val FPR {cal['val_fpr_achieved']:.3f}) "
        f"fires on {fpr_real:.3f} of them — {gap} the {target:.0%} budget. This "
        "false-alarm rate reflects mock-vs-real distribution shift on the "
        "transferable features, not detection of any thesis behaviour (absent "
        "from IoT-23). Report it as the real-world FPR caveat, not a result.")


# ---------------------------------------------------------------------------
# CLI:  python -m src.evaluate.cross_track --track-b <csv> --iot23-benign <csv>
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Cross-track FPR: score a Track-B-trained detector on "
                    "IoT-23 benign windows (the only permitted track crossing).")
    p.add_argument("--track-b", required=True,
                   help="Track B (mock) observations CSV to train on")
    p.add_argument("--iot23-benign", required=True,
                   help="IoT-23 (Track A) BENIGN observations CSV to score")
    p.add_argument("--model", default=R.RANDOM_FOREST, choices=R.ALL_NAMES)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--include-proxies", action="store_true",
                   help="also use proxy features (rpc_endpoint_ratio, "
                        "login_burst_count); off by default")
    p.add_argument("--out", default=None, help="write the JSON report here")
    args = p.parse_args(argv)

    track_b = read_observations(args.track_b)
    iot23 = read_observations(args.iot23_benign)
    report = cross_track_fpr(track_b, iot23, seed=args.seed,
                             model_name=args.model,
                             include_proxies=args.include_proxies)

    text = json.dumps(report, indent=2, default=str)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"cross-track FPR report -> {args.out}")
    print(report["reading"])
    print(f"  FPR(real benign) = {report['fpr_real_benign']}  "
          f"coverage = {report['coverage']}  "
          f"abstained = {report['n_abstained']}/{report['n_real_total']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
