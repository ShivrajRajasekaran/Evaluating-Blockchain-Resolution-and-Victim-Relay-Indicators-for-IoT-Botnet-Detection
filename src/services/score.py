"""
services/score.py — offline batch detection with a real abstention channel.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

WHAT THIS IS
    A function over files. It loads (or trains) a detector, reads a local CSV of
    device-window observations, and writes a local CSV of decisions. It opens no
    socket, binds no port, starts no server, resolves no name and forwards no
    packet — see docs/ethics-and-containment.md and the package docstring. The
    absence of an HTTP layer is a feature, not a gap.

THE DECISION SET IS {MALICIOUS, BENIGN, ABSTAIN}
    ABSTAIN is a first-class output, not a low-confidence MALICIOUS. It fires for
    three distinct reasons, each recorded on the row so a human can act on it:

      schema_invalid    — the input could not be trusted as a valid observation
                          (a required feature column is absent). Configurable via
                          service.abstain_on_schema_failure; when off, this
                          raises instead of abstaining.
      missing_features  — this row lacks a value the model needs (a NaN feature:
                          "not measurable", never imputed to 0). Configurable via
                          service.abstain_on_missing_features.
      low_confidence    — the score sits within service.abstain_below_confidence
                          of the decision threshold. A detector that is unsure
                          should say so rather than commit to a coin-flip.

    Crucially there is NO "unknown" class. `unmapped` is a data state; a model
    trained to predict "unknown" learns the signature of whatever happened to be
    unlabelled, which is a fact about the annotation process, not the traffic.
    Abstention keeps that distinction intact.
"""
from __future__ import annotations

import argparse
import sys

import numpy as np
import pandas as pd

from src.config import load_config, provenance_note
from src.evaluate import splits as S
from src.evaluate import thresholds as T
from src.models import registry as R
from src.schema import columns as K
from src.schema.validate import SchemaError, read_observations, trainable

DECISION_MALICIOUS = "MALICIOUS"
DECISION_BENIGN = "BENIGN"
DECISION_ABSTAIN = "ABSTAIN"

REASON_OK = ""
REASON_SCHEMA = "schema_invalid"
REASON_MISSING = "missing_features"
REASON_LOW_CONF = "low_confidence"

# Columns copied through to the output when present, so a decision can be traced
# back to the exact device-window it describes.
_PASSTHROUGH = [K.OBSERVATION_ID, K.DEVICE_ID, K.WINDOW_START, K.SOURCE_DATASET]


class ServiceError(RuntimeError):
    """The scoring request could not be honoured (and abstention was not the
    configured response)."""


class DetectionService:
    """A fitted detector plus its calibrated threshold, applied to CSV batches.

    Construct directly with an already-fitted detector, or via
    :meth:`from_training_frame` to train and calibrate in one call. Either way,
    the operating point is fixed at construction; scoring never re-tunes it.
    """

    def __init__(self, detector, feature_names, threshold: float, *, cfg=None):
        self.detector = detector
        self.feature_names = list(feature_names)
        self.threshold = float(threshold)
        self.cfg = cfg or load_config()

    # -- construction ----------------------------------------------------
    @classmethod
    def from_training_frame(cls, train_df: pd.DataFrame, *,
                            groups: list[str] | None = None,
                            model_name: str = R.RANDOM_FOREST,
                            cfg=None, seed: int = 42) -> "DetectionService":
        """Train on a single-track labelled frame and calibrate to the budget.

        The threshold is pinned on the validation split to
        ``evaluation.target_fpr`` — the same operating point the experiments use,
        so the service's alarms are comparable to the reported numbers.
        """
        cfg = cfg or load_config()
        groups = groups or ["infection", "payload", "resolution", "relay"]
        feats = K.features_for_groups(groups)
        split = S.make_split(
            trainable(train_df), strategy=cfg.evaluation.split_strategy,
            seed=seed, test_size=cfg.evaluation.test_size,
            val_size=cfg.evaluation.val_size,
            min_windows_per_device=cfg.evaluation.min_windows_per_device)
        Xtr, ytr, Xval, yval, _Xte, _yte = split.matrices(feats)
        det = R.by_name(model_name, cfg, seed=seed).fit(Xtr, ytr)
        thr = T.calibrate(yval, R.positive_score(det, Xval),
                          target_fpr=cfg.evaluation.target_fpr)["threshold"]
        return cls(det, feats, thr, cfg=cfg)

    # -- scoring ---------------------------------------------------------
    def score_frame(self, df: pd.DataFrame) -> pd.DataFrame:
        """Return one decision row per input row, order preserved.

        Output columns: the available passthrough ids, then ``decision``,
        ``score``, ``confidence``, ``threshold``, ``reason`` and ``explanation``.
        """
        svc = self.cfg.service
        cap = int(svc.max_rows_per_request)
        if len(df) > cap:
            raise ServiceError(
                f"request has {len(df)} rows, over max_rows_per_request={cap}; "
                "split the batch. (No streaming server exists by design.)")

        df = df.reset_index(drop=True)
        n = len(df)

        # --- schema gate: are the model's feature columns even present? ---
        missing_cols = [c for c in self.feature_names if c not in df.columns]
        out = self._empty_output(df, n)
        if missing_cols:
            if not svc.abstain_on_schema_failure:
                raise ServiceError(
                    f"input is missing feature column(s) {missing_cols} and "
                    "abstain_on_schema_failure is off")
            out["decision"] = DECISION_ABSTAIN
            out["reason"] = REASON_SCHEMA
            out["explanation"] = f"missing feature column(s): {missing_cols}"
            return out

        X = df[self.feature_names].apply(pd.to_numeric, errors="coerce")
        row_has_nan = X.isna().any(axis=1).to_numpy()

        # A NaN feature is "not measurable" and is NEVER imputed (0.0 is the most
        # malicious-looking value most of these features can take). A tree cannot
        # consume a NaN, so it must abstain; the heuristic reads NaN as "no
        # evidence" and can score it. abstain_on_missing_features therefore only
        # changes behaviour for a NaN-tolerant detector — for a tree, a row with
        # a missing feature always abstains.
        tolerates_nan = bool(getattr(self.detector, "tolerates_nan", False))
        abstain_missing = (bool(svc.abstain_on_missing_features)
                           or not tolerates_nan)
        must_abstain_nan = row_has_nan & abstain_missing

        # Only rows we are willing to feed the detector get a score; the rest
        # stay NaN and abstain. (NaN rows reach the detector only when it is
        # NaN-tolerant and the flag is off.)
        scorable = ~must_abstain_nan
        scores = np.full(n, np.nan, dtype=float)
        if scorable.any():
            scores[scorable] = R.positive_score(self.detector, X.loc[scorable])
        confidence = np.abs(scores - self.threshold)   # NaN where unscored

        decision = np.full(n, DECISION_ABSTAIN, dtype=object)
        reason = np.full(n, REASON_OK, dtype=object)
        reason[must_abstain_nan] = REASON_MISSING

        band = float(svc.abstain_below_confidence)
        if scorable.any():
            idx = np.flatnonzero(scorable)
            sc = scores[idx]
            dec = np.where(sc >= self.threshold,
                           DECISION_MALICIOUS, DECISION_BENIGN).astype(object)
            rsn = np.full(idx.size, REASON_OK, dtype=object)
            # Too close to the threshold to commit: abstain rather than coin-flip.
            low = np.abs(sc - self.threshold) < band
            dec[low] = DECISION_ABSTAIN
            rsn[low] = REASON_LOW_CONF
            decision[idx] = dec
            reason[idx] = rsn

        out["decision"] = decision
        out["score"] = np.round(scores, 6)
        out["confidence"] = np.round(confidence, 6)
        out["reason"] = reason
        out["explanation"] = self._explanations(X, scorable, decision)
        return out

    def score_csv(self, in_path: str, out_path: str) -> dict:
        """Read ``in_path``, score, write ``out_path``; return a summary dict.

        The input is validated as a whole observation frame first. If it is not a
        valid frame, the entire batch abstains with reason ``schema_invalid``
        (when ``service.abstain_on_schema_failure`` is set) rather than emitting a
        decision the schema cannot vouch for; otherwise the schema error is
        raised. Row-level missing-feature and low-confidence abstentions are then
        applied by :meth:`score_frame`.
        """
        try:
            df = read_observations(in_path, validate=True)
        except SchemaError as exc:
            if not self.cfg.service.abstain_on_schema_failure:
                raise
            df = read_observations(in_path, validate=False)
            result = self._all_abstain(df, REASON_SCHEMA, f"schema invalid: {exc}")
        else:
            result = self.score_frame(df)
        result.to_csv(out_path, index=False)
        return summarize(result, out_path=out_path)

    # -- helpers ---------------------------------------------------------
    def _empty_output(self, df: pd.DataFrame, n: int) -> pd.DataFrame:
        cols = {c: (df[c] if c in df.columns else pd.Series([pd.NA] * n))
                for c in _PASSTHROUGH}
        out = pd.DataFrame(cols)
        out["decision"] = DECISION_ABSTAIN
        out["score"] = np.nan
        out["confidence"] = np.nan
        out["threshold"] = self.threshold
        out["reason"] = REASON_OK
        out["explanation"] = ""
        return out

    def _all_abstain(self, df: pd.DataFrame, reason: str,
                     explanation: str) -> pd.DataFrame:
        """A decision frame that abstains on every row for one shared reason.

        Used when the batch cannot be scored at all (schema failure) — the ids
        are still carried through so an operator can see which windows were
        skipped and why.
        """
        out = self._empty_output(df, len(df))
        out["reason"] = reason
        out["explanation"] = explanation
        return out

    def _explanations(self, X, scorable, decision) -> list[str]:
        """Human-readable why for MALICIOUS rows; blank otherwise.

        The heuristic can name the rules that fired; a tree cannot cheaply, so it
        reports the score-based decision without a fabricated rationale.
        """
        explain = getattr(self.detector, "explain", None)
        exps = [""] * len(X)
        if not callable(explain):
            return exps
        mal_idx = [i for i in range(len(X))
                   if scorable[i] and decision[i] == DECISION_MALICIOUS]
        if not mal_idx:
            return exps
        reasons = explain(X.iloc[mal_idx])
        for pos, i in enumerate(mal_idx):
            fired = reasons[pos]
            exps[i] = "; ".join(fired) if fired else ""
        return exps


def summarize(result: pd.DataFrame, *, out_path: str | None = None) -> dict:
    """Decision counts and abstention breakdown for logs and reports."""
    counts = result["decision"].value_counts().to_dict()
    abst = result.loc[result["decision"] == DECISION_ABSTAIN, "reason"]
    return {
        "n_rows": int(len(result)),
        "n_malicious": int(counts.get(DECISION_MALICIOUS, 0)),
        "n_benign": int(counts.get(DECISION_BENIGN, 0)),
        "n_abstain": int(counts.get(DECISION_ABSTAIN, 0)),
        "abstain_breakdown": {k: int(v) for k, v in
                              abst.value_counts().to_dict().items()},
        "out_path": out_path,
    }


# ---------------------------------------------------------------------------
# CLI:  python -m src.services.score --train <labelled.csv> \
#             --score <toscore.csv> --out <decisions.csv>
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Offline batch detection with abstention. Reads local CSVs, "
                    "writes a local CSV. No network I/O of any kind.")
    p.add_argument("--train", required=True,
                   help="labelled single-track observations CSV to train on")
    p.add_argument("--score", required=True,
                   help="observations CSV to classify (labels optional/ignored)")
    p.add_argument("--out", required=True, help="decisions CSV to write")
    p.add_argument("--model", default=R.RANDOM_FOREST, choices=R.ALL_NAMES)
    p.add_argument("--groups", nargs="+", default=None,
                   help="feature groups to use (default: all four)")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)

    cfg = load_config()
    train_df = read_observations(args.train)
    svc = DetectionService.from_training_frame(
        train_df, groups=args.groups, model_name=args.model, cfg=cfg,
        seed=args.seed)
    summary = svc.score_csv(args.score, args.out)
    print(f"decisions -> {args.out}")
    print(f"  malicious {summary['n_malicious']}  benign {summary['n_benign']}  "
          f"abstain {summary['n_abstain']} {summary['abstain_breakdown']}")
    print(f"  provenance: {provenance_note(cfg)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
