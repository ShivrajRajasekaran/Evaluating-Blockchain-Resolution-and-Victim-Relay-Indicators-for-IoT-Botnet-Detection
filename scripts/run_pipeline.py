"""
scripts/run_pipeline.py — one command from Track B data to the results/ artefacts.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

WHAT IT DOES
    Loads the Track B mock observations, runs the headline build-up experiment
    and its supporting analyses (model comparison, multi-seed robustness,
    permutation importance, lab-only sensitivity, drop-one), and writes every
    result three ways into results/:
        results/tables/*.csv     provenance-headed CSVs
        results/figures/*.png    captioned PNGs
        results/reports/*.json   the raw result dicts, for exact reproduction

    The one permitted crossing — a Track-B detector scored against IoT-23 benign
    for a real-benign false-alarm rate — runs ONLY when --iot23-benign is given.
    None ships with the repo, so by default it is skipped with a clear note.

CONTAINMENT
    Reads local CSVs, writes local files. No network I/O. See
    docs/ethics-and-containment.md.

USAGE
    python scripts/run_pipeline.py                     # full run, seed 42
    python scripts/run_pipeline.py --fast              # small forests, quick demo
    python scripts/run_pipeline.py --model XGBoost
    python scripts/run_pipeline.py --iot23-benign data/processed/track_a_iot23_observations.csv
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Make `import src...` work whether run as `python scripts/run_pipeline.py` or
# `python -m scripts.run_pipeline`, from any working directory.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src import config as C                                    # noqa: E402
from src.evaluate import cross_track as CT                     # noqa: E402
from src.evaluate import experiment as E                       # noqa: E402
from src.evaluate import explain as X                          # noqa: E402
from src.models import registry as R                           # noqa: E402
from src.reports import figures as FG                          # noqa: E402
from src.reports import tables as TB                           # noqa: E402
from src.schema.validate import read_observations             # noqa: E402


def _fast_config(cfg: C.ConfigNode) -> C.ConfigNode:
    """A cheaper config for a demo run: small forests, few bootstraps, 2 seeds.

    The science lives in the full run; --fast is for showing the pipeline end to
    end quickly. The provenance and null-result logic are identical either way.
    """
    d = cfg.as_dict()
    d["evaluation"]["n_bootstrap"] = 150
    d["models"]["random_forest"]["n_estimators"] = 60
    d["models"]["xgboost"]["n_estimators"] = 80
    d["seeds"]["split"] = d["seeds"]["split"][:2]
    return C.ConfigNode(d)


def _json_default(o):
    """Serialise numpy / pandas scalars that json can't handle natively."""
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, (np.bool_,)):
        return bool(o)
    if o is pd.NA or (isinstance(o, float) and pd.isna(o)):
        return None
    raise TypeError(f"not JSON-serialisable: {type(o)}")


def _write_json(obj: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=_json_default)
    return path


def _log(msg: str) -> None:
    print(msg, flush=True)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Run the Track B experiments and write results/ artefacts. "
                    "No network I/O.")
    p.add_argument("--data", default=str(C.TRACK_B_MOCK_CSV),
                   help="Track B observations CSV (default: the canonical one)")
    p.add_argument("--model", default=R.RANDOM_FOREST, choices=R.ALL_NAMES,
                   help="detector for the single-model analyses "
                        "(default: RandomForest)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--fast", action="store_true",
                   help="small forests / few bootstraps / 2 seeds for a quick demo")
    p.add_argument("--iot23-benign", default=None,
                   help="Track A IoT-23 benign observations CSV; enables the "
                        "one permitted cross-track FPR check")
    p.add_argument("--out-dir", default=str(C.RESULTS_DIR),
                   help="results directory (default: results/)")
    args = p.parse_args(argv)

    # Windows terminals default to cp1252; a provenance banner or verdict string
    # carrying a non-ASCII character would otherwise raise UnicodeEncodeError and
    # abort the run when stdout is redirected. Force UTF-8, degrade gracefully.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    C.ensure_dirs()
    cfg = C.load_config()
    if args.fast:
        cfg = _fast_config(cfg)
        _log("[mode] --fast: reduced forests/bootstraps/seeds (demo, not paper).")

    out = Path(args.out_dir)
    tables, figures, reports = out / "tables", out / "figures", out / "reports"

    data_path = Path(args.data)
    if not data_path.exists():
        _log(f"ERROR: Track B data not found at {data_path}.")
        _log("Generate it first (locally, no network):")
        _log("    python -m src.ingest.mock_generator")
        return 2
    df = read_observations(str(data_path))
    _log(f"[data] {len(df)} observations from {data_path.name} "
         f"({df[df.columns[0]].nunique()} ids)")

    # -- 1. headline: incremental value of the novel groups -----------------
    _log(f"[1/6] incremental build-up (model={args.model}, seed={args.seed}) ...")
    inc = E.run_incremental(df, cfg=cfg, seed=args.seed, model_name=args.model)
    TB.write_incremental_table(inc, path=tables / "incremental_value.csv")
    FG.fig_incremental(inc, path=figures / "incremental_value.png")
    _write_json(inc, reports / "incremental_value.json")

    # -- 2. multi-seed robustness of the headline ---------------------------
    _log("[2/6] multi-seed robustness ...")
    ms = E.run_incremental_multiseed(df, cfg=cfg, model_name=args.model)
    TB.write_multiseed_table(ms, path=tables / "multiseed_incremental.csv")
    _write_json(ms, reports / "multiseed_incremental.json")

    # -- 3. threshold-matched model comparison ------------------------------
    _log("[3/6] model comparison at the FPR budget ...")
    mc = E.run_model_comparison(df, cfg=cfg, seed=args.seed)
    TB.write_model_comparison_table(mc, path=tables / "model_comparison.csv")
    _write_json(mc, reports / "model_comparison.json")

    # -- 4. permutation importance ------------------------------------------
    _log("[4/6] permutation importance ...")
    perm = X.permutation_importance(df, cfg=cfg, seed=args.seed,
                                    model_name=args.model)
    TB.write_permutation_table(perm, path=tables / "permutation_importance.csv")
    FG.fig_permutation(perm, path=figures / "permutation_importance.png")
    _write_json(perm, reports / "permutation_importance.json")

    # -- 5. lab-only sensitivity --------------------------------------------
    _log("[5/6] lab-only sensitivity ...")
    lab = E.run_lab_only_sensitivity(df, cfg=cfg, seed=args.seed,
                                     model_name=args.model)
    _write_json(lab, reports / "lab_only_sensitivity.json")

    # -- 6. drop-one diagnostic ---------------------------------------------
    _log("[6/6] drop-one diagnostic ...")
    drop = E.run_drop_one(df, cfg=cfg, seed=args.seed, model_name=args.model)
    _write_json(drop, reports / "drop_one.json")

    # -- optional: the one permitted crossing -------------------------------
    if args.iot23_benign:
        ct_path = Path(args.iot23_benign)
        if not ct_path.exists():
            _log(f"[cross-track] SKIPPED: {ct_path} not found.")
        else:
            _log("[cross-track] scoring Track-B detector on IoT-23 benign ...")
            iot = read_observations(str(ct_path))
            ct = CT.cross_track_fpr(df, iot, cfg=cfg, seed=args.seed,
                                    model_name=args.model)
            TB.write_cross_track_table(ct, path=tables / "cross_track_fpr.csv")
            FG.fig_cross_track(ct, path=figures / "cross_track_fpr.png")
            _write_json(ct, reports / "cross_track_fpr.json")
    else:
        _log("[cross-track] SKIPPED: no --iot23-benign given (none ships with "
             "the repo). See docs/iot23-integration-plan.md.")

    # -- summary ------------------------------------------------------------
    _log("\n" + "=" * 70)
    _log("HEADLINE (Track B, SYNTHETIC -- not a real-world detection result):")
    _log("  single-seed: " + inc["verdict"]["reading"])
    _log("  multi-seed : " + ms["verdict"]["reading"])
    _log("=" * 70)
    _log(f"tables  -> {tables}")
    _log(f"figures -> {figures}")
    _log(f"reports -> {reports}")
    _log(inc["provenance"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
