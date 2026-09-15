"""
scripts/ingest_file.py — analyse an authorised capture from the command line.

    python -m scripts.ingest_file --input data/authorised_input/conn.log
    python -m scripts.ingest_file --input flows.csv --source op_flow_csv
    python -m scripts.ingest_file --all            # everything in the inbox
    python -m scripts.ingest_file --input conn.log --dry-run

THE SAME PIPELINE THE DASHBOARD RUNS
    This is a thin wrapper over :func:`src.api.pipeline.run_pipeline`, the
    identical code path an upload takes. A CLI that reimplemented ingestion
    would drift from the web app and produce subtly different alerts from the
    same file; there is one implementation, and this is one of its two callers.

WHAT IT WILL READ
    Exactly two things: a path you name explicitly, and the files an operator
    has placed in the authorised input directory (``product.input_dir``).
    Nothing is discovered, crawled or fetched. Symlinks in the inbox are
    skipped — a link there would read a file outside the authorised directory.

--dry-run
    Ingests and detects, prints what WOULD be raised, and writes nothing. Useful
    for checking what a new capture format produces before it lands in an
    analyst's queue.

CONTAINMENT
    Reads local files, writes one local database. No network I/O of any kind.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.api.pipeline import run_pipeline                      # noqa: E402
from src.api.uploads import authorised_input_files             # noqa: E402
from src.config import load_config, operational_data_note      # noqa: E402
from src.detection import DetectionEngine                      # noqa: E402
from src.detection import categories as CAT                    # noqa: E402
from src.schema import columns as K                            # noqa: E402
from src.storage import Database, Repository                   # noqa: E402

CONSOLE_ACTOR = "console"


class _ConsoleActor:
    """A stand-in actor so audit rows record that this came from the CLI."""

    user_id = None
    username = CONSOLE_ACTOR


def db_for(cfg, override: str | None) -> Database:
    path = (Path(override).expanduser().resolve() if override
            else (ROOT / str(cfg.storage.sqlite_path)).resolve())
    if not path.exists():
        raise SystemExit(
            f"{path} does not exist — run `python -m scripts.init_db` first")
    return Database(path)


def guess_source(path: Path, default: str = K.SOURCE_OP_ZEEK) -> str:
    """A sensible source for a filename, still overridable with --source.

    Only the extension and the Zeek header are consulted. Guessing wrong is not
    dangerous — the adapter refuses a file whose columns it cannot read — but
    guessing right saves the common case from needing a flag.
    """
    if path.suffix.lower() in (".log", ".labeled"):
        return K.SOURCE_OP_ZEEK
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(512)
    except OSError:
        return default
    if head.lstrip().startswith("#separator") or "#fields" in head:
        return K.SOURCE_OP_ZEEK
    return K.SOURCE_OP_FLOW_CSV


def dry_run(path: Path, source: str, cfg) -> int:
    """Ingest and detect in memory; report; persist nothing."""
    from src.api.pipeline import ingest_observations

    obs, report = ingest_observations(path, source=source,
                                      scenario_id=f"dryrun-{path.stem}",
                                      cfg=cfg)
    result = DetectionEngine(cfg=cfg).detect_frame(obs)
    summary = result.summary()

    print(f"DRY RUN  {path.name}  ({source})")
    print(f"  windows        {len(obs)}")
    print(f"  devices        {obs[K.DEVICE_ID].nunique()}")
    print("  verdicts:")
    for category, n in summary["by_category"].items():
        if n:
            marker = "  <- would alert" if CAT.raises_alert(category) else ""
            print(f"    {category:<42} {n}{marker}")
    blind = summary["windows_with_group_ungradeable"]
    if blind:
        print("  groups this source could not judge:")
        for group, n in blind.items():
            print(f"    {group:<12} on {n} window(s)")
    print(f"  would raise     {summary['n_alerting']} alert(s)")
    print("\n  nothing was written — this was a dry run")
    print(f"  {result.marker}")
    return 0


def ingest_one(path: Path, source: str, cfg, db: Database) -> int:
    with db.transaction() as conn:
        outcome = run_pipeline(path, source=source, repo=Repository(conn),
                               source_file=path.name, cfg=cfg,
                               actor=_ConsoleActor())
    if not outcome.ok:
        print(f"FAILED   {path.name}: {outcome.error}", file=sys.stderr)
        return 1

    print(f"INGESTED {path.name}  ({source})")
    print(f"  job            {outcome.job_id}")
    print(f"  windows        {outcome.windows} from {outcome.devices} device(s)")
    print(f"  alerts         {outcome.alerts_created} new, "
          f"{outcome.alerts_coalesced} coalesced into existing")
    if outcome.truncated:
        print("  NOTE          the run hit alerts.max_alerts_per_run and was "
              "truncated")
    counts = (outcome.summary or {}).get("by_category", {})
    insufficient = counts.get(CAT.CAT_INSUFFICIENT_TELEMETRY, 0)
    if insufficient:
        print(f"  {insufficient} window(s) could not be judged on at least one "
              "indicator group\n                 and were recorded as "
              "INSUFFICIENT_TELEMETRY, not as benign")
    return 0


def main(argv=None) -> int:
    cfg = load_config()
    parser = argparse.ArgumentParser(
        description="Ingest an authorised capture and run rule-based "
                    "detection over it. Reads only the file you name or the "
                    "authorised input directory.")
    parser.add_argument("--input", help="path to one local capture")
    parser.add_argument("--all", action="store_true",
                        help="process every eligible file in "
                             f"{cfg.product.input_dir}")
    parser.add_argument("--source", choices=list(K.OPERATIONAL_SOURCES),
                        default=None,
                        help="telemetry format (guessed from the file if "
                             "omitted)")
    parser.add_argument("--db", default=None)
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would be raised; write nothing")
    args = parser.parse_args(argv)

    if not args.input and not args.all:
        parser.error("give --input <path> or --all")

    if args.all:
        inbox = ROOT / str(cfg.product.input_dir)
        targets = authorised_input_files(inbox, cfg.api.allowed_extensions)
        if not targets:
            print(f"no eligible files in {inbox}")
            print(f"  accepted extensions: "
                  f"{', '.join(cfg.api.allowed_extensions)}")
            return 0
    else:
        one = Path(args.input).expanduser()
        if not one.is_file():
            raise SystemExit(f"not a readable file: {one}")
        targets = [one]

    if not args.dry_run:
        db = db_for(cfg, args.db)

    failures = 0
    for path in targets:
        source = args.source or guess_source(path)
        try:
            if args.dry_run:
                failures += dry_run(path, source, cfg)
            else:
                failures += ingest_one(path, source, cfg, db)
        except Exception as exc:           # one bad file must not stop the batch
            print(f"FAILED   {path.name}: {exc}", file=sys.stderr)
            failures += 1
        print()

    print(operational_data_note())
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
