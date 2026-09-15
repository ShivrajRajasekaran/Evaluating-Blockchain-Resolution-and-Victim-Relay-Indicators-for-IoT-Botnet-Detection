"""
schema/validate.py — enforce the observation schema before anything trusts it.

Every frame entering the pipeline passes through :func:`validate_observations`.
It is the mechanism that turns the two-track rule from a paragraph in a design
document into something the code physically cannot violate.

DESIGN
------
Two severities, and the distinction matters:

  ERROR    the frame is not usable; something is wrong with the DATA MODEL.
           Unknown enum value, cross-track pooling, a label_binary that
           disagrees with its research_class, a feature outside its declared
           range, an "unavailable" feature carrying a number.

  WARNING  the frame is usable but a reader must be told something.
           Proxy features present, unmapped rows present, a high share of
           missing cells. These are reported, never silently dropped.

The asymmetry is deliberate. Errors are things that would make a result WRONG.
Warnings are things that would make a result MISUNDERSTOOD. Both are failures
of a research pipeline; only the first should stop it.

USAGE
-----
    from src.schema import validate_observations, read_observations

    report = validate_observations(df)
    report.raise_if_failed()          # raises SchemaError listing every problem
    print(report.summary())
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from . import columns as K


class SchemaError(ValueError):
    """Raised when a frame violates the observation schema."""


# ---------------------------------------------------------------------------
# Report object
# ---------------------------------------------------------------------------
@dataclass
class ValidationReport:
    """Outcome of validating one frame. Collects EVERY problem, not just the
    first — a partially-migrated dataset usually has several, and fixing them
    one exception at a time wastes a lot of time."""

    n_rows: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def raise_if_failed(self) -> "ValidationReport":
        if self.errors:
            bullet = "\n  - "
            raise SchemaError(
                f"{len(self.errors)} schema error(s) in a frame of "
                f"{self.n_rows} row(s):{bullet}{bullet.join(self.errors)}"
            )
        return self

    def summary(self) -> str:
        lines = [
            f"rows={self.n_rows}  errors={len(self.errors)}  "
            f"warnings={len(self.warnings)}"
        ]
        for k, v in self.stats.items():
            lines.append(f"  {k}: {v}")
        for e in self.errors:
            lines.append(f"  ERROR   {e}")
        for w in self.warnings:
            lines.append(f"  WARNING {w}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------
def _check_columns(df: pd.DataFrame, rep: ValidationReport) -> bool:
    missing = [c for c in K.ALL_COLS if c not in df.columns]
    if missing:
        rep.error(f"missing required column(s): {missing}")
    extra = [c for c in df.columns if c not in K.ALL_COLS]
    if extra:
        rep.warn(f"unrecognised column(s) present, will be ignored: {extra}")
    return not missing


def _check_dtypes(df: pd.DataFrame, rep: ValidationReport) -> None:
    str_cols = [
        K.OBSERVATION_ID, K.DEVICE_ID, K.SOURCE_DATASET, K.SCENARIO_ID,
        K.CAPTURE_PROVENANCE, K.RESEARCH_CLASS, K.ORIGINAL_LABEL,
        K.LABEL_CONFIDENCE, K.QUALITY_FLAGS,
    ]
    for c in str_cols:
        if not (pd.api.types.is_object_dtype(df[c])
                or pd.api.types.is_string_dtype(df[c])):
            rep.error(f"{c}: expected string dtype, got {df[c].dtype}")

    if not pd.api.types.is_datetime64_any_dtype(df[K.WINDOW_START]):
        rep.error(
            f"{K.WINDOW_START}: expected datetime64, got "
            f"{df[K.WINDOW_START].dtype} — read CSVs via read_observations() "
            f"so the timestamp is parsed"
        )

    for c in (K.WINDOW_SECONDS, K.LABEL_BINARY, K.N_FEATURES_MISSING):
        if not pd.api.types.is_integer_dtype(df[c]):
            rep.error(f"{c}: expected integer dtype, got {df[c].dtype}")

    for c in K.FEATURE_COLS:
        if not pd.api.types.is_numeric_dtype(df[c]):
            rep.error(f"{c}: expected numeric dtype, got {df[c].dtype}")


def _check_enums(df: pd.DataFrame, rep: ValidationReport) -> None:
    checks = [
        (K.SOURCE_DATASET, set(K.SOURCE_DATASETS)),
        (K.CAPTURE_PROVENANCE, set(K.CAPTURE_PROVENANCES)),
        (K.RESEARCH_CLASS, set(K.RESEARCH_CLASSES) | {K.CLS_UNMAPPED}),
        (K.LABEL_CONFIDENCE, set(K.LABEL_CONFIDENCES)),
    ]
    for col, allowed in checks:
        bad = sorted(set(df[col].dropna().unique()) - allowed)
        if bad:
            rep.error(f"{col}: value(s) outside the controlled vocabulary: {bad}")

    for name in sorted({f for s in df[K.QUALITY_FLAGS].fillna("")
                        for f in K.parse_flags(s)}):
        if name not in K.QUALITY_FLAG_NAMES:
            rep.error(f"{K.QUALITY_FLAGS}: unknown flag {name!r}")

    bad_window = sorted(set(df[K.WINDOW_SECONDS].unique()) - {K.WINDOW_SECONDS_VALUE})
    if bad_window:
        rep.error(
            f"{K.WINDOW_SECONDS}: this project fixes the window at "
            f"{K.WINDOW_SECONDS_VALUE}s; found {bad_window}"
        )


def _check_identity(df: pd.DataFrame, rep: ValidationReport) -> None:
    dup = df[K.OBSERVATION_ID].duplicated()
    if dup.any():
        sample = df.loc[dup, K.OBSERVATION_ID].head(3).tolist()
        rep.error(
            f"{K.OBSERVATION_ID}: {int(dup.sum())} duplicate id(s), e.g. {sample}"
        )
    if df[K.DEVICE_ID].isna().any() or (df[K.DEVICE_ID] == "").any():
        rep.error(f"{K.DEVICE_ID}: empty value(s) — grouped splits need this key")
    if df[K.WINDOW_START].isna().any():
        rep.error(f"{K.WINDOW_START}: NaT value(s) — temporal splits need this key")


def _check_two_track_rule(df: pd.DataFrame, rep: ValidationReport) -> None:
    """The check this whole module exists for.

    Three ways to get it wrong, all caught here:
      1. a mock source carrying a real-track class (or vice versa)
      2. capture_provenance disagreeing with source_dataset
      3. one frame containing classes from BOTH tracks — the merged-pipeline
         mistake, which would let a model separate classes by capture artefact
    """
    expected_prov = {
        K.SOURCE_MOCK_LOCAL: K.PROV_SYNTHETIC,
        K.SOURCE_IOT23: K.PROV_REAL_CAPTURE,
    }
    expected_track = {K.SOURCE_MOCK_LOCAL: "B", K.SOURCE_IOT23: "A"}

    for source, sub in df.groupby(K.SOURCE_DATASET, sort=True):
        if source not in expected_prov:
            continue                            # already reported by _check_enums

        wrong_prov = sorted(set(sub[K.CAPTURE_PROVENANCE].unique())
                            - {expected_prov[source]})
        if wrong_prov:
            rep.error(
                f"source_dataset={source!r} must carry capture_provenance="
                f"{expected_prov[source]!r}, found {wrong_prov}"
            )

        want = expected_track[source]
        offenders = sorted({
            c for c in sub[K.RESEARCH_CLASS].unique()
            if c != K.CLS_UNMAPPED and K.TRACK_OF_CLASS.get(c) != want
        })
        if offenders:
            rep.error(
                f"TWO-TRACK VIOLATION: source_dataset={source!r} is Track "
                f"{want}, but carries Track "
                f"{'A' if want == 'B' else 'B'} class(es) {offenders}. Real "
                f"captures cannot contain blockchain-resolution or "
                f"victim-relay behaviour, and mock data is not evidence about "
                f"traditional botnets."
            )

    tracks = {K.TRACK_OF_CLASS[c] for c in df[K.RESEARCH_CLASS].unique()
              if c in K.TRACK_OF_CLASS}
    if len(tracks) > 1:
        rep.error(
            "TWO-TRACK VIOLATION: this frame pools Track A (real) and Track B "
            "(mock) observations. Their label spaces are disjoint by "
            "construction, so a model trained on the union learns which "
            "capture a row came from, not whether it is malicious. Keep the "
            "tracks in separate frames; the only permitted crossing is scoring "
            "a Track-B detector against Track-A benign rows."
        )


def _check_labels(df: pd.DataFrame, rep: ValidationReport) -> None:
    known = df[df[K.RESEARCH_CLASS] != K.CLS_UNMAPPED]
    if len(known):
        expected = known[K.RESEARCH_CLASS].map(
            lambda c: 1 if c in K.MALICIOUS_CLASSES else 0)
        mismatch = known[K.LABEL_BINARY].to_numpy() != expected.to_numpy()
        if mismatch.any():
            i = known.index[mismatch][0]
            rep.error(
                f"{K.LABEL_BINARY} disagrees with {K.RESEARCH_CLASS} on "
                f"{int(mismatch.sum())} row(s); first at index {i} "
                f"({known.at[i, K.RESEARCH_CLASS]!r} -> "
                f"{known.at[i, K.LABEL_BINARY]})"
            )

    unmapped = df[K.RESEARCH_CLASS] == K.CLS_UNMAPPED
    if unmapped.any():
        n = int(unmapped.sum())
        rep.warn(
            f"{n} row(s) ({n / len(df):.1%}) are {K.CLS_UNMAPPED} — retained "
            f"for auditing, MUST be excluded from training"
        )
        missing_flag = unmapped & ~df[K.QUALITY_FLAGS].fillna("").str.contains(
            K.FLAG_UNMAPPED_LABEL, regex=False)
        if missing_flag.any():
            rep.error(
                f"{int(missing_flag.sum())} {K.CLS_UNMAPPED} row(s) are not "
                f"flagged {K.FLAG_UNMAPPED_LABEL!r}"
            )

    expected_conf = {
        K.SOURCE_MOCK_LOCAL: K.CONF_SYNTHETIC_GROUND_TRUTH,
        K.SOURCE_IOT23: K.CONF_DATASET_ANNOTATED,
    }
    for source, sub in df.groupby(K.SOURCE_DATASET, sort=True):
        if source not in expected_conf:
            continue
        bad = sorted(set(sub[K.LABEL_CONFIDENCE].unique())
                     - {expected_conf[source]})
        if bad:
            rep.error(
                f"source_dataset={source!r} must carry label_confidence="
                f"{expected_conf[source]!r}, found {bad} — a locally generated "
                f"label and a dataset author's annotation are not the same "
                f"kind of evidence"
            )


def _check_feature_ranges(df: pd.DataFrame, rep: ValidationReport) -> None:
    for c in K.FEATURE_COLS:
        lo, hi = K.FEATURE_RANGES[c]
        v = df[c]
        below = v.notna() & (v < lo)
        if below.any():
            rep.error(f"{c}: {int(below.sum())} value(s) below minimum {lo} "
                      f"(min seen {float(v.min())!r})")
        if hi is not None:
            above = v.notna() & (v > hi)
            if above.any():
                rep.error(f"{c}: {int(above.sum())} value(s) above maximum {hi} "
                          f"(max seen {float(v.max())!r})")
        if not np.isfinite(v.fillna(0.0).to_numpy(dtype=float)).all():
            rep.error(f"{c}: contains +/-inf")

    for c in K.BINARY_FEATURES:
        bad = df[c].notna() & ~df[c].isin([0, 1])
        if bad.any():
            rep.error(f"{c}: declared binary but has {int(bad.sum())} "
                      f"non-0/1 value(s)")


def _check_availability(df: pd.DataFrame, rep: ValidationReport) -> None:
    """Missing cells must agree with what the source can actually supply.

    An "unavailable" feature carrying a number is the dangerous case: it means
    somebody imputed a value for a signal the capture never recorded, and any
    importance attributed to that feature afterwards is an artefact of the
    imputation.
    """
    for source, sub in df.groupby(K.SOURCE_DATASET, sort=True):
        if source not in K.FEATURE_AVAILABILITY:
            continue

        for c in K.unavailable_features(source):
            filled = sub[c].notna()
            if filled.any():
                rep.error(
                    f"source_dataset={source!r}: {c} is {K.AVAIL_UNAVAILABLE} "
                    f"for this source but {int(filled.sum())} row(s) carry a "
                    f"value. Imputing an unobservable feature invents evidence."
                )

        for c in K.features_by_availability(source, K.AVAIL_COMPUTABLE):
            empty = sub[c].isna()
            if empty.any():
                rep.warn(
                    f"source_dataset={source!r}: {c} is computable but NaN on "
                    f"{int(empty.sum())} row(s)"
                )

        proxies = K.proxy_features(source)
        if proxies:
            flagged = sub[K.QUALITY_FLAGS].fillna("").str.contains(
                K.FLAG_PROXY_FEATURES, regex=False)
            if not flagged.all():
                rep.error(
                    f"source_dataset={source!r}: {int((~flagged).sum())} row(s) "
                    f"are missing the {K.FLAG_PROXY_FEATURES!r} flag, but "
                    f"{proxies} are approximations for this source"
                )
            rep.warn(
                f"source_dataset={source!r}: {proxies} are approximations, not "
                f"exact measurements — do not cite their importance as a "
                f"finding"
            )

    counted = df[K.FEATURE_COLS].isna().sum(axis=1).to_numpy()
    declared = df[K.N_FEATURES_MISSING].to_numpy()
    if (counted != declared).any():
        n = int((counted != declared).sum())
        rep.error(
            f"{K.N_FEATURES_MISSING} disagrees with the actual NaN count on "
            f"{n} row(s)"
        )

    any_missing = df[K.FEATURE_COLS].isna().any(axis=1)
    flagged = df[K.QUALITY_FLAGS].fillna("").str.contains(
        K.FLAG_MISSING_FEATURES, regex=False)
    wrong = any_missing & ~flagged
    if wrong.any():
        rep.error(
            f"{int(wrong.sum())} row(s) have NaN feature(s) but no "
            f"{K.FLAG_MISSING_FEATURES!r} flag"
        )


def _collect_stats(df: pd.DataFrame, rep: ValidationReport) -> None:
    rep.stats["sources"] = df[K.SOURCE_DATASET].value_counts().to_dict()
    rep.stats["research_class"] = df[K.RESEARCH_CLASS].value_counts().to_dict()
    rep.stats["devices"] = int(df[K.DEVICE_ID].nunique())
    rep.stats["scenarios"] = int(df[K.SCENARIO_ID].nunique())
    rep.stats["window_span"] = (
        f"{df[K.WINDOW_START].min()} .. {df[K.WINDOW_START].max()}"
    )
    cells = len(df) * len(K.FEATURE_COLS)
    nan_cells = int(df[K.FEATURE_COLS].isna().to_numpy().sum())
    rep.stats["missing_cells"] = f"{nan_cells}/{cells} ({nan_cells / cells:.1%})"

    wpd = len(df) / max(df[K.DEVICE_ID].nunique(), 1)
    rep.stats["windows_per_device"] = round(wpd, 2)
    if wpd < 1.5:
        rep.warn(
            f"only {wpd:.2f} window(s) per device on average — a grouped split "
            f"will behave almost identically to a random split, so it will not "
            f"actually test cross-device generalisation"
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def validate_observations(df: pd.DataFrame) -> ValidationReport:
    """Validate an observation frame. Never raises; inspect or call
    :meth:`ValidationReport.raise_if_failed`."""
    rep = ValidationReport(n_rows=len(df))

    if df.empty:
        rep.error("frame is empty")
        return rep
    if not _check_columns(df, rep):
        return rep          # later checks would only produce KeyErrors

    _check_dtypes(df, rep)
    _check_enums(df, rep)
    _check_identity(df, rep)
    _check_two_track_rule(df, rep)
    _check_labels(df, rep)
    _check_feature_ranges(df, rep)
    _check_availability(df, rep)
    _collect_stats(df, rep)
    return rep


def assert_valid(df: pd.DataFrame) -> pd.DataFrame:
    """Validate and raise on error. Returns the frame for chaining."""
    validate_observations(df).raise_if_failed()
    return df


def trainable(df: pd.DataFrame) -> pd.DataFrame:
    """Rows usable for training: everything except `unmapped`.

    Use this instead of filtering by hand — `unmapped` rows are easy to forget
    and would silently enter a model as whatever their default binary label was.
    """
    return df[df[K.RESEARCH_CLASS] != K.CLS_UNMAPPED].copy()


# ---------------------------------------------------------------------------
# CSV round-trip with correct dtypes
# ---------------------------------------------------------------------------
_STR_COLS = (
    K.OBSERVATION_ID, K.DEVICE_ID, K.SOURCE_DATASET, K.SCENARIO_ID,
    K.CAPTURE_PROVENANCE, K.RESEARCH_CLASS, K.ORIGINAL_LABEL,
    K.LABEL_CONFIDENCE, K.QUALITY_FLAGS,
)


def read_observations(path, validate: bool = True) -> pd.DataFrame:
    """Read an observation CSV with the schema's dtypes restored.

    Plain ``pd.read_csv`` turns ``window_start`` into strings, ``quality_flags``
    of ``""`` into NaN, and numeric-looking device ids into integers — all three
    break downstream code in quiet ways. Always load through here.
    """
    df = pd.read_csv(
        path,
        dtype={c: "string" for c in _STR_COLS},
        keep_default_na=True,
    )
    if K.WINDOW_START in df.columns:
        df[K.WINDOW_START] = pd.to_datetime(df[K.WINDOW_START], errors="coerce")
    for c in _STR_COLS:
        if c in df.columns:
            df[c] = df[c].fillna("").astype(object)
    for c in (K.WINDOW_SECONDS, K.LABEL_BINARY, K.N_FEATURES_MISSING):
        if c in df.columns:
            df[c] = df[c].astype("int64")
    for c in K.FEATURE_COLS:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").astype("float64")
    if validate:
        assert_valid(df)
    return df


def write_observations(df: pd.DataFrame, path, validate: bool = True) -> None:
    """Write an observation CSV in canonical column order.

    Validated by default: a malformed frame should fail where it is produced,
    not three steps later where the cause is no longer visible.
    """
    if validate:
        assert_valid(df)
    out = df[K.ALL_COLS].copy()
    out[K.WINDOW_START] = pd.to_datetime(out[K.WINDOW_START]).dt.strftime(
        "%Y-%m-%dT%H:%M:%S")
    path = str(path)
    out.to_csv(path, index=False)
