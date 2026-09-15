"""
reports/generate_docs.py — documentation that is DERIVED, not typed by hand.

Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators for
         IoT Botnet Detection

The feature catalogue and the IoT-23 availability table state facts that live in
code: which group a feature belongs to, its validated range, whether it is
binary or lab-only, and — the load-bearing one — whether IoT-23's
conn.log.labeled can supply it at all. If those were retyped into Markdown, the
prose could quietly contradict the schema after a later edit, and the paper
would claim a feature is computable from IoT-23 when the code emits it as NaN.

So this module GENERATES docs/feature-catalogue.md straight from
src.schema.columns. The file carries a "generated — do not edit by hand" banner,
and tests assert its counts equal ``availability_summary`` rather than any
literal. Regenerate with:  python -m src.reports.generate_docs
"""
from __future__ import annotations

from pathlib import Path

from src.config import DOCS_DIR
from src.schema import columns as K

GENERATED_BANNER = (
    "<!-- GENERATED FILE — do not edit by hand.\n"
    "     Source of truth: src/schema/columns.py\n"
    "     Regenerate:      python -m src.reports.generate_docs -->\n"
)

_ROLE = {g: ("NOVEL — on trial" if g in K.NOVEL_GROUPS else "base — comparison")
         for g in K.FEATURE_GROUPS}

_AVAIL_LABEL = {
    K.AVAIL_COMPUTABLE: "computable",
    K.AVAIL_PROXY: "proxy (flagged)",
    K.AVAIL_UNAVAILABLE: "unavailable (NaN)",
}


def _range_str(feat: str) -> str:
    lo, hi = K.FEATURE_RANGES[feat]
    return f"[{lo:g}, {'∞' if hi is None else format(hi, 'g')}]"


def feature_catalogue_markdown() -> str:
    """A row per feature: group, role, IoT-23 availability, flags, range."""
    avail = K.FEATURE_AVAILABILITY[K.SOURCE_IOT23]
    lines = [
        "## Feature catalogue",
        "",
        f"16 features across 4 groups. Unit of analysis: one device over one "
        f"{K.WINDOW_SECONDS_VALUE}-second window. Ranges are enforced by the "
        f"validator; a value outside them is a schema error, not a clamp.",
        "",
        "| Feature | Group | Role | IoT-23 | Lab-only | Binary | Range |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for group, cols in K.FEATURE_GROUPS.items():
        for feat in cols:
            lines.append(
                f"| `{feat}` | {group} | {_ROLE[group]} "
                f"| {_AVAIL_LABEL[avail[feat]]} "
                f"| {'yes' if feat in K.LAB_ONLY_FEATURES else '—'} "
                f"| {'yes' if feat in K.BINARY_FEATURES else '—'} "
                f"| {_range_str(feat)} |")
    return "\n".join(lines)


def iot23_availability_markdown() -> str:
    """Per-group computable/proxy/unavailable counts for IoT-23, from the schema.

    This is the machine-checkable form of the central limitation: the groups that
    DEFINE the thesis are the ones IoT-23 cannot supply.
    """
    summary = K.availability_summary(K.SOURCE_IOT23)
    lines = [
        "## IoT-23 feature availability (Track A)",
        "",
        "IoT-23's lightweight distribution ships Zeek `conn.log.labeled` only — "
        "no `dns.log`, `http.log`, `ssl.log`, and no payload. The counts below "
        "are read from `src/schema/columns.py`, not asserted in prose.",
        "",
        "| Group | Computable | Proxy | Unavailable | Unavailable features |",
        "| --- | --- | --- | --- | --- |",
    ]
    for group, cols in K.FEATURE_GROUPS.items():
        c = summary[group]
        unavail = [f"`{x}`" for x in cols
                   if K.FEATURE_AVAILABILITY[K.SOURCE_IOT23][x] == K.AVAIL_UNAVAILABLE]
        lines.append(
            f"| {group} | {c[K.AVAIL_COMPUTABLE]} | {c[K.AVAIL_PROXY]} "
            f"| {c[K.AVAIL_UNAVAILABLE]} | {', '.join(unavail) or '—'} |")

    total_unavail = len(K.unavailable_features(K.SOURCE_IOT23))
    total_proxy = len(K.proxy_features(K.SOURCE_IOT23))
    lines += [
        "",
        f"**{total_unavail} of 16 features are unavailable and {total_proxy} are "
        "proxies on IoT-23.** Both resolution and relay — the groups whose "
        "independent value this project measures — are among them. This is why "
        "the thesis is tested only on Track B (mock), and why Track A measures "
        "false alarms on real benign traffic rather than the thesis itself.",
    ]
    return "\n".join(lines)


def feature_catalogue_document() -> str:
    """The full docs/feature-catalogue.md body."""
    return "\n\n".join([
        GENERATED_BANNER.rstrip(),
        "# Feature catalogue & IoT-23 availability",
        "> Project: Evaluating Blockchain-Resolution and Victim-Relay Indicators "
        "for IoT Botnet Detection.",
        feature_catalogue_markdown(),
        iot23_availability_markdown(),
        "---",
        "*Regenerated from the schema by `python -m src.reports.generate_docs`. "
        "Edit `src/schema/columns.py`, not this file.*",
    ]) + "\n"


def write_feature_catalogue(path=None) -> Path:
    out = Path(path) if path else DOCS_DIR / "feature-catalogue.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(feature_catalogue_document(), encoding="utf-8")
    return out


def main(argv=None) -> int:   # pragma: no cover - thin CLI
    out = write_feature_catalogue()
    print(f"generated {out}")
    return 0


if __name__ == "__main__":   # pragma: no cover
    import sys
    sys.exit(main())
