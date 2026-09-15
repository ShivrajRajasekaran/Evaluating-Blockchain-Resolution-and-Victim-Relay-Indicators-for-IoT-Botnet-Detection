"""
ingest/zeek.py — read a Zeek TSV log (conn.log / conn.log.labeled) locally.

CONTAINMENT
    This module opens a local file and parses text. It resolves no name, opens
    no socket and contacts nothing. It cannot download a dataset: the path must
    already exist on disk. See docs/ethics-and-containment.md.

WHY THIS IS NOT ONE LINE OF read_csv
    Two properties of real Zeek logs, and one property specific to IoT-23's
    labelled files, each break the naive call:

    1. THE HEADER IS DATA. A Zeek TSV declares its own column names and
       separator in ``#``-prefixed lines. Hard-coding the column list works
       until a capture was produced by a Zeek build with a different field set,
       at which point every column silently shifts by one and the numbers are
       wrong without anything raising. The header is therefore parsed, and the
       declared field list is what gets used.

    2. UNSET IS NOT ZERO IN THE SOURCE. Zeek writes ``-`` for an unset field and
       ``(empty)`` for an empty one. Read naively both become the string "-", the
       column becomes dtype object, and every downstream numeric comparison
       silently returns False. Here they are converted deliberately, and the
       number of cells that needed it is COUNTED and reported — a capture where
       40% of byte counts were unset is a different object from one where 0.1%
       were, and the reader should not have to guess which they have.

    3. IoT-23's LABEL COLUMNS ARE NOT ALWAYS TAB-SEPARATED. In part of the
       corpus the trailing ``tunnel_parents / label / detailed-label`` block is
       separated by runs of spaces rather than tabs. A tab-only parse then yields
       one fused column and the label is unreadable. The separator actually
       present is DETECTED from the first data line rather than assumed, and
       which path was taken is reported.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

# Zeek's own tokens for "no value". Distinct in the format, both meaning "not a
# number" for our purposes — but see the counting note above.
UNSET = "-"
EMPTY = "(empty)"
NULL_TOKENS = (UNSET, EMPTY)

_HEADER_PREFIX = "#"
_SEPARATOR_DIRECTIVE = "#separator"


class ZeekLogError(ValueError):
    """The file is not a readable Zeek TSV log."""


@dataclass
class ZeekHeader:
    fields: list[str]
    types: list[str]
    separator: str
    path: str
    n_header_lines: int

    def index_of(self, name: str) -> int:
        try:
            return self.fields.index(name)
        except ValueError as exc:
            raise ZeekLogError(
                f"required field {name!r} is not in this log; it declares "
                f"{self.fields}"
            ) from exc


@dataclass
class ReadStats:
    """What the parse actually did. Written into the ingest report."""

    rows_read: int = 0
    rows_skipped_malformed: int = 0
    data_lines_total: int = 0
    separator_used: str = "\t"
    used_whitespace_fallback: bool = False
    truncated_by_max_flows: bool = False
    coerced_cells: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "rows_read": self.rows_read,
            "rows_skipped_malformed": self.rows_skipped_malformed,
            "data_lines_total": self.data_lines_total,
            "malformed_line_fraction": (
                self.rows_skipped_malformed / self.data_lines_total
                if self.data_lines_total else 0.0),
            "separator_used": ("whitespace_runs"
                               if self.used_whitespace_fallback else "tab"),
            "truncated_by_max_flows": self.truncated_by_max_flows,
            "unset_cells_coerced_to_zero": dict(self.coerced_cells),
        }


def _decode_separator(raw: str) -> str:
    """``#separator \\x09`` declares the separator as an escape sequence."""
    raw = raw.strip()
    m = re.fullmatch(r"\\x([0-9a-fA-F]{2})", raw)
    if m:
        return chr(int(m.group(1), 16))
    return raw


def read_header(path: str | Path) -> ZeekHeader:
    """Parse the ``#``-prefixed header block.

    Raises ZeekLogError with an actionable message if the file is not a Zeek TSV
    — including the case of a gzipped file handed over unextracted, which is how
    IoT-23 is distributed and therefore the most likely first mistake.
    """
    p = Path(path)
    if not p.exists():
        raise ZeekLogError(
            f"file not found: {p}\n"
            "This adapter never downloads anything. Obtain the IoT-23 capture "
            "separately, extract it, and pass the local path to the extracted "
            "conn.log.labeled. See docs/iot23-integration-plan.md."
        )
    if p.is_dir():
        raise ZeekLogError(
            f"{p} is a directory. Pass the path to a single conn.log.labeled "
            "file, not the scenario folder."
        )
    if p.suffix in {".gz", ".zip", ".tgz", ".xz", ".bz2"}:
        raise ZeekLogError(
            f"{p.name} looks compressed. Extract it first and pass the "
            "extracted conn.log.labeled; parsing a compressed stream would "
            "hide how much of the file was actually read."
        )

    separator = "\t"
    fields: list[str] = []
    types: list[str] = []
    n_header = 0
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.startswith(_HEADER_PREFIX):
                break
            n_header += 1
            stripped = line.rstrip("\n").rstrip("\r")
            if stripped.startswith(_SEPARATOR_DIRECTIVE):
                separator = _decode_separator(
                    stripped[len(_SEPARATOR_DIRECTIVE):])
                continue
            parts = stripped.split(separator)
            directive = parts[0]
            if directive == "#fields":
                fields = parts[1:]
            elif directive == "#types":
                types = parts[1:]

    if not fields:
        raise ZeekLogError(
            f"{p.name} has no '#fields' header line, so its columns cannot be "
            "identified. A Zeek TSV always declares them. If this file came "
            "from a converter that stripped the header, the column order is "
            "unknowable and the file must not be used."
        )
    return ZeekHeader(fields=fields, types=types, separator=separator,
                      path=str(p), n_header_lines=n_header)


def _first_data_line(path: Path) -> str | None:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith(_HEADER_PREFIX):
                continue
            if line.strip():
                return line.rstrip("\n").rstrip("\r")
    return None


def detect_separator_mode(header: ZeekHeader) -> bool:
    """True if the file needs the whitespace-run fallback. See quirk 3.

    Decided from the first data line, by counting: if splitting on the declared
    separator yields the declared number of fields, the declared separator is
    right. Anything else and splitting on whitespace runs is tried instead.
    """
    line = _first_data_line(Path(header.path))
    if line is None:
        raise ZeekLogError(
            f"{Path(header.path).name} has a header but no data rows.")
    n_declared = len(header.fields)
    if len(line.split(header.separator)) == n_declared:
        return False
    if len(line.split()) >= n_declared:
        return True
    raise ZeekLogError(
        f"the first data row of {Path(header.path).name} splits into "
        f"{len(line.split(header.separator))} tab-separated fields and "
        f"{len(line.split())} whitespace-separated fields, but the header "
        f"declares {n_declared}. The file's columns cannot be identified "
        "safely, so it is not read rather than read wrongly."
    )


def count_data_lines(path: str | Path) -> int:
    """Exact count of non-comment lines, by counting newline bytes.

    Needed so ``rows_skipped_malformed`` is an exact number instead of a
    reassuring silence: pandas skips unparseable lines without telling the caller
    how many, and "we read 4.1 million flows" means something different if 300
    000 lines were dropped.

    COMMENT LINES ARE SUBTRACTED WHEREVER THEY APPEAR, not just at the top. A
    Zeek log ends with a ``#close`` line, and every log written by a rotating
    Zeek process has a second ``#`` block in the middle. Subtracting only the
    opening header would therefore report at least one malformed line for every
    well-formed file in existence — and a discrepancy counter that is never zero
    is one the reader learns to ignore, which defeats the point of having it.

    One sequential pass, two byte scans, no parsing, so it stays affordable on a
    multi-gigabyte log. A blank line would be counted as data (pandas skips it),
    but Zeek does not write blank lines; if that ever changes it shows up as a
    small non-zero malformed count rather than as a wrong flow total.
    """
    total = 0
    comments = 0
    # A synthetic leading newline so the file's first byte counts as a line start.
    carry = b"\n"
    tail_newline = True
    with open(path, "rb") as fh:
        while chunk := fh.read(8 << 20):
            total += chunk.count(b"\n")
            # Every adjacent byte pair is examined exactly once: the pair
            # straddling a chunk boundary is what `carry` reinstates.
            comments += (carry + chunk).count(b"\n#")
            carry = chunk[-1:]
            tail_newline = chunk.endswith(b"\n")
    if not tail_newline:
        total += 1        # a final line with no trailing newline
    return max(0, total - comments)


def read_log(path: str | Path, *, usecols: list[str] | None = None,
             max_rows: int | None = None,
             chunksize: int = 1_000_000) -> tuple[pd.DataFrame, ZeekHeader,
                                                  ReadStats]:
    """Read a Zeek TSV into a DataFrame with the declared column names.

    All columns come back as strings. Numeric conversion happens in the adapter,
    where the ``-``-to-zero decision can be counted and reported rather than
    performed invisibly here.

    ``max_rows`` caps the read for smoke tests. When it truncates, the fact is
    recorded in ReadStats and must be surfaced — a capped run is not a run of
    the capture, and a result table that does not say so is misleading.
    """
    p = Path(path)
    header = read_header(p)
    use_whitespace = detect_separator_mode(header)

    stats = ReadStats(
        separator_used=header.separator,
        used_whitespace_fallback=use_whitespace,
        data_lines_total=count_data_lines(p),
    )

    # The whitespace fallback needs a regex separator, which forces pandas' pure
    # Python engine. Slower, and only used for the files that require it.
    read_kwargs: dict = {
        "names": header.fields,
        "comment": _HEADER_PREFIX,
        "header": None,
        "dtype": str,
        "na_filter": False,          # keep "-" as a token; do not invent NaN
        "on_bad_lines": "skip",
        "chunksize": chunksize,
    }
    if use_whitespace:
        read_kwargs.update(sep=r"\s+", engine="python")
    else:
        read_kwargs.update(sep=header.separator, engine="c")

    # usecols is validated here but deliberately NOT passed to pandas.
    #
    # Handing pandas a usecols list disables its field-count check: a line with
    # more fields than the header declares is then silently accepted, the wanted
    # columns are taken from it, and on_bad_lines="skip" never fires. That leaves
    # rows_skipped_malformed structurally zero for exactly the anomaly it exists
    # to report — a counter that cannot rise is worse than no counter, because it
    # reads as evidence of a clean file.
    #
    # Parsing all declared columns and dropping the unused ones per chunk costs
    # some throughput on a 23-column log. In exchange, a malformed line is DROPPED
    # AND COUNTED rather than read with its later fields shifted, which is the
    # safer of the two failures here: a shifted line can put the wrong string in
    # the label column and produce a confidently mislabelled flow.
    if usecols:
        missing = [c for c in usecols if c not in header.fields]
        if missing:
            raise ZeekLogError(
                f"{p.name} does not declare required field(s) {missing}; "
                f"it declares {header.fields}"
            )

    frames: list[pd.DataFrame] = []
    total = 0
    # The reader is closed explicitly: breaking out of the chunk loop on
    # --max-flows otherwise leaves the file handle open until GC, which on
    # Windows keeps a lock on the capture.
    with pd.read_csv(p, **read_kwargs) as reader:
        for chunk in reader:
            if usecols:
                # Per chunk, not after concat: on a multi-gigabyte log the
                # unwanted columns would otherwise all be held in memory at once.
                chunk = chunk[usecols]
            if max_rows is not None and total + len(chunk) >= max_rows:
                frames.append(chunk.iloc[: max_rows - total])
                total = max_rows
                stats.truncated_by_max_flows = True
                break
            frames.append(chunk)
            total += len(chunk)

    df = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame(
        columns=usecols or header.fields, dtype=str)

    stats.rows_read = len(df)
    if not stats.truncated_by_max_flows:
        stats.rows_skipped_malformed = max(
            0, stats.data_lines_total - stats.rows_read)
    return df, header, stats


def to_numeric(series: pd.Series, *, name: str, stats: ReadStats,
               fill: float = 0.0) -> pd.Series:
    """Convert a Zeek string column to float, counting the unset cells.

    ``-`` becomes ``fill`` (0.0), which is the right value for the cases that
    actually produce it in conn.log — a single-packet flow has no duration, and a
    flow with no payload accounting moved no payload that any feature here can
    see. It is nonetheless a COERCION, so the count goes into the ingest report.
    A capture where most byte counts were unset is not usable for byte features,
    and the only way to know is to be told the number.
    """
    s = series.astype(str).str.strip()
    n_unset = int(s.isin(NULL_TOKENS).sum())
    out = pd.to_numeric(s.where(~s.isin(NULL_TOKENS)), errors="coerce")
    n_unparseable = int(out.isna().sum()) - n_unset
    if n_unset or n_unparseable:
        stats.coerced_cells[name] = {
            "unset_token": n_unset,
            "unparseable": max(0, n_unparseable),
        }
    return out.fillna(fill).astype("float64")
