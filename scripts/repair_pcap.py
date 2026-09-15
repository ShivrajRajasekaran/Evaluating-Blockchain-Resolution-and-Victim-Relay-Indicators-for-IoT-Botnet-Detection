"""
scripts/repair_pcap.py — salvage captures that were stopped mid-write.

WHY THIS EXISTS
    Several IoT-23 captures end in a partial packet record. The dataset
    documentation explains it: "the pcap file was growing too fast and we decided
    to stop the capture", so the writer was killed between emitting a record
    header and finishing its payload. Zeek treats that as fatal
    ("truncated dump file") and refuses the whole file, discarding millions of
    perfectly good packets because the last one is incomplete.

    This walks the record chain, keeps every COMPLETE packet, and stops at the
    first incomplete one. Nothing is invented and nothing is reordered: the output
    is a byte-exact prefix of the input, re-headered as a valid capture.

WHAT IS LOST, AND WHY THAT IS RECORDED
    Exactly one partial packet at the tail, plus any trailing bytes. The count and
    byte offset are printed and written into the repair manifest, because "we
    repaired the captures" is not a reproducible statement whereas "we dropped 1
    incomplete packet at offset 381,443,201 of N" is.

CONTAINMENT
    Reads a local file, writes a local file. No network access.

USAGE
    python scripts/repair_pcap.py --check          # report which captures are truncated
    python scripts/repair_pcap.py                  # repair the truncated ones
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIO_ROOT = (ROOT / "references" / "iot_23_datasets_full" / "opt"
                 / "Malware-Project" / "BigDataset" / "IoTScenarios")
REPAIR_ROOT = ROOT / "data" / "pcap_repaired"
MANIFEST = REPAIR_ROOT / "repair_manifest.json"

GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16

# Classic libpcap magics. The 3c4d variants mark nanosecond timestamps; the record
# layout is identical and only the fractional unit differs, so one walk covers all
# four. Byte order is whatever makes the magic read as written.
_BIG = (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d")
_LITTLE = (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


class PcapError(ValueError):
    """The file is not a classic libpcap capture this tool can walk."""


def _endianness(magic: bytes) -> str:
    """Return the struct prefix implied by the magic's byte order."""
    if magic in _BIG:
        return ">"
    if magic in _LITTLE:
        return "<"
    raise PcapError(f"unrecognised pcap magic {magic.hex()}")


def scan(path: Path) -> dict:
    """Walk the record chain; report where the last complete packet ends.

    Returns the byte offset one past the final complete record, the packet count,
    and how many trailing bytes are unusable. ``truncated`` is True when those
    trailing bytes exist.
    """
    size = path.stat().st_size
    with path.open("rb") as fh:
        magic = fh.read(4)
        if magic == _PCAPNG_MAGIC:
            raise PcapError("pcapng format — this tool handles classic pcap only")
        if len(magic) < 4:
            raise PcapError("file shorter than a pcap magic")
        endian = _endianness(magic)
        if len(fh.read(GLOBAL_HEADER_LEN - 4)) < GLOBAL_HEADER_LEN - 4:
            raise PcapError("file shorter than a pcap global header")

        rec = struct.Struct(endian + "IIII")
        offset = GLOBAL_HEADER_LEN
        packets = 0
        while True:
            head = fh.read(RECORD_HEADER_LEN)
            if len(head) < RECORD_HEADER_LEN:
                break                                    # partial record header
            _ts_sec, _ts_frac, incl_len, _orig_len = rec.unpack(head)
            # Guard against a corrupt length: seeking past EOF succeeds silently,
            # so the record must be shown to fit inside the file before advancing.
            if incl_len > 262_144:
                break
            end_of_record = offset + RECORD_HEADER_LEN + incl_len
            if end_of_record > size:
                break                                    # payload cut off
            fh.seek(incl_len, 1)
            offset = end_of_record
            packets += 1

    return {
        "path": str(path),
        "size_bytes": size,
        "good_bytes": offset,
        "packets": packets,
        "dropped_bytes": size - offset,
        "truncated": size != offset,
    }


def repair(path: Path, out: Path, info: dict) -> dict:
    """Write the valid prefix of ``path`` to ``out``, byte for byte."""
    out.parent.mkdir(parents=True, exist_ok=True)
    remaining = info["good_bytes"]
    with path.open("rb") as src, out.open("wb") as dst:
        while remaining:
            block = src.read(min(1 << 20, remaining))
            if not block:
                break
            dst.write(block)
            remaining -= len(block)
    return {**info, "repaired_to": str(out), "repaired_bytes": out.stat().st_size}


def captures() -> list[Path]:
    """Every capture the Zeek driver would process (same exclusions)."""
    skip_names = {"telnet.pcap", "test.pcap"}
    return sorted(p for p in SCENARIO_ROOT.rglob("*.pcap")
                  if p.name not in skip_names and not p.name.endswith(".irc.pcap"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Salvage IoT-23 captures that were stopped mid-write. "
                    "Keeps every complete packet; drops only the partial tail.")
    ap.add_argument("--check", action="store_true",
                    help="report truncation without writing anything")
    args = ap.parse_args(argv)

    found = captures()
    if not found:
        print(f"no captures under {SCENARIO_ROOT}")
        return 1

    print(f"scanning {len(found)} capture(s)...\n")
    results, broken = [], []
    for p in found:
        try:
            info = scan(p)
        except PcapError as exc:
            print(f"  ! {p.name}: {exc}", file=sys.stderr)
            continue
        results.append(info)
        if info["truncated"]:
            broken.append(info)
            print(f"  TRUNCATED  {p.parent.name}/{p.name}")
            print(f"             {info['packets']:,} complete packets, "
                  f"{info['dropped_bytes']:,} trailing bytes unusable "
                  f"({info['dropped_bytes'] / info['size_bytes'] * 100:.4f}% of file)")

    if not broken:
        print("  every capture is intact — nothing to repair")
        return 0

    print(f"\n{len(broken)} of {len(results)} captures are truncated")
    if args.check:
        return 0

    print("\nrepairing...")
    repaired = []
    for info in broken:
        src = Path(info["path"])
        rel = src.relative_to(SCENARIO_ROOT)
        out = REPAIR_ROOT / rel
        repaired.append(repair(src, out, info))
        print(f"  + {rel.as_posix()}  ->  {info['packets']:,} packets kept")

    REPAIR_ROOT.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps({
        "note": ("Captures stopped mid-write end in a partial packet record, which "
                 "Zeek rejects outright. Each file below was rewritten as the "
                 "byte-exact prefix ending at its last COMPLETE packet. No packet "
                 "was modified, reordered or synthesised."),
        "repaired": repaired,
    }, indent=2), encoding="utf-8")
    print(f"\nmanifest -> {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
