"""
scripts/run_zeek.py — regenerate the protocol logs IoT-23 does not ship.

WHY THIS EXISTS
    IoT-23 distributes one Zeek log per capture: ``bro/conn.log.labeled``. Verified
    across all sixteen retained scenarios — there is no dns.log, no http.log and no
    ssl.log anywhere in the dataset. Those three are exactly where the behaviour
    this project measures lives (name resolution, server-list retrieval, TLS SNI),
    so a connection record alone cannot express it.

    The captures themselves are complete, so the logs can be regenerated: replay
    each .pcap through Zeek locally and keep the full log set. This script is that
    step, and it records enough provenance that a reader can reproduce it.

CONTAINMENT
    Reads local .pcap files and writes local .log files. Zeek runs offline with
    ``-r`` (read from file); it never opens an interface, never resolves a name and
    never sends a packet. Nothing here contacts the network.

WHERE ZEEK RUNS
    Zeek is a Unix tool and this is a Windows host, so it is invoked inside WSL.
    WSL mounts the Windows filesystem at /mnt/c, so the captures are read in place
    and no copy is made.

USAGE
    python scripts/run_zeek.py --list
    python scripts/run_zeek.py --only CTU-IoT-Malware-Capture-42-1
    python scripts/run_zeek.py                # every scenario, smallest first
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCENARIO_ROOT = (ROOT / "references" / "iot_23_datasets_full" / "opt"
                 / "Malware-Project" / "BigDataset" / "IoTScenarios")
OUT_ROOT = ROOT / "data" / "zeek"
MANIFEST = OUT_ROOT / "manifest.json"

# Six captures were stopped mid-write and end in a partial packet record, which
# Zeek rejects outright. scripts/repair_pcap.py writes a byte-exact prefix of each
# ending at its last complete packet; where such a copy exists it is used instead
# of the original. See data/pcap_repaired/repair_manifest.json for what was lost
# (7-246 trailing bytes per file, one incomplete packet each).
REPAIR_ROOT = ROOT / "data" / "pcap_repaired"

WSL_DISTRO = "Ubuntu"
ZEEK_BIN = "/opt/zeek/bin/zeek"

# The log types this project consumes. Zeek writes others (weird.log, files.log);
# they are kept but not required.
WANTED = ("conn.log", "dns.log", "http.log", "ssl.log")

# ---------------------------------------------------------------------------
# Connection-state timeouts for scan-heavy captures.
#
# Zeek holds per-connection state in memory until a connection is considered
# finished. Its default inactivity timeout is 5 minutes, which is correct for
# ordinary traffic and catastrophic for a horizontal port scan: every unanswered
# SYN to a dead host occupies memory for five minutes of capture time. On
# CTU-IoT-Malware-Capture-36-1 (13.6M connections) this exhausted 7.5 GB of RAM
# and all 2 GB of swap, and Zeek began thrashing at ~50% CPU.
#
# Shortening the timeout releases that state almost immediately. It does NOT
# discard data: an unanswered SYN is complete at the moment it is recorded, and
# its conn.log entry is written either way. The features derived here
# (scan_rate, distinct_dst_ports, failed_conn_ratio, flow_fanout) read those
# records, so their values are unaffected. Only the residency of half-open state
# changes.
#
# Applied ONLY to captures above SCAN_HEAVY_MB; everything smaller runs on Zeek's
# defaults so the common case stays stock. The setting is recorded per capture in
# the manifest.
SCAN_HEAVY_MB = 800.0
# Passed via Zeek's -e (inline script) as a SINGLE shell-quoted argument. It must
# not be appended bare: the semicolons are Zeek statement terminators, and an
# unquoted string would be split by the shell into separate commands, silently
# dropping the tuning while still exiting 0.
SCAN_TUNING = ("redef tcp_inactivity_timeout=10secs;"
               "redef udp_inactivity_timeout=10secs;"
               "redef icmp_inactivity_timeout=10secs;"
               # Half-open scan attempts are the bulk of these captures and their
               # state is what exhausts memory. A shorter attempt delay retires
               # them sooner; the conn.log record is written regardless.
               "redef tcp_attempt_delay=2secs;")

# NOTE: Zeek 8 has no --disable-analyzer flag (checked against `zeek --help`).
# Analyser suppression would have to go through Analyzer::disabled_analyzers in
# script, which needs exact tag constants; not worth guessing at, since the
# timeouts plus a larger WSL memory budget are what actually bound residency.

# Some scenarios ship protocol-filtered EXTRACTS alongside the full capture:
#   34-1  *.irc.pcap   (IRC subset)
#   9-1   telnet.pcap  (276 MB carved out of the 472 MB capture)
#   3-1   test.pcap    (962 KB sample)
# Their packets are already inside the main capture, so processing both would
# count the same traffic twice and inflate every per-window rate. They are
# skipped here, named explicitly rather than filtered by a silent glob.
SKIP_SUFFIXES = (".irc.pcap",)
SKIP_NAMES = ("telnet.pcap", "test.pcap")


class ZeekError(RuntimeError):
    """Zeek could not process a capture."""


@dataclass
class Job:
    scenario: str          # e.g. CTU-IoT-Malware-Capture-42-1
    label: str             # scenario, or scenario/Somfy-03 for split captures
    pcap: Path
    out_dir: Path
    size_bytes: int = 0
    logs: dict = field(default_factory=dict)
    seconds: float = 0.0
    sha256: str = ""
    repaired: bool = False
    scan_tuned: bool = False


def win_to_wsl(p: Path) -> str:
    """C:\\Users\\x -> /mnt/c/Users/x  (WSL reads the Windows disk in place)."""
    s = p.resolve().as_posix()
    if len(s) > 1 and s[1] == ":":
        return f"/mnt/{s[0].lower()}{s[2:]}"
    return s


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def zeek_version() -> str:
    out = subprocess.run(
        ["wsl", "-d", WSL_DISTRO, "--", ZEEK_BIN, "--version"],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise ZeekError(
            f"{ZEEK_BIN} not runnable in WSL '{WSL_DISTRO}'.\n"
            f"{(out.stderr or out.stdout).strip()}\n"
            "Install it first — see the repository README.")
    return (out.stdout or out.stderr).strip()


def discover() -> list[Job]:
    """Every capture worth processing, smallest first.

    Most scenarios hold one .pcap. CTU-Honeypot-Capture-7-1 (Somfy) is split into
    six session folders; each is processed separately and keeps its own label, so
    the six stay distinguishable downstream instead of being silently merged.
    """
    if not SCENARIO_ROOT.is_dir():
        raise SystemExit(f"scenario root not found: {SCENARIO_ROOT}")

    jobs: list[Job] = []
    for scen in sorted(p for p in SCENARIO_ROOT.iterdir() if p.is_dir()):
        keep = [p for p in sorted(scen.rglob("*.pcap"))
                if not p.name.endswith(SKIP_SUFFIXES)
                and p.name not in SKIP_NAMES]

        # How many usable captures share one directory decides the label. One is
        # the common case and keeps the path clean; more than one (Philips HUE
        # was captured on two separate dates) must be disambiguated by filename,
        # or the second Zeek run would overwrite the first one's logs.
        per_dir: dict[Path, int] = {}
        for p in keep:
            per_dir[p.parent] = per_dir.get(p.parent, 0) + 1

        for pcap in keep:
            rel = pcap.parent.relative_to(scen)
            label = scen.name if rel == Path(".") else f"{scen.name}/{rel.as_posix()}"
            if per_dir[pcap.parent] > 1:
                label = f"{label}/{pcap.stem}"

            # A repaired copy, when present, is the readable form of the same
            # capture and is preferred. The original stays untouched on disk.
            repaired = REPAIR_ROOT / pcap.relative_to(SCENARIO_ROOT)
            source = repaired if repaired.exists() else pcap

            jobs.append(Job(
                scenario=scen.name,
                label=label,
                pcap=source,
                out_dir=OUT_ROOT / label,
                size_bytes=source.stat().st_size,
                repaired=repaired.exists(),
            ))
    jobs.sort(key=lambda j: j.size_bytes)

    # A label collision would mean two captures writing into one directory and
    # silently clobbering each other. Fail loudly instead.
    seen: set[str] = set()
    for j in jobs:
        if j.label in seen:
            raise SystemExit(f"duplicate output label {j.label!r} — refusing to "
                             "overwrite; fix discover() before running")
        seen.add(j.label)
    return jobs


def run_one(job: Job, *, force: bool = False) -> Job:
    """Replay one capture through Zeek into its own output directory."""
    marker = job.out_dir / ".zeek_complete"
    if marker.exists() and not force:
        print(f"  = {job.label}  (already processed, skipping)")
        job.logs = {p.name: p.stat().st_size
                    for p in sorted(job.out_dir.glob("*.log"))}
        return job

    job.out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()

    # Large captures in this dataset are large because they are scans, so they
    # get the bounded-state tuning; small ones run stock.
    job.scan_tuned = job.size_bytes / 1e6 >= SCAN_HEAVY_MB
    tuning = f" -e {SCAN_TUNING!r}" if job.scan_tuned else ""

    # Zeek writes its logs into the working directory, so cd into the output dir
    # and point -r at the capture. Offline replay: no interface is opened.
    cmd = (f"cd {win_to_wsl(job.out_dir)!r} && "
           f"{ZEEK_BIN} -r {win_to_wsl(job.pcap)!r}{tuning} 2>&1")
    proc = subprocess.run(["wsl", "-d", WSL_DISTRO, "--", "bash", "-lc", cmd],
                          capture_output=True, text=True)
    job.seconds = time.time() - started

    # Zeek reports recoverable parse issues on stderr and still exits 0; only a
    # non-zero exit means the capture could not be read at all.
    if proc.returncode != 0:
        raise ZeekError(f"{job.label}: zeek exited {proc.returncode}\n"
                        f"{(proc.stdout or proc.stderr)[:2000]}")

    job.logs = {p.name: p.stat().st_size
                for p in sorted(job.out_dir.glob("*.log"))}
    if "conn.log" not in job.logs or job.logs["conn.log"] == 0:
        raise ZeekError(
            f"{job.label}: zeek exited 0 but produced no conn.log. "
            f"Output: {(proc.stdout or proc.stderr)[:600]}")
    # Written only after a clean exit. conn.log is streamed as Zeek runs, so its
    # presence says nothing about whether the run finished — an interrupted run
    # leaves a plausible-looking but partial log behind.
    marker.write_text("zeek ok " + time.strftime("%Y-%m-%dT%H:%M:%S"),
                      encoding="utf-8")
    got = [n for n in WANTED if n in job.logs]
    missing = [n for n in WANTED if n not in job.logs]
    print(f"  + {job.label}  ({job.size_bytes/1e6:.1f} MB, {job.seconds:.0f}s)"
          f"  logs={got}" + (f"  absent={missing}" if missing else ""))
    return job


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Replay IoT-23 captures through Zeek to regenerate the "
                    "dns/http/ssl logs the dataset does not ship. Offline only.")
    ap.add_argument("--only", action="append", default=None,
                    help="process just this scenario (repeatable)")
    ap.add_argument("--list", action="store_true",
                    help="show what would be processed and exit")
    ap.add_argument("--force", action="store_true",
                    help="reprocess captures that already have output")
    ap.add_argument("--max-mb", type=float, default=None,
                    help="skip captures larger than this (quick first pass)")
    args = ap.parse_args(argv)

    jobs = discover()
    if args.only:
        wanted = set(args.only)
        jobs = [j for j in jobs if j.scenario in wanted or j.label in wanted]
    if args.max_mb is not None:
        jobs = [j for j in jobs if j.size_bytes <= args.max_mb * 1e6]

    if not jobs:
        print("nothing to do")
        return 0

    total_mb = sum(j.size_bytes for j in jobs) / 1e6
    if args.list:
        print(f"{len(jobs)} capture(s), {total_mb:.0f} MB total:\n")
        for j in jobs:
            print(f"  {j.size_bytes/1e6:9.1f} MB  {j.label}")
        return 0

    version = zeek_version()
    print(f"zeek: {version}")
    print(f"{len(jobs)} capture(s), {total_mb:.0f} MB -> {OUT_ROOT}\n")

    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    done, failed = [], []
    for job in jobs:
        try:
            done.append(run_one(job, force=args.force))
        except ZeekError as exc:
            print(f"  ! {job.label}: {exc}", file=sys.stderr)
            failed.append(job.label)

    # Provenance: enough to reproduce this step exactly. Hashes are computed only
    # for captures actually processed, since hashing 14 GB is not free.
    print("\nhashing captures for the manifest...")
    for job in done:
        job.sha256 = sha256_of(job.pcap)

    manifest = {
        "zeek_version": version,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "scenario_root": str(SCENARIO_ROOT),
        "note": ("IoT-23 ships only bro/conn.log.labeled; dns.log, http.log and "
                 "ssl.log are regenerated here by replaying each .pcap through "
                 "Zeek offline. No network access at any point."),
        "captures": [
            {"scenario": j.scenario, "label": j.label, "pcap": j.pcap.name,
             "pcap_bytes": j.size_bytes, "pcap_sha256": j.sha256,
             "used_repaired_copy": j.repaired,
             "bounded_conn_state": j.scan_tuned,
             "seconds": round(j.seconds, 1), "logs": j.logs}
            for j in done
        ],
        "failed": failed,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"\nprocessed {len(done)}/{len(jobs)}   manifest -> {MANIFEST}")
    if failed:
        print(f"FAILED: {failed}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
