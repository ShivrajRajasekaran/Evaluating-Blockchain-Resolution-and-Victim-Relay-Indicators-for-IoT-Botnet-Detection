"""
tests/test_iot23_adapter.py — the Track A adapter, end to end.

The adapter is the only module in the project that touches real data, so its
failures are the ones a reader of the paper cannot detect. A shifted column, an
unset field read as zero, or an orientation left as Zeek wrote it all produce a
full observation table with plausible numbers in it.

The tests that matter most here, in order:

  * ORIENTATION. Zeek writes conn.log from the ORIGINATOR's point of view. For a
    flow the monitored device answered rather than opened, ``orig_bytes`` means
    bytes the PEER sent. Left unswapped, ``updownlink_ratio`` is inverted for
    exactly the inbound-heavy devices a relay detector cares about.
  * UNSET IS NOT ZERO, and where zero is genuinely wrong (the timestamp) the row
    is dropped rather than placed in 1970.
  * REFUSAL. A plain conn.log, a compressed file, a capture with no identifiable
    device: each is refused with a message, because each would otherwise produce
    a table that looks like a result.

Fixtures are written to a temp directory as real Zeek TSV text — header block,
declared #fields, the lot — rather than by calling the parser's internals. A
test that constructs a DataFrame directly cannot catch a header bug, and the
header is the thing most likely to differ between captures.
"""
from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.features import windowing as W
from src.ingest import iot23
from src.ingest import zeek
from src.schema import columns as K

# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------
# DEV is private, so the adapter's fallback basis finds it. The peers are in
# 100.64.0.0/10 (carrier-grade NAT space): NOT private by ipaddress' definition,
# so they are not mistaken for devices, and not allocated to any real party, so
# no test fixture in this project names a real third-party host.
#
# The RFC 5737 documentation ranges cannot be used here: Python's
# ipaddress.is_private returns True for 192.0.2.0/24, 198.51.100.0/24 AND
# 203.0.113.0/24, so a documentation-range peer would be detected as a second
# monitored device and silently change every per-device feature.
DEV = "192.168.1.132"
DEV2 = "192.168.1.140"
PEER_A = "100.64.0.10"
PEER_B = "100.64.0.20"
PEER_C = "100.64.0.30"

# 2019-01-01T00:00:00Z. Chosen because it is an exact multiple of 300, so the
# absolute window grid lands on it and expected window starts are readable.
T0 = 1_546_300_800
WIN = [pd.Timestamp("2019-01-01T00:00:00"), pd.Timestamp("2019-01-01T00:05:00"),
       pd.Timestamp("2019-01-01T00:10:00"), pd.Timestamp("2019-01-01T00:15:00")]

# ---------------------------------------------------------------------------
# A real IoT-23 conn.log.labeled header
# ---------------------------------------------------------------------------
IOT23_FIELDS: tuple[str, ...] = (
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
    "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
    "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents", "label", "detailed-label",
)
_TYPES: dict[str, str] = {
    "ts": "time", "uid": "string", "id.orig_h": "addr", "id.orig_p": "port",
    "id.resp_h": "addr", "id.resp_p": "port", "proto": "enum",
    "service": "string", "duration": "interval", "orig_bytes": "count",
    "resp_bytes": "count", "conn_state": "string", "local_orig": "bool",
    "local_resp": "bool", "missed_bytes": "count", "history": "string",
    "orig_pkts": "count", "orig_ip_bytes": "count", "resp_pkts": "count",
    "resp_ip_bytes": "count", "tunnel_parents": "set[string]",
    "label": "string", "detailed-label": "string",
}

_ROW_DEFAULTS: dict[str, str] = {
    "uid": "CTEST00000000000000",
    "id.orig_h": DEV,
    "id.orig_p": "49152",
    "id.resp_h": PEER_A,
    "id.resp_p": "443",
    "proto": "tcp",
    "service": "-",
    "duration": "10.0",
    "orig_bytes": "500",
    "resp_bytes": "1500",
    "conn_state": "SF",
    # Unset, which is the normal state in IoT-23: Site::local_nets was not
    # configured when the captures were produced.
    "local_orig": "-",
    "local_resp": "-",
    "missed_bytes": "0",
    "history": "ShADadFf",
    "orig_pkts": "6",
    "orig_ip_bytes": "800",
    "resp_pkts": "8",
    "resp_ip_bytes": "1900",
    "tunnel_parents": "-",
    "label": "Benign",
    "detailed-label": "-",
}


def row(ts, **overrides) -> dict[str, str]:
    """One conn.log line as a field->string mapping. Every value is a STRING,
    because that is what the file holds and what the reader must cope with."""
    r = dict(_ROW_DEFAULTS)
    r["ts"] = f"{float(ts):.6f}"
    r.update({k: str(v) for k, v in overrides.items()})
    return r


def write_log(path, rows, *, fields: tuple[str, ...] = IOT23_FIELDS,
              space_separated_label_block: bool = False) -> Path:
    """Write a Zeek TSV whose header declares ``fields``.

    ``space_separated_label_block`` reproduces the part of the IoT-23 corpus
    where the trailing tunnel_parents/label/detailed-label block is separated by
    runs of spaces rather than tabs — the quirk that makes a tab-only parse fuse
    three columns into one and lose the label entirely.
    """
    p = Path(path)
    out = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tconn",
        "#open\t2019-01-01-00-00-00",
        "#fields\t" + "\t".join(fields),
        "#types\t" + "\t".join(_TYPES.get(f, "string") for f in fields),
    ]
    for r in rows:
        vals = [r.get(f, "-") for f in fields]
        if space_separated_label_block and len(vals) > 3:
            out.append("\t".join(vals[:-3]) + "   " + "   ".join(vals[-3:]))
        else:
            out.append("\t".join(vals))
    out.append("#close\t2019-01-01-00-20-00")
    p.write_text("\n".join(out) + "\n", encoding="utf-8")
    return p


def standard_rows() -> list[dict[str, str]]:
    """One device over four windows, with a known label in each.

    W0  six benign conversations with one peer, 30 s apart
    W1  the same shape, with one C&C-HeartBeat flow among the six -> mixed
    W2  four rejected outbound probes to four ports -> a port scan, all
        malicious, and every byte/duration field unset (as Zeek writes them
        for a connection that never established)
    W3  a single benign flow, so at least one window has no measurable beacon
    """
    rows: list[dict[str, str]] = []
    for i in range(6):
        rows.append(row(T0 + 30 * i))
    for i in range(6):
        r = row(T0 + 300 + 30 * i, **{"id.resp_h": PEER_B})
        if i == 3:
            r.update({"label": "Malicious", "detailed-label": "C&C-HeartBeat"})
        rows.append(r)
    for i in range(4):
        rows.append(row(T0 + 600 + 20 * i, **{
            "id.resp_h": PEER_C, "id.resp_p": 3000 + i, "conn_state": "S0",
            "duration": "-", "orig_bytes": "-", "resp_bytes": "-",
            "orig_pkts": 1, "orig_ip_bytes": 40, "resp_pkts": 0,
            "resp_ip_bytes": 0,
            "label": "Malicious",
            "detailed-label": "PartOfAHorizontalPortScan"}))
    rows.append(row(T0 + 900))
    return rows


def raw_frame(rows) -> pd.DataFrame:
    """The string frame ``normalise_orientation`` expects, without going through
    a file. Used only by the orientation tests, which are about the swap itself.
    """
    df = pd.DataFrame([{f: r.get(f, "-") for f in IOT23_FIELDS} for r in rows],
                      dtype=str)
    return df.assign(_raw_label=[
        iot23.L.raw_label_string(r.get("label", "-"),
                                 r.get("detailed-label", "-")) for r in rows])


class _TempCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def log(self, rows, name="conn.log.labeled", **kw) -> Path:
        return write_log(self.tmp / name, rows, **kw)


# ===========================================================================
# Reading the file
# ===========================================================================
class TestReading(_TempCase):
    def test_the_standard_capture_ingests(self):
        obs, rep = iot23.ingest(self.log(standard_rows()), scenario_id="TEST-1")
        self.assertEqual(len(obs), 4)
        self.assertEqual(rep["read"]["rows_read"], 17)
        self.assertEqual(rep["read"]["rows_skipped_malformed"], 0)

    def test_the_trailing_close_line_is_not_counted_as_malformed(self):
        # Every Zeek log ends with '#close', and a rotated one carries a second
        # '#' block mid-file. Subtracting only the opening header would report at
        # least one malformed line for every well-formed capture in existence —
        # and a discrepancy counter that is never zero is one the reader learns
        # to ignore, which is worse than not having it.
        _, rep = iot23.ingest(self.log(standard_rows()), scenario_id="TEST-1")
        self.assertEqual(rep["read"]["data_lines_total"], 17)
        self.assertEqual(rep["read"]["rows_skipped_malformed"], 0)
        self.assertEqual(rep["read"]["malformed_line_fraction"], 0.0)

    def test_an_over_long_line_is_counted_as_malformed(self):
        # The complement of the test above: the counter must still fire. A fix
        # that made it structurally zero would be worse than the bug it replaced.
        path = self.log(standard_rows())
        with path.open("a", encoding="utf-8") as fh:
            fh.write("\t".join(["x"] * (len(IOT23_FIELDS) + 3)) + "\n")
        _, rep = iot23.ingest(path, scenario_id="TEST-1")
        self.assertEqual(rep["read"]["data_lines_total"], 18)
        self.assertEqual(rep["read"]["rows_skipped_malformed"], 1)

    def test_a_truncated_line_is_padded_by_pandas_and_dropped_downstream(self):
        # Documented because it is NOT symmetric with the case above and the
        # asymmetry is pandas', not ours: a line with too many fields is skipped
        # and counted, but a line with too FEW is padded with NaN and read as a
        # row. So rows_skipped_malformed does not see it.
        #
        # What stops it becoming an observation is that its address columns are
        # unreadable, so no end of it is an identified device and orientation
        # drops it — counted under no_device_involved rather than as malformed.
        # The row cannot silently acquire a class; it can only vanish, and the
        # count of vanished flows is reported. Recorded in docs/limitations.md.
        path = self.log(standard_rows())
        with path.open("a", encoding="utf-8") as fh:
            fh.write("1546301900.0\ttruncated\tline\n")
        obs, rep = iot23.ingest(path, scenario_id="TEST-1")
        self.assertEqual(rep["read"]["rows_read"], 18)
        self.assertEqual(rep["read"]["rows_skipped_malformed"], 0)
        self.assertEqual(rep["orientation"]["no_device_involved_dropped"], 1)
        self.assertEqual(len(obs), 4)

    def test_columns_come_from_the_declared_header_not_a_fixed_list(self):
        # A capture produced by a different Zeek build carries extra fields. If
        # the reader assumed a column order, every column after the insertion
        # point would shift by one and nothing would raise — the numbers would
        # simply be wrong. Inserting a field mid-header proves the header is read.
        fields = list(IOT23_FIELDS)
        fields.insert(8, "some_future_zeek_field")
        rows = [dict(r, some_future_zeek_field="x") for r in standard_rows()]
        obs, _ = iot23.ingest(self.log(rows, fields=tuple(fields)),
                              scenario_id="TEST-1")
        self.assertEqual(len(obs), 4)

    def test_space_separated_label_block_is_read_not_fused(self):
        # Part of the IoT-23 corpus separates the trailing label block with
        # spaces. A tab-only parse fuses three columns into one, and the label
        # becomes unreadable — which would make every flow unmapped and every
        # window unlabelled while the run still "succeeded".
        path = self.log(standard_rows(), space_separated_label_block=True)
        obs, rep = iot23.ingest(path, scenario_id="TEST-1")
        self.assertEqual(rep["read"]["separator_used"], "whitespace_runs")
        self.assertEqual(len(obs), 4)
        self.assertNotIn(K.CLS_UNMAPPED, set(obs[K.RESEARCH_CLASS]))
        self.assertIn(K.CLS_TRADITIONAL_C2, set(obs[K.RESEARCH_CLASS]))

    def test_unset_cells_are_counted_not_silently_zeroed(self):
        # W2's four probe rows have duration, orig_bytes and resp_bytes unset.
        # Coercing them to 0.0 is right for those fields, but a capture where
        # most byte counts were unset is unusable for byte features and the only
        # way to know is to be told the number.
        _, rep = iot23.ingest(self.log(standard_rows()), scenario_id="TEST-1")
        coerced = rep["read"]["unset_cells_coerced_to_zero"]
        for fld in ("duration", "orig_bytes", "resp_bytes"):
            self.assertEqual(coerced[fld]["unset_token"], 4, msg=fld)

    def test_max_flows_marks_the_run_as_truncated(self):
        # A capped run is not a run of the capture. If the report did not say so,
        # a smoke test's numbers could be quoted as the capture's.
        obs, rep = iot23.ingest(self.log(standard_rows()), scenario_id="TEST-1",
                                max_flows=6)
        self.assertTrue(rep["truncated_by_max_flows"])
        self.assertEqual(rep["read"]["rows_read"], 6)
        self.assertEqual(len(obs), 1)


class TestRefusals(_TempCase):
    """Each of these would otherwise emit a table that looks like a result."""

    def test_a_plain_conn_log_is_refused(self):
        # Unlabelled flows cannot be given a class. Defaulting them to benign
        # would fabricate a benign population out of unknown traffic and deflate
        # the false-positive rate this whole track exists to measure.
        fields = tuple(f for f in IOT23_FIELDS
                       if f not in ("label", "detailed-label"))
        with self.assertRaises(iot23.IoT23Error) as cm:
            iot23.ingest(self.log(standard_rows(), fields=fields),
                         scenario_id="TEST-1")
        self.assertIn("label", str(cm.exception))

    def test_coarse_labels_only_is_a_warning_not_a_refusal(self):
        # Usable, but every malicious flow collapses to botnet activity with no
        # C2 distinction — so the run must not claim a C2 finding.
        fields = tuple(f for f in IOT23_FIELDS if f != "detailed-label")
        obs, _ = iot23.ingest(self.log(standard_rows(), fields=fields),
                              scenario_id="TEST-1")
        classes = set(obs[K.RESEARCH_CLASS])
        self.assertIn(K.CLS_TRADITIONAL_BOTNET, classes)
        self.assertNotIn(K.CLS_TRADITIONAL_C2, classes)

    def test_a_missing_required_zeek_field_is_refused_by_name(self):
        fields = tuple(f for f in IOT23_FIELDS if f != "conn_state")
        with self.assertRaises(iot23.IoT23Error) as cm:
            iot23.ingest(self.log(standard_rows(), fields=fields),
                         scenario_id="TEST-1")
        self.assertIn("conn_state", str(cm.exception))

    def test_a_missing_file_says_the_adapter_never_downloads(self):
        # The containment guarantee has to be legible at the point of failure,
        # or the next person's fix is to add a download.
        with self.assertRaises(zeek.ZeekLogError) as cm:
            iot23.ingest(self.tmp / "nope.log.labeled", scenario_id="TEST-1")
        self.assertIn("never downloads", str(cm.exception))

    def test_a_compressed_file_is_refused_before_parsing(self):
        # IoT-23 ships compressed, so this is the most likely first mistake.
        p = self.tmp / "conn.log.labeled.gz"
        p.write_bytes(b"\x1f\x8b\x08\x00 not really gzip")
        with self.assertRaises(zeek.ZeekLogError) as cm:
            iot23.ingest(p, scenario_id="TEST-1")
        self.assertIn("Extract it first", str(cm.exception))

    def test_a_header_with_no_fields_line_is_refused(self):
        p = self.tmp / "conn.log.labeled"
        p.write_text("#separator \\x09\n#path\tconn\n1546300800\tx\n",
                     encoding="utf-8")
        with self.assertRaises(zeek.ZeekLogError) as cm:
            iot23.ingest(p, scenario_id="TEST-1")
        self.assertIn("#fields", str(cm.exception))

    def test_a_capture_with_no_identifiable_device_is_refused(self):
        # Both ends public and local_* unset. Guessing a device would make every
        # feature a property of an arbitrary endpoint.
        rows = [row(T0 + 30 * i, **{"id.orig_h": PEER_A, "id.resp_h": PEER_B})
                for i in range(5)]
        with self.assertRaises(iot23.IoT23Error) as cm:
            iot23.ingest(self.log(rows), scenario_id="TEST-1")
        self.assertIn("--device-ip", str(cm.exception))

    def test_an_explicit_device_ip_absent_from_the_capture_is_refused(self):
        # Ignoring the flag and auto-detecting instead would silently discard the
        # operator's recorded decision.
        with self.assertRaises(iot23.IoT23Error) as cm:
            iot23.ingest(self.log(standard_rows()), scenario_id="TEST-1",
                         device_ips=["10.9.9.9"])
        self.assertIn("--device-ip", str(cm.exception))


# ===========================================================================
# Device identification
# ===========================================================================
class TestDeviceIdentification(_TempCase):
    def test_explicit_device_ip_wins_and_is_recorded_as_the_basis(self):
        _, rep = iot23.ingest(self.log(standard_rows()), scenario_id="TEST-1",
                             device_ips=[DEV])
        self.assertEqual(rep["devices"]["devices"], [DEV])
        self.assertIn("explicit", rep["devices"]["basis"])

    def test_zeek_local_fields_are_used_when_populated(self):
        rows = [dict(r, local_orig="T", local_resp="F") for r in standard_rows()]
        _, rep = iot23.ingest(self.log(rows), scenario_id="TEST-1")
        self.assertEqual(rep["devices"]["devices"], [DEV])
        self.assertIn("local_orig", rep["devices"]["basis"])

    def test_private_range_fallback_when_local_fields_are_unset(self):
        # The common case in IoT-23. The basis string must say so, because it is
        # an inference and a reader has to be able to see that it was made.
        _, rep = iot23.ingest(self.log(standard_rows()), scenario_id="TEST-1")
        self.assertEqual(rep["devices"]["devices"], [DEV])
        self.assertIn("private", rep["devices"]["basis"])

    def test_the_report_counts_flows_per_candidate_device(self):
        # A capture that yields 300 one-flow "devices" is a capture of a whole
        # network and wants an explicit --device-ip; the counts are how a reader
        # notices that before trusting per-device features.
        _, rep = iot23.ingest(self.log(standard_rows()), scenario_id="TEST-1")
        self.assertEqual(rep["devices"]["flows_originated_per_candidate"][DEV],
                         17)


# ===========================================================================
# Orientation — the swap
# ===========================================================================
class TestOrientation(unittest.TestCase):
    """Zeek writes conn.log from the originator's point of view.

    ``orig_bytes`` means "bytes the originator sent". For a flow the monitored
    device ANSWERED, that is the peer's traffic. Every byte, packet and address
    column must therefore be swapped so ``orig_*`` always means device -> peer.
    Without the swap, the two features a relay detector depends on —
    updownlink_ratio and mean_pkt_size — are inverted for precisely the
    inbound-heavy devices it is meant to catch.
    """

    def setUp(self):
        self.stats = zeek.ReadStats()

    def norm(self, rows, devices=None):
        return iot23.normalise_orientation(
            raw_frame(rows), devices or {DEV}, self.stats)

    def test_outbound_flows_are_used_as_written(self):
        flows, o = self.norm([row(T0)])
        self.assertEqual(flows.loc[0, W.F_DEVICE_ID], DEV)
        self.assertEqual(flows.loc[0, W.F_DST_IP], PEER_A)
        self.assertEqual(flows.loc[0, W.F_ORIG_BYTES], 500.0)
        self.assertEqual(flows.loc[0, W.F_RESP_BYTES], 1500.0)
        self.assertTrue(bool(flows.loc[0, W.F_OUTBOUND]))
        self.assertEqual(o.device_is_originator, 1)

    def test_responder_side_flows_are_swapped_end_for_end(self):
        # Peer opens the connection to the device and sends 1000 bytes; the
        # device answers with 2000. Device-relative, uplink is 2000.
        flows, o = self.norm([row(T0, **{
            "id.orig_h": PEER_A, "id.orig_p": 51000,
            "id.resp_h": DEV, "id.resp_p": 8080,
            "orig_bytes": 1000, "resp_bytes": 2000,
            "orig_pkts": 4, "resp_pkts": 9,
            "orig_ip_bytes": 1200, "resp_ip_bytes": 2400})])
        r = flows.loc[0]
        self.assertEqual(r[W.F_DEVICE_ID], DEV)      # device, not originator
        self.assertEqual(r[W.F_DST_IP], PEER_A)      # peer, not responder
        self.assertEqual(r[W.F_ORIG_BYTES], 2000.0)  # device -> peer
        self.assertEqual(r[W.F_RESP_BYTES], 1000.0)
        self.assertEqual(r[W.F_ORIG_PKTS], 9.0)
        self.assertEqual(r[W.F_RESP_PKTS], 4.0)
        self.assertEqual(r[W.F_ORIG_IP_BYTES], 2400.0)
        self.assertEqual(r[W.F_RESP_IP_BYTES], 1200.0)
        self.assertFalse(bool(r[W.F_OUTBOUND]))
        self.assertEqual(o.device_is_responder, 1)

    def test_the_remote_port_is_the_peers_port_after_the_swap(self):
        # dst_port must mean "the port at the far end", which for an inbound flow
        # is the peer's ephemeral source port — not the device's listening port.
        # Confusing the two would put the device's own service port into
        # distinct_dst_ports and make a quiet server look like a scanner.
        flows, _ = self.norm([row(T0, **{
            "id.orig_h": PEER_A, "id.orig_p": 51000,
            "id.resp_h": DEV, "id.resp_p": 8080})])
        self.assertEqual(flows.loc[0, W.F_DST_PORT], 51000.0)

    def test_updownlink_ratio_would_be_inverted_without_the_swap(self):
        # The concrete damage, stated as a number. A device that receives little
        # and sends much — the shape of a relay hop — has a device-relative ratio
        # of 2.0. Read as Zeek wrote it, the same flow gives 0.5: the opposite
        # end of the feature's range.
        from src.features import derive as D
        flows, _ = self.norm([row(T0 + 30 * i, **{
            "id.orig_h": PEER_A, "id.orig_p": 51000 + i, "id.resp_h": DEV,
            "id.resp_p": 8080, "orig_bytes": 1000, "resp_bytes": 2000})
            for i in range(4)])
        feats = D.derive_features(W.assign_windows(flows[W.FLOW_COLS]),
                                 source=K.SOURCE_IOT23).features
        self.assertAlmostEqual(feats["updownlink_ratio"].iloc[0], 2.0)

    def test_conn_state_is_not_swapped(self):
        # The documented approximation. conn_state describes the ORIGINATOR's
        # attempt and has no device-relative equivalent, so it is carried through
        # unchanged and failed_conn_ratio is computed over outbound flows only.
        # Recorded in docs/limitations.md.
        flows, _ = self.norm([row(T0, **{
            "id.orig_h": PEER_A, "id.resp_h": DEV, "conn_state": "S0"})])
        self.assertEqual(flows.loc[0, W.F_CONN_STATE], "S0")

    def test_lateral_flows_are_attributed_to_the_originator_and_counted(self):
        # Both ends monitored. Counted separately because on a NATed IoT capture
        # this is usually device-to-gateway traffic: if it dominates, the "peer"
        # of most flows is the router rather than anything on the internet, which
        # changes what flow_fanout means.
        flows, o = self.norm([row(T0, **{"id.orig_h": DEV, "id.resp_h": DEV2})],
                             devices={DEV, DEV2})
        self.assertEqual(o.both_ends_are_devices, 1)
        self.assertEqual(flows.loc[0, W.F_DEVICE_ID], DEV)
        self.assertTrue(bool(flows.loc[0, W.F_OUTBOUND]))

    def test_flows_involving_no_device_are_dropped_and_counted(self):
        flows, o = self.norm([
            row(T0, **{"id.orig_h": PEER_A, "id.resp_h": PEER_B}),
            row(T0 + 30),
        ])
        self.assertEqual(o.no_device_involved, 1)
        self.assertEqual(len(flows), 1)
        self.assertEqual(o.as_dict()["flows_kept"], 1)

    def test_a_capture_where_no_flow_involves_the_device_is_refused(self):
        with self.assertRaises(iot23.IoT23Error):
            self.norm([row(T0, **{"id.orig_h": PEER_A, "id.resp_h": PEER_B})])

    def test_the_responder_side_fraction_is_reported(self):
        # Six of eleven derivable features are outbound-only. A capture that is
        # mostly responder-side leaves them near-empty, and the reader needs the
        # number before interpreting any of them.
        _, o = self.norm(
            [row(T0)] + [row(T0 + 30 * (i + 1),
                             **{"id.orig_h": PEER_A, "id.resp_h": DEV})
                         for i in range(3)])
        self.assertAlmostEqual(o.as_dict()["responder_side_fraction"], 0.75)

    def test_an_unreadable_timestamp_is_dropped_not_turned_into_1970(self):
        # to_numeric with fill=0.0 would make this epoch 0 — a valid-LOOKING
        # timestamp that creates a window 56 years before the capture and gets
        # silently included. NaN, then dropped, then counted.
        flows, _ = self.norm([row(T0), dict(row(T0 + 30), ts="-"),
                              row(T0 + 60)])
        self.assertEqual(len(flows), 2)
        self.assertEqual(
            self.stats.coerced_cells["ts_unparseable_rows_dropped"], 1)
        self.assertTrue((flows[W.F_TS].dt.year == 2019).all())

    def test_a_capture_of_only_unreadable_timestamps_is_refused(self):
        with self.assertRaises(iot23.IoT23Error):
            self.norm([dict(row(T0), ts="-"), dict(row(T0 + 30), ts="nan")])

    def test_the_flow_table_it_produces_satisfies_the_contract(self):
        # The adapter's output is the input to windowing, which validates. If the
        # two ever disagree the failure surfaces here, in the module that caused
        # it, rather than three layers downstream.
        flows, _ = self.norm(standard_rows())
        W.validate_flow_table(flows[W.FLOW_COLS])


# ===========================================================================
# Labels and windows
# ===========================================================================
class TestWindowLabels(_TempCase):
    def setUp(self):
        super().setUp()
        self.obs, self.rep = iot23.ingest(self.log(standard_rows()),
                                          scenario_id="TEST-1")
        self.by_win = self.obs.set_index(K.WINDOW_START)

    def _flags(self, window_start) -> dict[str, list[str]]:
        raw = self.by_win.loc[str(window_start.isoformat()), K.QUALITY_FLAGS] \
            if str(window_start.isoformat()) in self.by_win.index else None
        if raw is None:
            row_ = self.obs[self.obs[K.WINDOW_START] == window_start]
            raw = row_[K.QUALITY_FLAGS].iloc[0]
        out: dict[str, list[str]] = {}
        for part in str(raw).split(K.FLAG_SEP):
            if not part:
                continue
            name, _, args = part.partition(K.FLAG_ARG_SEP)
            out[name] = args.split(K.FLAG_LIST_SEP) if args else []
        return out

    def test_four_windows_in_grid_order(self):
        self.assertEqual(list(self.obs[K.WINDOW_START]), WIN)

    def test_an_all_benign_window_is_benign(self):
        self.assertEqual(self.obs[K.RESEARCH_CLASS].iloc[0], K.CLS_BENIGN_REAL)

    def test_one_c2_flow_among_six_makes_the_window_c2(self):
        # ANY, not majority. A detector that misses a compromised device because
        # only one of its flows was C&C has missed the device.
        self.assertEqual(self.obs[K.RESEARCH_CLASS].iloc[1],
                         K.CLS_TRADITIONAL_C2)

    def test_the_scan_window_is_botnet_activity(self):
        self.assertEqual(self.obs[K.RESEARCH_CLASS].iloc[2],
                         K.CLS_TRADITIONAL_BOTNET)

    def test_the_mixed_window_carries_the_malicious_fraction(self):
        # ANY-semantics makes a 17%-malicious window and a 100%-malicious window
        # share one label. This flag is what pays that back, so a reader can tell
        # them apart in the CSV without re-running the ingest.
        flags = self._flags(WIN[1])
        self.assertIn(K.FLAG_MIXED_LABEL_WINDOW, flags)
        self.assertEqual(flags[K.FLAG_MIXED_LABEL_WINDOW], ["0.1667"])

    def test_an_unambiguous_window_is_not_flagged_mixed(self):
        for i in (0, 2, 3):
            self.assertNotIn(K.FLAG_MIXED_LABEL_WINDOW, self._flags(WIN[i]),
                             msg=str(WIN[i]))

    def test_original_label_shows_the_source_spelling_of_the_finding(self):
        # Not a count and not our class name: the words the dataset used, so a
        # reviewer can check our interpretation against them.
        self.assertEqual(self.obs[K.ORIGINAL_LABEL].iloc[1],
                         "Malicious|C&C-HeartBeat")
        self.assertEqual(self.obs[K.ORIGINAL_LABEL].iloc[0], "Benign")

    def test_no_row_carries_a_track_b_class(self):
        # The absolute rule, asserted on the adapter's actual output and not only
        # on the mapping function. IoT-23 predates blockchain-anchored C2; a
        # Track B class here would be fabricated real-world evidence.
        self.assertFalse(set(self.obs[K.RESEARCH_CLASS]) & set(K.TRACK_B_CLASSES))

    def test_an_unmapped_flow_does_not_take_a_labelled_window_with_it(self):
        rows = standard_rows()
        rows[0] = dict(rows[0], label="Malicious",
                       detailed_label="SomethingNobodyMapped")
        rows[0]["detailed-label"] = "SomethingNobodyMapped"
        rows[0].pop("detailed_label", None)
        obs, _ = iot23.ingest(self.log(rows, name="b.log.labeled"),
                              scenario_id="TEST-1")
        # W0 still holds five confidently benign flows, so it is not unmapped.
        self.assertNotEqual(obs[K.RESEARCH_CLASS].iloc[0], K.CLS_UNMAPPED)

    def test_a_wholly_unmapped_window_is_unmapped_and_flagged(self):
        # Retained for audit, excluded from training. CLS_UNMAPPED is a data
        # state, not a class: nothing trains on it and nothing predicts it.
        rows = [row(T0 + 30 * i, label="Malicious",
                    **{"detailed-label": "NoSuchLabel"}) for i in range(4)]
        obs, rep = iot23.ingest(self.log(rows, name="c.log.labeled"),
                                scenario_id="TEST-1")
        self.assertEqual(obs[K.RESEARCH_CLASS].iloc[0], K.CLS_UNMAPPED)
        self.assertIn(K.FLAG_UNMAPPED_LABEL, str(obs[K.QUALITY_FLAGS].iloc[0]))
        self.assertEqual(rep["observations"]["unmapped_rows"], 1)

        from src.schema import trainable
        self.assertEqual(len(trainable(obs)), 0)


# ===========================================================================
# The observation table
# ===========================================================================
class TestObservationTable(_TempCase):
    def setUp(self):
        super().setUp()
        self.obs, self.rep = iot23.ingest(self.log(standard_rows()),
                                          scenario_id="CTU-IoT-TEST-1")

    def test_it_passes_the_schema_validator(self):
        from src.schema import assert_valid
        assert_valid(self.obs)

    def test_the_five_unavailable_features_are_nan_everywhere(self):
        # NOT 0.0. A resolution_entropy of 0.0 asserts "this device resolved one
        # name repeatedly", which is a measurement; NaN says "this source cannot
        # see name resolution at all", which is the truth.
        for col in K.unavailable_features(K.SOURCE_IOT23):
            self.assertTrue(self.obs[col].isna().all(), msg=col)

    def test_the_derivable_features_are_actually_derived(self):
        # The complement of the test above: if everything were NaN the adapter
        # would be trivially "correct" and useless.
        self.assertAlmostEqual(self.obs["scan_rate"].iloc[0], 6 / 5)
        self.assertAlmostEqual(self.obs["distinct_dst_ports"].iloc[2], 4.0)
        self.assertAlmostEqual(self.obs["failed_conn_ratio"].iloc[2], 1.0)
        self.assertAlmostEqual(self.obs["beacon_interval"].iloc[0], 30.0)
        self.assertAlmostEqual(self.obs["beacon_jitter"].iloc[0], 0.0)
        self.assertAlmostEqual(self.obs["mean_pkt_size"].iloc[2], 40.0)

    def test_the_probe_window_has_no_bidirectional_duration(self):
        # 0.0 and NaN, deliberately different, for the two features that both
        # "have nothing to measure" here:
        #   bidir_flow_duration is 0.0 because the device demonstrably held no
        #     two-way conversation — an observation about four connections that
        #     were refused.
        #   updownlink_ratio is NaN because neither direction moved any payload,
        #     so the ratio has no denominator. 0.0 would assert "this device
        #     received but did not send", which is not what happened.
        self.assertEqual(self.obs["bidir_flow_duration"].iloc[2], 0.0)
        self.assertTrue(math.isnan(self.obs["updownlink_ratio"].iloc[2]))

    def test_provenance_marks_every_row_as_a_real_capture(self):
        self.assertTrue(
            (self.obs[K.CAPTURE_PROVENANCE] == K.PROV_REAL_CAPTURE).all())
        self.assertTrue((self.obs[K.SOURCE_DATASET] == K.SOURCE_IOT23).all())
        self.assertTrue((self.obs[K.SCENARIO_ID] == "CTU-IoT-TEST-1").all())

    def test_device_ids_are_the_device_not_the_peer(self):
        self.assertEqual(set(self.obs[K.DEVICE_ID]), {DEV})

    def test_the_proxy_features_are_flagged_as_proxies(self):
        # rpc_endpoint_ratio and login_burst_count exist on this source only as
        # port-based stand-ins. Naming them proxies in the row is what stops a
        # port-8545 hit being read as an observed RPC call.
        for name in K.proxy_features(K.SOURCE_IOT23):
            self.assertIn(name, str(self.obs[K.QUALITY_FLAGS].iloc[0]))

    def test_observation_ids_are_unique_and_stable(self):
        again, _ = iot23.ingest(self.log(standard_rows(), name="again.labeled"),
                                scenario_id="CTU-IoT-TEST-1")
        self.assertEqual(self.obs[K.OBSERVATION_ID].nunique(), len(self.obs))
        self.assertEqual(list(again[K.OBSERVATION_ID]),
                         list(self.obs[K.OBSERVATION_ID]))


# ===========================================================================
# The report
# ===========================================================================
class TestReport(_TempCase):
    def setUp(self):
        super().setUp()
        self.obs, self.rep = iot23.ingest(self.log(standard_rows()),
                                          scenario_id="TEST-1")

    def test_it_names_the_features_this_source_cannot_provide(self):
        # The report is what a reader has instead of the code. If it did not name
        # these, a NaN column would look like a bug rather than a property of the
        # dataset.
        self.assertEqual(self.rep["features_unavailable_for_this_source"],
                         K.unavailable_features(K.SOURCE_IOT23))
        self.assertEqual(self.rep["features_that_are_proxies"],
                         K.proxy_features(K.SOURCE_IOT23))

    def test_missing_feature_counts_are_a_range_not_one_number(self):
        # The count is NOT constant per row, which is why the report gives a
        # range. Two separate causes stack:
        #
        #   FLOOR (every row): the five features this source cannot provide, plus
        #     rpc_endpoint_ratio — undefined here because no flow in this capture
        #     goes to a resolver or JSON-RPC port, so the ratio has no
        #     denominator. Six, not five.
        #   ABOVE THE FLOOR: windows whose beacon interval was unmeasurable (the
        #     single-flow window has no inter-arrival gap to measure).
        #
        # Reporting only the floor would hide the second cause entirely, and a
        # reader comparing two captures would not see that one had far more
        # unmeasurable windows than the other.
        o = self.rep["observations"]
        self.assertGreaterEqual(o["features_missing_min"],
                                len(K.unavailable_features(K.SOURCE_IOT23)))
        self.assertEqual(o["features_missing_min"], 6)
        self.assertEqual(o["features_missing_max"], 8)
        self.assertGreater(o["features_missing_max"], o["features_missing_min"])
        self.assertLessEqual(o["features_missing_median"],
                             o["features_missing_max"])

    def test_the_sixth_missing_feature_is_the_undefined_rpc_proxy(self):
        # Named explicitly, because "6 of 16 missing" in a report is only
        # interpretable if a reader can find out which six. A capture with no
        # DNS traffic at all leaves the resolver-choice proxy with no denominator
        # in every window — which is the honest result, not a defect.
        self.assertTrue(self.obs["rpc_endpoint_ratio"].isna().all())
        self.assertEqual(
            self.rep["windowing"]["rpc_endpoint_ratio_undefined_fraction"], 1.0)

    def test_it_reports_the_class_counts_and_mixed_window_count(self):
        o = self.rep["observations"]
        self.assertEqual(o["rows"], 4)
        self.assertEqual(o["class_counts"][K.CLS_BENIGN_REAL], 2)
        self.assertEqual(o["class_counts"][K.CLS_TRADITIONAL_C2], 1)
        self.assertEqual(o["class_counts"][K.CLS_TRADITIONAL_BOTNET], 1)
        self.assertEqual(o["mixed_label_windows"], 1)

    def test_it_reports_the_inbound_share_from_the_coverage_report(self):
        self.assertEqual(self.rep["windowing"]["inbound_flow_fraction"], 0.0)
        self.assertEqual(self.rep["windowing"]["windows"], 4)

    def test_it_carries_the_real_data_provenance_note(self):
        # Every artefact gets the same wording. A softer note on one output than
        # another is how a synthetic number ends up quoted as a real one.
        self.assertTrue(self.rep["provenance_note"])

    def test_the_whole_report_is_json_serialisable(self):
        # It is written to results/ at the very end of a long run; a numpy scalar
        # in here fails json.dump after all the work is done.
        json.dumps(self.rep, default=None)


# ===========================================================================
# CLI
# ===========================================================================
class TestCLI(_TempCase):
    def test_it_writes_observations_and_a_report(self):
        src = self.log(standard_rows())
        out = self.tmp / "out" / "track_a.csv"
        rc = iot23.main(["--input", str(src), "--scenario-id", "TEST-1",
                         "--device-ip", DEV, "--out", str(out)])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())
        self.assertTrue(out.with_suffix(".report.json").exists())

        # Read back through the project's own reader, not read_csv: the point of
        # write_observations is that the file round-trips through the schema.
        from src.schema import read_observations
        back = read_observations(out)
        self.assertEqual(len(back), 4)
        self.assertEqual(list(back.columns), K.ALL_COLS)
        self.assertEqual(list(back[K.WINDOW_START]), WIN)

        rep = json.loads(out.with_suffix(".report.json").read_text("utf-8"))
        self.assertEqual(rep["scenario_id"], "TEST-1")

    def test_it_exits_nonzero_on_a_missing_file_without_a_traceback(self):
        rc = iot23.main(["--input", str(self.tmp / "nope"),
                         "--scenario-id", "TEST-1"])
        self.assertEqual(rc, 2)

    def test_it_exits_nonzero_on_a_plain_conn_log(self):
        fields = tuple(f for f in IOT23_FIELDS
                       if f not in ("label", "detailed-label"))
        src = self.log(standard_rows(), fields=fields)
        rc = iot23.main(["--input", str(src), "--scenario-id", "TEST-1",
                         "--out", str(self.tmp / "x.csv")])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
