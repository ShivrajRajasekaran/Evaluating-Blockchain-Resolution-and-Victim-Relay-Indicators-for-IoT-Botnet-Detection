"""
tests/test_operational_csv.py — the parametrised flow-CSV product adapter.

operational_csv turns three flavours of local flow export (a rich bidirectional
CSV, classic NetFlow, and a firewall connection log) into the SAME unlabelled,
review-only observation schema the Zeek product adapter produces. It does that
by normalising every row into a Zeek-conn-shaped frame and reusing the project's
one device-orientation implementation, so these tests concentrate on what is new
here rather than re-testing orientation:

  * Each format is accepted from its own column vocabulary, and produces an
    all-unmapped, unlabelled frame — never a class.
  * The column contract is enforced: a file missing a required column is REFUSED
    with the list of what it needed, rather than read with columns guessed.
  * A --column-map is honoured for non-standard exports, and rejected when it
    points at a column that is not there or a field that does not exist.
  * Per-source availability matches the schema: the five flow-gaps are NaN for
    every format, and each format's declared proxies are flagged on every row.
  * The firewall action -> connection-state mapping actually reaches the
    features: a log of denied connections yields a non-zero failed_conn_ratio.
  * Labels never enter the pipeline. A stray "label" column in the CSV is not in
    the vocabulary, is never read, and cannot ride into the output as a class.

Timestamps are exercised in all three shapes a real export uses — epoch seconds,
epoch milliseconds, and ISO-8601 — because a millisecond epoch read as seconds
would place every window 50 000 years in the future and silently corrupt the
window grid.
"""
from __future__ import annotations

import csv
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from src.config import operational_data_note
from src.ingest import operational_csv as oc
from src.schema import assert_valid, columns as K, read_observations

# A private device auto-detected as the monitored host, talking to two external
# peers. The peers must be globally-routable literals: Python 3.13's
# ipaddress.is_private treats the RFC-5737 documentation ranges (198.51.100/24,
# 203.0.113/24) as private, which would make them look like a second and third
# device rather than external hosts. These are only ever strings in a CSV
# fixture — the adapter does no network I/O, so nothing is ever contacted.
DEVICE = "192.168.10.50"
PEER1 = "8.8.8.8"
PEER2 = "1.1.1.1"
# A 300-second window boundary (300 * 5_666_667), so a short run of flows lands
# in exactly one window and per-window assertions are deterministic.
T0 = 1_700_000_100


# ---------------------------------------------------------------------------
# Fixtures — one row builder per format, plus a CSV writer.
# ---------------------------------------------------------------------------
def write_csv(path: Path, rows: list[dict], *, header: list[str] | None = None
              ) -> Path:
    header = header or list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in rows:
            w.writerow([r.get(h, "") for h in header])
    return path


def flow_rows(n: int = 6, *, peers=(PEER1, PEER2), dport: int = 443,
              state: str = "SF", src_ip: str = DEVICE, t0: int = T0,
              gap: int = 30, ts_fmt: str = "epoch") -> list[dict]:
    """Rich bidirectional flow rows (op_flow_csv): both directions + a state."""
    rows = []
    for i in range(n):
        rows.append({
            "ts": _stamp(t0 + gap * i, ts_fmt),
            "src_ip": src_ip,
            "src_port": str(44000 + i),
            "dst_ip": peers[i % len(peers)],
            "dst_port": str(dport),
            "proto": "tcp",
            "duration": "10.0",
            "src_bytes": "500",
            "dst_bytes": "1500",
            "src_pkts": "6",
            "dst_pkts": "8",
            "conn_state": state,
        })
    return rows


def netflow_rows(n: int = 6, *, t0: int = T0, gap: int = 30) -> list[dict]:
    """Unidirectional NetFlow rows: one total, numeric protocol, no state."""
    return [{
        "ts": str(t0 + gap * i),
        "src_ip": DEVICE,
        "src_port": str(44000 + i),
        "dst_ip": PEER1,
        "dst_port": "443",
        "proto": "6",                 # numeric protocol -> mapped to tcp
        "bytes": "1000",
        "pkts": "10",
    } for i in range(n)]


def firewall_rows(n: int = 6, *, t0: int = T0, gap: int = 30,
                  deny_every: int = 2) -> list[dict]:
    """Firewall rows: an allow/deny action instead of a connection state.

    deny_every=0 means never deny (used to check the all-allow floor); note a
    naive ``i % deny_every == 0`` would still deny row 0, so the guard is
    explicit."""
    return [{
        "ts": str(t0 + gap * i),
        "src_ip": DEVICE,
        "dst_ip": PEER1,
        "dst_port": "443",
        "proto": "tcp",
        "action": "deny" if (deny_every and i % deny_every == 0) else "allow",
        "bytes": "1200",
        "pkts": "10",
    } for i in range(n)]


def _stamp(epoch: int, fmt: str) -> str:
    if fmt == "epoch":
        return str(epoch)
    if fmt == "millis":
        return str(epoch * 1000)
    if fmt == "iso":
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    raise ValueError(fmt)


# The three formats and a builder for each, for the parity sweeps.
FORMATS = (
    (K.SOURCE_OP_FLOW_CSV, flow_rows),
    (K.SOURCE_OP_NETFLOW, netflow_rows),
    (K.SOURCE_OP_FIREWALL, firewall_rows),
)


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def ingest(self, source, rows, *, header=None, name="flows.csv", **kw):
        path = write_csv(self.tmp / name, rows, header=header)
        return oc.ingest(path, source=source, scenario_id="op-csv-01", **kw)


class TestEachFormatAccepted(_Base):
    """Every format is read into a valid, all-unmapped, review-only frame."""

    def test_all_formats_produce_unmapped_observations(self):
        for source, build in FORMATS:
            with self.subTest(source=source):
                obs, report = self.ingest(source, build(), name=f"{source}.csv")
                assert_valid(obs)
                self.assertGreater(len(obs), 0)
                self.assertEqual(report["source_dataset"], source)
                self.assertEqual(report["adapter"], "operational_csv")
                # Unlabelled by nature: unmapped class, empty label, the
                # operational confidence, but a REAL capture provenance.
                self.assertTrue((obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())
                self.assertTrue((obs[K.ORIGINAL_LABEL] == "").all())
                self.assertTrue(
                    (obs[K.LABEL_CONFIDENCE] == K.CONF_UNLABELLED).all())
                self.assertTrue(
                    (obs[K.CAPTURE_PROVENANCE] == K.PROV_REAL_CAPTURE).all())
                self.assertTrue(
                    (obs[K.LABEL_BINARY] == K.LABEL_BINARY_UNMAPPED).all())
                # Every row flagged unmapped, and the report omits any class
                # count — there is no ground truth to count.
                for flags in obs[K.QUALITY_FLAGS]:
                    self.assertIn(K.FLAG_UNMAPPED_LABEL, K.parse_flags(flags))
                self.assertTrue(report["observations"]["all_unmapped"])
                self.assertNotIn("class_counts", report["observations"])

    def test_observation_id_carries_source(self):
        for source, build in FORMATS:
            with self.subTest(source=source):
                obs, _ = self.ingest(source, build(), name=f"{source}.csv")
                self.assertTrue(
                    obs[K.OBSERVATION_ID].str.startswith(source + "|").all())


class TestAvailabilityParity(_Base):
    """Each format's NaN floor and proxy set match schema/columns.py exactly."""

    def test_unavailable_features_are_nan_for_every_format(self):
        for source, build in FORMATS:
            with self.subTest(source=source):
                obs, _ = self.ingest(source, build(), name=f"{source}.csv")
                unavailable = K.unavailable_features(source)
                for feat in unavailable:
                    self.assertTrue(obs[feat].isna().all(),
                                    f"{feat} must be NaN for {source}")
                # The unavailable set is the floor; rpc/beacon NaNs can lift the
                # per-row count above it, so this is >=, never ==.
                self.assertGreaterEqual(int(obs[K.N_FEATURES_MISSING].min()),
                                        len(unavailable))

    def test_proxy_features_flagged_on_every_row(self):
        for source, build in FORMATS:
            with self.subTest(source=source):
                obs, _ = self.ingest(source, build(), name=f"{source}.csv")
                proxies = set(K.proxy_features(source))
                self.assertTrue(proxies, f"{source} should declare proxies")
                for flags in obs[K.QUALITY_FLAGS]:
                    flagged = set(K.parse_flags(flags).get(
                        K.FLAG_PROXY_FEATURES, []))
                    self.assertEqual(flagged, proxies)

    def test_netflow_has_more_proxies_than_flow_csv(self):
        # The honesty gradient the schema encodes: a NetFlow export approximates
        # strictly more than a rich flow CSV, and a firewall log more still.
        self.assertLess(len(K.proxy_features(K.SOURCE_OP_FLOW_CSV)),
                        len(K.proxy_features(K.SOURCE_OP_NETFLOW)))
        self.assertLess(len(K.proxy_features(K.SOURCE_OP_NETFLOW)),
                        len(K.proxy_features(K.SOURCE_OP_FIREWALL)))


class TestFirewallActionMapping(_Base):
    """A denied connection is a failed one, and the feature must show it."""

    def test_deny_actions_raise_failed_conn_ratio(self):
        # Three of six flows denied -> REJ (a configured failed state) -> the
        # device's outbound failure ratio is 0.5, computed as a proxy.
        obs, _ = self.ingest(K.SOURCE_OP_FIREWALL,
                             firewall_rows(n=6, deny_every=2))
        self.assertEqual(len(obs), 1)                 # all six in one window
        ratio = obs["failed_conn_ratio"].iloc[0]
        self.assertFalse(pd.isna(ratio))
        self.assertAlmostEqual(ratio, 0.5, places=6)

    def test_all_allow_gives_zero_failed_ratio(self):
        obs, _ = self.ingest(K.SOURCE_OP_FIREWALL,
                             firewall_rows(n=6, deny_every=0))  # never deny
        self.assertAlmostEqual(obs["failed_conn_ratio"].iloc[0], 0.0, places=6)


class TestTimestampFormats(_Base):
    """Epoch seconds, epoch milliseconds and ISO-8601 all land in 2023."""

    def test_all_timestamp_formats_parse_to_same_window(self):
        for fmt in ("epoch", "millis", "iso"):
            with self.subTest(fmt=fmt):
                obs, _ = self.ingest(K.SOURCE_OP_FLOW_CSV,
                                     flow_rows(ts_fmt=fmt), name=f"{fmt}.csv")
                self.assertGreater(len(obs), 0)
                years = pd.to_datetime(obs[K.WINDOW_START]).dt.year.unique()
                self.assertEqual(list(years), [2023],
                                 f"{fmt} timestamp mis-scaled: {years}")


class TestColumnContract(_Base):
    """Missing required columns are refused; the message lists what was needed."""

    def test_flow_csv_missing_state_refused(self):
        rows = flow_rows()
        header = [c for c in rows[0] if c != "conn_state"]
        with self.assertRaises(oc.OperationalIngestError) as cm:
            self.ingest(K.SOURCE_OP_FLOW_CSV, rows, header=header)
        self.assertIn("op_flow_csv", str(cm.exception))

    def test_flow_csv_missing_dst_bytes_refused(self):
        rows = flow_rows()
        header = [c for c in rows[0] if c != "dst_bytes"]
        with self.assertRaises(oc.OperationalIngestError):
            self.ingest(K.SOURCE_OP_FLOW_CSV, rows, header=header)

    def test_netflow_missing_dst_port_refused(self):
        rows = netflow_rows()
        header = [c for c in rows[0] if c != "dst_port"]
        with self.assertRaises(oc.OperationalIngestError):
            self.ingest(K.SOURCE_OP_NETFLOW, rows, header=header)

    def test_firewall_missing_action_refused(self):
        rows = firewall_rows()
        header = [c for c in rows[0] if c != "action"]
        with self.assertRaises(oc.OperationalIngestError):
            self.ingest(K.SOURCE_OP_FIREWALL, rows, header=header)

    def test_unknown_source_refused(self):
        with self.assertRaises(oc.OperationalIngestError):
            self.ingest("op_smtp", flow_rows())

    def test_empty_file_refused(self):
        with self.assertRaises(oc.OperationalIngestError):
            self.ingest(K.SOURCE_OP_FLOW_CSV, [], header=list(flow_rows()[0]))

    def test_no_identifiable_device_refused(self):
        # Both ends public: identify_devices raises IoT23Error, which must reach
        # the caller as the product's own error type, not the borrowed one.
        rows = flow_rows(src_ip=PEER2)     # public -> public
        with self.assertRaises(oc.OperationalIngestError):
            self.ingest(K.SOURCE_OP_FLOW_CSV, rows)


class TestColumnMap(_Base):
    """A --column-map maps non-standard headers; misuse is rejected."""

    def _weird(self, rows):
        # Prefix every canonical name so nothing resolves via the alias table.
        rename = {"ts": "x_ts", "src_ip": "x_src", "src_port": "x_srcport",
                  "dst_ip": "x_dst", "dst_port": "x_dstport", "proto": "x_proto",
                  "duration": "x_dur", "src_bytes": "x_bo", "dst_bytes": "x_bi",
                  "src_pkts": "x_po", "dst_pkts": "x_pi", "conn_state": "x_cs"}
        return [{rename[k]: v for k, v in r.items()} for r in rows], rename

    def test_column_map_resolves_nonstandard_headers(self):
        rows, rename = self._weird(flow_rows())
        cmap = {canon: rename[canon] if canon != "state" else rename["conn_state"]
                for canon in ("ts", "src_ip", "src_port", "dst_ip", "dst_port",
                              "proto", "duration", "src_bytes", "dst_bytes",
                              "src_pkts", "dst_pkts")}
        cmap["state"] = rename["conn_state"]
        obs, report = self.ingest(K.SOURCE_OP_FLOW_CSV, rows, column_map=cmap)
        assert_valid(obs)
        self.assertGreater(len(obs), 0)
        self.assertTrue((obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())
        # The report records that the mapping was used, for auditability.
        self.assertIn("--column-map", report["resolved_columns"]["src_ip"])

    def test_column_map_without_map_is_refused(self):
        # The same weird file, no map: unresolvable, so refused rather than
        # read with columns guessed.
        rows, _ = self._weird(flow_rows())
        with self.assertRaises(oc.OperationalIngestError):
            self.ingest(K.SOURCE_OP_FLOW_CSV, rows)

    def test_column_map_to_absent_column_refused(self):
        with self.assertRaises(oc.OperationalIngestError):
            self.ingest(K.SOURCE_OP_FLOW_CSV, flow_rows(),
                        column_map={"src_ip": "NoSuchColumn"})

    def test_column_map_unknown_field_refused(self):
        with self.assertRaises(oc.OperationalIngestError):
            self.ingest(K.SOURCE_OP_FLOW_CSV, flow_rows(),
                        column_map={"not_a_field": "src_ip"})


class TestLabelsNeverEnter(_Base):
    """A CSV label column is not in the vocabulary and cannot leak as a class."""

    def test_stray_label_column_is_ignored(self):
        rows = flow_rows()
        for r in rows:
            r["label"] = "Malicious"          # attacker-controlled, ignored
        obs, _ = self.ingest(K.SOURCE_OP_FLOW_CSV, rows)
        self.assertTrue((obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())
        self.assertTrue((obs[K.ORIGINAL_LABEL] == "").all())
        haystack = "\n".join(
            obs.astype(str).apply(lambda col: "␟".join(col)).tolist())
        self.assertNotIn("Malicious", haystack)


class TestExplicitDevice(_Base):
    """--device-ip is honoured, matching the Zeek adapter and Track A."""

    def test_explicit_device_ip(self):
        obs, report = self.ingest(K.SOURCE_OP_FLOW_CSV, flow_rows(),
                                  device_ips=[DEVICE])
        self.assertEqual(report["devices"]["basis"], "explicit --device-ip")
        self.assertIn(DEVICE, report["devices"]["devices"])
        self.assertTrue((obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())


class TestReportProvenance(_Base):
    """The report carries the operational note and marks findings review-only."""

    def test_provenance_and_detection_notes(self):
        for source, build in FORMATS:
            with self.subTest(source=source):
                _, report = self.ingest(source, build(), name=f"{source}.csv")
                self.assertEqual(report["provenance_note"],
                                 operational_data_note())
                self.assertIn("UNLABELLED", report["provenance_note"])
                self.assertIn("review-only", report["detection_note"])
                self.assertIn("not ML-validated", report["detection_note"])
                # The CSV report labels its own separator honestly, not "tab".
                self.assertEqual(report["read"]["separator_used"], "comma")


class TestCLI(_Base):
    """main() writes a re-readable CSV and report, and returns the right codes."""

    def test_cli_writes_valid_csv(self):
        path = write_csv(self.tmp / "nf.csv", netflow_rows())
        out = self.tmp / "out.csv"
        rc = oc.main(["--input", str(path), "--source", K.SOURCE_OP_NETFLOW,
                      "--scenario-id", "op-cli-01", "--out", str(out)])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())
        self.assertTrue(out.with_suffix(".report.json").exists())
        reread = read_observations(out)
        assert_valid(reread)
        self.assertTrue((reread[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())

    def test_cli_bad_input_returns_2(self):
        rc = oc.main(["--input", str(self.tmp / "nope.csv"), "--source",
                      K.SOURCE_OP_NETFLOW, "--scenario-id", "op-cli-02",
                      "--out", str(self.tmp / "out.csv")])
        self.assertEqual(rc, 2)

    def test_cli_bad_column_map_json_returns_2(self):
        path = write_csv(self.tmp / "f.csv", flow_rows())
        rc = oc.main(["--input", str(path), "--source", K.SOURCE_OP_FLOW_CSV,
                      "--scenario-id", "op-cli-03", "--column-map", "{not json",
                      "--out", str(self.tmp / "out.csv")])
        self.assertEqual(rc, 2)

    def test_cli_unknown_source_rejected_by_argparse(self):
        path = write_csv(self.tmp / "f.csv", flow_rows())
        with self.assertRaises(SystemExit):
            oc.main(["--input", str(path), "--source", "op_smtp",
                     "--scenario-id", "op-cli-04"])

    def test_default_out_sanitises_scenario(self):
        out = oc._default_out(K.SOURCE_OP_NETFLOW, "a/b:c d")
        self.assertNotIn("/", out.name)
        self.assertNotIn(":", out.name)
        self.assertTrue(out.name.startswith(K.SOURCE_OP_NETFLOW + "_"))


if __name__ == "__main__":
    unittest.main()
