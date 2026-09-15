"""
tests/test_operational_zeek.py — the product Zeek adapter, end to end.

This adapter is the Track-A pipeline with labels removed, so the tests here
concentrate on the two things that removal must get exactly right:

  * A plain conn.log (no label columns) is ACCEPTED, where the research adapter
    refuses it. Operational telemetry is unlabelled by nature.
  * Labels, if the file happens to carry them, are IGNORED and never leak. Every
    window comes out research_class=unmapped with an empty original_label, and no
    label string reaches the observation frame. An attacker-supplied label must
    not be able to ride into the analyst UI dressed as a confirmed class.

The device-relative orientation transform is NOT re-tested here: this adapter
imports it verbatim from the IoT-23 adapter, whose suite exercises it in depth.
What is tested is that the wiring reuses it correctly and that the label removal
is complete.

The Zeek-log fixtures (real TSV text, declared #fields header and all) are
shared with tests/test_iot23_adapter.py rather than re-implemented, so both
adapters are tested against byte-identical capture files.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import operational_data_note
from src.ingest import operational_zeek as op
from src.ingest import zeek
from src.schema import assert_valid, columns as K, read_observations

from tests.test_iot23_adapter import (
    DEV, PEER_A, PEER_B, T0, IOT23_FIELDS, row, write_log, standard_rows,
)

# A plain conn.log: the same fields a real Zeek install writes, minus IoT-23's
# appended label block. This is the operational norm and the case the research
# adapter refuses.
PLAIN_FIELDS: tuple[str, ...] = tuple(
    f for f in IOT23_FIELDS if f not in ("label", "detailed-label"))

# Label strings present in standard_rows(). None of these may appear in an
# operational observation frame.
_LEAKABLE_LABELS = ("Malicious", "C&C-HeartBeat", "PartOfAHorizontalPortScan",
                    "Benign")


class _Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def ingest_rows(self, rows, *, fields=PLAIN_FIELDS, name="conn.log",
                    **kw):
        path = write_log(self.tmp / name, rows, fields=fields)
        return op.ingest(path, scenario_id="op-test-01", **kw)


class TestPlainConnLogAccepted(_Base):
    """The defining difference from Track A: no label column is required."""

    def test_plain_connlog_produces_valid_observations(self):
        obs, report = self.ingest_rows(standard_rows())
        # Would raise if invalid; assert_valid is also called inside ingest, but
        # re-checking the returned frame guards against a future refactor that
        # drops the internal call.
        assert_valid(obs)
        self.assertGreater(len(obs), 0)
        self.assertEqual(report["adapter"], "operational_zeek")
        self.assertEqual(report["source_dataset"], K.SOURCE_OP_ZEEK)

    def test_every_window_is_unmapped_and_unlabelled(self):
        obs, _ = self.ingest_rows(standard_rows())
        self.assertTrue((obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())
        self.assertTrue((obs[K.ORIGINAL_LABEL] == "").all())
        self.assertTrue((obs[K.LABEL_CONFIDENCE] == K.CONF_UNLABELLED).all())
        self.assertTrue(
            (obs[K.CAPTURE_PROVENANCE] == K.PROV_REAL_CAPTURE).all())
        self.assertTrue((obs[K.SOURCE_DATASET] == K.SOURCE_OP_ZEEK).all())
        # label_binary for unmapped rows is the sentinel, never a 0/1 class.
        self.assertTrue((obs[K.LABEL_BINARY] == K.LABEL_BINARY_UNMAPPED).all())

    def test_unmapped_flag_and_no_class_section_in_report(self):
        obs, report = self.ingest_rows(standard_rows())
        # Every row flagged unmapped so a reader cannot mistake it for a class.
        for flags in obs[K.QUALITY_FLAGS]:
            self.assertIn(K.FLAG_UNMAPPED_LABEL, K.parse_flags(flags))
        # The report honestly omits class/mixed-label sections — there is no
        # ground truth to count.
        self.assertTrue(report["observations"]["all_unmapped"])
        self.assertNotIn("class_counts", report["observations"])

    def test_observation_id_carries_operational_source(self):
        obs, _ = self.ingest_rows(standard_rows())
        self.assertTrue(
            obs[K.OBSERVATION_ID].str.startswith(K.SOURCE_OP_ZEEK + "|").all())


class TestLabelsIgnored(_Base):
    """A labelled file is accepted, but its labels are dropped, not honoured."""

    def test_labels_present_are_reported_as_ignored(self):
        _, report = self.ingest_rows(standard_rows(), fields=IOT23_FIELDS,
                                     name="conn.log.labeled")
        self.assertEqual(report["label_columns_present_but_ignored"],
                         ["label", "detailed-label"])

    def test_no_label_string_leaks_into_observations(self):
        obs, _ = self.ingest_rows(standard_rows(), fields=IOT23_FIELDS,
                                  name="conn.log.labeled")
        # Flatten every cell to string and assert not one label token survived.
        haystack = "\n".join(
            obs.astype(str).apply(lambda col: "␟".join(col)).tolist())
        for token in _LEAKABLE_LABELS:
            self.assertNotIn(token, haystack,
                             f"label token {token!r} leaked into observations")

    def test_labelled_input_still_all_unmapped(self):
        obs, _ = self.ingest_rows(standard_rows(), fields=IOT23_FIELDS,
                                  name="conn.log.labeled")
        self.assertTrue((obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())
        self.assertTrue((obs[K.ORIGINAL_LABEL] == "").all())


class TestAvailabilityParity(_Base):
    """derive() treats op_zeek like iot23: the same five features are NaN."""

    def test_unavailable_features_are_nan(self):
        obs, _ = self.ingest_rows(standard_rows())
        for feat in K.unavailable_features(K.SOURCE_OP_ZEEK):
            self.assertTrue(obs[feat].isna().all(),
                            f"{feat} should be NaN for op_zeek, is not")
        # The five unavailable set the floor on missing features per row.
        self.assertGreaterEqual(int(obs[K.N_FEATURES_MISSING].min()),
                                len(K.unavailable_features(K.SOURCE_OP_ZEEK)))

    def test_proxy_features_flagged_on_every_row(self):
        obs, _ = self.ingest_rows(standard_rows())
        proxies = set(K.proxy_features(K.SOURCE_OP_ZEEK))
        if proxies:
            for flags in obs[K.QUALITY_FLAGS]:
                flagged = set(K.parse_flags(flags).get(
                    K.FLAG_PROXY_FEATURES, []))
                self.assertEqual(flagged, proxies)


class TestRefusals(_Base):
    """Each unusable input is refused with a message, not read wrongly."""

    def test_missing_required_field_refused(self):
        # A conn.log missing 'duration' cannot yield the features that depend on
        # it; the adapter refuses rather than fabricating them.
        no_duration = tuple(f for f in PLAIN_FIELDS if f != "duration")
        with self.assertRaises(op.OperationalIngestError):
            self.ingest_rows(standard_rows(), fields=no_duration)

    def test_compressed_file_refused_by_reader(self):
        # zeek.read_header refuses on suffix before reading a byte; the product
        # error surface lets that ZeekLogError through unchanged.
        p = self.tmp / "conn.log.gz"
        p.write_text("not really gzip", encoding="utf-8")
        with self.assertRaises(zeek.ZeekLogError):
            op.ingest(p, scenario_id="op-test-01")

    def test_no_identifiable_device_refused(self):
        # Both ends in carrier-grade-NAT space (not private), local_* unset:
        # no device can be identified. The borrowed primitive raises IoT23Error;
        # it must reach the caller as the product's OperationalIngestError.
        rows = [row(T0 + 30 * i, **{"id.orig_h": PEER_A, "id.resp_h": PEER_B})
                for i in range(4)]
        with self.assertRaises(op.OperationalIngestError):
            self.ingest_rows(rows)

    def test_empty_capture_refused(self):
        # A header but no data rows: zeek raises first, and either way the run
        # does not silently produce an empty table.
        with self.assertRaises((op.OperationalIngestError, zeek.ZeekLogError)):
            self.ingest_rows([])


class TestExplicitDevice(_Base):
    """--device-ip is honoured and recorded, same as Track A."""

    def test_explicit_device_ip(self):
        obs, report = self.ingest_rows(standard_rows(), device_ips=[DEV])
        self.assertEqual(report["devices"]["basis"], "explicit --device-ip")
        self.assertIn(DEV, report["devices"]["devices"])
        self.assertTrue((obs[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())


class TestReportProvenance(_Base):
    """The frame and report carry the operational note, never the IoT-23 one."""

    def test_provenance_note_is_operational(self):
        _, report = self.ingest_rows(standard_rows())
        self.assertEqual(report["provenance_note"], operational_data_note())
        self.assertIn("UNLABELLED", report["provenance_note"])
        self.assertIn("not ML-validated", report["provenance_note"])

    def test_detection_note_marks_review_only(self):
        _, report = self.ingest_rows(standard_rows())
        note = report["detection_note"]
        self.assertIn("review-only", note)
        self.assertIn("not ML-validated", note)


class TestResponderSideCapture(_Base):
    """A responder-heavy capture ingests cleanly (orientation wiring works)."""

    def test_device_as_responder_still_ingests(self):
        # DEV answers PEER_A: device is the responder on every flow. The
        # orientation transform keeps these (device is involved) and re-orients
        # them; here we only assert the wiring produces a valid unmapped frame.
        rows = [row(T0 + 30 * i, **{"id.orig_h": PEER_A, "id.resp_h": DEV,
                                    "id.orig_p": 44000 + i, "id.resp_p": 443})
                for i in range(6)]
        obs, report = self.ingest_rows(rows)
        assert_valid(obs)
        self.assertGreater(len(obs), 0)
        self.assertGreater(report["orientation"]["device_is_responder"], 0)


class TestCLI(_Base):
    """main() writes a re-readable CSV and a report, and returns 0."""

    def test_cli_writes_valid_csv(self):
        logpath = write_log(self.tmp / "conn.log", standard_rows(),
                            fields=PLAIN_FIELDS)
        out = self.tmp / "out.csv"
        rc = op.main(["--input", str(logpath), "--scenario-id", "op-cli-01",
                      "--out", str(out)])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())
        self.assertTrue(out.with_suffix(".report.json").exists())
        reread = read_observations(out)
        assert_valid(reread)
        self.assertTrue((reread[K.RESEARCH_CLASS] == K.CLS_UNMAPPED).all())

    def test_cli_bad_input_returns_2(self):
        rc = op.main(["--input", str(self.tmp / "nope.log"),
                      "--scenario-id", "op-cli-02", "--out",
                      str(self.tmp / "out.csv")])
        self.assertEqual(rc, 2)

    def test_default_out_sanitises_scenario(self):
        # A scenario id with a path separator must not escape the processed dir.
        out = op._default_out("a/b:c d")
        self.assertNotIn("/", out.name)
        self.assertNotIn(":", out.name)
        self.assertTrue(out.name.startswith("operational_"))


if __name__ == "__main__":
    unittest.main()
