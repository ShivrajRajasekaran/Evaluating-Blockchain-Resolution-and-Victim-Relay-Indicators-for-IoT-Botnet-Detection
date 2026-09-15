"""
tests/test_upload_security — the only path by which untrusted bytes enter.

The filename on an upload is attacker-controlled, so the tests that matter here
are the ones that prove it is never used to build a path: a name of
"../../../../etc/passwd" or "C:\\Windows\\System32\\x.log" must produce an
ordinary file inside the jobs directory with a generated name. The size cap is
tested as a STREAMING limit, because a cap applied after reading is not a cap.
"""
from __future__ import annotations

import io
import shutil
import tempfile
import unittest
from pathlib import Path

from src.api import uploads as U

ALLOWED = [".log", ".labeled", ".csv", ".tsv", ".txt"]

ZEEK_HEAD = (
    "#separator \\x09\n"
    "#fields\tts\tid.orig_h\tid.resp_h\tproto\n"
    "1546300800.0\t192.168.1.10\t203.0.113.5\ttcp\n")

CSV_HEAD = "ts,src_ip,dst_ip,proto,bytes\n1546300800,192.168.1.10,203.0.113.5,tcp,500\n"


class _UploadCase(unittest.TestCase):
    def setUp(self):
        self._dir = Path(tempfile.mkdtemp(prefix="als_up_"))
        self.jobs = self._dir / "jobs"

    def tearDown(self):
        shutil.rmtree(self._dir, ignore_errors=True)

    def store(self, content, name="conn.log", *, max_bytes=1_000_000):
        if isinstance(content, str):
            content = content.encode("utf-8")
        return U.store_stream(io.BytesIO(content), original_name=name,
                              jobs_dir=self.jobs, max_bytes=max_bytes,
                              allowed_extensions=ALLOWED)


class ExtensionAllowlist(unittest.TestCase):
    def test_accepted_extensions_are_case_insensitive(self):
        self.assertEqual(U.check_extension("CONN.LOG", ALLOWED), ".log")
        self.assertEqual(U.check_extension("flows.CSV", ALLOWED), ".csv")

    def test_everything_else_is_refused(self):
        for name in ("payload.exe", "script.sh", "archive.zip", "notes.pdf",
                     "conn.log.gz", "noextension"):
            with self.subTest(name=name):
                with self.assertRaises(U.UploadRejected):
                    U.check_extension(name, ALLOWED)

    def test_the_refusal_says_what_is_accepted(self):
        with self.assertRaises(U.UploadRejected) as ctx:
            U.check_extension("payload.exe", ALLOWED)
        self.assertIn(".log", str(ctx.exception))

    def test_an_empty_name_is_refused(self):
        with self.assertRaises(U.UploadRejected):
            U.check_extension("", ALLOWED)


class PathTraversal(_UploadCase):
    """The client's filename is never a path. Not sanitised — not used."""

    HOSTILE = (
        "../../../../etc/passwd.log",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts.log",
        "C:\\Windows\\System32\\evil.log",
        "/etc/cron.d/evil.log",
        "....//....//evil.log",
        "conn.log/../../escape.log",
    )

    def test_hostile_names_land_inside_the_jobs_directory(self):
        for name in self.HOSTILE:
            with self.subTest(name=name):
                stored = self.store(ZEEK_HEAD, name=name)
                self.assertEqual(stored.path.parent.resolve(),
                                 self.jobs.resolve())
                self.assertTrue(stored.path.exists())

    def test_the_stored_name_is_generated_not_derived(self):
        stored = self.store(ZEEK_HEAD, name="../../etc/passwd.log")
        self.assertTrue(stored.stored_name.startswith("up_"))
        self.assertTrue(stored.stored_name.endswith(".log"))
        self.assertNotIn("passwd", stored.stored_name)
        self.assertNotIn("..", stored.stored_name)

    def test_two_uploads_of_one_name_do_not_collide(self):
        a = self.store(ZEEK_HEAD, name="conn.log")
        b = self.store(ZEEK_HEAD, name="conn.log")
        self.assertNotEqual(a.stored_name, b.stored_name)
        self.assertTrue(a.path.exists() and b.path.exists())

    def test_the_original_name_is_kept_for_display_only(self):
        stored = self.store(ZEEK_HEAD, name="../../etc/passwd.log")
        self.assertEqual(stored.original_name, "passwd.log")

    def test_display_name_strips_control_characters_and_bounds_length(self):
        self.assertEqual(U.display_name("co\x00nn\x1b.log"), "conn.log")
        self.assertEqual(len(U.display_name("a" * 5000)), 255)
        self.assertEqual(U.display_name(""), "(unnamed)")
        self.assertEqual(U.display_name("  /var/log/conn.log "), "conn.log")

    def test_resolve_inside_refuses_an_escape(self):
        inside = U.resolve_inside(self.jobs, "up_abc.log")
        self.assertTrue(str(inside).startswith(str(self.jobs.resolve())))
        with self.assertRaises(U.UploadRejected):
            U.resolve_inside(self.jobs, "../../../etc/passwd")


class SizeCap(_UploadCase):
    def test_a_file_over_the_cap_is_refused(self):
        big = ZEEK_HEAD + ("1546300800.0\t192.168.1.10\t203.0.113.5\ttcp\n"
                           * 5000)
        with self.assertRaises(U.UploadRejected) as ctx:
            self.store(big, max_bytes=1024)
        self.assertIn("larger than", str(ctx.exception))

    def test_a_refused_upload_leaves_no_partial_file_behind(self):
        big = "x" * 100_000
        with self.assertRaises(U.UploadRejected):
            self.store(big, max_bytes=1024)
        self.assertEqual(list(self.jobs.glob("*")), [])

    def test_a_file_at_the_cap_is_accepted(self):
        body = ZEEK_HEAD
        stored = self.store(body, max_bytes=len(body.encode()))
        self.assertEqual(stored.size_bytes, len(body.encode()))

    def test_the_cap_is_applied_while_reading(self):
        """A stream that would be enormous is abandoned, not buffered.

        The reader is asked for at most a few chunks before the limit trips; a
        cap applied after reading would drain all 50 MB into memory first.
        """
        class _Endless:
            def __init__(self):
                self.calls = 0

            def read(self, n):
                self.calls += 1
                return b"x" * n

        stream = _Endless()
        with self.assertRaises(U.UploadRejected):
            U.store_stream(stream, original_name="huge.log",
                           jobs_dir=self.jobs, max_bytes=64 * 1024,
                           allowed_extensions=ALLOWED)
        self.assertLessEqual(stream.calls, 4)


class ContentSniffing(_UploadCase):
    def test_a_zeek_header_is_recognised(self):
        self.assertEqual(U.sniff(ZEEK_HEAD.encode(), ".log"), "zeek")

    def test_a_csv_header_is_recognised(self):
        self.assertEqual(U.sniff(CSV_HEAD.encode(), ".csv"), "delimited")

    def test_a_binary_file_is_refused_even_with_an_allowed_extension(self):
        payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00" * 40
        with self.assertRaises(U.UploadRejected) as ctx:
            self.store(payload, name="conn.log")
        self.assertIn("binary", str(ctx.exception))

    def test_an_empty_file_is_refused(self):
        with self.assertRaises(U.UploadRejected):
            self.store(b"", name="conn.log")

    def test_a_log_that_is_not_a_zeek_log_is_refused_clearly(self):
        with self.assertRaises(U.UploadRejected) as ctx:
            self.store("just some prose about networks\n", name="conn.log")
        self.assertIn("#fields", str(ctx.exception))

    def test_a_csv_without_a_delimiter_is_refused(self):
        with self.assertRaises(U.UploadRejected) as ctx:
            self.store("a single column of prose\nand another line\n",
                       name="flows.csv")
        self.assertIn("delimited", str(ctx.exception))

    def test_a_rejected_sniff_removes_the_file(self):
        with self.assertRaises(U.UploadRejected):
            self.store(b"\x00\x01\x02" * 100, name="conn.log")
        self.assertEqual(list(self.jobs.glob("*")), [])


class StoredMetadata(_UploadCase):
    def test_the_digest_and_size_describe_what_was_written(self):
        import hashlib
        stored = self.store(ZEEK_HEAD)
        raw = ZEEK_HEAD.encode()
        self.assertEqual(stored.size_bytes, len(raw))
        self.assertEqual(stored.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(stored.path.read_bytes(), raw)

    def test_the_projection_never_carries_the_server_path(self):
        payload = self.store(ZEEK_HEAD).as_dict()
        self.assertNotIn("path", payload)
        self.assertEqual(
            set(payload),
            {"stored_name", "original_name", "size_bytes", "extension",
             "sha256"})


class AuthorisedInputDirectory(_UploadCase):
    """The one directory read without an upload."""

    def setUp(self):
        super().setUp()
        self.inbox = self._dir / "authorised_input"
        self.inbox.mkdir()

    def test_only_allowlisted_extensions_are_listed(self):
        (self.inbox / "conn.log").write_text(ZEEK_HEAD, encoding="utf-8")
        (self.inbox / "flows.csv").write_text(CSV_HEAD, encoding="utf-8")
        (self.inbox / "notes.pdf").write_bytes(b"%PDF-1.4")
        found = {p.name for p in U.authorised_input_files(self.inbox, ALLOWED)}
        self.assertEqual(found, {"conn.log", "flows.csv"})

    def test_a_missing_directory_is_empty_not_an_error(self):
        self.assertEqual(
            U.authorised_input_files(self._dir / "nope", ALLOWED), [])

    def test_subdirectories_are_not_descended_into(self):
        nested = self.inbox / "sub"
        nested.mkdir()
        (nested / "conn.log").write_text(ZEEK_HEAD, encoding="utf-8")
        self.assertEqual(U.authorised_input_files(self.inbox, ALLOWED), [])

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlinks unavailable")
    def test_a_symlink_is_skipped(self):
        """A link planted here would read a file outside the authorised
        directory — the same escape the upload path refuses."""
        outside = self._dir / "secret.log"
        outside.write_text(ZEEK_HEAD, encoding="utf-8")
        link = self.inbox / "innocent.log"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("this platform/user cannot create symlinks")
        self.assertEqual(U.authorised_input_files(self.inbox, ALLOWED), [])


if __name__ == "__main__":
    unittest.main()
