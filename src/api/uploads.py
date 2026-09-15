"""
api/uploads.py — accepting a log file from an authenticated user, safely.

THE THREAT MODEL
    An upload is the only way untrusted bytes enter this product, and the
    filename is attacker-controlled. Four things are therefore true of every
    stored file, and each has a test:

    1.  THE CLIENT'S FILENAME IS NEVER A PATH. It is recorded verbatim for
        display and never used to build one. Storage names are generated from a
        random token plus a validated extension, so "../../etc/passwd",
        "C:\\Windows\\x", a NUL byte and a 4 KB name all land as an ordinary
        file inside the jobs directory. Sanitising the client's name would be a
        guessing game; not using it is not.

    2.  THE EXTENSION IS ALLOWLISTED. Taken from the client's name, lowercased,
        and checked against `api.allowed_extensions` — reject-by-default, so a
        format the ingest adapters cannot read never reaches them.

    3.  THE SIZE IS CAPPED WHILE READING, NOT AFTER. The stream is read in
        chunks against a running total and abandoned the moment it exceeds
        `api.max_upload_bytes`. Reading first and measuring second is how a
        25 MiB limit becomes an out-of-memory condition.

    4.  THE CONTENT IS SNIFFED. A file claiming .log must actually begin like a
        Zeek log, and a .csv must have a plausible header row. This is a
        usability guard as much as a security one — it fails in the uploader's
        face with a clear reason instead of deep inside a parser.

WHAT THIS MODULE DOES NOT DO
    It does not execute, decompress, or interpret anything. The file is bytes
    on disk until an ingest adapter reads it as text.
"""
from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

# Read the stream in chunks so an oversized upload is abandoned early rather
# than buffered whole.
_CHUNK = 64 * 1024

# A Zeek log declares its columns; a CSV has a header line. Anything binary is
# rejected outright, because no adapter here reads a binary format.
_ZEEK_MARKERS = (b"#separator", b"#fields", b"#types", b"#set_separator")
_TEXT_SAFE = bytes(range(0x20, 0x7F)) + b"\t\r\n"

# Extensions the sniffer treats as delimited text rather than Zeek.
_CSV_LIKE = frozenset({".csv", ".tsv", ".txt"})


class UploadRejected(ValueError):
    """The upload is not something this product will store or read.

    The message is safe to show a user: it says what was wrong with their file,
    never anything about the server's filesystem.
    """


@dataclass(frozen=True)
class StoredUpload:
    """A file that passed every check and now exists on disk."""

    path: Path
    stored_name: str
    original_name: str
    size_bytes: int
    extension: str
    sha256: str

    def as_dict(self) -> dict:
        return {
            "stored_name": self.stored_name,
            "original_name": self.original_name,
            "size_bytes": self.size_bytes,
            "extension": self.extension,
            "sha256": self.sha256,
        }


def check_extension(original_name: str, allowed) -> str:
    """The validated, lowercased extension of a client-supplied filename.

    Only the suffix is consulted, and only to match the allowlist — the rest of
    the name never influences where anything is written.
    """
    name = (original_name or "").strip()
    if not name:
        raise UploadRejected("the upload has no filename")
    ext = Path(name.replace("\\", "/")).suffix.lower()
    allowed = [str(a).lower() for a in allowed]
    if ext not in allowed:
        raise UploadRejected(
            f"files ending {ext or '(no extension)'} are not accepted; "
            f"this product reads {', '.join(sorted(allowed))}")
    return ext


def storage_name(extension: str) -> str:
    """A generated, collision-resistant name for a stored upload.

    Built from a random token, NOT from anything the client sent, which is what
    makes path traversal structurally impossible rather than filtered.
    """
    return f"up_{secrets.token_hex(16)}{extension}"


def display_name(original_name: str, *, limit: int = 255) -> str:
    """The client's filename, made safe to render and store as a label.

    Control characters are stripped and the length is bounded. The result is
    shown to analysts and written to the alerts' ``source_file`` column; it is
    never used as a path.
    """
    name = (original_name or "").strip()
    name = re.sub(r"[\x00-\x1f\x7f]", "", name)
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    return name[:limit] or "(unnamed)"


def sniff(head: bytes, extension: str) -> str:
    """Identify the content, or raise. Returns a short format label.

    Deliberately permissive about WHICH text format it is (the ingest adapters
    do the real parsing) and strict about it being text at all.
    """
    if not head:
        raise UploadRejected("the uploaded file is empty")
    if b"\x00" in head:
        raise UploadRejected(
            "the uploaded file looks binary; this product reads Zeek logs and "
            "delimited text exports only")
    sample = head[:2048]
    printable = sum(1 for b in sample if b in _TEXT_SAFE)
    if printable / len(sample) < 0.85:
        raise UploadRejected(
            "the uploaded file does not look like text; this product reads "
            "Zeek logs and delimited text exports only")

    stripped = head.lstrip()
    if any(stripped.startswith(m) for m in _ZEEK_MARKERS):
        return "zeek"
    first_line = head.split(b"\n", 1)[0]
    if extension in _CSV_LIKE and (b"," in first_line or b"\t" in first_line):
        return "delimited"
    if extension in _CSV_LIKE:
        raise UploadRejected(
            "the first line has no comma or tab, so this does not look like a "
            "delimited export; check the file is the flow CSV and not a report")
    raise UploadRejected(
        "the file does not start with a Zeek header (#separator / #fields); "
        "check it is a conn.log or conn.log.labeled")


def store_stream(stream, *, original_name: str, jobs_dir: Path,
                 max_bytes: int, allowed_extensions) -> StoredUpload:
    """Validate and write one uploaded stream. The only way a file gets stored.

    ``stream`` is anything with ``.read(n)`` — Starlette's ``UploadFile.file``,
    a ``BytesIO`` in a test, or an open local file when an operator drops a
    capture into the authorised input directory. The size cap is enforced
    DURING the read, and a rejected upload leaves nothing behind.
    """
    import hashlib

    extension = check_extension(original_name, allowed_extensions)
    jobs_dir = Path(jobs_dir)
    jobs_dir.mkdir(parents=True, exist_ok=True)
    stored = storage_name(extension)
    path = jobs_dir / stored

    digest = hashlib.sha256()
    total = 0
    head = b""
    try:
        with path.open("wb") as fh:
            while True:
                chunk = stream.read(_CHUNK)
                if not chunk:
                    break
                if isinstance(chunk, str):      # a text-mode stream
                    chunk = chunk.encode("utf-8", "replace")
                total += len(chunk)
                if total > max_bytes:
                    raise UploadRejected(
                        f"the file is larger than the {_mib(max_bytes)} limit; "
                        "split the capture or raise api.max_upload_bytes")
                if len(head) < 4096:
                    head += chunk[:4096 - len(head)]
                digest.update(chunk)
                fh.write(chunk)
        sniff(head, extension)
    except BaseException:
        # A rejected or failed upload must not leave a partial file behind for
        # an operator to mistake for a real capture.
        path.unlink(missing_ok=True)
        raise

    return StoredUpload(
        path=path, stored_name=stored,
        original_name=display_name(original_name), size_bytes=total,
        extension=extension, sha256=digest.hexdigest())


def authorised_input_files(input_dir: Path, allowed_extensions) -> list[Path]:
    """Files an operator has placed in the authorised input directory.

    The ONLY directory read without an upload. Symlinks are skipped: a link
    planted here would otherwise let a file outside the authorised directory be
    ingested, which is the same traversal the upload path refuses.
    """
    input_dir = Path(input_dir)
    if not input_dir.is_dir():
        return []
    allowed = {str(a).lower() for a in allowed_extensions}
    out: list[Path] = []
    for entry in sorted(input_dir.iterdir()):
        if entry.is_symlink() or not entry.is_file():
            continue
        if entry.suffix.lower() not in allowed:
            continue
        out.append(entry)
    return out


def resolve_inside(directory: Path, name: str) -> Path:
    """Resolve ``name`` within ``directory``, refusing anything that escapes.

    Used where a stored name arrives from a URL or a form. Belt and braces: the
    names are generated, so this should never fire — and it is here so that if
    a future caller ever passes something else, it fails closed.
    """
    directory = Path(directory).resolve()
    candidate = (directory / name).resolve()
    if not str(candidate).startswith(str(directory) + os.sep) \
            and candidate != directory:
        raise UploadRejected("that file is not in the product's storage")
    return candidate


def _mib(n: int) -> str:
    return f"{n / (1024 * 1024):.0f} MiB"
