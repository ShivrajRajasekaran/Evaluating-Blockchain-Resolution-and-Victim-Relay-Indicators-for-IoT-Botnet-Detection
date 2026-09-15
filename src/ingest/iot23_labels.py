"""
ingest/iot23_labels.py — IoT-23 flow labels -> this project's taxonomy.

Separate from the adapter because this mapping is the single most contestable
decision in Track A and a reviewer must be able to read it on one page without
the CSV plumbing around it.

THE ABSOLUTE RULE
    No IoT-23 label may EVER map to blockchain_resolution_mock,
    victim_relay_mock, or combined_mock. IoT-23 was captured in 2018-2019 and
    predates blockchain-anchored C2 entirely; every malicious flow in it resolves
    its C2 by DNS or hard-coded IP. Mapping any of it to a blockchain class would
    fabricate real-world evidence for this project's central claim out of a
    dataset that contains none. The rule is enforced by an assertion at import
    time and by tests/test_iot23_labels.py, not left to reviewer vigilance.

WHAT UNMAPPED MEANS
    IoT-23's detailed-label vocabulary is not formally closed — different
    scenario files carry spellings and combinations the published table does not
    list. Anything this module does not recognise becomes CLS_UNMAPPED: retained
    for auditing, excluded from training, counted in every report, and NEVER
    guessed at. Guessing would silently move a row into whichever class happens
    to be nearest in spelling.

    CLS_UNMAPPED is a data state, not a class. Nothing trains on it and nothing
    predicts it; at inference the equivalent is abstention.
"""
from __future__ import annotations

from src.schema import columns as K

# ---------------------------------------------------------------------------
# The raw vocabulary
# ---------------------------------------------------------------------------
# IoT-23 carries two label fields per flow:
#   label           "Benign" | "Malicious" | "-"        (coarse)
#   detailed-label  "-" | "C&C" | "PartOfAHorizontalPortScan" | ...  (specific)
# The coarse field decides benign vs malicious; the detailed field decides WHICH
# malicious class. Both are consulted, because a row marked Malicious with an
# unrecognised detailed-label is a known-malicious flow of unknown type — which
# is a different state from a row whose coarse label itself is unreadable.

LABEL_BENIGN = "benign"
LABEL_MALICIOUS = "malicious"

# Zeek's unset-field token, and the two spellings of "no detailed label".
_NULL_TOKENS = frozenset({"-", "", "(empty)", "none", "nan"})

# Detailed labels that indicate command-and-control communication. Matched as
# substrings after normalisation, because IoT-23 composes them:
# "C&C-HeartBeat-FileDownload" is one label in the corpus.
_C2_MARKERS: tuple[str, ...] = (
    "c&c",      # C&C, C&C-HeartBeat, C&C-FileDownload, C&C-Torii, C&C-Mirai
    "cc",       # some scenario files write CC without the ampersand
)

# Detailed labels that indicate botnet activity OTHER than C2 dialogue: the
# propagation, scanning and attack behaviour of an already-infected device.
_BOTNET_MARKERS: tuple[str, ...] = (
    "partofahorizontalportscan",
    "horizontalportscan",
    "portscan",
    "ddos",
    "attack",
    "okiru",
    "mirai",
    "torii",
    "muhstik",
    "hakai",
    "hajime",
    "kenjiro",
    "hide and seek",
    "hideandseek",
    "filedownload",
    "heartbeat",
)

# Priority when a window contains several malicious kinds. C2 outranks generic
# botnet activity because it is the more specific observation: a window holding
# both C&C dialogue and port scanning is a C2 window that also scanned, and
# collapsing it to "botnet activity" would erase the finding that matters.
CLASS_PRIORITY: tuple[str, ...] = (
    K.CLS_TRADITIONAL_C2,
    K.CLS_TRADITIONAL_BOTNET,
    K.CLS_BENIGN_REAL,
)


def _norm(s) -> str:
    return str(s).strip().lower()


def map_flow_label(label, detailed_label) -> str:
    """Map one flow's (label, detailed-label) pair to a research class.

    Returns a Track A class or :data:`K.CLS_UNMAPPED`. Never returns a Track B
    class — see the module docstring.
    """
    coarse = _norm(label)
    detail = _norm(detailed_label)

    if coarse == LABEL_BENIGN:
        # A benign flow with a detailed label is a contradiction in the source,
        # not something to reinterpret. Benign wins; the raw pair is preserved
        # verbatim in original_label so the contradiction stays visible.
        return K.CLS_BENIGN_REAL

    if coarse == LABEL_MALICIOUS:
        if any(m in detail for m in _C2_MARKERS):
            return K.CLS_TRADITIONAL_C2
        if any(m in detail for m in _BOTNET_MARKERS):
            return K.CLS_TRADITIONAL_BOTNET
        if detail in _NULL_TOKENS:
            # Malicious with no detail. Known-bad of unknown kind: real
            # information, and the broader of the two malicious classes is the
            # honest home for it.
            return K.CLS_TRADITIONAL_BOTNET
        # Malicious with a detail string this module does not recognise. Do not
        # guess which malicious class it belongs to.
        return K.CLS_UNMAPPED

    # Coarse label itself unreadable ("-", blank, a value not in the vocabulary).
    return K.CLS_UNMAPPED


def raw_label_string(label, detailed_label) -> str:
    """The verbatim source label pair, for the ``original_label`` column.

    Kept as one string in the source's own spelling. The schema's contract for
    original_label is that a reader can always recover what the dataset actually
    said, independently of how this module chose to interpret it.
    """
    detail = str(detailed_label).strip()
    if _norm(detail) in _NULL_TOKENS:
        return str(label).strip()
    return f"{str(label).strip()}|{detail}"


def resolve_window_class(flow_classes) -> tuple[str, float]:
    """Collapse a window's per-flow classes to one class and a malicious share.

    A window is malicious if ANY flow in it is malicious. That is the detection
    question as actually posed — a detector that misses a device because only 3%
    of its window was attack traffic has missed it — and the alternative,
    majority vote, would relabel genuinely compromised devices as benign and
    understate the false-negative rate.

    The cost is that a 3%-malicious window and a 100%-malicious window become the
    same label. The returned fraction is what pays that cost back: the adapter
    writes it into FLAG_MIXED_LABEL_WINDOW so the distinction survives into the
    observation table.

    An unmapped flow does not contaminate a window that also holds confidently
    labelled flows; a window is only unmapped when it has nothing else to go on.
    """
    classes = [c for c in flow_classes]
    if not classes:
        raise ValueError("cannot resolve the class of a window with no flows")

    known = [c for c in classes if c != K.CLS_UNMAPPED]
    if not known:
        return K.CLS_UNMAPPED, float("nan")

    malicious = [c for c in known if c in K.MALICIOUS_CLASSES]
    frac = len(malicious) / len(classes)

    if not malicious:
        return K.CLS_BENIGN_REAL, 0.0
    for candidate in CLASS_PRIORITY:
        if candidate in malicious:
            return candidate, frac
    raise AssertionError(f"unreachable: {sorted(set(malicious))}")


# ---------------------------------------------------------------------------
# Import-time enforcement of the absolute rule
# ---------------------------------------------------------------------------
# Cheap, and it fires the moment anyone edits the tables above in the wrong
# direction rather than at the next test run.
assert not (set(CLASS_PRIORITY) & set(K.TRACK_B_CLASSES)), (
    "IoT-23 label mapping must never target a Track B (mock) class"
)
