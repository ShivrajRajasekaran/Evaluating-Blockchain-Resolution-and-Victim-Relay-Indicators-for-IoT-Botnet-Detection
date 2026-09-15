"""
config.py — single source of truth for the detection prototype.

Project: Detecting Blockchain-Anchored Command-and-Control in IoT Botnets
Scope:   DEFENSIVE detection/analysis only. All data here is LOCAL and SYNTHETIC.
         No real network, no real C2, no real malware, no attacker infrastructure.

The synthetic generator produces realistic *feature shapes* for labelling only,
so the detection pipeline (heuristic + RandomForest + XGBoost) can be built and
evaluated end-to-end before any real testbed capture exists. Real public
datasets (IoT-23, Bot-IoT, N-BaIoT, CIC-IDS) are swapped in at a later stage.

UNIT OF ANALYSIS
----------------
One row = ONE DEVICE OBSERVED OVER ONE 5-MINUTE WINDOW.
Not one flow. Several features (distinct_dst_ports, scan_rate,
login_burst_count, flow_fanout, beacon_jitter) are undefined for a single flow —
they only exist as per-device aggregates over a time window. The label applies
to the device-window, not to a packet or a connection.
"""
from pathlib import Path

# ----------------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
RESULTS_DIR = ROOT / "results"
FIG_DIR = RESULTS_DIR / "figures"
TAB_DIR = RESULTS_DIR / "tables"
for _d in (DATA_DIR, RESULTS_DIR, FIG_DIR, TAB_DIR):
    _d.mkdir(parents=True, exist_ok=True)

DATASET_CSV = DATA_DIR / "synthetic_device_windows.csv"

# The prediction unit, stated once so every table/figure/report can cite it.
UNIT_OF_ANALYSIS = "device observed over a 5-minute window"
WINDOW_SECONDS = 300

# ----------------------------------------------------------------------------
# Reproducibility
# ----------------------------------------------------------------------------
RANDOM_SEED = 42
SEEDS = [42, 7, 123, 2024, 99]   # multi-seed robustness protocol

# ----------------------------------------------------------------------------
# Labels
# ----------------------------------------------------------------------------
# Binary target: 0 = benign, 1 = malicious (blockchain-C2 / relay behaviour).
LABEL_COL = "label"
LABEL_NAMES = {0: "benign", 1: "malicious"}

# ----------------------------------------------------------------------------
# Feature groups  (mirrors PROJECT_SPEC: resolution / relay / infection / payload)
# These are the columns the ablation study drops one group at a time.
# ----------------------------------------------------------------------------
FEATURE_GROUPS = {
    "resolution": [
        "ens_query_rate",        # queries/min to blockchain-name / RPC endpoints
        "rpc_endpoint_ratio",    # fraction of DNS/RPC lookups to non-standard resolvers
        "resolution_entropy",    # randomness of resolved-name pattern (DGA-like)
        "serverlist_pull",       # HTTP "server-list" pull observed after resolution (0/1)
    ],
    "relay": [
        "bidir_flow_duration",   # seconds; long-lived relay flows run long
        "flow_fanout",           # distinct peers a device relays to
        "upnp_addportmapping",   # UPnP AddPortMapping events (victim-relay setup)
        "updownlink_ratio",      # symmetry of up/down bytes (relay ~ 1.0)
    ],
    "infection": [
        "login_burst_count",     # Telnet/SSH login-burst attempts
        "scan_rate",             # outbound connection attempts/min (spread)
        "distinct_dst_ports",    # port variety touched
        "failed_conn_ratio",     # fraction of failed outbound connections
    ],
    "payload": [
        "beacon_interval",       # seconds; periodic C2 beaconing rhythm
        "beacon_jitter",         # variance around the beacon interval
        "rc4_string_score",      # LAB-ONLY: see LAB_ONLY_FEATURES below
        "mean_pkt_size",         # average packet size of the flow
    ],
}

# Features that are NOT observable from encrypted network traffic in a real
# deployment. They require host telemetry or plaintext payload inspection, so
# they can only be used in a lab/testbed setting. A reviewer will ask about
# these — the pipeline reports results both WITH and WITHOUT them.
LAB_ONLY_FEATURES = ["rc4_string_score"]

# Flat ordered feature list
FEATURE_COLS = [c for group in FEATURE_GROUPS.values() for c in group]

def features_excluding(group_name):
    """Return feature columns with one group removed (for ablation)."""
    return [c for g, cols in FEATURE_GROUPS.items() if g != group_name for c in cols]

# ----------------------------------------------------------------------------
# Dataset composition (synthetic)
# ----------------------------------------------------------------------------
N_BENIGN = 8000
N_MALICIOUS = 1200          # deliberate class imbalance (~6.7:1) — realistic
LABEL_NOISE = 0.02          # 2% of labels are flipped after generation

# NOTE: N_BENIGN / N_MALICIOUS are the counts BEFORE label noise. Because
# LABEL_NOISE flips 2% of rows, the ACTUAL label counts differ (seed 42:
# 7,866 benign / 1,334 malicious). Always report the realised counts from the
# CSV, never these nominal ones.

# Split protocol: test set is LOCKED and touched once, at final evaluation.
# Model selection, threshold calibration and permutation importance all use the
# validation split only.
TEST_SIZE = 0.30            # of the whole dataset
VAL_SIZE = 0.20             # of the remaining (train+val) portion

# Operating point for the fair, threshold-matched comparison. Every detector is
# tuned on validation to sit at (or under) this false-positive rate, then scored
# on the locked test set at that threshold.
TARGET_FPR = 0.01

# Bootstrap resamples for confidence intervals on test-set F1.
N_BOOTSTRAP = 1000

# ----------------------------------------------------------------------------
# Incremental-value protocol (replaces naive drop-one ablation as the headline)
# ----------------------------------------------------------------------------
# The paper's claim is that `resolution` and `relay` add value BEYOND the
# generic malware signals. Drop-one ablation cannot show that when groups are
# correlated. Instead we build up from a base and measure what each adds.
BASE_GROUPS = ["infection", "payload"]
INCREMENT_SETS = {
    "base (infection+payload)":  ["infection", "payload"],
    "base + resolution":         ["infection", "payload", "resolution"],
    "base + relay":              ["infection", "payload", "relay"],
    "base + resolution + relay": ["infection", "payload", "resolution", "relay"],
}

def features_for_groups(group_names):
    """Return the feature columns belonging to the named groups, in config order."""
    return [c for g, cols in FEATURE_GROUPS.items() if g in group_names for c in cols]
