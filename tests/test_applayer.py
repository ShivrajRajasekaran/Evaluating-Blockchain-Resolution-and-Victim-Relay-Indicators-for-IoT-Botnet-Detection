"""
tests/test_applayer — the four features a connection log cannot express.

The rule under test throughout is MISSING IS NOT ZERO. A feature reads 0.0 only
when the log that feeds it was present and showed nothing; when the log is absent
the feature must be NaN, so a capture that could not be assessed never resembles
one that was assessed and found clean.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.features import applayer as A
from src.features import windowing as W

W0 = pd.Timestamp("2019-01-10 14:35:00")
W1 = pd.Timestamp("2019-01-10 14:40:00")
DEV = "192.168.1.197"

PARAMS = A.ResolutionParams(
    rpc_gateways=("eth.llamarpc.com", "1rpc.io", "sdk-proxy.sns.id"),
    serverlist_window_seconds=120.0,
    serverlist_query_keys=("key", "token"),
)


def _keys(*pairs) -> pd.MultiIndex:
    return pd.MultiIndex.from_tuples(
        list(pairs), names=[W.F_DEVICE_ID, W.WINDOW_START])


def _ssl(rows) -> pd.DataFrame:
    """rows: (epoch_ts, orig, server_name)"""
    return pd.DataFrame(rows, columns=[A.SSL_TS, A.SSL_ORIG, A.SSL_SNI]
                        ).astype(str)


def _dns(rows) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=[A.DNS_TS, A.DNS_ORIG, A.DNS_QUERY]
                        ).astype(str)


def _http(rows) -> pd.DataFrame:
    """rows: (epoch_ts, orig, host, uri)"""
    return pd.DataFrame(
        rows, columns=[A.HTTP_TS, A.HTTP_ORIG, A.HTTP_HOST, A.HTTP_URI]
    ).astype(str)


TS0 = int(W0.timestamp())


class MissingIsNotZero(unittest.TestCase):
    """The distinction the whole project rests on."""

    def test_no_logs_at_all_yields_nan_not_zero(self):
        # CTU-IoT-Malware-Capture-8-1 is exactly this: every flow unrecognised by
        # Zeek, so no dns/http/ssl exists. It must be unassessable, not clean.
        keys = _keys((DEV, W0), (DEV, W1))
        res = A.derive_applayer({}, keys, params=PARAMS)
        for feat in A.APPLAYER_FEATURES:
            col = res.features[feat]
            self.assertTrue(col.isna().all(),
                            f"{feat} must be NaN with no logs, got {list(col)}")

    def test_ssl_present_but_no_gateway_contact_is_measured_zero(self):
        # The Amazon Echo case: plenty of TLS, none of it to a gateway. That is a
        # measured result and must NOT be NaN.
        keys = _keys((DEV, W0))
        bundle = {"ssl.log": _ssl([(TS0 + 5, DEV, "device-api.amazon.com"),
                                   (TS0 + 9, DEV, "s3.amazonaws.com")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["ens_query_rate"].iloc[0], 0.0)
        self.assertEqual(res.features["rpc_endpoint_ratio"].iloc[0], 0.0)

    def test_dns_only_leaves_sni_features_unmeasurable(self):
        # dns.log alone cannot answer "did it reach a gateway", so those stay NaN
        # while the DNS-derived feature is real.
        keys = _keys((DEV, W0))
        bundle = {"dns.log": _dns([(TS0 + 1, DEV, "example.com")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertTrue(np.isnan(res.features["ens_query_rate"].iloc[0]))
        self.assertTrue(np.isnan(res.features["rpc_endpoint_ratio"].iloc[0]))
        self.assertFalse(np.isnan(res.features["resolution_entropy"].iloc[0]))


class GatewayMatching(unittest.TestCase):
    def test_exact_sni_match_counts(self):
        keys = _keys((DEV, W0))
        bundle = {"ssl.log": _ssl([(TS0 + 3, DEV, "eth.llamarpc.com")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertGreater(res.features["ens_query_rate"].iloc[0], 0.0)
        self.assertEqual(res.features["rpc_endpoint_ratio"].iloc[0], 1.0)

    def test_subdomain_of_a_gateway_matches(self):
        keys = _keys((DEV, W0))
        bundle = {"ssl.log": _ssl([(TS0 + 3, DEV, "mainnet.1rpc.io")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["rpc_endpoint_ratio"].iloc[0], 1.0)

    def test_lookalike_domain_does_not_match(self):
        # "not1rpc.io" ends with the gateway's characters but is a different host.
        # Matching on a bare suffix would be a false positive.
        keys = _keys((DEV, W0))
        bundle = {"ssl.log": _ssl([(TS0 + 3, DEV, "not1rpc.io")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["rpc_endpoint_ratio"].iloc[0], 0.0)

    def test_ratio_is_a_share_of_the_window_not_a_count(self):
        keys = _keys((DEV, W0))
        bundle = {"ssl.log": _ssl([(TS0 + 1, DEV, "eth.llamarpc.com"),
                                   (TS0 + 2, DEV, "example.com"),
                                   (TS0 + 3, DEV, "example.org"),
                                   (TS0 + 4, DEV, "example.net")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertAlmostEqual(res.features["rpc_endpoint_ratio"].iloc[0], 0.25)

    def test_absent_sni_token_is_not_a_hostname(self):
        # Zeek writes "-" when a handshake carried no SNI. Counting it as a host
        # would deflate every ratio in the window.
        keys = _keys((DEV, W0))
        bundle = {"ssl.log": _ssl([(TS0 + 1, DEV, "eth.llamarpc.com"),
                                   (TS0 + 2, DEV, "-")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["rpc_endpoint_ratio"].iloc[0], 1.0)

    def test_windows_are_independent(self):
        keys = _keys((DEV, W0), (DEV, W1))
        bundle = {"ssl.log": _ssl([
            (TS0 + 1, DEV, "eth.llamarpc.com"),          # W0
            (int(W1.timestamp()) + 1, DEV, "example.com"),  # W1
        ])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["rpc_endpoint_ratio"].iloc[0], 1.0)
        self.assertEqual(res.features["rpc_endpoint_ratio"].iloc[1], 0.0)


class ServerListPull(unittest.TestCase):
    """A pull AFTER resolution — ordering is what makes it meaningful."""

    def test_keyed_get_after_gateway_contact_fires(self):
        keys = _keys((DEV, W0))
        bundle = {
            "ssl.log": _ssl([(TS0 + 10, DEV, "eth.llamarpc.com")]),
            "http.log": _http([(TS0 + 30, DEV, "144.31.38.215",
                                "/nodes?key=meowmeowmeow")]),
        }
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["serverlist_pull"].iloc[0], 1.0)

    def test_keyed_get_before_resolution_does_not_fire(self):
        # A fetch that precedes the resolution is not a pull *after* it.
        keys = _keys((DEV, W0))
        bundle = {
            "ssl.log": _ssl([(TS0 + 90, DEV, "eth.llamarpc.com")]),
            "http.log": _http([(TS0 + 10, DEV, "x", "/nodes?key=abc")]),
        }
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["serverlist_pull"].iloc[0], 0.0)

    def test_plain_get_without_a_key_parameter_does_not_fire(self):
        keys = _keys((DEV, W0))
        bundle = {
            "ssl.log": _ssl([(TS0 + 10, DEV, "eth.llamarpc.com")]),
            "http.log": _http([(TS0 + 30, DEV, "x", "/index.html")]),
        }
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["serverlist_pull"].iloc[0], 0.0)


class Upnp(unittest.TestCase):
    def test_soap_marker_sets_the_flag(self):
        keys = _keys((DEV, W0))
        bundle = {"http.log": _http([
            (TS0 + 5, DEV, "192.168.1.1:5000", "/ctl/WANIPConnection")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["upnp_addportmapping"].iloc[0], 1.0)

    def test_ordinary_http_leaves_it_measured_zero(self):
        keys = _keys((DEV, W0))
        bundle = {"http.log": _http([(TS0 + 5, DEV, "example.com", "/x")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertEqual(res.features["upnp_addportmapping"].iloc[0], 0.0)


class Entropy(unittest.TestCase):
    def test_random_looking_names_score_above_repetitive_ones(self):
        keys = _keys((DEV, W0))
        low = A.derive_applayer(
            {"dns.log": _dns([(TS0 + 1, DEV, "aaaa.com"),
                              (TS0 + 2, DEV, "aaaa.com")])},
            keys, params=PARAMS).features["resolution_entropy"].iloc[0]
        high = A.derive_applayer(
            {"dns.log": _dns([(TS0 + 1, DEV, "x7q2vz9k4mbp.com"),
                              (TS0 + 2, DEV, "j3nf8wgt5rly.net")])},
            keys, params=PARAMS).features["resolution_entropy"].iloc[0]
        self.assertGreater(high, low)

    def test_window_with_no_queries_is_nan_not_zero(self):
        # dns.log exists but this window had none. Entropy of an empty set is
        # undefined, not 0.0.
        keys = _keys((DEV, W0), (DEV, W1))
        bundle = {"dns.log": _dns([(TS0 + 1, DEV, "example.com")])}
        res = A.derive_applayer(bundle, keys, params=PARAMS)
        self.assertFalse(np.isnan(res.features["resolution_entropy"].iloc[0]))
        self.assertTrue(np.isnan(res.features["resolution_entropy"].iloc[1]))


class Alignment(unittest.TestCase):
    def test_output_is_row_aligned_to_the_supplied_keys(self):
        # The features are attached to a window index by position, so a mismatch
        # here would silently give one window another window's evidence.
        keys = _keys((DEV, W0), ("10.0.0.9", W0), (DEV, W1))
        res = A.derive_applayer(
            {"ssl.log": _ssl([(TS0 + 1, DEV, "eth.llamarpc.com")])},
            keys, params=PARAMS)
        self.assertEqual(len(res.features), 3)
        self.assertTrue(res.features.index.equals(keys))
        # only the (DEV, W0) row saw the gateway
        self.assertEqual(res.features["rpc_endpoint_ratio"].iloc[0], 1.0)
        self.assertEqual(res.features["rpc_endpoint_ratio"].iloc[1], 0.0)


class BundleReading(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="bundle_"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, name: str, fields: list[str], rows: list[list[str]]):
        lines = ["#separator \\x09",
                 "#fields\t" + "\t".join(fields),
                 "#types\t" + "\t".join("string" for _ in fields)]
        lines += ["\t".join(r) for r in rows]
        (self.dir / name).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_absent_log_is_simply_absent(self):
        self._write("dns.log", [A.DNS_TS, A.DNS_ORIG, A.DNS_QUERY],
                    [[str(TS0), DEV, "example.com"]])
        got = A.read_bundle(self.dir)
        self.assertIn("dns.log", got)
        self.assertNotIn("ssl.log", got)

    def test_empty_log_file_is_treated_as_absent(self):
        (self.dir / "ssl.log").write_text("", encoding="utf-8")
        self.assertNotIn("ssl.log", A.read_bundle(self.dir))


if __name__ == "__main__":
    unittest.main()
