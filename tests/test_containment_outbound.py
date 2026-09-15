"""
tests/test_containment_outbound — the product makes no outbound connections.

THE CLAIM BEING ENFORCED
    This product reads authorised local telemetry and writes a local database.
    It accepts INBOUND connections on a loopback bind, because it serves a
    dashboard. It must never make an OUTBOUND one: no HTTP client, no socket
    connect, no name resolution, no mail or FTP transport, no CDN reference in
    a template or asset.

    That matters for three separate reasons, and the test enforces all three at
    once:

      * Exfiltration. The product holds an organisation's network metadata and
        alerts about its devices. Nothing in it should be ABLE to send that
        anywhere, so that "did it phone home?" is answerable by reading the
        source rather than by watching a firewall.
      * The stated ethics boundary. "Never scan, connect to, probe, or control
        any device" is a promise about capability, not intent. A codebase with
        no outbound primitive cannot break that promise through a bug.
      * The Content-Security-Policy. api/security.py sends a strict
        'self'-only CSP. That is only honest if the pages genuinely load
        nothing external — so the asset check below is part of the same claim.

HOW IT IS CHECKED
    By parsing the source of every module in the product tree with ``ast`` and
    looking for imports of networking modules and calls to their entry points.
    A regex over text would flag this very docstring; an AST sees only code.

    Two things are deliberately NOT flagged: ``socket`` used for a listening
    bind (uvicorn's job, not ours — and this tree does not import socket at
    all), and the word "connect" in prose.
"""
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

from src.config import ROOT

# The product packages. The research pipeline (models, evaluate, reports) is
# covered by its own long-standing guard in tests/test_service.py.
PRODUCT_PACKAGES = ("api", "alerts", "detection", "storage", "auth", "audit",
                    "ingest")

# Modules that can open an outbound connection. Importing one inside the
# product tree is the failure — it does not matter whether a call is reached.
FORBIDDEN_IMPORTS = frozenset({
    "requests", "httpx", "httpx2", "aiohttp", "urllib3", "socket", "smtplib",
    "ftplib", "telnetlib", "poplib", "imaplib", "nntplib", "http.client",
    "xmlrpc.client", "websockets", "websocket", "paramiko", "pycurl",
    "boto3", "botocore", "google.cloud", "azure", "scapy", "dns", "dnspython",
    "pysnmp", "nmap", "python-nmap", "urllib.request", "urllib.error",
    "ssl",
})

# Attribute/function calls that reach the network even without a bare import.
FORBIDDEN_CALLS = frozenset({
    "urlopen", "urlretrieve", "getaddrinfo", "gethostbyname", "create_connection",
    "sendmail", "SMTP", "FTP", "socket", "connect_ex",
})

# `urllib.parse` is pure string manipulation and is explicitly allowed; it is
# the only urllib submodule that touches no network.
ALLOWED_PREFIXES = ("urllib.parse",)


def product_files() -> list[Path]:
    files: list[Path] = []
    for package in PRODUCT_PACKAGES:
        root = ROOT / "src" / package
        if root.is_dir():
            files.extend(sorted(root.rglob("*.py")))
    return files


def _imported_names(tree: ast.AST) -> list[tuple[str, int]]:
    """Every module name imported, with its line number."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((alias.name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            if node.level:          # a relative import is in-project
                continue
            module = node.module or ""
            found.append((module, node.lineno))
            for alias in node.names:
                found.append((f"{module}.{alias.name}", node.lineno))
    return found


def _called_names(tree: ast.AST) -> list[tuple[str, int]]:
    """Every called function/attribute name, with its line number."""
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            found.append((func.id, node.lineno))
        elif isinstance(func, ast.Attribute):
            found.append((func.attr, node.lineno))
    return found


def _is_forbidden_import(name: str) -> bool:
    if any(name == p or name.startswith(p + ".") for p in ALLOWED_PREFIXES):
        return False
    if name in FORBIDDEN_IMPORTS:
        return True
    # A dotted import is forbidden when any ancestor is.
    parts = name.split(".")
    return any(".".join(parts[:i]) in FORBIDDEN_IMPORTS
               for i in range(1, len(parts) + 1))


class SourceIsFreeOfOutboundPrimitives(unittest.TestCase):
    def test_the_product_tree_is_non_empty(self):
        # Guards the guard: a path typo would otherwise make every test below
        # pass by scanning nothing.
        files = product_files()
        self.assertGreater(len(files), 25,
                           "the containment scan found almost no source files")

    def test_no_module_imports_a_network_client(self):
        for path in product_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for name, line in _imported_names(tree):
                if _is_forbidden_import(name):
                    self.fail(
                        f"{path.relative_to(ROOT)}:{line} imports {name!r}, "
                        "which can open an outbound connection. The product "
                        "must not be capable of sending telemetry anywhere.")

    def test_no_module_calls_a_network_entry_point(self):
        for path in product_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for name, line in _called_names(tree):
                if name in FORBIDDEN_CALLS:
                    self.fail(
                        f"{path.relative_to(ROOT)}:{line} calls {name!r}, "
                        "which reaches the network.")

    def test_no_module_shells_out(self):
        """A subprocess is an outbound primitive by proxy.

        `curl`, `wget` or `nslookup` launched from here would evade every check
        above, so the product tree does not run external commands at all.
        """
        forbidden = {"subprocess", "os.system", "os.popen", "os.execv",
                     "os.spawnv", "multiprocessing", "pty", "commands"}
        for path in product_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for name, line in _imported_names(tree):
                if name in forbidden:
                    self.fail(f"{path.relative_to(ROOT)}:{line} imports "
                              f"{name!r}; the product does not shell out")
            for name, line in _called_names(tree):
                if name in ("system", "popen", "execv", "spawnv", "run",
                            "Popen", "check_output", "check_call"):
                    source = path.read_text(encoding="utf-8").splitlines()
                    text = source[line - 1] if line <= len(source) else ""
                    # `.run(` is common on unrelated objects; only flag it when
                    # the line actually references subprocess or os.
                    if re.search(r"\b(subprocess|os)\s*\.", text):
                        self.fail(
                            f"{path.relative_to(ROOT)}:{line} shells out: "
                            f"{text.strip()!r}")


class InboundBindIsStillAllowed(unittest.TestCase):
    """Containment restricts OUTBOUND traffic; serving a local page is fine."""

    def test_the_server_defaults_to_a_loopback_bind(self):
        from src.api import server
        from src.config import load_config
        self.assertTrue(server.is_loopback(str(load_config().api.host)))

    def test_non_loopback_hosts_are_recognised(self):
        from src.api import server
        for host in ("127.0.0.1", "localhost", "::1"):
            self.assertTrue(server.is_loopback(host), host)
        for host in ("0.0.0.0", "10.0.0.5", "example.com"):
            self.assertFalse(server.is_loopback(host), host)

    def test_exposing_the_service_requires_an_explicit_acknowledgement(self):
        import contextlib
        import io as _io

        from src.api import server
        # argparse prints its usage to stderr on error; swallow it so the test
        # run's output stays readable.
        with contextlib.redirect_stderr(_io.StringIO()) as captured:
            with self.assertRaises(SystemExit):
                server.main(["--host", "0.0.0.0"])
        self.assertIn("not a loopback address", captured.getvalue())


class AssetsAreSelfHosted(unittest.TestCase):
    """The strict Content-Security-Policy has to be backed by the files."""

    def _assets(self) -> list[Path]:
        base = ROOT / "src" / "api"
        return (sorted((base / "templates").glob("*.html"))
                + sorted((base / "static").glob("*.css"))
                + sorted((base / "static").glob("*.js")))

    def test_there_are_assets_to_check(self):
        self.assertGreater(len(self._assets()), 8)

    def test_no_template_or_asset_references_an_external_origin(self):
        # Matches a real URL in markup or CSS, not the word "https" in prose.
        url = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+)["']"""
                         r"""|url\(\s*["']?([^"')]+)""", re.IGNORECASE)
        for path in self._assets():
            text = path.read_text(encoding="utf-8")
            for match in url.finditer(text):
                target = match.group(1) or match.group(2) or ""
                if target.startswith(("http://", "https://", "//")):
                    self.fail(f"{path.name} references external {target!r}")

    def test_no_asset_contains_a_fetch_or_xhr_call(self):
        js = (ROOT / "src" / "api" / "static" / "app.js").read_text(
            encoding="utf-8")
        for primitive in ("fetch(", "XMLHttpRequest", "WebSocket",
                          "navigator.sendBeacon", "EventSource", "import("):
            self.assertNotIn(primitive, js,
                             f"app.js uses {primitive}; the dashboard makes no "
                             "requests of its own")

    def test_the_csp_permits_only_self(self):
        from src.api.security import SECURITY_HEADERS
        csp = SECURITY_HEADERS["Content-Security-Policy"]
        self.assertNotIn("http://", csp)
        self.assertNotIn("https://", csp)
        self.assertNotIn("*", csp)
        for directive in ("default-src 'self'", "object-src 'none'",
                          "frame-ancestors 'none'", "base-uri 'none'"):
            self.assertIn(directive, csp)


class NoBotnetOrAttackCapability(unittest.TestCase):
    """The product reads metadata and classifies shapes. Nothing more.

    A plain-text scan is right here: these are names that would appear in code
    OR in a helpful-looking comment, and neither belongs in this tree.

    NAMING A BEHAVIOUR IS NOT PERFORMING IT. A detection tool has to talk about
    what it detects: `src/ingest/iot23_labels.py` matches the literal strings
    "ddos", "portscan" and "mirai" because those are IoT-23's own annotations,
    and `upnp_addportmapping` is a FEATURE COLUMN — a thing the product looks
    for. So the terms below are deliberately ACTION-SHAPED (a call, or a verb
    plus an object) rather than bare nouns: `ddos_attack(` is capability,
    "ddos" in a label table is vocabulary, and a test that cannot tell them
    apart would force the product to stop naming what it detects.
    """

    FORBIDDEN_TERMS = (
        "AddPortMapping(", "upnp_client", "port_forward(", "start_relay",
        "forward_packet", "send_packet", "c2_server", "command_and_control(",
        "launch_ddos", "ddos_attack(", "syn_flood", "port_scan(", "exploit(",
        "payload_deliver", "reverse_shell", "bind_shell", "eth_call",
        "json_rpc_request", "resolve_ens(", "from web3", "import web3",
        "infura.io",
    )

    def test_no_product_module_contains_an_offensive_primitive(self):
        for path in product_files():
            lowered = path.read_text(encoding="utf-8").lower()
            for term in self.FORBIDDEN_TERMS:
                if term.lower() in lowered:
                    self.fail(f"{path.relative_to(ROOT)} contains {term!r}; "
                              "this product is defensive-only and builds no "
                              "attack, relay or blockchain-query capability")

    def test_upnp_and_ens_appear_only_as_feature_names(self):
        """The features are named after behaviours the product LOOKS FOR.

        `upnp_addportmapping` and `ens_query_rate` are measurements, and must
        never be accompanied by anything that performs the operation.
        """
        from src.schema import columns as K
        self.assertIn("upnp_addportmapping", K.FEATURE_COLS)
        self.assertIn("ens_query_rate", K.FEATURE_COLS)


if __name__ == "__main__":
    unittest.main()
