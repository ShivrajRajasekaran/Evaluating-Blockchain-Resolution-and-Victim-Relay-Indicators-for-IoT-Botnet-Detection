"""
tests/asgi_shim — a minimal ASGI client, so the HTTP tests need no httpx.

WHY THIS EXISTS
    Starlette's own ``TestClient`` imports httpx, which is not installed and
    whose installation was not approved. More to the point, httpx is an
    outbound HTTP client: adding it to this project's dependency tree would put
    a network-capable library inside a product whose containment tests assert
    that no such thing is importable from the product packages.

    So the tests drive the ASGI application directly. There is no socket, no
    loopback connection and no server — the app's ``__call__`` is awaited with
    a hand-built scope and the response messages are collected. That is both
    faster and a more honest test of the application than one that proves a TCP
    stack works.

WHAT IT SUPPORTS
    GET and POST, query strings, headers, a cookie jar that persists across
    requests (so a login really does authenticate the next call), form-encoded
    and multipart bodies, JSON bodies, and redirect following. Enough to
    exercise every route this product has; deliberately not a general-purpose
    client.
"""
from __future__ import annotations

import asyncio
import json as jsonlib
import secrets
from http.cookies import SimpleCookie
from urllib.parse import urlencode, urlsplit


class Response:
    """What the application sent back."""

    def __init__(self, status: int, headers: list[tuple[bytes, bytes]],
                 body: bytes):
        self.status_code = status
        self.raw_headers = headers
        self.content = body
        self.headers = {}
        for key, value in headers:
            name = key.decode("latin-1").lower()
            text = value.decode("latin-1")
            # set-cookie legitimately repeats; everything else takes the last.
            if name in self.headers:
                self.headers[name] += ", " + text
            else:
                self.headers[name] = text

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self):
        return jsonlib.loads(self.content.decode("utf-8"))

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)

    @property
    def location(self) -> str:
        return self.headers.get("location", "")

    def __repr__(self) -> str:
        return f"<Response {self.status_code} {len(self.content)}b>"


class Client:
    """Drives an ASGI app in-process, keeping cookies between calls."""

    def __init__(self, app, *, base_host: str = "testserver",
                 client_host: str = "127.0.0.1"):
        self.app = app
        self.base_host = base_host
        self.client_host = client_host
        self.cookies: dict[str, str] = {}

    # -- verbs -----------------------------------------------------------
    def get(self, path: str, **kw) -> Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> Response:
        return self.request("POST", path, **kw)

    def request(self, method: str, path: str, *, data=None, json=None,
                files=None, headers=None, follow_redirects: bool = False,
                max_redirects: int = 5) -> Response:
        body, content_type = _encode_body(data, json, files)
        response = asyncio.run(
            self._send(method, path, body, content_type, headers or {}))
        self._absorb_cookies(response)

        redirects = 0
        while follow_redirects and response.is_redirect and redirects < max_redirects:
            target = response.location or "/"
            # A redirect after POST is followed as a GET, as a browser does.
            response = asyncio.run(
                self._send("GET", target, b"", None, headers or {}))
            self._absorb_cookies(response)
            redirects += 1
        return response

    # -- internals -------------------------------------------------------
    async def _send(self, method: str, path: str, body: bytes,
                    content_type: str | None, extra_headers: dict) -> Response:
        split = urlsplit(path)
        raw_headers: list[tuple[bytes, bytes]] = [
            (b"host", self.base_host.encode()),
            (b"user-agent", b"als-test-shim"),
            (b"accept", b"text/html,application/xhtml+xml"),
        ]
        if content_type:
            raw_headers.append((b"content-type", content_type.encode()))
        if body:
            raw_headers.append((b"content-length", str(len(body)).encode()))
        if self.cookies:
            jar = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            raw_headers.append((b"cookie", jar.encode()))
        for key, value in extra_headers.items():
            # An explicit header replaces the default of the same name.
            lowered = key.lower().encode()
            raw_headers = [h for h in raw_headers if h[0] != lowered]
            raw_headers.append((lowered, str(value).encode()))

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method.upper(),
            "scheme": "http",
            "path": split.path or "/",
            "raw_path": (split.path or "/").encode(),
            "query_string": split.query.encode(),
            "root_path": "",
            "headers": raw_headers,
            "client": (self.client_host, 54321),
            "server": (self.base_host, 80),
            "app": self.app,
        }

        sent = {"done": False}

        async def receive():
            if sent["done"]:
                return {"type": "http.disconnect"}
            sent["done"] = True
            return {"type": "http.request", "body": body, "more_body": False}

        status = {"code": 500}
        out_headers: list[tuple[bytes, bytes]] = []
        chunks: list[bytes] = []

        async def send(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
                out_headers.extend(message.get("headers") or [])
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b"") or b"")

        await self.app(scope, receive, send)
        return Response(status["code"], out_headers, b"".join(chunks))

    def _absorb_cookies(self, response: Response) -> None:
        """Update the jar from Set-Cookie, honouring deletions."""
        for key, value in response.raw_headers:
            if key.decode("latin-1").lower() != "set-cookie":
                continue
            jar = SimpleCookie()
            jar.load(value.decode("latin-1"))
            for name, morsel in jar.items():
                expires = morsel.get("max-age")
                if morsel.value == "" or (expires and str(expires) == "0"):
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = morsel.value


def _encode_body(data, json, files) -> tuple[bytes, str | None]:
    """Encode a request body as JSON, form-encoded, or multipart."""
    if json is not None:
        return jsonlib.dumps(json).encode("utf-8"), "application/json"
    if files:
        return _multipart(data or {}, files)
    if data:
        return (urlencode(data, doseq=True).encode("utf-8"),
                "application/x-www-form-urlencoded")
    return b"", None


def _multipart(fields: dict, files: dict) -> tuple[bytes, str]:
    """A multipart/form-data body.

    ``files`` maps a field name to ``(filename, content)``; content may be str
    or bytes. Deliberately literal rather than using the email package, so a
    test that needs a pathological filename can simply pass one.
    """
    boundary = f"----als{secrets.token_hex(12)}"
    parts: list[bytes] = []
    for name, value in fields.items():
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n".encode("utf-8"))
    for name, (filename, content) in files.items():
        if isinstance(content, str):
            content = content.encode("utf-8")
        head = (f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n")
        parts.append(head.encode("utf-8") + content + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"
