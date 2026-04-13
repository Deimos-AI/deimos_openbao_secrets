"""Test suite for helpers/auth_proxy.py — REM-009 (TST-01, Sprint 3).

Acceptance criteria covered:
  AC-01  This file exists at tests/test_auth_proxy.py
  AC-02  bind — start() binds to 127.0.0.1 on an ephemeral port and returns it
  AC-03  idempotency — second start() returns same port; no new thread spawned
  AC-04  auth injection — correct header name + format per PROVIDER_REGISTRY entry
  AC-05  sentinel stripping — proxy-a0 sentinel not forwarded to upstream
  AC-06  SSE streaming — upstream SSE content forwarded verbatim to caller
  AC-07  stop — port closed after stop(); stop() idempotent; stop-before-start safe
  AC-08  local only — proxy binds 127.0.0.1, not 0.0.0.0
  AC-09  All tests pass with pytest 0 failures

Approach
--------
A real loopback HTTPServer acts as the mock upstream.  By patching
``helpers.auth_proxy.PROVIDER_REGISTRY`` to redirect all upstream URLs to this
server we can inspect exactly which headers the proxy forwarded without making
any real external network calls.

``AuthProxy._get_secret`` is patched on each instance to return a known
test credential, bypassing OpenBao lookup entirely.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar, Dict, List, Optional
from unittest.mock import patch

import pytest
import requests

# Plugin root must be on sys.path (conftest.py does this; belt-and-suspenders)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openbao_helpers.auth_proxy import AuthProxy, PROVIDER_REGISTRY  # noqa: E402


# ---------------------------------------------------------------------------
# Shared request log
# ---------------------------------------------------------------------------

class _RequestLog:
    """Thread-safe list of captured upstream request records."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: List[Dict] = []

    def append(self, entry: Dict) -> None:
        with self._lock:
            self._entries.append(entry)

    def latest(self) -> Optional[Dict]:
        with self._lock:
            return self._entries[-1] if self._entries else None

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_LOG = _RequestLog()


# ---------------------------------------------------------------------------
# Mock upstream HTTP server
# ---------------------------------------------------------------------------

class _MockUpstreamHandler(BaseHTTPRequestHandler):
    """Records each inbound request and returns a canned response."""

    sse_mode: ClassVar[bool] = False  # toggled True for SSE tests

    def do_GET(self) -> None:    self._handle()
    def do_POST(self) -> None:   self._handle()
    def do_PUT(self) -> None:    self._handle()
    def do_DELETE(self) -> None: self._handle()
    def do_HEAD(self) -> None:   self._handle()

    def _handle(self) -> None:
        _LOG.append({
            "method": self.command,
            "path":   self.path,
            "headers": dict(self.headers),
        })
        if _MockUpstreamHandler.sse_mode:
            body = b"data: chunk1\n\ndata: chunk2\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
        else:
            body = b"upstream ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def log_message(self, *args: object) -> None:  # suppress server noise
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mock_upstream_port():
    """Start a loopback mock HTTP server; yield its port; shut it down."""
    srv = HTTPServer(("127.0.0.1", 0), _MockUpstreamHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield port
    srv.shutdown()


@pytest.fixture(autouse=True)
def reset_log_and_mode() -> None:
    """Reset shared state before every test."""
    _LOG.clear()
    _MockUpstreamHandler.sse_mode = False


@pytest.fixture
def proxy_against_mock(mock_upstream_port):
    """AuthProxy whose upstream URLs are redirected to the mock server.

    Yields (proxy, proxy_port). _get_secret returns 'test-real-key'.
    PROVIDER_REGISTRY is patched to use the loopback mock upstream.
    """
    base = f"http://127.0.0.1:{mock_upstream_port}"
    patched_registry = {
        slug: {**cfg, "upstream": base}
        for slug, cfg in PROVIDER_REGISTRY.items()
    }

    proxy = AuthProxy()
    m_secret = patch.object(proxy, "_get_secret", return_value="test-real-key")
    m_reg = patch("openbao_helpers.auth_proxy.PROVIDER_REGISTRY", patched_registry)

    m_secret.start()
    m_reg.start()
    try:
        port = proxy.start()
        yield proxy, port
    finally:
        proxy.stop()
        m_reg.stop()
        m_secret.stop()


# ---------------------------------------------------------------------------
# Helper: case-insensitive header lookup
# ---------------------------------------------------------------------------

def _hdr(headers: dict, name: str) -> Optional[str]:
    """Return header value matching ``name`` (case-insensitive), or None."""
    nl = name.lower()
    for k, v in headers.items():
        if k.lower() == nl:
            return v
    return None


# ---------------------------------------------------------------------------
# AC-02 — Bind
# ---------------------------------------------------------------------------

class TestBind:
    """AC-02: start() binds to 127.0.0.1 on an ephemeral port and returns it."""

    def test_start_returns_positive_integer_port(self):
        """start() returns an integer in the valid port range."""
        proxy = AuthProxy()
        try:
            port = proxy.start()
            assert isinstance(port, int)
            assert 1 <= port <= 65535
        finally:
            proxy.stop()

    def test_returned_port_is_actively_listening(self):
        """The returned port accepts TCP connections immediately after start()."""
        proxy = AuthProxy()
        try:
            port = proxy.start()
            # Successful connect confirms the port is bound and listening
            with socket.create_connection(("127.0.0.1", port), timeout=3):
                pass
        finally:
            proxy.stop()


# ---------------------------------------------------------------------------
# AC-03 — Idempotency
# ---------------------------------------------------------------------------

class TestIdempotency:
    """AC-03: start() called twice returns same port; no extra thread spawned."""

    def test_second_start_returns_same_port(self):
        proxy = AuthProxy()
        try:
            port1 = proxy.start()
            port2 = proxy.start()
            assert port1 == port2
        finally:
            proxy.stop()

    def test_second_start_does_not_spawn_new_thread(self):
        """A second start() must reuse the existing daemon thread."""
        proxy = AuthProxy()
        try:
            proxy.start()
            thread_ref = proxy._thread
            proxy.start()
            assert proxy._thread is thread_ref, (
                "start() spawned a new thread on the second call"
            )
        finally:
            proxy.stop()


# ---------------------------------------------------------------------------
# AC-04 — Auth injection per provider
# ---------------------------------------------------------------------------

class TestAuthInjection:
    """AC-04: Correct auth header name and format injected per provider."""

    @pytest.mark.parametrize("slug", list(PROVIDER_REGISTRY))
    def test_correct_header_and_format_for_provider(
        self, proxy_against_mock, slug
    ):
        """For each provider: upstream receives the correct auth header value."""
        proxy, proxy_port = proxy_against_mock
        cfg = PROVIDER_REGISTRY[slug]
        expected_value = cfg["format"].format(key="test-real-key")

        r = requests.get(
            f"http://127.0.0.1:{proxy_port}/proxy/{slug}/api/test",
            timeout=5,
        )
        assert r.status_code == 200, (
            f"Proxy returned {r.status_code} for {slug}: {r.text!r}"
        )

        entry = _LOG.latest()
        assert entry is not None, "Mock upstream received no request"

        actual_value = _hdr(entry["headers"], cfg["auth_header"])
        assert actual_value == expected_value, (
            f"[{slug}] {cfg['auth_header']}: expected {expected_value!r}, "
            f"got {actual_value!r}.\nAll upstream headers: {entry['headers']}"
        )


# ---------------------------------------------------------------------------
# AC-05 — Sentinel stripping
# ---------------------------------------------------------------------------

class TestSentinelStripping:
    """AC-05: proxy-a0 sentinel values are stripped before reaching upstream."""

    def test_bearer_proxy_a0_not_forwarded(self, proxy_against_mock):
        """'Authorization: Bearer proxy-a0' replaced by real credential."""
        _, proxy_port = proxy_against_mock
        r = requests.get(
            f"http://127.0.0.1:{proxy_port}/proxy/openai/v1/models",
            headers={"Authorization": "Bearer proxy-a0"},
            timeout=5,
        )
        assert r.status_code == 200

        entry = _LOG.latest()
        assert entry is not None, "Mock upstream received no request"
        auth = _hdr(entry["headers"], "Authorization") or ""

        assert "proxy-a0" not in auth.lower(), (
            f"Sentinel 'proxy-a0' leaked to upstream: Authorization={auth!r}"
        )
        assert "test-real-key" in auth, (
            f"Real credential absent from upstream: Authorization={auth!r}"
        )

    def test_x_api_key_proxy_a0_not_forwarded(self, proxy_against_mock):
        """'x-api-key: proxy-a0' replaced by real credential (anthropic)."""
        _, proxy_port = proxy_against_mock
        r = requests.get(
            f"http://127.0.0.1:{proxy_port}/proxy/anthropic/v1/messages",
            headers={"x-api-key": "proxy-a0"},
            timeout=5,
        )
        assert r.status_code == 200

        entry = _LOG.latest()
        assert entry is not None, "Mock upstream received no request"
        key_val = _hdr(entry["headers"], "x-api-key") or ""

        assert "proxy-a0" not in key_val.lower(), (
            f"Sentinel 'proxy-a0' leaked to upstream: x-api-key={key_val!r}"
        )
        assert "test-real-key" in key_val, (
            f"Real credential absent from upstream: x-api-key={key_val!r}"
        )


# ---------------------------------------------------------------------------
# AC-06 — SSE streaming
# ---------------------------------------------------------------------------

class TestSSEStreaming:
    """AC-06: SSE-formatted upstream response is forwarded to the caller."""

    def test_sse_body_forwarded_verbatim(self, proxy_against_mock):
        """SSE data chunks from upstream appear in the proxied response body."""
        _, proxy_port = proxy_against_mock
        _MockUpstreamHandler.sse_mode = True

        r = requests.get(
            f"http://127.0.0.1:{proxy_port}/proxy/openai/v1/completions",
            stream=True,
            timeout=5,
        )
        body = r.content  # reads full body; works for both chunked + C-L responses
        assert b"data: chunk1" in body, f"First SSE event missing. Body: {body!r}"
        assert b"data: chunk2" in body, f"Second SSE event missing. Body: {body!r}"

    def test_sse_content_type_preserved(self, proxy_against_mock):
        """Content-Type: text/event-stream header is preserved end-to-end."""
        _, proxy_port = proxy_against_mock
        _MockUpstreamHandler.sse_mode = True

        r = requests.get(
            f"http://127.0.0.1:{proxy_port}/proxy/openai/v1/completions",
            stream=True,
            timeout=5,
        )
        ct = r.headers.get("Content-Type", "")
        r.close()
        assert "text/event-stream" in ct, (
            f"Expected Content-Type: text/event-stream, got: {ct!r}"
        )


# ---------------------------------------------------------------------------
# AC-07 — Stop
# ---------------------------------------------------------------------------

class TestStop:
    """AC-07: stop() shuts the proxy; idempotent; safe before start."""

    def test_port_no_longer_accepts_connections_after_stop(self):
        """After stop(), attempts to connect to the proxy port are refused."""
        proxy = AuthProxy()
        port = proxy.start()
        # Confirm the proxy is up
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            pass
        proxy.stop()
        # Wait for the OS to release the port (stop() blocks until cleanup)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                time.sleep(0.1)  # still open — wait and retry
            except OSError:
                return  # ECONNREFUSED / timeout — port closed as expected
        pytest.fail(f"Port {port} still accepting connections 3 s after stop()")

    def test_stop_idempotent(self):
        """Calling stop() twice must not raise."""
        proxy = AuthProxy()
        proxy.start()
        proxy.stop()
        proxy.stop()  # second call — must be a no-op

    def test_stop_before_start_does_not_raise(self):
        """stop() on a proxy that was never started must not raise."""
        AuthProxy().stop()


# ---------------------------------------------------------------------------
# AC-08 — Local only (127.0.0.1, never 0.0.0.0)
# ---------------------------------------------------------------------------

class TestLocalOnly:
    """AC-08: proxy binds to 127.0.0.1 only — not 0.0.0.0."""

    def test_proxy_reachable_on_loopback(self):
        """The proxy is connectable via 127.0.0.1."""
        proxy = AuthProxy()
        try:
            port = proxy.start()
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                pass  # connection succeeds
        finally:
            proxy.stop()

    def test_proxy_not_reachable_on_non_loopback(self):
        """The proxy is NOT reachable via a non-loopback IP (127.0.0.1 binding only)."""
        proxy = AuthProxy()
        try:
            port = proxy.start()

            # Resolve a non-loopback IP for this host
            try:
                host_ip = socket.gethostbyname(socket.gethostname())
            except socket.gaierror:
                pytest.skip("Cannot resolve hostname — skipping non-loopback check")

            if host_ip.startswith("127."):
                pytest.skip(
                    f"Hostname resolves to loopback ({host_ip}) — "
                    "cannot distinguish binding scope in this environment"
                )

            # Port must NOT be reachable on the non-loopback interface
            try:
                with socket.create_connection((host_ip, port), timeout=1):
                    pytest.fail(
                        f"Proxy is reachable on {host_ip}:{port} — "
                        "should be loopback-only (127.0.0.1)"
                    )
            except OSError:
                pass  # ConnectionRefusedError or timeout — expected
        finally:
            proxy.stop()
