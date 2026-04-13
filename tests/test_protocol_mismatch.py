"""Tests for protocol mismatch handling — issue #18.

Verifies that HTTP/HTTPS protocol mismatches produce a single clean failure
instead of cascading retry errors that block Agent Zero boot.

Root causes addressed:
    RC-1: validate_config() only checks URL prefix — no server probe
    RC-2: _connect() does not set _client=None on auth failure
    RC-3: Protocol errors classified as TRANSIENT (retry cascade)

Fix layers:
    Layer 1: Health probe in _connect() detects protocol mismatch early
    Layer 2: ssl.SSLError reclassified as PERMANENT (no retry)
    Layer 3: _client=None on is_authenticated() failure

Satisfies: AC-01 through AC-05
"""
import os
import ssl
import sys
import logging
import pytest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from openbao_helpers.config import OpenBaoConfig
from openbao_helpers.openbao_client import OpenBaoClient, PERMANENT_ERRORS, _PROTOCOL_MISMATCH_MARKERS


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture
def base_config():
    """Config with token auth for simplicity."""
    return OpenBaoConfig(
        enabled=True,
        url="http://127.0.0.1:8200",
        auth_method="token",
        token="hvs.test-token",
        mount_point="secret",
        secrets_path="agentzero",
        timeout=5.0,
        cache_ttl=10,
        retry_attempts=2,
        circuit_breaker_threshold=3,
        circuit_breaker_recovery=5,
    )


@pytest.fixture
def https_config():
    """Config pointing at HTTPS URL (for mismatch tests)."""
    return OpenBaoConfig(
        enabled=True,
        url="https://127.0.0.1:8200",
        auth_method="token",
        token="hvs.test-token",
        mount_point="secret",
        secrets_path="agentzero",
        timeout=5.0,
        cache_ttl=10,
        retry_attempts=2,
        circuit_breaker_threshold=3,
        circuit_breaker_recovery=5,
    )


@pytest.fixture
def mock_hvac_client():
    """Mocked hvac.Client that appears authenticated."""
    client = MagicMock()
    client.is_authenticated.return_value = True
    client.auth.token.lookup_self.return_value = {
        "data": {"ttl": 3600}
    }
    client.sys.read_health_status.return_value = {
        "initialized": True,
        "sealed": False,
        "standby": False,
        "server_time_utc": 1234567890,
    }
    client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {
                "API_KEY": "sk-test-123",
            }
        }
    }
    return client


# ── AC-01: Protocol mismatch caught during _connect() ─────────

class TestProtocolMismatchDetection:
    """AC-01: Protocol mismatch caught during _connect(), single error
    logged, _client set to None."""

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_ssl_error_in_probe_sets_client_none(self, mock_hvac_cls, base_config):
        """AC-01: ssl.SSLError during health probe kills client."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.side_effect = ssl.SSLError(
            "SSL: WRONG_VERSION_NUMBER"
        )
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)  # AC-01
        assert client._client is None  # AC-01: decisively killed
        assert not client.is_connected()  # AC-01

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_ssl_error_logs_single_protocol_message(self, mock_hvac_cls, base_config, caplog):
        """AC-01: Single clear 'Protocol mismatch' log on SSL error."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.side_effect = ssl.SSLError(
            "SSL: WRONG_VERSION_NUMBER"
        )
        mock_hvac_cls.return_value = mock_client

        with caplog.at_level(logging.ERROR, logger="openbao_helpers.openbao_client"):
            client = OpenBaoClient(base_config)  # AC-01

        protocol_errors = [
            r for r in caplog.records
            if r.levelno >= logging.ERROR and "protocol mismatch" in r.message.lower()
        ]
        assert len(protocol_errors) >= 1  # AC-01: at least one clear message

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_protocol_mismatch_string_detection(self, mock_hvac_cls, base_config):
        """AC-01: Non-SSLError with protocol mismatch string also kills client."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.side_effect = ConnectionError(
            "Client sent an HTTP request to an HTTPS server"
        )
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)  # AC-01
        assert client._client is None  # AC-01: killed by string detection
        assert not client.is_connected()

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_non_protocol_connection_error_allows_retry(self, mock_hvac_cls, base_config):
        """AC-01: Regular ConnectionError during probe does NOT kill client."""
        mock_client = MagicMock()
        # First call (probe) fails, second call (auth check) succeeds
        mock_client.sys.read_health_status.side_effect = [
            ConnectionError("Connection refused"),  # probe failure — not protocol mismatch
            {"initialized": True, "sealed": False},  # subsequent health check
        ]
        mock_client.is_authenticated.return_value = True
        mock_client.auth.token.lookup_self.return_value = {"data": {"ttl": 3600}}
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)
        # Connection refused is NOT a protocol mismatch — client should still attempt auth
        # But since the probe failed with generic ConnectionError, auth proceeds
        assert client._client is not None  # AC-01: NOT killed — only protocol mismatch kills


# ── AC-02: No cascading retries ────────────────────────────────

class TestPermanentErrorClassification:
    """AC-02: PERMANENT error classification prevents retry loop."""

    def test_ssl_error_in_permanent_errors(self):
        """AC-02: ssl.SSLError is in PERMANENT_ERRORS tuple."""
        assert ssl.SSLError in PERMANENT_ERRORS  # AC-02

    def test_protocol_mismatch_markers_defined(self):
        """AC-02: Protocol mismatch markers are defined for detection."""
        assert len(_PROTOCOL_MISMATCH_MARKERS) > 0  # AC-02
        # Verify key marker strings
        markers_lower = [m.lower() for m in _PROTOCOL_MISMATCH_MARKERS]
        assert any("http" in m and "https" in m for m in markers_lower)  # AC-02

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_ssl_error_in_fetch_raises_runtime_not_retried(self, mock_hvac_cls, base_config):
        """AC-02: SSLError in _fetch() raises RuntimeError (not in TRANSIENT_ERRORS)."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.return_value = {
            "initialized": True, "sealed": False,
        }
        mock_client.is_authenticated.return_value = True
        mock_client.auth.token.lookup_self.return_value = {"data": {"ttl": 3600}}
        # Simulate SSLError during actual secrets read (not during connect probe)
        mock_client.secrets.kv.v2.read_secret_version.side_effect = ssl.SSLError(
            "SSL: WRONG_VERSION_NUMBER"
        )
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)
        # Clear cache to force fetch
        client.invalidate_cache()

        # RuntimeError is NOT in TRANSIENT_ERRORS, so no retry cascade
        with pytest.raises(RuntimeError, match="Protocol mismatch"):  # AC-02
            client.read_all_secrets()

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_no_retry_count_on_ssl_error(self, mock_hvac_cls, base_config):
        """AC-02: SSLError triggers exactly one read attempt, not retry cascade."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.return_value = {
            "initialized": True, "sealed": False,
        }
        mock_client.is_authenticated.return_value = True
        mock_client.auth.token.lookup_self.return_value = {"data": {"ttl": 3600}}
        mock_client.secrets.kv.v2.read_secret_version.side_effect = ssl.SSLError(
            "SSL: WRONG_VERSION_NUMBER"
        )
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)
        client.invalidate_cache()

        with pytest.raises(RuntimeError):  # AC-02
            client.read_all_secrets()

        # read_secret_version called exactly once — no retries
        assert mock_client.secrets.kv.v2.read_secret_version.call_count == 1  # AC-02


# ── AC-03: Fallback to .env works ──────────────────────────────

class TestFallbackBehavior:
    """AC-03: Agent Zero boots regardless — fallback to .env works."""

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_protocol_mismatch_client_not_connected(self, mock_hvac_cls, base_config):
        """AC-03: Protocol mismatch results in is_connected()=False."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.side_effect = ssl.SSLError(
            "SSL: WRONG_VERSION_NUMBER"
        )
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)
        assert not client.is_connected()  # AC-03: not connected → fallback path

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_protocol_mismatch_no_exception_raised(self, mock_hvac_cls, base_config):
        """AC-03: Constructor does not raise — caller can proceed with fallback."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.side_effect = ssl.SSLError(
            "SSL: WRONG_VERSION_NUMBER"
        )
        mock_hvac_cls.return_value = mock_client

        # Constructor should NOT raise — graceful degradation
        client = OpenBaoClient(base_config)  # AC-03: no exception
        assert client._client is None  # AC-03

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_health_check_returns_disconnected(self, mock_hvac_cls, base_config):
        """AC-03: health_check() on mismatched client returns disconnected."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.side_effect = ssl.SSLError(
            "SSL: WRONG_VERSION_NUMBER"
        )
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)
        health = client.health_check()  # AC-03
        assert health["connected"] is False
        assert health["authenticated"] is False


# ── AC-04: Clean error on hard_fail ────────────────────────────

class TestHardFailCleanError:
    """AC-04: hard_fail_on_unavailable=true raises single clean RuntimeError.

    Note: hard_fail_on_unavailable is enforced at the manager layer, not in
    OpenBaoClient itself. These tests verify that the client produces a clean
    state (single error, _client=None) that the manager can check.
    """

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_single_error_log_on_mismatch(self, mock_hvac_cls, base_config, caplog):
        """AC-04: Protocol mismatch produces exactly one error, not a cascade."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.side_effect = ssl.SSLError(
            "SSL: WRONG_VERSION_NUMBER"
        )
        mock_hvac_cls.return_value = mock_client

        with caplog.at_level(logging.WARNING, logger="openbao_helpers.openbao_client"):
            client = OpenBaoClient(base_config)  # AC-04

        # Count error-level protocol messages — should be exactly 1
        protocol_errors = [
            r for r in caplog.records
            if r.levelno >= logging.ERROR and "protocol" in r.message.lower()
        ]
        assert len(protocol_errors) == 1  # AC-04: single clean error

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_client_state_is_clean_after_mismatch(self, mock_hvac_cls, base_config):
        """AC-04: Client state is fully clean — no lingering references."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.side_effect = ssl.SSLError(
            "SSL: WRONG_VERSION_NUMBER"
        )
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)
        assert client._client is None  # AC-04: no dangling client
        assert not client.is_connected()  # AC-04: clean state


# ── AC-05: is_authenticated() failure → _client = None ─────────

class TestAuthFailureKillsClient:
    """AC-05: is_authenticated() failure results in _client = None."""

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_auth_failure_sets_client_none(self, mock_hvac_cls, base_config):
        """AC-05: When is_authenticated() returns False, _client is set to None."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.return_value = {
            "initialized": True, "sealed": False,
        }
        mock_client.is_authenticated.return_value = False  # AC-05
        mock_client.auth.token.lookup_self.return_value = {"data": {"ttl": 0}}
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)
        assert client._client is None  # AC-05: killed on auth failure

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_auth_failure_not_connected(self, mock_hvac_cls, base_config):
        """AC-05: Auth failure means is_connected() returns False."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.return_value = {
            "initialized": True, "sealed": False,
        }
        mock_client.is_authenticated.return_value = False  # AC-05
        mock_client.auth.token.lookup_self.return_value = {"data": {"ttl": 0}}
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)
        assert not client.is_connected()  # AC-05

    @patch("openbao_helpers.openbao_client.hvac.Client")
    def test_auth_failure_prevents_token_renewal_path(self, mock_hvac_cls, base_config):
        """AC-05: With _client=None, token renewal is a no-op (no cascade)."""
        mock_client = MagicMock()
        mock_client.sys.read_health_status.return_value = {
            "initialized": True, "sealed": False,
        }
        mock_client.is_authenticated.return_value = False  # AC-05
        mock_client.auth.token.lookup_self.return_value = {"data": {"ttl": 0}}
        mock_hvac_cls.return_value = mock_client

        client = OpenBaoClient(base_config)
        assert client._client is None  # AC-05

        # Token renewal should be a no-op
        client._ensure_token_valid()  # should not raise  # AC-05
        assert mock_client.auth.token.renew_self.call_count == 0  # no renewal attempt
