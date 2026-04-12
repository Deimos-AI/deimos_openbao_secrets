"""Tests for OpenBaoSecretsManager subclass.

Mocks the A0 framework SecretsManager since this plugin runs outside the
A0 runtime during testing. Uses sys.modules patching to intercept the
`python.helpers.secrets` import.

See Issue #4: https://192.168.200.52:3000/deimosAI/a0-plugin-openbao-secrets/issues/4
"""
import os
import sys
import threading
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from circuitbreaker import CircuitBreakerError

# Insert plugin root into path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Mock A0 framework modules before importing our code ───────

def _create_mock_secrets_manager():
    """Create a mock SecretsManager class that behaves like the real one."""
    class MockSecretsManager:
        PLACEHOLDER_PATTERN = r"dummy"
        MASK_VALUE = "***"
        _instances = {}

        def __init__(self, *files):
            self._lock = threading.RLock()
            self._files = tuple(files) if files else ("usr/secrets.env",)
            self._raw_snapshots = {}
            self._secrets_cache = None
            self._last_raw_text = None

        @classmethod
        def get_instance(cls, *files):
            key = tuple(files)
            if key not in cls._instances:
                cls._instances[key] = cls(*files)
            return cls._instances[key]

        def load_secrets(self):
            return {"FALLBACK_KEY": "fallback-value"}

        def get_keys(self):
            return list(self.load_secrets().keys())

        def get_secrets_for_prompt(self):
            return ""

        def clear_cache(self):
            self._secrets_cache = None
            self._raw_snapshots = {}
            self._last_raw_text = None

        @classmethod
        def _invalidate_all_caches(cls):
            for inst in cls._instances.values():
                inst.clear_cache()

    return MockSecretsManager


def _mock_alias_for_key(key, placeholder="secret_alias({key})"):
    return placeholder.format(key=key.upper())


# Install mock modules
MockSecretsManager = _create_mock_secrets_manager()

_mock_python = MagicMock()
_mock_python_helpers = MagicMock()
_mock_python_helpers_secrets = MagicMock()
_mock_python_helpers_secrets.SecretsManager = MockSecretsManager
_mock_python_helpers_secrets.alias_for_key = _mock_alias_for_key
_mock_python_helpers_secrets.DEFAULT_SECRETS_FILE = "usr/secrets.env"

sys.modules.setdefault("python", _mock_python)
sys.modules.setdefault("python.helpers", _mock_python_helpers)
sys.modules.setdefault("python.helpers.secrets", _mock_python_helpers_secrets)

# Now we can import our module
from helpers.config import OpenBaoConfig
from helpers.openbao_secrets_manager import OpenBaoSecretsManager


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_instances():
    """Clear singleton caches before each test."""
    OpenBaoSecretsManager._instances = {}
    MockSecretsManager._instances = {}
    yield
    OpenBaoSecretsManager._instances = {}
    MockSecretsManager._instances = {}


@pytest.fixture
def base_config():
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
        fallback_to_env=True,
        hard_fail_on_unavailable=False,
    )


@pytest.fixture
def disabled_config():
    return OpenBaoConfig(enabled=False, fallback_to_env=True, hard_fail_on_unavailable=False)


@pytest.fixture
def no_fallback_config():
    return OpenBaoConfig(
        enabled=True,
        url="http://127.0.0.1:8200",
        auth_method="token",
        token="hvs.test",
        fallback_to_env=False,
        hard_fail_on_unavailable=False,
    )


@pytest.fixture
def mock_bao_client():
    """Mock OpenBaoClient that returns test secrets."""
    client = MagicMock()
    client.is_connected.return_value = True
    client.read_all_secrets.return_value = {
        "API_KEY": "sk-test-123",
        "DB_PASSWORD": "secret-pw",
    }
    client.health_check.return_value = {
        "connected": True,
        "authenticated": True,
        "initialized": True,
        "sealed": False,
    }
    client.cache_age = 5.0
    client.list_secret_keys.return_value = ["API_KEY", "DB_PASSWORD"]  # E-07: bare names
    return client


@pytest.fixture
def mock_bao_client_down():
    """Mock OpenBaoClient that raises CircuitBreakerError."""
    client = MagicMock()
    client.is_connected.return_value = False
    client.read_all_secrets.side_effect = CircuitBreakerError(MagicMock())
    return client


@pytest.fixture
def manager_with_bao(base_config, mock_bao_client):
    """OpenBaoSecretsManager with mocked OpenBao client."""
    with patch("helpers.openbao_secrets_manager.OpenBaoClient", return_value=mock_bao_client):
        mgr = OpenBaoSecretsManager(base_config)
    return mgr


@pytest.fixture
def manager_disabled(disabled_config):
    """OpenBaoSecretsManager with OpenBao disabled."""
    mgr = OpenBaoSecretsManager(disabled_config)
    return mgr


@pytest.fixture
def manager_no_fallback(no_fallback_config, mock_bao_client_down):
    """Manager with OpenBao down and fallback disabled."""
    with patch("helpers.openbao_secrets_manager.OpenBaoClient", return_value=mock_bao_client_down):
        mgr = OpenBaoSecretsManager(no_fallback_config)
    return mgr


# ── Instance Management Tests ─────────────────────────────────

class TestInstanceManagement:
    def test_separate_instances_dict(self):
        """OpenBaoSecretsManager._instances must be separate from MockSecretsManager._instances."""
        assert OpenBaoSecretsManager._instances is not MockSecretsManager._instances

    def test_get_or_create_returns_singleton(self, base_config, mock_bao_client):
        with patch("helpers.openbao_secrets_manager.OpenBaoClient", return_value=mock_bao_client):
            mgr1 = OpenBaoSecretsManager.get_or_create(base_config)
            mgr2 = OpenBaoSecretsManager.get_or_create(base_config)
        assert mgr1 is mgr2

    def test_different_configs_get_different_instances(self, mock_bao_client):
        config1 = OpenBaoConfig(enabled=True, url="http://host1:8200", auth_method="token", token="t1")
        config2 = OpenBaoConfig(enabled=True, url="http://host2:8200", auth_method="token", token="t2")
        with patch("helpers.openbao_secrets_manager.OpenBaoClient", return_value=mock_bao_client):
            mgr1 = OpenBaoSecretsManager.get_or_create(config1)
            mgr2 = OpenBaoSecretsManager.get_or_create(config2)
        assert mgr1 is not mgr2


# ── Load Secrets Tests ────────────────────────────────────────

class TestLoadSecrets:
    def test_load_from_openbao(self, manager_with_bao):
        secrets = manager_with_bao.load_secrets()
        assert secrets == {"API_KEY": "sk-test-123", "DB_PASSWORD": "secret-pw"}

    def test_caches_result(self, manager_with_bao):
        secrets1 = manager_with_bao.load_secrets()
        secrets2 = manager_with_bao.load_secrets()
        assert secrets1 == secrets2
        # Should only call OpenBao once
        assert manager_with_bao._bao_client.read_all_secrets.call_count == 1

    def test_fallback_on_circuit_open(self, base_config, mock_bao_client_down):
        with patch("helpers.openbao_secrets_manager.OpenBaoClient", return_value=mock_bao_client_down):
            mgr = OpenBaoSecretsManager(base_config)
        secrets = mgr.load_secrets()
        assert mgr._fallback_active is True
        # Should get fallback secrets from parent
        assert "FALLBACK_KEY" in secrets

    def test_no_fallback_returns_empty(self, manager_no_fallback):
        secrets = manager_no_fallback.load_secrets()
        assert manager_no_fallback._fallback_active is False
        assert secrets == {}

    def test_disabled_config_uses_fallback(self, manager_disabled):
        assert manager_disabled._bao_client is None
        secrets = manager_disabled.load_secrets()
        # Falls back to parent .env loading
        assert "FALLBACK_KEY" in secrets

    def test_connection_error_triggers_fallback(self, base_config):
        bad_client = MagicMock()
        bad_client.is_connected.return_value = True
        bad_client.read_all_secrets.side_effect = ConnectionError("refused")
        with patch("helpers.openbao_secrets_manager.OpenBaoClient", return_value=bad_client):
            mgr = OpenBaoSecretsManager(base_config)
        secrets = mgr.load_secrets()
        assert mgr._fallback_active is True


# ── get_secrets_for_prompt Tests ──────────────────────────────

class TestGetSecretsForPrompt:
    def test_returns_key_names_only(self, manager_with_bao):
        """E-07 AC-02: get_secrets_for_prompt returns bare key names (not resolver aliases)."""
        result = manager_with_bao.get_secrets_for_prompt()
        # AC-02: bare sorted key names, comma-separated — no alias format
        assert "API_KEY" in result    # E-07: key name present
        assert "DB_PASSWORD" in result  # E-07: key name present
        assert "secret(" not in result  # E-07: no resolver alias format

    def test_empty_when_no_secrets(self, manager_no_fallback):
        result = manager_no_fallback.get_secrets_for_prompt()
        assert result == ""


# ── get_keys Tests ────────────────────────────────────────────

class TestGetKeys:
    def test_returns_key_list(self, manager_with_bao):
        keys = manager_with_bao.get_keys()
        assert set(keys) == {"API_KEY", "DB_PASSWORD"}


# ── Save Tests (read-only mode) ───────────────────────────────

class TestSaveNotSupported:
    def test_save_secrets_raises(self, manager_with_bao):
        with pytest.raises(NotImplementedError, match="read-only"):
            manager_with_bao.save_secrets("KEY=value")

    def test_save_secrets_with_merge_raises(self, manager_with_bao):
        with pytest.raises(NotImplementedError, match="read-only"):
            manager_with_bao.save_secrets_with_merge("KEY=value")


# ── Cache Management Tests ────────────────────────────────────

class TestCacheManagement:
    def test_clear_cache_invalidates_both(self, manager_with_bao):
        manager_with_bao.load_secrets()
        assert manager_with_bao._secrets_cache is not None
        manager_with_bao.clear_cache()
        assert manager_with_bao._secrets_cache is None
        manager_with_bao._bao_client.invalidate_cache.assert_called_once()


# ── Health Status Tests ───────────────────────────────────────

class TestHealthStatus:
    def test_with_openbao(self, manager_with_bao):
        status = manager_with_bao.health_status()
        assert status["enabled"] is True
        assert status["openbao"] is not None
        assert status["openbao"]["connected"] is True

    def test_without_openbao(self, manager_disabled):
        status = manager_disabled.health_status()
        assert status["enabled"] is False
        assert status["openbao"] is None


# ── is_available Tests ────────────────────────────────────────

class TestIsAvailable:
    def test_available_when_connected(self, manager_with_bao):
        assert manager_with_bao.is_available() is True

    def test_unavailable_when_disabled(self, manager_disabled):
        assert manager_disabled.is_available() is False

    def test_unavailable_when_client_down(self, manager_no_fallback):
        assert manager_no_fallback.is_available() is False


# ── Repr Tests ────────────────────────────────────────────────

class TestRepr:
    def test_repr_contains_info(self, manager_with_bao):
        r = repr(manager_with_bao)
        assert "OpenBaoSecretsManager" in r
        assert "127.0.0.1" in r


# ---------------------------------------------------------------------------
# E-07 AC-09: get_secrets_for_prompt() least-privilege override
# ---------------------------------------------------------------------------

def test_get_secrets_for_prompt_calls_list_secret_keys(manager_with_bao):
    """AC-01: list_secret_keys() called (metadata LIST, not load_secrets); AC-02: sorted names."""
    manager_with_bao._bao_client.list_secret_keys.return_value = [
        "ZEBRA_KEY", "ALPHA_TOKEN", "MIDDLE_SECRET"
    ]
    result = manager_with_bao.get_secrets_for_prompt()
    # AC-02: sorted bare key names, comma-separated
    assert result == "ALPHA_TOKEN, MIDDLE_SECRET, ZEBRA_KEY"
    # AC-01: list_secret_keys() was called (metadata LIST, not load_secrets)
    manager_with_bao._bao_client.list_secret_keys.assert_called_once()


def test_get_secrets_for_prompt_no_resolver_aliases(manager_with_bao):
    """AC-02: output contains no resolver alias pattern."""
    manager_with_bao._bao_client.list_secret_keys.return_value = ["API_KEY", "DB_PASS"]
    result = manager_with_bao.get_secrets_for_prompt()
    # AC-02: no alias pattern strings in output
    assert "secret(" not in result
    assert "secret_alias(" not in result


def test_get_secrets_for_prompt_does_not_call_load_secrets(manager_with_bao):
    """AC-01: load_secrets() is NOT called (no value decryption at prompt time)."""
    from unittest.mock import patch
    manager_with_bao._bao_client.list_secret_keys.return_value = ["KEY_A"]
    with patch.object(manager_with_bao, "load_secrets") as mock_load:
        manager_with_bao.get_secrets_for_prompt()
    # AC-01: no value decryption
    mock_load.assert_not_called()


def test_get_secrets_for_prompt_empty_vault_returns_empty(manager_with_bao):
    """AC-04: empty vault returns empty string (hides {{secrets}} block)."""
    manager_with_bao._bao_client.list_secret_keys.return_value = []
    result = manager_with_bao.get_secrets_for_prompt()
    assert result == ""  # AC-04


def test_get_secrets_for_prompt_no_client_falls_back(manager_disabled):
    """AC-03: no bao_client -> falls back to super().get_secrets_for_prompt()."""
    assert manager_disabled._bao_client is None
    # Should not raise, returns parent fallback
    result = manager_disabled.get_secrets_for_prompt()
    assert isinstance(result, str)  # AC-03: graceful fallback


def test_get_secrets_for_prompt_exception_falls_back(manager_with_bao):
    """AC-03: list_secret_keys() raises -> graceful fallback to super()."""
    manager_with_bao._bao_client.list_secret_keys.side_effect =         ConnectionError("vault unreachable")
    result = manager_with_bao.get_secrets_for_prompt()  # AC-03: no raise
    assert isinstance(result, str)  # fallback returns string, never raises


# ---------------------------------------------------------------------------
# E-07 AC-09: get_secrets_for_prompt() least-privilege override
# ---------------------------------------------------------------------------

def test_get_secrets_for_prompt_returns_key_names_only(manager_with_bao):
    """AC-01, AC-02: returns sorted key names only — no resolver aliases, no values."""
    manager_with_bao._bao_client.list_secret_keys.return_value = ["KEY_B", "KEY_A", "KEY_C"]
    result = manager_with_bao.get_secrets_for_prompt()
    # AC-02: bare key names, sorted, comma-separated — no $bao: prefix
    assert result == "KEY_A, KEY_B, KEY_C"  # AC-09
    # AC-01: no resolver alias format in result
    assert "$bao:" not in result
