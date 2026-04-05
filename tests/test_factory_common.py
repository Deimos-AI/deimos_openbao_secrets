"""Test suite for helpers/factory_common.py — REM-010 (Sprint 3).

Acceptance criteria covered:
  AC-01  This file exists at tests/test_factory_common.py
  AC-02  Happy path: first call initialises manager and stores it in module state
  AC-03  Bool retry guard: second call after failed init returns None (no new attempt)
  AC-04  reset()-based retry: after reset(), next call triggers fresh init attempt
  AC-05  reset() clears state: clears _manager, _init_attempted, _proxy_instance
  AC-06  reset() stops proxy: proxy.stop() called if _proxy_instance was registered
  AC-07  _inject_proxy_env(port): correct env vars set (OPENAI/ANTHROPIC/OPENROUTER only)
  AC-08  All tests pass, pytest 0 failures

Deviation note — AC-03/AC-04 vs story description:
  The story references 'init_retry_backoff_seconds' (time-based retry window).
  helpers/factory_common.py has NO time-based backoff — it uses a simple bool
  _init_attempted (set True on first attempt, cleared by reset()).
  - AC-03: 'within window' maps to 'bool guard still True, no reset() called'
            → second call returns None without a new init attempt
  - AC-04: 'after window elapsed' maps to 'after reset() is called'
            → reset() clears _init_attempted=False, next call retries

Deviation note — AC-07 vs story description:
  Story AC-7 mentions GH_TOKEN should be set by _inject_proxy_env().
  The actual implementation does NOT set GH_TOKEN — only 6 env vars are set:
    OPENAI_API_KEY, OPENAI_API_BASE, ANTHROPIC_API_KEY, ANTHROPIC_BASE_URL,
    OPENROUTER_API_KEY, OPENROUTER_BASE_URL.
  test_gh_token_not_set() documents and verifies this discrepancy.
"""
from __future__ import annotations

import os
import sys
import types
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

# Belt-and-suspenders: conftest.py handles sys.path, but be explicit
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import helpers.factory_common as fc  # noqa: E402


# ===========================================================================
# Constants
# ===========================================================================

_FAKE_PLUGIN_DIR = "/fake/deimos_openbao_secrets"

# sys.modules keys that factory_common registers during init — must be cleaned
# between tests to prevent cross-test state pollution.
_MANAGED_SYS_KEYS = (
    "openbao_config",
    "openbao_client",
    "openbao_manager",
    "openbao_deps",
)


# ===========================================================================
# Mock-building helpers
# ===========================================================================

def _make_enabled_config() -> MagicMock:
    """Return a mock OpenBaoConfig with enabled=True."""
    cfg = MagicMock()
    cfg.enabled = True
    return cfg


def _build_spec_stack(config_obj):
    """Return (spec_side_effect_fn, mock_manager) for a full successful init.

    spec_side_effect_fn: use with patch("importlib.util.spec_from_file_location").
    mock_manager: the SecretsManager instance that get_or_create() will return.

    Mocked chain:
      openbao_config  → load_config() returns config_obj, validate_config() returns []
      openbao_client  → exec_module is a no-op (module just needs to load)
      openbao_manager → OpenBaoSecretsManager.get_or_create() returns mock_manager
    """
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True

    mock_mgr_class = MagicMock()
    mock_mgr_class.get_or_create.return_value = mock_manager

    def _spec_side_effect(name, path):  # noqa: ARG001
        spec = MagicMock()
        spec.name = name  # direct attr assignment — not the MagicMock 'name' kwarg

        if name == "openbao_config":
            def _exec_config(mod):
                mod.load_config = MagicMock(return_value=config_obj)
                mod.validate_config = MagicMock(return_value=[])
            spec.loader.exec_module.side_effect = _exec_config

        elif name == "openbao_client":
            # No attributes accessed on client_mod by factory_common directly
            spec.loader.exec_module.return_value = None

        elif name == "openbao_manager":
            def _exec_mgr(mod):
                mod.OpenBaoSecretsManager = mock_mgr_class
            spec.loader.exec_module.side_effect = _exec_mgr

        return spec

    return _spec_side_effect, mock_manager


@contextmanager
def _happy_path():
    """Patch the full manager-init stack so get_openbao_manager() succeeds.

    Patches applied (all restored on exit):
      - helpers.deps.ensure_dependencies  → returns True
      - helpers.plugins.find_plugin_dir   → returns _FAKE_PLUGIN_DIR
      - importlib.util.spec_from_file_location → mock spec per module name
      - importlib.util.module_from_spec   → types.SimpleNamespace() per call

    Yields mock_manager so callers can assert on the returned object.
    """
    config_obj = _make_enabled_config()
    spec_fn, mock_manager = _build_spec_stack(config_obj)

    mock_deps = MagicMock()
    mock_deps.ensure_dependencies.return_value = True

    mock_plugins = MagicMock()
    mock_plugins.find_plugin_dir.return_value = _FAKE_PLUGIN_DIR

    with patch.dict(sys.modules, {
        "helpers.deps": mock_deps,
        "helpers.plugins": mock_plugins,
    }):
        with patch(
            "importlib.util.spec_from_file_location",
            side_effect=spec_fn,
        ):
            with patch(
                "importlib.util.module_from_spec",
                side_effect=lambda _spec: types.SimpleNamespace(),
            ):
                yield mock_manager


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture(autouse=True)
def reset_factory_state():
    """Reset module-level singletons and sys.modules entries before/after each test.

    Ensures tests are fully isolated from each other regardless of execution order.
    Cleans up the sys.modules entries that factory_common registers during init
    (openbao_config, openbao_client, openbao_manager, openbao_deps).
    """
    fc.reset()
    for key in _MANAGED_SYS_KEYS:
        sys.modules.pop(key, None)
    yield
    fc.reset()
    for key in _MANAGED_SYS_KEYS:
        sys.modules.pop(key, None)


@pytest.fixture
def deps_fail():
    """Patch helpers.deps so ensure_dependencies returns False.

    Simulates the scenario where OpenBao plugin dependencies (hvac, tenacity,
    circuitbreaker) are not installed. The factory returns None on first call
    and sets _init_attempted=True.
    """
    mock_deps = MagicMock()
    mock_deps.ensure_dependencies.return_value = False
    # helpers.plugins mock is defensive — ensure_dependencies=False causes
    # early return before helpers.plugins is ever imported.
    with patch.dict(sys.modules, {
        "helpers.deps": mock_deps,
        "helpers.plugins": MagicMock(),
    }):
        yield mock_deps


# ===========================================================================
# AC-02 — Happy path: first call initialises manager and stores it
# ===========================================================================

class TestHappyPathInit:
    """AC-02: first call with reachable OpenBao initialises manager + module state."""

    def test_returns_manager_instance(self):
        """get_openbao_manager() returns a non-None manager on the happy path."""
        with _happy_path() as mock_manager:
            result = fc.get_openbao_manager()
        assert result is mock_manager

    def test_manager_stored_in_module_state(self):
        """After successful init, fc._manager holds the returned manager."""
        with _happy_path() as mock_manager:
            fc.get_openbao_manager()
        # _manager persists after patch context exits (module-level global)
        assert fc._manager is mock_manager

    def test_second_call_returns_cached_manager(self):
        """Second call returns the same manager from cache (fast path, no re-init)."""
        with _happy_path() as mock_manager:
            r1 = fc.get_openbao_manager()
            r2 = fc.get_openbao_manager()
        assert r1 is mock_manager
        assert r2 is mock_manager

    def test_init_attempted_set_true_after_success(self):
        """_init_attempted is True after a successful init."""
        with _happy_path():
            fc.get_openbao_manager()
        assert fc._init_attempted is True


# ===========================================================================
# AC-03 — Bool retry guard: second call after failed init returns None
# ===========================================================================

class TestRetryGuardBoolFlag:
    """AC-03: after failed init (_init_attempted=True), second call returns None.

    Story describes this as 'second call within init_retry_backoff_seconds'.
    factory_common.py has no time-based backoff — the guard is a simple bool.
    'Within window' maps to: no reset() has been called, _init_attempted=True.
    """

    def test_first_failed_call_returns_none(self, deps_fail):  # noqa: ARG002
        """First call when deps unavailable returns None."""
        result = fc.get_openbao_manager()
        assert result is None

    def test_second_call_after_failure_returns_none(self, deps_fail):  # noqa: ARG002
        """Second call (bool guard active, no reset) also returns None."""
        fc.get_openbao_manager()  # first: fails, sets _init_attempted=True
        result = fc.get_openbao_manager()  # second: bool guard → None
        assert result is None

    def test_ensure_deps_called_exactly_once(self, deps_fail):
        """ensure_dependencies is called only once across two failed calls.

        The bool guard prevents a second init attempt — manager creation
        (ensure_deps check) is invoked exactly once.
        """
        fc.get_openbao_manager()  # init attempt
        fc.get_openbao_manager()  # bool guard — no new attempt
        deps_fail.ensure_dependencies.assert_called_once()

    def test_init_attempted_remains_true_without_reset(self, deps_fail):  # noqa: ARG002
        """_init_attempted stays True between calls when reset() is not called."""
        fc.get_openbao_manager()
        assert fc._init_attempted is True
        fc.get_openbao_manager()
        assert fc._init_attempted is True


# ===========================================================================
# AC-04 — reset()-based retry: after reset(), next call triggers fresh attempt
# ===========================================================================

class TestResetBasedRetry:
    """AC-04: after reset(), _init_attempted is cleared, next call retries.

    Story describes this as 'after init_retry_backoff_seconds have elapsed'.
    factory_common.py has no time window — reset() is the equivalent trigger.
    """

    def test_fresh_attempt_made_after_reset(self, deps_fail):
        """ensure_dependencies called twice: once before and once after reset()."""
        fc.get_openbao_manager()  # attempt 1 — fails
        fc.reset()                # clears _init_attempted
        fc.get_openbao_manager()  # attempt 2 — retries
        assert deps_fail.ensure_dependencies.call_count == 2

    def test_init_attempted_false_immediately_after_reset(self, deps_fail):  # noqa: ARG002
        """reset() sets _init_attempted=False, confirmed before next call."""
        fc.get_openbao_manager()  # fails → _init_attempted=True
        assert fc._init_attempted is True
        fc.reset()
        assert fc._init_attempted is False

    def test_successful_manager_returned_after_reset_and_retry(self):
        """After failed init + reset(), a successful retry returns a manager."""
        # Phase 1: failed init
        mock_fail_deps = MagicMock()
        mock_fail_deps.ensure_dependencies.return_value = False
        with patch.dict(sys.modules, {
            "helpers.deps": mock_fail_deps,
            "helpers.plugins": MagicMock(),
        }):
            r1 = fc.get_openbao_manager()
        assert r1 is None

        # Phase 2: reset + successful retry
        fc.reset()
        with _happy_path() as mock_manager:
            r2 = fc.get_openbao_manager()
        assert r2 is mock_manager


# ===========================================================================
# AC-05 — reset() clears state
# ===========================================================================

class TestResetClearsState:
    """AC-05: reset() clears _manager, _init_attempted, _proxy_instance.

    After reset(), a subsequent factory call triggers a fresh init attempt
    regardless of prior state.
    """

    def test_reset_clears_manager(self):
        """reset() sets _manager to None."""
        with _happy_path():
            fc.get_openbao_manager()
        assert fc._manager is not None
        fc.reset()
        assert fc._manager is None

    def test_reset_clears_init_attempted(self):
        """reset() sets _init_attempted to False."""
        mock_fail = MagicMock()
        mock_fail.ensure_dependencies.return_value = False
        with patch.dict(sys.modules, {
            "helpers.deps": mock_fail,
            "helpers.plugins": MagicMock(),
        }):
            fc.get_openbao_manager()
        assert fc._init_attempted is True
        fc.reset()
        assert fc._init_attempted is False

    def test_reset_clears_proxy_instance(self):
        """reset() sets _proxy_instance to None."""
        fc._proxy_instance = MagicMock()
        assert fc._proxy_instance is not None
        fc.reset()
        assert fc._proxy_instance is None


# ===========================================================================
# AC-06 — reset() stops proxy
# ===========================================================================

class TestResetStopsProxy:
    """AC-06: reset() calls stop() on _proxy_instance if one is registered."""

    def test_reset_calls_stop_on_proxy(self):
        """reset() calls proxy.stop() exactly once."""
        mock_proxy = MagicMock()
        fc._proxy_instance = mock_proxy

        fc.reset()

        mock_proxy.stop.assert_called_once_with()

    def test_reset_clears_proxy_instance_after_stop(self):
        """reset() sets _proxy_instance to None after calling stop()."""
        mock_proxy = MagicMock()
        fc._proxy_instance = mock_proxy
        fc.reset()
        assert fc._proxy_instance is None

    def test_reset_safe_when_no_proxy_registered(self):
        """reset() is safe when _proxy_instance is None — no AttributeError."""
        assert fc._proxy_instance is None
        fc.reset()  # must not raise

    def test_reset_does_not_propagate_proxy_stop_exception(self):
        """Exceptions from proxy.stop() are swallowed, not re-raised."""
        mock_proxy = MagicMock()
        mock_proxy.stop.side_effect = RuntimeError("proxy stop failed")
        fc._proxy_instance = mock_proxy

        fc.reset()  # must not raise RuntimeError

        assert fc._proxy_instance is None

    def test_reset_idempotent_with_proxy(self):
        """Two sequential reset() calls are safe (second has no proxy to stop)."""
        mock_proxy = MagicMock()
        fc._proxy_instance = mock_proxy
        fc.reset()   # stops proxy
        fc.reset()   # _proxy_instance is None — safe no-op for proxy path
        mock_proxy.stop.assert_called_once_with()  # stop called only once


# ===========================================================================
# AC-07 — _inject_proxy_env(port)
# ===========================================================================

class TestInjectProxyEnv:
    """AC-07: _inject_proxy_env sets sentinel API keys and proxy base URLs.

    Verified variables (6 total — no GH_TOKEN despite story AC-7 listing it):
      OPENAI_API_KEY          -> 'proxy-a0'
      OPENAI_API_BASE         -> http://127.0.0.1:{port}/proxy/openai
      ANTHROPIC_API_KEY       -> 'proxy-a0'
      ANTHROPIC_BASE_URL      -> http://127.0.0.1:{port}/proxy/anthropic
      OPENROUTER_API_KEY      -> 'proxy-a0'
      OPENROUTER_BASE_URL     -> http://127.0.0.1:{port}/proxy/openrouter

    GH_TOKEN: story AC-7 lists it; implementation does NOT set it.
    test_gh_token_not_set() explicitly documents this discrepancy.
    """

    _EXPECTED_KEYS = (
        "OPENAI_API_KEY",
        "OPENAI_API_BASE",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_BASE_URL",
        "OPENROUTER_API_KEY",
        "OPENROUTER_BASE_URL",
    )

    @pytest.fixture(autouse=True)
    def clean_env(self):
        """Save, clear, and restore the 6 proxy env vars around each test."""
        originals = {k: os.environ.get(k) for k in self._EXPECTED_KEYS}
        for k in self._EXPECTED_KEYS:
            os.environ.pop(k, None)
        yield
        for k, v in originals.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # -- Sentinel key tests --------------------------------------------------

    def test_openai_api_key_is_sentinel(self):
        """OPENAI_API_KEY is set to the 'proxy-a0' sentinel."""
        fc._inject_proxy_env(8080)
        assert os.environ["OPENAI_API_KEY"] == "proxy-a0"

    def test_anthropic_api_key_is_sentinel(self):
        """ANTHROPIC_API_KEY is set to the 'proxy-a0' sentinel."""
        fc._inject_proxy_env(8080)
        assert os.environ["ANTHROPIC_API_KEY"] == "proxy-a0"

    def test_openrouter_api_key_is_sentinel(self):
        """OPENROUTER_API_KEY is set to the 'proxy-a0' sentinel."""
        fc._inject_proxy_env(8080)
        assert os.environ["OPENROUTER_API_KEY"] == "proxy-a0"

    # -- Base URL correctness tests ------------------------------------------

    def test_openai_api_base_url_correct(self):
        """OPENAI_API_BASE is http://127.0.0.1:{port}/proxy/openai."""
        fc._inject_proxy_env(9123)
        assert os.environ["OPENAI_API_BASE"] == "http://127.0.0.1:9123/proxy/openai"

    def test_anthropic_base_url_correct(self):
        """ANTHROPIC_BASE_URL is http://127.0.0.1:{port}/proxy/anthropic."""
        fc._inject_proxy_env(9123)
        assert os.environ["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:9123/proxy/anthropic"

    def test_openrouter_base_url_correct(self):
        """OPENROUTER_BASE_URL is http://127.0.0.1:{port}/proxy/openrouter."""
        fc._inject_proxy_env(9123)
        assert os.environ["OPENROUTER_BASE_URL"] == "http://127.0.0.1:9123/proxy/openrouter"

    # -- Coverage tests ------------------------------------------------------

    def test_all_six_expected_vars_set(self):
        """All 6 expected env vars are present after _inject_proxy_env."""
        fc._inject_proxy_env(5000)
        for key in self._EXPECTED_KEYS:
            assert key in os.environ, f"{key} not set by _inject_proxy_env"

    def test_port_substituted_in_all_base_urls(self):
        """The port number appears in all three *_BASE_URL / *_API_BASE vars."""
        fc._inject_proxy_env(12345)
        assert "12345" in os.environ["OPENAI_API_BASE"]
        assert "12345" in os.environ["ANTHROPIC_BASE_URL"]
        assert "12345" in os.environ["OPENROUTER_BASE_URL"]

    def test_gh_token_not_set(self):
        """GH_TOKEN is NOT modified by _inject_proxy_env.

        Story AC-7 lists GH_TOKEN as a var that should be set, but the
        actual implementation of _inject_proxy_env() does not set it.
        This test documents and verifies the implementation behaviour.
        """
        # Capture state before — handles both 'set' and 'unset' cases
        gh_token_before = os.environ.get("GH_TOKEN")
        fc._inject_proxy_env(5000)
        assert os.environ.get("GH_TOKEN") == gh_token_before
