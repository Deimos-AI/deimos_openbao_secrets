"""Test suite for E-02 (issue #21): extra_env on LocalInteractiveSession.

Acceptance criteria:
  AC-01  Secrets stored in agent.context._terminal_extra_env, NOT os.environ
  AC-02  extra_env dict passed to LocalInteractiveSession on creation
  AC-03  os.environ does NOT contain secret keys after injection (when extra_env supported)
  AC-04  Cleanup hook clears _terminal_extra_env
  AC-05  Fallback to old os.environ path when extra_env not available (backward compat)
  AC-06  No-op for non-code_execution_tool tools
  AC-07  No-op when manager unavailable
  AC-08  No-op when terminal_secrets is empty
  AC-09  Fail-open on exceptions

Approach
--------
We instantiate the inject and cleanup Extension classes directly, passing
a mock agent with a mock context. The factory_common module is patched
to provide a mock manager. We verify the exact state transitions on
agent.context._terminal_extra_env, _terminal_injected_keys, and os.environ.
"""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Plugin root on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from extensions.python.tool_execute_before._15_inject_terminal_secrets import (  # noqa: E402
    InjectTerminalSecrets,
    _load_terminal_keys,
)
from extensions.python.tool_execute_after._15_cleanup_terminal_secrets import (  # noqa: E402
    CleanupTerminalSecrets,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_context():
    """Provide a fresh SimpleNamespace context for each test."""
    return SimpleNamespace()


@pytest.fixture
def mock_agent(mock_context):
    """Provide a mock agent with a context attribute."""
    agent = MagicMock()
    agent.context = mock_context
    return agent


@pytest.fixture
def inject_ext(mock_agent):
    """Provide an InjectTerminalSecrets extension bound to mock_agent."""
    ext = InjectTerminalSecrets()
    ext.agent = mock_agent
    return ext


@pytest.fixture
def cleanup_ext(mock_agent):
    """Provide a CleanupTerminalSecrets extension bound to mock_agent."""
    ext = CleanupTerminalSecrets()
    ext.agent = mock_agent
    return ext


@pytest.fixture
def mock_manager():
    """Provide a mock OpenBao manager returning predictable secrets."""
    mgr = MagicMock()
    mgr.get_secret.side_effect = lambda key: {
        "DB_PASSWORD": "supersecret123",
        "API_TOKEN": "tok_abc456",
    }.get(key)
    return mgr


@pytest.fixture(autouse=True)
def clean_os_environ():
    """Ensure no leftover test keys in os.environ between tests."""
    keys_to_clean = ["DB_PASSWORD", "API_TOKEN"]
    saved = {k: os.environ.pop(k, None) for k in keys_to_clean}
    yield
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        elif k in os.environ:
            del os.environ[k]


# ---------------------------------------------------------------------------
# AC-01: Secrets stored in agent.context._terminal_extra_env, NOT os.environ
# ---------------------------------------------------------------------------


class TestExtraEnvStorage:
    """AC-01: Secrets go to _terminal_extra_env, not os.environ."""

    @pytest.mark.asyncio
    async def test_secrets_in_extra_env_not_os_environ(
        self, inject_ext, mock_agent, mock_context, mock_manager
    ):
        """AC-01: resolved secrets stored in _terminal_extra_env."""
        # Mark framework as supporting extra_env
        mock_context._terminal_extra_env_supported = True

        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=["DB_PASSWORD", "API_TOKEN"]):
            await inject_ext.execute(tool_name="code_execution_tool")

        # AC-01: secrets in extra_env
        assert mock_context._terminal_extra_env == {
            "DB_PASSWORD": "supersecret123",
            "API_TOKEN": "tok_abc456",
        }
        # AC-01: NOT in os.environ
        assert "DB_PASSWORD" not in os.environ
        assert "API_TOKEN" not in os.environ

    @pytest.mark.asyncio
    async def test_extra_env_is_dict(self, inject_ext, mock_agent, mock_context, mock_manager):
        """AC-01: _terminal_extra_env is a dict when secrets resolved."""
        mock_context._terminal_extra_env_supported = True

        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=["DB_PASSWORD"]):
            await inject_ext.execute(tool_name="code_execution_tool")

        assert isinstance(mock_context._terminal_extra_env, dict)
        assert mock_context._terminal_extra_env["DB_PASSWORD"] == "supersecret123"


# ---------------------------------------------------------------------------
# AC-02: extra_env dict passed to LocalInteractiveSession on creation
# ---------------------------------------------------------------------------

class TestExtraEnvPassthrough:
    """AC-02: Framework passes extra_env to LocalInteractiveSession."""

    def test_local_session_accepts_extra_env(self):
        """AC-02: LocalInteractiveSession stores extra_env kwarg."""
        # We verify the contract by inspecting the actual shell_local.py source
        # rather than importing (deep framework deps not available in test env).
        import ast
        shell_local_path = os.path.join(
            os.path.dirname(__file__),
            "..", "..", "..", "..", "..",
            "plugins", "_code_execution", "helpers", "shell_local.py",
        )
        shell_local_path = os.path.normpath(shell_local_path)
        with open(shell_local_path) as f:
            tree = ast.parse(f.read())
        # Find LocalInteractiveSession.__init__
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "__init__":
                param_names = [a.arg for a in node.args.args]
                assert "extra_env" in param_names, (
                    f"LocalInteractiveSession.__init__ params: {param_names} "
                    "— missing extra_env"
                )
                break

    def test_local_session_default_extra_env_none(self):
        """AC-02: Default extra_env is None — verified by source inspection."""
        import ast
        shell_local_path = os.path.join(
            os.path.dirname(__file__),
            "..", "..", "..", "..", "..",
            "plugins", "_code_execution", "helpers", "shell_local.py",
        )
        shell_local_path = os.path.normpath(shell_local_path)
        with open(shell_local_path) as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "__init__":
                defaults = node.args.defaults
                kw_defaults = node.args.kw_defaults
                # extra_env default should be None
                param_names = [a.arg for a in node.args.args]
                idx = param_names.index("extra_env")
                all_defaults = [None] * (len(param_names) - len(defaults)) + defaults
                default_val = all_defaults[idx]
                if isinstance(default_val, ast.Constant):
                    assert default_val.value is None
                else:
                    # If it's a Name node like 'None'
                    assert isinstance(default_val, ast.NameConstant | ast.Name)
                break


# ---------------------------------------------------------------------------
# AC-03: os.environ does NOT contain secret keys after injection
# ---------------------------------------------------------------------------


class TestOsEnvironClean:
    """AC-03: os.environ stays clean when extra_env is supported."""

    @pytest.mark.asyncio
    async def test_os_environ_clean_with_extra_env_support(
        self, inject_ext, mock_agent, mock_context, mock_manager
    ):
        """AC-03: No secrets in os.environ when framework supports extra_env."""
        mock_context._terminal_extra_env_supported = True

        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=["DB_PASSWORD", "API_TOKEN"]):
            await inject_ext.execute(tool_name="code_execution_tool")

        assert "DB_PASSWORD" not in os.environ
        assert "API_TOKEN" not in os.environ


# ---------------------------------------------------------------------------
# AC-04: Cleanup hook clears _terminal_extra_env
# ---------------------------------------------------------------------------


class TestCleanupExtraEnv:
    """AC-04: cleanup clears _terminal_extra_env and _terminal_injected_keys."""

    @pytest.mark.asyncio
    async def test_cleanup_clears_extra_env(
        self, cleanup_ext, mock_agent, mock_context
    ):
        """AC-04: _terminal_extra_env set to None after cleanup."""
        mock_context._terminal_extra_env = {"KEY": "val"}
        mock_context._terminal_injected_keys = ["KEY"]

        await cleanup_ext.execute(tool_name="code_execution_tool")

        assert mock_context._terminal_extra_env is None

    @pytest.mark.asyncio
    async def test_cleanup_clears_injected_keys(
        self, cleanup_ext, mock_agent, mock_context
    ):
        """AC-04: _terminal_injected_keys cleared after cleanup."""
        mock_context._terminal_extra_env = {"KEY": "val"}
        mock_context._terminal_injected_keys = ["KEY"]

        await cleanup_ext.execute(tool_name="code_execution_tool")

        assert mock_context._terminal_injected_keys == []

    @pytest.mark.asyncio
    async def test_cleanup_noop_when_no_extra_env(
        self, cleanup_ext, mock_agent, mock_context
    ):
        """AC-04: cleanup is safe when no _terminal_extra_env set."""
        mock_context._terminal_injected_keys = []
        await cleanup_ext.execute(tool_name="code_execution_tool")
        # No exception raised — pass

    @pytest.mark.asyncio
    async def test_full_inject_cleanup_cycle(
        self, inject_ext, cleanup_ext, mock_agent, mock_context, mock_manager
    ):
        """AC-04: full inject→execute→cleanup cycle clears everything."""
        mock_context._terminal_extra_env_supported = True

        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=["DB_PASSWORD"]):
            await inject_ext.execute(tool_name="code_execution_tool")

        # After inject: extra_env has secrets
        assert mock_context._terminal_extra_env == {"DB_PASSWORD": "supersecret123"}

        # Cleanup
        await cleanup_ext.execute(tool_name="code_execution_tool")

        # After cleanup: extra_env is None, keys list empty
        assert mock_context._terminal_extra_env is None
        assert mock_context._terminal_injected_keys == []
        assert "DB_PASSWORD" not in os.environ


# ---------------------------------------------------------------------------
# AC-05: Fallback to os.environ when extra_env not available
# ---------------------------------------------------------------------------


class TestLegacyFallback:
    """AC-05: backward compat — os.environ fallback when no extra_env support."""

    @pytest.mark.asyncio
    async def test_fallback_to_os_environ_when_not_supported(
        self, inject_ext, mock_agent, mock_context, mock_manager
    ):
        """AC-05: without _terminal_extra_env_supported, secrets go to os.environ."""
        # Do NOT set _terminal_extra_env_supported — simulates old framework

        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=["DB_PASSWORD"]):
            await inject_ext.execute(tool_name="code_execution_tool")

        # AC-05: secrets ALSO in os.environ (legacy fallback)
        assert os.environ.get("DB_PASSWORD") == "supersecret123"
        # AND in extra_env
        assert mock_context._terminal_extra_env == {"DB_PASSWORD": "supersecret123"}

        # Cleanup
        os.environ.pop("DB_PASSWORD", None)

    @pytest.mark.asyncio
    async def test_fallback_os_environ_cleaned_by_cleanup(
        self, inject_ext, cleanup_ext, mock_agent, mock_context, mock_manager
    ):
        """AC-05: cleanup removes os.environ keys from legacy fallback."""
        # Do NOT set _terminal_extra_env_supported

        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=["DB_PASSWORD"]):
            await inject_ext.execute(tool_name="code_execution_tool")

        assert os.environ.get("DB_PASSWORD") == "supersecret123"

        await cleanup_ext.execute(tool_name="code_execution_tool")

        assert "DB_PASSWORD" not in os.environ


# ---------------------------------------------------------------------------
# AC-06: No-op for non-code_execution_tool tools
# ---------------------------------------------------------------------------


class TestToolGating:
    """AC-06: inject and cleanup are no-op for other tools."""

    @pytest.mark.asyncio
    async def test_inject_noop_for_other_tool(self, inject_ext, mock_context):
        """AC-06: inject skips non-code_execution_tool."""
        await inject_ext.execute(tool_name="browser_agent")
        # _terminal_extra_env should not be set
        assert not hasattr(mock_context, "_terminal_extra_env") or \
            getattr(mock_context, "_terminal_extra_env", None) is None

    @pytest.mark.asyncio
    async def test_cleanup_noop_for_other_tool(self, cleanup_ext, mock_context):
        """AC-06: cleanup skips non-code_execution_tool."""
        mock_context._terminal_extra_env = {"X": "y"}
        mock_context._terminal_injected_keys = ["X"]

        await cleanup_ext.execute(tool_name="browser_agent")

        # Should NOT have been cleaned
        assert mock_context._terminal_extra_env == {"X": "y"}


# ---------------------------------------------------------------------------
# AC-07: No-op when manager unavailable
# ---------------------------------------------------------------------------


class TestManagerUnavailable:
    """AC-07: graceful no-op when manager is None."""

    @pytest.mark.asyncio
    async def test_inject_noop_no_factory(self, inject_ext, mock_context):
        """AC-07: no factory module → no injection."""
        with patch.dict(sys.modules, {}):
            # Remove factory_common if present
            sys.modules.pop("openbao_secrets_factory_common", None)
            await inject_ext.execute(tool_name="code_execution_tool")

        assert mock_context._terminal_extra_env is None
        assert mock_context._terminal_injected_keys == []

    @pytest.mark.asyncio
    async def test_inject_noop_manager_none(self, inject_ext, mock_context):
        """AC-07: factory returns None manager → no injection."""
        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = None

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}):
            await inject_ext.execute(tool_name="code_execution_tool")

        assert mock_context._terminal_extra_env is None
        assert mock_context._terminal_injected_keys == []


# ---------------------------------------------------------------------------
# AC-08: No-op when terminal_secrets is empty
# ---------------------------------------------------------------------------


class TestEmptyTerminalSecrets:
    """AC-08: graceful no-op when terminal_secrets config is empty."""

    @pytest.mark.asyncio
    async def test_inject_noop_empty_terminal_keys(
        self, inject_ext, mock_context, mock_manager
    ):
        """AC-08: empty terminal_secrets list → no injection."""
        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=[]):
            await inject_ext.execute(tool_name="code_execution_tool")

        assert mock_context._terminal_extra_env is None
        assert mock_context._terminal_injected_keys == []


# ---------------------------------------------------------------------------
# AC-09: Fail-open on exceptions
# ---------------------------------------------------------------------------


class TestFailOpen:
    """AC-09: exceptions are caught, logged, never raised."""

    @pytest.mark.asyncio
    async def test_inject_fail_open_on_exception(
        self, inject_ext, mock_context
    ):
        """AC-09: inject catches all exceptions, sets safe defaults."""
        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.side_effect = RuntimeError("boom")

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}):
            # Should NOT raise
            await inject_ext.execute(tool_name="code_execution_tool")

        assert mock_context._terminal_extra_env is None
        assert mock_context._terminal_injected_keys == []

    @pytest.mark.asyncio
    async def test_cleanup_fail_open_on_exception(
        self, cleanup_ext, mock_agent, mock_context
    ):
        """AC-09: cleanup catches all exceptions, never raises."""
        # Make getattr on context raise
        mock_agent.context = MagicMock()
        mock_agent.context._terminal_injected_keys = ["X"]
        # Force an exception in the middle of cleanup
        type(mock_agent.context)._terminal_extra_env = property(
            lambda self: (_ for _ in ()).throw(RuntimeError("boom"))
        )
        cleanup_ext.agent = mock_agent

        # Should NOT raise
        await cleanup_ext.execute(tool_name="code_execution_tool")


# ---------------------------------------------------------------------------
# Sentinel filtering
# ---------------------------------------------------------------------------


class TestSentinelFiltering:
    """proxy-a0 sentinel values are not injected."""

    @pytest.mark.asyncio
    async def test_sentinel_not_injected(
        self, inject_ext, mock_context, mock_agent
    ):
        """Sentinel 'proxy-a0' values are skipped."""
        mock_context._terminal_extra_env_supported = True

        mock_manager = MagicMock()
        mock_manager.get_secret.return_value = "proxy-a0"

        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=["DB_PASSWORD"]):
            await inject_ext.execute(tool_name="code_execution_tool")

        # Sentinel filtered out → empty extra_env → set to None
        assert mock_context._terminal_extra_env is None
        assert mock_context._terminal_injected_keys == []


# ---------------------------------------------------------------------------
# None-value filtering
# ---------------------------------------------------------------------------


class TestNoneFiltering:
    """None values are not injected."""

    @pytest.mark.asyncio
    async def test_none_not_injected(
        self, inject_ext, mock_context, mock_agent
    ):
        """None values from manager.get_secret are skipped."""
        mock_context._terminal_extra_env_supported = True

        mock_manager = MagicMock()
        mock_manager.get_secret.return_value = None

        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=["DB_PASSWORD"]):
            await inject_ext.execute(tool_name="code_execution_tool")

        assert mock_context._terminal_extra_env is None
        assert mock_context._terminal_injected_keys == []


# ---------------------------------------------------------------------------
# Partial failure — one key resolves, another fails
# ---------------------------------------------------------------------------


class TestPartialFailure:
    """Individual key resolution failures are logged, others continue."""

    @pytest.mark.asyncio
    async def test_partial_failure_continues(
        self, inject_ext, mock_context, mock_agent
    ):
        """One key failing doesn't block others."""
        mock_context._terminal_extra_env_supported = True

        mock_manager = MagicMock()
        mock_manager.get_secret.side_effect = lambda key: {
            "DB_PASSWORD": "supersecret123",
            "BROKEN_KEY": (_ for _ in ()).throw(RuntimeError("vault down")),
            "API_TOKEN": "tok_abc456",
        }.get(key, None)
        # For BROKEN_KEY, the lambda itself raises when accessed
        def side_effect_fn(key):
            if key == "BROKEN_KEY":
                raise RuntimeError("vault down")
            return {"DB_PASSWORD": "supersecret123", "API_TOKEN": "tok_abc456"}.get(key)

        mock_manager.get_secret.side_effect = side_effect_fn

        fc_mock = MagicMock()
        fc_mock.get_openbao_manager.return_value = mock_manager

        with patch.dict(sys.modules, {"openbao_secrets_factory_common": fc_mock}), \
             patch("extensions.python.tool_execute_before._15_inject_terminal_secrets._load_terminal_keys",
                   return_value=["DB_PASSWORD", "BROKEN_KEY", "API_TOKEN"]):
            await inject_ext.execute(tool_name="code_execution_tool")

        # Two good keys should be in extra_env
        assert mock_context._terminal_extra_env == {
            "DB_PASSWORD": "supersecret123",
            "API_TOKEN": "tok_abc456",
        }
        assert set(mock_context._terminal_injected_keys) == {"DB_PASSWORD", "API_TOKEN"}
        assert "BROKEN_KEY" not in (mock_context._terminal_extra_env or {})
