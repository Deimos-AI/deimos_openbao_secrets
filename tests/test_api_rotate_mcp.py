"""Tests for api/rotate_mcp.py — RotateMcp API handler.

Covers AC-03 (file creation) and AC-06 (8 test cases):
  manager_unavailable, no_mcp_json, placeholder_resolved, no_placeholders,
  mcp_config_update_failure, resolve_mcp_config_real_json,
  resolve_value_valid, resolve_value_invalid.

Also covers AC-07 (Optional import fix) and AC-08 (_BAO_SUFFIX fix).

Satisfies: AC-03, AC-06, AC-07, AC-08

Notes on mock strategy:
  rotate_mcp.py imports helpers.settings and helpers.mcp_handler INSIDE
  process() via `from helpers.settings import get_settings` etc.
  These are pre-injected into sys.modules by the fixture so that the
  function-local imports pick them up directly.
  vault_io is pre-injected under its cache key
  'deimos_openbao_secrets_helpers_vault_io' to bypass find_plugin_dir.
"""
import asyncio
import importlib.util
import json
import os
import sys
from unittest.mock import MagicMock, patch
import pytest


@pytest.fixture(scope="module")
def rotate_mod():
    """Load api/rotate_mcp.py with A0 runtime deps stubbed.

    vault_io is loaded by _load_vault_io() using the sys.modules cache key
    _VAULT_IO_MODULE = 'deimos_openbao_secrets_helpers_vault_io'.
    Pre-injecting that key bypasses the find_plugin_dir path lookup entirely.
    helpers.settings and helpers.mcp_handler are imported inside process().

    Satisfies: AC-03 (file created and loadable)
    """
    mock_api = MagicMock()

    class _StubApiHandler:
        pass

    mock_api.ApiHandler = _StubApiHandler
    mock_api.Request = MagicMock
    mock_api.Response = MagicMock
    sys.modules.setdefault("helpers.api", mock_api)
    sys.modules.setdefault("helpers.plugins", MagicMock())

    # Pre-inject vault_io under its cache key so _load_vault_io() returns it
    mock_vault_io = MagicMock()
    sys.modules["deimos_openbao_secrets_helpers_vault_io"] = mock_vault_io

    # helpers.settings — get_settings() called inside process()
    sys.modules.setdefault("helpers.settings", MagicMock())

    # helpers.mcp_handler — MCPConfig.update() called inside process()
    sys.modules.setdefault("helpers.mcp_handler", MagicMock())

    path = os.path.join(os.path.dirname(__file__), "..", "api", "rotate_mcp.py")
    spec = importlib.util.spec_from_file_location("api_rotate_mcp", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# AC-06: manager_unavailable
# ---------------------------------------------------------------------------

def test_manager_unavailable_returns_error(rotate_mod):
    """AC-06: manager None returns success=False.

    Satisfies: AC-06 (manager_unavailable)
    """
    handler = rotate_mod.RotateMcp()
    with patch.object(rotate_mod, "_get_manager", return_value=None):
        result = asyncio.run(handler.process({}, MagicMock()))

    assert result["success"] is False          # AC-06: manager_unavailable
    assert "not available" in result["error"]  # AC-06


# ---------------------------------------------------------------------------
# AC-06: no_mcp_json
# ---------------------------------------------------------------------------

def test_no_mcp_json_returns_zero_refresh(rotate_mod):
    """AC-06: empty mcp_servers returns servers_refreshed=0, success=True.

    Satisfies: AC-06 (no_mcp_json)
    """
    manager = MagicMock()
    manager.is_available.return_value = True
    sys.modules["helpers.settings"].get_settings.return_value = {"mcp_servers": ""}

    with patch.object(rotate_mod, "_get_manager", return_value=manager):
        result = asyncio.run(rotate_mod.RotateMcp().process({}, MagicMock()))

    assert result["success"] is True                         # AC-06: no_mcp_json
    assert result["servers_refreshed"] == 0                  # AC-06
    assert "No MCP servers configured" in result["message"]  # AC-06


# ---------------------------------------------------------------------------
# AC-06: placeholder_resolved calls MCPConfig.update
# ---------------------------------------------------------------------------

def test_placeholder_resolved_calls_mcp_update(rotate_mod):
    """AC-06: resolved placeholders triggers MCPConfig.update with resolved JSON.

    Satisfies: AC-06 (placeholder_resolved)
    """
    manager = MagicMock()
    manager.is_available.return_value = True
    resolved_json = '{"mcpServers": {"srv": {"headers": {"Authorization": "live-token"}}}}'
    # provide non-empty mcp_json to avoid early return
    sys.modules["helpers.settings"].get_settings.return_value = {
        "mcp_servers": '{"mcpServers": {"srv": {"headers": {"Authorization": "placeholder"}}}}'
    }
    mcp_mock = sys.modules["helpers.mcp_handler"]
    mcp_mock.MCPConfig.update.reset_mock()
    mcp_mock.MCPConfig.update.side_effect = None

    with patch.object(rotate_mod, "_get_manager", return_value=manager), \
         patch.object(rotate_mod, "_resolve_mcp_config", return_value=(resolved_json, 1)):
        result = asyncio.run(rotate_mod.RotateMcp().process({}, MagicMock()))

    assert result["success"] is True                     # AC-06: placeholder_resolved
    assert result["servers_refreshed"] == 1              # AC-06
    mcp_mock.MCPConfig.update.assert_called_once_with(resolved_json)  # AC-06


# ---------------------------------------------------------------------------
# AC-06: no_placeholders — MCPConfig.update NOT called
# ---------------------------------------------------------------------------

def test_no_placeholders_skips_mcp_update(rotate_mod):
    """AC-06: count=0 means MCPConfig.update is NOT called.

    Satisfies: AC-06 (no_placeholders)
    """
    manager = MagicMock()
    manager.is_available.return_value = True
    plain_json = '{"mcpServers": {"srv": {"command": "npx"}}}'
    sys.modules["helpers.settings"].get_settings.return_value = {"mcp_servers": plain_json}
    mcp_mock = sys.modules["helpers.mcp_handler"]
    mcp_mock.MCPConfig.update.reset_mock()
    mcp_mock.MCPConfig.update.side_effect = None

    with patch.object(rotate_mod, "_get_manager", return_value=manager), \
         patch.object(rotate_mod, "_resolve_mcp_config", return_value=(plain_json, 0)):
        result = asyncio.run(rotate_mod.RotateMcp().process({}, MagicMock()))

    assert result["success"] is True                     # AC-06: no_placeholders
    assert result["servers_refreshed"] == 0              # AC-06
    mcp_mock.MCPConfig.update.assert_not_called()        # AC-06


# ---------------------------------------------------------------------------
# AC-06: mcp_config_update_failure
# ---------------------------------------------------------------------------

def test_mcp_config_update_failure_returns_error(rotate_mod):
    """AC-06: MCPConfig.update() exception returns success=False.

    Satisfies: AC-06 (mcp_config_update_failure)
    """
    manager = MagicMock()
    manager.is_available.return_value = True
    resolved_json = '{"mcpServers": {}}'
    sys.modules["helpers.settings"].get_settings.return_value = {"mcp_servers": resolved_json}
    mcp_mock = sys.modules["helpers.mcp_handler"]
    mcp_mock.MCPConfig.update.reset_mock()
    mcp_mock.MCPConfig.update.side_effect = Exception("update failed")

    with patch.object(rotate_mod, "_get_manager", return_value=manager), \
         patch.object(rotate_mod, "_resolve_mcp_config", return_value=(resolved_json, 2)):
        result = asyncio.run(rotate_mod.RotateMcp().process({}, MagicMock()))

    mcp_mock.MCPConfig.update.side_effect = None  # reset for subsequent tests
    assert result["success"] is False                    # AC-06: mcp_config_update_failure
    assert "MCPConfig update failed" in result["error"]  # AC-06


# ---------------------------------------------------------------------------
# AC-06: resolve_mcp_config with real JSON structure
# ---------------------------------------------------------------------------

def test_resolve_mcp_config_real_json(rotate_mod):
    """AC-06: _resolve_mcp_config resolves placeholder in real JSON structure.

    Satisfies: AC-06 (resolve_mcp_config_real_json)
    """
    manager = MagicMock()
    prefix = rotate_mod._BAO_PREFIX
    suffix = rotate_mod._BAO_SUFFIX
    placeholder = f"{prefix}mcp/my-server/Authorization{suffix}"
    mcp_json = (
        '{"mcpServers": {"my-server": {"headers": {"Authorization": "' + placeholder + '"}}}}'
    )

    with patch.object(rotate_mod, "_vault_read", return_value={"value": "Bearer live"}):
        resolved, count = rotate_mod._resolve_mcp_config(manager, mcp_json)  # AC-06

    data = json.loads(resolved)
    assert count == 1                                                                   # AC-06: resolve_mcp_config_real_json
    assert data["mcpServers"]["my-server"]["headers"]["Authorization"] == "Bearer live"  # AC-06


# ---------------------------------------------------------------------------
# AC-06: _resolve_value — valid / invalid placeholder
# ---------------------------------------------------------------------------

def test_resolve_value_valid_placeholder_returns_live(rotate_mod):
    """AC-06: _resolve_value returns vault value for well-formed placeholder.

    Satisfies: AC-06 (resolve_value valid_placeholder)
    """
    manager = MagicMock()
    prefix = rotate_mod._BAO_PREFIX
    suffix = rotate_mod._BAO_SUFFIX
    placeholder = f"{prefix}mcp/my-server/Authorization{suffix}"

    with patch.object(rotate_mod, "_vault_read", return_value={"value": "Bearer sk-live"}):
        result = rotate_mod._resolve_value(manager, placeholder)  # AC-06

    assert result == "Bearer sk-live"  # AC-06: valid_placeholder


def test_resolve_value_invalid_placeholder_returns_none(rotate_mod):
    """AC-06: _resolve_value returns None for non-placeholder string.

    Satisfies: AC-06 (resolve_value invalid_placeholder)
    """
    manager = MagicMock()
    result = rotate_mod._resolve_value(manager, "plain-string-no-prefix")
    assert result is None  # AC-06: invalid_placeholder


# ---------------------------------------------------------------------------
# AC-07: Optional import fix — no NameError when evaluating type hints
# ---------------------------------------------------------------------------

def test_optional_import_present(rotate_mod):
    """AC-07: Optional is importable from rotate_mcp module namespace (bug fix verified).

    Satisfies: AC-07 (Optional not imported NameError fixed)
    """
    import typing
    hints = typing.get_type_hints(rotate_mod._resolve_value)  # AC-07: no NameError
    assert "return" in hints  # AC-07: annotation evaluable


# ---------------------------------------------------------------------------
# AC-08: _BAO_SUFFIX constant defined and correct
# ---------------------------------------------------------------------------

def test_bao_suffix_constant_defined(rotate_mod):
    """AC-08: _BAO_SUFFIX constant exists and is the expected Unicode character.

    Satisfies: AC-08 (_BAO_SUFFIX undefined NameError fixed)
    """
    assert hasattr(rotate_mod, "_BAO_SUFFIX")                 # AC-08: defined
    assert rotate_mod._BAO_SUFFIX == "\u27e7"                 # AC-08: correct value U+27E7 ⟧
