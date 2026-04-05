"""test_api_sync_plugins.py — Tests for SyncPlugins API handler.

Covers: AC-11 through AC-14 (cross-plugin sync endpoint).

Satisfies: AC-11, AC-12, AC-13, AC-14
"""
import asyncio
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml


# ---------------------------------------------------------------------------
# Fixture: load api/secrets.py with stubs pre-injected
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sync_mod():
    """Load api/secrets.py with A0 runtime stubs pre-injected."""
    mock_api = MagicMock()

    class _StubApiHandler:
        pass

    mock_api.ApiHandler = _StubApiHandler
    mock_api.Request = MagicMock
    mock_api.Response = MagicMock
    sys.modules.setdefault("helpers.api", mock_api)
    sys.modules.setdefault("helpers.plugins", MagicMock())

    mock_vio = MagicMock()
    sys.modules["deimos_openbao_secrets_helpers_vault_io"] = mock_vio

    mock_cfg_mod = MagicMock()
    sys.modules.setdefault("deimos_openbao_secrets_helpers_config", mock_cfg_mod)

    path = os.path.join(os.path.dirname(__file__), "..", "api", "secrets.py")
    spec = importlib.util.spec_from_file_location("api_secrets_sync", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_plugin_yaml(tmp_path, plugin_name: str, secrets: list) -> Path:
    """Write a plugin.yaml with optional secrets: field to tmp_path."""
    plugin_dir = tmp_path / plugin_name
    plugin_dir.mkdir(parents=True)
    data = {"name": plugin_name, "title": plugin_name}
    if secrets:
        data["secrets"] = secrets
    (plugin_dir / "plugin.yaml").write_text(yaml.dump(data))
    return tmp_path


# ---------------------------------------------------------------------------
# AC-11, AC-12, AC-13 — exists status
# ---------------------------------------------------------------------------

def test_sync_returns_exists_when_key_in_vault(sync_mod, tmp_path):
    """AC-11, AC-12, AC-13: key already in OpenBao -> status exists."""
    _make_plugin_yaml(tmp_path, "my_plugin",
                      [{"key": "API_KEY_OPENAI", "description": "OpenAI key"}])
    handler = sync_mod.SyncPlugins()
    mock_vio = MagicMock()
    mock_vio._get_manager.return_value = MagicMock()
    mock_vio._vault_read.return_value = {"API_KEY_OPENAI": "already-there"}
    mock_cfg = MagicMock()
    mock_cfg.plugin_sync_enabled = True
    mock_cfg.url = "https://vault.example.com:8200"  # MED-06: HTTPS required for sync
    mock_cfg.secrets_path = "agentzero"

    with patch.object(sync_mod, "load_config", return_value=mock_cfg), \
         patch.object(sync_mod, "_load_vault_io", return_value=mock_vio), \
         patch.object(sync_mod, "_USR_PLUGINS_DIR", tmp_path):
        result = asyncio.run(handler.process({}, MagicMock()))

    assert result["ok"] is True                                    # AC-11: ok True
    secret_entry = result["plugins"][0]["secrets"][0]              # AC-12: shape check
    assert secret_entry["key"] == "API_KEY_OPENAI"                 # AC-12
    assert secret_entry["status"] == "exists"                      # AC-13: exists status
    mock_vio.write_if_absent.assert_not_called()                   # AC-13: no write on exists


# ---------------------------------------------------------------------------
# AC-13 — migrated status
# ---------------------------------------------------------------------------

def test_sync_migrates_from_env_when_key_absent_in_vault(sync_mod, tmp_path):
    """AC-13: key absent in vault + present in env -> status migrated."""
    _make_plugin_yaml(tmp_path, "my_plugin",
                      [{"key": "API_KEY_OPENAI", "description": "OpenAI key"}])
    handler = sync_mod.SyncPlugins()
    mock_vio = MagicMock()
    mock_vio._get_manager.return_value = MagicMock()
    mock_vio._vault_read.return_value = {}  # absent in vault
    mock_vio.write_if_absent.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.plugin_sync_enabled = True
    mock_cfg.url = "https://vault.example.com:8200"  # MED-06: HTTPS required for sync
    mock_cfg.secrets_path = "agentzero"

    with patch.object(sync_mod, "load_config", return_value=mock_cfg), \
         patch.object(sync_mod, "_load_vault_io", return_value=mock_vio), \
         patch.object(sync_mod, "_USR_PLUGINS_DIR", tmp_path), \
         patch.dict(os.environ, {"API_KEY_OPENAI": "sk-from-env"}):
        result = asyncio.run(handler.process({}, MagicMock()))

    assert result["ok"] is True                                    # AC-11
    assert result["plugins"][0]["secrets"][0]["status"] == "migrated"  # AC-13: migrated
    mock_vio.write_if_absent.assert_called_once()                  # AC-13: write called


# ---------------------------------------------------------------------------
# AC-13 — missing status
# ---------------------------------------------------------------------------

def test_sync_reports_missing_when_absent_from_both(sync_mod, tmp_path):
    """AC-13: key absent in vault AND env -> status missing, no write."""
    _make_plugin_yaml(tmp_path, "my_plugin",
                      [{"key": "GHOST_KEY", "description": "Never set"}])
    handler = sync_mod.SyncPlugins()
    mock_vio = MagicMock()
    mock_vio._get_manager.return_value = MagicMock()
    mock_cfg = MagicMock()
    mock_cfg.plugin_sync_enabled = True
    mock_cfg.url = "https://vault.example.com:8200"  # MED-06: HTTPS required for sync
    mock_cfg.secrets_path = "agentzero"

    with patch.object(sync_mod, "load_config", return_value=mock_cfg), \
         patch.object(sync_mod, "_load_vault_io", return_value=mock_vio), \
         patch.object(sync_mod, "_USR_PLUGINS_DIR", tmp_path), \
         patch.dict(os.environ, {}, clear=True):  # GHOST_KEY absent
        result = asyncio.run(handler.process({}, MagicMock()))

    assert result["ok"] is True                                    # AC-11
    assert result["plugins"][0]["secrets"][0]["status"] == "missing"  # AC-13: missing
    mock_vio.write_if_absent.assert_not_called()                   # AC-13: no write on missing


# ---------------------------------------------------------------------------
# AC-14 — gate: plugin_sync_enabled=False
# ---------------------------------------------------------------------------

def test_sync_disabled_gate_returns_error(sync_mod, tmp_path):
    """AC-14: plugin_sync_enabled=False -> endpoint returns ok=False error."""
    handler = sync_mod.SyncPlugins()
    mock_cfg = MagicMock()
    mock_cfg.plugin_sync_enabled = False

    with patch.object(sync_mod, "load_config", return_value=mock_cfg):
        result = asyncio.run(handler.process({}, MagicMock()))

    assert result["ok"] is False                                   # AC-14: gated
    assert "plugin_sync_enabled" in result["error"]                # AC-14: reason in message


# ---------------------------------------------------------------------------
# AC-11 — plugins without secrets field omitted
# ---------------------------------------------------------------------------

def test_sync_skips_plugins_without_secrets_field(sync_mod, tmp_path):
    """AC-11: plugins with no 'secrets:' field are omitted from results."""
    _make_plugin_yaml(tmp_path, "plain_plugin", secrets=[])  # no secrets field
    handler = sync_mod.SyncPlugins()
    mock_vio = MagicMock()
    mock_vio._get_manager.return_value = MagicMock()
    mock_cfg = MagicMock()
    mock_cfg.plugin_sync_enabled = True
    mock_cfg.url = "https://vault.example.com:8200"  # MED-06: HTTPS required for sync
    mock_cfg.secrets_path = "agentzero"

    with patch.object(sync_mod, "load_config", return_value=mock_cfg), \
         patch.object(sync_mod, "_load_vault_io", return_value=mock_vio), \
         patch.object(sync_mod, "_USR_PLUGINS_DIR", tmp_path):
        result = asyncio.run(handler.process({}, MagicMock()))

    assert result["ok"] is True                                    # AC-11
    assert result["plugins"] == []                                 # AC-11: empty — no secrets declared
