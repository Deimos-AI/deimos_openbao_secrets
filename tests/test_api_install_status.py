"""Test suite for api/install_status.py — E-08 AC-07.

Acceptance criteria covered:
  AC-07  WebUI config page shows install status
"""
from __future__ import annotations

import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.install_status import InstallStatus  # noqa: E402


def _make_config(**overrides):
    cfg = MagicMock()
    cfg.url = overrides.get("url", "http://127.0.0.1:8200")
    cfg.token = overrides.get("token", "test-token")
    cfg.mount_point = overrides.get("mount_point", "secret")
    cfg.secrets_path = overrides.get("secrets_path", "agentzero")
    cfg.tls_verify = overrides.get("tls_verify", False)
    cfg.tls_ca_cert = overrides.get("tls_ca_cert", "")
    cfg.timeout = overrides.get("timeout", 5.0)
    cfg.vault_namespace = overrides.get("vault_namespace", "")
    cfg.enabled = overrides.get("enabled", True)
    return cfg


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def clean_sys_modules():
    """Clean deferred import modules between tests."""
    for key in ("openbao_helpers.config", "helpers.plugins", "openbao_helpers.openbao_client", "openbao_helpers.registry"):
        sys.modules.pop(key, None)
    yield
    for key in ("openbao_helpers.config", "helpers.plugins", "openbao_helpers.openbao_client", "openbao_helpers.registry"):
        sys.modules.pop(key, None)


class TestInstallStatusEndpoint:
    """AC-07: install_status returns structured status."""

    def test_plugin_dir_not_found(self):
        """Returns error when plugin directory not found."""
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = None

        with patch.dict(sys.modules, {"helpers.plugins": mock_plugins}):
            handler = InstallStatus()
            result = _run(handler.process())

        assert result["ok"] is False
        assert "not found" in result["status"]["errors"][0].lower()

    def test_plugin_disabled(self):
        """Returns error when plugin is disabled."""
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"
        mock_config_mod = MagicMock()
        config = _make_config(enabled=False)
        mock_config_mod.load_config.return_value = config

        with patch.dict(sys.modules, {
            "helpers.plugins": mock_plugins,
            "openbao_helpers.config": mock_config_mod,
        }):
            handler = InstallStatus()
            result = _run(handler.process())

        assert result["ok"] is False
        assert "disabled" in result["status"]["errors"][0].lower()

    def test_connected_with_secrets(self):
        """Returns full status when connected with secrets."""
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"
        mock_config_mod = MagicMock()
        config = _make_config()
        mock_config_mod.load_config.return_value = config

        mock_client = MagicMock()
        mock_client.health_check.return_value = {
            "connected": True, "authenticated": True, "sealed": False,
        }
        mock_client._client = MagicMock()
        mock_client._client.sys.list_mounted_secrets_engines.return_value = {
            "secret/": {"type": "kv"},
        }
        mock_client._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"KEY1": "val1", "KEY2": "val2"}},
        }
        mock_client_mod = MagicMock()
        mock_client_mod.OpenBaoClient.return_value = mock_client

        mock_registry_mod = MagicMock()
        mock_rm = MagicMock()
        mock_rm.load.return_value = {"entries": [{"id": "1"}, {"id": "2"}], "bootstrapped_at": "2026-01-01"}
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {
            "helpers.plugins": mock_plugins,
            "openbao_helpers.config": mock_config_mod,
            "openbao_helpers.openbao_client": mock_client_mod,
            "openbao_helpers.registry": mock_registry_mod,
        }):
            handler = InstallStatus()
            result = _run(handler.process())

        s = result["status"]
        assert result["ok"] is True
        assert s["connected"] is True
        assert s["authenticated"] is True
        assert s["mount_exists"] is True
        assert s["path_exists"] is True
        assert s["secrets_count"] == 2
        assert s["registry_count"] == 2
        assert s["bootstrapped_at"] == "2026-01-01"

    def test_connection_error(self):
        """Returns error when OpenBao unreachable."""
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"
        mock_config_mod = MagicMock()
        config = _make_config()
        mock_config_mod.load_config.return_value = config

        mock_client_mod = MagicMock()
        mock_client_mod.OpenBaoClient.side_effect = ConnectionError("refused")

        with patch.dict(sys.modules, {
            "helpers.plugins": mock_plugins,
            "openbao_helpers.config": mock_config_mod,
            "openbao_helpers.openbao_client": mock_client_mod,
        }):
            handler = InstallStatus()
            result = _run(handler.process())

        assert result["ok"] is False
        assert len(result["status"]["errors"]) > 0

    def test_status_default_values(self):
        """Status has all expected default keys."""
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = None

        with patch.dict(sys.modules, {"helpers.plugins": mock_plugins}):
            handler = InstallStatus()
            result = _run(handler.process())

        s = result["status"]
        assert "connected" in s
        assert "authenticated" in s
        assert "mount_exists" in s
        assert "path_exists" in s
        assert "secrets_count" in s
        assert "registry_count" in s
        assert "bootstrapped_at" in s

    def test_discovery_fields_default_to_fresh(self):
        """Discovery fields default to fresh/empty when no discovery metadata."""
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = None

        with patch.dict(sys.modules, {"helpers.plugins": mock_plugins}):
            handler = InstallStatus()
            result = _run(handler.process())

        s = result["status"]
        assert s["vault_secrets_count"] == 0
        assert s["vault_secret_keys"] == []
        assert s["discovery_status"] == "fresh"
        assert s["awaiting_confirmation"] is False

    def test_discovery_status_discovered(self):
        """awaiting_confirmation=True when registry has discovery_status='discovered'."""
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"
        mock_config_mod = MagicMock()
        config = _make_config()
        mock_config_mod.load_config.return_value = config

        mock_client = MagicMock()
        mock_client.health_check.return_value = {
            "connected": True, "authenticated": True, "sealed": False,
        }
        mock_client._client = MagicMock()
        mock_client._client.sys.list_mounted_secrets_engines.return_value = {
            "secret/": {"type": "kv"},
        }
        mock_client._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"KEY1": "val1"}},
        }
        mock_client_mod = MagicMock()
        mock_client_mod.OpenBaoClient.return_value = mock_client

        mock_registry_mod = MagicMock()
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [{"id": "1"}],
            "bootstrapped_at": "2026-01-01",
            "discovery_status": "discovered",
            "vault_secret_keys": ["KEY1", "KEY2"],
        }
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {
            "helpers.plugins": mock_plugins,
            "openbao_helpers.config": mock_config_mod,
            "openbao_helpers.openbao_client": mock_client_mod,
            "openbao_helpers.registry": mock_registry_mod,
        }):
            handler = InstallStatus()
            result = _run(handler.process())

        s = result["status"]
        assert s["discovery_status"] == "discovered"
        assert s["vault_secrets_count"] == 2
        assert s["vault_secret_keys"] == ["KEY1", "KEY2"]
        assert s["awaiting_confirmation"] is True

    def test_discovery_status_propagated(self):
        """awaiting_confirmation=False when discovery_status='propagated'."""
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"
        mock_config_mod = MagicMock()
        config = _make_config()
        mock_config_mod.load_config.return_value = config

        mock_client = MagicMock()
        mock_client.health_check.return_value = {
            "connected": True, "authenticated": True, "sealed": False,
        }
        mock_client._client = MagicMock()
        mock_client._client.sys.list_mounted_secrets_engines.return_value = {
            "secret/": {"type": "kv"},
        }
        mock_client._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"KEY1": "val1"}},
        }
        mock_client_mod = MagicMock()
        mock_client_mod.OpenBaoClient.return_value = mock_client

        mock_registry_mod = MagicMock()
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [{"id": "1"}],
            "bootstrapped_at": "2026-01-01",
            "discovery_status": "propagated",
            "vault_secret_keys": ["KEY1"],
            "propagated_at": "2026-01-02",
        }
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {
            "helpers.plugins": mock_plugins,
            "openbao_helpers.config": mock_config_mod,
            "openbao_helpers.openbao_client": mock_client_mod,
            "openbao_helpers.registry": mock_registry_mod,
        }):
            handler = InstallStatus()
            result = _run(handler.process())

        s = result["status"]
        assert s["discovery_status"] == "propagated"
        assert s["vault_secrets_count"] == 1
        assert s["awaiting_confirmation"] is False

    def test_secrets_count_excludes_internal_keys(self):
        """secrets_count excludes keys starting with underscore."""
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"
        mock_config_mod = MagicMock()
        config = _make_config()
        mock_config_mod.load_config.return_value = config

        mock_client = MagicMock()
        mock_client.health_check.return_value = {
            "connected": True, "authenticated": True, "sealed": False,
        }
        mock_client._client = MagicMock()
        mock_client._client.sys.list_mounted_secrets_engines.return_value = {
            "secret/": {"type": "kv"},
        }
        mock_client._client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"_initialized": "true", "API_KEY": "val"}},
        }
        mock_client_mod = MagicMock()
        mock_client_mod.OpenBaoClient.return_value = mock_client

        mock_registry_mod = MagicMock()
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [], "bootstrapped_at": None,
        }
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {
            "helpers.plugins": mock_plugins,
            "openbao_helpers.config": mock_config_mod,
            "openbao_helpers.openbao_client": mock_client_mod,
            "openbao_helpers.registry": mock_registry_mod,
        }):
            handler = InstallStatus()
            result = _run(handler.process())

        s = result["status"]
        assert s["secrets_count"] == 1  # Only API_KEY, not _initialized
        assert "errors" in s
