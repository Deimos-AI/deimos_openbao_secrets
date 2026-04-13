"""Test suite for helpers/install_flow.py — E-08 Evergreen Install Flow.

Acceptance criteria covered:
  AC-01  validate_connection: health check + auth verification
  AC-02  ensure_kv_mount: create KV v2 mount if absent
  AC-03  ensure_secrets_path: create path if absent
  AC-04  seed_terminal_secrets: seed from env vars into vault
  AC-05  bootstrap_registry: register seeded entries
  AC-08  Idempotent: re-running is a no-op for existing resources

All tests mock hvac.Client to avoid requiring a real OpenBao instance.
"""
from __future__ import annotations

import os
import sys
import types
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import helpers.install_flow as inf  # noqa: E402


# ===========================================================================
# Mock config factory
# ===========================================================================

def _make_config(**overrides):
    """Create a mock OpenBaoConfig with sensible defaults."""
    cfg = MagicMock()
    cfg.url = overrides.get("url", "http://127.0.0.1:8200")
    cfg.token = overrides.get("token", "test-token")
    cfg.auth_method = overrides.get("auth_method", "token")
    cfg.mount_point = overrides.get("mount_point", "secret")
    cfg.secrets_path = overrides.get("secrets_path", "agentzero")
    cfg.tls_verify = overrides.get("tls_verify", False)
    cfg.tls_ca_cert = overrides.get("tls_ca_cert", "")
    cfg.timeout = overrides.get("timeout", 5.0)
    cfg.vault_namespace = overrides.get("vault_namespace", "")
    cfg.terminal_secrets = overrides.get("terminal_secrets", [])
    cfg.enabled = overrides.get("enabled", True)
    return cfg


def _mock_hvac_client():
    """Create a mock hvac.Client that appears authenticated."""
    client = MagicMock()
    client.is_authenticated.return_value = True
    client.token = "test-token"
    return client


# ===========================================================================
# AC-01: validate_connection
# ===========================================================================

class TestValidateConnection:
    """AC-01: install() validates OpenBao connectivity before proceeding."""

    def test_connected_and_authenticated(self):
        """Successful connection returns connected=True, authenticated=True."""
        mock_client = _mock_hvac_client()
        mock_client.health_check.return_value = {
            "connected": True,
            "authenticated": True,
            "sealed": False,
        }

        with patch("helpers.openbao_client.OpenBaoClient", return_value=mock_client) as mock_cls:
            config = _make_config()
            result = inf.validate_connection(config)

        assert result["connected"] is True
        assert result["authenticated"] is True
        assert result["error"] is None
        mock_cls.assert_called_once_with(config)

    def test_unreachable_server(self):
        """Unreachable server returns connected=False with error."""
        mock_client = _mock_hvac_client()
        mock_client.health_check.return_value = {
            "connected": False,
            "authenticated": False,
            "sealed": None,
        }

        with patch("helpers.openbao_client.OpenBaoClient", return_value=mock_client):
            result = inf.validate_connection(_make_config())

        assert result["connected"] is False
        assert "unreachable" in result["error"].lower()

    def test_auth_failed(self):
        """Auth failure returns connected=True, authenticated=False with error."""
        mock_client = _mock_hvac_client()
        mock_client.health_check.return_value = {
            "connected": True,
            "authenticated": False,
            "sealed": False,
        }

        with patch("helpers.openbao_client.OpenBaoClient", return_value=mock_client):
            result = inf.validate_connection(_make_config())

        assert result["connected"] is True
        assert result["authenticated"] is False
        assert "authentication" in result["error"].lower()

    def test_sealed_vault(self):
        """Sealed vault returns error about seal status."""
        mock_client = _mock_hvac_client()
        mock_client.health_check.return_value = {
            "connected": True,
            "authenticated": True,
            "sealed": True,
        }

        with patch("helpers.openbao_client.OpenBaoClient", return_value=mock_client):
            result = inf.validate_connection(_make_config())

        assert result["sealed"] is True
        assert "sealed" in result["error"].lower()

    def test_connection_exception(self):
        """Exception during connection returns error without crashing."""
        with patch("helpers.openbao_client.OpenBaoClient", side_effect=ConnectionError("refused")):
            result = inf.validate_connection(_make_config())

        assert result["connected"] is False
        assert result["error"] is not None


# ===========================================================================
# AC-02: ensure_kv_mount
# ===========================================================================

class TestEnsureKvMount:
    """AC-02: install() creates KV v2 mount if absent."""

    def test_mount_already_exists(self):
        """Existing mount returns created=False, no error (idempotent)."""
        mock_client = _mock_hvac_client()
        mock_client.sys.list_mounted_secrets_engines.return_value = {
            "secret/": {"type": "kv", "options": {"version": "2"}},
        }

        with patch("hvac.Client", return_value=mock_client):
            result = inf.ensure_kv_mount(_make_config())

        assert result["created"] is False
        assert result["error"] is None
        assert result["mount_point"] == "secret"

    def test_mount_created(self):
        """Missing mount is created with KV v2 options."""
        mock_client = _mock_hvac_client()
        mock_client.sys.list_mounted_secrets_engines.return_value = {}

        with patch("hvac.Client", return_value=mock_client):
            result = inf.ensure_kv_mount(_make_config())

        assert result["created"] is True
        assert result["error"] is None
        mock_client.sys.enable_secrets_engine.assert_called_once()
        call_kwargs = mock_client.sys.enable_secrets_engine.call_args
        assert call_kwargs[1]["backend_type"] == "kv"
        assert call_kwargs[1]["options"] == {"version": "2"}

    def test_not_authenticated(self):
        """Unauthenticated client returns error."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = False

        with patch("hvac.Client", return_value=mock_client):
            result = inf.ensure_kv_mount(_make_config())

        assert result["error"] is not None
        assert "authenticated" in result["error"].lower()

    def test_create_failure(self):
        """Mount creation failure returns error."""
        mock_client = _mock_hvac_client()
        mock_client.sys.list_mounted_secrets_engines.side_effect = Exception("list failed")
        mock_client.sys.enable_secrets_engine.side_effect = Exception("forbidden")

        with patch("hvac.Client", return_value=mock_client):
            result = inf.ensure_kv_mount(_make_config())

        assert result["error"] is not None


# ===========================================================================
# AC-03: ensure_secrets_path
# ===========================================================================

class TestEnsureSecretsPath:
    """AC-03: install() creates secrets path if absent."""

    def test_path_already_exists(self):
        """Existing path returns created=False (idempotent)."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"KEY": "value"}},
        }

        with patch("hvac.Client", return_value=mock_client):
            result = inf.ensure_secrets_path(_make_config())

        assert result["created"] is False
        assert result["error"] is None

    def test_path_created(self):
        """Missing path is created with placeholder entry."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.side_effect = Exception("not found")

        with patch("hvac.Client", return_value=mock_client):
            result = inf.ensure_secrets_path(_make_config())

        assert result["created"] is True
        assert result["error"] is None
        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once()

    def test_not_authenticated(self):
        """Unauthenticated client returns error."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = False

        with patch("hvac.Client", return_value=mock_client):
            result = inf.ensure_secrets_path(_make_config())

        assert result["error"] is not None
        assert "authenticated" in result["error"].lower()


# ===========================================================================
# AC-04: seed_terminal_secrets
# ===========================================================================

class TestSeedTerminalSecrets:
    """AC-04: install() seeds terminal_secrets from env vars into vault."""

    def test_no_terminal_secrets_configured(self):
        """Empty terminal_secrets list returns empty result."""
        result = inf.seed_terminal_secrets(_make_config(terminal_secrets=[]))
        assert result["seeded"] == []
        assert result["skipped"] == []
        assert result["errors"] == []

    def test_seed_from_env(self):
        """Secrets present in env are written to vault."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {}},
        }

        env_vars = {"API_KEY": "test-value", "GH_TOKEN": "gh-test"}
        with patch("hvac.Client", return_value=mock_client), \
             patch.dict(os.environ, env_vars, clear=False):
            result = inf.seed_terminal_secrets(
                _make_config(terminal_secrets=["API_KEY", "GH_TOKEN"])
            )

        assert "API_KEY" in result["seeded"]
        assert "GH_TOKEN" in result["seeded"]
        assert result["errors"] == []
        assert mock_client.secrets.kv.v2.create_or_update_secret.call_count == 2

    def test_skip_existing_in_vault(self):
        """Secrets already in vault are skipped (idempotent). AC-08."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"API_KEY": "existing-value"}},
        }

        with patch("hvac.Client", return_value=mock_client), \
             patch.dict(os.environ, {"API_KEY": "new-value"}, clear=False):
            result = inf.seed_terminal_secrets(
                _make_config(terminal_secrets=["API_KEY"])
            )

        assert "API_KEY" in result["skipped"]
        assert result["seeded"] == []
        mock_client.secrets.kv.v2.create_or_update_secret.assert_not_called()

    def test_skip_not_in_env(self):
        """Secrets not present in env are skipped."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {}},
        }

        with patch("hvac.Client", return_value=mock_client), \
             patch.dict(os.environ, {}, clear=False):
            result = inf.seed_terminal_secrets(
                _make_config(terminal_secrets=["MISSING_KEY"])
            )

        assert "MISSING_KEY" in result["skipped"]
        assert result["seeded"] == []

    def test_write_error(self):
        """Write failure for one key is recorded in errors."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {}},
        }
        mock_client.secrets.kv.v2.create_or_update_secret.side_effect = Exception("write failed")

        with patch("hvac.Client", return_value=mock_client), \
             patch.dict(os.environ, {"API_KEY": "val"}, clear=False):
            result = inf.seed_terminal_secrets(
                _make_config(terminal_secrets=["API_KEY"])
            )

        assert len(result["errors"]) == 1
        assert "API_KEY" in result["errors"][0]


# ===========================================================================
# AC-05: bootstrap_registry
# ===========================================================================

class TestBootstrapRegistry:
    """AC-05: install() bootstraps secrets registry with seeded entries."""

    def test_empty_seeded_keys(self):
        """No seeded keys results in empty registry with bootstrapped_at."""
        result = inf.bootstrap_registry(_make_config(), seeded_keys=[])
        assert result["registered"] == 0
        assert result["skipped"] == 0
        assert result["bootstrapped_at"] is not None
        assert result["error"] is None

    def test_register_seeded_keys(self):
        """Seeded keys are registered with 'migrated' status."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {"version": 1, "entries": []}

        with patch("helpers.registry.RegistryManager", return_value=mock_rm), \
             patch("helpers.registry.RegistryEntry") as mock_entry_cls:
            mock_entry = MagicMock()
            mock_entry.id = "test-id"
            mock_entry.to_dict.return_value = {"id": "test-id", "key": "API_KEY"}
            mock_entry_cls.return_value = mock_entry
            mock_entry_cls.make_id.return_value = "test-id"

            result = inf.bootstrap_registry(
                _make_config(), seeded_keys=["API_KEY"]
            )

        assert result["registered"] == 1
        assert result["error"] is None
        mock_rm.save.assert_called_once()

    def test_skip_existing_entries(self):
        """Already-registered entries are skipped (idempotent). AC-08."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "version": 1,
            "entries": [{"id": "test-id", "key": "API_KEY"}],
        }

        with patch("helpers.registry.RegistryManager", return_value=mock_rm), \
             patch("helpers.registry.RegistryEntry") as mock_entry_cls:
            mock_entry = MagicMock()
            mock_entry.id = "test-id"
            mock_entry_cls.return_value = mock_entry
            mock_entry_cls.make_id.return_value = "test-id"

            result = inf.bootstrap_registry(
                _make_config(), seeded_keys=["API_KEY"]
            )

        assert result["skipped"] == 1
        assert result["registered"] == 0
        mock_rm.save.assert_called_once()  # Still saves bootstrapped_at

    def test_registry_error(self):
        """Registry error returns error but doesn't crash."""
        with patch("helpers.registry.RegistryManager", side_effect=Exception("no registry")):
            result = inf.bootstrap_registry(_make_config(), seeded_keys=["KEY"])

        assert result["error"] is not None
        assert "registry" in result["error"].lower()


# ===========================================================================
# patch_core.py integration
# ===========================================================================

class TestPatchCore:
    """User requirement: patch_core.py is executed as part of install flow."""

    def test_should_apply_when_not_patched(self):
        """should_apply_core_patch returns True when patch not present."""
        with patch("helpers.install_flow.Path") as mock_path_cls:
            mock_path = MagicMock()
            mock_path.exists.return_value = True
            mock_path.read_text.return_value = "original content without patch"
            mock_path_cls.return_value = mock_path
            # Need __truediv__ to not interfere
            mock_path_cls.side_effect = lambda p: mock_path
            result = inf.should_apply_core_patch()

    def test_should_not_apply_when_already_patched(self):
        """should_apply_core_patch returns False when already patched."""
        with patch("helpers.install_flow.Path") as mock_path_cls:
            mock_path = MagicMock()
            mock_path.exists.return_value = True
            mock_path.read_text.return_value = "some code hook_context={'caller': 'ui'} more code"
            mock_path_cls.side_effect = lambda p: mock_path
            result = inf.should_apply_core_patch()

    def test_apply_core_patch_already_applied(self):
        """apply_core_patch returns immediately if already patched."""
        with patch.object(inf, "should_apply_core_patch", return_value=False):
            result = inf.apply_core_patch()
        assert result["applied"] is True
        assert "skip" in result["output"].lower()

    def test_apply_core_patch_script_not_found(self):
        """Missing patch script is non-fatal."""
        with patch.object(inf, "should_apply_core_patch", return_value=True):
            with patch("helpers.install_flow.Path") as mock_path:
                p1 = MagicMock()
                p1.exists.return_value = False
                p2 = MagicMock()
                p2.exists.return_value = False
                # First call checks primary location, second checks alternate
                mock_path.side_effect = [p1, p2]
                result = inf.apply_core_patch()

        assert result["applied"] is True  # Non-fatal
        assert result["error"] is not None

    def test_apply_core_patch_success(self):
        """Successful patch execution returns applied=True."""
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "OK patch applied"
        mock_proc.stderr = ""

        with patch.object(inf, "should_apply_core_patch", return_value=True), \
             patch("helpers.install_flow.Path") as mock_path, \
             patch("subprocess.run", return_value=mock_proc) as mock_run:
            p1 = MagicMock()
            p1.exists.return_value = True
            p1.__str__ = lambda s: "/path/patch_core.py"
            mock_path.side_effect = [p1]
            result = inf.apply_core_patch()

        assert result["applied"] is True


# ===========================================================================
# AC-08: Idempotency
# ===========================================================================

class TestIdempotency:
    """AC-08: Install is idempotent — re-running is a no-op for existing resources."""

    def test_ensure_kv_mount_idempotent(self):
        """Calling ensure_kv_mount twice on existing mount returns created=False both times."""
        mock_client = _mock_hvac_client()
        mock_client.sys.list_mounted_secrets_engines.return_value = {
            "secret/": {"type": "kv"},
        }

        with patch("hvac.Client", return_value=mock_client):
            r1 = inf.ensure_kv_mount(_make_config())
            r2 = inf.ensure_kv_mount(_make_config())

        assert r1["created"] is False
        assert r2["created"] is False
        assert r1["error"] is None
        assert r2["error"] is None

    def test_ensure_secrets_path_idempotent(self):
        """Calling ensure_secrets_path twice on existing path returns created=False."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"KEY": "val"}},
        }

        with patch("hvac.Client", return_value=mock_client):
            r1 = inf.ensure_secrets_path(_make_config())
            r2 = inf.ensure_secrets_path(_make_config())

        assert r1["created"] is False
        assert r2["created"] is False

    def test_seed_skips_existing_secrets(self):
        """seed_terminal_secrets skips keys already in vault."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"API_KEY": "existing"}},
        }

        with patch("hvac.Client", return_value=mock_client), \
             patch.dict(os.environ, {"API_KEY": "new-val"}, clear=False):
            r1 = inf.seed_terminal_secrets(
                _make_config(terminal_secrets=["API_KEY"])
            )

        assert "API_KEY" in r1["skipped"]


# ===========================================================================
# E-08-ext: Vault secrets discovery — AC-D1
# ===========================================================================

class TestDiscoverExistingSecrets:
    """AC-D1: discover_existing_secrets lists key names from vault."""

    def test_empty_vault_returns_count_zero(self):
        """Empty vault (no secrets) returns keys=[], count=0."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = None

        with patch("hvac.Client", return_value=mock_client):
            result = inf.discover_existing_secrets(_make_config())

        assert result["keys"] == []
        assert result["count"] == 0
        assert result["error"] is None

    def test_populated_vault_returns_key_names(self):
        """Vault with secrets returns sorted key names, never values."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"API_KEY": "secret123", "DB_PASSWORD": "hunter2"}},
        }

        with patch("hvac.Client", return_value=mock_client):
            result = inf.discover_existing_secrets(_make_config())

        assert result["keys"] == ["API_KEY", "DB_PASSWORD"]
        assert result["count"] == 2
        assert result["error"] is None

    def test_filters_internal_initialized_marker(self):
        """Internal _initialized marker is excluded from results."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"_initialized": "true", "SECRET": "val"}},
        }

        with patch("hvac.Client", return_value=mock_client):
            result = inf.discover_existing_secrets(_make_config())

        assert result["keys"] == ["SECRET"]
        assert result["count"] == 1

    def test_not_authenticated_returns_error(self):
        """Unauthenticated client returns error, empty keys."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = False

        with patch("hvac.Client", return_value=mock_client):
            result = inf.discover_existing_secrets(_make_config())

        assert result["error"] is not None
        assert "Not authenticated" in result["error"]
        assert result["keys"] == []
        assert result["count"] == 0

    def test_connection_error_returns_error(self):
        """Connection error returns error message, empty keys."""
        with patch("hvac.Client", side_effect=ConnectionError("refused")):
            result = inf.discover_existing_secrets(_make_config())

        assert result["error"] is not None
        assert result["keys"] == []

    def test_keys_are_sorted(self):
        """Returned keys are sorted alphabetically."""
        mock_client = _mock_hvac_client()
        mock_client.secrets.kv.v2.read_secret_version.return_value = {
            "data": {"data": {"ZEBRA": "z", "APPLE": "a", "MANGO": "m"}},
        }

        with patch("hvac.Client", return_value=mock_client):
            result = inf.discover_existing_secrets(_make_config())

        assert result["keys"] == ["APPLE", "MANGO", "ZEBRA"]


# ===========================================================================
# E-08-ext: Brownfield discovery registration — AC-D2
# ===========================================================================

class TestRegisterDiscoveredSecrets:
    """AC-D2: register_discovered_secrets marks entries as 'discovered'."""

    def test_registers_keys_as_discovered(self):
        """Each key is registered with status='discovered' in registry."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {"entries": [], "bootstrapped_at": None}
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm
        mock_registry_mod.RegistryEntry = inf.RegistryEntry if hasattr(inf, 'RegistryEntry') else MagicMock()

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            result = inf.register_discovered_secrets(_make_config(), ["KEY1", "KEY2"])

        assert result["registered"] == 2
        assert result["skipped"] == 0
        assert result["error"] is None
        assert result["discovered_at"] is not None
        # Verify save was called
        mock_rm.save.assert_called_once()
        # Verify discovery metadata in saved registry
        saved = mock_rm.save.call_args[0][0]
        assert saved["discovery_status"] == "discovered"
        assert saved["vault_secret_keys"] == ["KEY1", "KEY2"]

    def test_skips_already_registered_keys(self):
        """Keys already in registry are skipped (idempotent)."""
        from helpers.registry import RegistryEntry
        existing_id = RegistryEntry.make_id("vault_discovery", "existing_secrets", "KEY1")

        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [{"id": existing_id, "key": "KEY1", "status": "discovered"}],
            "bootstrapped_at": None,
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm
        mock_registry_mod.RegistryEntry = RegistryEntry  # Use real class for correct IDs

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            result = inf.register_discovered_secrets(_make_config(), ["KEY1", "KEY2"])

        assert result["registered"] == 1  # KEY2 new, KEY1 skipped
        assert result["skipped"] == 1

    def test_empty_keys_returns_early(self):
        """Empty key list returns registered=0, no registry write."""
        result = inf.register_discovered_secrets(_make_config(), [])
        assert result["registered"] == 0
        assert result["discovered_at"] is not None

    def test_registry_save_failure_returns_error(self):
        """Registry save failure is caught and returned as error."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {"entries": []}
        mock_rm.save.side_effect = OSError("disk full")
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm
        # Need real RegistryEntry for the loop
        try:
            from helpers.registry import RegistryEntry as RE
            mock_registry_mod.RegistryEntry = RE
        except Exception:
            pass

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            result = inf.register_discovered_secrets(_make_config(), ["KEY1"])

        assert result["error"] is not None
        assert "failed" in result["error"].lower()


# ===========================================================================
# E-08-ext: _bootstrap_vault fork — AC-D1 integration
# ===========================================================================

class TestBootstrapVaultFork:
    """AC-D1 integration: _bootstrap_vault forks between fresh and brownfield."""

    def test_fresh_path_seeds_and_bootstraps(self):
        """Empty vault triggers fresh evergreen path (seed + bootstrap)."""
        import hooks as hk

        mock_install = MagicMock()
        mock_install.apply_core_patch.return_value = {"applied": True, "error": None}
        mock_install.validate_connection.return_value = {"error": None, "connected": True}
        mock_install.ensure_kv_mount.return_value = {"error": None}
        mock_install.ensure_secrets_path.return_value = {"error": None}
        mock_install.discover_existing_secrets.return_value = {"keys": [], "count": 0, "error": None}
        mock_install.seed_terminal_secrets.return_value = {"seeded": ["KEY1"], "skipped": [], "errors": []}
        mock_install.bootstrap_registry.return_value = {"registered": 1, "skipped": 0, "error": None}

        mock_config_mod = MagicMock()
        config = _make_config()
        mock_config_mod.load_config.return_value = config
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"

        with patch.dict(sys.modules, {
            "helpers.install_flow": mock_install,
            "helpers.config": mock_config_mod,
            "helpers.plugins": mock_plugins,
        }):
            hk._bootstrap_vault()

        # Verify fresh path was taken
        mock_install.seed_terminal_secrets.assert_called_once_with(config)
        mock_install.bootstrap_registry.assert_called_once_with(config, ["KEY1"])
        # Verify brownfield path was NOT taken
        mock_install.register_discovered_secrets.assert_not_called()

    def test_brownfield_path_registers_and_stops(self):
        """Populated vault triggers brownfield path — no seed, no bootstrap."""
        import hooks as hk

        mock_install = MagicMock()
        mock_install.apply_core_patch.return_value = {"applied": True, "error": None}
        mock_install.validate_connection.return_value = {"error": None, "connected": True}
        mock_install.ensure_kv_mount.return_value = {"error": None}
        mock_install.ensure_secrets_path.return_value = {"error": None}
        mock_install.discover_existing_secrets.return_value = {
            "keys": ["EXISTING_KEY"], "count": 1, "error": None,
        }
        mock_install.register_discovered_secrets.return_value = {
            "registered": 1, "skipped": 0, "error": None,
        }

        mock_config_mod = MagicMock()
        config = _make_config()
        mock_config_mod.load_config.return_value = config
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"

        with patch.dict(sys.modules, {
            "helpers.install_flow": mock_install,
            "helpers.config": mock_config_mod,
            "helpers.plugins": mock_plugins,
        }):
            hk._bootstrap_vault()

        # Verify brownfield path was taken
        mock_install.register_discovered_secrets.assert_called_once_with(config, ["EXISTING_KEY"])
        # Verify fresh path was NOT taken
        mock_install.seed_terminal_secrets.assert_not_called()
        mock_install.bootstrap_registry.assert_not_called()

    def test_discovery_error_falls_through_to_fresh(self):
        """Discovery scan error is non-fatal — falls through to fresh path."""
        import hooks as hk

        mock_install = MagicMock()
        mock_install.apply_core_patch.return_value = {"applied": True, "error": None}
        mock_install.validate_connection.return_value = {"error": None, "connected": True}
        mock_install.ensure_kv_mount.return_value = {"error": None}
        mock_install.ensure_secrets_path.return_value = {"error": None}
        mock_install.discover_existing_secrets.return_value = {
            "keys": [], "count": 0, "error": "scan failed",
        }
        mock_install.seed_terminal_secrets.return_value = {"seeded": [], "skipped": [], "errors": []}
        mock_install.bootstrap_registry.return_value = {"registered": 0, "skipped": 0, "error": None}

        mock_config_mod = MagicMock()
        config = _make_config()
        mock_config_mod.load_config.return_value = config
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"

        with patch.dict(sys.modules, {
            "helpers.install_flow": mock_install,
            "helpers.config": mock_config_mod,
            "helpers.plugins": mock_plugins,
        }):
            hk._bootstrap_vault()

        # Fresh path taken despite discovery error
        mock_install.seed_terminal_secrets.assert_called_once()
        mock_install.register_discovered_secrets.assert_not_called()

    def test_idempotent_rerun_with_existing_secrets(self):
        """Re-running install with existing secrets doesn't re-register."""
        import hooks as hk

        mock_install = MagicMock()
        mock_install.apply_core_patch.return_value = {"applied": True, "error": None}
        mock_install.validate_connection.return_value = {"error": None, "connected": True}
        mock_install.ensure_kv_mount.return_value = {"error": None}
        mock_install.ensure_secrets_path.return_value = {"error": None}
        mock_install.discover_existing_secrets.return_value = {
            "keys": ["KEY1"], "count": 1, "error": None,
        }
        mock_install.register_discovered_secrets.return_value = {
            "registered": 0, "skipped": 1, "error": None,
        }

        mock_config_mod = MagicMock()
        config = _make_config()
        mock_config_mod.load_config.return_value = config
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = "/fake/dir"

        with patch.dict(sys.modules, {
            "helpers.install_flow": mock_install,
            "helpers.config": mock_config_mod,
            "helpers.plugins": mock_plugins,
        }):
            hk._bootstrap_vault()

        # Brownfield path taken, register called (idempotent — skipped)
        mock_install.register_discovered_secrets.assert_called_once()
        result = mock_install.register_discovered_secrets.return_value
        assert result["skipped"] == 1
