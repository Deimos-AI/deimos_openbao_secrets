"""
tests/test_config_meta.py

Covers:
  AC-07 — _sources dict tracks env / settings / default correctly
  AC-08 — config_meta endpoint returns ok:true + env_overrides list
  AC-04 — credential field names may appear; values never returned
  AC-01 — env-set fields appear in env_overrides
  AC-03 — settings-set fields do NOT appear in env_overrides
  AC-05 — bool (toggle) fields appear when set via env
  AC-06 — empty env -> empty env_overrides list
"""
import asyncio
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

_PLUGIN_DIR = Path(__file__).resolve().parent.parent


@pytest.fixture()
def clean_env():
    """Clear all OPENBAO_* environment variables for test isolation."""
    saved = {k: v for k, v in os.environ.items() if k.startswith("OPENBAO_")}
    for k in saved:
        del os.environ[k]
    yield
    # Restore original env
    for k in list(os.environ):
        if k.startswith("OPENBAO_") and k not in saved:
            del os.environ[k]
    os.environ.update(saved)


def _load_config_module():
    """Load helpers/config.py in isolated namespace, registering in sys.modules
    so Python 3.13 dataclass __module__ lookup succeeds."""
    mod_name = "deimos_openbao_secrets_config_test"
    spec = importlib.util.spec_from_file_location(
        mod_name,
        _PLUGIN_DIR / "helpers" / "config.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod  # required for Python 3.13 dataclass __module__ resolution
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(mod_name, None)
    return mod


def _load_config_meta_module():
    """Load api/config_meta.py, injecting helpers.api stub so ApiHandler import resolves."""
    # Stub helpers.api before loading config_meta (matches test_api_bootstrap.py pattern)
    _HELPERS_API_KEY = "helpers.api"
    _saved_api = sys.modules.get(_HELPERS_API_KEY)

    mock_api = MagicMock()

    class _StubApiHandler:
        pass

    mock_api.ApiHandler = _StubApiHandler
    mock_api.Request = MagicMock
    mock_api.Response = MagicMock
    sys.modules[_HELPERS_API_KEY] = mock_api

    mod_name = "deimos_openbao_config_meta_test"
    spec = importlib.util.spec_from_file_location(
        mod_name,
        _PLUGIN_DIR / "api" / "config_meta.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod  # required for Python 3.13 __module__ resolution
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(mod_name, None)
        # Restore helpers.api to prior state
        if _saved_api is None:
            sys.modules.pop(_HELPERS_API_KEY, None)
        else:
            sys.modules[_HELPERS_API_KEY] = _saved_api

    return mod


class TestSourcesTracking:
    """AC-07: load_config() _sources correctly tracks field origins."""

    def test_env_field_tracked_as_env(self, tmp_path, clean_env):
        """AC-07: OPENBAO_URL env var -> _sources['url'] == 'env'."""
        with patch.dict(os.environ, {"OPENBAO_URL": "https://vault.example.com:8200"}):
            cfg = _load_config_module().load_config(str(tmp_path))
        assert hasattr(cfg, "_sources")
        assert cfg._sources.get("url") == "env"

    def test_settings_field_tracked_as_settings(self, tmp_path, clean_env):
        """AC-07: url in settings.json -> _sources['url'] == 'settings'."""
        (tmp_path / "config.json").write_text('{"url": "https://local:8200"}')
        cfg = _load_config_module().load_config(str(tmp_path))
        assert cfg._sources.get("url") == "settings"

    def test_default_field_absent_from_sources(self, tmp_path, clean_env):
        """AC-07: field at default (no env, no settings) -> absent from _sources."""
        cfg = _load_config_module().load_config(str(tmp_path))
        assert "url" not in cfg._sources

    def test_env_wins_over_settings_source_is_env(self, tmp_path, clean_env):
        """AC-07: same field in both settings.json AND env -> _sources[field] == 'env'."""
        (tmp_path / "config.json").write_text('{"url": "https://from-settings:8200"}')
        with patch.dict(os.environ, {"OPENBAO_URL": "https://from-env:8200"}):
            cfg = _load_config_module().load_config(str(tmp_path))
        assert cfg._sources.get("url") == "env"
        assert cfg.url == "https://from-env:8200"

    def test_bool_field_tracked_as_env(self, tmp_path, clean_env):
        """AC-05/AC-07: OPENBAO_ENABLED env var -> _sources['enabled'] == 'env'."""
        with patch.dict(os.environ, {"OPENBAO_ENABLED": "true"}):
            cfg = _load_config_module().load_config(str(tmp_path))
        assert cfg._sources.get("enabled") == "env"
        assert cfg.enabled is True

    def test_all_22_field_to_env_fields_trackable(self, tmp_path, clean_env):
        """AC-07: all 22 OPENBAO_* env vars -> all 22 in _sources as 'env'."""
        env = {
            "OPENBAO_ENABLED": "true",
            "OPENBAO_URL": "https://vault:8200",
            "OPENBAO_AUTH_METHOD": "token",
            "OPENBAO_ROLE_ID": "test-role",
            "OPENBAO_SECRET_ID": "test-secret",
            "OPENBAO_TOKEN": "test-token",
            "OPENBAO_MOUNT_POINT": "secret",
            "OPENBAO_SECRETS_PATH": "agentzero",
            "OPENBAO_PROJECT_TEMPLATE": "agentzero-{project_slug}",
            "OPENBAO_TLS_VERIFY": "true",
            "OPENBAO_TLS_CA_CERT": "",
            "OPENBAO_TIMEOUT": "10",
            "OPENBAO_CACHE_TTL": "300",
            "OPENBAO_RETRY_ATTEMPTS": "3",
            "OPENBAO_CB_THRESHOLD": "5",
            "OPENBAO_CB_RECOVERY": "60",
            "OPENBAO_FALLBACK_TO_ENV": "true",
            "OPENBAO_HARD_FAIL_ON_UNAVAILABLE": "true",
            "OPENBAO_VAULT_NAMESPACE": "",
            "OPENBAO_VAULT_TOKEN_FILE": "",
            "OPENBAO_SECRET_ID_ENV": "OPENBAO_SECRET_ID",
            "OPENBAO_SECRET_ID_FILE": "",
        }
        with patch.dict(os.environ, env):
            cfg = _load_config_module().load_config(str(tmp_path))
        env_sourced = {k for k, v in cfg._sources.items() if v == "env"}
        # All 22 _FIELD_TO_ENV keys must appear as "env" when their env var is set
        expected = {
            "enabled", "url", "auth_method", "role_id", "secret_id", "token",
            "mount_point", "secrets_path", "vault_project_template", "tls_verify",
            "tls_ca_cert", "timeout", "cache_ttl", "retry_attempts",
            "circuit_breaker_threshold", "circuit_breaker_recovery",
            "fallback_to_env", "hard_fail_on_unavailable", "vault_namespace",
            "vault_token_file", "secret_id_env", "secret_id_file",
        }
        assert expected.issubset(env_sourced)

    def test_mixed_sources_correctly_distinguished(self, tmp_path, clean_env):
        """AC-07: url=env, mount_point=settings -> sources correctly split."""
        (tmp_path / "config.json").write_text('{"mount_point": "custom"}')
        with patch.dict(os.environ, {"OPENBAO_URL": "https://vault:8200"}):
            cfg = _load_config_module().load_config(str(tmp_path))
        assert cfg._sources.get("url") == "env"
        assert cfg._sources.get("mount_point") == "settings"
        assert "secrets_path" not in cfg._sources  # still at default


class TestConfigMetaEndpoint:
    """AC-08, AC-04, AC-01, AC-03, AC-06: endpoint behavior."""

    def _make_handler(self):
        mod = _load_config_meta_module()
        return mod.ConfigMeta()

    def test_returns_ok_true_with_env_overrides_list(self, tmp_path, clean_env):
        """AC-08: response structure is {ok: True, env_overrides: list}."""
        with patch.dict(os.environ, {"OPENBAO_URL": "https://vault:8200"}):
            handler = self._make_handler()
            result = asyncio.run(
                handler.process({}, MagicMock())
            )
        assert result["ok"] is True
        assert isinstance(result["env_overrides"], list)

    def test_env_overridden_fields_appear_in_list(self, tmp_path, clean_env):
        """AC-01/AC-08: url set via env -> 'url' in env_overrides."""
        with patch.dict(os.environ, {"OPENBAO_URL": "https://vault:8200",
                                      "OPENBAO_MOUNT_POINT": "secret"}):
            handler = self._make_handler()
            result = asyncio.run(
                handler.process({}, MagicMock())
            )
        assert "url" in result["env_overrides"]
        assert "mount_point" in result["env_overrides"]

    def test_settings_fields_absent_from_env_overrides(self, tmp_path, clean_env):
        """AC-03: field from settings.json only -> absent from env_overrides."""
        mock_cfg = MagicMock()
        mock_cfg._sources = {"url": "settings"}
        mod = _load_config_meta_module()
        with patch.object(mod, "load_config", return_value=mock_cfg):
            result = asyncio.run(
                mod.ConfigMeta().process({}, MagicMock())
            )
        assert "url" not in result["env_overrides"]

    def test_credential_names_included_values_not_returned(self, tmp_path, clean_env):
        """AC-04: role_id/secret_id/token in env_overrides when env-set; no value keys."""
        mock_cfg = MagicMock()
        mock_cfg._sources = {"role_id": "env", "token": "env"}
        mod = _load_config_meta_module()
        with patch.object(mod, "load_config", return_value=mock_cfg):
            result = asyncio.run(
                mod.ConfigMeta().process({}, MagicMock())
            )
        # Names present
        assert "role_id" in result["env_overrides"]
        assert "token" in result["env_overrides"]
        # No value keys in response
        assert "role_id_value" not in result
        assert "token_value" not in result
        assert "value" not in result
        # env_overrides is a list of strings (names), not dicts with values
        for item in result["env_overrides"]:
            assert isinstance(item, str)

    def test_no_env_vars_returns_empty_list(self, tmp_path, clean_env):
        """AC-06: no OPENBAO_* env vars -> env_overrides is empty list."""
        mock_cfg = MagicMock()
        mock_cfg._sources = {}  # nothing sourced from env or settings
        mod = _load_config_meta_module()
        with patch.object(mod, "load_config", return_value=mock_cfg):
            result = asyncio.run(
                mod.ConfigMeta().process({}, MagicMock())
            )
        assert result["ok"] is True
        assert result["env_overrides"] == []

    def test_bool_field_in_env_overrides(self, tmp_path, clean_env):
        """AC-05: OPENBAO_ENABLED env var -> 'enabled' in env_overrides."""
        mock_cfg = MagicMock()
        mock_cfg._sources = {"enabled": "env"}
        mod = _load_config_meta_module()
        with patch.object(mod, "load_config", return_value=mock_cfg):
            result = asyncio.run(
                mod.ConfigMeta().process({}, MagicMock())
            )
        assert "enabled" in result["env_overrides"]
