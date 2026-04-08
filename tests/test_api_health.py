"""Tests for api/health.py — TestConnection API handler.

Covers AC-01 (file creation) and AC-04 (7 test cases):
  no_url, sealed_vault, token_auth_missing_env, token_auth_success,
  approle_auth_success, approle_login_failure, hvac_not_installed.

Satisfies: AC-01, AC-04

Notes on mock strategy:
  health.py does `import hvac` INSIDE process() — not at module level.
  patch.object(mod, 'hvac', ...) would silently do nothing because the
  function-local `import hvac` reads sys.modules directly.
  Correct approach: patch.dict(sys.modules, {'hvac': mock_hvac}).
"""
import asyncio
import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch
import pytest


@pytest.fixture(scope="module")
def health_mod():
    """Load api/health.py with A0 runtime deps stubbed.

    Satisfies: AC-01 (file created and loadable)
    """
    mock_api = MagicMock()

    class _StubApiHandler:
        pass

    mock_api.ApiHandler = _StubApiHandler
    mock_api.Request = MagicMock
    mock_api.Response = MagicMock
    sys.modules.setdefault("helpers.api", mock_api)
    sys.modules.setdefault("helpers.plugins", MagicMock())
    # hvac stub — process() does `import hvac` inside function body
    sys.modules.setdefault("hvac", MagicMock())

    path = os.path.join(os.path.dirname(__file__), "..", "api", "health.py")
    spec = importlib.util.spec_from_file_location("api_health", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# AC-04: hvac_not_installed
# ---------------------------------------------------------------------------

def test_hvac_not_installed_returns_error(health_mod):
    """AC-04: hvac unavailable returns ok=False with 'hvac' in error.

    Satisfies: AC-04 (hvac_not_installed)
    """
    handler = health_mod.TestConnection()
    with patch.object(health_mod, "_ensure_hvac", return_value=False):
        result = asyncio.run(handler.process({"config": {}}, MagicMock()))

    assert result["ok"] is False           # AC-04: hvac_not_installed
    assert "hvac" in result["error"]       # AC-04


# ---------------------------------------------------------------------------
# AC-04: no_url
# ---------------------------------------------------------------------------

def test_no_url_returns_error(health_mod):
    """AC-04: missing url returns ok=False error.

    Satisfies: AC-04 (no_url)
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.dict(sys.modules, {"hvac": mock_hvac}):
        result = asyncio.run(handler.process({"config": {"url": ""}}, MagicMock()))

    assert result["ok"] is False                           # AC-04: no_url
    assert "No OpenBao URL configured" in result["error"]  # AC-04


# ---------------------------------------------------------------------------
# AC-04: sealed_vault
# ---------------------------------------------------------------------------

def test_sealed_vault_returns_error(health_mod):
    """AC-04: sealed vault returns ok=False with SEALED error.

    Satisfies: AC-04 (sealed_vault)
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_hvac.Client.return_value.sys.read_health_status.return_value = {
        "initialized": True, "sealed": True, "version": "2.0.0"
    }

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.dict(sys.modules, {"hvac": mock_hvac}):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is False                    # AC-04: sealed_vault
    assert "SEALED" in result["error"]              # AC-04
    assert result["data"]["sealed"] is True         # AC-04
    assert result["data"]["authenticated"] is False # AC-04


# ---------------------------------------------------------------------------
# AC-04: token_auth_missing_env
# ---------------------------------------------------------------------------

def test_token_auth_missing_env_returns_error(health_mod):
    """AC-04: token auth with no OPENBAO_TOKEN env returns ok=False.

    Satisfies: AC-04 (token_auth_missing_env)
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_hvac.Client.return_value.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "token"
    mock_cfg.token = ""  # REM-024: empty → triggers env fallback

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {}, clear=True):   # ensure OPENBAO_TOKEN absent
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is False                         # AC-04: token_auth_missing_env
    assert "OPENBAO_TOKEN" in result["error"]             # AC-04
    assert result["data"]["auth_method"] == "token"       # AC-04


# ---------------------------------------------------------------------------
# AC-04: token_auth_success
# ---------------------------------------------------------------------------

def test_token_auth_success(health_mod):
    """AC-04: valid token auth returns ok=True with authenticated=True.

    Satisfies: AC-04 (token_auth_success)
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_client.is_authenticated.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "token"
    mock_cfg.token = ""  # REM-024: empty → uses env OPENBAO_TOKEN

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {"OPENBAO_TOKEN": "s.valid-token"}):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is True                           # AC-04: token_auth_success
    assert result["data"]["authenticated"] is True        # AC-04
    assert result["data"]["auth_method"] == "token"       # AC-04


# ---------------------------------------------------------------------------
# AC-04: approle_auth_success
# ---------------------------------------------------------------------------

def test_approle_auth_success(health_mod):
    """AC-04: valid approle auth returns ok=True with authenticated=True.

    Satisfies: AC-04 (approle_auth_success)
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_client.auth.approle.login.return_value = {"auth": {"client_token": "s.approle"}}
    mock_client.is_authenticated.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "approle"
    mock_cfg.role_id = ""  # REM-024: empty → uses env OPENBAO_ROLE_ID
    mock_cfg.secret_id = ""  # REM-024: empty → uses env OPENBAO_SECRET_ID
    mock_cfg.secret_id_env = "OPENBAO_SECRET_ID"  # REM-025: named env var for secret_id
    mock_cfg.secret_id_file = ""  # REM-025: no file-based secret_id

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {"OPENBAO_ROLE_ID": "my-role", "OPENBAO_SECRET_ID": "my-secret"}):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is True                           # AC-04: approle_auth_success
    assert result["data"]["authenticated"] is True        # AC-04
    assert result["data"]["auth_method"] == "approle"     # AC-04


# ---------------------------------------------------------------------------
# AC-04: approle_login_failure
# ---------------------------------------------------------------------------

def test_approle_login_failure_returns_error(health_mod):
    """AC-04: approle login exception returns ok=False.

    Satisfies: AC-04 (approle_login_failure)
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_client.auth.approle.login.side_effect = Exception("permission denied")
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "approle"
    mock_cfg.role_id = ""  # REM-024: empty → uses env OPENBAO_ROLE_ID
    mock_cfg.secret_id = ""
    mock_cfg.secret_id_env = "OPENBAO_SECRET_ID"  # REM-025
    mock_cfg.secret_id_file = ""  # REM-025

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {"OPENBAO_ROLE_ID": "bad-role"}):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is False                          # AC-04: approle_login_failure


# ---------------------------------------------------------------------------
# REM-024 regression: config-first credential pickup
# ---------------------------------------------------------------------------

def test_token_auth_uses_plugin_cfg_token(health_mod):
    """REM-024: token auth uses plugin_cfg.token when set, ignoring os.environ.

    Simulates first-boot scenario: config Layer 2 maps Docker env vars into
    plugin_cfg fields, but config.json doesn't exist yet. health.py must read
    credentials from plugin_cfg, not directly from os.environ.
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_client.is_authenticated.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "token"
    mock_cfg.token = "s.cfg-token-from-layer2"

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {}, clear=True):  # no OPENBAO_TOKEN in env
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is True
    assert result["data"]["authenticated"] is True
    assert result["data"]["auth_method"] == "token"
    # Verify the client token was set to the cfg value, not env
    assert mock_client.token == "s.cfg-token-from-layer2"


def test_approle_auth_uses_plugin_cfg_credentials(health_mod):
    """REM-024: approle auth uses plugin_cfg.role_id/secret_id when set.

    Simulates first-boot: Docker env vars flow through load_config() Layer 2
    into plugin_cfg fields. health.py must read role_id/secret_id from
    plugin_cfg, not directly from os.environ.
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_client.auth.approle.login.return_value = {
        "auth": {"client_token": "s.approle-from-cfg"}
    }
    mock_client.is_authenticated.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "approle"
    mock_cfg.role_id = "cfg-role-id"
    mock_cfg.secret_id = "cfg-secret-id"
    mock_cfg.secret_id_env = "OPENBAO_SECRET_ID"  # REM-025
    mock_cfg.secret_id_file = ""  # REM-025

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {}, clear=True):  # no env vars
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is True
    assert result["data"]["authenticated"] is True
    assert result["data"]["auth_method"] == "approle"
    # Verify approle.login was called with cfg values, not env
    mock_client.auth.approle.login.assert_called_once_with(
        role_id="cfg-role-id", secret_id="cfg-secret-id"
    )


def test_env_fallback_when_plugin_cfg_fields_empty(health_mod):
    """REM-024: os.environ fallback works when plugin_cfg fields are empty/falsy.

    When plugin_cfg.token is empty string (falsy), health.py must fall back
    to os.environ.get(). This preserves backward compatibility.
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_client.is_authenticated.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "token"
    mock_cfg.token = ""  # empty — should trigger env fallback

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {"OPENBAO_TOKEN": "s.env-fallback-token"}):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is True
    assert result["data"]["authenticated"] is True
    assert mock_client.token == "s.env-fallback-token"


# ---------------------------------------------------------------------------
# REM-025: secret_id_env / secret_id_file resolution
# ---------------------------------------------------------------------------

def test_approle_uses_custom_secret_id_env(health_mod):
    """REM-025: secret_id resolved from custom env var name (secret_id_env).

    When plugin_cfg.secret_id is empty and secret_id_env='CUSTOM_SECRET_VAR',
    health.py must read secret_id from os.environ['CUSTOM_SECRET_VAR'].
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_client.auth.approle.login.return_value = {"auth": {"client_token": "s.custom-env"}}
    mock_client.is_authenticated.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "approle"
    mock_cfg.role_id = "role-from-cfg"
    mock_cfg.secret_id = ""
    mock_cfg.secret_id_env = "MY_CUSTOM_SECRET"
    mock_cfg.secret_id_file = ""

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {
             "OPENBAO_ROLE_ID": "role-from-cfg",  # REM-026: pin OPENBAO_ROLE_ID so env-first is deterministic
             "MY_CUSTOM_SECRET": "custom-secret-value",
         }):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is True
    assert result["data"]["authenticated"] is True
    mock_client.auth.approle.login.assert_called_once_with(
        role_id="role-from-cfg", secret_id="custom-secret-value"
    )


def test_approle_uses_secret_id_file(health_mod, tmp_path):
    """REM-025: secret_id resolved from file path (secret_id_file).

    When plugin_cfg.secret_id is empty and secret_id_env is not in os.environ,
    health.py must read secret_id from the file at secret_id_file.
    """
    secret_file = tmp_path / "secret_id.txt"
    secret_file.write_text("file-based-secret-id")

    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_client.auth.approle.login.return_value = {"auth": {"client_token": "s.file-secret"}}
    mock_client.is_authenticated.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "approle"
    mock_cfg.role_id = "role-from-cfg"
    mock_cfg.secret_id = ""
    mock_cfg.secret_id_env = "MISSING_ENV_VAR"
    mock_cfg.secret_id_file = str(secret_file)

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {}, clear=True):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is True
    assert result["data"]["authenticated"] is True
    mock_client.auth.approle.login.assert_called_once_with(
        role_id="role-from-cfg", secret_id="file-based-secret-id"
    )


def test_approle_role_id_error_message_diagnostic(health_mod):
    """REM-025: improved error message mentions both config and env sources."""
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_cfg = MagicMock()
    mock_cfg.auth_method = "approle"
    mock_cfg.role_id = ""
    mock_cfg.secret_id = ""
    mock_cfg.secret_id_env = "OPENBAO_SECRET_ID"
    mock_cfg.secret_id_file = ""

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {}, clear=True):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is False
    # REM-025: error message now mentions both config and env sources
    assert "config.json" in result["error"]
    assert "OPENBAO_ROLE_ID" in result["error"]
    assert "Agent Zero container" in result["error"]  # REM-025: message clarifies which container


# ---------------------------------------------------------------------------
# REM-026: env-first credential resolution — env takes precedence over stale config
# ---------------------------------------------------------------------------

def test_approle_env_creds_win_over_stale_config(health_mod):
    """REM-026: OPENBAO_ROLE_ID/OPENBAO_SECRET_ID env vars beat stale config.json values.

    Regression scenario: config.json was written with credentials that have
    since rotated. The container's env vars carry the fresh credentials.
    Before REM-026, health.py was config-first (plugin_cfg.role_id first,
    then env) while openbao_client.py was always env-first. This caused
    'Test Connection' to fail with stale credentials while secrets display
    (via openbao_client.py) worked — a confusing split-brain state.

    openbao_client.py::_resolve_approle_credentials():
        role_id   = os.environ.get('OPENBAO_ROLE_ID') or config.role_id  ← env-first
        secret_id = os.environ.get(secret_id_env_name)                   ← NEVER reads config.secret_id

    After REM-026, health.py mirrors this exactly.

    Satisfies: REM-026 acceptance criteria AC-1 (root cause), AC-2 (fix applied),
               AC-3 (regression test)
    """
    handler = health_mod.TestConnection()
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.sys.read_health_status.return_value = {
        "initialized": True, "sealed": False, "version": "2.0.0"
    }
    mock_client.auth.approle.login.return_value = {"auth": {"client_token": "s.env-wins"}}
    mock_client.is_authenticated.return_value = True

    mock_cfg = MagicMock()
    mock_cfg.auth_method = "approle"
    mock_cfg.role_id = "STALE-role-id-from-config-json"       # stale — must NOT be used
    mock_cfg.secret_id = "STALE-secret-id-from-config-json"   # stale — must NOT be used
    mock_cfg.secret_id_env = "OPENBAO_SECRET_ID"              # default env var name
    mock_cfg.secret_id_file = ""                              # no file fallback

    env_role = "fresh-role-id-from-env"
    env_secret = "fresh-secret-id-from-env"

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {
             "OPENBAO_ROLE_ID": env_role,
             "OPENBAO_SECRET_ID": env_secret,
         }):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://openbao.test:8210"}}, MagicMock()
        ))

    assert result["ok"] is True                            # REM-026: env creds succeed
    assert result["data"]["authenticated"] is True         # REM-026
    assert result["data"]["auth_method"] == "approle"      # REM-026
    # Core assertion: fresh env values used, NOT stale config.json values
    mock_client.auth.approle.login.assert_called_once_with(
        role_id=env_role,
        secret_id=env_secret,
    )
