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
            {"config": {"url": "http://localhost:8200"}}, MagicMock()
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

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {}, clear=True):   # ensure OPENBAO_TOKEN absent
        result = asyncio.run(handler.process(
            {"config": {"url": "http://localhost:8200"}}, MagicMock()
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

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {"OPENBAO_TOKEN": "s.valid-token"}):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://localhost:8200"}}, MagicMock()
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

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {"OPENBAO_ROLE_ID": "my-role", "OPENBAO_SECRET_ID": "my-secret"}):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://localhost:8200"}}, MagicMock()
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

    with patch.object(health_mod, "_ensure_hvac", return_value=True), \
         patch.object(health_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}), \
         patch.dict(os.environ, {"OPENBAO_ROLE_ID": "bad-role"}):
        result = asyncio.run(handler.process(
            {"config": {"url": "http://localhost:8200"}}, MagicMock()
        ))

    assert result["ok"] is False                          # AC-04: approle_login_failure
    assert "AppRole login failed" in result["error"]      # AC-04
