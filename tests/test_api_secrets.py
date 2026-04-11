"""Tests for api/secrets.py — SecretsManager API handler.

Covers AC-02 (file creation) and AC-05 (14 test cases):
  _get_client no_credentials/token_auth, _get_path no_project/with_project,
  list, get key_found/key_not_found, set, delete key_found/key_not_found,
  bulk_set valid/parse_errors/empty_text, unknown_action.

Satisfies: AC-02, AC-05

Notes on mock strategy:
  secrets.py does `import hvac` inside _get_client() and
  `import hvac.exceptions` inside process() — both function-local.
  patch.object(mod, 'hvac', ...) is ignored because local `import hvac`
  reads sys.modules directly.
  Correct approach: patch.dict(sys.modules, {'hvac': ..., 'hvac.exceptions': ...}).

  For action tests, use patch.object(mod, '_get_client', ...) to bypass
  auth entirely, which also removes the need to patch hvac in those tests.
"""
import asyncio
import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch
import pytest


@pytest.fixture(scope="module")
def secrets_mod():
    """Load api/secrets.py with A0 runtime deps stubbed.

    Satisfies: AC-02 (file created and loadable)
    """
    mock_api = MagicMock()

    class _StubApiHandler:
        pass

    mock_api.ApiHandler = _StubApiHandler
    mock_api.Request = MagicMock
    mock_api.Response = MagicMock
    sys.modules.setdefault("helpers.api", mock_api)
    sys.modules.setdefault("helpers.plugins", MagicMock())
    # hvac stub — _get_client() does `import hvac` + `import hvac.exceptions`
    mock_hvac = MagicMock()
    sys.modules.setdefault("hvac", mock_hvac)
    sys.modules.setdefault("hvac.exceptions", MagicMock())

    path = os.path.join(os.path.dirname(__file__), "..", "api", "secrets.py")
    spec = importlib.util.spec_from_file_location("api_secrets", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# AC-05: _get_client
# ---------------------------------------------------------------------------

def test_get_client_no_credentials_raises(secrets_mod):
    """AC-05: _get_client with no credentials raises RuntimeError.

    REM-021: credentials come from config, not os.environ.
    Empty cfg.token + cfg.role_id → RuntimeError.
    Satisfies: AC-05 (_get_client no_credentials)
    """
    mock_hvac = MagicMock()
    mock_hvac.Client.return_value.is_authenticated.return_value = False
    mock_cfg = MagicMock()
    mock_cfg.url = "http://localhost:8200"
    mock_cfg.tls_verify = True
    mock_cfg.tls_ca_cert = ""
    mock_cfg.timeout = 10
    mock_cfg.token = ""       # REM-021: config-based, not os.environ
    mock_cfg.role_id = ""     # REM-021
    mock_cfg.secret_id = ""   # REM-021

    with patch.object(secrets_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}):
        with pytest.raises(RuntimeError):          # AC-05: no_credentials
            secrets_mod._get_client()


def test_get_client_token_auth_succeeds(secrets_mod):
    """AC-05: _get_client with cfg.token returns (client, cfg).

    REM-021: token comes from config, not os.environ.
    Satisfies: AC-05 (_get_client token_auth_succeeds)
    """
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.is_authenticated.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.url = "http://localhost:8200"
    mock_cfg.tls_verify = True
    mock_cfg.tls_ca_cert = ""
    mock_cfg.timeout = 10
    mock_cfg.token = "s.test-token"  # REM-021: config-based credential

    with patch.object(secrets_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}):
        client, cfg = secrets_mod._get_client()  # AC-05: token_auth_succeeds

    assert client is mock_client  # AC-05
    assert cfg is mock_cfg        # AC-05


def test_get_client_approle_auth_succeeds(secrets_mod):
    """REM-021: _get_client with cfg.role_id/secret_id uses approle login.

    Satisfies: AC-02, AC-03 (credentials from config, same path as openbao_client)
    """
    mock_hvac = MagicMock()
    mock_client = mock_hvac.Client.return_value
    mock_client.is_authenticated.return_value = True
    mock_client.auth.approle.login.return_value = {
        "auth": {"client_token": "s.approle-token"}
    }
    mock_cfg = MagicMock()
    mock_cfg.url = "http://localhost:8200"
    mock_cfg.tls_verify = True
    mock_cfg.tls_ca_cert = ""
    mock_cfg.timeout = 10
    mock_cfg.token = ""                # no token → fallback to approle
    mock_cfg.role_id = "role-abc"      # REM-021: config-based
    mock_cfg.secret_id = "secret-xyz"  # REM-021: config-based

    with patch.object(secrets_mod, "load_config", return_value=mock_cfg), \
         patch.dict(sys.modules, {"hvac": mock_hvac}):
        client, cfg = secrets_mod._get_client()

    mock_client.auth.approle.login.assert_called_once_with(
        role_id="role-abc", secret_id="secret-xyz"
    )
    assert client.token == "s.approle-token"
    assert client is mock_client
    assert cfg is mock_cfg


def test_get_client_no_os_environ_access(secrets_mod):
    """REM-021 (AC-01): _get_client never reads OPENBAO_TOKEN from os.environ."""
    import inspect
    source = inspect.getsource(secrets_mod._get_client)
    # AC-01: no direct os.environ.get for credential env vars
    assert 'os.environ.get("OPENBAO_TOKEN")' not in source
    assert 'os.environ.get("OPENBAO_ROLE_ID")' not in source
    assert 'os.environ.get("OPENBAO_SECRET_ID")' not in source
    assert "os.environ.get('OPENBAO_TOKEN')" not in source
    assert "os.environ.get('OPENBAO_ROLE_ID')" not in source
    assert "os.environ.get('OPENBAO_SECRET_ID')" not in source


# ---------------------------------------------------------------------------
# AC-05: _get_path
# ---------------------------------------------------------------------------

def test_get_path_without_project(secrets_mod):
    """AC-05: _get_path with no project returns base secrets_path.

    Satisfies: AC-05 (_get_path no_project)
    """
    mock_cfg = MagicMock()
    mock_cfg.secrets_path = "deimos"
    result = secrets_mod._get_path(mock_cfg)   # AC-05: get_path_no_project
    assert result == "deimos"                   # AC-05


def test_get_path_with_project(secrets_mod):
    """AC-05: _get_path with project_name appends to base path.

    Satisfies: AC-05 (_get_path with_project)
    """
    mock_cfg = MagicMock()
    mock_cfg.secrets_path = "deimos"
    result = secrets_mod._get_path(mock_cfg, "my-app")  # AC-05: get_path_with_project
    assert result == "deimos/my-app"                     # AC-05


# ---------------------------------------------------------------------------
# Helpers shared by action tests
# ---------------------------------------------------------------------------

def _make_action_mocks():
    """Return (mock_client, mock_cfg) suitable for action-level tests."""
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"API_KEY": "sk-12345", "DB_PASS": "hunter2"}}
    }
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"
    return mock_client, mock_cfg


# ---------------------------------------------------------------------------
# AC-05: list action
# ---------------------------------------------------------------------------

def test_list_action_returns_keys(secrets_mod):
    """AC-05: list action returns ok=True with sorted key list.

    Satisfies: AC-05 (list_action)
    """
    handler = secrets_mod.SecretsManager()
    mock_client, mock_cfg = _make_action_mocks()

    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "list"}, MagicMock()
        ))

    assert result["ok"] is True                          # AC-05: list_action
    keys = [s["key"] for s in result["secrets"]]
    assert "API_KEY" in keys                             # AC-05
    assert "DB_PASS" in keys                             # AC-05


# ---------------------------------------------------------------------------
# AC-05: get action — key_found / key_not_found
# ---------------------------------------------------------------------------

def test_get_action_key_found(secrets_mod):
    """AC-05: get action with existing key returns ok=True and value.

    Satisfies: AC-05 (get_action key_found)
    """
    handler = secrets_mod.SecretsManager()
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"API_KEY": "sk-12345"}}
    }
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"

    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "get", "key": "API_KEY"}, MagicMock()
        ))

    assert result["ok"] is True              # AC-05: get_key_found
    assert result["key"] == "API_KEY"        # AC-05
    assert result["value"] == "sk-12345"     # AC-05


def test_get_action_key_not_found(secrets_mod):
    """AC-05: get action with missing key returns ok=False.

    Satisfies: AC-05 (get_action key_not_found)
    """
    handler = secrets_mod.SecretsManager()
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {}}
    }
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"

    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "get", "key": "MISSING"}, MagicMock()
        ))

    assert result["ok"] is False                  # AC-05: get_key_not_found
    assert "Key not found" in result["error"]     # AC-05


# ---------------------------------------------------------------------------
# AC-05: set action
# ---------------------------------------------------------------------------

def test_set_action_saves_pairs(secrets_mod):
    """AC-05: set action writes key-value pairs and returns ok=True.

    Satisfies: AC-05 (set_action)
    """
    handler = secrets_mod.SecretsManager()
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {}}
    }
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"

    pairs = [{"key": "NEW_KEY", "value": "new-value"}]
    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "set", "pairs": pairs}, MagicMock()
        ))

    assert result["ok"] is True                      # AC-05: set_action
    mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once()  # AC-05


# ---------------------------------------------------------------------------
# AC-05: delete action — key_found / key_not_found
# ---------------------------------------------------------------------------

def test_delete_action_key_found(secrets_mod):
    """AC-05: delete action removes existing key and returns ok=True.

    Satisfies: AC-05 (delete_action key_found)
    """
    handler = secrets_mod.SecretsManager()
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"OLD_KEY": "old-val"}}
    }
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"

    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "delete", "key": "OLD_KEY"}, MagicMock()
        ))

    assert result["ok"] is True                      # AC-05: delete_key_found
    assert "Deleted" in result["message"]            # AC-05


def test_delete_action_key_not_found(secrets_mod):
    """AC-05: delete action with missing key returns ok=False.

    Satisfies: AC-05 (delete_action key_not_found)
    """
    handler = secrets_mod.SecretsManager()
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {}}
    }
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"

    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "delete", "key": "GHOST"}, MagicMock()
        ))

    assert result["ok"] is False                      # AC-05: delete_key_not_found
    assert "Key not found" in result["error"]         # AC-05


# ---------------------------------------------------------------------------
# AC-05: bulk_set — valid / parse_errors / empty_text
# ---------------------------------------------------------------------------

def test_bulk_set_valid_text(secrets_mod):
    """AC-05: bulk_set valid KEY=VALUE text writes all pairs.

    Satisfies: AC-05 (bulk_set valid_text)
    """
    handler = secrets_mod.SecretsManager()
    mock_client = MagicMock()
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {}}
    }
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"

    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "bulk_set", "text": "ALPHA=one\nBETA=two\n"},
            MagicMock()
        ))

    assert result["ok"] is True                                   # AC-05: bulk_set_valid
    mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once()  # AC-05


def test_bulk_set_parse_error(secrets_mod):
    """AC-05: bulk_set malformed line returns parse error.

    Satisfies: AC-05 (bulk_set parse_errors)
    """
    handler = secrets_mod.SecretsManager()
    mock_client = MagicMock()
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"

    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "bulk_set", "text": "VALID=value\nNO_EQUALS_HERE\n"},
            MagicMock()
        ))

    assert result["ok"] is False                    # AC-05: bulk_set_parse_errors
    assert "Parse errors" in result["error"]        # AC-05


def test_bulk_set_empty_text(secrets_mod):
    """AC-05: bulk_set with empty text returns error.

    Satisfies: AC-05 (bulk_set empty_text)
    """
    handler = secrets_mod.SecretsManager()
    mock_client = MagicMock()
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"

    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "bulk_set", "text": "   "}, MagicMock()
        ))

    assert result["ok"] is False                    # AC-05: bulk_set_empty_text


# ---------------------------------------------------------------------------
# AC-05: unknown_action
# ---------------------------------------------------------------------------

def test_unknown_action_returns_error(secrets_mod):
    """AC-05: unrecognised action returns ok=False.

    Satisfies: AC-05 (unknown_action)
    """
    handler = secrets_mod.SecretsManager()
    mock_client = MagicMock()
    mock_cfg = MagicMock()
    mock_cfg.mount_point = "secret"
    mock_cfg.secrets_path = "deimos"

    with patch.object(secrets_mod, "_ensure_hvac", return_value=True), \
         patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process(
            {"action": "explode"}, MagicMock()
        ))

    assert result["ok"] is False                    # AC-05: unknown_action
    assert "Unknown action" in result["error"]      # AC-05


# ---------------------------------------------------------------------------
# E-06 AC-13: list_keys action tests
# ---------------------------------------------------------------------------

def test_list_keys_returns_bare_sorted_names(secrets_mod):
    """AC-02: list_keys returns sorted bare key name strings, no values."""
    mock_client, mock_cfg = _make_action_mocks()
    mock_client.secrets.kv.v2.list_secrets.return_value = {
        "data": {"keys": ["ZEBRA", "ALPHA", "MIDDLE"]}
    }
    handler = secrets_mod.SecretsManager()
    with patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(handler.process({"action": "list_keys"}, MagicMock()))
    assert result["ok"] is True                                    # AC-02
    assert result["keys"] == ["ALPHA", "MIDDLE", "ZEBRA"]          # AC-02: sorted
    assert "values" not in result                                   # AC-02: no values
    mock_client.secrets.kv.v2.list_secrets.assert_called_once()   # AC-01: list_secrets used


def test_list_keys_empty_vault_returns_empty_list(secrets_mod):
    """AC-11: empty vault (InvalidPath) returns ok=True with empty keys list."""
    mock_client, mock_cfg = _make_action_mocks()
    import hvac.exceptions as hvac_exc
    mock_client.secrets.kv.v2.list_secrets.side_effect = hvac_exc.InvalidPath()
    handler = secrets_mod.SecretsManager()
    with patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)), \
         patch.dict(sys.modules, {"hvac.exceptions": hvac_exc}):
        result = asyncio.run(handler.process({"action": "list_keys"}, MagicMock()))
    assert result["ok"] is True   # AC-11
    assert result["keys"] == []   # AC-11


def test_list_keys_vault_unavailable_returns_error(secrets_mod):
    """AC-09: vault unavailable (_get_client raises) returns ok=False, no crash."""
    handler = secrets_mod.SecretsManager()
    with patch.object(secrets_mod, "_get_client",
                      side_effect=ConnectionError("Connection refused")):
        result = asyncio.run(handler.process({"action": "list_keys"}, MagicMock()))
    assert result["ok"] is False                          # AC-09
    assert "Connection refused" in result["error"]        # AC-09


def test_list_keys_forbidden_returns_permission_error(secrets_mod):
    """AC-10: Forbidden → permission denied error."""
    mock_client, mock_cfg = _make_action_mocks()
    import hvac.exceptions as hvac_exc
    mock_client.secrets.kv.v2.list_secrets.side_effect = hvac_exc.Forbidden()
    handler = secrets_mod.SecretsManager()
    with patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)), \
         patch.dict(sys.modules, {"hvac.exceptions": hvac_exc}):
        result = asyncio.run(handler.process({"action": "list_keys"}, MagicMock()))
    assert result["ok"] is False                           # AC-10
    assert "Permission denied" in result["error"]         # AC-10


def test_list_keys_with_project_name_scopes_path(secrets_mod):
    """AC-03: project_name scopes list_keys to project sub-path."""
    mock_client, mock_cfg = _make_action_mocks()
    mock_client.secrets.kv.v2.list_secrets.return_value = {
        "data": {"keys": ["PROJ_SECRET"]}
    }
    handler = secrets_mod.SecretsManager()
    with patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)):
        result = asyncio.run(
            handler.process({"action": "list_keys", "project_name": "my-app"}, MagicMock())
        )
    assert result["ok"] is True
    assert result["keys"] == ["PROJ_SECRET"]              # AC-03
    call_kwargs = mock_client.secrets.kv.v2.list_secrets.call_args[1]
    assert "my-app" in call_kwargs.get("path", "")        # AC-03: project-scoped path


# ---------------------------------------------------------------------------
# E-06 AC-13: compliance action tests
# ---------------------------------------------------------------------------

def test_compliance_detects_missing_keys(secrets_mod):
    """AC-05, AC-08: registry keys absent from vault → missing, compliant=False."""
    mock_client, mock_cfg = _make_action_mocks()
    mock_client.secrets.kv.v2.list_secrets.return_value = {
        "data": {"keys": ["SYNCED_KEY"]}
    }
    mock_entry_synced = MagicMock(key="SYNCED_KEY", status="migrated")
    mock_entry_missing = MagicMock(key="MISSING_KEY", status="discovered")
    mock_reg_mgr = MagicMock()
    mock_reg_mgr.get_entries.return_value = [mock_entry_synced, mock_entry_missing]
    mock_reg_mod = MagicMock()
    mock_reg_mod.RegistryManager.return_value = mock_reg_mgr
    handler = secrets_mod.SecretsManager()
    with patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)), \
         patch.object(secrets_mod, "_get_registry_module", return_value=mock_reg_mod):
        result = asyncio.run(handler.process({"action": "compliance"}, MagicMock()))
    assert result["ok"] is True
    assert result["compliant"] is False                     # AC-08
    assert result["missing"] == ["MISSING_KEY"]             # AC-05
    assert result["synced"] == ["SYNCED_KEY"]               # AC-06


def test_compliance_fully_synced_returns_compliant(secrets_mod):
    """AC-08: all registry keys in vault → compliant=True, missing=[]."""
    mock_client, mock_cfg = _make_action_mocks()
    mock_client.secrets.kv.v2.list_secrets.return_value = {
        "data": {"keys": ["KEY_A", "KEY_B"]}
    }
    mock_reg_mgr = MagicMock()
    mock_reg_mgr.get_entries.return_value = [
        MagicMock(key="KEY_A", status="migrated"),
        MagicMock(key="KEY_B", status="migrated"),
    ]
    mock_reg_mod = MagicMock()
    mock_reg_mod.RegistryManager.return_value = mock_reg_mgr
    handler = secrets_mod.SecretsManager()
    with patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)), \
         patch.object(secrets_mod, "_get_registry_module", return_value=mock_reg_mod):
        result = asyncio.run(handler.process({"action": "compliance"}, MagicMock()))
    assert result["compliant"] is True                          # AC-08
    assert result["missing"] == []                             # AC-05
    assert sorted(result["synced"]) == ["KEY_A", "KEY_B"]      # AC-06


def test_compliance_ignored_entries_excluded(secrets_mod):
    """AC-05: ignored registry entries not counted as missing."""
    mock_client, mock_cfg = _make_action_mocks()
    mock_client.secrets.kv.v2.list_secrets.return_value = {"data": {"keys": []}}
    mock_reg_mgr = MagicMock()
    mock_reg_mgr.get_entries.return_value = [MagicMock(key="OLD_TOKEN", status="ignored")]
    mock_reg_mod = MagicMock()
    mock_reg_mod.RegistryManager.return_value = mock_reg_mgr
    handler = secrets_mod.SecretsManager()
    with patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)), \
         patch.object(secrets_mod, "_get_registry_module", return_value=mock_reg_mod):
        result = asyncio.run(handler.process({"action": "compliance"}, MagicMock()))
    assert result["compliant"] is True    # AC-05: ignored entry not a violation
    assert result["missing"] == []


def test_compliance_detects_orphans(secrets_mod):
    """AC-07: vault keys with no registry entry reported as orphans."""
    mock_client, mock_cfg = _make_action_mocks()
    mock_client.secrets.kv.v2.list_secrets.return_value = {
        "data": {"keys": ["ORPHAN_KEY"]}
    }
    mock_reg_mgr = MagicMock()
    mock_reg_mgr.get_entries.return_value = []   # empty registry
    mock_reg_mod = MagicMock()
    mock_reg_mod.RegistryManager.return_value = mock_reg_mgr
    handler = secrets_mod.SecretsManager()
    with patch.object(secrets_mod, "_get_client", return_value=(mock_client, mock_cfg)), \
         patch.object(secrets_mod, "_get_registry_module", return_value=mock_reg_mod):
        result = asyncio.run(handler.process({"action": "compliance"}, MagicMock()))
    assert result["orphans"] == ["ORPHAN_KEY"]  # AC-07
    assert result["compliant"] is True           # no registry keys to violate
