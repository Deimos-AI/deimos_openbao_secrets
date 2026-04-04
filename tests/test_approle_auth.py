# Copyright 2024 Deimos
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for REM-031 — AppRole credential resolution and authentication.

Verifies:
- _resolve_approle_credentials(): env > config hierarchy for role_id and secret_id
- _auth_approle(): POSTs to approle login with correct credentials
- RuntimeError with clear messages when credentials missing
- Token auth path unchanged
"""
from __future__ import annotations

import os
import sys
import tempfile
import pytest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers.config import OpenBaoConfig
from helpers.openbao_client import OpenBaoClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def approle_config():
    """Minimal AppRole config with credentials in config fields."""
    return OpenBaoConfig(
        enabled=True,
        url="http://127.0.0.1:8200",
        auth_method="approle",
        role_id="config-role-id",
        secret_id="config-secret-id",
        secret_id_env="OPENBAO_SECRET_ID",
        secret_id_file="",
        mount_point="secret",
        secrets_path="agentzero",
        timeout=5.0,
        cache_ttl=10,
        retry_attempts=2,
        circuit_breaker_threshold=3,
        circuit_breaker_recovery=5,
    )


@pytest.fixture
def token_config():
    """Minimal token auth config."""
    return OpenBaoConfig(
        enabled=True,
        url="http://127.0.0.1:8200",
        auth_method="token",
        token="hvs.test-token",
        mount_point="secret",
        secrets_path="agentzero",
        timeout=5.0,
        cache_ttl=10,
        retry_attempts=2,
        circuit_breaker_threshold=3,
        circuit_breaker_recovery=5,
    )


@pytest.fixture
def mock_hvac_approle():
    """Mock hvac.Client that succeeds AppRole login."""
    client = MagicMock()
    client.is_authenticated.return_value = True
    client.auth.token.lookup_self.return_value = {"data": {"ttl": 3600}}
    client.auth.approle.login.return_value = {
        "auth": {"client_token": "hvs.approle-token"}
    }
    return client


# ---------------------------------------------------------------------------
# Tests — _resolve_approle_credentials()
# ---------------------------------------------------------------------------

class TestResolveAppRoleCredentials:
    """Unit tests for _resolve_approle_credentials() — no network required."""

    def _make_client_no_connect(self, config):
        """Create OpenBaoClient with connect() stubbed out."""
        with patch("helpers.openbao_client.hvac.Client"):
            with patch.object(OpenBaoClient, "_connect"):
                client = OpenBaoClient(config)
        return client

    def test_role_id_from_env_takes_priority(self, approle_config, monkeypatch):
        """AC-03: env var OPENBAO_ROLE_ID overrides config.role_id."""
        monkeypatch.setenv("OPENBAO_ROLE_ID", "env-role-id")
        monkeypatch.setenv("OPENBAO_SECRET_ID", "env-secret-id")
        client = self._make_client_no_connect(approle_config)
        role_id, secret_id = client._resolve_approle_credentials()
        assert role_id == "env-role-id"  # env wins

    def test_role_id_from_config_when_env_absent(self, approle_config, monkeypatch):
        """AC-03: config.role_id used when OPENBAO_ROLE_ID env var absent."""
        monkeypatch.delenv("OPENBAO_ROLE_ID", raising=False)
        monkeypatch.setenv("OPENBAO_SECRET_ID", "env-secret-id")
        client = self._make_client_no_connect(approle_config)
        role_id, _ = client._resolve_approle_credentials()
        assert role_id == "config-role-id"  # config fallback

    def test_secret_id_from_env_var(self, approle_config, monkeypatch):
        """AC-04: secret_id resolved from env var named in config.secret_id_env."""
        monkeypatch.delenv("OPENBAO_ROLE_ID", raising=False)
        monkeypatch.setenv("OPENBAO_SECRET_ID", "env-secret-id")
        client = self._make_client_no_connect(approle_config)
        _, secret_id = client._resolve_approle_credentials()
        assert secret_id == "env-secret-id"

    def test_secret_id_from_file_when_env_absent(self, approle_config, monkeypatch):
        """AC-04: secret_id resolved from secret_id_file when env var absent."""
        monkeypatch.delenv("OPENBAO_SECRET_ID", raising=False)
        monkeypatch.delenv("OPENBAO_ROLE_ID", raising=False)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("file-secret-id\n")
            f.flush()
            approle_config.secret_id_file = f.name
        client = self._make_client_no_connect(approle_config)
        _, secret_id = client._resolve_approle_credentials()
        assert secret_id == "file-secret-id"

    def test_runtime_error_when_role_id_missing(self, approle_config, monkeypatch):
        """AC-05: RuntimeError with clear message when role_id absent from env + config."""
        monkeypatch.delenv("OPENBAO_ROLE_ID", raising=False)
        monkeypatch.setenv("OPENBAO_SECRET_ID", "env-secret-id")
        approle_config.role_id = ""  # clear config value too
        client = self._make_client_no_connect(approle_config)
        with pytest.raises(RuntimeError, match="role_id"):
            client._resolve_approle_credentials()

    def test_runtime_error_when_secret_id_missing(self, approle_config, monkeypatch):
        """AC-06: RuntimeError with clear message when secret_id absent from env + file."""
        monkeypatch.delenv("OPENBAO_ROLE_ID", raising=False)
        monkeypatch.delenv("OPENBAO_SECRET_ID", raising=False)
        approle_config.secret_id_file = ""  # no file either
        client = self._make_client_no_connect(approle_config)
        with pytest.raises(RuntimeError, match="secret_id"):
            client._resolve_approle_credentials()

    def test_runtime_error_on_unreadable_secret_id_file(self, approle_config, monkeypatch):
        """RuntimeError when secret_id_file path does not exist."""
        monkeypatch.delenv("OPENBAO_SECRET_ID", raising=False)
        monkeypatch.delenv("OPENBAO_ROLE_ID", raising=False)
        approle_config.secret_id_file = "/nonexistent/path/secret_id.txt"
        client = self._make_client_no_connect(approle_config)
        with pytest.raises(RuntimeError, match="secret_id_file"):
            client._resolve_approle_credentials()


# ---------------------------------------------------------------------------
# Tests — _auth_approle() POST behaviour
# ---------------------------------------------------------------------------

class TestAuthAppRole:
    """Tests for _auth_approle() — verifies correct POST payload."""

    def test_approle_login_posts_correct_payload(self, approle_config, mock_hvac_approle, monkeypatch):
        """AC-07: _auth_approle() POSTs to approle login with resolved role_id + secret_id."""
        monkeypatch.delenv("OPENBAO_ROLE_ID", raising=False)
        monkeypatch.setenv("OPENBAO_SECRET_ID", "env-secret-id")

        with patch("helpers.openbao_client.hvac.Client", return_value=mock_hvac_approle):
            client = OpenBaoClient(approle_config)

        mock_hvac_approle.auth.approle.login.assert_called_once_with(
            role_id="config-role-id",
            secret_id="env-secret-id",
        )
        # AC-08: token stored on hvac client (memory only — no disk write)
        assert mock_hvac_approle.token == "hvs.approle-token"

    def test_token_auth_path_unchanged(self, token_config, monkeypatch):
        """AC-10: token auth still works when vault_token is present."""
        mock_client = MagicMock()
        mock_client.is_authenticated.return_value = True
        mock_client.auth.token.lookup_self.return_value = {"data": {"ttl": 0}}

        with patch("helpers.openbao_client.hvac.Client", return_value=mock_client):
            client = OpenBaoClient(token_config)

        # Token set directly — no approle login called
        assert mock_client.token == "hvs.test-token"
        mock_client.auth.approle.login.assert_not_called()
