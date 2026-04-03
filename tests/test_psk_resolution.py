# Copyright 2026 deimosAI
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
"""Unit tests for PSK (Project-Scoped Keys) two-tier vault path resolution hierarchy.

Resolution rules under test:
    R1: No active project -> only global path consulted
    R2: Active project, key in project vault -> project value returned (override wins)
    R3: Active project, key absent in project vault -> global value returned (fallback)
    R4: Active project, project vault document does not exist -> global value returned
    R5: Project slug derived from final path component of agent.context.project

All tests use mocks -- no live OpenBao instance required.

Ref: PSK-006
"""
from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from helpers.config import OpenBaoConfig, resolve_project_path
from helpers.openbao_secrets_manager import OpenBaoSecretsManager


# ---------------------------------------------------------------------------
# Internal helper: construct manager without a live OpenBao connection
# ---------------------------------------------------------------------------


def _make_manager(
    config: OpenBaoConfig,
    bao_client: object,
) -> OpenBaoSecretsManager:
    """Return an OpenBaoSecretsManager bypassing __init__ to avoid real connection.

    Sets only the attributes accessed by get_secret() and load_project_secrets().
    """
    mgr = object.__new__(OpenBaoSecretsManager)
    # Parent (_MockSecretsManager) attributes required by the base class
    mgr._lock = threading.RLock()
    mgr._files = ("usr/secrets.env",)
    mgr._raw_snapshots = {}
    mgr._secrets_cache = None
    mgr._last_raw_text = None
    # OpenBaoSecretsManager-specific attributes
    mgr._config = config
    mgr._bao_client = bao_client
    mgr._bao_lock = threading.RLock()
    mgr._fallback_active = False
    return mgr


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> OpenBaoConfig:
    """Default OpenBaoConfig with stable test values."""
    return OpenBaoConfig(
        enabled=True,
        url="http://localhost:8200",
        auth_method="token",
        token="test-token",
        mount_point="secret",
        secrets_path="agentzero",
        vault_project_template="agentzero-{project_slug}",
    )


@pytest.fixture
def mock_client() -> MagicMock:
    """Fully mocked OpenBaoClient with safe default return values."""
    client = MagicMock()
    client.is_connected.return_value = True
    client.read_secret.return_value = None
    client.get_secret.return_value = None
    client.read_all_from_path.return_value = {}
    return client


@pytest.fixture
def manager(config: OpenBaoConfig, mock_client: MagicMock) -> OpenBaoSecretsManager:
    """OpenBaoSecretsManager wired to mock_client; no real connection attempted."""
    return _make_manager(config, bao_client=mock_client)


# ---------------------------------------------------------------------------
# R5 -- Project slug derivation and path resolution
# ---------------------------------------------------------------------------


class TestResolveProjectPath:
    """Covers R5: slug = Path(project).name; resolve_project_path formats template."""

    def test_default_template_produces_expected_path(
        self, config: OpenBaoConfig
    ) -> None:
        """R5: default template 'agentzero-{project_slug}' formats slug correctly."""
        result = resolve_project_path(config, "deimos-openbao-project")
        assert result == "agentzero-deimos-openbao-project"

    def test_custom_template_overrides_default(
        self, config: OpenBaoConfig
    ) -> None:
        """R5: custom vault_project_template is applied verbatim."""
        config.vault_project_template = "myorg-{project_slug}"
        result = resolve_project_path(config, "alpha")
        assert result == "myorg-alpha"

    def test_slug_is_final_path_component_of_project(self) -> None:
        """R5: slug derived via Path(agent.context.project).name -- final component only."""
        full_project_path = "/a0/usr/projects/deimos-openbao-project"
        slug = Path(full_project_path).name
        assert slug == "deimos-openbao-project"


# ---------------------------------------------------------------------------
# R1 -- No active project -> global only
# ---------------------------------------------------------------------------


class TestR1NoActiveProject:
    """R1: project_slug absent or empty -> global path only; project path never queried."""

    def test_no_active_project_uses_global_only(
        self, manager: OpenBaoSecretsManager, mock_client: MagicMock
    ) -> None:
        """R1: project_slug=None -> read_secret(key) called; get_secret() not called."""
        mock_client.read_secret.return_value = "global-api-key"

        result = manager.get_secret("API_KEY", project_slug=None)

        assert result == "global-api-key"
        mock_client.read_secret.assert_called_once_with("API_KEY")
        mock_client.get_secret.assert_not_called()

    def test_empty_project_slug_behaves_as_no_project(
        self, manager: OpenBaoSecretsManager, mock_client: MagicMock
    ) -> None:
        """R1: project_slug='' treated as no active project -> global only."""
        mock_client.read_secret.return_value = "global-value"

        result = manager.get_secret("MY_KEY", project_slug="")

        assert result == "global-value"
        mock_client.read_secret.assert_called_once_with("MY_KEY")
        mock_client.get_secret.assert_not_called()


# ---------------------------------------------------------------------------
# R2 -- Project override wins
# ---------------------------------------------------------------------------


class TestR2ProjectOverrideWins:
    """R2: key present in project vault -> project value returned; global not queried."""

    def test_project_value_returned_when_key_found_in_project_vault(
        self, manager: OpenBaoSecretsManager, mock_client: MagicMock
    ) -> None:
        """R2: project vault has the key -> project value wins; read_secret not called."""
        mock_client.get_secret.return_value = "project-specific-api-key"
        mock_client.read_secret.return_value = "global-api-key"

        result = manager.get_secret("LANGFUSE_PUBLIC_KEY", project_slug="my-project")

        assert result == "project-specific-api-key"
        # Project path must be queried with the resolved vault path
        mock_client.get_secret.assert_called_once_with(
            "LANGFUSE_PUBLIC_KEY", path_override="agentzero-my-project"
        )
        # Global read_secret must NOT be called when project value was found
        mock_client.read_secret.assert_not_called()


# ---------------------------------------------------------------------------
# R3 -- Key absent from project vault -> global fallback
# ---------------------------------------------------------------------------


class TestR3GlobalFallback:
    """R3: key absent from project vault (vault document exists) -> global value returned."""

    def test_global_fallback_when_key_absent_from_project_vault(
        self, manager: OpenBaoSecretsManager, mock_client: MagicMock
    ) -> None:
        """R3: project vault exists but key missing -> get_secret None -> global used."""
        mock_client.get_secret.return_value = None   # key not in project vault
        mock_client.read_secret.return_value = "shared-global-value"

        result = manager.get_secret("SHARED_KEY", project_slug="active-project")

        assert result == "shared-global-value"
        # Project path was queried first
        mock_client.get_secret.assert_called_once_with(
            "SHARED_KEY", path_override="agentzero-active-project"
        )
        # Global fallback then consulted
        mock_client.read_secret.assert_called_once_with("SHARED_KEY")


# ---------------------------------------------------------------------------
# R4 -- Project vault document does not exist -> global fallback
# ---------------------------------------------------------------------------


class TestR4MissingProjectVault:
    """R4: project vault path not provisioned -> client returns None -> global fallback."""

    def test_missing_project_vault_falls_back_to_global(
        self, manager: OpenBaoSecretsManager, mock_client: MagicMock
    ) -> None:
        """R4: InvalidPath caught in OpenBaoClient.get_secret -> None -> global fallback.

        OpenBaoClient.get_secret() catches hvac.exceptions.InvalidPath and returns
        None when the project vault path does not exist.  The manager layer sees
        None and transparently falls back to the global path without raising.
        """
        # Client-level get_secret catches InvalidPath and surfaces it as None
        mock_client.get_secret.return_value = None
        mock_client.read_secret.return_value = "global-fallback-for-missing-project"

        result = manager.get_secret("ENV_KEY", project_slug="unprovisioned")

        assert result == "global-fallback-for-missing-project"
        mock_client.get_secret.assert_called_once_with(
            "ENV_KEY", path_override="agentzero-unprovisioned"
        )
        mock_client.read_secret.assert_called_once_with("ENV_KEY")

    def test_load_project_secrets_returns_empty_dict_on_missing_vault(
        self, manager: OpenBaoSecretsManager, mock_client: MagicMock
    ) -> None:
        """R4: read_all_from_path returns {} when project vault path is absent."""
        mock_client.read_all_from_path.return_value = {}

        result = manager.load_project_secrets("unprovisioned-project")

        assert result == {}
        mock_client.read_all_from_path.assert_called_once_with(
            "agentzero-unprovisioned-project"
        )


# ---------------------------------------------------------------------------
# Client unavailable guard
# ---------------------------------------------------------------------------


class TestClientUnavailable:
    """Guard: _bao_client=None -> safe return values; no exception raised."""

    def test_get_secret_returns_none_when_bao_client_is_none(
        self, config: OpenBaoConfig
    ) -> None:
        """Client unavailable: get_secret() returns None without raising."""
        mgr = _make_manager(config, bao_client=None)
        result = mgr.get_secret("ANY_KEY", project_slug="some-project")
        assert result is None

    def test_load_project_secrets_returns_empty_when_bao_client_is_none(
        self, config: OpenBaoConfig
    ) -> None:
        """Client unavailable: load_project_secrets() returns {} without raising."""
        mgr = _make_manager(config, bao_client=None)
        result = mgr.load_project_secrets("some-project")
        assert result == {}
