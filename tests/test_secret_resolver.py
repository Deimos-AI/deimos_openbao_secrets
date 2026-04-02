# Copyright 2024 Deimos AI
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
"""Tests for Surface C \u00a7\u00a7secret() resolver extension.

Covers OpenBaoSecretsResolver (no-op execute) and the get_secrets_manager()
@extensible hook introduced in Step 10a of IMPLEMENTATION_PLAN.md.

The module under test lives in extensions/python/agent_init/ and has no
__init__.py chain, so it is loaded via importlib.util.spec_from_file_location.
The conftest.py bootstrap wires openbao_config / openbao_client / helpers.secrets;
this file owns all patching of sys.modules['openbao_secrets_factory_common'].

Ref: IMPLEMENTATION_PLAN.md Step 10a
"""
from __future__ import annotations

import asyncio
import importlib.util
import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Load module under test via importlib (extensions/ has no __init__.py chain)
# ---------------------------------------------------------------------------
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGIN_ROOT = os.path.dirname(_TESTS_DIR)
_RESOLVER_PATH = os.path.join(
    _PLUGIN_ROOT,
    "extensions",
    "python",
    "agent_init",
    "_05_openbao_secrets_resolver.py",
)

_spec = importlib.util.spec_from_file_location(
    "_05_openbao_secrets_resolver", _RESOLVER_PATH
)
_resolver_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_resolver_mod)  # type: ignore[union-attr]

OpenBaoSecretsResolver = _resolver_mod.OpenBaoSecretsResolver
get_secrets_manager = _resolver_mod.get_secrets_manager

# Capture the module-level logger name for precise caplog targeting
_LOGGER_NAME: str = _resolver_mod.logger.name


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def factory_mock():
    """Provide a mock openbao_secrets_factory_common module with a healthy manager."""
    manager = MagicMock()
    manager.is_available.return_value = True
    factory = MagicMock()
    factory.get_openbao_manager.return_value = manager
    return factory, manager


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_returns_manager_when_openbao_available(factory_mock):
    """get_secrets_manager() returns the OpenBao manager when factory is present and is_available() is True."""
    factory, manager = factory_mock
    with patch.dict(sys.modules, {"openbao_secrets_factory_common": factory}):
        result = get_secrets_manager()
    assert result is manager


def test_returns_none_when_factory_not_in_sys_modules():
    """get_secrets_manager() returns None when openbao_secrets_factory_common is absent from sys.modules."""
    sys.modules.pop("openbao_secrets_factory_common", None)
    result = get_secrets_manager()
    assert result is None


def test_returns_none_when_get_openbao_manager_returns_none(factory_mock):
    """get_secrets_manager() returns None when factory.get_openbao_manager() returns None."""
    factory, _ = factory_mock
    factory.get_openbao_manager.return_value = None
    with patch.dict(sys.modules, {"openbao_secrets_factory_common": factory}):
        result = get_secrets_manager()
    assert result is None


def test_returns_none_when_manager_not_available(factory_mock):
    """get_secrets_manager() returns None when the manager reports is_available() as False."""
    factory, manager = factory_mock
    manager.is_available.return_value = False
    with patch.dict(sys.modules, {"openbao_secrets_factory_common": factory}):
        result = get_secrets_manager()
    assert result is None


def test_returns_none_when_factory_raises(factory_mock):
    """get_secrets_manager() returns None without re-raising when factory.get_openbao_manager() throws."""
    factory, _ = factory_mock
    factory.get_openbao_manager.side_effect = Exception("vault unreachable")
    with patch.dict(sys.modules, {"openbao_secrets_factory_common": factory}):
        result = get_secrets_manager()
    assert result is None


def test_returns_none_when_get_secrets_manager_raises_internally():
    """get_secrets_manager() returns None and never re-raises when _get_openbao_manager itself raises."""
    with patch.object(
        _resolver_mod, "_get_openbao_manager", side_effect=Exception("internal boom")
    ):
        result = get_secrets_manager()
    assert result is None


def test_execute_is_noop():
    """OpenBaoSecretsResolver.execute() completes without exception and returns None."""
    resolver = OpenBaoSecretsResolver()
    result = asyncio.run(resolver.execute(agent=MagicMock()))
    assert result is None


def test_context_kwarg_accepted(factory_mock):
    """get_secrets_manager(context='ui') forwards the kwarg without error and returns the manager."""
    factory, manager = factory_mock
    with patch.dict(sys.modules, {"openbao_secrets_factory_common": factory}):
        result = get_secrets_manager(context="ui")
    assert result is manager


def test_degraded_logging_on_warning(caplog):
    """A logger.warning is emitted when an unexpected exception propagates inside get_secrets_manager."""
    with patch.object(
        _resolver_mod, "_get_openbao_manager", side_effect=Exception("unexpected-resolver-err")
    ):
        with caplog.at_level(logging.WARNING, logger=_LOGGER_NAME):
            result = get_secrets_manager()
    assert result is None
    assert any(
        "unexpected-resolver-err" in msg or "OpenBaoSecretsResolver" in msg
        for msg in caplog.messages
    )


# ---------------------------------------------------------------------------
# Tests for resolve_secret() -- non-proxy secret resolution
# ---------------------------------------------------------------------------


class TestResolveSecret:
    """Unit tests for factory_common.resolve_secret().

    Uses monkeypatch.setattr to patch get_openbao_manager() directly on the
    factory_common module -- avoids singleton state interference.

    AC-01: OpenBao available => returns real value
    AC-03: OpenBao unavailable / returns None => os.environ fallback
    AC-04: Key absent from both backends => None
    AC-05: sentinel 'proxy-a0' never returned from any code path
    """

    def test_resolve_secret_openbao_available_returns_real_value(self, monkeypatch):
        """AC-01/AC-05: OpenBao returns real value; sentinel never leaked."""
        import helpers.factory_common as fc
        from unittest.mock import MagicMock

        mock_mgr = MagicMock()
        mock_mgr.get_secret.return_value = "gho_realtoken123abc"
        monkeypatch.setattr(fc, "get_openbao_manager", lambda: mock_mgr)

        result = fc.resolve_secret("GH_TOKEN")

        assert result == "gho_realtoken123abc"  # AC-01: real value returned
        assert result != "proxy-a0"             # AC-05: sentinel never returned
        mock_mgr.get_secret.assert_called_once_with("GH_TOKEN", project_slug=None)

    def test_resolve_secret_openbao_unavailable_falls_back_to_env(self, monkeypatch):
        """AC-03: OpenBao returns None => os.environ fallback; sentinel never leaked."""
        import helpers.factory_common as fc
        from unittest.mock import MagicMock

        mock_mgr = MagicMock()
        mock_mgr.get_secret.return_value = None  # vault has no value for this key
        monkeypatch.setattr(fc, "get_openbao_manager", lambda: mock_mgr)
        monkeypatch.setenv("GH_TOKEN", "env_fallback_token_xyz")

        result = fc.resolve_secret("GH_TOKEN")

        assert result == "env_fallback_token_xyz"  # AC-03: env fallback used
        assert result != "proxy-a0"                # AC-05: sentinel never returned

    def test_resolve_secret_key_absent_returns_none(self, monkeypatch):
        """AC-04: Key absent from both OpenBao and os.environ => None."""
        import helpers.factory_common as fc
        from unittest.mock import MagicMock

        mock_mgr = MagicMock()
        mock_mgr.get_secret.return_value = None
        monkeypatch.setattr(fc, "get_openbao_manager", lambda: mock_mgr)
        monkeypatch.delenv("_RESOLVE_ABSENT_KEY_XYZ", raising=False)

        result = fc.resolve_secret("_RESOLVE_ABSENT_KEY_XYZ")

        assert result is None  # AC-04: None when absent from all backends
