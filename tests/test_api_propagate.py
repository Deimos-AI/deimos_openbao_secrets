"""test_api_propagate.py -- Integration tests for api/propagate.py (E-03).

Covers: AC-20 through AC-26.
"""
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest
import yaml

_PROPAGATE_API_MODULE = "deimos_openbao_secrets_api_propagate"
_PLUGIN_DIR = os.path.join(os.path.dirname(__file__), "..")


@pytest.fixture(scope="module")
def propagate_api():
    """Load api/propagate.py with A0 runtime stubs pre-injected."""
    mock_api = MagicMock()

    class _StubApiHandler:
        pass

    mock_api.ApiHandler = _StubApiHandler
    mock_api.Request = MagicMock
    mock_api.Response = MagicMock
    sys.modules.setdefault("helpers.api", mock_api)
    sys.modules.setdefault("helpers.plugins", MagicMock())

    path = os.path.join(_PLUGIN_DIR, "api", "propagate.py")
    if not os.path.exists(path):
        pytest.skip("api/propagate.py not yet created")
    spec = importlib.util.spec_from_file_location(_PROPAGATE_API_MODULE, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_PROPAGATE_API_MODULE] = mod
    spec.loader.exec_module(mod)
    return mod

def _make_handler(propagate_api):
    """Create a Propagate handler instance."""
    return propagate_api.Propagate()


def _mock_request():
    """Create a mock Request."""
    return MagicMock()


def _load_config_result(enabled=True, url="https://vault:8200"):
    """Create a mock config with the given settings."""
    cfg = MagicMock()
    cfg.plugin_sync_enabled = enabled
    cfg.url = url
    cfg.secret_field_patterns = ["*key*", "*token*", "*secret*", "*password*", "*auth*"]
    return cfg


# ===========================================================================
# AC-20: All four actions accepted
# ===========================================================================


class TestApiActions:
    """AC-20: POST propagate accepts scan, propagate, undo, list_backups."""

    @pytest.mark.asyncio
    async def test_scan_action(self, propagate_api):
        """AC-20, AC-21: scan action returns targets."""
        handler = _make_handler(propagate_api)
        cfg = _load_config_result()
        with patch.object(propagate_api, "load_config", return_value=cfg), \
             patch.object(propagate_api, "_load_vault_io") as mock_vio, \
             patch.object(propagate_api, "_load_propagator") as mock_prop:
            mock_vio.return_value = MagicMock()
            mock_vio.return_value._get_manager.return_value = MagicMock()
            mock_prop_instance = MagicMock()
            mock_prop_instance.scan_targets.return_value = []
            mock_prop.return_value = mock_prop_instance
            result = await handler.process(
                {"action": "scan"}, _mock_request()
            )
            assert result.get("targets") is not None or result.get("ok") is not None

    @pytest.mark.asyncio
    async def test_propagate_action(self, propagate_api):
        """AC-20, AC-22, AC-23: propagate action accepts targets."""
        handler = _make_handler(propagate_api)
        cfg = _load_config_result()
        with patch.object(propagate_api, "load_config", return_value=cfg), \
             patch.object(propagate_api, "_load_vault_io") as mock_vio, \
             patch.object(propagate_api, "_load_propagator") as mock_prop:
            mock_vio.return_value = MagicMock()
            mock_vio.return_value._get_manager.return_value = MagicMock()
            mock_prop_instance = MagicMock()
            mock_prop_instance.scan_targets.return_value = []
            from helpers.propagator import PropagationResult
            mock_prop_instance.propagate.return_value = PropagationResult(
                ok=True, propagated=0, skipped=0, errors=[], backups_created=[]
            )
            mock_prop.return_value = mock_prop_instance
            result = await handler.process(
                {"action": "propagate", "targets": []}, _mock_request()
            )
            assert result.get("ok") is True or result.get("propagated") is not None

    @pytest.mark.asyncio
    async def test_undo_action(self, propagate_api):
        """AC-20, AC-24: undo action accepts backup_id."""
        handler = _make_handler(propagate_api)
        cfg = _load_config_result()
        with patch.object(propagate_api, "load_config", return_value=cfg), \
             patch.object(propagate_api, "_load_vault_io") as mock_vio, \
             patch.object(propagate_api, "_load_propagator") as mock_prop:
            mock_vio.return_value = MagicMock()
            mock_vio.return_value._get_manager.return_value = MagicMock()
            mock_prop_instance = MagicMock()
            mock_prop_instance.undo.return_value = {"ok": True, "restored": 0, "errors": []}
            mock_prop_module = MagicMock()
            mock_prop_module.Propagator.return_value = mock_prop_instance
            mock_prop.return_value = mock_prop_module
            result = await handler.process(
                {"action": "undo", "backup_id": "2026-04-07T10:00:00Z"}, _mock_request()
            )
            assert result.get("ok") is True

    @pytest.mark.asyncio
    async def test_list_backups_action(self, propagate_api):
        """AC-20: list_backups action returns backup list."""
        handler = _make_handler(propagate_api)
        cfg = _load_config_result()
        with patch.object(propagate_api, "load_config", return_value=cfg), \
             patch.object(propagate_api, "_load_vault_io") as mock_vio, \
             patch.object(propagate_api, "_load_propagator") as mock_prop:
            mock_vio.return_value = MagicMock()
            mock_vio.return_value._get_manager.return_value = MagicMock()
            mock_prop_instance = MagicMock()
            mock_prop_instance.list_backups.return_value = []
            mock_prop.return_value = mock_prop_instance
            result = await handler.process(
                {"action": "list_backups"}, _mock_request()
            )
            assert result.get("backups") is not None or result.get("ok") is not None


# ===========================================================================
# AC-25: Disabled when plugin_sync_enabled=false
# ===========================================================================


class TestSyncGate:
    """AC-25: All propagate/undo actions gated by plugin_sync_enabled."""

    @pytest.mark.asyncio
    async def test_disabled_returns_error(self, propagate_api):
        """AC-25: Disabled when plugin_sync_enabled=false."""
        handler = _make_handler(propagate_api)
        cfg = _load_config_result(enabled=False)
        with patch.object(propagate_api, "load_config", return_value=cfg):
            result = await handler.process(
                {"action": "scan"}, _mock_request()
            )
            assert result.get("ok") is False
            assert "disabled" in result.get("error", "").lower()


# ===========================================================================
# AC-26: HTTPS enforcement
# ===========================================================================


class TestHTTPSEnforcement:
    """AC-26: Propagate refuses http:// vault URL."""

    @pytest.mark.asyncio
    async def test_http_url_refused(self, propagate_api):
        """AC-26: http:// vault URL is refused."""
        handler = _make_handler(propagate_api)
        cfg = _load_config_result(url="http://vault:8200")
        with patch.object(propagate_api, "load_config", return_value=cfg):
            result = await handler.process(
                {"action": "scan"}, _mock_request()
            )
            assert result.get("ok") is False
            assert "https" in result.get("error", "").lower()
