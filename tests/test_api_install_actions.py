"""Test suite for api/install_actions.py — E-08 extension.

Acceptance criteria covered:
  AC-D4  POST propagate — marks discovered secrets as propagated
  AC-D5  POST defer-propagation — marks discovery as deferred
"""
from __future__ import annotations

import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.install_actions import InstallActions  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def clean_sys_modules():
    """Clean deferred import modules between tests."""
    for key in ("helpers.registry",):
        sys.modules.pop(key, None)
    yield
    for key in ("helpers.registry",):
        sys.modules.pop(key, None)


class TestPropagate:
    """AC-D4: POST propagate marks discovered secrets as propagated."""

    def test_propagate_success(self):
        """Propagate with pending discovery updates registry status."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [
                {"id": "1", "key": "KEY1", "source": "vault_discovery", "status": "discovered"},
                {"id": "2", "key": "KEY2", "source": "vault_discovery", "status": "discovered"},
            ],
            "discovery_status": "discovered",
            "vault_secret_keys": ["KEY1", "KEY2"],
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler = InstallActions()
            request = MagicMock()
            request.path = "/api/plugins/deimos_openbao_secrets/install/propagate"
            result = _run(handler.process(request))

        assert result["ok"] is True
        assert result["action"] == "propagate"
        assert result["propagated"] == 2
        assert result["keys"] == ["KEY1", "KEY2"]
        # Verify registry was saved with propagated status
        mock_rm.save.assert_called_once()
        saved = mock_rm.save.call_args[0][0]
        assert saved["discovery_status"] == "propagated"
        assert "propagated_at" in saved
        # Verify individual entries updated
        for entry in saved["entries"]:
            if entry["source"] == "vault_discovery":
                assert entry["status"] == "propagated"

    def test_propagate_no_pending_discovery(self):
        """Propagate when no pending discovery returns error."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [],
            "discovery_status": "propagated",
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler = InstallActions()
            result = _run(handler._propagate())

        assert result["ok"] is False
        assert "No pending discovery" in result["errors"][0]

    def test_propagate_no_keys(self):
        """Propagate with discovery but no keys returns error."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [],
            "discovery_status": "discovered",
            "vault_secret_keys": [],
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler = InstallActions()
            result = _run(handler._propagate())

        assert result["ok"] is False
        assert "No discovered secret keys" in result["errors"][0]

    def test_propagate_with_dict_request(self):
        """Propagate routes correctly with dict-style request."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [{"id": "1", "key": "K", "source": "vault_discovery", "status": "discovered"}],
            "discovery_status": "discovered",
            "vault_secret_keys": ["K"],
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler = InstallActions()
            result = _run(handler.process({"path": "/install/propagate"}))

        assert result["ok"] is True
        assert result["propagated"] == 1


class TestDeferPropagation:
    """AC-D5: POST defer-propagation marks discovery as deferred."""

    def test_defer_success(self):
        """Defer with pending discovery adds deferred_at timestamp."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [
                {"id": "1", "key": "KEY1", "source": "vault_discovery", "status": "discovered"},
            ],
            "discovery_status": "discovered",
            "vault_secret_keys": ["KEY1"],
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler = InstallActions()
            request = MagicMock()
            request.path = "/api/plugins/deimos_openbao_secrets/install/defer-propagation"
            result = _run(handler.process(request))

        assert result["ok"] is True
        assert result["action"] == "defer-propagation"
        assert result["deferred"] is True
        # Verify deferred_at was added
        mock_rm.save.assert_called_once()
        saved = mock_rm.save.call_args[0][0]
        assert "deferred_at" in saved
        # Discovery status stays 'discovered'
        assert saved["discovery_status"] == "discovered"

    def test_defer_no_pending_discovery(self):
        """Defer when no pending discovery returns error."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [],
            "discovery_status": None,
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler = InstallActions()
            result = _run(handler._defer_propagation())

        assert result["ok"] is False
        assert "No pending discovery" in result["errors"][0]

    def test_defer_already_propagated(self):
        """Defer when already propagated returns error."""
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": [],
            "discovery_status": "propagated",
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler = InstallActions()
            result = _run(handler._defer_propagation())

        assert result["ok"] is False
        assert "No pending discovery" in result["errors"][0]


class TestRegistryEntryStatus:
    """Verify registry entries have correct status transitions."""

    def test_propagate_updates_entry_status(self):
        """Propagate changes individual entry status from discovered to propagated."""
        entries = [
            {"id": "1", "key": "KEY1", "source": "vault_discovery", "status": "discovered"},
            {"id": "2", "key": "KEY2", "source": "install_seed", "status": "migrated"},
            {"id": "3", "key": "KEY3", "source": "vault_discovery", "status": "discovered"},
        ]
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": entries,
            "discovery_status": "discovered",
            "vault_secret_keys": ["KEY1", "KEY3"],
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler = InstallActions()
            result = _run(handler._propagate())

        assert result["ok"] is True
        saved = mock_rm.save.call_args[0][0]
        # Only vault_discovery entries changed
        statuses = {e["key"]: e["status"] for e in saved["entries"]}
        assert statuses["KEY1"] == "propagated"
        assert statuses["KEY2"] == "migrated"  # Unchanged
        assert statuses["KEY3"] == "propagated"

    def test_defer_preserves_entry_status(self):
        """Defer does NOT change individual entry statuses."""
        entries = [
            {"id": "1", "key": "KEY1", "source": "vault_discovery", "status": "discovered"},
        ]
        mock_rm = MagicMock()
        mock_rm.load.return_value = {
            "entries": entries,
            "discovery_status": "discovered",
            "vault_secret_keys": ["KEY1"],
        }
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler = InstallActions()
            result = _run(handler._defer_propagation())

        assert result["ok"] is True
        saved = mock_rm.save.call_args[0][0]
        # Entry status stays discovered
        assert saved["entries"][0]["status"] == "discovered"


class TestIdempotency:
    """Verify idempotent behavior."""

    def test_double_propagate_second_fails(self):
        """Second propagate call after first succeeds returns error."""
        mock_rm = MagicMock()
        # First call returns discovered, second returns propagated
        mock_rm.load.side_effect = [
            {
                "entries": [{"id": "1", "key": "K", "source": "vault_discovery", "status": "discovered"}],
                "discovery_status": "discovered",
                "vault_secret_keys": ["K"],
            },
            {
                "entries": [{"id": "1", "key": "K", "source": "vault_discovery", "status": "propagated"}],
                "discovery_status": "propagated",
                "vault_secret_keys": ["K"],
                "propagated_at": "2026-01-01",
            },
        ]
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler1 = InstallActions()
            r1 = _run(handler1._propagate())

            handler2 = InstallActions()
            r2 = _run(handler2._propagate())

        assert r1["ok"] is True
        assert r2["ok"] is False  # Second call fails — no pending discovery

    def test_double_defer_second_fails(self):
        """Second defer after first defer still has discovered status — succeeds."""
        mock_rm = MagicMock()
        mock_rm.load.side_effect = [
            {
                "entries": [{"id": "1", "key": "K", "source": "vault_discovery", "status": "discovered"}],
                "discovery_status": "discovered",
                "vault_secret_keys": ["K"],
                "deferred_at": "2026-01-01",
            },
            {
                "entries": [{"id": "1", "key": "K", "source": "vault_discovery", "status": "discovered"}],
                "discovery_status": "discovered",
                "vault_secret_keys": ["K"],
                "deferred_at": "2026-01-02",
            },
        ]
        mock_registry_mod = MagicMock()
        mock_registry_mod.RegistryManager.return_value = mock_rm

        with patch.dict(sys.modules, {"helpers.registry": mock_registry_mod}):
            handler1 = InstallActions()
            r1 = _run(handler1._defer_propagation())

            handler2 = InstallActions()
            r2 = _run(handler2._defer_propagation())

        assert r1["ok"] is True
        assert r2["ok"] is True  # Defer is always valid while discovered
