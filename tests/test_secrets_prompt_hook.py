"""Tests for extensions/python/agent_init/_25_openbao_secrets_prompt.py

E-07 AC-10: prompt substitution hook.

Satisfies: E-07 AC-07, AC-08, AC-10
"""
import asyncio
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest


@pytest.fixture(scope="module")
def hook_mod():
    """Load the _25_openbao_secrets_prompt extension module."""
    path = os.path.join(
        os.path.dirname(__file__), "..",
        "extensions", "python", "agent_init",
        "_25_openbao_secrets_prompt.py"
    )
    # Stub required framework imports before loading
    mock_ext = MagicMock()
    mock_ext.Extension = object
    sys.modules.setdefault("helpers.extension", mock_ext)

    spec = importlib.util.spec_from_file_location("openbao_secrets_prompt_e07", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_mock_agent():
    """Create a minimal mock agent."""
    mock_agent = MagicMock()
    mock_agent.context = MagicMock()
    mock_agent.read_prompt.return_value = "## secrets\nKEY_A, KEY_B"
    return mock_agent


# ---------------------------------------------------------------------------
# AC-10: _is_openbao_active() helper
# ---------------------------------------------------------------------------

def test_is_openbao_active_true_when_available(hook_mod):
    """AC-08: returns True when factory + available manager present."""
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True
    mock_fc = MagicMock()
    mock_fc.get_openbao_manager.return_value = mock_manager

    with patch.dict(sys.modules, {"openbao_secrets_factory_common": mock_fc}):
        result = hook_mod._is_openbao_active()

    assert result is True  # AC-08


def test_is_openbao_active_false_when_manager_none(hook_mod):
    """AC-08: returns False when manager is None."""
    mock_fc = MagicMock()
    mock_fc.get_openbao_manager.return_value = None

    with patch.dict(sys.modules, {"openbao_secrets_factory_common": mock_fc}):
        result = hook_mod._is_openbao_active()

    assert result is False  # AC-08


def test_is_openbao_active_false_when_unavailable(hook_mod):
    """AC-08: returns False when manager.is_available() is False."""
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = False
    mock_fc = MagicMock()
    mock_fc.get_openbao_manager.return_value = mock_manager

    with patch.dict(sys.modules, {"openbao_secrets_factory_common": mock_fc}):
        result = hook_mod._is_openbao_active()

    assert result is False  # AC-08


def test_is_openbao_active_false_no_factory(hook_mod):
    """AC-08: returns False when factory module not in sys.modules."""
    saved = sys.modules.pop("openbao_secrets_factory_common", None)
    try:
        result = hook_mod._is_openbao_active()
        assert result is False  # AC-08
    finally:
        if saved is not None:
            sys.modules["openbao_secrets_factory_common"] = saved


# ---------------------------------------------------------------------------
# AC-10: build_prompt() hook function
# ---------------------------------------------------------------------------

def test_build_prompt_returns_none_when_inactive(hook_mod):
    """AC-08: inactive OpenBao -> returns None (framework default used)."""
    mock_agent = _make_mock_agent()

    with patch.object(hook_mod, "_is_openbao_active", return_value=False):
        result = asyncio.run(hook_mod.build_prompt(mock_agent))

    assert result is None  # AC-08: framework default
    mock_agent.read_prompt.assert_not_called()  # AC-08: no plugin prompt read


def test_build_prompt_returns_none_when_prompt_file_missing(hook_mod, tmp_path):
    """AC-08: active OpenBao but missing prompt file -> returns None."""
    missing_path = tmp_path / "nonexistent.md"
    mock_agent = _make_mock_agent()

    with patch.object(hook_mod, "_is_openbao_active", return_value=True), \
         patch.object(hook_mod, "_CUSTOM_PROMPT", missing_path):
        result = asyncio.run(hook_mod.build_prompt(mock_agent))

    assert result is None  # AC-08: fail-open


def test_build_prompt_returns_rendered_prompt_when_active(hook_mod, tmp_path):
    """AC-07: active OpenBao + prompt file present -> returns rendered plugin prompt."""
    custom_prompt = tmp_path / "agent.system.secrets.md"
    custom_prompt.write_text("## secrets\n{{secrets}}")

    mock_agent = _make_mock_agent()
    mock_agent.read_prompt.return_value = "## secrets\nALPHA_TOKEN, BETA_KEY"

    mock_secrets_mgr = MagicMock()
    mock_secrets_mgr.get_secrets_for_prompt.return_value = "ALPHA_TOKEN, BETA_KEY"

    mock_secrets_mod = MagicMock()
    mock_secrets_mod.get_secrets_manager.return_value = mock_secrets_mgr

    mock_settings_mod = MagicMock()
    mock_settings_mod.get_settings.return_value = {"variables": {}}

    with patch.object(hook_mod, "_is_openbao_active", return_value=True), \
         patch.object(hook_mod, "_CUSTOM_PROMPT", custom_prompt), \
         patch.dict(sys.modules, {
             "helpers.secrets": mock_secrets_mod,
             "helpers.settings": mock_settings_mod,
         }):
        result = asyncio.run(hook_mod.build_prompt(mock_agent))

    # AC-07: custom prompt was read
    assert result == "## secrets\nALPHA_TOKEN, BETA_KEY"  # AC-07
    mock_agent.read_prompt.assert_called_once()  # AC-07: plugin prompt file read
    # Verify it was called with the plugin's prompt path
    call_args = mock_agent.read_prompt.call_args[0]
    assert str(custom_prompt) in call_args[0]  # AC-07


def test_build_prompt_returns_none_on_exception(hook_mod, tmp_path):
    """AC-08: any exception during prompt build -> returns None (fail-open)."""
    custom_prompt = tmp_path / "agent.system.secrets.md"
    custom_prompt.write_text("## secrets")

    mock_agent = MagicMock()
    mock_agent.read_prompt.side_effect = RuntimeError("prompt render failed")

    mock_secrets_mgr = MagicMock()
    mock_secrets_mgr.get_secrets_for_prompt.return_value = "KEY_A"

    mock_secrets_mod = MagicMock()
    mock_secrets_mod.get_secrets_manager.return_value = mock_secrets_mgr

    mock_settings_mod = MagicMock()
    mock_settings_mod.get_settings.return_value = {"variables": {}}

    with patch.object(hook_mod, "_is_openbao_active", return_value=True), \
         patch.object(hook_mod, "_CUSTOM_PROMPT", custom_prompt), \
         patch.dict(sys.modules, {
             "helpers.secrets": mock_secrets_mod,
             "helpers.settings": mock_settings_mod,
         }):
        result = asyncio.run(hook_mod.build_prompt(mock_agent))

    assert result is None  # AC-08: fail-open, no exception propagated
