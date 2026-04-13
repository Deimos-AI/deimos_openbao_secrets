"""test_surface_a_ref_resolution.py — Tests for Surface A bao-ref resolution.

Covers: AC-04 through AC-10 (reference detection + resolution) + ADR-02 guard.

Satisfies: AC-04, AC-05, AC-06, AC-07, AC-08, AC-09, AC-10, ADR-02
"""
import asyncio
import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixture: load Surface A with vault_io + config pre-injected
# ---------------------------------------------------------------------------

_VAULT_IO_KEY = "deimos_openbao_secrets_vault_io"
_CFG_KEY = "openbao_helpers.config"
_PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture(scope="module")
def surface_a_mod():
    """Load Surface A extension with vault_io + config pre-injected."""
    # Stub helpers.plugins
    mock_plugins = MagicMock()
    mock_plugins.find_plugin_dir.return_value = _PLUGIN_ROOT
    sys.modules.setdefault("helpers.plugins", mock_plugins)

    # Pre-inject vault_io stub so _load_vault_io() returns it without filesystem lookup
    mock_vio = MagicMock()
    sys.modules[_VAULT_IO_KEY] = mock_vio

    # Pre-inject config stub
    mock_cfg_mod = MagicMock()
    mock_cfg = MagicMock()
    mock_cfg.hard_fail_on_unavailable = False
    mock_cfg_mod.load_config.return_value = mock_cfg
    sys.modules[_CFG_KEY] = mock_cfg_mod

    path = os.path.join(_PLUGIN_ROOT, "extensions", "python",
                        "plugin_config", "_10_openbao_plugin_config.py")
    spec = importlib.util.spec_from_file_location("surface_a_ref_res", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# AC-04 — bare ALL_CAPS detection
# ---------------------------------------------------------------------------

def test_bare_allcaps_detected_as_ref(surface_a_mod):
    """AC-04: bare ALL_CAPS value matches reference regex.

    MED-01: Tightened to require >= 8 chars AND >= 2 underscores.
    Short/common values like NONE, TRUE, MY_TOKEN are NOT refs.
    """
    assert surface_a_mod._is_bao_ref("OPENBAO_API_KEY") is True   # AC-04: 2+ underscores, 8+ chars
    assert surface_a_mod._is_bao_ref("NONE") is False              # MED-01: too short, no underscores
    assert surface_a_mod._is_bao_ref("TRUE") is False              # MED-01: common config value
    assert surface_a_mod._is_bao_ref("AB") is False                # AC-04: too short
    assert surface_a_mod._is_bao_ref("lowercase_key") is False     # AC-04: not ALL_CAPS
    assert surface_a_mod._is_bao_ref("Mixed_Case") is False        # AC-04: mixed case not matched


# ---------------------------------------------------------------------------
# AC-05 — explicit $bao: prefix detection
# ---------------------------------------------------------------------------

def test_explicit_bao_prefix_detected(surface_a_mod):
    """AC-05: $bao: prefix form is detected as a vault reference."""
    assert surface_a_mod._is_bao_ref("$bao:MY_KEY") is True       # AC-05: explicit prefix
    assert surface_a_mod._extract_ref_key("$bao:MY_KEY") == "MY_KEY"  # AC-05: key extracted


# ---------------------------------------------------------------------------
# AC-06 — OpenBao hit: resolved value returned
# ---------------------------------------------------------------------------

def test_vault_hit_returns_resolved_value(surface_a_mod):
    """AC-06: OpenBao hit -> resolved value returned in settings."""
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.hard_fail_on_unavailable = False
    settings = {"api_key": "API_KEY_OPENAI", "name": "my-plugin"}

    with patch.object(surface_a_mod, "_get_manager", return_value=mock_manager), \
         patch.object(surface_a_mod, "_load_config_if_available", return_value=mock_cfg), \
         patch.object(surface_a_mod, "_vault_read",
                      return_value={"value": "sk-live-secret-value"}):
        result = asyncio.run(surface_a_mod.get_plugin_config(
            "some_plugin", "", "", settings
        ))

    assert result is not None                                    # AC-06: returns modified dict
    assert result["api_key"] == "sk-live-secret-value"           # AC-06: resolved value
    assert result["name"] == "my-plugin"                         # AC-06: non-ref fields unchanged


# ---------------------------------------------------------------------------
# AC-07 — OpenBao miss: original value returned + WARNING logged
# ---------------------------------------------------------------------------

def test_vault_miss_returns_original_value_and_warns(surface_a_mod, caplog):
    """AC-07: OpenBao miss -> original value returned, WARNING logged."""
    import logging
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.hard_fail_on_unavailable = False
    settings = {"token": "OPENBAO_AUTH_TOKEN"}  # MED-01: 2+ underscores required

    with patch.object(surface_a_mod, "_get_manager", return_value=mock_manager), \
         patch.object(surface_a_mod, "_load_config_if_available", return_value=mock_cfg), \
         patch.object(surface_a_mod, "_vault_read", return_value={}), \
         caplog.at_level(logging.WARNING):
        result = asyncio.run(surface_a_mod.get_plugin_config(
            "some_plugin", "", "", settings
        ))

    # AC-07: miss returns None (no modification) -> original dict pass-through
    assert result is None or result.get("token") == "OPENBAO_AUTH_TOKEN"  # AC-07
    # WARNING logged about vault miss
    assert any("OPENBAO_AUTH_TOKEN" in r.message or "not found" in r.message
               for r in caplog.records)                          # AC-07: warning emitted


# ---------------------------------------------------------------------------
# AC-08 — OpenBao unavailable + hard_fail=False: fallback to env
# ---------------------------------------------------------------------------

def test_unavailable_hard_fail_false_falls_back_to_env(surface_a_mod):
    """AC-08: vault unavailable + hard_fail=False -> os.getenv fallback."""
    mock_cfg = MagicMock()
    mock_cfg.hard_fail_on_unavailable = False
    settings = {"api_key": "OPENBAO_API_KEY"}  # MED-01: 2+ underscores required

    with patch.object(surface_a_mod, "_get_manager", return_value=None), \
         patch.object(surface_a_mod, "_load_config_if_available", return_value=mock_cfg), \
         patch.dict(os.environ, {"OPENBAO_API_KEY": "env-fallback-value"}):
        result = asyncio.run(surface_a_mod.get_plugin_config(
            "some_plugin", "", "", settings
        ))

    assert result is not None                                    # AC-08: returns modified dict
    assert result["api_key"] == "env-fallback-value"             # AC-08: env fallback used


# ---------------------------------------------------------------------------
# AC-09 — OpenBao unavailable + hard_fail=True: raises RuntimeError
# ---------------------------------------------------------------------------

def test_unavailable_hard_fail_true_raises(surface_a_mod):
    """AC-09: vault unavailable + hard_fail=True -> RuntimeError raised."""
    mock_cfg = MagicMock()
    mock_cfg.hard_fail_on_unavailable = True
    settings = {"secret_key": "OPENBAO_SECRET_VALUE"}  # MED-01: 2+ underscores required

    with patch.object(surface_a_mod, "_get_manager", return_value=None), \
         patch.object(surface_a_mod, "_load_config_if_available", return_value=mock_cfg):
        with pytest.raises(RuntimeError):                        # AC-09: raises on hard_fail=True
            asyncio.run(surface_a_mod.get_plugin_config(
                "some_plugin", "", "", settings
            ))


# ---------------------------------------------------------------------------
# AC-10 — for_display=True: resolved values masked
# ---------------------------------------------------------------------------

def test_display_mode_masks_resolved_value(surface_a_mod):
    """AC-10: for_display=True -> resolved value masked as [bao-ref: KEY_NAME]."""
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True
    mock_cfg = MagicMock()
    mock_cfg.hard_fail_on_unavailable = False
    settings = {"api_key": "MY_API_KEY"}

    with patch.object(surface_a_mod, "_get_manager", return_value=mock_manager), \
         patch.object(surface_a_mod, "_load_config_if_available", return_value=mock_cfg), \
         patch.object(surface_a_mod, "_vault_read",
                      return_value={"value": "sk-live-plaintext"}):
        result = asyncio.run(surface_a_mod.get_plugin_config(
            "some_plugin", "", "", settings, for_display=True
        ))

    assert result is not None                                       # AC-10: returns dict
    assert result["api_key"] == "[bao-ref: MY_API_KEY]"             # AC-10: masked not plaintext
    assert "sk-live-plaintext" not in str(result)                   # AC-10: plaintext never exposed


# ---------------------------------------------------------------------------
# ADR-02 — bootstrapping guard: own plugin never intercepted
# ---------------------------------------------------------------------------

def test_bootstrapping_guard_skips_own_plugin(surface_a_mod):
    """ADR-02 preserved: deimos_openbao_secrets plugin is never intercepted."""
    settings = {"SOME_KEY": "should-not-resolve"}
    result = asyncio.run(surface_a_mod.get_plugin_config(
        "deimos_openbao_secrets", "", "", settings
    ))
    assert result is None  # ADR-02: bootstrapping guard returns None immediately
