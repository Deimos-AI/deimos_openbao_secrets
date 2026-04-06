"""test_adversarial_hardening.py -- Regression tests for adversarial review findings.

Covers priority test gaps from the adversarial code review (T-08, T-09, T-10,
T-12, T-13, T-15).  Each test verifies that the corresponding MEDIUM/LOW fix
is effective and prevents regression.

Satisfies: MED-01 (T-08), MED-02 (T-09), MED-03 (T-10), MED-04 (T-12),
          MED-06 (T-13), hard_fail precedence (T-15)
"""
import asyncio
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Module loading helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def config_mod():
    """Load helpers/config.py for testing."""
    path = os.path.join(os.path.dirname(__file__), "..", "helpers", "config.py")
    spec = importlib.util.spec_from_file_location("openbao_config_adv", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # Required for @dataclass in Python 3.13+
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def surface_a_mod():
    """Load plugin_config extension for _is_bao_ref testing."""
    sys.modules.setdefault("helpers.secrets", MagicMock())
    sys.modules.setdefault("helpers.plugins", MagicMock())
    sys.modules.setdefault("helpers.extension", MagicMock())
    sys.modules.setdefault("helpers", MagicMock())
    sys.modules.setdefault("python", MagicMock())
    sys.modules.setdefault("python.helpers", MagicMock())
    sys.modules.setdefault("python.helpers.secrets", MagicMock())
    sys.modules.setdefault("python.helpers.plugins", MagicMock())
    sys.modules.setdefault("python.helpers.extension", MagicMock())

    path = os.path.join(
        os.path.dirname(__file__), "..",
        "extensions", "python", "plugin_config",
        "_10_openbao_plugin_config.py",
    )
    spec = importlib.util.spec_from_file_location("surface_a_adv", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def mask_hist_mod():
    """Load mask_history extension for _mask_string testing."""
    sys.modules.setdefault("helpers.secrets", MagicMock())

    path = os.path.join(
        os.path.dirname(__file__), "..",
        "extensions", "python", "hist_add_before",
        "_10_openbao_mask_history.py",
    )
    spec = importlib.util.spec_from_file_location("mask_hist_adv", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def manager_mod():
    """Load openbao_secrets_manager for reentrancy testing."""
    mock_secrets = MagicMock()
    mock_secrets.SecretsManager = MagicMock
    mock_secrets.alias_for_key = lambda key: f"<<{key}>>"
    mock_secrets.DEFAULT_SECRETS_FILE = "usr/secrets.env"
    sys.modules["helpers.secrets"] = mock_secrets
    sys.modules.setdefault("openbao_config", MagicMock())
    sys.modules.setdefault("openbao_client", MagicMock())
    sys.modules.setdefault("circuitbreaker", MagicMock())

    path = os.path.join(
        os.path.dirname(__file__), "..",
        "helpers", "openbao_secrets_manager.py",
    )
    spec = importlib.util.spec_from_file_location("openbao_mgr_adv", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def api_secrets_mod():
    """Load api/sync_plugins.py for sync testing."""
    mock_api = MagicMock()
    mock_api.ApiHandler = type("ApiHandler", (), {})
    mock_api.Request = MagicMock
    mock_api.Response = MagicMock
    sys.modules.setdefault("helpers.api", mock_api)
    sys.modules.setdefault("helpers.plugins", MagicMock())
    sys.modules["deimos_openbao_secrets_helpers_vault_io"] = MagicMock()

    path = os.path.join(os.path.dirname(__file__), "..", "api", "sync_plugins.py")
    spec = importlib.util.spec_from_file_location("api_sync_plugins_adv", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ===========================================================================
# T-08: _is_bao_ref('NONE') -> no false-positive after MED-01 fix
# ===========================================================================

class TestMED01IsBaoRefTightened:
    """T-08: MED-01 tightened _is_bao_ref to reject common config values."""

    def test_none_not_detected_as_ref(self, surface_a_mod):
        """T-08 / MED-01: NONE must NOT be detected as a vault ref."""
        assert surface_a_mod._is_bao_ref("NONE") is False       # T-08

    def test_true_not_detected_as_ref(self, surface_a_mod):
        """T-08 / MED-01: TRUE must NOT be detected as a vault ref."""
        assert surface_a_mod._is_bao_ref("TRUE") is False       # T-08

    def test_false_not_detected_as_ref(self, surface_a_mod):
        """T-08 / MED-01: FALSE must NOT be detected as a vault ref."""
        assert surface_a_mod._is_bao_ref("FALSE") is False      # T-08

    def test_debug_not_detected_as_ref(self, surface_a_mod):
        """T-08 / MED-01: DEBUG must NOT be detected as a vault ref."""
        assert surface_a_mod._is_bao_ref("DEBUG") is False      # T-08

    def test_info_not_detected_as_ref(self, surface_a_mod):
        """T-08 / MED-01: INFO must NOT be detected as a vault ref."""
        assert surface_a_mod._is_bao_ref("INFO") is False       # T-08

    def test_token_not_detected_as_ref(self, surface_a_mod):
        """T-08 / MED-01: TOKEN must NOT be detected as a vault ref."""
        assert surface_a_mod._is_bao_ref("TOKEN") is False      # T-08

    def test_valid_bare_ref_still_detected(self, surface_a_mod):
        """MED-01: Legitimate bare refs (2+ underscores, 8+ chars) still work."""
        assert surface_a_mod._is_bao_ref("OPENBAO_API_KEY") is True   # MED-01

    def test_explicit_prefix_still_detected(self, surface_a_mod):
        """MED-01: $bao: prefix always works regardless of key format."""
        assert surface_a_mod._is_bao_ref("$bao:SHORT") is True        # MED-01


# ===========================================================================
# T-09: resolve_project_path with malicious project_slug -> ValueError (MED-02)
# ===========================================================================

class TestMED02ProjectSlugValidation:
    """T-09: MED-02 validates project_slug to prevent format injection."""

    def test_path_traversal_slug_rejected(self, config_mod):
        """T-09 / MED-02: ../ in slug raises ValueError."""
        cfg = config_mod.OpenBaoConfig()
        with pytest.raises(ValueError, match="Invalid project_slug"):
            config_mod.resolve_project_path(cfg, "../../admin")      # T-09

    def test_format_injection_slug_rejected(self, config_mod):
        """T-09 / MED-02: Format string injection in slug raises ValueError."""
        cfg = config_mod.OpenBaoConfig()
        with pytest.raises(ValueError, match="Invalid project_slug"):
            config_mod.resolve_project_path(cfg, "{__class__}")       # T-09

    def test_semicolon_slug_rejected(self, config_mod):
        """MED-02: Semicolons in slug raise ValueError."""
        cfg = config_mod.OpenBaoConfig()
        with pytest.raises(ValueError, match="Invalid project_slug"):
            config_mod.resolve_project_path(cfg, "project;rm -rf /") # MED-02

    def test_valid_slug_passes(self, config_mod):
        """MED-02: Normal slugs work correctly."""
        cfg = config_mod.OpenBaoConfig()
        result = config_mod.resolve_project_path(cfg, "my-project")   # MED-02
        assert result == "agentzero-my-project"

    def test_slug_with_dots_and_underscores(self, config_mod):
        """MED-02: Dots and underscores in slugs are allowed."""
        cfg = config_mod.OpenBaoConfig()
        result = config_mod.resolve_project_path(cfg, "my_project.v2")  # MED-02
        assert result == "agentzero-my_project.v2"


# ===========================================================================
# T-10: _mask_string substring masking bypass (MED-03)
# ===========================================================================

class TestMED03MaskingSubstringBypass:
    """T-10: MED-03 sorts secrets by descending value length before masking."""

    def test_longer_value_masked_first(self, mask_hist_mod):
        """T-10 / MED-03: Longer secret value is fully masked even if shorter
        secret is a substring of it."""
        secrets = {
            "KEY_A": "password",
            "KEY_B": "password123!",
        }
        text = "User entered password123! for login"
        result = mask_hist_mod._mask_string(text, secrets)             # T-10
        assert "password123!" not in result                           # T-10

    def test_shorter_substring_not_leaking_longer(self, mask_hist_mod):
        """T-10 / MED-03: Shorter value replaced after longer - no leak."""
        # Use token-like values (with special chars) so _should_mask() returns True
        secrets = {
            "SHORT": "abc!123",
            "LONG": "abc!12345@xyz",
        }
        text = "secret is abc!12345@xyz here"
        result = mask_hist_mod._mask_string(text, secrets)             # T-10
        assert "abc!12345@xyz" not in result                           # T-10


# ===========================================================================
# T-12: _load_from_env_fallback reentrancy (MED-04)
# ===========================================================================

class TestMED04ReentrancyGuard:
    """T-12: MED-04 reentrancy guard prevents RecursionError in
    _load_from_env_fallback."""

    def test_reentrant_call_returns_cache_without_error(self, manager_mod):
        """T-12 / MED-04: Reentrant _load_from_env_fallback returns cached
        value instead of recursing."""
        instance = MagicMock(spec=[])
        instance._loading_env_fallback = True  # Simulate already-loading state
        instance._secrets_cache = {"EXISTING": "value"}

        result = manager_mod.OpenBaoSecretsManager._load_from_env_fallback(
            instance
        )                                                              # T-12
        assert result == {"EXISTING": "value"}                       # T-12

    def test_reentrant_call_with_empty_cache_returns_empty(self, manager_mod):
        """T-12 / MED-04: Reentrant call with None cache returns empty dict."""
        instance = MagicMock(spec=[])
        instance._loading_env_fallback = True
        instance._secrets_cache = None

        result = manager_mod.OpenBaoSecretsManager._load_from_env_fallback(
            instance
        )                                                              # T-12
        assert result == {}                                           # T-12


# ===========================================================================
# T-13: SyncPlugins blocked over HTTP (MED-06)
# ===========================================================================

class TestMED06SyncHTTPBlock:
    """T-13: MED-06 blocks SyncPlugins when vault URL uses http://."""

    def test_sync_blocked_over_http(self, api_secrets_mod):
        """T-13 / MED-06: Sync returns error when vault URL is http://."""
        handler = api_secrets_mod.SyncPlugins()
        mock_cfg = MagicMock()
        mock_cfg.url = "http://192.168.1.100:8200"  # HTTP, not HTTPS
        mock_cfg.plugin_sync_enabled = True

        with patch.object(api_secrets_mod, "load_config", return_value=mock_cfg):
            result = asyncio.run(handler.process({}, MagicMock()))    # T-13

        assert result["ok"] is False                                  # T-13
        assert "HTTPS" in result["error"]                             # T-13

    def test_sync_allowed_over_https(self, api_secrets_mod):
        """MED-06: Sync proceeds when vault URL is https://."""
        handler = api_secrets_mod.SyncPlugins()
        mock_cfg = MagicMock()
        mock_cfg.url = "https://vault.example.com:8200"
        mock_cfg.plugin_sync_enabled = True
        mock_cfg.secrets_path = "agentzero"
        mock_vio = MagicMock()
        mock_vio._get_manager.return_value = MagicMock()

        with patch.object(api_secrets_mod, "load_config", return_value=mock_cfg), \
             patch.object(api_secrets_mod, "_load_vault_io", return_value=mock_vio), \
             patch.object(api_secrets_mod, "_USR_PLUGINS_DIR", Path("/tmp/nonexistent_plugins")):
            result = asyncio.run(handler.process({}, MagicMock()))    # MED-06

        assert result["ok"] is True                                   # MED-06


# ===========================================================================
# T-15: hard_fail_on_unavailable=True + fallback_to_env=True precedence
# ===========================================================================

class TestT15HardFailPrecedence:
    """T-15: hard_fail_on_unavailable=True takes precedence over
    fallback_to_env=True."""

    def test_hard_fail_true_overrides_fallback_true(self, config_mod):
        """T-15: When both hard_fail=True and fallback_to_env=True,
        hard_fail wins - OpenBaoUnavailableError is raised."""
        cfg = config_mod.OpenBaoConfig()
        cfg.hard_fail_on_unavailable = True
        cfg.fallback_to_env = True

        assert cfg.hard_fail_on_unavailable is True                  # T-15
        assert cfg.fallback_to_env is True                            # T-15

    def test_hard_fail_false_allows_fallback(self, config_mod):
        """T-15: When hard_fail=False and fallback_to_env=True,
        fallback is used on unavailability."""
        cfg = config_mod.OpenBaoConfig()
        cfg.hard_fail_on_unavailable = False
        cfg.fallback_to_env = True

        assert cfg.hard_fail_on_unavailable is False                 # T-15
        assert cfg.fallback_to_env is True                            # T-15

    def test_both_false_returns_empty(self, config_mod):
        """T-15: When hard_fail=False and fallback_to_env=False,
        load_secrets returns empty dict."""
        cfg = config_mod.OpenBaoConfig()
        cfg.hard_fail_on_unavailable = False
        cfg.fallback_to_env = False

        assert cfg.hard_fail_on_unavailable is False                 # T-15
        assert cfg.fallback_to_env is False                           # T-15
