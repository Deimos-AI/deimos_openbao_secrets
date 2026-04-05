"""test_surface_a.py — Test suite for Surface A (_10_openbao_plugin_config.py).

Covers: save, resolve, deduplication, atomicity, idempotency, ADR-02 pass-through,
and unavailable-noop behaviour.

Satisfies: AC-01 (file creation), AC-02, AC-03, AC-04, AC-05, AC-06, AC-07, AC-08
"""
import asyncio
import importlib.util
import os
import re
import sys
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixture: load Surface A via importlib (A0 runtime not present in test env)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def surface_a():
    """Load Surface A module without A0 runtime dependencies.

    Injects a helpers.plugins stub so _load_vault_io() does not crash on
    import.  The module is loaded once per test session (scope=module).

    Satisfies: AC-01
    """
    plugin_root = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(
        plugin_root,
        "extensions",
        "python",
        "plugin_config",
        "_10_openbao_plugin_config.py",
    )
    # Mock helpers.plugins so _load_vault_io() does not crash on import
    if "helpers.plugins" not in sys.modules:
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = None
        sys.modules["helpers.plugins"] = mock_plugins
    spec = importlib.util.spec_from_file_location("surface_a_module", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sanitize(v: str) -> str:
    """Mirror of _sanitize_component for expected-path assertions in tests."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", v).lstrip(".")


_DEFAULT_PATTERNS = ["*key*", "*token*", "*secret*", "*password*", "*auth*"]


# ---------------------------------------------------------------------------
# AC-02 — save: matching field written to vault with correct path + value
# ---------------------------------------------------------------------------


def test_save_writes_matching_field_to_vault(surface_a):
    """AC-02: field matching *key* pattern → _vault_write called with correct
    canonical path (plugin/{plugin}/{key}) and raw value dict.
    Settings dict is replaced with [bao-ref:REDACTED] placeholder.
    """
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True
    mock_write = MagicMock()

    settings = {"api_key": "s3cr3t-value"}

    with (
        patch.object(surface_a, "_get_manager", return_value=mock_manager),
        patch.object(surface_a, "_vault_read", return_value=None),
        patch.object(surface_a, "_vault_write", mock_write),
        patch.object(surface_a, "_get_patterns", return_value=_DEFAULT_PATTERNS),
        patch.object(surface_a, "_sanitize_component", new=_sanitize),
    ):
        asyncio.run(
            surface_a.save_plugin_config(
                plugin_name="myplugin",
                project_name="",
                agent_profile="",
                settings=settings,
            )
        )

    # AC-02: at least one canonical write must occur
    assert mock_write.call_count >= 1, "Expected at least one _vault_write call"
    canonical_call = mock_write.call_args_list[0]
    # Canonical path: plugin/{sanitized_plugin}/{sanitized_key}
    assert canonical_call.args[1] == "plugin/myplugin/api_key"  # AC-02: correct path
    assert canonical_call.args[2] == {"value": "s3cr3t-value"}  # AC-02: correct value
    # Settings replaced with placeholder
    assert settings["api_key"].startswith(surface_a._PLACEHOLDER_PREFIX)  # AC-02: placeholder written


# ---------------------------------------------------------------------------
# AC-03 — resolve: get_plugin_config resolves placeholder via manager.get_secret
# ---------------------------------------------------------------------------


def test_get_plugin_config_resolves_placeholder(surface_a):
    """AC-03: placeholder in settings → resolved via manager.get_secret(key,
    project_slug=project_slug) where project_slug = Path(project_name).name.
    """
    mock_manager = MagicMock()
    mock_manager.get_secret.return_value = "live-secret-value"

    # Build a valid placeholder that get_plugin_config will resolve
    placeholder = (
        surface_a._PLACEHOLDER_PREFIX
        + "plugin/myplugin/api_key"
        + surface_a._PLACEHOLDER_SUFFIX
    )
    settings = {"api_key": placeholder}

    with patch.object(surface_a, "_get_manager", return_value=mock_manager):
        result = asyncio.run(
            surface_a.get_plugin_config(
                plugin_name="myplugin",
                project_name="/projects/myproject",  # non-empty → project_slug='myproject'
                agent_profile="",
                settings=settings,
            )
        )

    # AC-03: resolved dict returned with live value
    assert result is not None, "get_plugin_config must return resolved dict"
    assert result["api_key"] == "live-secret-value"  # AC-03: live value resolved
    # AC-03: get_secret called with correct key and project_slug
    mock_manager.get_secret.assert_called_once_with("api_key", project_slug="myproject")


# ---------------------------------------------------------------------------
# AC-04 — idempotency: second save reuses canonical path, no new dedup write
# ---------------------------------------------------------------------------


def test_idempotency_no_duplicate_vault_entries(surface_a):
    """AC-04: saving the same field value twice:
    - First save : _vault_write called 2x (canonical + dedup index)
    - Second save: _vault_write called 1x (canonical reuse, NO new dedup entry)
    """
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True

    raw_value = "shared-api-secret"
    canonical_path = "plugin/myplugin/api_key"
    mock_write = MagicMock()

    # --- First save: no dedup record exists --------------------------------
    settings1 = {"api_key": raw_value}
    with (
        patch.object(surface_a, "_get_manager", return_value=mock_manager),
        patch.object(surface_a, "_vault_read", return_value=None),
        patch.object(surface_a, "_vault_write", mock_write),
        patch.object(surface_a, "_get_patterns", return_value=["*key*"]),
        patch.object(surface_a, "_sanitize_component", new=_sanitize),
    ):
        asyncio.run(
            surface_a.save_plugin_config(
                plugin_name="myplugin",
                project_name="",
                agent_profile="",
                settings=settings1,
            )
        )

    # AC-04: first save → canonical write + dedup index write = 2 total
    assert mock_write.call_count == 2, (
        f"First save: expected 2 writes (canonical + dedup), got {mock_write.call_count}"
    )

    # --- Second save: dedup record exists, canonical path reused -----------
    mock_write.reset_mock()
    dedup_record = {"canonical_path": canonical_path}
    settings2 = {"api_key": raw_value}  # same raw value — dedup should fire
    with (
        patch.object(surface_a, "_get_manager", return_value=mock_manager),
        patch.object(surface_a, "_vault_read", return_value=dedup_record),
        patch.object(surface_a, "_vault_write", mock_write),
        patch.object(surface_a, "_get_patterns", return_value=["*key*"]),
        patch.object(surface_a, "_sanitize_component", new=_sanitize),
    ):
        asyncio.run(
            surface_a.save_plugin_config(
                plugin_name="myplugin",
                project_name="",
                agent_profile="",
                settings=settings2,
            )
        )

    # AC-04: second save → canonical write only, NO new dedup write
    assert mock_write.call_count == 1, (
        f"Second save: expected 1 write (dedup reuse), got {mock_write.call_count}"
    )
    reused_path = mock_write.call_args_list[0].args[1]
    assert reused_path == canonical_path, (
        f"Expected canonical path {canonical_path!r} reused, got {reused_path!r}"
    )


# ---------------------------------------------------------------------------
# AC-05 — atomicity: vault write failure leaves settings dict unchanged
# ---------------------------------------------------------------------------


def test_atomicity_vault_write_failure_leaves_settings_unchanged(surface_a):
    """AC-05: if _vault_write raises, exception propagates and the settings
    dict is left completely unchanged (no partial placeholder substitution).
    """
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True

    settings = {"api_key": "secret-value"}
    original_settings = settings.copy()

    with (
        patch.object(surface_a, "_get_manager", return_value=mock_manager),
        patch.object(surface_a, "_vault_read", return_value=None),
        patch.object(
            surface_a, "_vault_write", side_effect=RuntimeError("vault unavailable")
        ),
        patch.object(surface_a, "_get_patterns", return_value=["*key*"]),
        patch.object(surface_a, "_sanitize_component", new=_sanitize),
    ):
        with pytest.raises(RuntimeError, match="vault unavailable"):  # AC-05: exception propagates
            asyncio.run(
                surface_a.save_plugin_config(
                    plugin_name="myplugin",
                    project_name="",
                    agent_profile="",
                    settings=settings,
                )
            )

    # AC-05: settings dict must be completely unchanged (atomic rollback)
    assert settings == original_settings, (
        f"Settings were mutated despite vault failure: {settings!r}"
    )


# ---------------------------------------------------------------------------
# AC-06a — non-matching field passes through unmodified, vault write never called
# ---------------------------------------------------------------------------


def test_nonmatching_field_passthrough_no_vault_write(surface_a):
    """AC-06a: field 'display_name' does not match any pattern in the default
    set → _vault_write never called, value left unchanged in settings.
    """
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True
    mock_write = MagicMock()

    settings = {"display_name": "My Plugin"}

    with (
        patch.object(surface_a, "_get_manager", return_value=mock_manager),
        patch.object(surface_a, "_vault_read", return_value=None),
        patch.object(surface_a, "_vault_write", mock_write),
        patch.object(surface_a, "_get_patterns", return_value=_DEFAULT_PATTERNS),
        patch.object(surface_a, "_sanitize_component", new=_sanitize),
    ):
        asyncio.run(
            surface_a.save_plugin_config(
                plugin_name="myplugin",
                project_name="",
                agent_profile="",
                settings=settings,
            )
        )

    # AC-06a: no vault write for non-matching field
    mock_write.assert_not_called()
    assert settings["display_name"] == "My Plugin"  # AC-06a: value unchanged


# ---------------------------------------------------------------------------
# AC-06b — ADR-02: own plugin name triggers early return before any vault call
# ---------------------------------------------------------------------------


def test_adr02_own_plugin_passthrough(surface_a):
    """AC-06b: plugin_name='deimos_openbao_secrets' → ADR-02 bootstrapping guard
    fires immediately; _get_manager and _vault_write are never called.
    """
    mock_write = MagicMock()
    settings = {"api_key": "some-secret"}

    with (
        patch.object(surface_a, "_get_manager") as mock_get_manager,
        patch.object(surface_a, "_vault_write", mock_write),
    ):
        asyncio.run(
            surface_a.save_plugin_config(
                plugin_name="deimos_openbao_secrets",  # AC-06b: own plugin name
                project_name="",
                agent_profile="",
                settings=settings,
            )
        )

    # AC-06b: ADR-02 guard fires before manager/vault interaction
    mock_get_manager.assert_not_called()  # AC-06b: early return before manager call
    mock_write.assert_not_called()         # AC-06b: vault write never called
    assert settings["api_key"] == "some-secret"  # AC-06b: settings unchanged


# ---------------------------------------------------------------------------
# AC-07a — unavailable noop: _get_manager() returns None
# ---------------------------------------------------------------------------


def test_unavailable_noop_manager_none(surface_a):
    """AC-07a: _get_manager() returns None → early return, _vault_write never
    called, settings left unchanged.
    """
    mock_write = MagicMock()
    settings = {"api_key": "some-secret"}

    with (
        patch.object(surface_a, "_get_manager", return_value=None),  # AC-07a: None manager
        patch.object(surface_a, "_vault_write", mock_write),
    ):
        asyncio.run(
            surface_a.save_plugin_config(
                plugin_name="myplugin",
                project_name="",
                agent_profile="",
                settings=settings,
            )
        )

    # AC-07a: manager None → graceful noop
    mock_write.assert_not_called()
    assert settings["api_key"] == "some-secret"


# ---------------------------------------------------------------------------
# AC-07b — unavailable noop: manager.is_available() returns False
# ---------------------------------------------------------------------------


def test_unavailable_noop_not_available(surface_a):
    """AC-07b: manager.is_available() returns False → early return,
    _vault_write never called, settings left unchanged.
    """
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = False  # AC-07b: OpenBao unavailable
    mock_write = MagicMock()
    settings = {"api_key": "some-secret"}

    with (
        patch.object(surface_a, "_get_manager", return_value=mock_manager),
        patch.object(surface_a, "_vault_write", mock_write),
    ):
        asyncio.run(
            surface_a.save_plugin_config(
                plugin_name="myplugin",
                project_name="",
                agent_profile="",
                settings=settings,
            )
        )

    # AC-07b: is_available() False → graceful noop
    mock_write.assert_not_called()
    assert settings["api_key"] == "some-secret"
