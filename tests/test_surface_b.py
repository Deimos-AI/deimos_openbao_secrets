"""test_surface_b.py — Test suite for Surface B (_10_openbao_mcp_scan.py).

Covers: MCP credential extraction, atomic rollback, idempotency, fnmatch pattern
matching, and unavailable-noop behaviour.

Satisfies: AC-01 (file creation), AC-02, AC-03, AC-04, AC-05, AC-06, AC-07
"""
import asyncio
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixture: load Surface B via importlib (A0 runtime not present in test env)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def surface_b():
    """Load Surface B module without A0 runtime dependencies.

    Injects helpers.extension and helpers.plugins stubs so the module can be
    imported without the full Agent Zero runtime.  Loaded once per session.

    Satisfies: AC-01
    """
    # --- helpers.extension stub (Extension base class) -------------------
    if "helpers.extension" not in sys.modules:
        helpers_ext = type(sys)("helpers.extension")

        class _StubExtension:
            pass

        helpers_ext.Extension = _StubExtension
        sys.modules["helpers.extension"] = helpers_ext

    # --- helpers.plugins stub (find_plugin_dir / get_plugin_config) ------
    if "helpers.plugins" not in sys.modules:
        mock_plugins = MagicMock()
        mock_plugins.find_plugin_dir.return_value = None
        sys.modules["helpers.plugins"] = mock_plugins

    plugin_root = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(
        plugin_root,
        "extensions",
        "python",
        "tool_execute_after",
        "_10_openbao_mcp_scan.py",
    )
    spec = importlib.util.spec_from_file_location("surface_b_module", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _sanitize(v: str) -> str:
    """Mirror of _sanitize_component fallback for expected-path assertions."""
    return re.sub(r"[^a-zA-Z0-9_.\-]", "_", v).lstrip(".")


# ---------------------------------------------------------------------------
# AC-01 — file exists: test file itself validates existence
# ---------------------------------------------------------------------------


def test_surface_b_file_exists():
    """AC-01: tests/test_surface_b.py is created and importable.

    The fact that pytest collects this test file proves its existence.

    Satisfies: AC-01
    """
    # AC-01: file name confirms this is the correct test file
    assert os.path.basename(__file__) == "test_surface_b.py"  # AC-01: file exists with correct name


# ---------------------------------------------------------------------------
# AC-02 — extraction: vault write called with correct path + value
# ---------------------------------------------------------------------------


def test_extraction_writes_credential_to_vault(surface_b):
    """AC-02: MCP settings with a header matching the credential detection pattern
    triggers a vault write (mocked); the written vault path and value dict are
    verified.  The file is replaced with a placeholder.

    Satisfies: AC-02
    """
    mock_manager = MagicMock()
    mock_write = MagicMock()

    mcp_data = {
        "mcpServers": {
            "my-server": {
                "command": "npx",
                "headers": {
                    "Authorization": "Bearer sk-real-secret-token",
                    "Content-Type": "application/json",
                },
            }
        }
    }

    with tempfile.NamedTemporaryFile(
        suffix=".json", mode="w", delete=False, encoding="utf-8"
    ) as f:
        json.dump(mcp_data, f)
        tmp_path = Path(f.name)

    try:
        with (
            patch.object(surface_b, "_vault_read", return_value=None),
            patch.object(surface_b, "_vault_write", mock_write),
            patch.object(
                surface_b,
                "_get_header_patterns",
                return_value=["Authorization", "*token*", "*key*"],
            ),
            patch.object(surface_b, "_sanitize_component", new=_sanitize),
        ):
            asyncio.run(surface_b._process_mcp_file(mock_manager, tmp_path))

        # AC-02: vault write must be called at least once
        assert mock_write.call_count >= 1, "Expected at least one _vault_write call"  # AC-02: vault write called

        # AC-02: first call uses canonical path mcp/{server}/{header}
        first_call = mock_write.call_args_list[0]
        assert first_call.args[1] == "mcp/my-server/Authorization"  # AC-02: correct canonical vault path
        assert first_call.args[2] == {"value": "Bearer sk-real-secret-token"}  # AC-02: correct value dict

        # AC-02: file now contains placeholder for the extracted credential
        updated = json.loads(tmp_path.read_text(encoding="utf-8"))
        header_val = updated["mcpServers"]["my-server"]["headers"]["Authorization"]
        assert header_val.startswith(surface_b._PLACEHOLDER_PREFIX)  # AC-02: placeholder prefix written back
        assert header_val.endswith(surface_b._PLACEHOLDER_SUFFIX)    # AC-02: placeholder suffix present
        assert "mcp/my-server/Authorization" in header_val            # AC-02: canonical path embedded in placeholder
    finally:
        tmp_path.unlink(missing_ok=True)
        Path(str(tmp_path) + ".tmp").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# AC-03 — atomic rollback: vault failure → original unchanged, .tmp deleted
# ---------------------------------------------------------------------------


def test_atomic_rollback_on_vault_failure(surface_b):
    """AC-03: If vault write fails mid-scan, the original MCP file is left
    unchanged and the .tmp staging file is deleted — no partial credential
    writes persist.

    Satisfies: AC-03
    """
    mcp_data = {
        "mcpServers": {
            "server-a": {
                "headers": {
                    "Authorization": "Bearer live-token-xyz",
                }
            }
        }
    }
    original_content = json.dumps(mcp_data, indent=2)

    with tempfile.NamedTemporaryFile(
        suffix=".json", mode="w", delete=False, encoding="utf-8"
    ) as f:
        f.write(original_content)
        tmp_path = Path(f.name)

    try:
        with (
            patch.object(surface_b, "_vault_read", return_value=None),
            patch.object(
                surface_b,
                "_vault_write",
                side_effect=RuntimeError("vault unavailable"),
            ),
            patch.object(
                surface_b, "_get_header_patterns", return_value=["Authorization"]
            ),
            patch.object(surface_b, "_sanitize_component", new=_sanitize),
        ):
            with pytest.raises(RuntimeError, match="vault unavailable"):
                asyncio.run(surface_b._process_mcp_file(MagicMock(), tmp_path))

        # AC-03: original file must be byte-identical after vault failure
        after_data = json.loads(tmp_path.read_text(encoding="utf-8"))
        assert after_data == json.loads(original_content)  # AC-03: original file unchanged after rollback

        # AC-03: .tmp staging file must be deleted (atomic rollback guarantee)
        dot_tmp = Path(str(tmp_path) + ".tmp")
        assert not dot_tmp.exists()  # AC-03: .tmp deleted on vault failure
    finally:
        tmp_path.unlink(missing_ok=True)
        Path(str(tmp_path) + ".tmp").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# AC-04 — idempotency: second scan skips; vault write count unchanged
# ---------------------------------------------------------------------------


def test_idempotency_second_scan_no_extra_write(surface_b):
    """AC-04: Running the scan twice on the same MCP file results in exactly
    one round of vault writes — the placeholder already present on the second
    scan triggers an early skip via the idempotency guard (_IDEMPOTENCY_PREFIX).

    Satisfies: AC-04
    """
    mock_manager = MagicMock()
    mock_write = MagicMock()

    mcp_data = {
        "mcpServers": {
            "my-server": {
                "headers": {
                    "Authorization": "Bearer secret-token-abc",
                }
            }
        }
    }

    with tempfile.NamedTemporaryFile(
        suffix=".json", mode="w", delete=False, encoding="utf-8"
    ) as f:
        json.dump(mcp_data, f)
        tmp_path = Path(f.name)

    try:
        with (
            patch.object(surface_b, "_vault_read", return_value=None),
            patch.object(surface_b, "_vault_write", mock_write),
            patch.object(
                surface_b, "_get_header_patterns", return_value=["Authorization"]
            ),
            patch.object(surface_b, "_sanitize_component", new=_sanitize),
        ):
            # First scan: live credential → vault write occurs, file updated
            asyncio.run(surface_b._process_mcp_file(mock_manager, tmp_path))
            write_count_first = mock_write.call_count
            assert write_count_first >= 1  # AC-04: first scan writes to vault

            # Second scan: file now has placeholder — idempotency guard must fire
            asyncio.run(surface_b._process_mcp_file(mock_manager, tmp_path))
            write_count_second = mock_write.call_count

        # AC-04: second scan adds NO new vault writes (guard fired, pending empty)
        assert write_count_second == write_count_first  # AC-04: idempotency — no new writes on second scan
    finally:
        tmp_path.unlink(missing_ok=True)
        Path(str(tmp_path) + ".tmp").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# AC-05 — fnmatch: matching header detected, non-matching header skipped
# ---------------------------------------------------------------------------


def test_fnmatch_exact_match_detected_non_match_skipped(surface_b):
    """AC-05: Header field name matching the configured exact pattern is
    detected and scanned; a non-matching field name is skipped without a
    vault write.

    Satisfies: AC-05
    """
    mock_write = MagicMock()

    mcp_data = {
        "mcpServers": {
            "server1": {
                "headers": {
                    "Authorization": "Bearer secret",    # matches "Authorization"
                    "Content-Type": "application/json",  # does NOT match
                }
            }
        }
    }

    with tempfile.NamedTemporaryFile(
        suffix=".json", mode="w", delete=False, encoding="utf-8"
    ) as f:
        json.dump(mcp_data, f)
        tmp_path = Path(f.name)

    try:
        with (
            patch.object(surface_b, "_vault_read", return_value=None),
            patch.object(surface_b, "_vault_write", mock_write),
            patch.object(
                surface_b, "_get_header_patterns", return_value=["Authorization"]
            ),
            patch.object(surface_b, "_sanitize_component", new=_sanitize),
        ):
            asyncio.run(surface_b._process_mcp_file(MagicMock(), tmp_path))

        written_paths = [c.args[1] for c in mock_write.call_args_list]
        assert any("Authorization" in p for p in written_paths)  # AC-05: matching header detected and written
        assert not any(
            "Content-Type" in p or "Content_Type" in p for p in written_paths
        )  # AC-05: non-matching header skipped — no vault write
    finally:
        tmp_path.unlink(missing_ok=True)
        Path(str(tmp_path) + ".tmp").unlink(missing_ok=True)


def test_fnmatch_glob_pattern_matches_token_header(surface_b):
    """AC-05: Glob pattern *token* matches headers containing 'token' anywhere
    in the name; headers with no token substring are skipped without a
    vault write.

    Satisfies: AC-05
    """
    mock_write = MagicMock()

    mcp_data = {
        "mcpServers": {
            "server1": {
                "headers": {
                    "X-Auth-Token": "my-secret-token-value",  # matches *token*
                    "X-Request-ID": "12345",                  # no match
                }
            }
        }
    }

    with tempfile.NamedTemporaryFile(
        suffix=".json", mode="w", delete=False, encoding="utf-8"
    ) as f:
        json.dump(mcp_data, f)
        tmp_path = Path(f.name)

    try:
        with (
            patch.object(surface_b, "_vault_read", return_value=None),
            patch.object(surface_b, "_vault_write", mock_write),
            patch.object(
                surface_b, "_get_header_patterns", return_value=["*token*"]
            ),
            patch.object(surface_b, "_sanitize_component", new=_sanitize),
        ):
            asyncio.run(surface_b._process_mcp_file(MagicMock(), tmp_path))

        written_paths = [c.args[1] for c in mock_write.call_args_list]
        # AC-05: *token* glob matched X-Auth-Token (path contains sanitized header name)
        assert any("Token" in p or "token" in p for p in written_paths)  # AC-05: *token* glob matched X-Auth-Token
        assert not any("Request" in p or "ID" in p for p in written_paths)  # AC-05: X-Request-ID skipped
    finally:
        tmp_path.unlink(missing_ok=True)
        Path(str(tmp_path) + ".tmp").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# AC-06 — unavailable noop: _get_manager() None → execute() returns early
# ---------------------------------------------------------------------------


def test_execute_noop_when_manager_unavailable(surface_b):
    """AC-06: When _get_manager() returns None, execute() returns immediately
    without processing any file or calling _vault_write.

    Satisfies: AC-06
    """
    mock_write = MagicMock()

    with (
        patch.object(surface_b, "_get_manager", return_value=None),
        patch.object(surface_b, "_vault_write", mock_write),
    ):
        extension = surface_b.OpenBaoMcpScan()
        asyncio.run(
            extension.execute(
                tool_name="text_editor:write",
                tool=None,
                path="/any/path/mcp_servers.json",
            )
        )

    # AC-06: no vault writes when manager is unavailable
    assert mock_write.call_count == 0  # AC-06: noop — 0 vault writes when _get_manager() returns None


def test_execute_noop_for_non_write_tool(surface_b):
    """AC-06 (guard variant): execute() returns immediately for tool names not
    in _WRITE_OPS without reaching vault logic.

    Satisfies: AC-06
    """
    mock_write = MagicMock()
    mock_manager = MagicMock()
    mock_manager.is_available.return_value = True

    with (
        patch.object(surface_b, "_get_manager", return_value=mock_manager),
        patch.object(surface_b, "_vault_write", mock_write),
    ):
        extension = surface_b.OpenBaoMcpScan()
        asyncio.run(
            extension.execute(
                tool_name="code_execution_tool",  # not in _WRITE_OPS
                tool=None,
            )
        )

    # AC-06: tool_name guard fires before vault logic — no vault writes
    assert mock_write.call_count == 0  # AC-06: non-write tool names are skipped immediately
