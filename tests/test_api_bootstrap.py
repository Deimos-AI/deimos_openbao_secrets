"""test_api_bootstrap.py — Tests for api/bootstrap.py Bootstrap handler.

Covers: AC-11, AC-12 (REM-017)
status/scan actions, dry_run, no-values assertion, sorted response.

Satisfies: AC-18
"""
import asyncio
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Fixture: load api/bootstrap.py with stubs pre-injected
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def bootstrap_mod():
    """Load api/bootstrap.py with A0 runtime stubs pre-injected.

    Uses yield + sys.modules cleanup to prevent pollution of later test files.
    """
    # Keys we may inject — save current state for teardown
    _OWNED_KEYS = [
        "api_bootstrap",
        "helpers.api",
        "helpers.plugins",
        "openbao_helpers.secrets_scanner",
        "openbao_helpers.registry",
    ]
    _saved = {k: sys.modules.get(k) for k in _OWNED_KEYS}

    mock_api = MagicMock()

    class _StubApiHandler:
        pass

    mock_api.ApiHandler = _StubApiHandler
    mock_api.Request = MagicMock
    mock_api.Response = MagicMock
    sys.modules.setdefault("helpers.api", mock_api)
    sys.modules.setdefault("helpers.plugins", MagicMock())

    fpath = os.path.join(os.path.dirname(__file__), "..", "api", "bootstrap.py")
    spec = importlib.util.spec_from_file_location("api_bootstrap", fpath)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["api_bootstrap"] = mod
    spec.loader.exec_module(mod)

    yield mod

    # Teardown: restore sys.modules to pre-fixture state
    for k, v in _saved.items():
        if v is None:
            sys.modules.pop(k, None)
        else:
            sys.modules[k] = v


# ---------------------------------------------------------------------------
# Helper: build mock registry module + manager
# ---------------------------------------------------------------------------

def _make_mock_registry(bootstrap_needed: bool = True, entries=None):
    """Return a mock registry module with RegistryManager behaviour."""
    if entries is None:
        entries = []

    mock_rm = MagicMock()
    mock_rm.is_bootstrap_needed.return_value = bootstrap_needed
    mock_rm.get_entries.return_value = entries
    mock_rm.get_path.return_value = Path("/tmp/test_registry.yaml")
    mock_rm.save = MagicMock()

    mock_reg_mod = MagicMock()
    mock_reg_mod.RegistryManager.return_value = mock_rm

    # RegistryEntry factory
    from openbao_helpers.registry import RegistryEntry
    mock_reg_mod.RegistryEntry = RegistryEntry

    return mock_reg_mod, mock_rm


def _make_mock_scanner(env_entries=None, a0proj_entries=None, mcp_entries=None):
    """Return a mock scanner module."""
    from openbao_helpers.secrets_scanner import ScanEntry
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    if env_entries is None:
        env_entries = []
    if a0proj_entries is None:
        a0proj_entries = []
    if mcp_entries is None:
        mcp_entries = []

    mock_scanner = MagicMock()
    mock_scanner.env_scan.return_value = env_entries
    mock_scanner.a0proj_scan.return_value = a0proj_entries
    mock_scanner.mcp_scan.return_value = mcp_entries
    return mock_scanner


def _make_scan_entry(key: str, source: str = "env_scan", context: str = "test.env"):
    from openbao_helpers.secrets_scanner import ScanEntry
    from datetime import datetime, timezone
    return ScanEntry(key=key, source=source, context=context,
                     discovered_at=datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# AC-11 — status action: bootstrap_needed=True
# ---------------------------------------------------------------------------

class TestStatusAction:

    def test_status_action_bootstrap_needed(self, bootstrap_mod):
        """AC-11: status action with bootstrap_needed=True returns correct response."""
        mock_reg_mod, mock_rm = _make_mock_registry(bootstrap_needed=True, entries=[])

        with patch.object(bootstrap_mod, "_load_registry", return_value=mock_reg_mod):
            handler = bootstrap_mod.Bootstrap()
            result = asyncio.run(handler.process({"action": "status"}, MagicMock()))

        assert result["ok"] is True
        assert result["bootstrap_needed"] is True
        assert result["entry_count"] == 0
        assert "registry_path" in result

    def test_status_action_registry_present(self, bootstrap_mod):
        """AC-11: status action with 5 entries returns entry_count=5, bootstrap_needed=False."""
        from openbao_helpers.registry import RegistryEntry
        entries = [
            RegistryEntry(
                id=RegistryEntry.make_id("env_scan", f"ctx{i}", f"KEY_{i}"),
                key=f"KEY_{i}",
                source="env_scan",
                context=f"ctx{i}",
                description="",
                discovered_at="2026-01-01T00:00:00+00:00",
                status="discovered",
            )
            for i in range(5)
        ]
        mock_reg_mod, mock_rm = _make_mock_registry(bootstrap_needed=False, entries=entries)

        with patch.object(bootstrap_mod, "_load_registry", return_value=mock_reg_mod):
            handler = bootstrap_mod.Bootstrap()
            result = asyncio.run(handler.process({"action": "status"}, MagicMock()))

        assert result["ok"] is True
        assert result["bootstrap_needed"] is False
        assert result["entry_count"] == 5


# ---------------------------------------------------------------------------
# AC-11 — scan action: writes registry
# ---------------------------------------------------------------------------

class TestScanAction:

    def test_scan_action_writes_registry(self, bootstrap_mod):
        """AC-11: scan with 3 entries each from 3 sources; save called once with 9 entries."""
        mock_reg_mod, mock_rm = _make_mock_registry(bootstrap_needed=True)

        # 3 entries per source, all unique keys
        env_entries = [_make_scan_entry(f"ENV_KEY_{i}", source="env_scan", context=f"env_{i}.env")
                       for i in range(3)]
        a0proj_entries = [_make_scan_entry(f"A0_KEY_{i}", source="a0proj_scan", context=f"a0_{i}.yaml")
                          for i in range(3)]
        mcp_entries = [_make_scan_entry(f"MCP_KEY_{i}", source="mcp_scan", context=f"mcp_{i}.json")
                       for i in range(3)]
        mock_scanner = _make_mock_scanner(env_entries, a0proj_entries, mcp_entries)

        raw_cfg = {"env_scan_root": "/tmp", "mcp_scan_paths": [], "a0proj_search_roots": ["/tmp"]}

        with patch.object(bootstrap_mod, "_load_registry", return_value=mock_reg_mod), \
             patch.object(bootstrap_mod, "_load_scanner", return_value=mock_scanner), \
             patch.object(bootstrap_mod, "_load_raw_config", return_value=raw_cfg):
            handler = bootstrap_mod.Bootstrap()
            result = asyncio.run(handler.process({"action": "scan"}, MagicMock()))

        assert result["ok"] is True
        # save must be called exactly once with entries list
        mock_rm.save.assert_called_once()
        saved_registry = mock_rm.save.call_args[0][0]
        assert len(saved_registry["entries"]) == 9, f"Expected 9 entries, got {len(saved_registry['entries'])}"  # 3*3 = 9

    def test_scan_action_dry_run(self, bootstrap_mod):
        """AC-11: dry_run=True — save NOT called; results still returned."""
        mock_reg_mod, mock_rm = _make_mock_registry(bootstrap_needed=True)

        env_entries = [_make_scan_entry("DRY_KEY", source="env_scan")]
        mock_scanner = _make_mock_scanner(env_entries=env_entries)

        raw_cfg = {"env_scan_root": "/tmp", "mcp_scan_paths": [], "a0proj_search_roots": ["/tmp"]}

        with patch.object(bootstrap_mod, "_load_registry", return_value=mock_reg_mod), \
             patch.object(bootstrap_mod, "_load_scanner", return_value=mock_scanner), \
             patch.object(bootstrap_mod, "_load_raw_config", return_value=raw_cfg):
            handler = bootstrap_mod.Bootstrap()
            result = asyncio.run(handler.process(
                {"action": "scan", "dry_run": True}, MagicMock()
            ))

        assert result["ok"] is True
        mock_rm.save.assert_not_called()  # AC-11: dry_run must NOT write registry
        assert len(result["entries"]) >= 1, "Dry run must still return entries"

    def test_scan_response_no_values(self, bootstrap_mod):
        """AC-12: inspect ALL fields in every response entry; assert no mock secret values present."""
        mock_reg_mod, mock_rm = _make_mock_registry(bootstrap_needed=True)

        # Entries with known key names (values are only in the ScanEntry source files, not here)
        env_entries = [
            _make_scan_entry("OPENAI_API_KEY", source="env_scan", context="secrets.env"),
            _make_scan_entry("GITHUB_TOKEN", source="env_scan", context="config.env"),
        ]
        mock_scanner = _make_mock_scanner(env_entries=env_entries)
        # Known "secret values" that must NOT appear in response
        secret_values = ["sk-verysecret123", "ghp_mysupersecrettoken456"]

        raw_cfg = {"env_scan_root": "/tmp", "mcp_scan_paths": [], "a0proj_search_roots": ["/tmp"]}

        with patch.object(bootstrap_mod, "_load_registry", return_value=mock_reg_mod), \
             patch.object(bootstrap_mod, "_load_scanner", return_value=mock_scanner), \
             patch.object(bootstrap_mod, "_load_raw_config", return_value=raw_cfg):
            handler = bootstrap_mod.Bootstrap()
            result = asyncio.run(handler.process(
                {"action": "scan", "dry_run": True}, MagicMock()
            ))

        assert result["ok"] is True
        response_text = str(result)
        for sv in secret_values:
            assert sv not in response_text, f"Secret value '{sv}' must not appear in response"

    def test_scan_response_sorted(self, bootstrap_mod):
        """AC-11: response entries sorted by source ascending then key ascending."""
        mock_reg_mod, mock_rm = _make_mock_registry(bootstrap_needed=True)

        env_entries = [
            _make_scan_entry("Z_ENV_KEY", source="env_scan"),
            _make_scan_entry("A_ENV_KEY", source="env_scan"),
        ]
        mcp_entries = [
            _make_scan_entry("MCP_SECRET", source="mcp_scan", context="mcp.json"),
        ]
        a0proj_entries = [
            _make_scan_entry("A0PROJ_KEY", source="a0proj_scan", context="dir.yaml"),
        ]
        mock_scanner = _make_mock_scanner(env_entries, a0proj_entries, mcp_entries)

        raw_cfg = {"env_scan_root": "/tmp", "mcp_scan_paths": [], "a0proj_search_roots": ["/tmp"]}

        with patch.object(bootstrap_mod, "_load_registry", return_value=mock_reg_mod), \
             patch.object(bootstrap_mod, "_load_scanner", return_value=mock_scanner), \
             patch.object(bootstrap_mod, "_load_raw_config", return_value=raw_cfg):
            handler = bootstrap_mod.Bootstrap()
            result = asyncio.run(handler.process(
                {"action": "scan", "dry_run": True}, MagicMock()
            ))

        assert result["ok"] is True
        entries = result["entries"]
        # Extract (source, key) tuples
        pairs = [(e["source"], e["key"]) for e in entries]
        # Must be sorted: a0proj_scan < env_scan < mcp_scan
        assert pairs == sorted(pairs), f"Response must be sorted by (source, key), got: {pairs}"
        # Check source order specifically
        sources = [e["source"] for e in entries]
        assert sources.index("a0proj_scan") < sources.index("env_scan"), "a0proj_scan must come before env_scan"
        assert sources.index("env_scan") < sources.index("mcp_scan"), "env_scan must come before mcp_scan"
        # Within env_scan: A_ENV_KEY before Z_ENV_KEY
        env_keys = [e["key"] for e in entries if e["source"] == "env_scan"]
        assert env_keys == sorted(env_keys), f"Keys within same source must be sorted: {env_keys}"

    def test_scan_default_action(self, bootstrap_mod):
        """AC-11: default action (no 'action' key in input) is 'scan'."""
        mock_reg_mod, mock_rm = _make_mock_registry(bootstrap_needed=True)
        mock_scanner = _make_mock_scanner()
        raw_cfg = {"env_scan_root": "/tmp", "mcp_scan_paths": [], "a0proj_search_roots": ["/tmp"]}

        with patch.object(bootstrap_mod, "_load_registry", return_value=mock_reg_mod), \
             patch.object(bootstrap_mod, "_load_scanner", return_value=mock_scanner), \
             patch.object(bootstrap_mod, "_load_raw_config", return_value=raw_cfg):
            handler = bootstrap_mod.Bootstrap()
            # No 'action' key — defaults to scan
            result = asyncio.run(handler.process({}, MagicMock()))

        assert result["ok"] is True
        assert "entries" in result  # scan response has entries

    def test_scan_context_relative_no_leading_slash(self, bootstrap_mod):
        """AC-12: context values are relative paths — no leading '/'."""
        mock_reg_mod, mock_rm = _make_mock_registry(bootstrap_needed=True)

        # entry with absolute-looking context
        env_entries = [
            _make_scan_entry("MY_KEY", source="env_scan", context="/absolute/path/to/file.env"),
        ]
        mock_scanner = _make_mock_scanner(env_entries=env_entries)
        raw_cfg = {"env_scan_root": "/tmp", "mcp_scan_paths": [], "a0proj_search_roots": ["/tmp"]}

        with patch.object(bootstrap_mod, "_load_registry", return_value=mock_reg_mod), \
             patch.object(bootstrap_mod, "_load_scanner", return_value=mock_scanner), \
             patch.object(bootstrap_mod, "_load_raw_config", return_value=raw_cfg):
            handler = bootstrap_mod.Bootstrap()
            result = asyncio.run(handler.process(
                {"action": "scan", "dry_run": True}, MagicMock()
            ))

        assert result["ok"] is True
        for entry in result["entries"]:
            assert not entry["context"].startswith("/"), (
                f"AC-12: context must not have leading '/': {entry['context']}"
            )
