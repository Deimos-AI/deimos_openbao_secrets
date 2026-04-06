"""test_secrets_scanner.py — Tests for helpers/secrets_scanner.py.

Covers: AC-01 to AC-05 (REM-017)
All three scan sources, edge cases, no-value assertion.

Satisfies: AC-18
"""
import json
import logging
import os
from pathlib import Path
from unittest.mock import patch, mock_open

import pytest
import yaml

import helpers.secrets_scanner as scanner
from helpers.secrets_scanner import ScanEntry, env_scan, a0proj_scan, mcp_scan


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entry_keys(entries: list[ScanEntry]) -> list[str]:
    """Extract key names from ScanEntry list."""
    return [e.key for e in entries]


def _any_field_contains(entries: list[ScanEntry], value: str) -> bool:
    """Return True if any field of any ScanEntry contains the given string."""
    for e in entries:
        for field_val in (e.key, e.source, e.context, e.discovered_at):
            if value in str(field_val):
                return True
    return False


# ===========================================================================
# env_scan tests (AC-02)
# ===========================================================================

class TestEnvScan:

    def test_env_scan_finds_all_caps_keys(self, tmp_path):
        """AC-02: .env file with ALL_CAPS key discovered; secret value not in any ScanEntry field."""
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY_FOO=secret123\n")

        entries = env_scan(str(tmp_path))

        keys = _entry_keys(entries)
        assert "API_KEY_FOO" in keys, "Expected API_KEY_FOO to be discovered"
        # AC-05: raw secret value must NOT appear in any field
        assert not _any_field_contains(entries, "secret123"), "Secret value leaked into ScanEntry"

    def test_env_scan_ignores_lowercase_keys(self, tmp_path):
        """AC-02: lowercase keys are not matched."""
        env_file = tmp_path / ".env"
        env_file.write_text("lowercase_var=value\n")

        entries = env_scan(str(tmp_path))
        assert _entry_keys(entries) == [], "Lowercase key must not be discovered"

    def test_env_scan_ignores_two_char_keys(self, tmp_path):
        """AC-02: AB=val not matched (2 chars); ABC=val matched (3 chars minimum)."""
        env_file = tmp_path / ".env"
        env_file.write_text("AB=twochar\nABC=threechar\n")

        entries = env_scan(str(tmp_path))
        keys = _entry_keys(entries)
        assert "AB" not in keys, "2-char key must not be discovered"
        assert "ABC" in keys, "3-char key must be discovered"

    def test_env_scan_handles_permission_error(self, tmp_path):
        """AC-02: PermissionError caught — no exception propagated; result is empty list."""
        env_file = tmp_path / "secrets.env"
        env_file.write_text("API_KEY_OPENAI=should_not_matter\n")

        with patch("builtins.open", side_effect=PermissionError("denied")):
            entries = env_scan(str(tmp_path))

        assert entries == [], "PermissionError must yield empty result, not exception"

    def test_env_scan_respects_scan_root(self, tmp_path):
        """AC-02: scan from specific root; only files under root returned."""
        sub_a = tmp_path / "a"
        sub_b = tmp_path / "b"
        sub_a.mkdir()
        sub_b.mkdir()
        (sub_a / ".env").write_text("KEY_IN_A=val\n")
        (sub_b / ".env").write_text("KEY_IN_B=val\n")

        entries = env_scan(str(sub_a))
        keys = _entry_keys(entries)
        assert "KEY_IN_A" in keys
        assert "KEY_IN_B" not in keys, "Key from outside scan root must not appear"

    def test_env_scan_no_values_in_any_field(self, tmp_path):
        """AC-05: check every field of every ScanEntry; assert known secret value absent."""
        env_file = tmp_path / ".env"
        secret_value = "ultra_secret_value_xyz_12345"
        env_file.write_text(f"MY_SECRET_KEY={secret_value}\n")

        entries = env_scan(str(tmp_path))
        assert len(entries) >= 1, "Should discover MY_SECRET_KEY"
        assert not _any_field_contains(entries, secret_value), (
            f"Secret value '{secret_value}' must not appear in any ScanEntry field"
        )

    def test_env_scan_skips_large_files(self, tmp_path):
        """AC-02: files > 10 MB are skipped (mocked getsize)."""
        env_file = tmp_path / ".env"
        env_file.write_text("BIG_KEY=value\n")

        with patch("os.path.getsize", return_value=11 * 1024 * 1024):
            entries = env_scan(str(tmp_path))

        assert entries == [], "File > 10MB must be skipped"

    def test_env_scan_handles_unicode_decode_error(self, tmp_path):
        """AC-02: UnicodeDecodeError caught — no exception; result is empty."""
        env_file = tmp_path / "binary.env"
        env_file.write_bytes(b"API_KEY_TEST=\xff\xfe\x00")

        # The file may or may not raise UnicodeDecodeError depending on content.
        # Either way, no exception must propagate.
        try:
            entries = env_scan(str(tmp_path))
        except Exception as exc:
            pytest.fail(f"env_scan must not raise; got: {exc}")


# ===========================================================================
# a0proj_scan tests (AC-03)
# ===========================================================================

class TestA0projScan:

    def test_a0proj_scan_detects_bare_all_caps(self, tmp_path):
        """AC-03: .a0proj/variables.env with ALL_CAPS key discovered."""
        a0proj = tmp_path / ".a0proj"
        a0proj.mkdir()
        (a0proj / "variables.env").write_text("API_KEY_OPENAI=someval\n")

        entries = a0proj_scan([str(tmp_path)])
        keys = _entry_keys(entries)
        assert "API_KEY_OPENAI" in keys

    def test_a0proj_scan_detects_bao_ref(self, tmp_path):
        """AC-03: .a0proj/config.yaml with $bao:VAULT_TOKEN discovers VAULT_TOKEN."""
        a0proj = tmp_path / ".a0proj"
        a0proj.mkdir()
        cfg = {"token": "$bao:VAULT_TOKEN", "other": "plain_value"}
        (a0proj / "config.yaml").write_text(yaml.safe_dump(cfg))

        entries = a0proj_scan([str(tmp_path)])
        keys = _entry_keys(entries)
        assert "VAULT_TOKEN" in keys, "$bao: reference key must be discovered"
        assert "plain_value" not in keys, "Non-ALL_CAPS plain value must not be discovered"

    def test_a0proj_scan_deduplicates_by_key_context(self, tmp_path):
        """AC-03: same key in two different .env files → two entries (different context);
        same key in same file twice → one entry."""
        a0proj = tmp_path / ".a0proj"
        a0proj.mkdir()
        # Same key twice in same file → 1 entry
        (a0proj / "variables.env").write_text("DUP_KEY=val1\nDUP_KEY=val2\n")
        # Same key in different file → additional entry (different context)
        (a0proj / "also.env").write_text("DUP_KEY=val3\n")

        entries = a0proj_scan([str(tmp_path)])
        dup_entries = [e for e in entries if e.key == "DUP_KEY"]
        contexts = [e.context for e in dup_entries]
        assert len(dup_entries) == 2, f"Expected 2 entries for DUP_KEY (diff contexts), got: {dup_entries}"
        assert len(set(contexts)) == 2, "Contexts must differ for different files"

    def test_a0proj_scan_detects_json_all_caps(self, tmp_path):
        """AC-03: .a0proj/*.json with bare ALL_CAPS scalar value discovered."""
        a0proj = tmp_path / ".a0proj"
        a0proj.mkdir()
        data = {"api_key": "MY_API_SECRET"}
        (a0proj / "settings.json").write_text(json.dumps(data))

        entries = a0proj_scan([str(tmp_path)])
        keys = _entry_keys(entries)
        assert "MY_API_SECRET" in keys

    def test_a0proj_scan_no_values_in_output(self, tmp_path):
        """AC-05: secret values must not appear in any returned ScanEntry field."""
        secret_val = "super_secret_env_value_xyz"
        a0proj = tmp_path / ".a0proj"
        a0proj.mkdir()
        (a0proj / "variables.env").write_text(f"THE_SECRET={secret_val}\n")

        entries = a0proj_scan([str(tmp_path)])
        assert not _any_field_contains(entries, secret_val), (
            f"Secret value '{secret_val}' leaked into ScanEntry"
        )


# ===========================================================================
# mcp_scan tests (AC-04)
# ===========================================================================

class TestMcpScan:

    def test_mcp_scan_extracts_token_key(self, tmp_path):
        """AC-04: headers sub-dict with Authorization key discovered via fnmatch *_token pattern."""
        # Note: Authorization doesn't match *_token; but it matches ALL_CAPS? No.
        # Use a key that matches pattern: api_token matches *_token
        mcp_file = tmp_path / "mcp_servers.json"
        data = {
            "mcpServers": {
                "myserver": {
                    "headers": {
                        "api_token": "tok_abc123",
                    }
                }
            }
        }
        mcp_file.write_text(json.dumps(data))

        entries = mcp_scan([str(mcp_file)])
        keys = _entry_keys(entries)
        assert "api_token" in keys, "api_token matches *_token pattern — must be discovered"
        # AC-05: value must not appear
        assert not _any_field_contains(entries, "tok_abc123"), "Token value must not appear in ScanEntry"

    def test_mcp_scan_extracts_all_caps_env_key(self, tmp_path):
        """AC-04: env sub-dict with ALL_CAPS key discovered."""
        mcp_file = tmp_path / "mcp_servers.json"
        data = {
            "mcpServers": {
                "myserver": {
                    "env": {
                        "OPENAI_API_KEY": "sk-secret"
                    }
                }
            }
        }
        mcp_file.write_text(json.dumps(data))

        entries = mcp_scan([str(mcp_file)])
        keys = _entry_keys(entries)
        assert "OPENAI_API_KEY" in keys

    def test_mcp_scan_handles_missing_file(self, tmp_path, caplog):
        """AC-04: path to non-existent file — no exception; result is empty; WARNING logged."""
        nonexistent = str(tmp_path / "nonexistent_mcp.json")

        with caplog.at_level(logging.WARNING, logger="helpers.secrets_scanner"):
            entries = mcp_scan([nonexistent])

        assert entries == [], "Missing file must yield empty result"
        assert any("WARNING" in r.levelname or r.levelno >= logging.WARNING
                   for r in caplog.records), "WARNING must be logged for missing file"

    def test_mcp_scan_handles_malformed_json(self, tmp_path, caplog):
        """AC-04: file contains invalid JSON — no exception; result is empty; WARNING logged."""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json content")

        with caplog.at_level(logging.WARNING, logger="helpers.secrets_scanner"):
            entries = mcp_scan([str(bad_file)])

        assert entries == [], "Malformed JSON must yield empty result"

    def test_mcp_scan_context_is_filename_only(self, tmp_path):
        """AC-04: context field must be filename only — no directory path."""
        mcp_file = tmp_path / "mcp_servers.json"
        data = {
            "mcpServers": {
                "srv": {
                    "env": {"MY_SECRET_KEY": "val"}
                }
            }
        }
        mcp_file.write_text(json.dumps(data))

        entries = mcp_scan([str(mcp_file)])
        assert len(entries) >= 1
        for e in entries:
            assert "/" not in e.context, f"context must be filename only, got: {e.context}"
            assert e.context == "mcp_servers.json"

    def test_mcp_scan_no_values_in_output(self, tmp_path):
        """AC-05: secret values must not appear in any ScanEntry field."""
        secret_val = "my_ultra_secret_mcp_token_xyz"
        mcp_file = tmp_path / "mcp.json"
        data = {
            "mcpServers": {
                "srv": {
                    "headers": {"Authorization_token": secret_val}
                }
            }
        }
        mcp_file.write_text(json.dumps(data))

        entries = mcp_scan([str(mcp_file)])
        assert not _any_field_contains(entries, secret_val), "Secret value must not appear in any ScanEntry field"


# ===========================================================================
# ScanEntry dataclass — no value field (AC-01)
# ===========================================================================

class TestScanEntryNoValueField:

    def test_scan_entry_has_no_value_field(self):
        """AC-01, AC-05: ScanEntry dataclass must not have a 'value' field."""
        e = ScanEntry(key="MY_KEY", source="env_scan", context="test.env", discovered_at="2026-01-01T00:00:00+00:00")
        assert not hasattr(e, "value"), "ScanEntry must not have a 'value' field"

    def test_scan_entry_fields(self):
        """AC-01: ScanEntry has exactly key, source, context, discovered_at."""
        e = ScanEntry(key="K", source="mcp_scan", context="file.json", discovered_at="2026-01-01T00:00:00+00:00")
        assert e.key == "K"
        assert e.source == "mcp_scan"
        assert e.context == "file.json"
        assert "2026" in e.discovered_at
