"""test_vault_io_write_if_absent.py — Tests for vault_io.write_if_absent().

Covers: AC-01 — write_if_absent idempotency semantics.

Satisfies: AC-01 (file creation + 4 test cases)
"""
import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixture: load vault_io via importlib (no A0 runtime needed — stdlib only)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def vio_mod():
    """Load helpers/vault_io.py directly via importlib — no stubs required."""
    path = os.path.join(os.path.dirname(__file__), "..", "openbao_helpers", "vault_io.py")
    spec = importlib.util.spec_from_file_location("test_vault_io", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# AC-01 tests
# ---------------------------------------------------------------------------

def test_write_if_absent_key_absent_writes_and_returns_true(vio_mod):
    """AC-01: key absent → writes merged data, returns True."""
    mock_manager = MagicMock()
    existing = {"OTHER_KEY": "existing-value"}

    with patch.object(vio_mod, "_vault_read", return_value=dict(existing)), \
         patch.object(vio_mod, "_vault_write") as mock_write:
        result = vio_mod.write_if_absent(mock_manager, "agentzero/my-plugin", "API_KEY", "sk-test")

    assert result is True                                        # AC-01: returns True when written
    mock_write.assert_called_once()                              # AC-01: write called
    written_data = mock_write.call_args[0][2]                    # positional arg: data dict
    assert written_data["API_KEY"] == "sk-test"                  # AC-01: new key present
    assert written_data["OTHER_KEY"] == "existing-value"         # AC-01: existing keys preserved


def test_write_if_absent_key_present_skips_and_returns_false(vio_mod):
    """AC-01: key already present → no write, returns False (idempotent)."""
    mock_manager = MagicMock()
    existing = {"API_KEY": "original-value"}

    with patch.object(vio_mod, "_vault_read", return_value=dict(existing)), \
         patch.object(vio_mod, "_vault_write") as mock_write:
        result = vio_mod.write_if_absent(mock_manager, "agentzero/my-plugin", "API_KEY", "new-val")

    assert result is False          # AC-01: returns False when key exists
    mock_write.assert_not_called()  # AC-01: no write on existing key


def test_write_if_absent_empty_existing_data(vio_mod):
    """AC-01: path exists but returns empty dict → treated as absent, writes."""
    mock_manager = MagicMock()

    with patch.object(vio_mod, "_vault_read", return_value={}), \
         patch.object(vio_mod, "_vault_write") as mock_write:
        result = vio_mod.write_if_absent(mock_manager, "agentzero/my-plugin", "DB_PASS", "hunter2")

    assert result is True           # AC-01: writes when path empty
    mock_write.assert_called_once() # AC-01: write called


def test_write_if_absent_vault_path_miss_treated_as_empty(vio_mod):
    """AC-01: _vault_read returns None (path miss) → treats as empty, writes."""
    mock_manager = MagicMock()

    with patch.object(vio_mod, "_vault_read", return_value=None), \
         patch.object(vio_mod, "_vault_write") as mock_write:
        result = vio_mod.write_if_absent(mock_manager, "new/path", "FRESH_KEY", "value")

    assert result is True           # AC-01: None treated as empty
    mock_write.assert_called_once() # AC-01: write called
