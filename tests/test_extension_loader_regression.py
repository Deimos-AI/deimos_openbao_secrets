"""Regression tests — extension file loader pattern (REM-020 / REM-001).

This suite guards against a recurring regression where the four OpenBao
factory extension files are changed from importlib absolute-path loading
to a direct `from openbao_helpers.factory_loader import ...` statement.

Root cause of the regression:
  In the A0 runtime, `helpers` resolves to A0's own helpers package
  (e.g. /a0/helpers/), which has no `factory_loader` module.  The
  resulting ModuleNotFoundError is silently swallowed by the `except
  Exception` guard in each extension, causing all secret and API-key
  resolution to return None — breaking every model call.

History:
  REM-001 regression: fixed in commit 237ef00
  REM-020 regression: fixed in commit 9575c55 (same root cause)

Correct pattern (must be present in each extension file):
  importlib.util.spec_from_file_location(...)  — absolute-path loader
  find_plugin_dir(...)                          — runtime path resolver

Forbidden pattern (must NOT appear in any extension file):
  from openbao_helpers.factory_loader import           — breaks in A0 runtime

Acceptance criteria:
  AC-01  All four factory extension files exist at expected paths.
  AC-02  No extension file contains the forbidden direct import.
  AC-03  Every extension file contains importlib.util absolute-path loading.
  AC-04  Every extension file calls find_plugin_dir() for runtime resolution.
  AC-05  Every extension file caches the loaded module in sys.modules.
  AC-06  All tests pass, pytest 0 failures.
"""
from __future__ import annotations

import ast
import os
import sys

import pytest

# Ensure we can always locate the plugin root regardless of invocation cwd
_PLUGIN_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _PLUGIN_DIR)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: The four extension files that MUST use importlib absolute-path loading.
FACTORY_EXTENSION_FILES: tuple[str, ...] = (
    os.path.join(
        _PLUGIN_DIR,
        "extensions",
        "python",
        "_functions",
        "models",
        "get_api_key",
        "start",
        "_10_openbao_api_key.py",
    ),
    os.path.join(
        _PLUGIN_DIR,
        "extensions",
        "python",
        "_functions",
        "helpers",
        "secrets",
        "get_secrets_manager",
        "start",
        "_10_openbao_factory.py",
    ),
    os.path.join(
        _PLUGIN_DIR,
        "extensions",
        "python",
        "_functions",
        "helpers",
        "secrets",
        "get_default_secrets_manager",
        "start",
        "_10_openbao_default_factory.py",
    ),
    os.path.join(
        _PLUGIN_DIR,
        "extensions",
        "python",
        "_functions",
        "helpers",
        "secrets",
        "get_project_secrets_manager",
        "start",
        "_10_openbao_project_factory.py",
    ),
)

#: Import statement that MUST NOT appear in any factory extension file.
FORBIDDEN_PATTERN = "from openbao_helpers.factory_loader import"

#: Tokens that MUST be present in every factory extension file.
REQUIRED_TOKENS = (
    "importlib.util",
    "spec_from_file_location",
    "find_plugin_dir",
    "sys.modules",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read(path: str) -> str:
    """Read a file and return its text content."""
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


# ---------------------------------------------------------------------------
# AC-01: All four files exist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", FACTORY_EXTENSION_FILES)
def test_extension_file_exists(path):
    """AC-01: Each factory extension file is present at its expected path."""
    assert os.path.isfile(path), (
        f"Factory extension file not found: {path}\n"
        "This file must exist for OpenBao secret resolution to work."
    )


# ---------------------------------------------------------------------------
# AC-02: Forbidden direct import is absent
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", FACTORY_EXTENSION_FILES)
def test_no_direct_helpers_factory_loader_import(path):
    """AC-02: No factory extension file contains the forbidden direct import.

    `from openbao_helpers.factory_loader import` resolves to A0's own helpers
    package at runtime, which has no factory_loader module.  The resulting
    ModuleNotFoundError is silently swallowed, breaking all secret resolution.

    REM-020 regression (commit 9575c55) and REM-001 regression (commit 237ef00)
    were both caused by this exact pattern.
    """
    source = _read(path)
    assert FORBIDDEN_PATTERN not in source, (
        f"Forbidden import found in {os.path.basename(path)}:\n"
        f"  '{FORBIDDEN_PATTERN}'\n\n"
        "This causes a silent ModuleNotFoundError in the A0 runtime because "
        "`helpers` resolves to A0's own helpers package, not the plugin's.\n"
        "Fix: use importlib.util.spec_from_file_location() + find_plugin_dir() "
        "to load factory_loader.py by absolute path (see REM-020-fix pattern)."
    )


# ---------------------------------------------------------------------------
# AC-03: importlib absolute-path loading is present
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", FACTORY_EXTENSION_FILES)
@pytest.mark.parametrize("token", REQUIRED_TOKENS)
def test_required_importlib_tokens_present(path, token):
    """AC-03 / AC-04 / AC-05: Each required token is present in each extension.

    Verifies:
      - importlib.util                   (AC-03: module is imported)
      - spec_from_file_location          (AC-03: absolute-path loader used)
      - find_plugin_dir                  (AC-04: runtime path resolver present)
      - sys.modules                      (AC-05: caching to prevent re-execution)
    """
    source = _read(path)
    assert token in source, (
        f"Required token '{token}' not found in {os.path.basename(path)}.\n"
        "Factory extension files must use importlib.util absolute-path loading "
        "via find_plugin_dir() with sys.modules caching.  "
        "See REM-020-fix pattern."
    )


# ---------------------------------------------------------------------------
# AC-03 extra: source parses as valid Python
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", FACTORY_EXTENSION_FILES)
def test_extension_file_is_valid_python(path):
    """AC-03 extra: each extension file must be syntactically valid Python."""
    source = _read(path)
    try:
        ast.parse(source)
    except SyntaxError as exc:
        pytest.fail(
            f"SyntaxError in {os.path.basename(path)}: {exc}\n"
            "The file cannot be loaded by A0 if it contains syntax errors."
        )
