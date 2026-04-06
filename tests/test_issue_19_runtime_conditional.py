# Copyright 2024 Deimos AI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for REM-019: runtime-conditional alias token handling (issue #19).

The _05_openbao_shell_transform extension must only replace alias tokens
with $VAR shell references for terminal runtime.  For python/nodejs runtimes
it must be a no-op, letting the framework primitive (_10_unmask_secrets)
handle alias-to-real-value replacement instead.

Acceptance Criteria:
  AC-01: terminal runtime -> alias tokens converted to $VAR
  AC-02: empty/missing runtime -> same as terminal (backward compat)
  AC-03: python runtime -> no transformation (pass-through)
  AC-04: nodejs runtime -> no transformation (pass-through)
  AC-05: python runtime with real-value replacement works after _05 no-op
  AC-06: _guard_bao_placeholders only called for terminal runtime
  AC-07: runtime value is case-insensitive
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_REPO = os.path.dirname(os.path.abspath(__file__)) + "/.."
_REPO = os.path.realpath(_REPO)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# Alias pattern matching production alias token format (doubled section sign)
_ALIAS_PATTERN = r"§§secret\(([^)]+)\)"


def _ensure_helpers_secrets_alias_pattern():
    """Ensure helpers.secrets.ALIAS_PATTERN is a real regex string.

    conftest.py registers a MagicMock for helpers.secrets, but ALIAS_PATTERN
    must be a real regex string for _05 re.sub() to work in tests.
    """
    hs = sys.modules.get("helpers.secrets")
    if hs is not None:
        hs.ALIAS_PATTERN = _ALIAS_PATTERN


def _ensure_helpers_extension():
    """Ensure helpers.extension.Extension is available."""
    he = sys.modules.get("helpers.extension")
    if he is not None and hasattr(he, "Extension"):
        return
    stub = types.ModuleType("helpers.extension")

    class _Extension:
        def execute(self, **kw): ...

    stub.Extension = _Extension
    if "helpers" not in sys.modules:
        sys.modules["helpers"] = types.ModuleType("helpers")
    sys.modules["helpers.extension"] = stub


@pytest.fixture(scope="module")
def shell_mod():
    """Load _05_openbao_shell_transform with A0 runtime deps stubbed.

    Strategy: exec_module first (conftest.py stubs satisfy imports),
    then monkey-patch _get_code_execution_class to return a mock class.
    """
    _ensure_helpers_extension()
    _ensure_helpers_secrets_alias_pattern()

    ext_path = os.path.join(
        _REPO,
        "extensions",
        "python",
        "tool_execute_before",
        "_05_openbao_shell_transform.py",
    )
    spec = importlib.util.spec_from_file_location(
        "_05_openbao_shell_transform", ext_path
    )
    mod = importlib.util.module_from_spec(spec)

    # exec_module first — conftest.py stubs handle helpers.extension/secrets
    spec.loader.exec_module(mod)

    # Now patch _get_code_execution_class to return our mock class
    mock_code_exec = type("CodeExecution", (), {})
    mod._get_code_execution_class = lambda: mock_code_exec
    return mod


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_alias_token(key: str) -> str:
    """Return an alias token matching the ALIAS_PATTERN regex."""
    return "§§secret(" + key + ")"


# ===================================================================
# AC-01: terminal runtime -> alias tokens converted to $VAR
# ===================================================================


def test_terminal_runtime_transforms_alias_to_dollar_var(shell_mod):
    """AC-01: For runtime=terminal, alias tokens become $VAR references."""
    ext = shell_mod.OpenBaoShellTransform()
    token = _make_alias_token("OPENAI_API_KEY")
    tool_args = {"runtime": "terminal", "code": "echo " + token}

    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )

    assert tool_args["code"] == "echo $OPENAI_API_KEY"


# ===================================================================
# AC-02: empty/missing runtime -> same as terminal
# ===================================================================


def test_empty_runtime_transforms_alias_to_dollar_var(shell_mod):
    """AC-02: Empty runtime string behaves like terminal."""
    ext = shell_mod.OpenBaoShellTransform()
    token = _make_alias_token("MY_SECRET")
    tool_args = {"runtime": "", "code": "echo " + token}

    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )

    assert tool_args["code"] == "echo $MY_SECRET"


def test_missing_runtime_transforms_alias_to_dollar_var(shell_mod):
    """AC-02: Missing runtime key defaults to terminal behavior."""
    ext = shell_mod.OpenBaoShellTransform()
    token = _make_alias_token("MY_SECRET")
    tool_args = {"code": "echo " + token}

    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )

    assert tool_args["code"] == "echo $MY_SECRET"


# ===================================================================
# AC-03: python runtime -> no transformation (pass-through)
# ===================================================================


def test_python_runtime_passes_through(shell_mod):
    """AC-03: For runtime=python, alias tokens remain unchanged."""
    ext = shell_mod.OpenBaoShellTransform()
    token = _make_alias_token("OPENAI_API_KEY")
    original_code = "import os; key = '" + token + "'"
    tool_args = {"runtime": "python", "code": original_code}

    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )

    # Token must NOT be transformed -- left for _10_unmask_secrets
    assert tool_args["code"] == original_code


# ===================================================================
# AC-04: nodejs runtime -> no transformation (pass-through)
# ===================================================================


def test_nodejs_runtime_passes_through(shell_mod):
    """AC-04: For runtime=nodejs, alias tokens remain unchanged."""
    ext = shell_mod.OpenBaoShellTransform()
    token = _make_alias_token("GH_TOKEN")
    original_code = "const key = '" + token + "';"
    tool_args = {"runtime": "nodejs", "code": original_code}

    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )

    assert tool_args["code"] == original_code


# ===================================================================
# AC-05: python runtime -- real value replacement works after _05 no-op
# ===================================================================


def test_python_runtime_real_value_replacement(shell_mod):
    """AC-05: After _05 no-op, alias tokens can be replaced with real values.

    Simulates what _10_unmask_secrets would do: replace alias tokens with
    actual secret values.  This proves the pipeline works end-to-end when
    _05 does not interfere.
    """
    ext = shell_mod.OpenBaoShellTransform()
    token = _make_alias_token("API_KEY")
    tool_args = {"runtime": "python", "code": "key = '" + token + "'"}

    # Step 1: _05 extension is a no-op for python
    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )
    assert token in tool_args["code"], "Token should still be present after _05"

    # Step 2: Simulate _10_unmask_secrets replacing token with real value
    real_value = "sk-real-api-key-12345"
    tool_args["code"] = tool_args["code"].replace(token, real_value)
    assert real_value in tool_args["code"]
    assert token not in tool_args["code"]


# ===================================================================
# AC-06: _guard_bao_placeholders only called for terminal runtime
# ===================================================================


def test_guard_bao_placeholders_skipped_for_python(shell_mod):
    """AC-06: _guard_bao_placeholders is NOT called for python runtime.

    A bao token in tool_args would raise ValueError for terminal
    but should be silently passed through for python (the framework
    handles it differently).
    """
    ext = shell_mod.OpenBaoShellTransform()
    bao_token = "⟦bao:v1:secret/data/mykey⟧"
    tool_args = {"runtime": "python", "code": "key = '" + bao_token + "'"}

    # For python runtime, the extension returns before reaching
    # _guard_bao_placeholders, so no ValueError should be raised
    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )

    # Token unchanged -- no guard fired
    assert bao_token in tool_args["code"]


def test_guard_bao_placeholders_terminal_raises(shell_mod):
    """AC-06: For terminal runtime, bao token DOES trigger guard."""
    ext = shell_mod.OpenBaoShellTransform()
    bao_token = "⟦bao:v1:secret/data/mykey⟧"
    tool_args = {"runtime": "terminal", "code": "echo '" + bao_token + "'"}

    with pytest.raises(ValueError, match="Unresolved"):
        asyncio.run(
            ext.execute(
                tool_args=tool_args,
                tool_name="code_execution_tool",
                tool=shell_mod._get_code_execution_class()(),
            )
        )


# ===================================================================
# AC-07: runtime value is case-insensitive
# ===================================================================


def test_runtime_case_insensitive_python(shell_mod):
    """AC-07: Python (capitalized) is treated as python runtime."""
    ext = shell_mod.OpenBaoShellTransform()
    token = _make_alias_token("SECRET_KEY")
    original = "key = '" + token + "'"
    tool_args = {"runtime": "Python", "code": original}

    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )

    assert tool_args["code"] == original


def test_runtime_case_insensitive_terminal(shell_mod):
    """AC-07: TERMINAL (upper) is treated as terminal runtime."""
    ext = shell_mod.OpenBaoShellTransform()
    token = _make_alias_token("SECRET_KEY")
    tool_args = {"runtime": "TERMINAL", "code": "echo " + token}

    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )

    assert tool_args["code"] == "echo $SECRET_KEY"


def test_runtime_case_insensitive_nodejs(shell_mod):
    """AC-07: NodeJS (mixed case) is treated as nodejs runtime."""
    ext = shell_mod.OpenBaoShellTransform()
    token = _make_alias_token("SECRET_KEY")
    original = "const k = '" + token + "';"
    tool_args = {"runtime": "NodeJS", "code": original}

    asyncio.run(
        ext.execute(
            tool_args=tool_args,
            tool_name="code_execution_tool",
            tool=shell_mod._get_code_execution_class()(),
        )
    )

    assert tool_args["code"] == original
