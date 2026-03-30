# Copyright 2024 DeimosAI
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
"""Tests for R-08 mitigations 4+5: placeholder masking and shell guard."""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup + A0 framework stubs
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parent.parent.resolve()
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

# Include A0 framework root when running inside the container
_A0 = Path("/a0")
if _A0.is_dir() and str(_A0) not in sys.path:
    sys.path.insert(0, str(_A0))


def _ensure_stubs() -> None:
    """Inject minimal framework stubs when A0 is not available."""
    # helpers.extension
    he = sys.modules.get("helpers.extension")
    if he is None or not hasattr(he, "Extension"):
        try:
            import helpers.extension as _he  # noqa: PLC0415
            if not hasattr(_he, "Extension"): raise ImportError
        except (ImportError, ModuleNotFoundError):
            _stub = types.ModuleType("helpers.extension")
            class _Extension:
                def execute(self, **kw): ...
            _stub.Extension = _Extension
            sys.modules["helpers"] = sys.modules.get("helpers") or types.ModuleType("helpers")
            sys.modules["helpers.extension"] = _stub

    # helpers.secrets
    hs = sys.modules.get("helpers.secrets")
    if hs is None or not hasattr(hs, "ALIAS_PATTERN"):
        try:
            import helpers.secrets as _hs  # noqa: PLC0415
            if not hasattr(_hs, "ALIAS_PATTERN"): raise ImportError
        except (ImportError, ModuleNotFoundError):
            _stub2 = types.ModuleType("helpers.secrets")
            _stub2.ALIAS_PATTERN = r"§§secret\(([^)]+)\)"
            _stub2.alias_for_key = lambda k: f"§§secret({k})"
            sys.modules["helpers.secrets"] = _stub2


_ensure_stubs()

# Placeholder constants (escape sequences -- no literal chars in source)
_PFX = "⟦bao:v1:"
_SFX = "⟧"
_ANY = "⟦bao:"


# ---------------------------------------------------------------------------
# _redact_bao_placeholders tests
# ---------------------------------------------------------------------------

def test_bao_placeholder_masked_before_llm_history() -> None:
    """_redact_bao_placeholders() replaces bao tokens with [bao-ref:REDACTED] (R-08 mit.4)."""
    from extensions.python.hist_add_before._10_openbao_mask_history import (  # noqa: PLC0415
        _redact_bao_placeholders,
    )
    content = "Authorization: " + _PFX + "plugin/test/api_key" + _SFX
    result = _redact_bao_placeholders(content)
    assert _ANY not in result, f"Placeholder not redacted: {result!r}"
    assert "[bao-ref:REDACTED]" in result, f"Redacted token missing: {result!r}"


def test_bao_placeholder_masked_in_list_of_dicts() -> None:
    """_redact_bao_placeholders() handles list-of-dict LLM message format (R-08 mit.4)."""
    from extensions.python.hist_add_before._10_openbao_mask_history import (  # noqa: PLC0415
        _redact_bao_placeholders,
    )
    content = [{"role": "user", "content": "key: " + _PFX + "mcp/srv/hdr" + _SFX}]
    result = _redact_bao_placeholders(content)
    assert _ANY not in str(result), f"Placeholder not redacted in list: {result!r}"
    assert "[bao-ref:REDACTED]" in str(result), f"Missing redacted token: {result!r}"


def test_bao_placeholder_idempotent_already_redacted() -> None:
    """Already-redacted [bao-ref:REDACTED] passes through unchanged (R-08 mit.4)."""
    from extensions.python.hist_add_before._10_openbao_mask_history import (  # noqa: PLC0415
        _redact_bao_placeholders,
    )
    content = "Authorization: [bao-ref:REDACTED]"
    assert _redact_bao_placeholders(content) == content


# ---------------------------------------------------------------------------
# _guard_bao_placeholders tests
# ---------------------------------------------------------------------------

def test_bao_placeholder_in_shell_args_raises() -> None:
    """_guard_bao_placeholders() raises ValueError on bao placeholder in tool args (R-08 mit.5)."""
    from extensions.python.tool_execute_before._05_openbao_shell_transform import (  # noqa: PLC0415
        _guard_bao_placeholders,
    )
    bad = "curl -H 'Auth: " + _PFX + "mcp/s/h" + _SFX + "'"
    with pytest.raises(ValueError, match="Unresolved"):
        _guard_bao_placeholders({"code": bad})


def test_bao_placeholder_safe_args_no_raise() -> None:
    """_guard_bao_placeholders() does NOT raise on clean tool args (no false positive)."""
    from extensions.python.tool_execute_before._05_openbao_shell_transform import (  # noqa: PLC0415
        _guard_bao_placeholders,
    )
    _guard_bao_placeholders({"code": "echo hello", "runtime": "terminal"})  # must not raise
