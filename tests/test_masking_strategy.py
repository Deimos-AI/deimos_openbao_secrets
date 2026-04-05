# Copyright 2024 Deimos
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
"""Tests for REM-034b: smarter masking strategy.

Verifies _should_mask() and _mask_string() from both extension modules:
  - extensions/python/tool_output_update/_10_openbao_mask_output.py
  - extensions/python/hist_add_before/_10_openbao_mask_history.py

Both modules MUST produce identical results (AC-06).

Acceptance Criteria covered:
  AC-01: _MIN_SECRET_LEN == 6 in both files
  AC-02: Token-like secrets (alphanumeric mix / special chars) masked at len >= 6
  AC-03: Pure-alpha short secrets (len < 20) NOT masked as arbitrary substrings
  AC-04: Passphrases (3+ words or len >= 20) masked as full phrase
  AC-05: Very short secrets (len < 6) never masked
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parent.parent.resolve()
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

_A0 = Path("/a0")
if _A0.is_dir() and str(_A0) not in sys.path:
    sys.path.insert(0, str(_A0))


def _ensure_stubs() -> None:
    """Inject minimal framework stubs when A0 is not available in CI."""
    # helpers.extension
    he = sys.modules.get("helpers.extension")
    if he is None or not hasattr(he, "Extension"):
        try:
            import helpers.extension as _he  # noqa: PLC0415
            if not hasattr(_he, "Extension"):
                raise ImportError
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
            if not hasattr(_hs, "ALIAS_PATTERN"):
                raise ImportError
        except (ImportError, ModuleNotFoundError):
            _stub2 = types.ModuleType("helpers.secrets")
            _stub2.ALIAS_PATTERN = r"\u00a7\u00a7secret\(([^)]+)\)"
            _stub2.alias_for_key = lambda k: f"\u00a7\u00a7secret({k})"
            sys.modules["helpers.secrets"] = _stub2


_ensure_stubs()

# Alias placeholder prefix for assertions
_PH = "\u00a7\u00a7secret"

# ---------------------------------------------------------------------------
# Import symbols under test from BOTH extension modules
# ---------------------------------------------------------------------------

from extensions.python.tool_output_update._10_openbao_mask_output import (  # noqa: E402
    _MIN_SECRET_LEN as _MIN_LEN_OUT,
    _mask_string as _mask_string_out,
    _should_mask as _should_mask_out,
)
from extensions.python.hist_add_before._10_openbao_mask_history import (  # noqa: E402
    _MIN_SECRET_LEN as _MIN_LEN_HIST,
    _mask_string as _mask_string_hist,
    _should_mask as _should_mask_hist,
)

# Canonical references (output module — both should be identical)
_should_mask = _should_mask_out
_mask_string = _mask_string_out


# ===========================================================================
# AC-01 — _MIN_SECRET_LEN = 6 in both files
# ===========================================================================

class TestAC01MinSecretLen:
    """Both extension files must declare _MIN_SECRET_LEN = 6 (REM-034b)."""

    def test_min_len_output_extension_is_6(self):
        """AC-01: tool_output_update extension has _MIN_SECRET_LEN == 6."""
        assert _MIN_LEN_OUT == 6, f"Expected 6, got {_MIN_LEN_OUT}"

    def test_min_len_hist_extension_is_6(self):
        """AC-01: hist_add_before extension has _MIN_SECRET_LEN == 6."""
        assert _MIN_LEN_HIST == 6, f"Expected 6, got {_MIN_LEN_HIST}"


# ===========================================================================
# AC-02 — Token-like secrets (alphanumeric mix / special chars) masked at >= 6
# ===========================================================================

class TestAC02TokenLikeMasking:
    """Secrets containing digits, special chars, or uppercase are token-like."""

    def test_short_alphanumeric_token_should_mask(self):
        """AC-02: len=8 alphanumeric mix → _should_mask True."""
        assert _should_mask("abc12345") is True

    def test_short_alphanumeric_token_masked_in_string(self):
        """AC-02: len=8 alphanumeric token replaced in output."""
        text = "connecting token=abc12345 to endpoint"
        result = _mask_string(text, {"MY_TOKEN": "abc12345"})
        assert "abc12345" not in result  # secret value must be gone
        assert result != text             # something was replaced
    def test_token_with_special_char_masked(self):
        """AC-02: secret containing '@' special char masked at len >= 6."""
        assert _should_mask("abc@def") is True

    def test_exactly_6_alphanumeric_masked(self):
        """AC-02: exactly len=6 alphanumeric → masked."""
        assert _should_mask("abc123") is True

    def test_uuid_should_mask(self):
        """AC-02: UUID (len=36, hyphens = special chars) → MASKED."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        assert len(uuid) == 36
        assert _should_mask(uuid) is True

    def test_uuid_masked_in_output(self):
        """AC-02: UUID value replaced in text output."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        text = f"app_id={uuid} connecting"
        result = _mask_string(text, {"APP_ID": uuid})
        assert uuid not in result  # UUID must be gone
        assert result != text      # something was replaced
    def test_uppercase_short_masked(self):
        """AC-02: uppercase-only len=6 → masked (non-risky path: len >= 6)."""
        # 'SECURE': no digits, no special chars, not pure lowercase → len >= 6 fallthrough
        assert _should_mask("SECURE") is True

    def test_mixed_case_len6_masked(self):
        """AC-02: mixed-case len=6 → masked."""
        assert _should_mask("SecRet") is True


# ===========================================================================
# AC-03 — Pure-alpha short secrets use word-boundary; not arbitrary substrings
# ===========================================================================

class TestAC03PureAlphaWordBoundary:
    """Pure-lowercase short secrets must NOT corrupt normal text output."""

    def test_pure_alpha_len7_not_masked(self):
        """AC-03: len=7 pure-alpha lowercase 'correct' → _should_mask False."""
        assert _should_mask("correct") is False

    def test_pure_alpha_len7_does_not_corrupt_output(self):
        """AC-03: 'correct' as secret does NOT alter 'the correct answer'."""
        text = "the correct answer is correct usage"
        result = _mask_string(text, {"PASSWORD": "correct"})
        assert result == text  # must be completely unchanged

    def test_pure_alpha_len8_not_masked(self):
        """AC-03: 'password' (len=8, pure-alpha) → not masked (< 12 threshold)."""
        assert _should_mask("password") is False

    def test_pure_alpha_len10_not_masked(self):
        """AC-03: 10-char pure-alpha secret not masked — below 12-char threshold."""
        assert _should_mask("stableconn") is False
        text = "stableconnection uses stableconn backend"
        result = _mask_string(text, {"SECRET": "stableconn"})
        assert result == text

    def test_pure_alpha_len12_masked_with_word_boundary(self):
        """AC-03: Pure-alpha len=12 (at threshold) → masked but only whole words."""
        val = "correcthorse"  # len=12, pure lowercase
        assert len(val) == 12
        assert _should_mask(val) is True
        # Appears as whole word → masked
        text = f"login with {val} here"
        result = _mask_string(text, {"KEY": val})
        assert val not in result

    def test_pure_alpha_len12_not_masked_as_substring(self):
        """AC-03: Pure-alpha len=12 NOT masked when embedded in longer word."""
        val = "correcthorse"  # len=12
        # Embedded in longer string — word boundary regex should NOT match substring
        text = f"mycorrecthorsepower is strong"
        result = _mask_string(text, {"KEY": val})
        # 'correcthorse' is substring of 'mycorrecthorsepower' — word boundary prevents match
        assert "mycorrecthorsepower" in result

    def test_hist_pure_alpha_short_not_masked(self):
        """AC-03: hist_add_before module also skips pure-alpha short secrets."""
        assert _should_mask_hist("correct") is False
        text = "the correct answer"
        assert _mask_string_hist(text, {"P": "correct"}) == text


# ===========================================================================
# AC-04 — Passphrases (3+ words or len >= 20) masked as full phrase
# ===========================================================================

class TestAC04PassphraseMasking:
    """Passphrases must be masked in full, not word-by-word."""

    def test_passphrase_with_spaces_should_mask(self):
        """AC-04: 'correct horse battery' has spaces (special chars) → masked."""
        phrase = "correct horse battery"
        assert len(phrase) == 21
        assert _should_mask(phrase) is True

    def test_passphrase_masked_as_full_phrase(self):
        """AC-04: Full passphrase replaced as single unit in output."""
        phrase = "correct horse battery"
        text = f"use passphrase: {phrase} for access"
        result = _mask_string(text, {"PASSPHRASE": phrase})
        assert phrase not in result  # full phrase must be gone
        assert result != text        # something was replaced
    def test_long_pure_alpha_no_spaces_masked(self):
        """AC-04: Pure-alpha len=21 no spaces → masked (>= 20 threshold)."""
        phrase = "correcthorsebatstaple"  # len=21, no spaces, all lowercase
        assert len(phrase) == 21
        assert _should_mask(phrase) is True

    def test_passphrase_25chars_masked(self):
        """AC-04: Passphrase >= 25 chars with spaces → MASKED."""
        phrase = "correct horse battery staple"  # len=28
        assert _should_mask(phrase) is True

    def test_hist_passphrase_masked(self):
        """AC-04: hist_add_before module also masks passphrases."""
        phrase = "correct horse battery"
        assert _should_mask_hist(phrase) is True


# ===========================================================================
# AC-05 — Very short secrets (len < 6) never masked
# ===========================================================================

class TestAC05VeryShortNotMasked:
    """No secret shorter than _MIN_SECRET_LEN should ever trigger masking."""

    def test_len5_not_masked(self):
        """AC-05: len=5 secret → NOT masked."""
        assert _should_mask("ab123") is False

    def test_len4_not_masked(self):
        """AC-05: len=4 → NOT masked."""
        assert _should_mask("abc1") is False

    def test_len1_not_masked(self):
        """AC-05: single char → NOT masked."""
        assert _should_mask("A") is False

    def test_empty_string_not_masked(self):
        """AC-05: empty string → NOT masked."""
        assert _should_mask("") is False

    def test_none_not_masked(self):
        """AC-05: None → NOT masked (falsy guard)."""
        assert _should_mask(None) is False  # type: ignore[arg-type]

    def test_len5_secret_does_not_corrupt_output(self):
        """AC-05: len=5 secret never touches output text."""
        text = "ABCDE FGHIJ KLMNO PQRST UVWXYZ"
        result = _mask_string(text, {"SHORT": "ab123"})
        assert result == text


# ===========================================================================
# Cross-module consistency — both modules must produce identical results
# ===========================================================================

class TestCrossModuleConsistency:
    """Both extension modules MUST produce identical _should_mask and _mask_string output."""

    @pytest.mark.parametrize("val,expected", [
        ("abc12345", True),   # alphanumeric mix len=8
        ("correct", False),   # pure-alpha len=7
        ("SECURE", True),     # uppercase len=6
        ("ab123", False),     # len=5
        ("", False),          # empty
        ("correct horse battery", True),  # passphrase with spaces
        ("550e8400-e29b-41d4-a716-446655440000", True),  # UUID
        ("correcthorse", True),  # pure-alpha len=12 (at threshold)
        ("password", False),  # pure-alpha len=8 < 12
    ])
    def test_both_modules_agree_on_should_mask(self, val, expected):
        """Both extension modules return identical _should_mask(val)."""
        out_result = _should_mask_out(val)
        hist_result = _should_mask_hist(val)
        assert out_result == hist_result, (
            f"Module mismatch for {val!r}: output={out_result}, hist={hist_result}"
        )
        assert out_result is expected, (
            f"Expected _should_mask({val!r}) == {expected}, got {out_result}"
        )

    def test_both_modules_mask_token_identically(self):
        """Both modules replace alphanumeric token identically."""
        text = "token abc12345 here"
        secrets = {"TOKEN": "abc12345"}
        assert _mask_string_out(text, secrets) == _mask_string_hist(text, secrets)

    def test_both_modules_skip_pure_alpha_identically(self):
        """Both modules leave pure-alpha short secret unchanged."""
        text = "the correct answer"
        secrets = {"PASS": "correct"}
        result_out = _mask_string_out(text, secrets)
        result_hist = _mask_string_hist(text, secrets)
        assert result_out == result_hist == text

    def test_both_modules_mask_uuid_identically(self):
        """Both modules replace UUID identically."""
        uuid = "550e8400-e29b-41d4-a716-446655440000"
        text = f"id={uuid} connecting"
        secrets = {"APP_ID": uuid}
        assert _mask_string_out(text, secrets) == _mask_string_hist(text, secrets)


# ===========================================================================
# Identity / no-op behaviour
# ===========================================================================

class TestIdentityBehavior:
    """_mask_string must return the same object when no masking is applied."""

    def test_no_match_returns_identity(self):
        """If secret not present in text, same object returned."""
        text = "no secrets here at all"
        result = _mask_string(text, {"TOKEN": "abc12345"})
        # abc12345 not in text → identity
        assert result is text

    def test_not_masked_secret_returns_identity(self):
        """If secret below threshold, same object returned."""
        text = "the correct answer"
        result = _mask_string(text, {"PASS": "correct"})
        assert result is text

    def test_empty_secrets_returns_identity(self):
        """Empty secrets dict → original text unchanged."""
        text = "some output text"
        result = _mask_string(text, {})
        assert result is text
