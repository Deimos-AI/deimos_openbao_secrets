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
"""Backstop: mask real secret values before any message enters agent history.

Hook:   hist_add_before  (synchronous)
Priority: 10

Purpose
-------
This is the final safety net in the combined secret-prevention architecture.
Even if an upstream path (tool output, LLM response, tool_result text) somehow
carries a live secret value before reaching agent history, this extension
scans the content and replaces every known secret value with its placeholder
representation, constructed via helpers.secrets.alias_for_key().

This ensures that:
    1. The LLM never sees real credential values in its context window.
    2. Persistent history files (.json) never contain plaintext secrets.
    3. The log / UI display layer receives only masked representations.

Content structures handled
--------------------------
The ``content`` value in ``content_data`` can take several forms depending on
which hist_add_* method called hist_add_message():

    str  -- plain text (AI response, warning messages)
    dict -- tool result: {"tool_name": ..., "tool_result": ..., ...}
    list -- list of message dicts (used by some history implementations)

All string leaves are scanned.  Non-string values are left untouched.

Secret lookup
-------------
Secrets are loaded via get_openbao_manager().load_secrets(), which is cached
inside the manager singleton so repeated calls are O(1) after the first load.
If the manager is unavailable the extension is a no-op -- it never raises.

Placeholder construction
------------------------
alias_for_key(key) is imported from helpers.secrets and constructs the
canonical placeholder representation for a given key name.  The literal
placeholder pattern string does NOT appear in this file.
"""
from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Any

from helpers.extension import Extension
from helpers.secrets import alias_for_key

logger = logging.getLogger(__name__)

# Minimum secret value length to scan for.  Values shorter than this are
# skipped to avoid false-positive replacements — real secrets are UUIDs (36+),
# tokens (26+), or API keys (32+).  _MIN_SECRET_LEN=4 was the original guard
# but caused REM-034: short secret values matching and stripping arbitrary
# uppercase characters from tool output.
_MIN_SECRET_LEN = 6  # AC-01 / REM-034b: lowered from 12; _should_mask() guards prevent false positives


# ---------------------------------------------------------------------------
# ⟦bao:v1:…⟧ placeholder redaction (ADR-04 / R-08 premortem mitigation)
# ---------------------------------------------------------------------------
# ⟦bao:vN:path⟧ tokens written by Surface A/B encode OpenBao KV v2 paths.
# Exposing those paths to the LLM leaks internal vault topology and may confuse
# resolution logic.  Replace the full token with an inert safe form BEFORE any
# content reaches agent history.
#
# Pattern covers all ⟦bao:vN:…⟧ versions (v[0-9]+ is future-proof).
# Runs BEFORE _mask_content and BEFORE the "if not secrets: return" guard
# so bao tokens are stripped even when OpenBao is unavailable.
_BAO_PLACEHOLDER_RE = re.compile(r"⟦bao:v[0-9]+:[^⟧]*⟧")
_BAO_REDACTED = "[bao-ref:REDACTED]"


def _redact_bao_placeholders(content):
    """Replace ⟦bao:vN:…⟧ tokens with [bao-ref:REDACTED] (ADR-04/R-08).

    Runs BEFORE secret-value masking so vault-path topology never reaches
    the LLM context window.  Handles str, dict, list — same surfaces as
    _mask_content.  Must be called even when secrets dict is empty.
    """
    if isinstance(content, str):
        if "⟦bao:" in content:  # fast check before regex
            return _BAO_PLACEHOLDER_RE.sub(_BAO_REDACTED, content)
        return content

    if isinstance(content, dict):
        changed = False
        result = {}
        for k, v in content.items():
            new_v = _redact_bao_placeholders(v)
            result[k] = new_v
            if new_v is not v:
                changed = True
        return result if changed else content

    if isinstance(content, list):
        changed = False
        result_list = []
        for item in content:
            new_item = _redact_bao_placeholders(item)
            result_list.append(new_item)
            if new_item is not item:
                changed = True
        return result_list if changed else content

    return content


class OpenBaoMaskHistory(Extension):
    """Replace live secret values with placeholders before history storage.

    Synchronous hook -- hist_add_before is called via call_extensions_sync.
    The execute() method MUST NOT be a coroutine.
    """

    def execute(self, content_data: dict = None, ai: bool = False, **kwargs) -> None:  # noqa: FBT001
        if content_data is None:
            return

        content = content_data.get("content")
        if not content:
            return

        try:
            # ADR-04 / R-08: redact ⟦bao:vN:…⟧ placeholders BEFORE secret masking.
            # Runs even when secrets dict is empty — vault-path topology must
            # never reach the LLM regardless of OpenBao availability.
            redacted = _redact_bao_placeholders(content)
            if redacted is not content:
                content = redacted
                content_data["content"] = content

            secrets = self._load_secrets()
            if not secrets:
                return

            masked = _mask_content(content, secrets)
            if masked is not content:  # only update if something changed
                content_data["content"] = masked

        except Exception as exc:  # pylint: disable=broad-except
            # Never block history writes -- log and continue
            logger.debug("OpenBaoMaskHistory: error during masking: %s", exc)

    # ------------------------------------------------------------------
    # Secret loading
    # ------------------------------------------------------------------

    def _load_secrets(self) -> dict:
        """Return the combined global + project secrets dict for masking.

        Loads global secrets from secret/data/agentzero.
        When an active project is detected, also loads project-specific secrets
        and merges them — project values overwrite global on key collision.
        Returns {} on any error — never raises, never blocks history writes.
        PSK-005: extends pre-PSK global-only masking to cover project secrets.
        """
        try:
            fc = sys.modules.get("openbao_secrets_factory_common")
            if fc is None:
                return {}
            manager = fc.get_openbao_manager()
            if manager is None:
                return {}

            # AC-01: load global secrets (unchanged pre-PSK)
            global_secrets = manager.load_secrets() or {}

            # AC-02: detect active project and derive slug
            project = getattr(self.agent.context, 'project', None) or ''
            project_slug = Path(project).name if project else None

            # AC-03: load project secrets when project is active
            if project_slug:
                project_secrets = manager.load_project_secrets(project_slug)
            else:
                project_secrets = {}

            # AC-04: merge — project values overwrite global on collision
            if project_secrets:
                combined = {**global_secrets, **project_secrets}
            else:
                combined = global_secrets

            return combined

        except Exception as exc:  # pylint: disable=broad-except
            logger.debug("OpenBaoMaskHistory: could not load secrets: %s", exc)
            return {}

# ---------------------------------------------------------------------------
# Content masking helpers (module-level for testability)
# ---------------------------------------------------------------------------

_TOKEN_PATTERN = re.compile(
    r'[0-9].*[A-Za-z]|[A-Za-z].*[0-9]'  # alphanumeric mix
    r'|[^A-Za-z0-9]',                       # contains special chars
)
_RISKY_PATTERN = re.compile(r'^[a-z]+$')


def _should_mask(val: str) -> bool:
    """Decide if a secret value is safe to mask.

    AC-02: token-like secrets (alphanumeric mix, special chars) masked at len >= 6.
    AC-03: pure-alpha short secrets (len < 20) use word-boundary replacement only.
    AC-04: passphrases (3+ words or len >= 20) masked as full phrase.
    Never raises — returns False on any unexpected input.
    """
    if not val or len(val) < _MIN_SECRET_LEN:
        return False
    # Always mask: contains digits, special chars, or uppercase (token-like)
    if _TOKEN_PATTERN.search(val):
        return True
    # Risky: pure lowercase alpha — could be a dictionary word
    if _RISKY_PATTERN.match(val):
        words = val.split()
        if len(words) >= 3 or len(val) >= 20:
            return True  # passphrase — safe to mask as full phrase (AC-04)
        return len(val) >= 12  # short dict-word: require 12+ for safety
    # Mixed-case or other — mask if len >= 6
    return len(val) >= 6


def _mask_string(text: str, secrets: dict) -> str:
    """Replace secret values in *text* with their placeholder aliases.

    Uses _should_mask() to determine per-value masking eligibility.
    Pure-alpha short secrets (< 20 chars) use word-boundary replacement
    to avoid corrupting normal text substrings (AC-03).
    Token-like and passphrase secrets are replaced globally (AC-02/AC-04).

    Returns the same object (identity) if no replacements were made.
    """
    result = text
    # MED-03: Sort by descending value length to prevent substring masking bypass
    for key, value in sorted(secrets.items(), key=lambda kv: -len(kv[1])):
        if not _should_mask(value):
            continue
        if value not in result:
            continue
        replacement = alias_for_key(key)
        if _RISKY_PATTERN.match(value) and len(value) < 20:
            # Pure-alpha short secret — word-boundary match only (AC-03)
            result = re.sub(
                r'\b' + re.escape(value) + r'\b',
                replacement,
                result,
            )
        else:
            # Token-like or long passphrase — safe full replace (AC-02/AC-04)
            result = result.replace(value, replacement)
    return result


def _mask_content(content: Any, secrets: dict) -> Any:
    """Recursively mask secrets in all string leaves of *content*.

    Handles:
        str  -- masked directly
        dict -- all string values masked recursively
        list -- each element masked recursively
        other -- returned unchanged
    """
    if isinstance(content, str):
        return _mask_string(content, secrets)

    if isinstance(content, dict):
        changed = False
        result: dict = {}
        for k, v in content.items():
            new_v = _mask_content(v, secrets)
            result[k] = new_v
            if new_v is not v:
                changed = True
        return result if changed else content

    if isinstance(content, list):
        changed = False
        result_list: list = []
        for item in content:
            new_item = _mask_content(item, secrets)
            result_list.append(new_item)
            if new_item is not item:
                changed = True
        return result_list if changed else content

    # Non-string, non-collection: pass through unchanged
    return content
