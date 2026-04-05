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
"""Mask real secret values in tool output before they reach the UI or LLM context.

Hook:   tool_output_update  (async, priority 10)

Extension-point signature (from helpers/tool.py:32-35 and 46-49)::

    ctx = {"content": <str>}
    await call_extensions_async("tool_output_update", self.agent, ctx=ctx)
    # self.progress = ctx["content"]   ← reads back mutated value

Purpose
-------
Fires at two points during every tool invocation:

1. **set_progress()** — streaming stdout chunks from code_execution_tool and
   other tools that emit incremental output.
2. **before_execution()** — individual tool-argument display (one call per
   key-value pair in tool_args before the tool runs).

At both points this extension scans ``ctx['content']`` and replaces every
known secret value with its canonical placeholder alias, constructed via
``helpers.secrets.alias_for_key(key)``.

Secret sources
--------------
1. **OpenBao global + project secrets** — loaded from the manager singleton
   via ``manager.load_secrets()`` (same source as hist_add_before masking).
2. **Terminal-injected keys** — keys in ``agent.context._terminal_injected_keys``
   whose values are read from ``os.environ`` while they are still present
   (the cleanup hook removes them in tool_execute_after, after this hook fires).

Security
--------
- AC-06: replaces known secret values in ctx['content'] before return.
- AC-07: never raises — logs warning and returns ctx unchanged on any error.
- Minimum value length of 8 characters to avoid false positives on short strings.
- Does NOT import or hardcode the placeholder pattern literal — uses
  ``alias_for_key()`` from helpers.secrets exclusively.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any

from helpers.extension import Extension
from helpers.secrets import alias_for_key

logger = logging.getLogger(__name__)

# Minimum secret value length — values shorter than this are too likely to
# produce false-positive replacements in normal text output.
# Raised from 8 to 12 (REM-034): real secrets are UUIDs (36+), tokens (26+),
# API keys (32+). A len=7 secret was causing systematic stripping of uppercase
# characters from code_execution_tool output.
_MIN_SECRET_LEN = 12  # AC-01 / REM-034: prevent short secrets corrupting output


class OpenBaoMaskOutput(Extension):
    """Replace live secret values with placeholder aliases in all tool output.

    Registered in the tool_output_update lifecycle hook at priority 10.
    Fires for every tool — masking is value-driven so non-secret content
    passes through with only a dict lookup cost.
    """

    async def execute(
        self,
        ctx: dict | None = None,
        **kwargs: Any,
    ) -> None:
        """Scan ctx['content'] and replace secret values with placeholder aliases.

        Satisfies: AC-06, AC-07
        """
        if ctx is None or not isinstance(ctx, dict):
            return

        content = ctx.get("content", "")
        if not content or not isinstance(content, str):
            return

        try:
            secrets = self._collect_secrets()
            if not secrets:
                return

            masked = _mask_string(content, secrets)
            if masked is not content:
                ctx["content"] = masked

        except Exception as exc:  # pylint: disable=broad-except
            # AC-07: fail-open — never block output delivery
            logger.warning(
                "OpenBaoMaskOutput: unexpected error during masking: %s", exc
            )
            # Do NOT modify ctx on error — return original content unchanged

    # ------------------------------------------------------------------
    # Secret collection
    # ------------------------------------------------------------------

    def _collect_secrets(self) -> dict[str, str]:
        """Return merged dict of key->value for all secrets to mask.

        Merges:
        1. Global + project secrets from the OpenBao manager.
        2. Values for terminal-injected keys currently in os.environ.

        Returns {} on any error — never raises.
        """
        try:
            combined: dict[str, str] = {}

            # Source 1: OpenBao global + project secrets
            vault_secrets = self._load_vault_secrets()
            if vault_secrets:
                combined.update(vault_secrets)

            # Source 2: terminal-injected keys still in os.environ
            terminal_secrets = self._load_terminal_injected_secrets()
            if terminal_secrets:
                combined.update(terminal_secrets)

            return combined

        except Exception as exc:  # pylint: disable=broad-except
            logger.debug(
                "OpenBaoMaskOutput: could not collect secrets: %s", exc
            )
            return {}

    def _load_vault_secrets(self) -> dict[str, str]:
        """Load global + project secrets from the OpenBao manager.

        Returns {} if manager is unavailable or on any error.
        """
        try:
            fc = sys.modules.get("openbao_secrets_factory_common")
            if fc is None:
                return {}
            manager = fc.get_openbao_manager()
            if manager is None:
                return {}
            return manager.load_secrets() or {}
        except Exception as exc:  # pylint: disable=broad-except
            logger.debug(
                "OpenBaoMaskOutput: vault secrets load failed: %s", exc
            )
            return {}

    def _load_terminal_injected_secrets(self) -> dict[str, str]:
        """Read values for _terminal_injected_keys from os.environ.

        These keys were injected by _15_inject_terminal_secrets and are
        still present in os.environ during set_progress / before_execution.
        Returns {} if the attribute is absent or on any error.
        """
        try:
            injected_keys: list[str] = getattr(
                self.agent.context, "_terminal_injected_keys", []
            ) or []
            if not injected_keys:
                return {}

            result: dict[str, str] = {}
            for key in injected_keys:
                value = os.environ.get(key)
                if value and len(value) >= _MIN_SECRET_LEN:
                    result[key] = value
            return result

        except Exception as exc:  # pylint: disable=broad-except
            logger.debug(
                "OpenBaoMaskOutput: terminal secrets load failed: %s", exc
            )
            return {}


# ---------------------------------------------------------------------------
# Masking helper (module-level for testability)
# ---------------------------------------------------------------------------

def _mask_string(text: str, secrets: dict[str, str]) -> str:
    """Replace all known secret values in *text* with their placeholder aliases.

    Iterates the secrets dict and replaces each value whose length is at least
    _MIN_SECRET_LEN characters with ``alias_for_key(key)``.

    The alias is constructed by helpers.secrets.alias_for_key() — the literal
    placeholder format string does NOT appear in this file.

    Returns the same object (identity) if no replacements were made, so callers
    can use ``is`` to detect whether masking changed anything.
    """
    result = text
    for key, value in secrets.items():
        if not value or len(value) < _MIN_SECRET_LEN:
            continue
        if value in result:
            placeholder = alias_for_key(key)
            result = result.replace(value, placeholder)
    return result
