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
"""Transform secret placeholders to shell variable references in code execution args.

Priority 05 -- runs BEFORE the core _10_unmask_secrets extension (priority 10).

Problem
-------
When the agent builds a shell command that references a secret, the framework
emits a placeholder token managed by helpers.secrets.  The core
_10_unmask_secrets extension (priority 10) would then substitute the REAL
credential value into the command string before the shell executes it.  That
real value would be captured in:

    - tool_args (logged to agent history / LLM context window)
    - shell command history (bash ~/.bash_history, etc.)
    - process argument lists visible to other processes on the host

Solution
--------
This extension intercepts tool_args BEFORE _10_unmask_secrets and replaces
every placeholder with a $KEY_NAME shell variable reference instead.

    Example:  placeholder for OPENAI_API_KEY  ->  $OPENAI_API_KEY

Because the placeholder pattern is gone from the string, _10_unmask_secrets
finds nothing to expand and the real value never enters the command string.
The shell resolves $KEY_NAME from os.environ, which holds either the
"proxy-a0" sentinel (when AuthProxy is active) or the actual value.

Guard
-----
Only CodeExecution (shell/code runner) tool invocations are transformed.
All other tool types pass through unchanged.

The isinstance(tool, CodeExecution) check requires the ``tool=tool`` kwarg
injected by agent.py into tool_execute_before (present in the dev codebase).
If the kwarg is absent (older framework version), the extension falls back
to a tool_name string comparison as a safe degradation path.

Pattern import
--------------
The placeholder regex is imported from helpers.secrets as ALIAS_PATTERN and
bound locally to PLACEHOLDER_PATTERN.  The literal pattern string does NOT
appear anywhere in this file -- callers import it rather than redefining it.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict

from helpers.extension import Extension

# Import the placeholder regex from helpers.secrets.
# ALIAS_PATTERN is the module-level constant (same value as
# SecretsManager.PLACEHOLDER_PATTERN class attribute).  Binding it to
# PLACEHOLDER_PATTERN here makes the purpose explicit without repeating
# the literal pattern string in this file.
from helpers.secrets import ALIAS_PATTERN as PLACEHOLDER_PATTERN

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ⟦bao:⟧ placeholder guard constant (ADR-04 / R-08 premortem mitigation)
# ---------------------------------------------------------------------------
# ⟦bao:vN:path⟧ tokens are OpenBao KV v2 path references — NOT expandable
# shell variables.  If one appears in a code_execution tool arg it means the
# consumer forgot to call resolve_plugin_config() or
# resolve_mcp_server_headers() before invoking the tool.  Silently passing a
# literal placeholder as a credential produces a hard-to-debug auth failure.
# Fail loudly here instead (fail-closed, R-08 mitigations 4+5, ADR-04).
# This check MUST run BEFORE any §§secret() expansion logic.
_BAO_SHELL_PREFIX: str = "⟦bao:"  # U+27E6 + 'bao:'

# ---------------------------------------------------------------------------
# Lazy import of CodeExecution class
# ---------------------------------------------------------------------------

_CodeExecution = None
_code_execution_import_attempted = False


def _get_code_execution_class():
    """Return the CodeExecution Tool subclass, or None if unavailable.

    Cached after first successful import so repeated calls are O(1).
    A failed import returns None and the extension falls back to a
    tool_name string check.
    """
    global _CodeExecution, _code_execution_import_attempted
    if _code_execution_import_attempted:
        return _CodeExecution
    _code_execution_import_attempted = True
    try:
        from plugins._code_execution.tools.code_execution_tool import CodeExecution
        _CodeExecution = CodeExecution
        logger.debug(
            "OpenBaoShellTransform: CodeExecution class resolved successfully"
        )
    except ImportError as exc:
        logger.debug(
            "OpenBaoShellTransform: could not import CodeExecution (%s) -- "
            "will use tool_name string fallback",
            exc,
        )
    return _CodeExecution


# ---------------------------------------------------------------------------
# ⟦bao:⟧ placeholder guard helper (module-level for testability)
# ---------------------------------------------------------------------------

def _guard_bao_placeholders(tool_args: dict) -> None:
    """Raise ValueError if any shell tool arg contains a ⟦bao:⟧ placeholder.

    ⟦bao:vN:path⟧ tokens cannot be resolved by the shell.  Their presence
    in shell tool args is a SECURITY event: fail-closed rather than silently
    passing a literal placeholder as a credential value (ADR-04, R-08
    premortem mitigations 4+5).  Must be called BEFORE §§secret() expansion.
    """
    for key, value in tool_args.items():
        if not isinstance(value, str):
            continue
        # Fast check before any further processing
        if _BAO_SHELL_PREFIX not in value:
            continue
        # At least one ⟦bao: token present — SECURITY violation
        logger.error(
            "SECURITY: ⟦bao:⟧ placeholder detected in shell tool args "
            "for key %r — this placeholder cannot be expanded in shell context. "
            "Resolve via resolve_plugin_config() before passing to shell.",
            key,
        )
        raise ValueError(
            f"Unresolved ⟦bao:⟧ placeholder in shell argument {key!r} "
            f"— secret not injected"
        )


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------

class OpenBaoShellTransform(Extension):
    """Replace secret placeholders with $KEY_NAME shell references in code tool args.

    Registered in the tool_execute_before lifecycle hook at priority 05 so
    it runs before _10_unmask_secrets (priority 10).
    """

    async def execute(
        self,
        tool_args: Dict[str, Any] = None,
        tool_name: str = "",
        tool: Any = None,
        **kwargs,
    ) -> None:
        if not tool_args:
            return

        # ── Guard: only act on CodeExecution (shell/code) invocations ──────
        code_exec_cls = _get_code_execution_class()

        if tool is not None and code_exec_cls is not None:
            # Preferred path: isinstance check on the injected tool object.
            # Requires agent.py to pass tool=tool in call_extensions_async.
            if not isinstance(tool, code_exec_cls):
                return
        else:
            # Fallback path: name-based guard for framework versions that
            # do not yet pass the tool= kwarg.
            if tool_name != "code_execution_tool":
                return

        # ── Guard: ⟦bao:⟧ placeholders MUST NOT reach the shell (ADR-04/R-08) ──
        # Runs BEFORE §§secret() expansion — fail-closed on unresolved placeholder.
        _guard_bao_placeholders(tool_args)

        # ── Transform: replace placeholders with $KEY_NAME references ──────
        _transform_args_inplace(tool_args)


# ---------------------------------------------------------------------------
# Core transformation (module-level for testability)
# ---------------------------------------------------------------------------

def _transform_args_inplace(tool_args: Dict[str, Any]) -> None:
    """Scan all string values in tool_args and replace placeholder patterns.

    Modifies the dict in-place.  Non-string values are skipped.

    For each regex match of PLACEHOLDER_PATTERN:
        - Extracts KEY_NAME from capture group 1
        - Replaces the full match with $KEY_NAME (upper-cased)

    The PLACEHOLDER_PATTERN is imported from helpers.secrets -- the literal
    pattern string does NOT appear in this source file.
    """
    def _replacer(match: re.Match) -> str:
        key_name = match.group(1).upper()
        return f"${key_name}"

    changed: list[str] = []
    for arg_key, value in list(tool_args.items()):
        if not isinstance(value, str):
            continue
        new_value = re.sub(PLACEHOLDER_PATTERN, _replacer, value)
        if new_value != value:
            tool_args[arg_key] = new_value
            changed.append(arg_key)

    if changed:
        logger.debug(
            "OpenBaoShellTransform: replaced secret placeholders with "
            "$VAR shell references in args: %s",
            ", ".join(changed),
        )
