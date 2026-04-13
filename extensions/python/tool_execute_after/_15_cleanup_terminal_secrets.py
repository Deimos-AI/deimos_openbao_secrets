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
"""Clear extra_env terminal secrets after code_execution_tool completes.

Hook:   tool_execute_after  (async, priority 15)

Purpose
-------
Immediately after code_execution_tool finishes, clear the
_terminal_extra_env dict and _terminal_injected_keys list from
agent.context so that resolved secret values cannot leak to subsequent
tool invocations.

When the framework lacks extra_env support (legacy path), this hook also
removes the injected keys from os.environ for backward compatibility.

Security
--------
- AC-04: clears _terminal_extra_env after tool completes.
- AC-05: removes os.environ keys when legacy fallback was used.
- Fail-open: on any exception, logs a warning and does not raise.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from helpers.extension import Extension

logger = logging.getLogger(__name__)


class CleanupTerminalSecrets(Extension):
    """Clear terminal secrets staged by _15_inject_terminal_secrets.

    Registered in the tool_execute_after lifecycle hook at priority 15.
    No-op for all tools other than code_execution_tool.
    """

    async def execute(
        self,
        tool_name: str = "",
        tool: Any = None,
        **kwargs: Any,
    ) -> None:
        """Clear _terminal_extra_env and optionally clean os.environ.

        Satisfies: AC-04, AC-05
        """
        # Only clean up after code_execution_tool invocations
        if tool_name != "code_execution_tool":
            return

        try:
            # Read the list of keys injected by the before-hook
            injected_keys: list[str] = getattr(
                self.agent.context, "_terminal_injected_keys", []
            ) or []

            # AC-04: clear _terminal_extra_env so secrets don't persist
            try:
                extra_env = getattr(
                    self.agent.context, "_terminal_extra_env", None
                )
                if extra_env is not None:
                    self.agent.context._terminal_extra_env = None
                    logger.debug(
                        "CleanupTerminalSecrets: cleared _terminal_extra_env "
                        "(%d key(s))",
                        len(extra_env) if isinstance(extra_env, dict) else 0,
                    )
            except Exception:  # pylint: disable=broad-except
                pass

            # AC-05: backward compat — remove os.environ keys if legacy path used
            if injected_keys:
                removed: list[str] = []
                for key in injected_keys:
                    popped = os.environ.pop(key, None)
                    if popped is not None:
                        removed.append(key)
                        logger.debug(
                            "CleanupTerminalSecrets: removed %r from os.environ "
                            "(legacy fallback)",
                            key,
                        )

                if removed:
                    logger.debug(
                        "CleanupTerminalSecrets: removed %d key(s) from os.environ",
                        len(removed),
                    )

            # Clear the injected keys list on the context
            try:
                self.agent.context._terminal_injected_keys = []
            except Exception:  # pylint: disable=broad-except
                pass

            logger.debug(
                "CleanupTerminalSecrets: cleanup complete"
            )

        except Exception as exc:  # pylint: disable=broad-except
            # Fail-open — never block subsequent tool execution
            logger.warning(
                "CleanupTerminalSecrets: unexpected error during cleanup: %s", exc
            )
