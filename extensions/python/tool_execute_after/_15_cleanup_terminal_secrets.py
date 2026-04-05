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
"""Remove injected terminal secrets from os.environ after code_execution_tool completes.

Hook:   tool_execute_after  (async, priority 15)

Purpose
-------
Immediately after code_execution_tool finishes, remove from os.environ every key
that _15_inject_terminal_secrets.py (tool_execute_before, priority 15) set.

The list of injected keys is read from agent.context._terminal_injected_keys,
which is written by the injection hook before the tool fires.  If the attribute
is absent (e.g. the inject hook was skipped or raised) this hook is a safe no-op.

Security
--------
- AC-05: removes all injected keys immediately after tool completes.
- Minimises the os.environ exposure window to exactly one tool invocation.
- Fail-open: on any exception, logs a warning and does not raise — subsequent
  tool calls are never blocked by cleanup failures.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from helpers.extension import Extension

logger = logging.getLogger(__name__)


class CleanupTerminalSecrets(Extension):
    """Remove terminal secrets injected by _15_inject_terminal_secrets from os.environ.

    Registered in the tool_execute_after lifecycle hook at priority 15.
    No-op for all tools other than code_execution_tool.
    No-op if _terminal_injected_keys is absent or empty.
    """

    async def execute(
        self,
        tool_name: str = "",
        tool: Any = None,
        **kwargs: Any,
    ) -> None:
        """Pop all injected terminal secret keys from os.environ.

        Satisfies: AC-05
        """
        # Only clean up after code_execution_tool invocations
        if tool_name != "code_execution_tool":
            return

        try:
            # Read the list of keys injected by the before-hook.
            # AttributeError is expected when the inject hook was skipped.
            try:
                injected_keys: list[str] = getattr(
                    self.agent.context, "_terminal_injected_keys", []
                ) or []
            except AttributeError:
                injected_keys = []

            if not injected_keys:
                logger.debug(
                    "CleanupTerminalSecrets: no injected keys to clean up"
                )
                return

            removed: list[str] = []
            for key in injected_keys:
                popped = os.environ.pop(key, None)
                if popped is not None:
                    removed.append(key)
                    # AC-05: log key name only — never log the value
                    logger.debug(
                        "CleanupTerminalSecrets: removed %r from os.environ", key
                    )
                else:
                    logger.debug(
                        "CleanupTerminalSecrets: %r was not present in os.environ "
                        "(already removed or never set)",
                        key,
                    )

            # Clear the injected keys list on the context
            try:
                self.agent.context._terminal_injected_keys = []
            except Exception:  # pylint: disable=broad-except
                pass

            # LOW-03: Log only count, not key names (prevents secret name leakage)
            logger.debug(
                "CleanupTerminalSecrets: cleanup complete — removed %d key(s)",
                len(removed),
            )

        except Exception as exc:  # pylint: disable=broad-except
            # Fail-open — never block subsequent tool execution
            logger.warning(
                "CleanupTerminalSecrets: unexpected error during cleanup: %s", exc
            )
