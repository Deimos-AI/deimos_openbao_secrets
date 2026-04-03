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
"""Inject terminal secrets into os.environ before code_execution_tool runs.

Hook:   tool_execute_before  (async, priority 15)

Purpose
-------
Secrets listed in config.terminal_secrets are resolved from OpenBao and
injected into os.environ so that shell commands executed by code_execution_tool
can reference them as $KEY_NAME environment variables.

This runs AFTER _05_openbao_shell_transform (priority 05), which converts
\u00a7\u00a7secret(KEY) placeholders to $KEY shell references. The injected
environment values are then available when the subprocess shell launches.

Cleanup
-------
Injected keys are recorded in agent.context._terminal_injected_keys so that
_15_cleanup_terminal_secrets.py (tool_execute_after, priority 15) can remove
them immediately after the tool completes, minimising the exposure window.

Security
--------
- AC-02: fires only when tool_name == 'code_execution_tool'.
- AC-03: sets os.environ[key] only when resolved value is non-None.
- AC-04: logs key name at DEBUG level; values are NEVER logged.
- Fail-open: on any exception, logs warning and does not raise.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any

from helpers.extension import Extension

logger = logging.getLogger(__name__)


class InjectTerminalSecrets(Extension):
    """Inject config.terminal_secrets into os.environ before code_execution_tool.

    Registered in the tool_execute_before lifecycle hook at priority 15.
    Runs after _05_openbao_shell_transform (priority 05).
    No-op for all tools other than code_execution_tool.
    """

    async def execute(
        self,
        tool_name: str = "",
        tool: Any = None,
        **kwargs: Any,
    ) -> None:
        """Resolve terminal_secrets keys from OpenBao and inject into os.environ.

        Satisfies: AC-02, AC-03, AC-04
        """
        # AC-02: only fire on code_execution_tool
        if tool_name != "code_execution_tool":
            return

        try:
            # Obtain the OpenBao manager singleton via factory_common
            fc = sys.modules.get("openbao_secrets_factory_common")
            manager = fc.get_openbao_manager() if fc is not None else None

            if manager is None:
                logger.debug(
                    "InjectTerminalSecrets: manager unavailable — skipping injection"
                )
                self.agent.context._terminal_injected_keys = []
                return

            # Read terminal_secrets list from plugin config
            terminal_keys: list[str] = _load_terminal_keys()

            if not terminal_keys:
                logger.debug(
                    "InjectTerminalSecrets: terminal_secrets is empty — nothing to inject"
                )
                self.agent.context._terminal_injected_keys = []
                return

            injected: list[str] = []
            for key in terminal_keys:
                try:
                    # AC-03: only inject when value is non-None (and not proxy sentinel)
                    value = manager.get_secret(key)
                    if value is not None and value != "proxy-a0":
                        os.environ[key] = value
                        injected.append(key)
                        # AC-04: log key name only — never log the value
                        logger.debug(
                            "InjectTerminalSecrets: injected %r into os.environ", key
                        )
                    else:
                        logger.debug(
                            "InjectTerminalSecrets: %r resolved to None or sentinel "
                            "— skipping injection",
                            key,
                        )
                except Exception as key_exc:  # pylint: disable=broad-except
                    logger.warning(
                        "InjectTerminalSecrets: failed to resolve %r: %s", key, key_exc
                    )

            # Record injected keys so the cleanup hook can remove them
            self.agent.context._terminal_injected_keys = injected
            logger.debug(
                "InjectTerminalSecrets: %d key(s) staged for cleanup: %s",
                len(injected),
                injected,
            )

        except Exception as exc:  # pylint: disable=broad-except
            # Fail-open — never block tool execution
            logger.warning(
                "InjectTerminalSecrets: unexpected error during injection: %s", exc
            )
            try:
                self.agent.context._terminal_injected_keys = []
            except Exception:  # pylint: disable=broad-except
                pass


# ---------------------------------------------------------------------------
# Config helper (module-level for testability)
# ---------------------------------------------------------------------------

def _load_terminal_keys() -> list[str]:
    """Return the terminal_secrets list from plugin config, or [] on any error."""
    try:
        from helpers.plugins import get_plugin_config  # noqa: PLC0415
        cfg = get_plugin_config("deimos_openbao_secrets")
        if isinstance(cfg, dict):
            keys = cfg.get("terminal_secrets") or []
            return [str(k) for k in keys if k]
        return []
    except Exception as exc:  # pylint: disable=broad-except
        logger.debug(
            "InjectTerminalSecrets: could not load plugin config: %s", exc
        )
        return []
