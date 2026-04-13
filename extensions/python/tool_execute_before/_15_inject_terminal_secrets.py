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
"""Inject terminal secrets via extra_env on LocalInteractiveSession.

Hook:   tool_execute_before  (async, priority 15)

Purpose
-------
Secrets listed in config.terminal_secrets are resolved from OpenBao and
stored in agent.context._terminal_extra_env so that the framework's
prepare_state() can pass them to LocalInteractiveSession(extra_env=...).

This scopes secrets to the subprocess environment only — they are NEVER
written to os.environ and therefore invisible to the LLM, other agents,
and any code running in the Agent Zero process.

Approach
--------
E-02 (issue #21): Store resolved secrets in agent.context._terminal_extra_env.
The framework's code_execution_tool.py prepare_state() reads this dict
and passes it to LocalInteractiveSession(extra_env=...), which builds a
clean subprocess env from _SAFE_ENV_KEYS whitelist + extra_env only.

Fallback: When the framework does not support extra_env (e.g. old version
without the patch), we fall back to the legacy os.environ injection path
for backward compatibility.

This runs AFTER _05_openbao_shell_transform (priority 05), which converts
SSsecret(KEY) placeholders to $KEY shell references.

Cleanup
-------
Injected keys are recorded in agent.context._terminal_injected_keys so that
_15_cleanup_terminal_secrets.py (tool_execute_after, priority 15) can clear
_terminal_extra_env after the tool completes.

Security
--------
- AC-01: secrets stored in agent.context._terminal_extra_env, NOT os.environ.
- AC-02: fires only when tool_name == 'code_execution_tool'.
- AC-03: sets env only when resolved value is non-None.
- AC-04: logs key name at DEBUG level; values are NEVER logged.
- AC-05: fallback to os.environ when extra_env not available (backward compat).
- Fail-open: on any exception, logs warning and does not raise.

Framework Patch Required
------------------------
plugins/_code_execution/tools/code_execution_tool.py line 127 must be
changed from:
    shell = LocalInteractiveSession(cwd=cwd)
to:
    extra_env = getattr(self.agent.context, '_terminal_extra_env', None)
    shell = LocalInteractiveSession(cwd=cwd, extra_env=extra_env)
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any

from helpers.extension import Extension

logger = logging.getLogger(__name__)

# Sentinel: if the framework sets this attribute on agent.context, we know
# extra_env is supported and we can skip the os.environ fallback.
_EXTRA_ENV_SUPPORTED_ATTR = "_terminal_extra_env_supported"


class InjectTerminalSecrets(Extension):
    """Inject config.terminal_secrets via extra_env before code_execution_tool.

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
        """Resolve terminal_secrets keys from OpenBao and stage in extra_env.

        Satisfies: AC-01, AC-02, AC-03, AC-04, AC-05
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
                self.agent.context._terminal_extra_env = None
                self.agent.context._terminal_injected_keys = []
                return

            # Read terminal_secrets list from plugin config
            terminal_keys: list[str] = _load_terminal_keys()

            if not terminal_keys:
                logger.debug(
                    "InjectTerminalSecrets: terminal_secrets is empty — nothing to inject"
                )
                self.agent.context._terminal_extra_env = None
                self.agent.context._terminal_injected_keys = []
                return

            extra_env: dict[str, str] = {}
            injected: list[str] = []

            for key in terminal_keys:
                try:
                    # AC-03: only inject when value is non-None (and not proxy sentinel)
                    value = manager.get_secret(key)
                    if value is not None and value != "proxy-a0":
                        extra_env[key] = value
                        injected.append(key)
                        # AC-04: log key name only — never log the value
                        logger.debug(
                            "InjectTerminalSecrets: staged %r in extra_env", key
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

            # AC-01: store in agent.context._terminal_extra_env, NOT os.environ
            self.agent.context._terminal_extra_env = extra_env if extra_env else None

            # AC-05: backward compat — if framework doesn't support extra_env,
            # fall back to os.environ injection (legacy path)
            if not getattr(self.agent.context, _EXTRA_ENV_SUPPORTED_ATTR, False):
                if extra_env:
                    os.environ.update(extra_env)
                    logger.debug(
                        "InjectTerminalSecrets: framework lacks extra_env support "
                        "— fell back to os.environ for %d key(s)",
                        len(extra_env),
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
                self.agent.context._terminal_extra_env = None
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
