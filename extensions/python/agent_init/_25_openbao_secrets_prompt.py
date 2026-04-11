"""E-07: Least-privilege secrets prompt injection — priority 25.

Hooks the @extensible build_prompt() function in
/a0/extensions/python/system_prompt/_13_secrets_prompt.py.

When OpenBao is active, substitutes the plugin's
prompts/agent.system.secrets.md for the framework's default
agent.system.secrets.md.

The custom prompt uses the {{secrets}} slot which is already
populated with vault key names (not resolver aliases) by the
overridden OpenBaoSecretsManager.get_secrets_for_prompt().

Fallback: if OpenBao is inactive/unavailable, returns None so
the framework uses its default secrets prompt behaviour.

Satisfies: E-07 AC-05, AC-06, AC-07, AC-08
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from helpers.extension import Extension

logger = logging.getLogger(__name__)

_PLUGIN_DIR = Path(__file__).resolve().parent.parent.parent.parent
_CUSTOM_PROMPT = _PLUGIN_DIR / "prompts" / "agent.system.secrets.md"


class OpenBaoSecretsPrompt(Extension):
    """agent_init extension — priority 25.

    The execute() method is a no-op; this class exists only to satisfy the
    extension loader. The real work is done by the build_prompt hook function
    below, registered via the @extensible decorator on the framework's
    build_prompt in _13_secrets_prompt.py.
    """

    async def execute(self, agent: Any = None, **kwargs: Any) -> None:
        """No-op — hook registration happens at module import time."""
        pass


def _is_openbao_active() -> bool:
    """Return True when the OpenBao manager singleton is initialised and available.

    Satisfies: E-07 AC-08 (fallback when plugin inactive)
    """
    try:
        fc = sys.modules.get("openbao_secrets_factory_common")
        if fc is None:
            return False
        manager = fc.get_openbao_manager()
        return manager is not None and manager.is_available()
    except Exception as exc:
        logger.debug("_is_openbao_active: check failed: %s", exc)
        return False


async def build_prompt(agent: Any, **kwargs: Any) -> str | None:  # type: ignore[override]
    """@extensible hook for build_prompt in _13_secrets_prompt.py.

    When OpenBao is active and the custom prompt file exists, reads the
    plugin's prompts/agent.system.secrets.md and renders it with the
    vault key names populated by get_secrets_for_prompt().

    Returns None when:
    - OpenBao is inactive or unavailable (AC-08: use framework default)
    - Custom prompt file not found (fail-open: use framework default)
    - Any exception (fail-open: never block agent init)

    Satisfies: E-07 AC-07, AC-08
    """
    try:
        if not _is_openbao_active():  # AC-08: plugin inactive → framework default
            return None

        if not _CUSTOM_PROMPT.exists():  # AC-05: prompt file must exist
            logger.warning("E-07: custom prompt not found at %s — using default",
                           _CUSTOM_PROMPT)
            return None

        from helpers.secrets import get_secrets_manager
        from helpers.settings import get_settings

        secrets_manager = get_secrets_manager(agent.context)
        secrets = secrets_manager.get_secrets_for_prompt()  # AC-01, AC-02: key names only
        variables = get_settings()["variables"]

        # AC-07: read plugin prompt file instead of framework default
        result = agent.read_prompt(
            str(_CUSTOM_PROMPT), secrets=secrets, vars=variables
        )
        logger.debug("E-07: OpenBao secrets prompt substituted (keys: %s)",
                     secrets[:50] if secrets else "<empty>")
        return result

    except Exception as exc:  # pragma: no cover
        logger.warning("E-07: build_prompt hook failed: %s — using default", exc)
        return None  # Fail-open: never block agent init
