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

"""
Surface C \u2014 \u00a7\u00a7secret() OpenBao-first resolver (priority 05).

Hooks the already-@extensible get_secrets_manager() function in helpers/secrets.py.
When OpenBao is available, returns the OpenBaoSecretsManager instance instead of the
default .env-backed SecretsManager. This makes .env a fallback-only backend \u2014
rotation propagates instantly on the next placeholder resolution.

Bootstrapping exception (ADR-02): if OpenBao is unavailable, returns None so the
framework falls back to the default SecretsManager gracefully.

Priority 05 \u2014 fires BEFORE _10_start_auth_proxy.py so the proxy init receives
live OpenBao credentials on its first get_secrets_manager() call.

Ref: IMPLEMENTATION_PLAN.md Step 10a
"""

import logging
import sys
from typing import Optional

logger = logging.getLogger(__name__)


def _get_openbao_manager():
    """Return OpenBaoSecretsManager singleton if available, else None."""
    try:
        factory_mod = sys.modules.get("openbao_secrets_factory_common")
        if factory_mod is None:
            return None
        manager = factory_mod.get_openbao_manager()
        if manager is None:
            return None
        if not manager.is_available():
            return None
        return manager
    except Exception as exc:
        logger.debug("OpenBao manager not available: %s", exc)
        return None


class OpenBaoSecretsResolver:
    """
    agent_init extension \u2014 priority 05.

    The execute() method is a no-op; this class exists only to satisfy the
    extension loader. The real work is done by the get_secrets_manager hook
    function below, which is registered by the @extensible decorator on
    helpers.secrets.get_secrets_manager.
    """

    async def execute(self, agent, **kwargs):
        """No-op \u2014 hook registration happens at module import time."""
        pass


def get_secrets_manager(context=None, **kwargs):
    """
    @extensible hook for helpers.secrets.get_secrets_manager.

    Returns the OpenBaoSecretsManager when OpenBao is available, allowing it
    to serve as the primary secrets backend for all \u00a7\u00a7secret() resolutions.

    Returns None when:
    - Plugin is disabled
    - OpenBao is unreachable
    - Manager singleton not yet initialised

    Returning None signals the framework to proceed with the default
    .env-backed SecretsManager (graceful fallback \u2014 ADR-02).
    """
    try:
        manager = _get_openbao_manager()
        if manager is None:
            # OpenBao not available \u2014 let framework use default .env manager
            return None

        logger.debug(
            "get_secrets_manager: returning OpenBaoSecretsManager (OpenBao-first)"
        )
        return manager

    except Exception as exc:
        # Never raise from secret resolution hooks \u2014 always degrade gracefully
        logger.warning(
            "OpenBaoSecretsResolver: unexpected error in get_secrets_manager hook: %s",
            exc,
        )
        return None
