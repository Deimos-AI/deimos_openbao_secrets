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
"""Start the AuthProxy credential-injection daemon at agent initialisation.

Priority 10 -- runs before any other agent_init extensions so that the
proxy is listening and os.environ is populated with dummy sentinels + proxy
base URLs BEFORE the framework resolves model clients.

Design notes
------------
* The AuthProxy instance is stored at MODULE level so it persists across
  agent re-initialisation cycles (agent_init fires on every agent reset).
  The guard '_proxy is not None and _proxy.port is not None' prevents
  double-start on subsequent resets.
* The factory_common._proxy_instance reference lets factory_common.reset()
  call stop() on the proxy during full teardown.
* On startup failure the extension logs a warning and continues -- the
  framework will fall back to direct os.environ lookups (without proxying).
"""
from __future__ import annotations

import importlib.util
import logging
import os
import sys

from helpers.extension import Extension

logger = logging.getLogger(__name__)

# Module-level singleton -- survives agent reinit cycles.
_proxy = None


class StartAuthProxy(Extension):
    """Initialise the loopback auth-proxy daemon on first agent_init."""

    def execute(self, **kwargs) -> None:  # sync hook
        global _proxy

        # Guard: proxy already running -- nothing to do on re-init
        if _proxy is not None and _proxy.port is not None:
            logger.debug(
                "AuthProxy already running on port %d -- skipping re-init",
                _proxy.port,
            )
            return

        try:
            proxy_mod = self._load_auth_proxy_module()
            if proxy_mod is None:
                logger.warning(
                    "AuthProxy module not found -- credentials will NOT be proxied"
                )
                return

            _proxy = proxy_mod.AuthProxy()
            port = _proxy.start()  # blocks until listening; returns port number

            # Inject dummy sentinels + proxy base URLs into os.environ
            fc = self._get_factory_common()
            if fc is not None:
                fc._inject_proxy_env(port)
                # Register proxy so factory_common.reset() can stop it
                fc._proxy_instance = _proxy
            else:
                # Fallback: call inject directly if factory_common not yet cached
                _inject_proxy_env_fallback(port)

            logger.info(
                "AuthProxy started on 127.0.0.1:%d; os.environ populated with "
                "proxy sentinels (real keys remain in OpenBao vault)",
                port,
            )

        except Exception as exc:  # pylint: disable=broad-except
            logger.warning(
                "AuthProxy failed to start -- credentials may appear in os.environ "
                "via legacy injection path.  Error: %s",
                exc,
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_auth_proxy_module(self):
        """Dynamically load helpers/auth_proxy.py from the plugin directory."""
        _MOD_NAME = "openbao_auth_proxy"
        if _MOD_NAME in sys.modules:
            return sys.modules[_MOD_NAME]

        try:
            from helpers.plugins import find_plugin_dir
            plugin_dir = find_plugin_dir("deimos_openbao_secrets")
            if not plugin_dir:
                return None

            path = os.path.join(plugin_dir, "helpers", "auth_proxy.py")
            if not os.path.exists(path):
                logger.warning("auth_proxy.py not found at %s", path)
                return None

            spec = importlib.util.spec_from_file_location(_MOD_NAME, path)
            if spec is None:
                return None
            mod = importlib.util.module_from_spec(spec)
            sys.modules[_MOD_NAME] = mod
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            return mod

        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Failed to load auth_proxy module: %s", exc)
            return None

    def _get_factory_common(self):
        """Return the cached factory_common module, or None."""
        return sys.modules.get("openbao_secrets_factory_common")


def _inject_proxy_env_fallback(port: int) -> None:
    """Minimal proxy-env injection used when factory_common is not yet cached."""
    proxy_base = f"http://127.0.0.1:{port}"
    os.environ["OPENAI_API_KEY"] = "proxy-a0"
    os.environ["OPENAI_API_BASE"] = f"{proxy_base}/proxy/openai"
    os.environ["ANTHROPIC_API_KEY"] = "proxy-a0"
    os.environ["ANTHROPIC_BASE_URL"] = f"{proxy_base}/proxy/anthropic"
    os.environ["OPENROUTER_API_KEY"] = "proxy-a0"
    os.environ["OPENROUTER_BASE_URL"] = f"{proxy_base}/proxy/openrouter"
    logger.info(
        "Proxy env injected (fallback path): port=%d", port
    )
