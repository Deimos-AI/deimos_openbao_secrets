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
"""Shared factory logic for all three @extensible secrets hooks.

Centralises OpenBao manager creation so the three extension
entry points stay thin.

Fallback behaviour:
    When OpenBao is enabled and configured, the factory ALWAYS returns
    the OpenBaoSecretsManager -- even if OpenBao is currently unreachable.
    The manager itself decides whether to fall back to .env files based
    on the `fallback_to_env` config setting.

    This prevents the framework from silently using the default .env
    manager when the user has explicitly configured OpenBao.

Proxy environment injection:
    Instead of placing real API key values directly into os.environ
    (which exposes them to subprocesses, LLM context, and shell history),
    _inject_proxy_env(port) installs DUMMY sentinel values and rewrites
    the relevant *_BASE_URL / *_API_BASE variables to point at the local
    AuthProxy (helpers/auth_proxy.py).  The proxy intercepts outbound API
    calls and re-attaches the real credential from OpenBao at request time
    -- the plaintext key never leaves the process heap.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from helpers.secrets import SecretsManager

logger = logging.getLogger(__name__)

# Module-level singleton -- shared across all three factory extensions
_manager: Optional["SecretsManager"] = None
_init_lock = threading.Lock()
_init_attempted = False

# AuthProxy instance -- registered by extensions/python/agent_init/_10_start_auth_proxy.py
# reset() will call stop() on it to shut down the proxy daemon gracefully.
_proxy_instance = None


def _inject_proxy_env(port: int) -> None:
    """Set dummy API key sentinels and redirect *_BASE_URL vars to local proxy.

    Called by _10_start_auth_proxy after AuthProxy binds to its port.
    Real credentials are NEVER placed in os.environ; the proxy fetches them
    from OpenBao at request time and injects them into the outbound
    Authorization / x-api-key header.

    Affected environment variables (all set on os.environ):
        OPENAI_API_KEY          -> "proxy-a0"  (dummy sentinel)
        OPENAI_API_BASE         -> http://127.0.0.1:{port}/proxy/openai
        ANTHROPIC_API_KEY       -> "proxy-a0"  (dummy sentinel)
        ANTHROPIC_BASE_URL      -> http://127.0.0.1:{port}/proxy/anthropic
        OPENROUTER_API_KEY      -> "proxy-a0"  (dummy sentinel)
        OPENROUTER_BASE_URL     -> http://127.0.0.1:{port}/proxy/openrouter
        GH_TOKEN                -> "proxy-a0"  (dummy sentinel)
    """
    proxy_base = f"http://127.0.0.1:{port}"
    os.environ["OPENAI_API_KEY"] = "proxy-a0"
    os.environ["OPENAI_API_BASE"] = f"{proxy_base}/proxy/openai"
    os.environ["ANTHROPIC_API_KEY"] = "proxy-a0"
    os.environ["ANTHROPIC_BASE_URL"] = f"{proxy_base}/proxy/anthropic"
    os.environ["OPENROUTER_API_KEY"] = "proxy-a0"
    os.environ["OPENROUTER_BASE_URL"] = f"{proxy_base}/proxy/openrouter"
    os.environ["GH_TOKEN"] = "proxy-a0"
    logger.info(
        "Proxy env injected: port=%d  "
        "(real keys remain in OpenBao vault, not in os.environ)",
        port,
    )


def get_openbao_manager() -> Optional["SecretsManager"]:
    """Get or create the shared OpenBaoSecretsManager singleton.

    Returns the manager if OpenBao is enabled and configured,
    None otherwise (letting the default .env path proceed).

    When the manager IS returned, it handles fallback internally:
        - fallback_to_env=True  -> OpenBao first, then .env on failure
        - fallback_to_env=False -> OpenBao only, empty dict on failure

    Thread-safe: uses a lock to ensure single initialization.
    """
    global _manager, _init_attempted

    if _manager is not None:
        # Fast path -- already initialized.
        return _manager

    if _init_attempted:
        # Already tried and failed -- don't retry on every call.
        return None

    with _init_lock:
        # Double-check after acquiring lock
        if _manager is not None:
            return _manager
        if _init_attempted:
            return None

        _init_attempted = True

        try:
            # Auto-install dependencies (hvac, tenacity, circuitbreaker)
            from helpers.deps import ensure_dependencies as _ensure_deps
        except ImportError:
            # If helpers.deps can't be imported, try via plugin dir
            import importlib.util as _ilu
            _dp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deps.py")
            _sp = _ilu.spec_from_file_location("openbao_deps", _dp)
            if _sp is None:
                logger.warning("Could not find deps.py at %s", _dp)
                return None
            _dm = _ilu.module_from_spec(_sp)
            sys.modules[_sp.name] = _dm
            try:
                _sp.loader.exec_module(_dm)
            except Exception as e:
                sys.modules.pop(_sp.name, None)
                logger.warning("Failed to load deps module: %s", e)
                return None
            _ensure_deps = _dm.ensure_dependencies

        if not _ensure_deps():
            logger.warning("OpenBao plugin dependencies not available")
            return None

        try:
            from helpers.plugins import find_plugin_dir
            from helpers.secrets import DEFAULT_SECRETS_FILE

            # Find our plugin directory for settings.json
            plugin_dir = find_plugin_dir("deimos_openbao_secrets")
            if not plugin_dir:
                logger.debug("deimos_openbao_secrets plugin directory not found")
                return None

            # Load and validate config
            import importlib.util

            config_path = os.path.join(plugin_dir, "helpers", "config.py")
            spec = importlib.util.spec_from_file_location("openbao_config", config_path)
            if spec is None:
                logger.warning("Could not load config module from %s", config_path)
                return None
            config_mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = config_mod  # Required for @dataclass in Python 3.13+
            try:
                spec.loader.exec_module(config_mod)
            except Exception as e:
                sys.modules.pop(spec.name, None)
                logger.warning("Failed to load config module: %s", e)
                return None

            config = config_mod.load_config(plugin_dir)
            errors = config_mod.validate_config(config)

            if not config.enabled:
                logger.debug("OpenBao plugin is disabled")
                return None

            if errors:
                logger.warning("OpenBao config validation errors: %s", errors)
                return None

            # Load the client module
            client_path = os.path.join(plugin_dir, "helpers", "openbao_client.py")
            spec_client = importlib.util.spec_from_file_location("openbao_client", client_path)
            if spec_client is None:
                logger.warning("Could not load client module from %s", client_path)
                return None
            client_mod = importlib.util.module_from_spec(spec_client)
            sys.modules[spec_client.name] = client_mod
            try:
                spec_client.loader.exec_module(client_mod)
            except Exception as e:
                sys.modules.pop(spec_client.name, None)
                logger.warning("Failed to load client module: %s", e)
                return None

            # Load the manager module
            manager_path = os.path.join(plugin_dir, "helpers", "openbao_secrets_manager.py")
            spec_mgr = importlib.util.spec_from_file_location("openbao_manager", manager_path)
            if spec_mgr is None:
                logger.warning("Could not load manager module from %s", manager_path)
                return None
            mgr_mod = importlib.util.module_from_spec(spec_mgr)
            # Both the logical import names AND the spec names must be in sys.modules --
            # Python 3.13's @dataclass looks up cls.__module__ and will fail with
            # 'NoneType has no attribute __dict__' if the module is not registered.
            sys.modules[spec_mgr.name] = mgr_mod
            try:
                spec_mgr.loader.exec_module(mgr_mod)
            except Exception as e:
                sys.modules.pop(spec_mgr.name, None)
                logger.warning("Failed to load manager module: %s", e)
                return None

            _manager = mgr_mod.OpenBaoSecretsManager.get_or_create(
                config, DEFAULT_SECRETS_FILE
            )

            # ALWAYS return the manager when enabled+configured.
            # The manager handles fallback_to_env internally:
            #   - True:  load_secrets() falls back to .env on OpenBao failure
            #   - False: load_secrets() returns empty dict on OpenBao failure
            if _manager.is_available():
                logger.info("OpenBao secrets manager active (connected)")
            else:
                if config.fallback_to_env:
                    logger.warning(
                        "OpenBao unavailable -- manager will use .env fallback"
                    )
                else:
                    logger.warning(
                        "OpenBao unavailable and fallback_to_env=False -- "
                        "secrets will be empty until OpenBao recovers"
                    )

            return _manager

        except ImportError as exc:
            logger.warning("OpenBao plugin dependencies not installed: %s", exc)
            return None
        except Exception as exc:
            logger.error("Failed to initialize OpenBao secrets manager: %s", exc)
            return None


def reset() -> None:
    """Reset the singleton -- for testing or explicit teardown.

    Also stops the AuthProxy daemon if one was registered by
    _10_start_auth_proxy (stored in the module-level _proxy_instance).
    """
    global _manager, _init_attempted, _proxy_instance
    with _init_lock:
        # Stop the auth proxy daemon if one is running
        if _proxy_instance is not None:
            try:
                _proxy_instance.stop()
                logger.debug("AuthProxy stopped via factory_common.reset()")
            except Exception as exc:
                logger.debug("AuthProxy stop error during reset: %s", exc)
            _proxy_instance = None

        _manager = None
        _init_attempted = False


# ---------------------------------------------------------------------------
# Secret resolution for non-proxy contexts
# ---------------------------------------------------------------------------
# Use resolve_secret() for any context that is NOT an LLM API call
# (git, HTTP APIs, direct tool use). Do not fetch from OpenBao directly.


def resolve_secret(key: str, project_slug: Optional[str] = None) -> Optional[str]:
    """Resolve the real value of a secret for non-proxy contexts.

    Use resolve_secret() for any context that is NOT an LLM API call
    (git, HTTP APIs, direct tool use). Do not fetch from OpenBao directly.

    Resolution order (AC-01 through AC-05):
      1. OpenBao via get_openbao_manager().get_secret(key, project_slug)
         - project_slug set => PSK project-first / global-fallback (AC-02)
         - sentinel 'proxy-a0' treated as absent (AC-05)
      2. os.environ fallback (.env backend) if OpenBao unavailable (AC-03)
         - sentinel 'proxy-a0' treated as absent (AC-05)
      3. None if key absent from all backends (AC-04)

    Args:
        key: Secret key name, e.g. 'GH_TOKEN'.
        project_slug: Optional project slug for PSK two-tier resolution (AC-02).

    Returns:
        Real secret value or None.  Never returns 'proxy-a0' (AC-05).

    Satisfies: resolve_secret AC-01 through AC-05
    """
    # AC-01: OpenBao primary resolution path
    try:
        manager = get_openbao_manager()
        if manager is not None:
            value = manager.get_secret(key, project_slug=project_slug)  # AC-02
            if value is not None and value != "proxy-a0":               # AC-05
                return value
    except Exception as exc:
        logger.debug("resolve_secret OpenBao lookup failed for %r: %s", key, exc)

    # AC-03: os.environ fallback (.env backend)
    env_value = os.environ.get(key)
    if env_value is not None and env_value != "proxy-a0":              # AC-05
        return env_value

    # AC-04: key absent from all backends
    return None
