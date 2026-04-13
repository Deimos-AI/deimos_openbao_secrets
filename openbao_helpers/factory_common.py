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
    on the ``fallback_to_env`` config setting.

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

Transient failure retry (F-09 fix):
    _attempt_init() classifies failures as PERMANENT or TRANSIENT.
    Permanent failures (deps missing, plugin not found, plugin disabled)
    immediately lock out the factory via _init_attempted=True.
    Transient failures (config validation, module loading, network errors)
    trigger an internal retry loop with exponential backoff, up to
    _MAX_RETRIES attempts (default 3, configurable via env var
    OPENBAO_FACTORY_MAX_RETRIES).
"""
from __future__ import annotations

import importlib.util
import logging
import os
import sys
import threading
import time
from typing import Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from helpers.secrets import SecretsManager

logger = logging.getLogger(__name__)

# Module-level singleton -- shared across all three factory extensions
_init_lock = threading.Lock()
_manager: "Optional[SecretsManager]" = None  # CR-1: must be at module level for NameError-free first call
_locked_at: float = 0.0  # monotonic timestamp when factory was locked (0 = unlocked)
_is_permanent: bool = False  # True = permanent lock (deps missing, plugin disabled)
_retry_count = 0
_MAX_RETRIES = int(os.environ.get("OPENBAO_FACTORY_MAX_RETRIES", "3"))
_RETRY_BACKOFF_BASE = float(os.environ.get("OPENBAO_FACTORY_RETRY_BACKOFF", "1.0"))
_TRANSIENT_TTL = float(os.environ.get("OPENBAO_FACTORY_TRANSIENT_TTL", "60"))  # F-09: auto-expiry for transient locks (seconds)

# AuthProxy instance -- registered by extensions/python/agent_init/_10_start_auth_proxy.py
# reset() will call stop() on it to shut down the proxy daemon gracefully.
_proxy_instance = None


def _is_locked() -> bool:
    """Check if the factory is currently locked out.

    AC-06 (F-09 fix): Transient lockouts auto-expire after _TRANSIENT_TTL seconds.
    Permanent lockouts stay locked until process restart or reset().

    Returns:
        True if factory is locked (and TTL has not expired for transient locks).
    """
    if _locked_at == 0.0:
        return False
    if _is_permanent:
        return True
    # Transient lock: check TTL expiry
    elapsed = time.monotonic() - _locked_at
    if elapsed >= _TRANSIENT_TTL:
        # Auto-expire — allow retry
        return False
    return True



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
    """
    proxy_base = f"http://127.0.0.1:{port}"
    os.environ["OPENAI_API_KEY"] = "proxy-a0"
    os.environ["OPENAI_API_BASE"] = f"{proxy_base}/proxy/openai"
    os.environ["ANTHROPIC_API_KEY"] = "proxy-a0"
    os.environ["ANTHROPIC_BASE_URL"] = f"{proxy_base}/proxy/anthropic"
    os.environ["OPENROUTER_API_KEY"] = "proxy-a0"
    os.environ["OPENROUTER_BASE_URL"] = f"{proxy_base}/proxy/openrouter"
    logger.info(
        "Proxy env injected: port=%d  "
        "(real keys remain in OpenBao vault, not in os.environ)",
        port,
    )


def _attempt_init() -> Tuple[Optional["SecretsManager"], bool]:
    """Attempt a single manager initialization.

    Returns:
        (manager_or_none, is_permanent) — is_permanent is True only for
        failures that will never succeed on retry (deps missing, plugin
        disabled, plugin not found).  All other failures are transient.
    """
    # --- Auto-install dependencies (hvac, tenacity, circuitbreaker) ---
    try:
        from openbao_helpers.deps import ensure_dependencies as _ensure_deps
    except ImportError:
        import importlib.util as _ilu
        _dp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deps.py")
        _sp = _ilu.spec_from_file_location("openbao_deps", _dp)
        if _sp is None:
            logger.warning("Could not find deps.py at %s", _dp)
            return None, False
        _dm = _ilu.module_from_spec(_sp)
        sys.modules[_sp.name] = _dm
        try:
            _sp.loader.exec_module(_dm)
        except Exception as e:
            sys.modules.pop(_sp.name, None)
            logger.warning("Failed to load deps module: %s", e)
            return None, False
        _ensure_deps = _dm.ensure_dependencies

    if not _ensure_deps():
        logger.warning("OpenBao plugin dependencies not available")
        return None, True  # permanent — deps missing

    try:
        from helpers.plugins import find_plugin_dir
        from helpers.secrets import DEFAULT_SECRETS_FILE

        # Find our plugin directory for settings.json
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            logger.debug("deimos_openbao_secrets plugin directory not found")
            return None, True  # permanent — plugin not installed

        # Load and validate config
        config_path = os.path.join(plugin_dir, "openbao_helpers", "config.py")
        spec = importlib.util.spec_from_file_location("openbao_config", config_path)
        if spec is None:
            logger.warning("Could not load config module from %s", config_path)
            return None, False  # transient — module load issue
        config_mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = config_mod  # Required for @dataclass in Python 3.13+
        try:
            spec.loader.exec_module(config_mod)
        except Exception as e:
            sys.modules.pop(spec.name, None)
            logger.warning("Failed to load config module: %s", e)
            return None, False  # transient — module load issue

        config = config_mod.load_config(plugin_dir)
        errors = config_mod.validate_config(config)

        if not config.enabled:
            logger.debug("OpenBao plugin is disabled")
            return None, True  # permanent — explicitly disabled

        if errors:
            logger.warning("OpenBao config validation errors: %s", errors)
            return None, False  # F-09: transient — env vars may not be propagated yet

        # Load the client module
        client_path = os.path.join(plugin_dir, "openbao_helpers", "openbao_client.py")
        spec_client = importlib.util.spec_from_file_location("openbao_client", client_path)
        if spec_client is None:
            logger.warning("Could not load client module from %s", client_path)
            return None, False  # transient
        client_mod = importlib.util.module_from_spec(spec_client)
        sys.modules[spec_client.name] = client_mod
        try:
            spec_client.loader.exec_module(client_mod)
        except Exception as e:
            sys.modules.pop(spec_client.name, None)
            logger.warning("Failed to load client module: %s", e)
            return None, False  # transient

        # Load the manager module
        manager_path = os.path.join(plugin_dir, "openbao_helpers", "openbao_secrets_manager.py")
        spec_mgr = importlib.util.spec_from_file_location("openbao_manager", manager_path)
        if spec_mgr is None:
            logger.warning("Could not load manager module from %s", manager_path)
            return None, False  # transient
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
            return None, False  # transient

        manager = mgr_mod.OpenBaoSecretsManager.get_or_create(
            config, DEFAULT_SECRETS_FILE
        )

        # ALWAYS return the manager when enabled+configured.
        # The manager handles fallback_to_env internally:
        #   - True:  load_secrets() falls back to .env on OpenBao failure
        #   - False: load_secrets() returns empty dict on OpenBao failure
        if manager.is_available():
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

        return manager, False  # success — is_permanent is irrelevant

    except ImportError as exc:
        logger.warning("OpenBao plugin dependencies not installed: %s", exc)
        return None, False  # transient — may succeed after env fix
    except Exception as exc:
        logger.error("Failed to initialize OpenBao secrets manager: %s", exc)
        return None, False  # transient — network / runtime error


def get_openbao_manager() -> Optional["SecretsManager"]:
    """Get or create the shared OpenBaoSecretsManager singleton.

    Returns the manager if OpenBao is enabled and configured,
    None otherwise (letting the default .env path proceed).

    When the manager IS returned, it handles fallback internally:
        - fallback_to_env=True  -> OpenBao first, then .env on failure
        - fallback_to_env=False -> OpenBao only, empty dict on failure

    Thread-safe: uses a lock to ensure single initialization.

    F-09 retry: transient init failures are retried up to _MAX_RETRIES
    with exponential backoff.  Only permanent failures (deps missing,
    plugin not found, plugin disabled) lock out the factory immediately.
    """
    global _manager, _locked_at, _is_permanent, _retry_count

    if _manager is not None:
        # Fast path -- already initialized.
        return _manager

    if _is_locked():
        # AC-06: F-09 fix — transient failures auto-expire after _TRANSIENT_TTL seconds.
        # Permanent failures stay locked until process restart or reset().
        return None

    with _init_lock:
        # Double-check after acquiring lock
        if _manager is not None:
            return _manager
        if _is_locked():
            return None

        # CR-2: If TTL expired, _retry_count is still at _MAX_RETRIES and the while
        # loop below would never run. Reset both so auto-retry actually executes.
        if _locked_at != 0.0 and not _is_permanent:
            _locked_at = 0.0
            _retry_count = 0

        while _retry_count < _MAX_RETRIES:
            manager, is_permanent = _attempt_init()

            if manager is not None:
                # Success — store singleton and mark complete
                _manager = manager
                _locked_at = 0.0  # unlocked
                _is_permanent = False
                _retry_count = 0
                return _manager

            if is_permanent:
                # Permanent failure — lock out permanently
                _locked_at = time.monotonic()
                _is_permanent = True
                logger.debug(
                    "Permanent init failure — factory locked (attempt %d/%d)",
                    _retry_count + 1, _MAX_RETRIES,
                )
                return None

            # Transient failure — retry with exponential backoff
            _retry_count += 1
            if _retry_count < _MAX_RETRIES:
                backoff = _RETRY_BACKOFF_BASE * (2 ** (_retry_count - 1))
                logger.info(
                    "Transient init failure — retrying in %.1fs (attempt %d/%d)",
                    backoff, _retry_count + 1, _MAX_RETRIES,
                )
                time.sleep(backoff)
            else:
                # Exhausted retries — transient lock with TTL (F-09 fix)
                _locked_at = time.monotonic()
                _is_permanent = False
                logger.warning(
                    "Transient init failures exhausted %d retries — "
                    "factory locked for %ds. Auto-retry after expiry or call reset().",
                    _MAX_RETRIES, _TRANSIENT_TTL,
                )

        return None


def reset() -> None:
    """Reset the singleton -- for testing or explicit teardown.

    Also stops the AuthProxy daemon if one was registered by
    _10_start_auth_proxy (stored in the module-level _proxy_instance).
    """
    global _manager, _locked_at, _is_permanent, _retry_count, _proxy_instance
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
        _locked_at = 0.0
        _is_permanent = False
        _retry_count = 0


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
