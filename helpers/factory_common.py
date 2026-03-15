"""Shared factory logic for all three @extensible secrets hooks.

Centralises OpenBao manager creation so the three extension
entry points stay thin.

Fallback behaviour:
    When OpenBao is enabled and configured, the factory ALWAYS returns
    the OpenBaoSecretsManager — even if OpenBao is currently unreachable.
    The manager itself decides whether to fall back to .env files based
    on the `fallback_to_env` config setting.

    This prevents the framework from silently using the default .env
    manager when the user has explicitly configured OpenBao.

Environment injection:
    After creating the manager, all secrets are injected into os.environ
    so that code paths using os.getenv() directly (e.g., models.get_api_key())
    can resolve secrets from OpenBao without any upstream code changes.
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

# Module-level singleton — shared across all three factory extensions
_manager: Optional["SecretsManager"] = None
_init_lock = threading.Lock()
_init_attempted = False
_env_injected = False


def _inject_secrets_to_env(manager: "SecretsManager") -> None:
    """Inject OpenBao secrets into os.environ for direct os.getenv() consumers.

    This bridges the gap between OpenBao-backed SecretsManager and code paths
    that read API keys via os.getenv() (e.g., models.get_api_key() which calls
    dotenv.get_dotenv_value() -> os.getenv()).

    Only injects keys that are not already set in the environment to avoid
    overriding explicit env vars (e.g., from docker-compose or .env).
    """
    global _env_injected
    if _env_injected:
        return

    try:
        secrets = manager.load_secrets()
        if not secrets:
            logger.debug("No secrets to inject into environment")
            return

        injected = []
        skipped = []
        for key, value in secrets.items():
            if not value:  # Skip empty values
                continue
            if key in os.environ:
                # Don't override existing env vars — explicit env takes precedence
                skipped.append(key)
            else:
                os.environ[key] = value
                injected.append(key)

        if injected:
            logger.info(
                "Injected %d OpenBao secrets into os.environ: %s",
                len(injected),
                ", ".join(sorted(injected)),
            )
        if skipped:
            logger.debug(
                "Skipped %d keys already in env: %s",
                len(skipped),
                ", ".join(sorted(skipped)),
            )

        _env_injected = True

    except Exception as exc:
        logger.warning("Failed to inject secrets into os.environ: %s", exc)


def get_openbao_manager() -> Optional["SecretsManager"]:
    """Get or create the shared OpenBaoSecretsManager singleton.

    Returns the manager if OpenBao is enabled and configured,
    None otherwise (letting the default .env path proceed).

    When the manager IS returned, it handles fallback internally:
        - fallback_to_env=True  -> OpenBao first, then .env on failure
        - fallback_to_env=False -> OpenBao only, empty dict on failure

    After creation, injects all resolved secrets into os.environ so that
    code paths using os.getenv() directly (e.g., models.get_api_key())
    can access OpenBao secrets without upstream code changes.

    Thread-safe: uses a lock to ensure single initialization.
    """
    global _manager, _init_attempted

    if _manager is not None:
        # Fast path — already initialized and returned regardless of
        # current OpenBao availability. The manager handles fallback.
        # Ensure env injection happened (covers edge case of reset())
        _inject_secrets_to_env(_manager)
        return _manager

    if _init_attempted:
        # Already tried and failed — don't retry on every call
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
            _sp.loader.exec_module(_dm)
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
            spec.loader.exec_module(config_mod)

            config = config_mod.load_config(plugin_dir)
            errors = config_mod.validate_config(config)

            if not config.enabled:
                logger.debug("OpenBao plugin is disabled")
                return None

            if errors:
                logger.warning("OpenBao config validation errors: %s", errors)
                return None

            # Load the client and manager modules
            client_path = os.path.join(plugin_dir, "helpers", "openbao_client.py")
            spec_client = importlib.util.spec_from_file_location("openbao_client", client_path)
            if spec_client is None:
                logger.warning("Could not load client module from %s", client_path)
                return None
            client_mod = importlib.util.module_from_spec(spec_client)
            sys.modules[spec_client.name] = client_mod
            spec_client.loader.exec_module(client_mod)

            manager_path = os.path.join(plugin_dir, "helpers", "openbao_secrets_manager.py")
            spec_mgr = importlib.util.spec_from_file_location("openbao_manager", manager_path)
            if spec_mgr is None:
                logger.warning("Could not load manager module from %s", manager_path)
                return None
            mgr_mod = importlib.util.module_from_spec(spec_mgr)

            # Inject dependencies for the manager module
            # Both the logical import names AND the spec names must be in
            # sys.modules — Python 3.13's @dataclass looks up cls.__module__
            # and will fail with 'NoneType has no attribute __dict__' if the
            # module is not registered.
            sys.modules[spec_mgr.name] = mgr_mod

            spec_mgr.loader.exec_module(mgr_mod)

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
                        "OpenBao unavailable — manager will use .env fallback"
                    )
                else:
                    logger.warning(
                        "OpenBao unavailable and fallback_to_env=False — "
                        "secrets will be empty until OpenBao recovers"
                    )

            # Bridge: inject secrets into os.environ for direct os.getenv() consumers
            # This is critical for models.get_api_key() which bypasses SecretsManager
            _inject_secrets_to_env(_manager)

            return _manager

        except ImportError as exc:
            logger.warning("OpenBao plugin dependencies not installed: %s", exc)
            return None
        except Exception as exc:
            logger.error("Failed to initialize OpenBao secrets manager: %s", exc)
            return None


def reset():
    """Reset the singleton — for testing."""
    global _manager, _init_attempted, _env_injected
    with _init_lock:
        _manager = None
        _init_attempted = False
        _env_injected = False
