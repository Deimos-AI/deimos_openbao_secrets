"""OpenBao-backed SecretsManager subclass.

Replaces the default .env-based SecretsManager with OpenBao KV v2 as the
primary secrets source, with graceful fallback to .env files.

See Issue #4: https://192.168.200.52:3000/deimosAI/a0-plugin-openbao-secrets/issues/4
"""
from __future__ import annotations

import logging
import threading
from typing import Dict, List, Optional, Tuple

from circuitbreaker import CircuitBreakerError
from helpers.secrets import SecretsManager, alias_for_key, DEFAULT_SECRETS_FILE
from openbao_config import OpenBaoConfig
from openbao_client import OpenBaoClient

logger = logging.getLogger(__name__)


class OpenBaoUnavailableError(RuntimeError):
    """Raised when OpenBao is unreachable and fallback is not permitted.

    Raised in ``load_secrets()`` when ``_load_from_openbao()`` returns None
    (connection failure, circuit breaker open, etc.) and
    ``config.fallback_to_env_on_error`` is ``False`` (the default — hard-fail mode).

    To suppress this error and allow graceful .env fallback, set
    ``fallback_to_env_on_error: true`` in the plugin config or via the
    ``OPENBAO_FALLBACK_TO_ENV_ON_ERROR=true`` environment variable.
    """


class OpenBaoSecretsManager(SecretsManager):
    """SecretsManager subclass backed by OpenBao KV v2.

    Preserves the full SecretsManager contract so all downstream callers
    (replace_placeholders, mask_values, StreamingSecretsFilter, etc.) work
    unchanged.

    Fallback chain:
        OpenBao KV v2 -> .env file -> empty dict (with error logging)

    Important implementation notes:
        - Declares its own _instances dict (base class shares class-level dict
          between parent and subclass in Python)
        - Overrides get_secrets_for_prompt() since base implementation calls
          read_secrets_raw() which bypasses load_secrets()
        - Thread-safe via RLock (matching parent pattern)
    """

    # Separate instance cache — base class _instances is shared across subclasses
    # in Python (class-level dict is the SAME object on parent and child).
    # Without this, OpenBaoSecretsManager.get_instance() would return a
    # SecretsManager instance from the parent's cache.
    _instances: Dict[Tuple[str, ...], "OpenBaoSecretsManager"] = {}

    def __init__(self, config: OpenBaoConfig, *files: str) -> None:
        """Initialize with OpenBao config and optional .env fallback files.

        Args:
            config: Validated OpenBaoConfig instance.
            *files: Fallback .env file paths (passed to parent).
        """
        # Initialize parent with .env file paths for fallback
        fallback_files = files if files else (DEFAULT_SECRETS_FILE,)
        super().__init__(*fallback_files)

        self._config = config
        self._bao_client: Optional[OpenBaoClient] = None
        self._bao_lock = threading.RLock()
        self._fallback_active = False

        # Initialize OpenBao client
        if config.enabled:
            try:
                self._bao_client = OpenBaoClient(config)
                if self._bao_client.is_connected():
                    logger.info("OpenBaoSecretsManager initialized with OpenBao backend")
                else:
                    logger.warning(
                        "OpenBao client created but not connected — "
                        "will fall back to .env files"
                    )
            except Exception as exc:
                logger.error(
                    "Failed to initialize OpenBao client: %s — "
                    "falling back to .env files",
                    exc,
                )
                self._bao_client = None

    @classmethod
    def get_or_create(
        cls,
        config: OpenBaoConfig,
        *files: str,
    ) -> "OpenBaoSecretsManager":
        """Get or create a singleton instance for the given config.

        Uses the OpenBao URL + mount + path as the cache key to ensure
        different configurations get different instances.

        Args:
            config: OpenBao configuration.
            *files: Fallback .env file paths.

        Returns:
            Cached or new OpenBaoSecretsManager instance.
        """
        # Use config identity as cache key (not file paths like parent)
        cache_key = (
            config.url,
            config.mount_point,
            config.secrets_path,
            config.auth_method,
        ) + tuple(files)

        if cache_key not in cls._instances:
            cls._instances[cache_key] = cls(config, *files)
        return cls._instances[cache_key]

    def is_available(self) -> bool:
        """Check if OpenBao backend is currently reachable.

        Returns:
            True if OpenBao client exists and is connected, False otherwise.
        """
        if not self._bao_client:
            return False
        return self._bao_client.is_connected()

    def load_secrets(self) -> Dict[str, str]:
        """Load secrets from OpenBao with .env fallback.

        Primary: OpenBao KV v2 via OpenBaoClient (cached with TTL).
        Fallback: super().load_secrets() (.env files) on:
            - Client not initialized
            - Connection failure
            - Circuit breaker open
            - Any unexpected error

        Returns:
            Dict mapping secret key names (uppercase) to values.
        """
        with self._lock:
            # Check parent's cache first (avoids redundant loads)
            if self._secrets_cache is not None:
                return self._secrets_cache

            secrets = self._load_from_openbao()
            if secrets is not None:
                self._secrets_cache = secrets
                if self._fallback_active:
                    logger.info("OpenBao recovered — switching back from .env fallback")
                    self._fallback_active = False
                return secrets

            # Gate fallback on opt-in flag — hard-fail by default
            if not self._config.fallback_to_env_on_error:
                raise OpenBaoUnavailableError(
                    f"OpenBao is unavailable at {self._config.url!r}. "
                    "Set fallback_to_env_on_error=true in plugin config (or via "
                    "OPENBAO_FALLBACK_TO_ENV_ON_ERROR=true env var) to allow "
                    ".env fallback, or ensure OpenBao is reachable."
                )

            # Fallback permitted (fallback_to_env_on_error=true) — use .env
            if self._config.fallback_to_env:
                if not self._fallback_active:
                    logger.warning(
                        "OpenBao unavailable — falling back to .env files"
                    )
                    self._fallback_active = True
                return self._load_from_env_fallback()

            # Fallback opted-in but fallback_to_env also disabled
            logger.error(
                "OpenBao unavailable, fallback_to_env_on_error=True but "
                "fallback_to_env=False — returning empty secrets"
            )
            return {}

    def _load_from_openbao(self) -> Optional[Dict[str, str]]:
        """Attempt to load secrets from OpenBao.

        Returns:
            Secrets dict if successful, None if OpenBao is unavailable.
        """
        if not self._bao_client:
            return None

        try:
            return self._bao_client.read_all_secrets()
        except CircuitBreakerError:
            logger.debug("Circuit breaker open — skipping OpenBao")
            return None
        except ConnectionError as exc:
            logger.debug("OpenBao connection failed: %s", exc)
            return None
        except Exception as exc:
            logger.warning("Unexpected error reading from OpenBao: %s", exc)
            return None

    def _load_from_env_fallback(self) -> Dict[str, str]:
        """Load secrets from .env files via parent implementation.

        Temporarily clears the parent's cache to force a fresh .env read.

        Returns:
            Secrets dict from .env files.
        """
        # Clear parent cache to force fresh .env read
        old_cache = self._secrets_cache
        self._secrets_cache = None
        try:
            secrets = super().load_secrets()
            # Restore our cache with the .env secrets
            self._secrets_cache = secrets
            return secrets
        except Exception as exc:
            logger.error("Failed to load .env fallback: %s", exc)
            self._secrets_cache = old_cache
            return old_cache or {}

    def get_keys(self) -> List[str]:
        """Get list of secret keys.

        Returns:
            List of uppercase secret key names.
        """
        return list(self.load_secrets().keys())

    def get_secrets_for_prompt(self) -> str:
        """Get formatted string of secret keys for system prompt.

        Overrides base implementation which calls read_secrets_raw() directly
        (bypassing load_secrets()). This version sources keys from the active
        secrets backend (OpenBao or .env fallback).

        Returns:
            Formatted string of secret aliases for the system prompt.
        """
        secrets = self.load_secrets()
        if not secrets:
            return ""

        lines = []
        for key in sorted(secrets.keys()):
            lines.append(alias_for_key(key))
        return "\n".join(lines)

    def save_secrets(self, secrets_content: str) -> None:
        """Save secrets to the default .env backend.

        OpenBao write-through is planned for a future version.
        For now, delegates to the base SecretsManager which writes
        to the .env file.
        """
        logger.info(
            "OpenBao plugin: save_secrets delegating to .env backend "
            "(OpenBao write-through not yet implemented)"
        )
        super().save_secrets(secrets_content)

    def save_secrets_with_merge(self, submitted_content: str) -> None:
        """Merge and save secrets to the default .env backend.

        OpenBao write-through is planned for a future version.
        For now, delegates to the base SecretsManager which merges
        and writes to the .env file.
        """
        logger.info(
            "OpenBao plugin: save_secrets_with_merge delegating to .env backend "
            "(OpenBao write-through not yet implemented)"
        )
        super().save_secrets_with_merge(submitted_content)

    def get_masked_secrets(self) -> str:
        """Get content with values masked for frontend display.

        Returns secrets from the active backend with values replaced
        by the mask placeholder.

        Returns:
            String of KEY="***" lines for display.
        """
        secrets = self.load_secrets()
        if not secrets:
            return ""

        lines = []
        for key in sorted(secrets.keys()):
            lines.append(f'{key}="{self.MASK_VALUE}"')
        return "\n".join(lines)

    def clear_cache(self) -> None:
        """Clear both OpenBao client cache and parent .env cache."""
        with self._lock:
            self._secrets_cache = None
            self._raw_snapshots = {}
            self._last_raw_text = None
        if self._bao_client:
            self._bao_client.invalidate_cache()
        logger.info("All secrets caches cleared")

    def health_status(self) -> Dict:
        """Get comprehensive health status for diagnostics.

        Returns:
            Dict with openbao_health, fallback_active, cache_age, config summary.
        """
        status = {
            "enabled": self._config.enabled,
            "fallback_active": self._fallback_active,
            "fallback_to_env": self._config.fallback_to_env,
            "fallback_to_env_on_error": self._config.fallback_to_env_on_error,
            "secrets_count": len(self.load_secrets()),
            "openbao": None,
            "cache_age": None,
        }

        if self._bao_client:
            status["openbao"] = self._bao_client.health_check()
            status["cache_age"] = self._bao_client.cache_age

        return status

    @classmethod
    def _invalidate_all_caches(cls) -> None:
        """Clear caches on all OpenBao manager instances."""
        for instance in cls._instances.values():
            instance.clear_cache()

    def __repr__(self) -> str:
        return (
            f"OpenBaoSecretsManager("
            f"url={self._config.url!r}, "
            f"available={self.is_available()}, "
            f"fallback={self._fallback_active})"
        )
