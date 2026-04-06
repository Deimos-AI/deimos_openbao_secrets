"""Resilient hvac client wrapper for OpenBao KV v2.

Provides connection management, AppRole/token authentication,
retry with tenacity, circuit breaker, TTL cache, and token renewal.

See Issue #3: https://192.168.200.52:3000/deimosAI/a0-plugin-openbao-secrets/issues/3
"""
from __future__ import annotations

import logging
import ssl
import threading
import time
from typing import Any, Dict, Optional, Tuple

import hvac
import hvac.exceptions
from circuitbreaker import circuit, CircuitBreakerError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    stop_after_delay,
    wait_exponential_jitter,
    before_sleep_log,
)

from openbao_config import OpenBaoConfig

logger = logging.getLogger(__name__)

# Transient errors that should trigger retry
TRANSIENT_ERRORS = (
    ConnectionError,
    TimeoutError,
    OSError,  # Covers network-level errors
    hvac.exceptions.InternalServerError,  # 500
    hvac.exceptions.VaultDown,  # 503
)

# Permanent errors that should NOT be retried
PERMANENT_ERRORS = (
    hvac.exceptions.Forbidden,  # 403
    hvac.exceptions.InvalidPath,  # 404
    hvac.exceptions.InvalidRequest,  # 400
    ssl.SSLError,  # Protocol mismatch / TLS errors — never retry
)

# Strings indicating HTTP/HTTPS protocol mismatch in error messages
_PROTOCOL_MISMATCH_MARKERS = (
    "client sent an http request to an https server",
    "wrong version number",
    "http request to https server",
)


class _TTLCache:
    """Thread-safe TTL cache for secrets dict.

    Stores a single cached value with a time-to-live.
    When TTL expires, next access returns None (cache miss).
    """

    def __init__(self, ttl_seconds: int = 300):
        self._ttl = ttl_seconds
        self._data: Optional[Dict[str, str]] = None
        self._timestamp: float = 0.0
        self._lock = threading.RLock()

    def get(self) -> Optional[Dict[str, str]]:
        """Get cached value if within TTL, else None."""
        with self._lock:
            if self._data is None:
                return None
            if self._ttl <= 0:  # TTL=0 means no caching
                return None
            age = time.monotonic() - self._timestamp
            if age >= self._ttl:
                logger.debug("Cache expired (age=%.1fs, ttl=%ds)", age, self._ttl)
                self._data = None
                return None
            return self._data.copy()

    def set(self, data: Dict[str, str]) -> None:
        """Store value with current timestamp."""
        with self._lock:
            self._data = data.copy()
            self._timestamp = time.monotonic()

    def invalidate(self) -> None:
        """Clear cached data."""
        with self._lock:
            self._data = None
            self._timestamp = 0.0

    @property
    def age(self) -> Optional[float]:
        """Seconds since last cache write, or None if empty."""
        with self._lock:
            if self._data is None:
                return None
            return time.monotonic() - self._timestamp


class OpenBaoClient:
    """Resilient hvac client with retry, circuit breaker, TTL cache, and timeout.

    Features:
        - AppRole and token authentication
        - Retry with exponential backoff + jitter (tenacity)
        - Circuit breaker for fail-fast on sustained failures (circuitbreaker)
        - TTL-based secrets cache (thread-safe)
        - Lazy token renewal on 403 / near-expiry
        - Configurable timeouts

    Usage:
        config = OpenBaoConfig(enabled=True, url="http://...", ...)
        client = OpenBaoClient(config)
        if client.is_connected():
            secrets = client.read_all_secrets()
    """

    def __init__(self, config: OpenBaoConfig) -> None:
        """Initialize client with OpenBao configuration.

        Args:
            config: Validated OpenBaoConfig instance.
        """
        self._config = config
        self._cache = _TTLCache(ttl_seconds=config.cache_ttl)
        self._lock = threading.RLock()
        self._client: Optional[hvac.Client] = None
        self._token_expiry: float = 0.0  # monotonic time when token expires

        # Build circuit breaker with config parameters
        self._circuit_breaker = circuit(
            failure_threshold=config.circuit_breaker_threshold,
            recovery_timeout=config.circuit_breaker_recovery,
            expected_exception=TRANSIENT_ERRORS,
        )

        # Initialize connection
        self._connect()

    def _connect(self) -> None:
        """Establish connection and authenticate."""
        try:
            self._client = hvac.Client(
                url=self._config.url,
                verify=self._config.tls_ca_cert if self._config.tls_ca_cert else self._config.tls_verify,
                timeout=self._config.timeout,
            )

            # Apply X-Vault-Namespace header to ALL requests when namespace is configured
            if getattr(self._config, 'vault_namespace', None):
                headers = {}
                headers['X-Vault-Namespace'] = self._config.vault_namespace
                self._client.session.headers.update(headers)

            # Layer 1: Protocol probe — detect HTTP/HTTPS mismatch before auth
            try:
                self._client.sys.read_health_status(method="GET")
            except ssl.SSLError as exc:
                logger.error(
                    "Protocol mismatch: server expects HTTPS but config has %s — %s",
                    self._config.url, exc,
                )
                self._client = None
                return
            except Exception as exc:
                err_lower = str(exc).lower()
                if any(m in err_lower for m in _PROTOCOL_MISMATCH_MARKERS):
                    logger.error(
                        "Protocol mismatch detected: %s (config URL: %s)",
                        exc, self._config.url,
                    )
                    self._client = None
                    return

            if self._config.auth_method == "approle":
                try:
                    self._auth_approle()
                except Exception as _approle_exc:
                    # HIGH-03: Do NOT silently downgrade to token auth.
                    # Silent downgrade masks misconfiguration — an operator
                    # who configured AppRole will not realise it failed and
                    # that requests are authenticated with a different
                    # method (or not authenticated at all).
                    #
                    # Dual-method fallback IS supported, but ONLY when the
                    # caller explicitly sets allow_auth_fallback=True in
                    # config — making the intent unambiguous in config.json.
                    allow_fallback = getattr(
                        self._config, "allow_auth_fallback", False
                    )
                    if allow_fallback and self._config.token:
                        logger.warning(
                            "AppRole auth failed (%s). "
                            "allow_auth_fallback=true: falling back to token auth. "
                            "Set auth_method=token explicitly for clean configuration.",
                            _approle_exc,
                        )
                        self._auth_token()
                    else:
                        logger.error(
                            "AppRole auth failed (%s). "
                            "Plugin will operate in degraded mode. "
                            "Fix AppRole credentials or set auth_method=token.",
                            _approle_exc,
                        )
                        self._client = None
                        return
            elif self._config.auth_method == "token":
                self._auth_token()

            if self._client.is_authenticated():
                logger.info("Connected to OpenBao at %s", self._config.url)
                self._update_token_expiry()
            else:
                logger.warning("Authentication failed for OpenBao at %s", self._config.url)
                self._client = None  # Layer 3: prevent token renewal cascade

        except Exception as exc:
            logger.error("Failed to connect to OpenBao at %s: %s", self._config.url, exc)
            self._client = None

    def _resolve_approle_credentials(self) -> tuple[str, str]:
        """Resolve AppRole role_id and secret_id from env > config hierarchy.

        Resolution order:
            role_id:   os.environ['OPENBAO_ROLE_ID'] > config.role_id
            secret_id: os.environ[config.secret_id_env] > file at config.secret_id_file

        Returns:
            Tuple of (role_id, secret_id) strings.

        Raises:
            RuntimeError: With clear message when role_id or secret_id cannot be resolved.

        Satisfies: AC-03, AC-04, AC-05, AC-06
        """
        import os as _os

        # AC-03: role_id: env > config
        role_id = _os.environ.get('OPENBAO_ROLE_ID') or self._config.role_id
        if not role_id:
            raise RuntimeError(
                "AppRole auth requires role_id. "
                "Set OPENBAO_ROLE_ID env var or configure via plugin settings."
            )

        # AC-04: secret_id: named env var > file path
        secret_id_env_name = getattr(self._config, 'secret_id_env', None) or 'OPENBAO_SECRET_ID'
        secret_id = _os.environ.get(secret_id_env_name)

        if not secret_id:
            secret_id_file = getattr(self._config, 'secret_id_file', '') or ''
            if secret_id_file:
                from pathlib import Path as _Path
                try:
                    secret_id = _Path(secret_id_file).read_text().strip()
                except (OSError, IOError) as exc:
                    raise RuntimeError(f"Cannot read secret_id_file: {exc}") from exc

        if not secret_id:
            raise RuntimeError(
                f"AppRole auth requires secret_id. "
                f"Set {secret_id_env_name} env var or configure secret_id_file."
            )

        return role_id, secret_id

    def _auth_approle(self) -> None:
        """Authenticate with AppRole using env>config credential resolution.

        Satisfies: AC-03, AC-04, AC-07, AC-08 (token held in memory only)
        """
        if not self._client:
            return
        try:
            role_id, secret_id = self._resolve_approle_credentials()
            # AC-04: log role_id prefix only — secret_id value NEVER logged
            safe_prefix = role_id[:8] if len(role_id) >= 8 else role_id
            logger.info("AppRole login for role_id=%s...", safe_prefix)
            result = self._client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id,
            )
            self._client.token = result["auth"]["client_token"]  # AC-08: memory only
            logger.info("AppRole authentication successful")
        except Exception as exc:
            logger.error("AppRole authentication failed: %s", exc)
            raise


    def _auth_token(self) -> None:
        """Authenticate with direct token."""
        if not self._client:
            return
        self._client.token = self._config.token
        logger.info("Token authentication configured")

    def _update_token_expiry(self) -> None:
        """Query token TTL and set expiry timestamp."""
        if not self._client:
            return
        try:
            lookup = self._client.auth.token.lookup_self()
            ttl = lookup.get("data", {}).get("ttl", 0)
            if ttl > 0:
                # Renew when 20% of TTL remains
                self._token_expiry = time.monotonic() + (ttl * 0.8)
                logger.debug("Token TTL: %ds, will renew at 80%%", ttl)
            else:
                # Root token or no expiry
                self._token_expiry = float("inf")
        except Exception as exc:
            logger.debug("Could not lookup token TTL: %s", exc)
            # Default to 1 hour if lookup fails
            self._token_expiry = time.monotonic() + 3600

    def _ensure_token_valid(self) -> None:
        """Lazily renew token if near expiry."""
        if not self._client or self._token_expiry == float("inf"):
            return

        if time.monotonic() >= self._token_expiry:
            logger.info("Token near expiry, renewing...")
            try:
                self._client.auth.token.renew_self()
                self._update_token_expiry()
                logger.info("Token renewed successfully")
            except hvac.exceptions.Forbidden:
                logger.warning("Token renewal forbidden, re-authenticating...")
                self._reconnect()
            except Exception as exc:
                logger.warning("Token renewal failed: %s, re-authenticating...", exc)
                self._reconnect()

    def _reconnect(self) -> None:
        """Re-establish connection and authentication."""
        logger.info("Reconnecting to OpenBao...")
        self._cache.invalidate()
        self._connect()

    def is_connected(self) -> bool:
        """Check if client is authenticated and OpenBao is reachable.

        Returns:
            True if connected and authenticated, False otherwise.
        """
        if not self._client:
            return False
        try:
            return self._client.is_authenticated()
        except Exception:
            return False

    def read_all_secrets(self, mount: str = "", path: str = "") -> Dict[str, str]:
        """Read all secrets from the configured KV v2 path.

        Uses TTL cache to avoid per-request API calls.
        Applies retry + circuit breaker for resilience.

        Args:
            mount: KV v2 mount point. Defaults to config.mount_point.
            path: Secrets path. Defaults to config.secrets_path.

        Returns:
            Dict mapping secret key names to their string values.

        Raises:
            CircuitBreakerError: If circuit breaker is open.
            ConnectionError: If OpenBao is unreachable after retries.
        """
        # Check cache first
        cached = self._cache.get()
        if cached is not None:
            logger.debug("Returning cached secrets (age=%.1fs)", self._cache.age)
            return cached

        # Fetch from OpenBao with resilience
        mount = mount or self._config.mount_point
        path = path or self._config.secrets_path
        secrets = self._fetch_secrets_resilient(mount, path)
        self._cache.set(secrets)
        return secrets

    def _fetch_secrets_resilient(self, mount: str, path: str) -> Dict[str, str]:
        """Fetch secrets with retry and circuit breaker.

        The circuit breaker wraps the retry logic:
        - If circuit is open, CircuitBreakerError is raised immediately
        - If circuit is closed/half-open, retries are attempted
        - Permanent errors (401/403/404) fail fast without retry
        """

        @self._circuit_breaker
        @retry(
            retry=retry_if_exception_type(TRANSIENT_ERRORS),
            stop=stop_after_attempt(self._config.retry_attempts) | stop_after_delay(30),
            wait=wait_exponential_jitter(initial=0.5, max=10),
            before_sleep=before_sleep_log(logger, logging.WARNING),
            reraise=True,
        )
        def _fetch() -> Dict[str, str]:
            self._ensure_token_valid()

            if not self._client:
                raise ConnectionError("OpenBao client not initialized")

            try:
                response = self._client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=mount,
                    raise_on_deleted_version=False,
                )
            except ssl.SSLError as exc:
                # Layer 2: Protocol errors are permanent — prevent retry cascade
                logger.error("Protocol error (permanent, not retrying): %s", exc)
                raise RuntimeError(f"Protocol mismatch: {exc}") from exc
            except hvac.exceptions.Forbidden:
                # Token may have been revoked — try re-auth once
                logger.warning("403 Forbidden, attempting re-authentication")
                self._reconnect()
                if not self._client:
                    raise ConnectionError("Re-authentication failed")
                response = self._client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=mount,
                    raise_on_deleted_version=False,
                )

            if response is None:
                logger.warning("No secrets found at %s/%s", mount, path)
                return {}

            data = response.get("data", {}).get("data", {})
            if not isinstance(data, dict):
                logger.warning("Unexpected secrets format at %s/%s: %s", mount, path, type(data))
                return {}

            # Coerce all values to strings and uppercase keys
            secrets: Dict[str, str] = {}
            for key, value in data.items():
                secrets[key.upper()] = str(value) if value is not None else ""

            logger.info("Loaded %d secrets from OpenBao (%s/%s)", len(secrets), mount, path)
            return secrets

        return _fetch()

    def read_secret(self, key: str, mount: str = "", path: str = "") -> Optional[str]:
        """Read a single secret value by key.

        Uses the cached dict from read_all_secrets().

        Args:
            key: Secret key name (case-insensitive).
            mount: KV v2 mount point. Defaults to config.mount_point.
            path: Secrets path. Defaults to config.secrets_path.

        Returns:
            Secret value string, or None if key not found.
        """
        secrets = self.read_all_secrets(mount=mount, path=path)
        return secrets.get(key.upper())

    def get_secret(self, key: str, path_override: Optional[str] = None) -> Optional[str]:
        """Read a single secret by key, optionally from a non-default vault path.

        PSK support: path_override bypasses the global TTL cache entirely.
        When None, delegates to read_secret(key) — unchanged pre-PSK behaviour.

        Args:
            key: Secret key name. Case-insensitive — normalised to uppercase.
            path_override: Vault path to read from. If None, uses global cache path.

        Returns:
            Secret value string, or None if key not found, vault path does not
            exist (InvalidPath — project not provisioned), or any error.

        Satisfies: PSK-002 AC-01, AC-02, AC-03, AC-04
        """
        if path_override is None:
            return self.read_secret(key)  # AC-02: global cache path, unchanged

        mount = self._config.mount_point
        try:
            secrets = self._fetch_secrets_resilient(mount, path_override)  # AC-01
        except hvac.exceptions.InvalidPath:
            logger.debug("PSK: project vault path not found: %s/%s", mount, path_override)
            return None  # AC-03: not provisioned is not an error
        except Exception as exc:
            logger.debug("PSK: get_secret path_override=%s failed: %s", path_override, exc)
            return None

        return secrets.get(key.upper())  # AC-04: uppercase normalisation

    def read_all_from_path(self, path: str) -> Dict[str, str]:
        """Fetch all secrets from a specific vault path without using the global cache.

        Used by the PSK masking layer to load the full project secrets dict.
        Does NOT read from or write to the global TTL cache.

        Args:
            path: Vault secrets path (e.g. "agentzero-deimos-openbao-project").

        Returns:
            Dict mapping uppercase secret key names to string values.
            Returns {} on InvalidPath, CircuitBreakerError, or any other error.

        Satisfies: PSK-002 AC-05, AC-06
        """
        mount = self._config.mount_point
        try:
            return self._fetch_secrets_resilient(mount, path)
        except hvac.exceptions.InvalidPath:
            logger.debug("PSK: read_all_from_path not found: %s/%s", mount, path)
            return {}  # AC-06
        except Exception as exc:
            logger.debug("PSK: read_all_from_path failed for path=%s: %s", path, exc)
            return {}

    def health_check(self) -> Dict[str, Any]:
        """Check OpenBao server health and seal status.

        This bypasses retry/circuit breaker since it's a diagnostic call.

        Returns:
            Dict with keys: initialized, sealed, standby, server_time_utc,
            connected, authenticated.
        """
        result: Dict[str, Any] = {
            "connected": False,
            "authenticated": False,
            "initialized": None,
            "sealed": None,
            "standby": None,
            "server_time_utc": None,
        }

        if not self._client:
            return result

        try:
            health = self._client.sys.read_health_status(method="GET")
            result["connected"] = True
            if isinstance(health, dict):
                result["initialized"] = health.get("initialized")
                result["sealed"] = health.get("sealed")
                result["standby"] = health.get("standby")
                result["server_time_utc"] = health.get("server_time_utc")
            else:
                # Health endpoint returned non-JSON (e.g., status code only)
                result["initialized"] = True
                result["sealed"] = False
        except Exception as exc:
            logger.debug("Health check failed: %s", exc)

        try:
            result["authenticated"] = self._client.is_authenticated()
        except Exception:
            pass

        return result

    def invalidate_cache(self) -> None:
        """Clear the TTL secrets cache, forcing re-fetch on next read."""
        self._cache.invalidate()
        logger.info("Secrets cache invalidated")

    @property
    def cache_age(self) -> Optional[float]:
        """Seconds since last cache write, or None if cache is empty."""
        return self._cache.age

    def close(self) -> None:
        """Close the client connection and clear cache."""
        self._cache.invalidate()
        self._client = None
        logger.info("OpenBao client closed")

    def __repr__(self) -> str:
        return (
            f"OpenBaoClient(url={self._config.url!r}, "
            f"auth={self._config.auth_method!r}, "
            f"connected={self.is_connected()})"
        )
