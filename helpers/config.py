"""OpenBao plugin configuration: loading, validation, and defaults.

Configuration priority:
    1. Environment variables (OPENBAO_*)
    2. Settings file (settings.json in plugin directory)
    3. Dataclass defaults

Security: Credential values (role_id, secret_id, token) are NEVER logged.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

logger = logging.getLogger(__name__)

ENV_PREFIX = "OPENBAO_"
SETTINGS_FILE = "config.json"

# Fields that contain credentials — never log their values
_CREDENTIAL_FIELDS = frozenset({"role_id", "secret_id", "token"})

# Mapping from dataclass field name to environment variable suffix
_FIELD_TO_ENV: Dict[str, str] = {
    "enabled": "ENABLED",
    "url": "URL",
    "auth_method": "AUTH_METHOD",
    "role_id": "ROLE_ID",
    "secret_id": "SECRET_ID",
    "token": "TOKEN",
    "mount_point": "MOUNT_POINT",
    "secrets_path": "SECRETS_PATH",
    "vault_project_template": "PROJECT_TEMPLATE",
    "tls_verify": "TLS_VERIFY",
    "tls_ca_cert": "TLS_CA_CERT",
    "timeout": "TIMEOUT",
    "cache_ttl": "CACHE_TTL",
    "retry_attempts": "RETRY_ATTEMPTS",
    "circuit_breaker_threshold": "CB_THRESHOLD",
    "circuit_breaker_recovery": "CB_RECOVERY",
    "fallback_to_env": "FALLBACK_TO_ENV",
    "fallback_to_env_on_error": "FALLBACK_TO_ENV_ON_ERROR",
    "vault_namespace": "VAULT_NAMESPACE",
    "vault_token_file": "VAULT_TOKEN_FILE",
}

# Fields with boolean type
_BOOL_FIELDS = frozenset({"enabled", "tls_verify", "fallback_to_env", "fallback_to_env_on_error"})
# Fields with int type
_INT_FIELDS = frozenset({"cache_ttl", "retry_attempts", "circuit_breaker_threshold", "circuit_breaker_recovery"})
# Fields with float type
_FLOAT_FIELDS = frozenset({"timeout"})


@dataclass
class OpenBaoConfig:
    """Configuration for the OpenBao secrets plugin.

    Attributes:
        enabled: Whether the OpenBao backend is active.
        url: OpenBao server URL.
        auth_method: Authentication method (\"approle\" or \"token\").
        role_id: AppRole role ID (required if auth_method=\"approle\").
        secret_id: AppRole secret ID.
        token: Direct token (required if auth_method=\"token\").
        mount_point: KV v2 mount point.
        secrets_path: Path within the mount for secrets.
        vault_project_template: Vault path template for project-scoped secret overrides.
            Uses Python str.format() with {project_slug} as the substitution placeholder.
            The resolved path is checked before secrets_path when a project is active.
            Overridable via OPENBAO_PROJECT_TEMPLATE env var.
            Default: "agentzero-{project_slug}".
        tls_verify: Whether to verify TLS certificates.
        tls_ca_cert: Path to CA certificate bundle.
        timeout: HTTP request timeout in seconds.
        cache_ttl: Secrets cache time-to-live in seconds.
        retry_attempts: Maximum retry attempts for transient failures.
        circuit_breaker_threshold: Failures before circuit opens.
        circuit_breaker_recovery: Seconds before circuit half-opens.
        fallback_to_env: Fall back to .env files when OpenBao is unavailable.
        fallback_to_env_on_error: When False (default), raise OpenBaoUnavailableError on
            unavailability. When True, allow graceful .env fallback (opt-in).
    """

    enabled: bool = False
    url: str = "http://127.0.0.1:8200"
    auth_method: Literal["approle", "token"] = "token"  # REM-007: aligned with default_config.yaml
    role_id: str = ""
    secret_id: str = ""
    token: str = ""
    mount_point: str = "secret"
    secrets_path: str = "agentzero"
    vault_project_template: str = "agentzero-{project_slug}"
    tls_verify: bool = True
    tls_ca_cert: str = ""
    timeout: float = 10.0
    cache_ttl: int = 300
    retry_attempts: int = 3
    circuit_breaker_threshold: int = 5
    circuit_breaker_recovery: int = 60
    fallback_to_env: bool = True
    fallback_to_env_on_error: bool = False
    vault_namespace: str = ""
    vault_token_file: str = ""


def _parse_value(field_name: str, raw: Any) -> Any:
    """Parse a raw value into the correct type for the given field.

    Args:
        field_name: Dataclass field name.
        raw: Raw value (typically a string from env var, or native type from JSON).

    Returns:
        Value coerced to the correct type.
    """
    if field_name in _BOOL_FIELDS:
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in ("true", "1", "yes")
    if field_name in _INT_FIELDS:
        return int(raw)
    if field_name in _FLOAT_FIELDS:
        return float(raw)
    return raw


def _safe_log_field(field_name: str, value: Any, source: str) -> None:
    """Log field loading without exposing credential values."""
    if field_name in _CREDENTIAL_FIELDS:
        status = "set" if value else "empty"
        logger.info("Config %s: %s (%s)", field_name, status, source)
    else:
        logger.debug("Config %s = %r (%s)", field_name, value, source)


def load_config(plugin_dir: str = ".") -> OpenBaoConfig:
    """Load OpenBao configuration from environment variables and settings file.

    Priority: env vars > settings.json > defaults.
    Environment variables override settings file values.

    Args:
        plugin_dir: Path to the plugin directory containing settings.json.

    Returns:
        Populated OpenBaoConfig instance.
    """
    config = OpenBaoConfig()
    valid_fields = {f.name for f in fields(config)}

    # Layer 1: Load from settings.json (lower priority)
    settings_path = Path(plugin_dir) / SETTINGS_FILE
    if settings_path.exists():
        try:
            with open(settings_path, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                logger.warning("settings.json root is not a dict, ignoring")
            else:
                for key, raw_value in data.items():
                    if key not in valid_fields:
                        logger.warning("Unknown config key in settings.json: %s", key)
                        continue
                    try:
                        parsed = _parse_value(key, raw_value)
                        setattr(config, key, parsed)
                        _safe_log_field(key, parsed, "settings.json")
                    except (ValueError, TypeError) as exc:
                        logger.warning("Invalid value for %s in settings.json: %s", key, exc)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse %s: %s", settings_path, exc)
        except OSError as exc:
            logger.warning("Failed to read %s: %s", settings_path, exc)

    # Layer 2: Load from environment variables (higher priority — overwrites settings)
    for field_name, env_suffix in _FIELD_TO_ENV.items():
        env_var = f"{ENV_PREFIX}{env_suffix}"
        raw_value = os.environ.get(env_var)
        if raw_value is not None:
            try:
                parsed = _parse_value(field_name, raw_value)
                setattr(config, field_name, parsed)
                _safe_log_field(field_name, parsed, f"env:{env_var}")
            except (ValueError, TypeError) as exc:
                logger.warning("Invalid value for env %s: %s", env_var, exc)

    # Bootstrap token file takes precedence over inline vault_token
    token_file = getattr(config, 'vault_token_file', '') or ''
    if token_file:
        token_path = Path(token_file)
        if token_path.exists():
            file_token = token_path.read_text().strip()
            if file_token:
                config.token = file_token
                logger.debug("vault_token loaded from vault_token_file")
            else:
                logger.warning("vault_token_file exists but is empty — using inline vault_token")
        else:
            logger.warning("vault_token_file path not found: %s — using inline vault_token", token_file)

    return config


def validate_config(config: OpenBaoConfig) -> List[str]:
    """Validate an OpenBaoConfig instance.

    Args:
        config: Configuration to validate.

    Returns:
        List of validation error strings. Empty list means valid.
    """
    errors: List[str] = []

    # URL validation
    if not config.url.startswith(("http://", "https://")):
        errors.append("url must start with http:// or https://")

    # Auth method validation
    if config.auth_method not in ("approle", "token"):
        errors.append("auth_method must be \"approle\" or \"token\"")
    elif config.auth_method == "approle" and not config.role_id:
        errors.append("auth_method=approle requires non-empty role_id")
    elif config.auth_method == "token" and not config.token:
        errors.append("auth_method=token requires non-empty token")

    # Numeric validations
    if config.timeout <= 0:
        errors.append("timeout must be > 0")
    if config.cache_ttl < 0:
        errors.append("cache_ttl must be >= 0")
    if config.retry_attempts < 0:
        errors.append("retry_attempts must be >= 0")
    if config.circuit_breaker_threshold <= 0:
        errors.append("circuit_breaker_threshold must be > 0")
    if config.circuit_breaker_recovery <= 0:
        errors.append("circuit_breaker_recovery must be > 0")

    # TLS CA cert path validation (if specified)
    if config.tls_ca_cert and not Path(config.tls_ca_cert).exists():
        errors.append(f"tls_ca_cert path does not exist: {config.tls_ca_cert}")

    return errors


def resolve_project_path(config: OpenBaoConfig, project_slug: str) -> str:
    """Resolve the project-specific vault secrets path for the given project slug.

    Formats ``config.vault_project_template`` using Python str.format(),
    substituting ``{project_slug}`` with the provided identifier.

    This is the single canonical path resolver for the PSK (Project-Scoped Keys)
    feature. All components that need the project vault path — client, manager,
    and extensions — import and call this function. Any change to the path format
    requires exactly one edit here.

    Args:
        config: Populated OpenBaoConfig instance.
        project_slug: Project identifier derived from
            ``Path(agent.context.project).name``.
            Example: ``"deimos-openbao-project"`` from
            ``"/a0/usr/projects/deimos-openbao-project"``.

    Returns:
        Vault secrets path for the project. With the default template
        ``"agentzero-{project_slug}"`` and slug ``"deimos-openbao-project"``,
        returns ``"agentzero-deimos-openbao-project"``.

    Example::

        cfg = OpenBaoConfig()
        path = resolve_project_path(cfg, "deimos-openbao-project")
        # -> "agentzero-deimos-openbao-project"

        cfg.vault_project_template = "myorg-{project_slug}"
        path = resolve_project_path(cfg, "alpha")
        # -> "myorg-alpha"
    """
    # AC-03, AC-04: single canonical resolver — format template with project_slug
    return config.vault_project_template.format(project_slug=project_slug)
