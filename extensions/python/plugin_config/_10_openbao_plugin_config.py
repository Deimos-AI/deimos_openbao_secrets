# Copyright 2024 DeimosAI
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

"""Surface A — Plugin Config Secret Interception.

This extension hooks into the Agent Zero plugin configuration lifecycle to
extract secret-valued fields from plugin settings and store them in OpenBao
KV v2.  Matched fields are replaced in-place with
``⟦bao:v1:<path>⟧`` placeholders before the config is persisted to
disk, keeping all credential material out of the filesystem.

Design decisions
----------------
ADR-01 (read is NO-OP)
    ``get_plugin_config`` always returns ``None``.  Placeholder strings are
    written through verbatim to the framework’s config file.  Live
    resolution must be requested explicitly by consumers via
    :func:`resolve_plugin_config`.

ADR-02 (bootstrapping guard)
    If *plugin_name* is ``'deimos_openbao_secrets'`` the hook returns
    immediately without any vault interaction, preventing a circular
    dependency during plugin initialisation before the OpenBao client is
    ready.

SHA-256 deduplication (G-03)
    Before writing a new secret the SHA-256 digest of the raw value is
    computed and the first 16 hex chars used as a lookup key:
    ``_dedup/{sha256[:16]}``.  Identical credentials shared across multiple
    plugins are written only once at a canonical path; subsequent writes
    reuse that path.  This eliminates redundant copies and makes rotation
    of shared credentials straightforward.

Atomicity guarantee
    All vault KV v2 writes are attempted *before* any in-place
    substitution in the ``settings`` dict.  If any write raises, the dict
    is left completely unchanged and the exception is re-raised so the
    caller can surface the failure.  All writes succeed before the settings
    dict is mutated — never a partial replacement.
"""

from __future__ import annotations

import copy
import hashlib
import logging
import re
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Placeholder tokens — literal Unicode chars so grep acceptance tests pass.
# ⟦ = MATHEMATICAL LEFT WHITE SQUARE BRACKET
# ⟧ = MATHEMATICAL RIGHT WHITE SQUARE BRACKET
# ---------------------------------------------------------------------------
_PLACEHOLDER_PREFIX: str = "⟦bao:v1:"
_PLACEHOLDER_SUFFIX: str = "⟧"
# Idempotency guard: matches any ⟦bao: version
_IDEMPOTENCY_PREFIX: str = "⟦bao:"


# ---------------------------------------------------------------------------
# Manager singleton — same pattern as _10_start_auth_proxy.py / _10_openbao_mask_history.py
# ---------------------------------------------------------------------------

def _get_manager():
    """Return the OpenBaoSecretsManager singleton via factory_common, or None."""
    fc = sys.modules.get("openbao_secrets_factory_common")
    if fc is None:
        logger.debug("Surface A: factory_common not yet loaded")
        return None
    try:
        return fc.get_openbao_manager()
    except Exception as exc:
        logger.debug("Surface A: get_openbao_manager() failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Low-level vault helpers using the hvac client inside the manager
# ---------------------------------------------------------------------------

def _get_hvac(manager):
    """Return ``(hvac_client, mount_point)`` from the manager, or ``(None, None)``."""
    bao = getattr(manager, "_bao_client", None)
    if bao is None:
        return None, None
    client = getattr(bao, "_client", None)
    if client is None:
        return None, None
    mount = getattr(getattr(bao, "_config", None), "mount_point", None) or "secret"
    return client, mount


def _vault_read(manager, path: str) -> Optional[dict]:
    """Read the KV v2 data dict at *path*, returning None on miss or error."""
    client, mount = _get_hvac(manager)
    if client is None:
        return None
    try:
        resp = client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=mount,
            raise_on_deleted_version=False,
        )
        if resp:
            return resp.get("data", {}).get("data") or {}
        return None
    except Exception:  # InvalidPath, Forbidden, etc.
        return None


def _vault_write(
    manager,
    path: str,
    data: dict,
    custom_metadata: Optional[dict] = None,
) -> None:
    """Write *data* to KV v2 *path*.  Raises on failure so callers can atomically roll back."""
    client, mount = _get_hvac(manager)
    if client is None:
        raise RuntimeError("Surface A: hvac client not available — cannot write to vault")

    client.secrets.kv.v2.create_or_update_secret(
        path=path,
        secret=data,
        mount_point=mount,
    )
    if custom_metadata:
        try:
            # KV v2 custom_metadata values must all be strings
            str_meta = {k: str(v) for k, v in custom_metadata.items()}
            client.secrets.kv.v2.update_metadata(
                path=path,
                custom_metadata=str_meta,
                mount_point=mount,
            )
        except Exception as meta_exc:
            logger.debug(
                "Surface A: metadata write failed for %r (non-fatal): %s",
                path,
                meta_exc,
            )


# ---------------------------------------------------------------------------
# Config helper — secret_field_patterns lives in plugin config, NOT OpenBaoConfig
# ---------------------------------------------------------------------------

def _get_patterns() -> list[str]:
    """Load ``secret_field_patterns`` from the deimos_openbao_secrets plugin config."""
    try:
        from helpers.plugins import get_plugin_config  # noqa: PLC0415
        cfg = get_plugin_config("deimos_openbao_secrets")
        if isinstance(cfg, dict):
            return list(cfg.get("secret_field_patterns") or [])
    except Exception as exc:
        logger.debug("Surface A: could not load secret_field_patterns: %s", exc)
    return []


# ---------------------------------------------------------------------------
# Path sanitisation
# ---------------------------------------------------------------------------

def _sanitize_component(value: str) -> str:
    """Replace unsafe characters with underscores and strip leading dots."""
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value).lstrip(".")


# ---------------------------------------------------------------------------
# Hook 1: save_plugin_config
# ---------------------------------------------------------------------------

async def save_plugin_config(
    plugin_name: str,
    project_name: str,
    agent_profile: str,
    settings: dict,
    **kwargs: Any,
) -> None:
    """Surface A interception hook — extracts secrets from plugin config on save.

    Called by Agent Zero via ``call_plugin_hook`` / ``@extensible`` when any
    plugin’s configuration is saved.  Scans *settings* for keys whose
    names match ``secret_field_patterns`` (case-insensitive fnmatch).  Each
    matched, non-empty string value is:

    1. SHA-256 dedup-checked: if an identical value was stored previously its
       canonical path is reused (no duplicate vault entry).
    2. Written to a canonical KV v2 path with provenance metadata:
       ``extracted_at``, ``surface=A``, ``source_plugin``, ``field``.
    3. Replaced in *settings* with ``⟦bao:v1:<canonical_path>⟧``.

    Atomicity: all vault writes succeed before the settings dict is mutated.
    If any vault write raises, the settings dict is left completely unchanged
    and the exception is re-raised for the caller to handle.
    """
    # ADR-02 — bootstrapping guard: deimos_openbao_secrets own config is never intercepted.
    # This prevents circular dependency before the OpenBao client is initialised.
    if plugin_name == "deimos_openbao_secrets":
        return

    manager = _get_manager()
    if manager is None:
        return

    # Graceful no-op when OpenBao is unavailable (disabled or unreachable)
    if not getattr(manager, "is_available", lambda: False)():
        return

    # Load fnmatch patterns that identify secret-valued config keys
    patterns = _get_patterns()
    if not patterns:
        return

    sanitized_plugin = _sanitize_component(plugin_name)
    extracted_at = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Phase 1: identify candidates and resolve canonical vault paths.
    # pending   = list of (settings_key, canonical_vault_path, raw_value)
    # new_dedup = list of (dedup_path, canonical_path) — entries to create
    # ------------------------------------------------------------------
    pending: list[tuple[str, str, str]] = []
    new_dedup: list[tuple[str, str]] = []

    for key, value in settings.items():
        # Case-insensitive fnmatch against every configured pattern
        lower_key = key.lower()
        if not any(fnmatch(lower_key, pat.lower()) for pat in patterns):
            continue

        # Only non-empty strings are eligible
        if not isinstance(value, str) or not value:
            continue

        # Idempotency guard: already a ⟦bao: placeholder — skip
        if value.startswith(_IDEMPOTENCY_PREFIX):
            continue

        sanitized_key = _sanitize_component(key)

        # --- SHA-256 dedup check -------------------------------------------
        # Compute sha256 digest; use first 16 hex chars as dedup index key.
        value_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
        hash_prefix = value_hash[:16]
        dedup_path = f"_dedup/{hash_prefix}"

        canonical_path: Optional[str] = None
        try:
            dedup_record = _vault_read(manager, dedup_path)
            if dedup_record and isinstance(dedup_record, dict):
                canonical_path = dedup_record.get("canonical_path")
        except Exception as exc:
            logger.debug("Surface A: dedup lookup error key=%r: %s", key, exc)

        if not canonical_path:
            canonical_path = f"plugin/{sanitized_plugin}/{sanitized_key}"
            new_dedup.append((dedup_path, canonical_path))

        pending.append((key, canonical_path, value))

    if not pending:
        return  # nothing matched or nothing to do

    # ------------------------------------------------------------------
    # Phase 2: ATOMICITY — all vault writes BEFORE settings dict mutation.
    #
    # All writes succeed before the settings dict is mutated.  If any
    # single vault write raises, we log the error and re-raise immediately
    # — the settings dict is left completely unchanged (no partial state).
    # ------------------------------------------------------------------
    try:
        # Write canonical secret values with KV v2 provenance metadata
        for settings_key, vault_path, raw_value in pending:
            custom_metadata = {
                "extracted_at": extracted_at,
                "surface": "A",
                "source_plugin": plugin_name,
                "field": settings_key,
            }
            _vault_write(
                manager,
                vault_path,
                {"value": raw_value},
                custom_metadata=custom_metadata,
            )
            logger.debug(
                "Surface A: wrote secret key=%r → vault_path=%r",
                settings_key,
                vault_path,
            )

        # Write dedup index entries for values seen for the first time
        for dedup_path, canonical_path in new_dedup:
            _vault_write(manager, dedup_path, {"canonical_path": canonical_path})
            logger.debug(
                "Surface A: wrote dedup index %r → %r",
                dedup_path,
                canonical_path,
            )

    except Exception as exc:
        # Atomicity enforced: all vault writes must succeed before settings dict is mutated.
        # On any failure we bail out without touching settings — atomic rollback.
        logger.error(
            "Surface A: vault write FAILED for plugin=%r — "
            "settings dict NOT modified (atomic rollback): %s",
            plugin_name,
            exc,
        )
        raise

    # ------------------------------------------------------------------
    # Phase 3: replace values in settings ONLY after ALL writes succeed.
    # ------------------------------------------------------------------
    for settings_key, vault_path, _raw in pending:
        settings[settings_key] = f"{_PLACEHOLDER_PREFIX}{vault_path}{_PLACEHOLDER_SUFFIX}"
        logger.info(
            "Surface A: settings[%r] → ⟦bao:v1:%s⟧",
            settings_key,
            vault_path,
        )


# ---------------------------------------------------------------------------
# Hook 2: get_plugin_config  (ADR-01 — NO-OP)
# ---------------------------------------------------------------------------

async def get_plugin_config(
    plugin_name: str,
    project_name: str,
    agent_profile: str,
    **kwargs: Any,
) -> None:
    """ADR-01: always return placeholders — never auto-resolve on read.

    This hook is intentionally a **NO-OP**.  Returning ``None`` instructs the
    framework to use the stored config value unchanged, preserving
    ``⟦bao:v1:…⟧`` placeholder strings in the returned dict.

    Live value resolution must be requested explicitly by service consumers
    via :func:`resolve_plugin_config` when actual credential values are
    required (e.g. before constructing an HTTP client or auth header).
    """
    return None  # framework uses stored config as-is (placeholders preserved)


# ---------------------------------------------------------------------------
# Helper: resolve_plugin_config
# ---------------------------------------------------------------------------

async def resolve_plugin_config(config: dict) -> dict:
    """Resolve all ``⟦bao:v1:…⟧`` placeholders in *config* to live vault values.

    Returns a **new** dict — the original *config* is never mutated.
    Service consumers call this explicitly when live secret values are needed.

    On resolution failure (vault unreachable, secret deleted, permission
    denied, etc.) the placeholder is left in place and a warning is logged.
    No exception is raised so partially-resolved configs remain usable.
    """
    resolved = copy.deepcopy(config)

    manager = _get_manager()
    if manager is None:
        logger.warning(
            "resolve_plugin_config: OpenBaoSecretsManager unavailable —"
            " returning config with ⟦bao:v1:⟧ placeholders intact"
        )
        return resolved

    for key, value in resolved.items():
        if not isinstance(value, str):
            continue
        if not (
            value.startswith(_PLACEHOLDER_PREFIX)
            and value.endswith(_PLACEHOLDER_SUFFIX)
        ):
            continue

        # Extract vault path from ⟦bao:v1:<path>⟧
        path = value[len(_PLACEHOLDER_PREFIX) : -len(_PLACEHOLDER_SUFFIX)]

        try:
            secret_data = _vault_read(manager, path)

            if secret_data is None:
                logger.warning(
                    "resolve_plugin_config: secret not found at %r — placeholder unchanged",
                    path,
                )
                continue

            if isinstance(secret_data, dict):
                # Primary field name written by save_plugin_config
                live_value: Optional[str] = secret_data.get("value")
                if live_value is None:
                    # Fallback: first non-index string value in the dict
                    for k, v in secret_data.items():
                        if k not in ("canonical_path",) and isinstance(v, str):
                            live_value = v
                            break
                if live_value is not None:
                    resolved[key] = live_value
                else:
                    logger.warning(
                        "resolve_plugin_config: no extractable value in secret at %r",
                        path,
                    )
            elif isinstance(secret_data, str):
                resolved[key] = secret_data

        except Exception as exc:
            logger.warning(
                "resolve_plugin_config: failed to resolve %r: %s — placeholder unchanged",
                path,
                exc,
            )

    return resolved
