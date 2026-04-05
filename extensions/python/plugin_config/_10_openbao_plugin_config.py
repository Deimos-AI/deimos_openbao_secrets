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
import importlib.util
import logging
import os
import re
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
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
# vault_io dynamic loader — bypasses A0 helpers/ namespace collision
# See: helpers/vault_io.py (REM-002)
# ---------------------------------------------------------------------------
_VAULT_IO_MODULE = "deimos_openbao_secrets_vault_io"  # MUST NOT start with 'helpers.'


def _load_vault_io():
    """Load helpers/vault_io.py dynamically — bypasses A0 helpers/ namespace collision."""
    if _VAULT_IO_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir  # A0's helpers.plugins — always safe
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            return None
        path = os.path.join(plugin_dir, "helpers", "vault_io.py")
        if not os.path.exists(path):
            return None
        spec = importlib.util.spec_from_file_location(_VAULT_IO_MODULE, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_VAULT_IO_MODULE] = mod  # register BEFORE exec_module
        spec.loader.exec_module(mod)
    return sys.modules.get(_VAULT_IO_MODULE)


# ---------------------------------------------------------------------------
# Vault I/O callables — delegate to helpers/vault_io.py (REM-002)
# Internal helpers use _vio_* names; originals assigned below (no 'def _get_*' here).
# ---------------------------------------------------------------------------

def _vio_get_manager():
    vio = _load_vault_io()
    return vio._get_manager() if vio else None


def _vio_get_hvac(manager):
    vio = _load_vault_io()
    return vio._get_hvac(manager) if vio else (None, None)


def _vio_vault_read(manager, path: str):
    vio = _load_vault_io()
    return vio._vault_read(manager, path) if vio else None


def _vio_vault_write(manager, path: str, data: dict, custom_metadata=None):
    vio = _load_vault_io()
    if vio is None:
        raise RuntimeError("vault_io not available — cannot write to vault")
    return vio._vault_write(manager, path, data, custom_metadata)


def _vio_sanitize_component(value: str) -> str:
    vio = _load_vault_io()
    return vio._sanitize_component(value) if vio else re.sub(r"[^a-zA-Z0-9_.-]", "_", value).lstrip(".")


# Assign to names expected by the rest of this file
_get_manager = _vio_get_manager
_get_hvac = _vio_get_hvac
_vault_read = _vio_vault_read
_vault_write = _vio_vault_write
_sanitize_component = _vio_sanitize_component

# ---------------------------------------------------------------------------
# Pattern loader — reads secret_field_patterns from plugin config
# ---------------------------------------------------------------------------

def _get_patterns() -> list:
    """Return fnmatch patterns identifying secret-valued plugin config keys.

    Delegates to vault_io._get_patterns() when available (which reads from
    the live plugin config). Falls back to hardcoded default_config.yaml
    defaults so Surface A remains functional even if vault_io cannot load.
    """
    vio = _load_vault_io()
    if vio and hasattr(vio, "_get_patterns"):
        return vio._get_patterns()
    # Hardcoded defaults matching default_config.yaml secret_field_patterns
    return ["*key*", "*token*", "*secret*", "*password*", "*auth*"]


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
    """Resolve plugin config secrets with project-first, global-fallback PSK lookup.

    PSK-004: When a project is active, resolves placeholder values using
    manager.get_secret(key, project_slug=project_slug) — project vault path
    first, global fallback on miss.

    Backward compat (ADR-01): When no project active, returns None so framework
    uses stored config unchanged (placeholders preserved).
    """
    # PSK-004: derive project slug from active project context
    project = project_name or ''
    if project:
        project_slug = Path(project).name  # AC-02: derivation
    else:
        project_slug = None  # AC-04: no project active — backward compat

    if not project_slug:
        return None  # ADR-01: no project active — no-op, framework uses stored config

    # Project active — resolve placeholders with PSK-aware manager
    manager = _get_manager()
    if manager is None:
        return None

    settings = kwargs.get('settings')
    if not settings or not isinstance(settings, dict):
        return None

    resolved = {}
    has_resolution = False
    for key, value in settings.items():
        if (
            isinstance(value, str)
            and value.startswith(_PLACEHOLDER_PREFIX)
            and value.endswith(_PLACEHOLDER_SUFFIX)
        ):
            # PSK-004 AC-03: project-first resolution via manager
            live = manager.get_secret(key, project_slug=project_slug)
            if live is not None:
                resolved[key] = live
                has_resolution = True
                logger.debug(
                    "PSK-004: resolved key=%r via project_slug=%r",
                    key, project_slug,
                )
            else:
                resolved[key] = value  # leave placeholder intact
        else:
            resolved[key] = value

    return resolved if has_resolution else None

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
