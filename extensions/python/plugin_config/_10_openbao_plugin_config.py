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
# Settings reference detection — Surface A read hook (AC-04, AC-05)
# ---------------------------------------------------------------------------
# MED-01: Tightened regex — bare ALL_CAPS only matches if >= 8 chars and
# contains at least 2 underscores. This avoids false-positives on common
# config values like NONE, TRUE, FALSE, DEBUG, INFO, TOKEN.
_BAO_REF_BARE_RE = re.compile(r"^[A-Z][A-Z0-9_]{7,}$")  # min 8 chars total
_BAO_REF_PREFIX = "$bao:"                                  # explicit prefix form
_BAO_DISPLAY_MASK = "[bao-ref: {key}]"                     # webui display mask (AC-10)


def _is_bao_ref(value: object) -> bool:
    """Return True if value looks like a vault reference.

    Accepts two forms:
      - Explicit prefix: ``$bao:KEY`` (always matched)
      - Bare ALL_CAPS: only if >= 8 chars AND contains >= 2 underscores
        (avoids false-positives on NONE, TRUE, FALSE, DEBUG, etc.)
    """
    if not isinstance(value, str):
        return False
    if value.startswith(_BAO_REF_PREFIX):
        return True
    # Bare ALL_CAPS: require >= 2 underscores to reduce false-positives (MED-01)
    if _BAO_REF_BARE_RE.match(value) and value.count("_") >= 2:
        return True
    return False


def _extract_ref_key(value: str) -> str:
    """Extract vault key from a bao reference value."""
    if value.startswith(_BAO_REF_PREFIX):
        return value[len(_BAO_REF_PREFIX):]
    return value  # bare ALL_CAPS — the value IS the key


def _mask_for_display(key: str) -> str:
    """Return webui display mask string for a resolved bao reference. AC-10."""
    return _BAO_DISPLAY_MASK.format(key=key)


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
        path = os.path.join(plugin_dir, "openbao_helpers", "vault_io.py")
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

def _vio_write_if_absent(
    manager, path: str, key: str, value: str, custom_metadata=None
) -> bool:
    vio = _load_vault_io()
    if vio is None:
        raise RuntimeError("vault_io not available — cannot check/write to vault")
    return vio.write_if_absent(manager, path, key, value, custom_metadata)



def _vio_sanitize_component(value: str) -> str:
    vio = _load_vault_io()
    return vio._sanitize_component(value) if vio else re.sub(r"[^a-zA-Z0-9_.-]", "_", value).lstrip(".")


# Assign to names expected by the rest of this file
_get_manager = _vio_get_manager
_get_hvac = _vio_get_hvac
_vault_read = _vio_vault_read
_vault_write = _vio_vault_write
_sanitize_component = _vio_sanitize_component
_write_if_absent = _vio_write_if_absent

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
# Reference resolution helpers (AC-04–AC-09)
# ---------------------------------------------------------------------------

def _load_config_if_available():
    """Load plugin config safely to read hard_fail_on_unavailable. Returns None on failure."""
    try:
        from helpers.plugins import find_plugin_dir
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            return None
        config_path = os.path.join(plugin_dir, "openbao_helpers", "config.py")
        if not os.path.exists(config_path):
            return None
        _CFG_MODULE = "openbao_helpers.config"
        if _CFG_MODULE not in sys.modules:
            spec = importlib.util.spec_from_file_location(_CFG_MODULE, config_path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[_CFG_MODULE] = mod
            spec.loader.exec_module(mod)
        cfg_mod = sys.modules[_CFG_MODULE]
        return cfg_mod.load_config(plugin_dir)
    except Exception as exc:
        logger.debug("_load_config_if_available failed: %s", exc)
        return None


def _resolve_ref(manager: Any, key: str, hard_fail: bool) -> Optional[str]:
    """Resolve vault reference key to live value.

    Resolution chain (AC-06 through AC-09):
    1. OpenBao available + hit  → return resolved value                    (AC-06)
    2. OpenBao available + miss → return None + log WARNING                (AC-07)
    3. OpenBao unavailable + hard_fail=False → fallback to os.getenv(key) (AC-08)
    4. OpenBao unavailable + hard_fail=True  → raise RuntimeError          (AC-09)
    """
    unavailable = manager is None or not getattr(manager, "is_available", lambda: False)()
    if unavailable:
        if hard_fail:
            raise RuntimeError(
                f"OpenBao unavailable and hard_fail_on_unavailable=True — "
                f"cannot resolve ref {key!r}"
            )
        env_val = os.environ.get(key)
        if env_val:
            logger.debug("_resolve_ref: vault unavailable — falling back to os.getenv(%r)", key)
            return env_val
        return None  # AC-08: env also absent — caller returns original value

    data = _vault_read(manager, key) or {}
    resolved = data.get("value") or data.get(key)
    if resolved is None:
        logger.warning(
            "_resolve_ref: key %r not found in OpenBao — returning original value as-is", key
        )
        return None  # AC-07: vault miss
    return resolved  # AC-06: vault hit


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
        # HIGH-01: Use first 32 hex chars (128 bits) to minimise collision risk.
        # hash_prefix is stored in dedup record for CAS-style verification.
        value_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
        hash_prefix = value_hash[:32]  # HIGH-01: was [:16] (64 bits -> 128 bits)
        dedup_path = f"_dedup/{hash_prefix}"

        canonical_path: Optional[str] = None
        try:
            dedup_record = _vault_read(manager, dedup_path)
            if dedup_record and isinstance(dedup_record, dict):
                # HIGH-01: CAS verify — confirm stored hash_prefix before reuse.
                # Backward-compat: if hash_prefix absent (legacy record), accept.
                stored_prefix = dedup_record.get("hash_prefix", "")
                if not stored_prefix or stored_prefix == hash_prefix:
                    canonical_path = dedup_record.get("canonical_path")
                else:
                    logger.warning(
                        "%s: dedup hash_prefix mismatch at %r "
                        "(stored=%.8s actual=%.8s) — new entry (HIGH-01)",
                        "Surface A", dedup_path, stored_prefix, hash_prefix,
                    )
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
            _vault_write(manager, dedup_path, {"canonical_path": canonical_path, "hash_prefix": hash_prefix})  # HIGH-01
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
# Hook 2: get_plugin_config  (ADR-01 REVISED — bao-ref resolution)
# ---------------------------------------------------------------------------

async def get_plugin_config(
    plugin_name: str,
    project_name: str,
    agent_profile: str,
    settings: dict,
    for_display: bool = False,
    **kwargs: Any,
) -> Optional[dict]:
    """Surface A read hook — resolves vault references in plugin settings on read.

    ADR-01 REVISED: Previously always returned None (NO-OP). Now scans settings values
    for vault references (bare ALL_CAPS or $bao: prefix) and resolves them from OpenBao.

    for_display=True  → resolved values masked as [bao-ref: KEY_NAME] (AC-10, webui safe)
    for_display=False → resolved values are live plaintext secrets (programmatic use)

    Returns None if no references found (pass-through — avoids unnecessary dict copy).
    Returns modified settings dict if any references were resolved or masked.
    """
    if plugin_name == "deimos_openbao_secrets":
        return None  # ADR-02: bootstrapping guard preserved

    manager = _get_manager()
    cfg = _load_config_if_available()
    hard_fail = getattr(cfg, "hard_fail_on_unavailable", False)

    resolved_any = False
    result = dict(settings)

    for field, value in settings.items():
        if not _is_bao_ref(value):
            continue
        ref_key = _extract_ref_key(value)  # AC-04, AC-05
        live = _resolve_ref(manager, ref_key, hard_fail)
        if live is None:
            continue  # AC-07: miss or unavailable — keep original value
        if for_display:
            result[field] = _mask_for_display(ref_key)  # AC-10: mask in webui
        else:
            result[field] = live  # AC-06: live value for programmatic use
        resolved_any = True

    return result if resolved_any else None
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
