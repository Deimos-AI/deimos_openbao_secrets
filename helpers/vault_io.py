# Copyright 2026 deimosAI
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
"""
vault_io.py — Shared OpenBao vault I/O helpers for deimos_openbao_secrets.

Provides the single canonical implementations of five vault access helpers
shared across all vault-interacting files in the plugin:

    _get_manager()          — resolve OpenBaoSecretsManager from factory_common
    _get_hvac(manager)      — extract (hvac_client, mount_point) from manager
    _vault_read(...)        — read KV v2 secret; returns None on miss/error
    _vault_write(...)       — write KV v2 secret + optional metadata; raises on error
    _sanitize_component()   — sanitise a string for use as a vault path component

Extracted from duplicated implementations in:
    extensions/python/plugin_config/_10_openbao_plugin_config.py (L81-183)
    extensions/python/tool_execute_after/_10_openbao_mcp_scan.py (L79-181)
    api/rotate_mcp.py (L45-78)
    extensions/python/agent_init/_20_openbao_mcp_header_resolver.py (L72-116)

As part of COD-02 remediation (REM-002).

Design note — stdlib only
-------------------------
This module imports ONLY from stdlib (logging, re, sys, typing).
Do NOT add any `from helpers.*` imports — those would resolve to A0's
helpers/ package, not the plugin's. This module is loaded via importlib.util
by extension files (to bypass the A0 helpers/ namespace collision) and
directly imported by api/ files where the plugin root is on sys.path.

SEC-03 note
-----------
_get_hvac() bypasses OpenBaoClient resilience (retry/circuit-breaker/TTL/
token-renewal). This is intentional for REM-002 — behaviour is preserved
AS-IS from the files it was extracted from. Hardening is handled in REM-006.
"""
from __future__ import annotations

import logging
import re
import sys
from typing import Any, Optional

_logger = logging.getLogger(__name__)


def _get_manager() -> Optional[Any]:
    """Return OpenBaoSecretsManager singleton via factory_common, or None.

    Accesses factory_common via sys.modules key 'openbao_secrets_factory_common'
    (registered by helpers/factory_loader.py at agent startup). Returns None
    silently if factory_common is not yet loaded or manager initialisation failed.
    """
    fc = sys.modules.get("openbao_secrets_factory_common")
    if fc is None:
        _logger.debug("vault_io: factory_common not yet loaded")
        return None
    try:
        return fc.get_openbao_manager()
    except Exception as exc:
        _logger.debug("vault_io: get_openbao_manager() failed: %s", exc)
        return None


def _get_hvac(manager: Any) -> tuple[Optional[Any], Optional[str]]:
    """Return (hvac_client, mount_point) from manager, or (None, None).

    Accesses the underlying hvac client directly, bypassing OpenBaoClient's
    resilience layer (retry, circuit-breaker, TTL, token renewal).
    SEC-03: this bypass is intentional and preserved from the source files.
    REM-006 will introduce get_raw_hvac_client() as the explicit bypass method.
    """
    bao = getattr(manager, "_bao_client", None)
    if bao is None:
        return None, None
    client = getattr(bao, "_client", None)
    if client is None:
        return None, None
    mount = getattr(getattr(bao, "_config", None), "mount_point", None) or "secret"
    return client, mount


def _vault_read(manager: Any, path: str) -> Optional[dict]:
    """Read the KV v2 data dict at path, returning None on miss or error.

    Swallows all hvac exceptions (InvalidPath, Forbidden, connection errors)
    and returns None — callers are responsible for handling a None response.
    """
    client, mount = _get_hvac(manager)
    if client is None:
        return None
    try:
        import hvac.exceptions as _hvac_exc
    except ImportError:
        _hvac_exc = None  # type: ignore[assignment]

    try:
        resp = client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=mount,
            raise_on_deleted_version=False,
        )
        if resp:
            return resp.get("data", {}).get("data") or {}
        return None
    except Exception as _exc:
        # HIGH-04: differentiate exception types — Forbidden re-raises (permission
        # error must be surfaced), InvalidPath returns None (legitimate miss),
        # everything else logs a WARNING and returns None.
        if _hvac_exc is not None and isinstance(_exc, _hvac_exc.Forbidden):
            _logger.error(
                "vault_io._vault_read: permission denied at %r — re-raising", path
            )
            raise
        if _hvac_exc is not None and isinstance(_exc, _hvac_exc.InvalidPath):
            return None  # legitimate miss — path does not exist
        _logger.warning(
            "vault_io._vault_read: unexpected error reading %r: %s", path, _exc
        )
        return None


def _get_cas_version(manager: Any, path: str) -> Optional[int]:
    """Return current KV v2 version at path for CAS, or None if unavailable.

    HIGH-02: Used by write_if_absent to obtain a CAS version before writing.
    Returns None (disables CAS) when: client unavailable, path does not exist
    yet, or metadata read fails for any reason.
    """
    client, mount = _get_hvac(manager)
    if client is None:
        return None
    try:
        meta_resp = client.secrets.kv.v2.read_secret_metadata(
            path=path, mount_point=mount
        )
        if meta_resp and isinstance(meta_resp, dict):
            versions = meta_resp.get("data", {}).get("versions", {})
            if versions and isinstance(versions, dict):
                return max(int(v) for v in versions)
        return None
    except Exception:
        return None  # new path or metadata unavailable — CAS disabled gracefully


def write_if_absent(
    manager: Any,
    path: str,
    key: str,
    value: str,
    custom_metadata: Optional[dict] = None,
) -> bool:
    """Write key=value to KV v2 path only if key is absent. Returns True if written, False if exists.

    Idempotent: reads current data at path first; if key already present skips write and returns
    False. Merges new key into existing data dict (read-modify-write) so other keys at path are
    preserved. Raises RuntimeError if hvac client unavailable. Re-raises vault write exceptions.

    HIGH-02: Obtains the current KV v2 version via _get_cas_version() and passes it to
    _vault_write as the ``cas`` parameter to prevent TOCTOU race conditions. Degrades
    gracefully to non-CAS write when the version cannot be obtained (new path, vault
    unavailable, or metadata read fails).
    """
    existing = _vault_read(manager, path) or {}
    if key in existing:
        _logger.debug(
            "vault_io.write_if_absent: key %r already present at %r — skipping", key, path
        )
        return False
    # HIGH-02: read version for CAS before writing
    cas_version = _get_cas_version(manager, path)
    merged = {**existing, key: value}
    _vault_write(manager, path, merged, custom_metadata=custom_metadata, cas=cas_version)
    _logger.debug("vault_io.write_if_absent: wrote key %r to %r (cas=%s)", key, path, cas_version)
    return True


def _vault_write(
    manager: Any,
    path: str,
    data: dict,
    custom_metadata: Optional[dict] = None,
    cas: Optional[int] = None,
) -> None:
    """Write data to KV v2 path. Raises on failure so callers can atomically roll back.

    custom_metadata values are coerced to str (KV v2 requirement).
    Metadata write failure is non-fatal and logged at DEBUG — the secret write
    itself succeeded and the data is safely stored.
    """
    client, mount = _get_hvac(manager)
    if client is None:
        raise RuntimeError(
            f"vault_io: hvac client not available — cannot write to vault path {path!r}"
        )

    # HIGH-02: pass CAS version when provided to prevent TOCTOU overwrites
    create_kwargs: dict = {"path": path, "secret": data, "mount_point": mount}
    if cas is not None:
        create_kwargs["cas"] = cas
    client.secrets.kv.v2.create_or_update_secret(**create_kwargs)
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
            _logger.debug(
                "vault_io: metadata write non-fatal for %r: %s",
                path,
                meta_exc,
            )


def _sanitize_component(value: str) -> str:
    """Replace unsafe characters with underscores and strip leading dots.

    Used to produce safe KV v2 path components from plugin names, field names,
    MCP server names, and header keys.
    """
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", value).lstrip(".")
