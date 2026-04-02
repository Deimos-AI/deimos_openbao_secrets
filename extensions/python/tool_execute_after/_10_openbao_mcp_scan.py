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

"""Surface B write — MCP credential scan and sanitise.

Hook: tool_execute_after  (fires after every tool execution, priority 10)

Purpose
-------
Whenever the agent writes or patches a file via the ``text_editor`` tool,
this extension checks whether the written path matches any pattern in
``mcp_scan_paths`` (default: ``**/mcp_servers.json``).

If matched, the file is parsed as JSON and ``mcpServers[*].headers`` are
scanned for keys matching ``mcp_header_scan_patterns``.  Live credential
values are:

1. Stored in OpenBao KV v2 at a canonical path with provenance metadata.
2. Replaced with ``⟦bao:v1:<canonical_path>⟧`` placeholders.
3. Written back to the file **atomically** via a ``.tmp`` file + ``os.replace``.

Atomicity guarantee (G-02)
    All KV v2 writes MUST succeed before the original file is modified.
    On any vault write failure the ``.tmp`` file is deleted and the original
    is left unchanged.  The exception is re-raised (fail-closed).

Deduplication (G-03)
    SHA-256 digest (first 16 hex chars) used as dedup index key
    ``_dedup/{hash[:16]}``.  Shared credentials stored exactly once.

Idempotency
    Values already starting with ``⟦bao:`` are skipped unconditionally.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Optional

from helpers.extension import Extension

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Placeholder tokens — literal Unicode U+27E6 / U+27E7
# ---------------------------------------------------------------------------
_PLACEHOLDER_PREFIX: str = "⟦bao:v1:"
_PLACEHOLDER_SUFFIX: str = "⟧"
_IDEMPOTENCY_PREFIX: str = "⟦bao:"

# text_editor operation names that write file content
_WRITE_OPS = frozenset({"text_editor:write", "text_editor:patch"})


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
# Vault I/O stubs — delegate to helpers/vault_io.py (REM-002)
# Thin wrappers preserve call signatures so the rest of this file is unchanged.
# ---------------------------------------------------------------------------

def _vio_get_manager():
    """Delegate to vault_io._get_manager()."""
    vio = _load_vault_io()
    return vio._get_manager() if vio else None


def _vio_get_hvac(manager):
    """Delegate to vault_io._get_hvac()."""
    vio = _load_vault_io()
    return vio._get_hvac(manager) if vio else (None, None)


def _vio_vault_read(manager, path: str):
    """Delegate to vault_io._vault_read()."""
    vio = _load_vault_io()
    return vio._vault_read(manager, path) if vio else None


def _vio_vault_write(manager, path: str, data: dict, custom_metadata=None):
    """Delegate to vault_io._vault_write()."""
    vio = _load_vault_io()
    if vio is None:
        raise RuntimeError("vault_io not available — cannot write to vault")
    return vio._vault_write(manager, path, data, custom_metadata)


# Assign to names expected by the rest of this file
_get_manager = _vio_get_manager
_get_hvac = _vio_get_hvac
_vault_read = _vio_vault_read
_vault_write = _vio_vault_write


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _get_plugin_cfg() -> dict:
    try:
        from helpers.plugins import get_plugin_config  # noqa: PLC0415
        cfg = get_plugin_config("deimos_openbao_secrets")
        return cfg if isinstance(cfg, dict) else {}
    except Exception as exc:
        logger.debug("Surface B scan: could not load plugin config: %s", exc)
        return {}


def _get_scan_patterns() -> list[str]:
    return list(_get_plugin_cfg().get("mcp_scan_paths") or [])


def _get_header_patterns() -> list[str]:
    return list(_get_plugin_cfg().get("mcp_header_scan_patterns") or [])


# ---------------------------------------------------------------------------
# Path sanitisation — delegates to helpers/vault_io.py (REM-002)
# ---------------------------------------------------------------------------

def _vio_sanitize_component(value: str) -> str:
    """Delegate to vault_io._sanitize_component()."""
    vio = _load_vault_io()
    return vio._sanitize_component(value) if vio else re.sub(r"[^a-zA-Z0-9_.-]", "_", value).lstrip(".")


_sanitize_component = _vio_sanitize_component


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------

class OpenBaoMcpScan(Extension):
    """Surface B: scan MCP config files written by text_editor for live credentials.

    Registered in the tool_execute_after lifecycle hook at priority 10.
    Only text_editor write/patch operations on paths matching mcp_scan_paths
    are processed — all other invocations are cheap no-ops.
    """

    async def execute(
        self,
        agent: Any = None,
        response: Any = None,
        tool_name: str = "",
        tool: Any = None,
        **kwargs: Any,
    ) -> None:
        """Intercept text_editor write/patch on MCP config files."""

        # ── Guard 1: only text_editor write or patch ──────────────────────
        if tool_name not in _WRITE_OPS:
            return

        # ── Guard 2: manager must be available ───────────────────────────
        manager = _get_manager()
        if manager is None:
            return
        if not getattr(manager, "is_available", lambda: False)():
            return

        # ── Resolve file path written by this tool invocation ─────────────
        # Primary: tool.tool_args (injected by agent.py PR #1377)
        tool_args: dict = {}
        if tool is not None:
            tool_args = getattr(tool, "tool_args", None) or {}
        if not isinstance(tool_args, dict):
            tool_args = {}

        path_str: Optional[str] = (
            tool_args.get("path")
            or kwargs.get("path")
        )
        if not path_str:
            logger.debug("Surface B scan: no path in tool_args — skipping")
            return

        file_path = Path(path_str)
        if not file_path.is_file():
            return

        # ── Guard 3: path must match mcp_scan_paths patterns ─────────────
        scan_patterns = _get_scan_patterns()
        if not scan_patterns:
            return

        if not any(file_path.match(pat) for pat in scan_patterns):
            return

        await _process_mcp_file(manager, file_path)


# ---------------------------------------------------------------------------
# Core scan logic
# ---------------------------------------------------------------------------

async def _process_mcp_file(manager: Any, file_path: Path) -> None:
    """Extract MCP server credentials to OpenBao and replace with placeholders.

    Implements the atomic write-then-rename pattern (G-02):

    1. Collect all (server, header, vault_path, value) candidates.
    2. Build modified JSON (deep copy with placeholder substitution).
    3. Write modified JSON to ``{file_path}.tmp``.
    4. Attempt ALL vault KV v2 writes.  On failure: delete ``.tmp``,
       re-raise — original file is NEVER touched.
    5. On full success: ``os.replace()`` renames ``.tmp`` → original.
    """
    # ── Parse JSON ────────────────────────────────────────────────────────
    try:
        raw_text = file_path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        logger.warning(
            "Surface B scan: %s is not valid JSON — skipping: %s", file_path, exc
        )
        return
    except Exception as exc:
        logger.warning("Surface B scan: cannot read %s: %s", file_path, exc)
        return

    mcp_servers = data.get("mcpServers", {})
    if not isinstance(mcp_servers, dict) or not mcp_servers:
        return

    header_patterns = _get_header_patterns()
    if not header_patterns:
        return

    extracted_at = datetime.now(timezone.utc).isoformat()

    # ── Phase 1: collect candidates ────────────────────────────────────────
    # pending   = [(server_name, header_key, canonical_path, raw_value), ...]
    # new_dedup = [(dedup_path, canonical_path), ...]  — entries to create
    pending: list[tuple[str, str, str, str]] = []
    new_dedup: list[tuple[str, str]] = []

    for server_name, server_cfg in mcp_servers.items():
        if not isinstance(server_cfg, dict):
            continue
        headers = server_cfg.get("headers", {})
        if not isinstance(headers, dict):
            continue

        for header_key, header_value in headers.items():
            # fnmatch: case-sensitive match OR exact match for header names
            if not any(
                fnmatch(header_key, pat) or fnmatch(header_key.lower(), pat.lower())
                for pat in header_patterns
            ):
                continue

            if not isinstance(header_value, str) or not header_value:
                continue

            # Idempotency: already a ⟦bao: placeholder — skip
            if header_value.startswith(_IDEMPOTENCY_PREFIX):
                continue

            s_server = _sanitize_component(server_name)
            s_header = _sanitize_component(header_key)

            # SHA-256 dedup: first 16 hex chars as index key
            value_hash = hashlib.sha256(header_value.encode("utf-8")).hexdigest()
            hash_prefix = value_hash[:16]
            dedup_path = f"_dedup/{hash_prefix}"

            canonical_path: Optional[str] = None
            try:
                dedup_record = _vault_read(manager, dedup_path)
                if dedup_record and isinstance(dedup_record, dict):
                    canonical_path = dedup_record.get("canonical_path")
            except Exception as exc:
                logger.debug(
                    "Surface B scan: dedup lookup error server=%r header=%r: %s",
                    server_name, header_key, exc,
                )

            if not canonical_path:
                canonical_path = f"mcp/{s_server}/{s_header}"
                new_dedup.append((dedup_path, canonical_path))

            pending.append((server_name, header_key, canonical_path, header_value))

    if not pending:
        return

    # ── Phase 2: build modified JSON with ⟦bao:v1:⟧ placeholders ──────────────
    modified = copy.deepcopy(data)
    for server_name, header_key, canonical_path, _ in pending:
        placeholder = f"{_PLACEHOLDER_PREFIX}{canonical_path}{_PLACEHOLDER_SUFFIX}"
        modified["mcpServers"][server_name]["headers"][header_key] = placeholder

    modified_json = json.dumps(modified, indent=2, ensure_ascii=False)
    tmp_path = Path(str(file_path) + ".tmp")

    # ── Phase 3: write .tmp ───────────────────────────────────────────────
    try:
        tmp_path.write_text(modified_json, encoding="utf-8")
    except Exception as exc:
        logger.error("Surface B scan: failed to write .tmp %s: %s", tmp_path, exc)
        raise

    # ── Phase 4: ATOMIC vault writes ─────────────────────────────────────
    # G-02: all vault writes must succeed before the original file is modified.
    # On any failure: delete .tmp, re-raise — atomic rollback, original untouched.
    try:
        for server_name, header_key, vault_path, raw_value in pending:
            custom_metadata = {
                "extracted_at": extracted_at,
                "surface": "B",
                "mcp_server": server_name,
                "header": header_key,
                "source_path": str(file_path),
            }
            _vault_write(
                manager,
                vault_path,
                {"value": raw_value},
                custom_metadata=custom_metadata,
            )
            logger.debug(
                "Surface B scan: wrote secret server=%r header=%r → %r",
                server_name, header_key, vault_path,
            )

        for dedup_path, canonical_path in new_dedup:
            _vault_write(manager, dedup_path, {"canonical_path": canonical_path})
            logger.debug(
                "Surface B scan: dedup index %r → %r", dedup_path, canonical_path
            )

    except Exception as exc:
        # Atomic rollback: .tmp deleted, original file NOT modified
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        logger.error(
            "Surface B scan: vault write FAILED — .tmp deleted, "
            "original file unchanged (atomic rollback): %s",
            exc,
        )
        raise

    # ── Phase 5: os.replace — atomic rename, only on full vault write success ──
    os.replace(str(tmp_path), str(file_path))
    logger.info(
        "Surface B scan: extracted %d credential(s) from %s — "
        "replaced with ⟦bao:v1:⟧ placeholders",
        len(pending),
        file_path,
    )
