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

"""Surface B consume — MCP server header credential resolver.

This module provides:

1. **``OpenBaoMcpHeaderResolver``** (Extension class, agent_init hook)
   Registered under ``agent_init`` at priority 20.  Its ``execute()`` is a
   no-op that ensures the module is imported and ``resolve_mcp_server_headers``
   is available as a callable at agent start-up.

2. **``resolve_mcp_server_headers()``** (module-level async function)
   Called by ``helpers/mcp_handler.py`` via ``call_extensions_async`` at MCP
   HTTP transport time (PR-C hook from Step 1).  Walks the headers dict and
   resolves every ``⟦bao:v1:<path>⟧`` placeholder to its live OpenBao
   value just before the connection to the MCP server is opened.

Design decisions
----------------
ADR-01 (fail-open on resolution failure)
    If a vault read fails the placeholder is left in the returned dict and a
    warning is logged.  No exception is raised — the MCP transport will
    produce an auth error, which is visible and debuggable without crashing
    the agent.

Fast path
    If no header value starts with ``⟦bao:`` the function returns ``None``
    immediately, signalling the framework to use the original headers
    unchanged.  This makes the common case (unmanaged credentials) zero-cost.

Immutability
    The input *headers* dict is **never mutated** — a copy is always
    returned when placeholders are found.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import re
import sys
from typing import Any, Optional

from helpers.extension import Extension

logger = logging.getLogger(__name__)


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
# Vault I/O stubs — delegate to helpers/vault_io.py (REM-002)
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



# Assign to names expected by the rest of this file
_get_manager = _vio_get_manager
_get_hvac = _vio_get_hvac
_vault_read = _vio_vault_read

# ---------------------------------------------------------------------------
# Placeholder token constants — must match Surface A / Surface B values exactly.
# CRIT-01: These were absent, causing NameError on every MCP header resolution
#          call (resolve_mcp_server_headers completely broken at runtime).
# Values mirror plugin_config/_10_openbao_plugin_config.py and
#          tool_execute_after/_10_openbao_mcp_scan.py constants.
# ---------------------------------------------------------------------------
_ANY_BAO_PREFIX: str = "bao:"         # fast-path: every managed placeholder starts here
_PLACEHOLDER_PREFIX: str = "bao:v1:"  # Surface A/B canonical placeholder prefix
_PLACEHOLDER_SUFFIX: str = "\u27e7"   # ⟧  MATHEMATICAL RIGHT WHITE SQUARE BRACKET



# ---------------------------------------------------------------------------
# Extension class (agent_init no-op)
# ---------------------------------------------------------------------------

class OpenBaoMcpHeaderResolver(Extension):
    """agent_init (priority 20): ensures resolver module is loaded at startup.

    The ``execute()`` method is a no-op.  Active resolution logic lives in
    :func:`resolve_mcp_server_headers`, called by ``helpers/mcp_handler.py``
    via the ``resolve_mcp_server_headers`` hook added in PR-C (Step 1).
    """

    def execute(self, **kwargs: Any) -> None:  # sync hook
        logger.debug(
            "OpenBaoMcpHeaderResolver ready — resolve_mcp_server_headers available"
        )


# ---------------------------------------------------------------------------
# resolve_mcp_server_headers — module-level hook function
# ---------------------------------------------------------------------------

async def resolve_mcp_server_headers(
    agent: Any,
    server_name: str,
    headers: dict,
    **kwargs: Any,
) -> dict | None:
    """Resolve ``⟦bao:v1:…⟧`` placeholders in MCP server headers to live values.

    Called by ``helpers/mcp_handler.py`` at MCP HTTP transport time.

    Parameters
    ----------
    agent:
        Active Agent instance (for context; not used directly).
    server_name:
        MCP server name as configured in ``mcp_servers.json``.
    headers:
        Raw headers dict that may contain ``⟦bao:v1:<path>⟧`` placeholders.
    **kwargs:
        Additional context from caller (ignored).

    Returns
    -------
    dict | None
        New dict with placeholders replaced by live vault values, or ``None``
        if no placeholders were found (fast path — caller uses original dict).

    Notes
    -----
    * Input *headers* is **never mutated** — always return a copy.
    * Fail-open (ADR-01): on vault read failure, warning is logged and the
      placeholder is left intact.  No exception is raised.
    """
    # ── Fast path: return None immediately when no placeholders present ───
    if not any(
        isinstance(v, str) and v.startswith(_ANY_BAO_PREFIX)
        for v in headers.values()
    ):
        return None  # framework uses original headers unchanged

    manager = _get_manager()
    if manager is None:
        logger.warning(
            "Surface B resolver: manager unavailable for server %r — "
            "returning None (original headers used)",
            server_name,
        )
        return None

    if not getattr(manager, "is_available", lambda: False)():
        logger.warning(
            "Surface B resolver: OpenBao not available for server %r — "
            "returning None",
            server_name,
        )
        return None

    # ── Resolve placeholders into a new dict (never mutate input) ─────────
    resolved = dict(headers)  # shallow copy — values are immutable strings

    for header_key, header_value in headers.items():
        if not isinstance(header_value, str):
            continue
        if not (
            header_value.startswith(_PLACEHOLDER_PREFIX)
            and header_value.endswith(_PLACEHOLDER_SUFFIX)
        ):
            continue

        # Extract vault path from ⟦bao:v1:<path>⟧
        vault_path = header_value[
            len(_PLACEHOLDER_PREFIX) : -len(_PLACEHOLDER_SUFFIX)
        ]

        try:
            secret_data = _vault_read(manager, vault_path)

            if secret_data is None:
                # ADR-01: warn only — keep placeholder, do NOT raise
                logger.warning(
                    "Surface B resolver: secret not found at %r "
                    "(server=%r header=%r) — placeholder unchanged",
                    vault_path, server_name, header_key,
                )
                continue

            if isinstance(secret_data, dict):
                live_value: Optional[str] = secret_data.get("value")
                if live_value is None:
                    # Fallback: first non-index string value
                    for k, v in secret_data.items():
                        if k not in ("canonical_path",) and isinstance(v, str):
                            live_value = v
                            break
                if live_value is not None:
                    resolved[header_key] = live_value
                    logger.debug(
                        "Surface B resolver: resolved %r for server %r",
                        header_key, server_name,
                    )
                else:
                    logger.warning(
                        "Surface B resolver: no extractable value at %r "
                        "(server=%r header=%r) — placeholder unchanged",
                        vault_path, server_name, header_key,
                    )
            elif isinstance(secret_data, str):
                resolved[header_key] = secret_data

        except Exception as exc:
            # ADR-01: fail-open — log warning, do NOT raise
            logger.warning(
                "Surface B resolver: failed to resolve %r "
                "(server=%r header=%r): %s — placeholder unchanged",
                vault_path, server_name, header_key, exc,
            )

    return resolved
