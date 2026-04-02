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
"""MCP credential rotation endpoint (G-05).

POST /api/plugins/deimos_openbao_secrets/rotate_mcp

Resolves all ⟦bao:v1:…⟧ placeholders in the running MCP configuration
to live values from OpenBao, then calls MCPConfig.update() to force MCP
reconnection with fresh auth headers.

The mcp_servers setting on disk retains placeholder strings unchanged.
Only the in-memory MCPConfig instance receives live credential values.
"""
from __future__ import annotations

import json
import logging

from helpers.api import ApiHandler, Request, Response
from helpers.vault_io import _get_manager, _get_hvac, _vault_read  # REM-002: bare import safe in api/

logger = logging.getLogger(__name__)

# Placeholder tokens -- literal Unicode U+27E6 / U+27E7
_BAO_PREFIX: str = "⟦bao:v1:"
_BAO_SUFFIX: str = "⟧"


# ---------------------------------------------------------------------------
# Placeholder resolution
# ---------------------------------------------------------------------------

def _resolve_value(manager, placeholder: str) -> Optional[str]:
    """Resolve a single ⟦bao:v1:<path>⟧ to its live vault value."""
    if not (placeholder.startswith(_BAO_PREFIX) and placeholder.endswith(_BAO_SUFFIX)):
        return None
    path = placeholder[len(_BAO_PREFIX):-len(_BAO_SUFFIX)]
    data = _vault_read(manager, path)
    if data is None:
        logger.warning("rotate_mcp: secret not found at %r", path)
        return None
    if isinstance(data, dict):
        live = data.get("value")
        if live is None:
            for k, v in data.items():
                if k != "canonical_path" and isinstance(v, str):
                    live = v
                    break
        return live
    return data if isinstance(data, str) else None


def _resolve_mcp_config(manager, mcp_json: str) -> tuple[str, int]:
    """Walk mcpServers[*].headers resolving ⟦bao:v1:⟧ tokens to live values.

    Returns (resolved_json_str, count_resolved). Original JSON structure is
    preserved; only placeholder header values are replaced with live credentials.
    """
    try:
        data = json.loads(mcp_json)
    except Exception as exc:
        logger.warning("rotate_mcp: cannot parse mcp_servers JSON: %s", exc)
        return mcp_json, 0

    mcp_servers = data.get("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        return mcp_json, 0

    count = 0
    for srv_name, srv_cfg in mcp_servers.items():
        if not isinstance(srv_cfg, dict):
            continue
        headers = srv_cfg.get("headers", {})
        if not isinstance(headers, dict):
            continue
        for hdr_key, hdr_value in list(headers.items()):
            if not isinstance(hdr_value, str):
                continue
            if not hdr_value.startswith(_BAO_PREFIX):
                continue
            live = _resolve_value(manager, hdr_value)
            if live is not None:
                headers[hdr_key] = live
                count += 1
                logger.info("rotate_mcp: resolved %r for server %r", hdr_key, srv_name)
            else:
                logger.warning("rotate_mcp: cannot resolve %r for server %r", hdr_key, srv_name)

    return json.dumps(data), count


# ---------------------------------------------------------------------------
# API handler
# ---------------------------------------------------------------------------

class RotateMcp(ApiHandler):
    """POST /api/plugins/deimos_openbao_secrets/rotate_mcp (G-05)

    Resolves ⟦bao:v1:⟧ placeholder tokens in the running MCP config to
    live OpenBao values and forces MCPConfig.update() so MCP servers
    reconnect with fresh credentials. Settings on disk are NOT modified.
    """

    @classmethod
    def requires_csrf(cls) -> bool:
        return False

    async def process(self, input: dict, request: Request) -> dict:
        manager = _get_manager()
        if manager is None or not getattr(manager, "is_available", lambda: False)():
            return {"success": False, "error": "OpenBao not available"}

        try:
            # --- Load current mcp_servers JSON string from A0 settings ---
            # get_settings()["mcp_servers"] is a JSON string (not a dict)
            mcp_json: str = ""
            try:
                from helpers.settings import get_settings  # noqa: PLC0415
                mcp_json = get_settings().get("mcp_servers") or ""
            except Exception as exc:
                logger.warning("rotate_mcp: cannot load settings: %s", exc)

            if not mcp_json or not mcp_json.strip():
                return {
                    "success": True,
                    "servers_refreshed": 0,
                    "message": "No MCP servers configured",
                }

            # --- Resolve placeholders in-memory (disk unchanged) ---
            resolved_json, count = _resolve_mcp_config(manager, mcp_json)

            # --- Force MCPConfig reconnect with live credentials ---
            # MCPConfig.update() is a classmethod accepting a JSON string
            if count > 0:
                try:
                    from helpers.mcp_handler import MCPConfig  # noqa: PLC0415
                    MCPConfig.update(resolved_json)
                    logger.info(
                        "rotate_mcp: MCPConfig.update() called (%d credential(s) resolved)",
                        count,
                    )
                except Exception as exc:
                    logger.error("rotate_mcp: MCPConfig.update() failed: %s", exc)
                    return {"success": False, "error": f"MCPConfig update failed: {exc}"}

            return {
                "success": True,
                "servers_refreshed": count,
                "message": (
                    f"{count} MCP credential(s) refreshed and MCPConfig updated"
                    if count > 0 else
                    "No placeholder tokens found in MCP server config"
                ),
            }

        except Exception as exc:
            logger.exception("rotate_mcp: unexpected error")
            return {"success": False, "error": str(exc)}
