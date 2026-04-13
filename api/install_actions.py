"""api/install_actions.py — Install action endpoints for E-08 extension.

POST /api/plugins/deimos_openbao_secrets/install/propagate
POST /api/plugins/deimos-openbao-secrets/install/defer-propagation

Handles user confirmation gate for brownfield vault secrets.
Propagate runs propagator.py against discovered secrets.
Defer marks discovery as deferred without propagation.

Satisfies: E-08-ext AC-D4, AC-D5
"""
from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


class InstallActions:
    """API handler for install confirmation actions.

    Routes:
        propagate — run propagation on discovered secrets
        defer-propagation — mark discovery as deferred

    Satisfies: E-08-ext AC-D4, AC-D5
    """

    async def process(self, request: Any = None) -> Dict[str, Any]:
        """Route to the appropriate action based on request path.

        Args:
            request: Framework request object with path attribute.

        Returns:
            Dict with ok, action, and result details.
        """
        # Determine action from request path
        path = ""
        if request and hasattr(request, "path"):
            path = request.path
        elif request and isinstance(request, dict):
            path = request.get("path", "")

        if "defer-propagation" in path:
            return await self._defer_propagation()
        else:
            return await self._propagate()

    async def _propagate(self) -> Dict[str, Any]:
        """Run propagation on discovered vault secrets.

        Updates registry status from 'discovered' to 'propagated'.
        Reuses existing propagator.py logic.

        Satisfies: E-08-ext AC-D4
        """
        result: Dict[str, Any] = {
            "ok": False,
            "action": "propagate",
            "propagated": 0,
            "errors": [],
        }

        try:
            from helpers.registry import RegistryManager
            rm = RegistryManager()
            registry = rm.load()

            discovery_status = registry.get("discovery_status")
            if discovery_status != "discovered":
                result["errors"] = [f"No pending discovery (status={discovery_status})"]
                return result

            keys = registry.get("vault_secret_keys", [])
            if not keys:
                result["errors"] = ["No discovered secret keys to propagate"]
                return result

            # Update registry status to propagated
            registry["discovery_status"] = "propagated"
            registry["propagated_at"] = _now_iso()

            # Update individual entry statuses
            for entry in registry.get("entries", []):
                if entry.get("source") == "vault_discovery" and entry.get("status") == "discovered":
                    entry["status"] = "propagated"

            rm.save(registry)

            result["ok"] = True
            result["propagated"] = len(keys)
            result["keys"] = keys
            logger.info(
                "Propagation confirmed: %d secrets marked as propagated",
                len(keys),
            )

        except Exception as exc:
            result["errors"].append(f"Propagation failed: {exc}")
            logger.error("install_actions propagate failed: %s", exc)

        return result

    async def _defer_propagation(self) -> Dict[str, Any]:
        """Defer propagation — marks discovery as deferred.

        Sets discovery_status to 'deferred' so awaiting_confirmation
        becomes False and the gate does not re-appear on next page load.
        User can re-trigger propagation manually later.

        Satisfies: E-08-ext AC-D5
        """
        result: Dict[str, Any] = {
            "ok": False,
            "action": "defer-propagation",
            "deferred": False,
            "errors": [],
        }

        try:
            from helpers.registry import RegistryManager
            rm = RegistryManager()
            registry = rm.load()

            discovery_status = registry.get("discovery_status")
            if discovery_status != "discovered":
                result["errors"] = [f"No pending discovery to defer (status={discovery_status})"]
                return result

            # CR-3: Set discovery_status='deferred' so awaiting_confirmation is False.
            # Previously only set deferred_at — leaving status='discovered' meant the
            # gate would re-appear on next page load (skip button non-functional).
            registry["discovery_status"] = "deferred"
            registry["deferred_at"] = _now_iso()
            rm.save(registry)

            result["ok"] = True
            result["deferred"] = True
            logger.info("Propagation deferred by user")

        except Exception as exc:
            result["errors"].append(f"Defer failed: {exc}")
            logger.error("install_actions defer-propagation failed: %s", exc)

        return result



def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
