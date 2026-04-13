"""api/install_status.py — Install status endpoint for E-08.

GET/POST /api/plugins/deimos_openbao_secrets/install_status

Returns the current install status: connectivity, mount, path,
secrets count, registry count, and vault discovery status.
Used by the WebUI config page (AC-07) to display install status.

E-08 extension: Added vault_secrets_count, vault_secret_keys,
discovery_status, awaiting_confirmation.

Satisfies: E-08 AC-07; E-08-ext AC-D3
"""
from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


class InstallStatus:
    """API handler for install status queries.

    Satisfies: E-08 AC-07; E-08-ext AC-D3
    """

    async def process(self, request: Any = None) -> Dict[str, Any]:
        """Return current install status.

        Returns:
            Dict with keys:
                ok (bool): True if no errors.
                status (dict): Detailed status breakdown:
                    connected (bool): OpenBao reachable.
                    authenticated (bool): Credentials valid.
                    mount_exists (bool): KV v2 mount present.
                    path_exists (bool): Secrets path present.
                    secrets_count (int): Number of secrets in vault.
                    registry_count (int): Number of registry entries.
                    bootstrapped_at (str|None): Last bootstrap timestamp.
                    vault_secrets_count (int): Pre-existing vault secrets count.
                    vault_secret_keys (list[str]): Pre-existing vault secret key names.
                    discovery_status (str): "fresh" | "discovered" | "propagated".
                    awaiting_confirmation (bool): True when secrets discovered but not propagated.
                    errors (list[str]): Any errors encountered.

        Satisfies: AC-07, E-08-ext AC-D3
        """
        status: Dict[str, Any] = {
            "connected": False,
            "authenticated": False,
            "mount_exists": False,
            "path_exists": False,
            "secrets_count": 0,
            "registry_count": 0,
            "bootstrapped_at": None,
            # E-08-ext: Discovery fields
            "vault_secrets_count": 0,
            "vault_secret_keys": [],
            "discovery_status": "fresh",
            "awaiting_confirmation": False,
            "errors": [],
        }

        try:
            from openbao_helpers.config import load_config
            from helpers.plugins import find_plugin_dir
            plugin_dir = find_plugin_dir("deimos_openbao_secrets")
            if not plugin_dir:
                status["errors"].append("Plugin directory not found")
                return {"ok": False, "status": status}

            config = load_config(plugin_dir)
            if not config.enabled:
                status["errors"].append("Plugin disabled")
                return {"ok": False, "status": status}

            # Check connectivity via OpenBaoClient health_check
            try:
                from openbao_helpers.openbao_client import OpenBaoClient
                client = OpenBaoClient(config)
                health = client.health_check()
                status["connected"] = health.get("connected", False)
                status["authenticated"] = health.get("authenticated", False)

                # Check mount and path existence
                if status["connected"] and client._client:
                    try:
                        mounts = client._client.sys.list_mounted_secrets_engines()
                        status["mount_exists"] = f"{config.mount_point}/" in mounts
                    except Exception:
                        pass

                    try:
                        resp = client._client.secrets.kv.v2.read_secret_version(
                            path=config.secrets_path,
                            mount_point=config.mount_point,
                            raise_on_deleted_version=False,
                        )
                        status["path_exists"] = resp is not None
                        if resp and isinstance(resp.get("data", {}).get("data"), dict):
                            secret_data = resp["data"]["data"]
                            non_internal = {
                                k: v for k, v in secret_data.items()
                                if not k.startswith("_")
                            }
                            status["secrets_count"] = len(non_internal)
                    except Exception:
                        pass

                client.close()
            except Exception as exc:
                status["errors"].append(f"Connection error: {exc}")

            # Check registry — includes discovery metadata
            try:
                from openbao_helpers.registry import RegistryManager
                rm = RegistryManager()
                registry = rm.load()
                status["registry_count"] = len(registry.get("entries", []))
                status["bootstrapped_at"] = registry.get("bootstrapped_at")

                # E-08-ext AC-D3: Extract discovery metadata from registry
                discovery_status = registry.get("discovery_status")
                if discovery_status:
                    status["discovery_status"] = discovery_status
                    status["vault_secret_keys"] = registry.get("vault_secret_keys", [])
                    status["vault_secrets_count"] = len(status["vault_secret_keys"])
                    status["awaiting_confirmation"] = (
                        discovery_status == "discovered"  # CR-3: 'deferred' does NOT await confirmation
                    )
                elif status["secrets_count"] > 0:
                    # Secrets exist but no discovery_status set — fresh install
                    # that was seeded (not brownfield)
                    status["discovery_status"] = "fresh"
                    status["awaiting_confirmation"] = False

            except Exception as exc:
                status["errors"].append(f"Registry error: {exc}")

        except Exception as exc:
            status["errors"].append(f"Status check failed: {exc}")
            logger.error("install_status error: %s", exc)

        return {"ok": len(status["errors"]) == 0, "status": status}
