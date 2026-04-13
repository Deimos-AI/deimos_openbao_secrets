"""Propagate secret placeholders into consuming configs.

Endpoint: POST /api/plugins/deimos_openbao_secrets/propagate
Actions: scan | propagate | undo | list_backups

Satisfies: AC-20 through AC-26
"""
import importlib
import importlib.util
import logging
import os
import sys
from pathlib import Path
from helpers.api import ApiHandler, Request, Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Plugin helper bootstrap -- load helpers/config.py via importlib.util.
# Same pattern as api/sync_plugins.py.
# ---------------------------------------------------------------------------
_PLUGIN_CFG_MODULE = "openbao_helpers.config_propagate"


def _get_config_module():
    """Load plugin's helpers/config.py, cached in sys.modules."""
    if _PLUGIN_CFG_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            raise ImportError("deimos_openbao_secrets plugin dir not found")
        config_path = os.path.join(plugin_dir, "openbao_helpers", "config.py")
        if not os.path.exists(config_path):
            raise ImportError(f"helpers/config.py not found at: {config_path}")
        spec = importlib.util.spec_from_file_location(_PLUGIN_CFG_MODULE, config_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_PLUGIN_CFG_MODULE] = mod
        spec.loader.exec_module(mod)
    return sys.modules[_PLUGIN_CFG_MODULE]


def load_config(plugin_dir: str):
    """Delegate to plugin's helpers/config.py::load_config()."""
    return _get_config_module().load_config(plugin_dir)


_PLUGIN_DIR = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# vault_io loader (same pattern as sync_plugins.py)
# ---------------------------------------------------------------------------
_VAULT_IO_MODULE = "openbao_helpers.vault_io_propagate"


def _load_vault_io():
    """Load helpers/vault_io.py, cached in sys.modules."""
    if _VAULT_IO_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            return None
        path = os.path.join(plugin_dir, "openbao_helpers", "vault_io.py")
        if not os.path.exists(path):
            return None
        spec = importlib.util.spec_from_file_location(_VAULT_IO_MODULE, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_VAULT_IO_MODULE] = mod
        spec.loader.exec_module(mod)
    return sys.modules.get(_VAULT_IO_MODULE)


# ---------------------------------------------------------------------------
# propagator loader
# ---------------------------------------------------------------------------
_PROPAGATOR_MODULE = "openbao_helpers.propagator_api"


def _load_propagator():
    """Load helpers/propagator.py via importlib.util."""
    if _PROPAGATOR_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            return None
        path = os.path.join(plugin_dir, "openbao_helpers", "propagator.py")
        if not os.path.exists(path):
            return None
        spec = importlib.util.spec_from_file_location(_PROPAGATOR_MODULE, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_PROPAGATOR_MODULE] = mod
        spec.loader.exec_module(mod)
    return sys.modules.get(_PROPAGATOR_MODULE)


# ---------------------------------------------------------------------------
# registry loader
# ---------------------------------------------------------------------------
_REGISTRY_MODULE = "openbao_helpers.registry_propagate"


def _load_registry():
    """Load helpers/registry.py via importlib.util."""
    if _REGISTRY_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            return None
        path = os.path.join(plugin_dir, "openbao_helpers", "registry.py")
        if not os.path.exists(path):
            return None
        spec = importlib.util.spec_from_file_location(_REGISTRY_MODULE, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_REGISTRY_MODULE] = mod
        spec.loader.exec_module(mod)
    return sys.modules.get(_REGISTRY_MODULE)


class Propagate(ApiHandler):
    """Propagate secret placeholders into consuming configs.

    Endpoint: POST /api/plugins/deimos_openbao_secrets/propagate
    Actions: scan | propagate | undo | list_backups

    Satisfies: AC-20 through AC-26
    """

    @classmethod
    def requires_csrf(cls) -> bool:
        return False

    async def process(self, input: dict, request: Request) -> dict | Response:
        action = input.get("action", "scan")

        # AC-25: Gate by plugin_sync_enabled
        try:
            cfg = load_config(str(_PLUGIN_DIR))
        except Exception as exc:
            return {"ok": False, "error": f"Config load failed: {exc}"}

        if not getattr(cfg, "plugin_sync_enabled", True):
            return {
                "ok": False,
                "error": "Plugin sync is disabled (plugin_sync_enabled=false)",
            }

        # AC-26: HTTPS enforcement
        if cfg.url.startswith("http://"):
            return {
                "ok": False,
                "error": "Propagate requires HTTPS vault URL -- refusing to operate "
                         "over unencrypted connection",
            }

        # Load dependencies
        vio = _load_vault_io()
        if vio is None:
            return {"ok": False, "error": "vault_io not available"}

        manager = vio._ensure_manager()
        if manager is None:
            return {"ok": False, "error": "OpenBao manager could not be initialized. The plugin factory may be locked out from a boot-time failure. Try restarting Agent Zero or check logs for initialization errors."}

        prop_mod = _load_propagator()
        if prop_mod is None:
            return {"ok": False, "error": "propagator module not available"}

        reg_mod = _load_registry()
        registry_manager = reg_mod.RegistryManager() if reg_mod else None

        propagator = prop_mod.Propagator(
            vault_reader=vio,
            registry_manager=registry_manager,
        )

        # Dispatch by action
        if action == "scan":
            return await self._action_scan(propagator, prop_mod)
        elif action == "propagate":
            return await self._action_propagate(
                propagator, prop_mod, input.get("targets", [])
            )
        elif action == "undo":
            return await self._action_undo(propagator, input.get("backup_id", ""))
        elif action == "list_backups":
            return await self._action_list_backups(propagator)
        else:
            return {"ok": False, "error": f"Unknown action: {action}"}

    async def _action_scan(self, propagator, prop_mod) -> dict:
        """AC-21: scan returns targets without modification."""
        targets = propagator.scan_targets()
        return {
            "ok": True,
            "targets": [
                {
                    "id": t.id,
                    "file_path": t.file_path,
                    "field_name": t.field_name,
                    "current_preview": t.current_preview,
                    "vault_key": t.vault_key,
                    "proposed_ref": t.proposed_ref,
                    "target_type": t.target_type,
                }
                for t in targets
            ],
        }

    async def _action_propagate(self, propagator, prop_mod, target_ids: list) -> dict:
        """AC-22, AC-23: propagate selected targets."""
        # Need to scan first to get full target objects
        all_targets = propagator.scan_targets()
        result = propagator.propagate(target_ids, all_targets)
        return {
            "ok": result.ok,  # AC-23
            "propagated": result.propagated,  # AC-23
            "skipped": result.skipped,
            "errors": result.errors,
            "backups": result.backups_created,  # AC-23
        }

    async def _action_undo(self, propagator, backup_id: str) -> dict:
        """AC-24: undo restores files from backup timestamp."""
        if not backup_id:
            return {"ok": False, "error": "backup_id is required for undo"}
        return propagator.undo(backup_id=backup_id)

    async def _action_list_backups(self, propagator) -> dict:
        """AC-19: list available backup sets."""
        backups = propagator.list_backups()
        return {"ok": True, "backups": backups}
