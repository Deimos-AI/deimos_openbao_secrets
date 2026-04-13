"""Cross-plugin secret discovery and .env → OpenBao migration endpoint.

Endpoint: POST /api/plugins/deimos_openbao_secrets/sync_plugins

Behaviour:
  If secrets registry exists (is_bootstrap_needed() == False):
    Registry-mode: migrate discovered entries to OpenBao (AC-15, AC-16).
  Else:
    Legacy-mode: scan usr/plugins/*/plugin.yaml for 'secrets:' declarations.

Gated by plugin_sync_enabled flag in default_config.yaml.
"""
import importlib
import importlib.util
import logging
import os
import re
import sys
from pathlib import Path
from helpers.api import ApiHandler, Request, Response

# ---------------------------------------------------------------------------
# Plugin helper bootstrap — load helpers/config.py via importlib.util.
# Same pattern as api/secrets.py — see that file for detailed rationale.
# ---------------------------------------------------------------------------
_PLUGIN_CFG_MODULE = "openbao_helpers.config"


def _get_config_module():
    """Load plugin's helpers/config.py, cached in sys.modules."""
    if _PLUGIN_CFG_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            raise ImportError("deimos_openbao_secrets plugin dir not found via find_plugin_dir()")
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


logger = logging.getLogger(__name__)

# Plugin directory — resolved from this file's location
_PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _sanitize_path_component(value: str) -> str:
    """CRIT-03: Sanitize a string for safe use as a KV v2 vault path component.

    Strips path separators, dotdot sequences, and non-safe characters.
    Raises ValueError if the sanitized result is empty (after stripping).
    """
    original = value
    for sep in ("/", "\\"):
        value = value.replace(sep, "_")
    value = re.sub(r"\.\. +", "_", value)
    value = re.sub(r"[^a-zA-Z0-9_.\-]", "_", value)
    value = value.lstrip(".")
    if not value:
        raise ValueError(
            f"path component {original!r} sanitizes to empty — rejected (CRIT-03)"
        )
    return value


# ---------------------------------------------------------------------------
# vault_io loader (mirrors Surface A loader pattern)
# ---------------------------------------------------------------------------
_VAULT_IO_MODULE = "openbao_helpers.vault_io"
_USR_PLUGINS_DIR = Path("/a0/usr/plugins")


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
# registry loader (AC-15) — importlib.util pattern
# ---------------------------------------------------------------------------
_REGISTRY_MODULE = "openbao_helpers.registry"


def _load_registry():
    """Load helpers/registry.py via importlib.util, cached in sys.modules."""
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


class SyncPlugins(ApiHandler):


    """Cross-plugin secret discovery and .env → OpenBao migration endpoint."""

    @classmethod
    def requires_csrf(cls) -> bool:
        return False

    async def process(self, input: dict, request: Request) -> dict | Response:
        import yaml  # PyYAML — already present in A0 runtime environment

        # Gate: plugin_sync_enabled (AC-14)
        try:
            cfg = load_config(str(_PLUGIN_DIR))
        except Exception as exc:
            return {"ok": False, "error": f"Config load failed: {exc}"}

        if not getattr(cfg, "plugin_sync_enabled", True):
            return {
                "ok": False,
                "error": "Plugin sync is disabled (plugin_sync_enabled=false)",
            }

        # MED-06: Block sync over HTTP — secrets must not transit unencrypted
        if cfg.url.startswith("http://"):
            return {
                "ok": False,
                "error": "Sync requires HTTPS vault URL — refusing to migrate "
                        "secrets over unencrypted connection",
            }

        vio = _load_vault_io()
        if vio is None:
            return {"ok": False, "error": "vault_io not available"}

        manager = vio._ensure_manager()
        if manager is None:
            return {"ok": False, "error": "OpenBao manager could not be initialized. The plugin factory may be locked out from a boot-time failure. Try restarting Agent Zero or check logs for initialization errors."}
        secrets_path = getattr(cfg, "secrets_path", "agentzero")

        # AC-15: registry-mode check — if registry exists, use registry-mode migration
        reg_mod = _load_registry()
        if reg_mod is not None:
            rm = reg_mod.RegistryManager()
            if not rm.is_bootstrap_needed():  # AC-15: registry present
                return await self._process_registry_mode(rm, cfg, vio, manager, secrets_path)
        # Fallback: legacy plugin.yaml scan (unchanged, backward compat)

        results = []
        for plugin_yaml_path in sorted(_USR_PLUGINS_DIR.glob("*/plugin.yaml")):
            plugin_name = plugin_yaml_path.parent.name
            try:
                with open(plugin_yaml_path) as f:
                    spec = yaml.safe_load(f) or {}
            except Exception:
                continue

            secrets_decls = spec.get("secrets", [])
            if not secrets_decls:
                continue

            plugin_result = {"name": plugin_name, "secrets": []}
            for decl in secrets_decls:
                key = decl.get("key", "")
                description = decl.get("description", "")
                if not key:
                    continue

                vault_path = f"{secrets_path}/{_sanitize_path_component(plugin_name)}"  # CRIT-03
                existing = vio._vault_read(manager, vault_path) or {}

                if key in existing:
                    status = "exists"  # AC-13: already in OpenBao
                else:
                    env_val = os.environ.get(key, "")
                    if env_val:
                        try:
                            written = vio.write_if_absent(manager, vault_path, key, env_val)
                            status = "migrated" if written else "exists"  # AC-13
                        except Exception as exc:
                            logger.error(
                                "sync_plugins: write_if_absent failed for %s/%s: %s",
                                plugin_name, key, exc,
                            )
                            status = "missing"
                    else:
                        status = "missing"  # AC-13: absent from both

                plugin_result["secrets"].append(
                    {"key": key, "status": status, "description": description}
                )
            results.append(plugin_result)

        return {"ok": True, "plugins": results}  # AC-12

    async def _process_registry_mode(self, rm, cfg, vio, manager, secrets_path: str) -> dict:
        """Registry-mode: migrate all 'discovered' registry entries to OpenBao.

        Satisfies: AC-15, AC-16
        """
        hard_fail = getattr(cfg, "hard_fail_on_unavailable", False)  # AC-16

        discovered = rm.get_entries(status_filter="discovered")  # AC-15

        result_pairs: list[tuple[str, str]] = []  # (entry_id, final_status)
        response_entries: list[dict] = []

        for entry in discovered:
            vault_path = f"{secrets_path}/{_sanitize_path_component(entry.key)}"

            # Check OpenBao
            try:
                existing = vio._vault_read(manager, vault_path) or {}
            except Exception as exc:
                # AC-16: OpenBao unavailable handling
                if hard_fail:  # AC-16: raise immediately
                    return {
                        "ok": False,
                        "error": "OpenBao unavailable and hard_fail_on_unavailable=True",
                    }
                logger.warning("sync_plugins registry-mode: vault read failed for %s: %s", entry.key, exc)
                existing = {}

            if entry.key in existing:
                final_status = "exists"  # AC-15
            else:
                env_val = os.environ.get(entry.key, "")
                if env_val:
                    try:
                        written = vio.write_if_absent(manager, vault_path, entry.key, env_val)
                        final_status = "migrated" if written else "exists"  # AC-15
                    except Exception as exc:
                        if hard_fail:  # AC-16
                            return {
                                "ok": False,
                                "error": "OpenBao unavailable and hard_fail_on_unavailable=True",
                            }
                        logger.warning("sync_plugins registry-mode: write_if_absent failed %s: %s", entry.key, exc)
                        final_status = "missing"
                else:
                    final_status = "missing"  # AC-15: absent from both

            # Collect update pairs — do NOT write registry mid-loop (AC-15)
            if final_status in ("exists", "migrated"):
                result_pairs.append((entry.id, final_status))

            response_entries.append({
                "key": entry.key,
                "source": entry.source,
                "context": entry.context,
                "status": final_status,
            })

        # AC-15: bulk-save registry after full loop completes (no partial writes)
        for entry_id, status in result_pairs:
            rm.update_status(entry_id, status)

        return {"ok": True, "mode": "registry", "entries": response_entries}  # AC-15
