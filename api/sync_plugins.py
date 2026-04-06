"""Cross-plugin secret discovery and .env → OpenBao migration endpoint.

Endpoint: POST /api/plugins/deimos_openbao_secrets/sync_plugins

Scans usr/plugins/*/plugin.yaml for 'secrets:' declarations.
For each declared key:
  exists   — key already in OpenBao (no write)
  migrated — key absent in OpenBao + present in .env → written via write_if_absent
  missing  — key absent in both (surfaced to user, no write)

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
_PLUGIN_CFG_MODULE = "deimos_openbao_secrets_helpers_config"


def _get_config_module():
    """Load plugin's helpers/config.py, cached in sys.modules."""
    if _PLUGIN_CFG_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            raise ImportError("deimos_openbao_secrets plugin dir not found via find_plugin_dir()")
        config_path = os.path.join(plugin_dir, "helpers", "config.py")
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
_VAULT_IO_MODULE = "deimos_openbao_secrets_helpers_vault_io"
_USR_PLUGINS_DIR = Path("/a0/usr/plugins")


def _load_vault_io():
    """Load helpers/vault_io.py, cached in sys.modules."""
    if _VAULT_IO_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            return None
        path = os.path.join(plugin_dir, "helpers", "vault_io.py")
        if not os.path.exists(path):
            return None
        spec = importlib.util.spec_from_file_location(_VAULT_IO_MODULE, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_VAULT_IO_MODULE] = mod
        spec.loader.exec_module(mod)
    return sys.modules.get(_VAULT_IO_MODULE)


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

        manager = vio._get_manager()
        secrets_path = getattr(cfg, "secrets_path", "agentzero")

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
