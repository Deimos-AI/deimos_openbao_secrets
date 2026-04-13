"""First-install secrets registry bootstrap endpoint.

Endpoint: POST /api/plugins/deimos_openbao_secrets/bootstrap

Actions:
  status — returns registry present/absent and entry count
  scan   — runs all three scan sources, writes registry (unless dry_run)

Satisfies: AC-11, AC-12 (REM-017)
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from helpers.api import ApiHandler, Request, Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Plugin config module loader (same pattern as sync_plugins.py)
# ---------------------------------------------------------------------------
_PLUGIN_CFG_MODULE = "openbao_helpers.config"
_SCANNER_MODULE = "openbao_helpers.secrets_scanner"
_REGISTRY_MODULE = "openbao_helpers.registry"

# Plugin directory — resolved from this file's location
_PLUGIN_DIR = Path(__file__).resolve().parent.parent


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


def _load_config(plugin_dir: str):
    """Delegate to plugin's helpers/config.py::load_config()."""
    return _get_config_module().load_config(plugin_dir)


def _load_raw_config(plugin_dir: str) -> dict:
    """Load default_config.yaml + config.json as raw dict.

    Bypasses OpenBaoConfig dataclass (which drops unknown keys like
    registry_path and env_scan_root). Same merge order as hooks.py.
    """
    import yaml

    cfg: dict = {}
    default_path = Path(plugin_dir) / "default_config.yaml"
    config_path = Path(plugin_dir) / "config.json"

    if default_path.exists():
        try:
            with open(default_path, encoding="utf-8") as f:
                cfg.update(yaml.safe_load(f) or {})
        except Exception as exc:
            logger.debug("_load_raw_config: default_config.yaml error: %s", exc)

    if config_path.exists():
        try:
            with open(config_path, encoding="utf-8") as f:
                cfg.update(json.load(f) or {})
        except Exception as exc:
            logger.debug("_load_raw_config: config.json error: %s", exc)

    return cfg


def _load_scanner():
    """Load helpers/secrets_scanner.py via importlib.util, cached."""
    if _SCANNER_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            return None
        path = os.path.join(plugin_dir, "openbao_helpers", "secrets_scanner.py")
        if not os.path.exists(path):
            return None
        spec = importlib.util.spec_from_file_location(_SCANNER_MODULE, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_SCANNER_MODULE] = mod
        spec.loader.exec_module(mod)
    return sys.modules.get(_SCANNER_MODULE)


def _load_registry():
    """Load helpers/registry.py via importlib.util, cached."""
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


class Bootstrap(ApiHandler):
    """First-install secrets registry bootstrap endpoint.

    Satisfies: AC-11, AC-12 (REM-017)
    """

    @classmethod
    def requires_csrf(cls) -> bool:  # AC-11: requires_csrf = False
        return False

    async def process(self, input: dict, request: Request) -> dict | Response:
        """Dispatch on action: status | scan.

        Satisfies: AC-11, AC-12
        """
        try:
            return await self._dispatch(input)
        except Exception as exc:
            logger.exception("Bootstrap.process: unhandled error")
            return {"ok": False, "error": str(exc)}

    async def _dispatch(self, input: dict) -> dict:
        action = input.get("action", "scan")  # AC-11: default action is scan

        reg_mod = _load_registry()
        if reg_mod is None:
            return {"ok": False, "error": "helpers/registry.py not available"}

        rm = reg_mod.RegistryManager()

        if action == "status":  # AC-11: status branch
            return {
                "ok": True,
                "bootstrap_needed": rm.is_bootstrap_needed(),
                "registry_path": str(rm.get_path()),
                "entry_count": len(rm.get_entries()),
            }

        if action == "scan":  # AC-11: scan branch
            return await self._handle_scan(input, rm, reg_mod)

        return {"ok": False, "error": f"Unknown action: {action!r}"}

    async def _handle_scan(self, input: dict, rm, reg_mod) -> dict:
        """Run all three scanners, build registry, optionally write.

        Satisfies: AC-11, AC-12
        """
        scanner_mod = _load_scanner()
        if scanner_mod is None:
            return {"ok": False, "error": "helpers/secrets_scanner.py not available"}

        # Load config for scan parameters
        plugin_dir = str(_PLUGIN_DIR)
        raw_cfg = _load_raw_config(plugin_dir)

        env_scan_root = raw_cfg.get("env_scan_root", "/a0")  # AC-10
        mcp_scan_paths = raw_cfg.get("mcp_scan_paths", [])  # AC-04

        # Determine a0proj search roots — default to /a0 (includes all project dirs)
        a0proj_search_roots = raw_cfg.get("a0proj_search_roots", [str(Path(plugin_dir).parent)])
        if isinstance(a0proj_search_roots, str):
            a0proj_search_roots = [a0proj_search_roots]

        # Run all three scan sources
        env_entries = scanner_mod.env_scan(env_scan_root)
        a0proj_entries = scanner_mod.a0proj_scan(a0proj_search_roots)
        mcp_entries = scanner_mod.mcp_scan(mcp_scan_paths)

        all_scan_entries = env_entries + a0proj_entries + mcp_entries

        # Build RegistryEntry list — deduplicate by make_id
        RegistryEntry = reg_mod.RegistryEntry
        seen_ids: set[str] = set()
        registry_entries: list = []

        for scan_entry in all_scan_entries:
            entry_id = RegistryEntry.make_id(
                scan_entry.source, scan_entry.context, scan_entry.key
            )
            if entry_id in seen_ids:
                continue
            seen_ids.add(entry_id)

            # AC-12: context = relative path (no leading /)
            context = scan_entry.context.lstrip("/")

            # AC-12: description contains no secret values
            description = f"Discovered in {scan_entry.source} at {context}"

            entry = RegistryEntry(
                id=entry_id,
                key=scan_entry.key,
                source=scan_entry.source,
                context=context,
                description=description,
                discovered_at=scan_entry.discovered_at,
                status="discovered",
            )
            registry_entries.append(entry)

        # Build registry dict  — AC-08 schema
        bootstrapped_at = datetime.now(timezone.utc).isoformat()
        registry = {
            "version": 1,
            "bootstrapped_at": bootstrapped_at,
            "entries": [e.to_dict() for e in registry_entries],
        }

        # AC-11: write registry unless dry_run
        dry_run = bool(input.get("dry_run", False))
        if not dry_run:
            rm.save(registry)

        # AC-11: sort by source ascending then key ascending
        sorted_entries = sorted(registry_entries, key=lambda e: (e.source, e.key))

        # Build response entries — AC-12: no secret values anywhere
        response_entries = [
            {
                "id": e.id,
                "key": e.key,
                "source": e.source,
                "context": e.context,  # AC-12: relative path, no leading /
                "status": e.status,
            }
            for e in sorted_entries
        ]

        return {"ok": True, "entries": response_entries}
