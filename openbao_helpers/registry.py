"""helpers/registry.py — Secrets registry persistence layer.

stdlib + yaml only — no top-level `from helpers.*` imports.
Loaded dynamically by api/ files via importlib.util pattern.

Satisfies: AC-06 to AC-09 (REM-017)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# _load_raw_config — bypass OpenBaoConfig dataclass (AC-09 workaround)
# ---------------------------------------------------------------------------

def _load_raw_config(plugin_dir: str) -> dict:
    """Load default_config.yaml + config.json as raw dict.

    Bypasses OpenBaoConfig dataclass which silently drops unknown keys.
    Merge order: default_config.yaml first, then config.json overrides.
    Same merge order used by hooks.py get_plugin_config().
    """
    import yaml  # PyYAML — A0 runtime

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


# ---------------------------------------------------------------------------
# RegistryEntry — AC-06, AC-07
# ---------------------------------------------------------------------------

@dataclass
class RegistryEntry:
    """One discovered secret key entry. Satisfies: AC-06, AC-07, AC-08."""

    id: str
    key: str
    source: str
    context: str
    description: str
    discovered_at: str
    status: str  # AC-08: one of discovered, migrated, ignored

    @staticmethod
    def make_id(source: str, context: str, key: str) -> str:  # AC-07
        """Composite id = '{source}:{sha256(context)[:8]}:{key}'.

        Ensures uniqueness across source + context + key combination.
        Satisfies: AC-07
        """
        digest = hashlib.sha256(context.encode()).hexdigest()[:8]
        return f"{source}:{digest}:{key}"

    @classmethod
    def from_dict(cls, d: dict) -> "RegistryEntry":
        """Deserialise from a registry YAML entry dict."""
        return cls(
            id=d["id"],
            key=d["key"],
            source=d["source"],
            context=d["context"],
            description=d.get("description", ""),
            discovered_at=d.get("discovered_at", ""),
            status=d.get("status", "discovered"),
        )

    def to_dict(self) -> dict:
        """Serialise to a plain dict for YAML storage."""
        return asdict(self)


# ---------------------------------------------------------------------------
# RegistryManager — AC-06, AC-08, AC-09
# ---------------------------------------------------------------------------

class RegistryManager:
    """Manages the secrets registry YAML file.

    Path resolution priority (AC-09):
      1. OPENBAO_REGISTRY_PATH environment variable
      2. cfg.registry_path if non-empty string
      3. Default: plugin_dir.parent / '.a0proj' / 'secrets_registry.yaml'

    Satisfies: AC-06, AC-07, AC-08, AC-09
    """

    def __init__(self) -> None:
        self._path: Optional[Path] = None  # lazy cache

    def get_path(self) -> Path:  # AC-09
        """Resolve registry file path (cached after first call).

        Priority: env var → config → default derivation.
        Satisfies: AC-09
        """
        if self._path is not None:
            return self._path

        # Priority 1: environment variable override
        env_val = os.environ.get("OPENBAO_REGISTRY_PATH", "")
        if env_val:
            self._path = Path(env_val)
            return self._path

        # Priority 2 + 3: need plugin directory
        plugin_dir: Optional[str] = None
        try:
            from helpers.plugins import find_plugin_dir  # deferred — A0 runtime
            plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        except Exception:
            pass

        if plugin_dir:
            raw_cfg = _load_raw_config(plugin_dir)
            registry_path_cfg = raw_cfg.get("registry_path", "")
            # Priority 2: config value if non-empty
            if isinstance(registry_path_cfg, str) and registry_path_cfg.strip():
                self._path = Path(registry_path_cfg)
                return self._path

            # Priority 3: default derivation (AC-09)
            resolved_plugin_dir = Path(os.path.realpath(plugin_dir))
            self._path = resolved_plugin_dir.parent / ".a0proj" / "secrets_registry.yaml"
            return self._path

        # Fallback — no plugin dir found (e.g. test context with env override missing)
        self._path = Path("/a0/usr/projects/deimos-openbao-project/.a0proj/secrets_registry.yaml")
        return self._path

    def load(self) -> dict:  # AC-06
        """Load registry from YAML file.

        Returns default empty schema if file absent.
        Satisfies: AC-08 (schema), AC-06
        """
        import yaml  # PyYAML

        target = self.get_path()
        if not target.exists():
            return {"version": 1, "bootstrapped_at": None, "entries": []}  # AC-08
        try:
            with open(target, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return {"version": 1, "bootstrapped_at": None, "entries": []}
            if "entries" not in data:
                data["entries"] = []
            return data
        except Exception as exc:
            logger.warning("RegistryManager.load: error reading %s: %s", target, exc)
            return {"version": 1, "bootstrapped_at": None, "entries": []}

    def save(self, registry: dict) -> None:  # AC-06
        """Atomically write registry dict to YAML file.

        Uses NamedTemporaryFile + os.replace for POSIX atomicity.
        Creates parent directories as needed.
        Satisfies: AC-06, AC-08
        """
        import yaml  # PyYAML

        target = self.get_path()
        target.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write: temp file in same directory → os.replace (AC-06)
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=str(target.parent),
            suffix=".tmp",
            delete=False,
            encoding="utf-8",
        ) as tf:
            yaml.safe_dump(
                registry, tf,
                default_flow_style=False,
                sort_keys=False,
                allow_unicode=True,
            )
            tmp_path = tf.name

        os.replace(tmp_path, str(target))  # atomic on POSIX

    def is_bootstrap_needed(self) -> bool:  # AC-06
        """Return True if registry file does not yet exist.

        Satisfies: AC-06
        """
        return not self.get_path().exists()

    def add_entry(self, entry: RegistryEntry) -> bool:  # AC-06, AC-07
        """Add entry to registry. Returns False (no-op) if id already exists.

        Satisfies: AC-07 (idempotency by id)
        """
        registry = self.load()
        existing_ids = {e["id"] for e in registry.get("entries", [])}
        if entry.id in existing_ids:  # AC-07: duplicate → no-op
            return False
        registry.setdefault("entries", []).append(entry.to_dict())
        self.save(registry)
        return True

    def update_status(self, entry_id: str, status: str) -> bool:  # AC-06
        """Update entry status in registry. Returns False if entry not found.

        Satisfies: AC-06
        """
        registry = self.load()
        for entry_dict in registry.get("entries", []):
            if entry_dict.get("id") == entry_id:
                entry_dict["status"] = status
                self.save(registry)
                return True
        return False  # not found

    def get_entries(self, status_filter: Optional[str] = None) -> list[RegistryEntry]:  # AC-06
        """Return all entries, optionally filtered by status.

        Satisfies: AC-06
        """
        registry = self.load()
        entries = [
            RegistryEntry.from_dict(e)
            for e in registry.get("entries", [])
        ]
        if status_filter is not None:
            entries = [e for e in entries if e.status == status_filter]
        return entries
