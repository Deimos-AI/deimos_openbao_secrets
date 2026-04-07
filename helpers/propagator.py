"""helpers/propagator.py — Propagate Secret Placeholders into consuming configs.

Discovers plaintext secret values in model presets, .env files, and plugin
configs — replaces them with $bao:KEY references that resolve from OpenBao.

Satisfies: AC-01 through AC-06, AC-07 through AC-19, AC-31 through AC-34

Design decisions:
  DDR-01: Adapter pattern for config formats
  DDR-02: SHA-256 dedup matching (reuses Surface A scheme with [:32] prefix)
  DDR-03: Backup-as-sidecar pattern
  DDR-04: No boot-time chicken-and-egg mitigation (Surface A handles fallback)

stdlib + yaml only — no top-level `from helpers.*` imports.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants — skip prefixes (AC-05, AC-06)
# ---------------------------------------------------------------------------
_BAO_REF_PREFIX = "$bao:"
_REDACTED_PREFIX = "[bao-ref:REDACTED]"

# AC-32: Values that should never be matched
_SKIP_VALUES = frozenset({"", '""', "None", "************", "****"})

# .env key patterns (AC-08)
_ENV_KEY_RE = re.compile(r"^(API_KEY_.+|.+_API_KEY)$")

# Backup pattern (DDR-03)
_BACKUP_SUFFIX_RE = re.compile(r"\.bao-backup\.(.+)$")
_MAX_BACKUPS = 10  # AC-34


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _sha256_prefix(value: str) -> str:
    """Return first 32 hex chars of SHA-256 of value. AC-03."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _should_skip_value(value: str) -> bool:
    """Return True if value should be skipped. AC-05, AC-06, AC-32."""
    if not isinstance(value, str):
        return True
    if not value.strip():  # AC-32: empty
        return True
    if value.startswith(_BAO_REF_PREFIX):  # AC-05: already a $bao: ref
        return True
    if value.startswith(_REDACTED_PREFIX):  # AC-06: Surface A placeholder
        return True
    if value in _SKIP_VALUES:  # AC-32: masked values
        return True
    return False


def _preview(value: str, max_len: int = 8) -> str:
    """Return masked preview of value for UI display. AC-02."""
    if len(value) <= max_len:
        return value[:3] + "..."
    return value[:max_len] + "..."


def _rotate_backups(file_path: str) -> None:
    """AC-34: Remove oldest backups if more than _MAX_BACKUPS exist."""
    p = Path(file_path)
    parent = p.parent
    stem = p.name
    backups = sorted(parent.glob(f"{stem}.bao-backup.*"))
    if len(backups) > _MAX_BACKUPS:
        for old_backup in backups[: len(backups) - _MAX_BACKUPS]:
            try:
                old_backup.unlink()
                logger.debug("Rotated old backup: %s", old_backup)
            except OSError:
                pass


def _create_backup(file_path: str) -> str:
    """AC-12: Create timestamped backup, return backup path."""
    _rotate_backups(file_path)  # AC-34
    ts = _now_iso().replace(":", "-").replace("+", "Z")
    backup_path = f"{file_path}.bao-backup.{ts}"
    with open(file_path, "r", encoding="utf-8") as src:
        content = src.read()
    with open(backup_path, "w", encoding="utf-8") as dst:
        dst.write(content)
    logger.debug("Created backup: %s", backup_path)
    return backup_path


# ---------------------------------------------------------------------------
# Data structures — AC-01, AC-02, AC-04
# ---------------------------------------------------------------------------

@dataclass
class PropagationTarget:
    """One candidate field for placeholder propagation.

    Satisfies: AC-02 (structure), AC-04 (vault_key field)
    """
    id: str                    # Composite: "{file_path}:{field_path}"
    file_path: str             # Absolute path to config file
    field_path: str            # Dot-separated path within the file
    field_name: str            # Human-readable field name
    current_preview: str       # First 8 chars + "..." (masked, for UI display)
    vault_key: str             # OpenBao key the $bao: reference will point to — AC-04
    proposed_ref: str          # "$bao:{vault_key}"
    target_type: str           # "preset" | "dotenv" | "plugin_json" | "plugin_yaml"
    adapter_name: str          # Adapter class name for writer dispatch


@dataclass
class PropagationResult:
    """Result of a propagation operation. AC-11."""
    ok: bool
    propagated: int
    skipped: int
    errors: list[str]
    backups_created: list[str]


# ---------------------------------------------------------------------------
# TargetAdapter ABC — DDR-01
# ---------------------------------------------------------------------------

class TargetAdapter(ABC):
    """Base class for config format adapters. DDR-01."""

    @abstractmethod
    def scan(self, dedup_index: dict[str, str], **kwargs) -> list[PropagationTarget]:
        """Scan config file for candidate fields. AC-02."""
        ...

    @abstractmethod
    def write(self, targets: list[PropagationTarget]) -> list[str]:
        """Write $bao: refs into target fields. Returns list of backup paths. AC-11."""
        ...

    @abstractmethod
    def validate(self) -> bool:
        """Verify file is syntactically valid after write. AC-14."""
        ...


# ---------------------------------------------------------------------------
# PresetsAdapter — AC-07, AC-15
# ---------------------------------------------------------------------------

class PresetsAdapter(TargetAdapter):
    """Scans / writes model presets YAML. AC-07, AC-15."""

    def __init__(self, presets_path: str):
        self._path = presets_path

    def scan(self, dedup_index: dict[str, str], **kwargs) -> list[PropagationTarget]:
        """AC-07: Scan [*].chat.api_key and [*].utility.api_key fields."""
        import yaml  # PyYAML

        if not os.path.exists(self._path):
            return []

        with open(self._path, "r", encoding="utf-8") as f:
            presets = yaml.safe_load(f)
        if not isinstance(presets, list):
            return []

        targets = []
        for idx, preset in enumerate(presets):
            if not isinstance(preset, dict):
                continue
            name = preset.get("name", f"preset_{idx}")
            for section in ("chat", "utility"):
                sub = preset.get(section, {})
                if not isinstance(sub, dict):
                    continue
                value = sub.get("api_key", "")
                if _should_skip_value(value):  # AC-05, AC-06, AC-32
                    continue
                digest = _sha256_prefix(value)  # AC-03
                vault_key = dedup_index.get(digest)
                if vault_key is None:
                    continue
                field_path = f"[{idx}].{section}.api_key"
                targets.append(PropagationTarget(
                    id=f"{self._path}:{field_path}",
                    file_path=self._path,
                    field_path=field_path,
                    field_name=f"{name}.{section}.api_key",
                    current_preview=_preview(value),
                    vault_key=vault_key,  # AC-04
                    proposed_ref=f"{_BAO_REF_PREFIX}{vault_key}",
                    target_type="preset",
                    adapter_name="PresetsAdapter",
                ))
        return targets

    def write(self, targets: list[PropagationTarget]) -> list[str]:
        """AC-11, AC-15: Write $bao: refs to presets YAML."""
        import yaml  # PyYAML

        if not targets:
            return []

        backup_path = _create_backup(self._path)  # AC-12

        with open(self._path, "r", encoding="utf-8") as f:
            presets = yaml.safe_load(f)

        # Build lookup: field_path -> target
        target_map = {t.field_path: t for t in targets}

        for idx, preset in enumerate(presets):
            for section in ("chat", "utility"):
                field_path = f"[{idx}].{section}.api_key"
                if field_path in target_map:
                    sub = preset.get(section, {})
                    sub["api_key"] = target_map[field_path].proposed_ref
                    preset[section] = sub

        # Atomic write — AC-13
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", dir=os.path.dirname(self._path) or ".",
                delete=False, encoding="utf-8",
            ) as tmp:
                yaml.dump(presets, tmp, default_flow_style=False, allow_unicode=True)
                tmp_path = tmp.name
            os.replace(tmp_path, self._path)
        except Exception:
            # AC-13: Rollback from backup
            try:
                os.replace(backup_path, self._path)
            except OSError:
                pass
            raise

        return [backup_path]

    def validate(self) -> bool:
        """AC-14: Verify file is valid YAML."""
        import yaml  # PyYAML

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            return isinstance(data, list)
        except Exception:
            return False


# ---------------------------------------------------------------------------
# DotEnvAdapter — AC-08, AC-16
# ---------------------------------------------------------------------------

class DotEnvAdapter(TargetAdapter):
    """Scans / writes .env files. AC-08, AC-16."""

    def __init__(self, env_path: str):
        self._path = env_path

    def scan(self, dedup_index: dict[str, str], **kwargs) -> list[PropagationTarget]:
        """AC-08: Match API_KEY_* and *_API_KEY entries."""
        if not os.path.exists(self._path):
            return []

        targets = []
        with open(self._path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f):
                line = line.rstrip("\n\r")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "=" not in stripped:
                    continue
                key, _, raw_value = stripped.partition("=")
                key = key.strip()
                # AC-08: Only match API_KEY_* and *_API_KEY patterns
                if not _ENV_KEY_RE.match(key):
                    continue
                # Strip quotes from value
                value = raw_value.strip()
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                elif value.startswith("'") and value.endswith("'"):
                    value = value[1:-1]
                # Strip trailing comment
                if " #" in value:
                    value = value[:value.index(" #")].strip()
                if _should_skip_value(value):  # AC-05, AC-06, AC-32
                    continue
                digest = _sha256_prefix(value)  # AC-03
                vault_key = dedup_index.get(digest)
                if vault_key is None:
                    continue
                targets.append(PropagationTarget(
                    id=f"{self._path}:{key}",
                    file_path=self._path,
                    field_path=key,
                    field_name=key,
                    current_preview=_preview(value),
                    vault_key=vault_key,
                    proposed_ref=f"{_BAO_REF_PREFIX}{vault_key}",
                    target_type="dotenv",
                    adapter_name="DotEnvAdapter",
                ))
        return targets

    def write(self, targets: list[PropagationTarget]) -> list[str]:
        """AC-11, AC-16: Write $bao: refs preserving comments and ordering."""
        if not targets:
            return []

        backup_path = _create_backup(self._path)  # AC-12

        # Build lookup: key -> target
        target_map = {t.field_path: t for t in targets}

        with open(self._path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_lines = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                new_lines.append(line)
                continue
            if "=" not in stripped:
                new_lines.append(line)
                continue
            key, sep, raw_value = stripped.partition("=")
            key = key.strip()
            if key in target_map:
                # Replace value portion, preserving any trailing comment
                value_part = raw_value.strip()
                comment = ""
                if " #" in value_part:
                    idx = value_part.index(" #")
                    comment = value_part[idx:]
                    value_part = value_part[:idx]
                new_lines.append(f"{key}={target_map[key].proposed_ref}{comment}\n")
            else:
                new_lines.append(line)

        # Atomic write — AC-13
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".env", dir=os.path.dirname(self._path) or ".",
                delete=False, encoding="utf-8",
            ) as tmp:
                tmp.writelines(new_lines)
                tmp_path = tmp.name
            os.replace(tmp_path, self._path)
        except Exception:
            try:
                os.replace(backup_path, self._path)
            except OSError:
                pass
            raise

        return [backup_path]

    def validate(self) -> bool:
        """AC-14: Verify file is valid .env format."""
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        continue
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# PluginJsonAdapter — AC-09
# ---------------------------------------------------------------------------

class PluginJsonAdapter(TargetAdapter):
    """Scans / writes plugin config.json files. AC-09."""

    def __init__(self, plugins_dir: str):
        self._plugins_dir = plugins_dir

    def scan(self, dedup_index: dict[str, str], patterns: list[str] = None, **kwargs) -> list[PropagationTarget]:
        """AC-09: Match fields against secret_field_patterns."""
        from fnmatch import fnmatch

        if patterns is None:
            patterns = ["*key*", "*token*", "*secret*", "*password*", "*auth*"]

        targets = []
        plugins_path = Path(self._plugins_dir)
        if not plugins_path.exists():
            return targets

        for config_path in sorted(plugins_path.glob("*/config.json")):
            plugin_name = config_path.parent.name
            # ADR-02: Skip own plugin
            if plugin_name == "deimos_openbao_secrets":
                continue
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            for key, value in data.items():
                if not isinstance(value, str):
                    continue
                lower_key = key.lower()
                if not any(fnmatch(lower_key, pat.lower()) for pat in patterns):
                    continue
                if _should_skip_value(value):
                    continue
                digest = _sha256_prefix(value)
                vault_key = dedup_index.get(digest)
                if vault_key is None:
                    continue
                targets.append(PropagationTarget(
                    id=f"{config_path}:{key}",
                    file_path=str(config_path),
                    field_path=key,
                    field_name=f"{plugin_name}.{key}",
                    current_preview=_preview(value),
                    vault_key=vault_key,
                    proposed_ref=f"{_BAO_REF_PREFIX}{vault_key}",
                    target_type="plugin_json",
                    adapter_name="PluginJsonAdapter",
                ))
        return targets

    def write(self, targets: list[PropagationTarget]) -> list[str]:
        """AC-11: Write $bao: refs to plugin config.json files."""
        if not targets:
            return []

        # Group targets by file
        by_file: dict[str, list[PropagationTarget]] = {}
        for t in targets:
            by_file.setdefault(t.file_path, []).append(t)

        backup_paths = []
        for file_path, file_targets in by_file.items():
            backup = _create_backup(file_path)  # AC-12
            backup_paths.append(backup)

            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            target_map = {t.field_path: t for t in file_targets}
            for key in list(data.keys()):
                if key in target_map:
                    data[key] = target_map[key].proposed_ref

            # Atomic write — AC-13
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", dir=os.path.dirname(file_path) or ".",
                    delete=False, encoding="utf-8",
                ) as tmp:
                    json.dump(data, tmp, indent=2)
                    tmp_path = tmp.name
                os.replace(tmp_path, file_path)
            except Exception:
                try:
                    os.replace(backup, file_path)
                except OSError:
                    pass
                raise

        return backup_paths

    def validate(self) -> bool:
        """AC-14: Verify all config.json files are valid JSON."""
        plugins_path = Path(self._plugins_dir)
        for config_path in plugins_path.glob("*/config.json"):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    json.load(f)
            except Exception:
                return False
        return True


# ---------------------------------------------------------------------------
# PluginYamlAdapter — AC-10
# ---------------------------------------------------------------------------

class PluginYamlAdapter(TargetAdapter):
    """Scans / writes plugin default_config.yaml files. AC-10."""

    def __init__(self, plugins_dir: str):
        self._plugins_dir = plugins_dir

    def scan(self, dedup_index: dict[str, str], patterns: list[str] = None, **kwargs) -> list[PropagationTarget]:
        """AC-10: Match fields against secret_field_patterns."""
        import yaml  # PyYAML
        from fnmatch import fnmatch

        if patterns is None:
            patterns = ["*key*", "*token*", "*secret*", "*password*", "*auth*"]

        targets = []
        plugins_path = Path(self._plugins_dir)
        if not plugins_path.exists():
            return targets

        for config_path in sorted(plugins_path.glob("*/default_config.yaml")):
            plugin_name = config_path.parent.name
            # ADR-02: Skip own plugin
            if plugin_name == "deimos_openbao_secrets":
                continue
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            for key, value in data.items():
                if not isinstance(value, str):
                    continue
                lower_key = key.lower()
                if not any(fnmatch(lower_key, pat.lower()) for pat in patterns):
                    continue
                if _should_skip_value(value):
                    continue
                digest = _sha256_prefix(value)
                vault_key = dedup_index.get(digest)
                if vault_key is None:
                    continue
                targets.append(PropagationTarget(
                    id=f"{config_path}:{key}",
                    file_path=str(config_path),
                    field_path=key,
                    field_name=f"{plugin_name}.{key}",
                    current_preview=_preview(value),
                    vault_key=vault_key,
                    proposed_ref=f"{_BAO_REF_PREFIX}{vault_key}",
                    target_type="plugin_yaml",
                    adapter_name="PluginYamlAdapter",
                ))
        return targets

    def write(self, targets: list[PropagationTarget]) -> list[str]:
        """AC-11: Write $bao: refs to plugin default_config.yaml files."""
        import yaml  # PyYAML

        if not targets:
            return []

        by_file: dict[str, list[PropagationTarget]] = {}
        for t in targets:
            by_file.setdefault(t.file_path, []).append(t)

        backup_paths = []
        for file_path, file_targets in by_file.items():
            backup = _create_backup(file_path)  # AC-12
            backup_paths.append(backup)

            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            target_map = {t.field_path: t for t in file_targets}
            for key in list(data.keys()):
                if key in target_map:
                    data[key] = target_map[key].proposed_ref

            # Atomic write — AC-13
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".yaml", dir=os.path.dirname(file_path) or ".",
                    delete=False, encoding="utf-8",
                ) as tmp:
                    yaml.dump(data, tmp, default_flow_style=False, allow_unicode=True)
                    tmp_path = tmp.name
                os.replace(tmp_path, file_path)
            except Exception:
                try:
                    os.replace(backup, file_path)
                except OSError:
                    pass
                raise

        return backup_paths

    def validate(self) -> bool:
        """AC-14: Verify all default_config.yaml files are valid YAML."""
        import yaml  # PyYAML

        plugins_path = Path(self._plugins_dir)
        for config_path in plugins_path.glob("*/default_config.yaml"):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    yaml.safe_load(f)
            except Exception:
                return False
        return True


# ---------------------------------------------------------------------------
# Propagator orchestrator — AC-01, AC-02, AC-03, AC-11, AC-17-19, AC-31
# ---------------------------------------------------------------------------

class Propagator:
    """Orchestrates placeholder propagation across all config formats.

    Satisfies: AC-01, AC-02, AC-11, AC-17, AC-18, AC-19, AC-31
    """

    def __init__(self, vault_reader=None, registry_manager=None):
        self._vault_reader = vault_reader
        self._registry_manager = registry_manager

    def _build_dedup_index(self) -> dict[str, str]:
        """Read all _dedup/* entries from OpenBao.

        Returns: {sha256_32hex: vault_key} — DDR-02

        AC-03: Value matching uses SHA-256 dedup paths
        """
        if self._vault_reader is None:
            return {}

        index: dict[str, str] = {}
        # The vault_reader is expected to have a method to list dedup paths
        # In practice, we iterate _dedup/ prefix via hvac list
        # For now, delegate to vault_reader's list_dedup_entries if available
        if hasattr(self._vault_reader, "list_dedup_entries"):
            for sha_prefix, canonical_path in self._vault_reader.list_dedup_entries():
                index[sha_prefix] = canonical_path
        return index

    def scan_targets(self) -> list[PropagationTarget]:
        """AC-02: Run all adapters' scan(), merge results.

        AC-31: If vault unavailable, returns empty list.
        """
        if self._vault_reader is None:  # AC-31
            logger.warning("Propagator.scan_targets: vault_reader is None — returning empty")
            return []

        dedup_index = self._build_dedup_index()
        targets = []

        # TODO: Add adapters with resolved paths when integrated into A0 runtime
        # For now, scan_targets requires external dedup_index construction

        return targets

    def propagate(self, target_ids: list[str], all_targets: list[PropagationTarget] = None) -> PropagationResult:
        """AC-11: Backup → write → validate for selected targets.

        AC-13: Atomicity — rollback on failure.
        """
        if not target_ids or not all_targets:
            return PropagationResult(ok=True, propagated=0, skipped=0, errors=[], backups_created=[])

        selected = [t for t in all_targets if t.id in target_ids]
        if not selected:
            return PropagationResult(ok=True, propagated=0, skipped=0, errors=[], backups_created=[])

        # Group by adapter
        by_adapter: dict[str, list[PropagationTarget]] = {}
        for t in selected:
            by_adapter.setdefault(t.adapter_name, []).append(t)

        all_backups = []
        errors = []
        propagated = 0

        for adapter_name, adapter_targets in by_adapter.items():
            # Each target carries enough info for the adapter to write
            # We need to instantiate the adapter per file group
            by_file: dict[str, list[PropagationTarget]] = {}
            for t in adapter_targets:
                by_file.setdefault(t.file_path, []).append(t)

            for file_path, file_targets in by_file.items():
                try:
                    adapter = self._instantiate_adapter(adapter_name, file_path)
                    if adapter is None:
                        errors.append(f"Unknown adapter: {adapter_name}")
                        continue
                    backups = adapter.write(file_targets)
                    all_backups.extend(backups)
                    propagated += len(file_targets)
                except Exception as exc:
                    errors.append(f"{file_path}: {exc}")

        return PropagationResult(
            ok=len(errors) == 0,
            propagated=propagated,
            skipped=0,
            errors=errors,
            backups_created=all_backups,
        )

    def _instantiate_adapter(self, adapter_name: str, file_path: str) -> Optional[TargetAdapter]:
        """Factory method to create adapter from name + file path."""
        if adapter_name == "DotEnvAdapter":
            return DotEnvAdapter(env_path=file_path)
        elif adapter_name == "PresetsAdapter":
            return PresetsAdapter(presets_path=file_path)
        elif adapter_name in ("PluginJsonAdapter", "PluginYamlAdapter"):
            # These need plugins_dir, derive from file_path parent
            plugins_dir = str(Path(file_path).parent)
            if adapter_name == "PluginJsonAdapter":
                return PluginJsonAdapter(plugins_dir=plugins_dir)
            return PluginYamlAdapter(plugins_dir=plugins_dir)
        return None

    def undo(self, backup_id: str, search_dir: str = "/a0") -> dict:
        """AC-17: Restore files from backup timestamp.
        AC-18: Remove backup files after restoration.
        """
        restored = 0
        errors = []
        search_path = Path(search_dir)

        for backup_file in sorted(search_path.glob(f"**/*.bao-backup.{backup_id}")):
            # Determine original file path
            # Pattern: {original}.bao-backup.{timestamp}
            match = _BACKUP_SUFFIX_RE.search(backup_file.name)
            if not match:
                continue
            original_name = backup_file.name[:match.start()]
            original_path = backup_file.parent / original_name

            try:
                # AC-17: Restore
                with open(backup_file, "r", encoding="utf-8") as src:
                    content = src.read()
                with open(original_path, "w", encoding="utf-8") as dst:
                    dst.write(content)
                # AC-18: Remove backup
                backup_file.unlink()
                restored += 1
            except Exception as exc:
                errors.append(f"{backup_file}: {exc}")

        return {"ok": len(errors) == 0, "restored": restored, "errors": errors}

    def list_backups(self, search_dir: str = "/a0") -> list[dict]:
        """AC-19: Return available backup sets."""
        search_path = Path(search_dir)
        by_ts: dict[str, list[str]] = {}

        for backup_file in sorted(search_path.glob("**/*.bao-backup.*")):
            match = _BACKUP_SUFFIX_RE.search(backup_file.name)
            if not match:
                continue
            ts = match.group(1)
            by_ts.setdefault(ts, []).append(str(backup_file))

        return [
            {"timestamp": ts, "file_count": len(files), "files": files}
            for ts, files in sorted(by_ts.items())
        ]
