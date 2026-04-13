"""test_registry.py — Tests for helpers/registry.py.

Covers: AC-06 to AC-09 (REM-017)
CRUD, id generation, atomicity, schema.

Satisfies: AC-18
"""
import hashlib
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import yaml

import openbao_helpers.registry as reg_mod
from openbao_helpers.registry import RegistryEntry, RegistryManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def registry_path(tmp_path) -> Path:
    """Return a tmp registry path and set OPENBAO_REGISTRY_PATH env var."""
    path = tmp_path / "secrets_registry.yaml"
    return path


@pytest.fixture
def rm(registry_path, monkeypatch) -> RegistryManager:
    """Return a RegistryManager pointed at tmp_path via env var."""
    monkeypatch.setenv("OPENBAO_REGISTRY_PATH", str(registry_path))
    return RegistryManager()


def _make_entry(
    key: str = "MY_KEY",
    source: str = "env_scan",
    context: str = "test.env",
    status: str = "discovered",
    description: str = "Test entry",
) -> RegistryEntry:
    entry_id = RegistryEntry.make_id(source, context, key)
    return RegistryEntry(
        id=entry_id,
        key=key,
        source=source,
        context=context,
        description=description,
        discovered_at="2026-01-01T00:00:00+00:00",
        status=status,
    )


# ---------------------------------------------------------------------------
# AC-06, AC-09 — is_bootstrap_needed
# ---------------------------------------------------------------------------

class TestBootstrapNeeded:

    def test_is_bootstrap_needed_true_when_file_absent(self, rm, registry_path):
        """AC-06: RegistryManager.is_bootstrap_needed() returns True when file absent."""
        assert not registry_path.exists()
        assert rm.is_bootstrap_needed() is True

    def test_is_bootstrap_needed_false_when_file_present(self, rm, registry_path):
        """AC-06: is_bootstrap_needed() returns False when file present."""
        # Write minimal valid YAML
        registry_path.write_text(
            "version: 1\nbootstrapped_at: null\nentries: []\n",
            encoding="utf-8",
        )
        assert rm.is_bootstrap_needed() is False


# ---------------------------------------------------------------------------
# AC-06, AC-07 — add_entry + idempotency
# ---------------------------------------------------------------------------

class TestAddEntry:

    def test_add_and_load_entry(self, rm):
        """AC-06: add RegistryEntry, reload, assert entry present with all fields correct."""
        entry = _make_entry(key="API_KEY_OPENAI", context=".env")
        result = rm.add_entry(entry)

        assert result is True, "First add must return True"

        loaded = rm.get_entries()
        assert len(loaded) == 1
        e = loaded[0]
        assert e.key == "API_KEY_OPENAI"
        assert e.source == "env_scan"
        assert e.context == ".env"
        assert e.status == "discovered"
        assert e.id == entry.id

    def test_add_entry_idempotent(self, rm):
        """AC-07: add same entry twice; get_entries returns exactly one entry; second add_entry returns False."""
        entry = _make_entry(key="DUPLICATE_KEY")
        first = rm.add_entry(entry)
        second = rm.add_entry(entry)

        assert first is True, "First add must return True"
        assert second is False, "Duplicate add must return False (AC-07)"
        assert len(rm.get_entries()) == 1, "Only one entry must exist after duplicate add"


# ---------------------------------------------------------------------------
# AC-06 — update_status
# ---------------------------------------------------------------------------

class TestUpdateStatus:

    def test_update_status(self, rm):
        """AC-06: add entry with status 'discovered', update to 'migrated', reload asserts status == 'migrated'."""
        entry = _make_entry(status="discovered")
        rm.add_entry(entry)

        result = rm.update_status(entry.id, "migrated")
        assert result is True

        loaded = rm.get_entries()
        assert loaded[0].status == "migrated"

    def test_update_status_returns_false_when_not_found(self, rm):
        """AC-06: update_status on nonexistent id returns False."""
        result = rm.update_status("nonexistent_id", "migrated")
        assert result is False


# ---------------------------------------------------------------------------
# AC-06 — get_entries with status filter
# ---------------------------------------------------------------------------

class TestGetEntries:

    def test_get_entries_status_filter(self, rm):
        """AC-06: add 3 entries (2 discovered, 1 migrated); filters return correct counts."""
        e1 = _make_entry(key="KEY_A", context="a.env", status="discovered")
        e2 = _make_entry(key="KEY_B", context="b.env", status="discovered")
        e3 = _make_entry(key="KEY_C", context="c.env", status="migrated")
        rm.add_entry(e1)
        rm.add_entry(e2)
        rm.add_entry(e3)

        discovered = rm.get_entries(status_filter="discovered")
        migrated = rm.get_entries(status_filter="migrated")
        all_entries = rm.get_entries()

        assert len(discovered) == 2, f"Expected 2 discovered, got {len(discovered)}"
        assert len(migrated) == 1, f"Expected 1 migrated, got {len(migrated)}"
        assert len(all_entries) == 3


# ---------------------------------------------------------------------------
# AC-06 — atomic save
# ---------------------------------------------------------------------------

class TestSaveAtomic:

    def test_save_atomic(self, rm, registry_path):
        """AC-06: save registry and verify target file exists after save."""
        registry = {
            "version": 1,
            "bootstrapped_at": "2026-01-01T00:00:00+00:00",
            "entries": [],
        }
        rm.save(registry)
        assert registry_path.exists(), "Registry file must exist after save"

        # Re-read and confirm content
        data = yaml.safe_load(registry_path.read_text())
        assert data["version"] == 1
        assert data["entries"] == []


# ---------------------------------------------------------------------------
# AC-07, AC-08 — RegistryEntry.make_id + schema
# ---------------------------------------------------------------------------

class TestRegistryEntryId:

    def test_make_id_deterministic(self):
        """AC-07: make_id is deterministic for same inputs."""
        id1 = RegistryEntry.make_id("env_scan", "test.env", "MY_KEY")
        id2 = RegistryEntry.make_id("env_scan", "test.env", "MY_KEY")
        assert id1 == id2

    def test_make_id_format(self):
        """AC-07: id format is '{source}:{sha256[:8]}:{key}'."""
        source, context, key = "env_scan", "test.env", "MY_KEY"
        expected_digest = hashlib.sha256(context.encode()).hexdigest()[:8]
        entry_id = RegistryEntry.make_id(source, context, key)
        assert entry_id == f"{source}:{expected_digest}:{key}"

    def test_make_id_unique_across_contexts(self):
        """AC-07: same key in different contexts → different ids."""
        id1 = RegistryEntry.make_id("env_scan", "dir_a/test.env", "API_KEY")
        id2 = RegistryEntry.make_id("env_scan", "dir_b/test.env", "API_KEY")
        assert id1 != id2


class TestRegistryYamlSchema:

    def test_registry_yaml_schema(self, rm, registry_path):
        """AC-08: save registry and re-read raw YAML; assert top-level keys + version + entries."""
        registry = {
            "version": 1,
            "bootstrapped_at": "2026-01-01T00:00:00+00:00",
            "entries": [
                _make_entry(key="SCHEMA_KEY").to_dict()
            ],
        }
        rm.save(registry)

        raw = yaml.safe_load(registry_path.read_text())
        # AC-08: top-level keys present
        assert "version" in raw
        assert "bootstrapped_at" in raw
        assert "entries" in raw
        assert raw["version"] == 1
        assert isinstance(raw["entries"], list)
        # AC-06: entry fields present
        e = raw["entries"][0]
        assert "id" in e
        assert "key" in e
        assert "source" in e
        assert "context" in e
        assert "status" in e
