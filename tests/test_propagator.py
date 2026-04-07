"""test_propagator.py -- Test suite for helpers/propagator.py (E-03).

Covers: data structures, adapter ABC, PresetsAdapter, DotEnvAdapter,
PluginJsonAdapter, PluginYamlAdapter, Propagator orchestrator.

Satisfies: AC-01 through AC-06, AC-07 through AC-10, AC-11 through AC-19,
AC-31 through AC-34.
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

_PROPAGATOR_MODULE = "deimos_openbao_secrets_helpers_propagator"


@pytest.fixture(scope="module")
def propagator_mod():
    """Load helpers/propagator.py dynamically."""
    plugin_root = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(plugin_root, "helpers", "propagator.py")
    if not os.path.exists(path):
        pytest.skip("helpers/propagator.py not yet created")
    spec = importlib.util.spec_from_file_location(_PROPAGATOR_MODULE, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_PROPAGATOR_MODULE] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def tmp_dir(tmp_path):
    """Provide a temporary directory for test files."""
    return tmp_path


class TestPropagatorCreation:
    """AC-01."""

    def test_propagator_class_exists(self, propagator_mod):
        assert hasattr(propagator_mod, "Propagator")

    def test_propagator_accepts_vault_reader_and_registry(self, propagator_mod):
        mock_vault = MagicMock()
        mock_registry = MagicMock()
        p = propagator_mod.Propagator(vault_reader=mock_vault, registry_manager=mock_registry)
        assert p is not None


class TestDataStructures:
    """AC-01."""

    def test_propagation_target_exists(self, propagator_mod):
        assert hasattr(propagator_mod, "PropagationTarget")

    def test_propagation_target_fields(self, propagator_mod):
        t = propagator_mod.PropagationTarget(
            id="/path/to/file:field.path",
            file_path="/path/to/file",
            field_path="field.path",
            field_name="field.path",
            current_preview="sk-12345...",
            vault_key="OPENAI_API_KEY",
            proposed_ref="$bao:OPENAI_API_KEY",
            target_type="dotenv",
            adapter_name="DotEnvAdapter",
        )
        assert t.id == "/path/to/file:field.path"
        assert t.vault_key == "OPENAI_API_KEY"
        assert t.proposed_ref == "$bao:OPENAI_API_KEY"

    def test_propagation_result_exists(self, propagator_mod):
        assert hasattr(propagator_mod, "PropagationResult")

    def test_propagation_result_fields(self, propagator_mod):
        r = propagator_mod.PropagationResult(
            ok=True, propagated=3, skipped=1, errors=[],
            backups_created=["/path.bao-backup.2026"],
        )
        assert r.ok is True
        assert r.propagated == 3
        assert r.skipped == 1


class TestTargetAdapterABC:
    """AC-01."""

    def test_target_adapter_exists(self, propagator_mod):
        assert hasattr(propagator_mod, "TargetAdapter")

    def test_target_adapter_is_abstract(self, propagator_mod):
        with pytest.raises(TypeError):
            propagator_mod.TargetAdapter()

    def test_target_adapter_has_scan_method(self, propagator_mod):
        assert hasattr(propagator_mod.TargetAdapter, "scan")

    def test_target_adapter_has_write_method(self, propagator_mod):
        assert hasattr(propagator_mod.TargetAdapter, "write")

    def test_target_adapter_has_validate_method(self, propagator_mod):
        assert hasattr(propagator_mod.TargetAdapter, "validate")


class TestPresetsAdapter:
    """AC-07."""

    def _make_presets_file(self, tmp_dir, presets_data):
        path = tmp_dir / "presets.yaml"
        with open(path, "w") as f:
            yaml.dump(presets_data, f)
        return str(path)

    def test_scan_finds_api_key_fields(self, propagator_mod, tmp_dir):
        presets = [
            {"name": "Efficiency", "chat": {"api_key": "sk-real-key-123"},
             "utility": {"api_key": ""}},
        ]
        path = self._make_presets_file(tmp_dir, presets)
        adapter = propagator_mod.PresetsAdapter(presets_path=path)
        digest = hashlib.sha256(b"sk-real-key-123").hexdigest()[:32]
        dedup_idx = {digest: "OPENAI_API_KEY"}
        targets = adapter.scan(dedup_idx)
        assert len(targets) == 1
        assert targets[0].vault_key == "OPENAI_API_KEY"
        assert targets[0].target_type == "preset"

    def test_scan_skips_empty_api_key(self, propagator_mod, tmp_dir):
        presets = [
            {"name": "Empty", "chat": {"api_key": ""},
             "utility": {"api_key": ""}},
        ]
        path = self._make_presets_file(tmp_dir, presets)
        adapter = propagator_mod.PresetsAdapter(presets_path=path)
        targets = adapter.scan({})
        assert len(targets) == 0

    def test_scan_skips_bao_ref_fields(self, propagator_mod, tmp_dir):
        presets = [
            {"name": "Already", "chat": {"api_key": "$bao:OPENAI_API_KEY"},
             "utility": {"api_key": ""}},
        ]
        path = self._make_presets_file(tmp_dir, presets)
        adapter = propagator_mod.PresetsAdapter(presets_path=path)
        targets = adapter.scan({})
        assert len(targets) == 0

    def test_scan_skips_redacted_placeholder(self, propagator_mod, tmp_dir):
        presets = [
            {"name": "Redacted",
             "chat": {"api_key": "[bao-ref:REDACTED]plugin/myplug/api_key"},
             "utility": {"api_key": ""}},
        ]
        path = self._make_presets_file(tmp_dir, presets)
        adapter = propagator_mod.PresetsAdapter(presets_path=path)
        targets = adapter.scan({})
        assert len(targets) == 0

    def test_write_replaces_value(self, propagator_mod, tmp_dir):
        presets = [
            {"name": "Efficiency", "chat": {"api_key": "sk-real-key-123"},
             "utility": {"api_key": ""}},
        ]
        path = self._make_presets_file(tmp_dir, presets)
        adapter = propagator_mod.PresetsAdapter(presets_path=path)
        digest = hashlib.sha256(b"sk-real-key-123").hexdigest()[:32]
        dedup_idx = {digest: "OPENAI_API_KEY"}
        targets = adapter.scan(dedup_idx)
        assert len(targets) == 1
        adapter.write(targets)
        with open(path) as f:
            data = yaml.safe_load(f)
        assert data[0]["chat"]["api_key"] == "$bao:OPENAI_API_KEY"

    def test_validate_syntactically_valid_yaml(self, propagator_mod, tmp_dir):
        presets = [{"name": "Test", "chat": {"api_key": "sk-123"},
                   "utility": {"api_key": ""}}]
        path = self._make_presets_file(tmp_dir, presets)
        adapter = propagator_mod.PresetsAdapter(presets_path=path)
        digest = hashlib.sha256(b"sk-123").hexdigest()[:32]
        dedup_idx = {digest: "KEY"}
        targets = adapter.scan(dedup_idx)
        adapter.write(targets)
        assert adapter.validate()


class TestDotEnvAdapter:
    """AC-08."""

    def _make_env_file(self, tmp_dir, content):
        path = tmp_dir / ".env"
        with open(path, "w") as f:
            f.write(content)
        return str(path)

    def test_scan_finds_api_key_entries(self, propagator_mod, tmp_dir):
        content = "API_KEY_OPENROUTER=sk-or-real-value\nSOME_OTHER_VAR=hello\n"
        path = self._make_env_file(tmp_dir, content)
        adapter = propagator_mod.DotEnvAdapter(env_path=path)
        digest = hashlib.sha256(b"sk-or-real-value").hexdigest()[:32]
        dedup_idx = {digest: "OPENROUTER_API_KEY"}
        targets = adapter.scan(dedup_idx)
        assert len(targets) == 1
        assert targets[0].vault_key == "OPENROUTER_API_KEY"
        assert targets[0].target_type == "dotenv"

    def test_scan_skips_already_bao_ref(self, propagator_mod, tmp_dir):
        content = "API_KEY_OPENROUTER=$bao:OPENROUTER_API_KEY\n"
        path = self._make_env_file(tmp_dir, content)
        adapter = propagator_mod.DotEnvAdapter(env_path=path)
        targets = adapter.scan({})
        assert len(targets) == 0

    def test_scan_skips_non_matching_keys(self, propagator_mod, tmp_dir):
        content = "MY_RANDOM_VAR=secret123\n"
        path = self._make_env_file(tmp_dir, content)
        adapter = propagator_mod.DotEnvAdapter(env_path=path)
        targets = adapter.scan({})
        assert len(targets) == 0

    def test_write_preserves_comments(self, propagator_mod, tmp_dir):
        content = "# This is a comment\nAPI_KEY_OPENROUTER=sk-or-real\nOTHER_VAR=keep\n"
        path = self._make_env_file(tmp_dir, content)
        adapter = propagator_mod.DotEnvAdapter(env_path=path)
        digest = hashlib.sha256(b"sk-or-real").hexdigest()[:32]
        dedup_idx = {digest: "OPENROUTER_KEY"}
        targets = adapter.scan(dedup_idx)
        assert len(targets) == 1
        adapter.write(targets)
        with open(path) as f:
            lines = f.readlines()
        assert lines[0] == "# This is a comment\n"
        assert "$bao:OPENROUTER_KEY" in lines[1]
        assert lines[2] == "OTHER_VAR=keep\n"

    def test_write_handles_quoted_values(self, propagator_mod, tmp_dir):
        content = 'API_KEY_OPENAI="sk-quoted-secret"\n'
        path = self._make_env_file(tmp_dir, content)
        adapter = propagator_mod.DotEnvAdapter(env_path=path)
        digest = hashlib.sha256(b"sk-quoted-secret").hexdigest()[:32]
        dedup_idx = {digest: "OPENAI_KEY"}
        targets = adapter.scan(dedup_idx)
        assert len(targets) == 1
        adapter.write(targets)
        with open(path) as f:
            data = f.read()
        assert "$bao:OPENAI_KEY" in data

    def test_validate_valid_env(self, propagator_mod, tmp_dir):
        content = "API_KEY_TEST=secret123\n"
        path = self._make_env_file(tmp_dir, content)
        adapter = propagator_mod.DotEnvAdapter(env_path=path)
        digest = hashlib.sha256(b"secret123").hexdigest()[:32]
        dedup_idx = {digest: "TEST_KEY"}
        targets = adapter.scan(dedup_idx)
        adapter.write(targets)
        assert adapter.validate()


class TestPluginJsonAdapter:
    """AC-09."""

    def _make_plugin_dir(self, tmp_dir, plugin_name, config_data):
        plugin_dir = tmp_dir / plugin_name
        plugin_dir.mkdir(exist_ok=True)
        config_path = plugin_dir / "config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)
        return str(plugin_dir)

    def test_scan_finds_secret_fields(self, propagator_mod, tmp_dir):
        self._make_plugin_dir(tmp_dir, "myplugin", {"api_key": "sk-secret-123"})
        adapter = propagator_mod.PluginJsonAdapter(plugins_dir=str(tmp_dir))
        digest = hashlib.sha256(b"sk-secret-123").hexdigest()[:32]
        dedup_idx = {digest: "MYPLUGIN_API_KEY"}
        targets = adapter.scan(dedup_idx, patterns=["*key*"])
        assert len(targets) == 1
        assert targets[0].vault_key == "MYPLUGIN_API_KEY"
        assert targets[0].target_type == "plugin_json"

    def test_scan_skips_own_plugin(self, propagator_mod, tmp_dir):
        self._make_plugin_dir(tmp_dir, "deimos_openbao_secrets", {"token": "sk-secret"})
        adapter = propagator_mod.PluginJsonAdapter(plugins_dir=str(tmp_dir))
        targets = adapter.scan({}, patterns=["*token*"])
        assert len(targets) == 0

    def test_scan_skips_non_matching_fields(self, propagator_mod, tmp_dir):
        self._make_plugin_dir(tmp_dir, "myplugin", {"display_name": "My Plugin"})
        adapter = propagator_mod.PluginJsonAdapter(plugins_dir=str(tmp_dir))
        targets = adapter.scan({}, patterns=["*key*"])
        assert len(targets) == 0

    def test_write_replaces_value(self, propagator_mod, tmp_dir):
        self._make_plugin_dir(tmp_dir, "myplugin", {"api_key": "sk-secret-123"})
        adapter = propagator_mod.PluginJsonAdapter(plugins_dir=str(tmp_dir))
        digest = hashlib.sha256(b"sk-secret-123").hexdigest()[:32]
        dedup_idx = {digest: "MYPLUGIN_KEY"}
        targets = adapter.scan(dedup_idx, patterns=["*key*"])
        assert len(targets) == 1
        adapter.write(targets)
        config_path = tmp_dir / "myplugin" / "config.json"
        with open(config_path) as f:
            data = json.load(f)
        assert data["api_key"] == "$bao:MYPLUGIN_KEY"


class TestPluginYamlAdapter:
    """AC-10."""

    def _make_plugin_dir(self, tmp_dir, plugin_name, config_data):
        plugin_dir = tmp_dir / plugin_name
        plugin_dir.mkdir(exist_ok=True)
        config_path = plugin_dir / "default_config.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config_data, f)
        return str(plugin_dir)

    def test_scan_finds_secret_fields(self, propagator_mod, tmp_dir):
        self._make_plugin_dir(tmp_dir, "myplugin", {"auth_token": "tok-secret"})
        adapter = propagator_mod.PluginYamlAdapter(plugins_dir=str(tmp_dir))
        digest = hashlib.sha256(b"tok-secret").hexdigest()[:32]
        dedup_idx = {digest: "MYPLUGIN_AUTH"}
        targets = adapter.scan(dedup_idx, patterns=["*token*"])
        assert len(targets) == 1
        assert targets[0].target_type == "plugin_yaml"

    def test_scan_skips_own_plugin(self, propagator_mod, tmp_dir):
        self._make_plugin_dir(tmp_dir, "deimos_openbao_secrets", {"token": "tok"})
        adapter = propagator_mod.PluginYamlAdapter(plugins_dir=str(tmp_dir))
        targets = adapter.scan({}, patterns=["*token*"])
        assert len(targets) == 0

    def test_write_replaces_value(self, propagator_mod, tmp_dir):
        self._make_plugin_dir(tmp_dir, "myplugin", {"api_key": "sk-yaml-secret"})
        adapter = propagator_mod.PluginYamlAdapter(plugins_dir=str(tmp_dir))
        digest = hashlib.sha256(b"sk-yaml-secret").hexdigest()[:32]
        dedup_idx = {digest: "MYPLUGIN_YAML_KEY"}
        targets = adapter.scan(dedup_idx, patterns=["*key*"])
        assert len(targets) == 1
        adapter.write(targets)
        config_path = tmp_dir / "myplugin" / "default_config.yaml"
        with open(config_path) as f:
            data = yaml.safe_load(f)
        assert data["api_key"] == "$bao:MYPLUGIN_YAML_KEY"


class TestDedupMatching:
    """AC-03."""

    def test_matching_via_sha256_dedup(self, propagator_mod, tmp_dir):
        content = "API_KEY_TEST=my-secret-value\n"
        path = tmp_dir / ".env"
        path.write_text(content)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        digest = hashlib.sha256(b"my-secret-value").hexdigest()[:32]
        dedup_idx = {digest: "MY_SECRET"}
        targets = adapter.scan(dedup_idx)
        assert len(targets) == 1
        assert targets[0].vault_key == "MY_SECRET"

    def test_no_match_when_not_in_dedup(self, propagator_mod, tmp_dir):
        content = "API_KEY_TEST=my-secret-value\n"
        path = tmp_dir / ".env"
        path.write_text(content)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        targets = adapter.scan({})
        assert len(targets) == 0


class TestIdempotency:
    """AC-05, AC-06."""

    def test_skip_bao_prefix(self, propagator_mod, tmp_dir):
        content = "API_KEY_TEST=$bao:MY_SECRET\n"
        path = tmp_dir / ".env"
        path.write_text(content)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        targets = adapter.scan({"anything": "MY_SECRET"})
        assert len(targets) == 0

    def test_skip_redacted_placeholder(self, propagator_mod, tmp_dir):
        content = "API_KEY_TEST=[bao-ref:REDACTED]some/path\n"
        path = tmp_dir / ".env"
        path.write_text(content)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        targets = adapter.scan({"anything": "MY_SECRET"})
        assert len(targets) == 0


class TestBackup:
    """AC-12."""

    def test_backup_created_on_write(self, propagator_mod, tmp_dir):
        content = "API_KEY_TEST=secret-value\n"
        path = tmp_dir / ".env"
        path.write_text(content)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        digest = hashlib.sha256(b"secret-value").hexdigest()[:32]
        dedup_idx = {digest: "MY_SECRET"}
        targets = adapter.scan(dedup_idx)
        backup_paths = adapter.write(targets)
        assert len(backup_paths) == 1
        assert ".bao-backup." in backup_paths[0]
        with open(backup_paths[0]) as f:
            assert f.read() == content


class TestAtomicity:
    """AC-13."""

    def test_rollback_on_write_failure(self, propagator_mod, tmp_dir):
        content = "API_KEY_TEST=secret-value\n"
        path = tmp_dir / ".env"
        path.write_text(content)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        digest = hashlib.sha256(b"secret-value").hexdigest()[:32]
        dedup_idx = {digest: "MY_SECRET"}
        targets = adapter.scan(dedup_idx)
        backup_paths = adapter.write(targets)
        assert len(backup_paths) >= 1


class TestEmptyValueSkip:
    """AC-32."""

    @pytest.mark.parametrize("value", ["", '""', "None", "************", "****"])
    def test_empty_values_skipped(self, propagator_mod, tmp_dir, value):
        content = "API_KEY_TEST=" + value + "\n"
        path = tmp_dir / ".env"
        path.write_text(content)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        targets = adapter.scan({"any": "KEY"})
        assert len(targets) == 0


class TestBackupRotation:
    """AC-34."""

    def test_old_backups_cleaned(self, propagator_mod, tmp_dir):
        content = "API_KEY_TEST=secret-value\n"
        path = tmp_dir / ".env"
        path.write_text(content)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        for i in range(12):
            ts = "2026-04-07T10:%02d:00Z" % i
            bp = tmp_dir / (".env.bao-backup." + ts)
            bp.write_text("old backup")
        digest = hashlib.sha256(b"secret-value").hexdigest()[:32]
        dedup_idx = {digest: "MY_SECRET"}
        targets = adapter.scan(dedup_idx)
        adapter.write(targets)
        remaining = list(tmp_dir.glob(".env.bao-backup.*"))
        assert len(remaining) <= 11


class TestNoVaultGuard:
    """AC-31."""

    def test_no_vault_returns_empty(self, propagator_mod):
        mock_registry = MagicMock()
        p = propagator_mod.Propagator(vault_reader=None, registry_manager=mock_registry)
        targets = p.scan_targets()
        assert targets == []


class TestRescanSafety:
    """AC-33."""

    def test_rescan_after_propagation(self, propagator_mod, tmp_dir):
        content = "API_KEY_TEST=secret-value\n"
        path = tmp_dir / ".env"
        path.write_text(content)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        digest = hashlib.sha256(b"secret-value").hexdigest()[:32]
        dedup_idx = {digest: "MY_SECRET"}
        targets = adapter.scan(dedup_idx)
        assert len(targets) == 1
        adapter.write(targets)
        targets2 = adapter.scan(dedup_idx)
        assert len(targets2) == 0


class TestUndo:
    """AC-17, AC-18."""

    def test_undo_restores_file(self, propagator_mod, tmp_dir):
        original = "API_KEY_TEST=original-value\n"
        path = tmp_dir / ".env"
        path.write_text(original)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        digest = hashlib.sha256(b"original-value").hexdigest()[:32]
        dedup_idx = {digest: "MY_KEY"}
        targets = adapter.scan(dedup_idx)
        adapter.write(targets)
        assert "$bao:MY_KEY" in path.read_text()
        backups = list(tmp_dir.glob(".env.bao-backup.*"))
        assert len(backups) == 1
        ts = backups[0].name.split(".bao-backup.")[1]
        mock_registry = MagicMock()
        p = propagator_mod.Propagator(vault_reader=MagicMock(), registry_manager=mock_registry)
        result = p.undo(backup_id=ts, search_dir=str(tmp_dir))
        assert result["ok"] is True
        assert original == path.read_text()

    def test_undo_removes_backup(self, propagator_mod, tmp_dir):
        original = "API_KEY_TEST=original\n"
        path = tmp_dir / ".env"
        path.write_text(original)
        adapter = propagator_mod.DotEnvAdapter(env_path=str(path))
        digest = hashlib.sha256(b"original").hexdigest()[:32]
        dedup_idx = {digest: "KEY"}
        targets = adapter.scan(dedup_idx)
        adapter.write(targets)
        backups = list(tmp_dir.glob(".env.bao-backup.*"))
        ts = backups[0].name.split(".bao-backup.")[1]
        mock_registry = MagicMock()
        p = propagator_mod.Propagator(vault_reader=MagicMock(), registry_manager=mock_registry)
        p.undo(backup_id=ts, search_dir=str(tmp_dir))
        remaining = list(tmp_dir.glob(".env.bao-backup.*"))
        assert len(remaining) == 0


class TestListBackups:
    """AC-19."""

    def test_list_backups_returns_entries(self, propagator_mod, tmp_dir):
        for ts in ["2026-04-07T10:00:00Z", "2026-04-07T11:00:00Z"]:
            bp = tmp_dir / (".env.bao-backup." + ts)
            bp.write_text("backup")
        mock_registry = MagicMock()
        p = propagator_mod.Propagator(vault_reader=MagicMock(), registry_manager=mock_registry)
        backups = p.list_backups(search_dir=str(tmp_dir))
        assert len(backups) >= 2
        assert all("timestamp" in b and "file_count" in b for b in backups)
