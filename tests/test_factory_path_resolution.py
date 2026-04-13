"""Regression test for factory path resolution -- catches directory-rename mismatches.

After commit a89636e renamed helpers/ to openbao_helpers/, four hardcoded path
strings in factory_loader.py and factory_common.py were left pointing at the
old directory, causing file-not-found on every factory init attempt.

This test suite walks the same os.path.join() calls that the factory chain
uses and asserts every constructed path resolves to a file that exists on disk.
It requires NO running OpenBao server -- purely filesystem checks.

Regression class: directory rename without updating all path literals.

AC-01  factory_loader.py path to factory_common.py resolves to existing file
AC-02  factory_common.py path to config.py resolves to existing file
AC-03  factory_common.py path to openbao_client.py resolves to existing file
AC-04  factory_common.py path to openbao_secrets_manager.py resolves to existing file
AC-05  No stale helpers directory references remain in factory chain sources
AC-06  Full init chain path walk: all 4 hops resolve without FileNotFoundError
"""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path

import pytest

# -- Plugin root resolution --
_PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The actual directory name after the rename.
_HELPERS_DIR = "openbao_helpers"

# Files that factory_loader / factory_common load via os.path.join.
_FACTORY_CHAIN_FILES = {
    "factory_loader.py": os.path.join(_PLUGIN_ROOT, _HELPERS_DIR, "factory_loader.py"),
    "factory_common.py": os.path.join(_PLUGIN_ROOT, _HELPERS_DIR, "factory_common.py"),
    "config.py": os.path.join(_PLUGIN_ROOT, _HELPERS_DIR, "config.py"),
    "openbao_client.py": os.path.join(_PLUGIN_ROOT, _HELPERS_DIR, "openbao_client.py"),
    "openbao_secrets_manager.py": os.path.join(_PLUGIN_ROOT, _HELPERS_DIR, "openbao_secrets_manager.py"),
}


def _extract_os_join_targets(source: str) -> list[tuple[str, str]]:
    """Parse all os.path.join(plugin_dir, DIR, FILE) string literals from source."""
    tree = ast.parse(source)
    targets: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Match os.path.join(...)
        if isinstance(func, ast.Attribute) and func.attr == "join":
            args = node.args
            # We want calls with exactly 3 args: plugin_dir, dir_name, file_name
            if len(args) == 3 and all(isinstance(a, ast.Constant) for a in args[1:]):
                dir_name = args[1].value  # type: ignore[union-attr]
                file_name = args[2].value  # type: ignore[union-attr]
                targets.append((dir_name, file_name))
    return targets


class TestFactoryPathResolution:
    """Verify all hardcoded factory chain paths resolve to real files."""

    def test_ac01_factory_loader_finds_factory_common(self):
        """AC-01: factory_loader.py path to factory_common.py resolves."""
        loader_src = Path(_FACTORY_CHAIN_FILES["factory_loader.py"]).read_text()
        targets = _extract_os_join_targets(loader_src)
        # Should contain a reference to factory_common.py
        fc_entries = [(d, f) for d, f in targets if f == "factory_common.py"]
        assert fc_entries, "factory_loader.py has no os.path.join to factory_common.py"
        dir_name, _ = fc_entries[0]
        resolved = os.path.join(_PLUGIN_ROOT, dir_name, "factory_common.py")
        assert os.path.isfile(resolved), (
            f"factory_loader.py references {dir_name}/factory_common.py "
            f"but file not found at {resolved}"
        )

    def test_ac02_factory_common_finds_config(self):
        """AC-02: factory_common.py path to config.py resolves."""
        fc_src = Path(_FACTORY_CHAIN_FILES["factory_common.py"]).read_text()
        targets = _extract_os_join_targets(fc_src)
        config_entries = [(d, f) for d, f in targets if f == "config.py"]
        assert config_entries, "factory_common.py has no os.path.join to config.py"
        dir_name, _ = config_entries[0]
        resolved = os.path.join(_PLUGIN_ROOT, dir_name, "config.py")
        assert os.path.isfile(resolved), (
            f"factory_common.py references {dir_name}/config.py "
            f"but file not found at {resolved}"
        )

    def test_ac03_factory_common_finds_client(self):
        """AC-03: factory_common.py path to openbao_client.py resolves."""
        fc_src = Path(_FACTORY_CHAIN_FILES["factory_common.py"]).read_text()
        targets = _extract_os_join_targets(fc_src)
        client_entries = [(d, f) for d, f in targets if f == "openbao_client.py"]
        assert client_entries, "factory_common.py has no os.path.join to openbao_client.py"
        dir_name, _ = client_entries[0]
        resolved = os.path.join(_PLUGIN_ROOT, dir_name, "openbao_client.py")
        assert os.path.isfile(resolved), (
            f"factory_common.py references {dir_name}/openbao_client.py "
            f"but file not found at {resolved}"
        )

    def test_ac04_factory_common_finds_manager(self):
        """AC-04: factory_common.py path to openbao_secrets_manager.py resolves."""
        fc_src = Path(_FACTORY_CHAIN_FILES["factory_common.py"]).read_text()
        targets = _extract_os_join_targets(fc_src)
        mgr_entries = [(d, f) for d, f in targets if f == "openbao_secrets_manager.py"]
        assert mgr_entries, "factory_common.py has no os.path.join to openbao_secrets_manager.py"
        dir_name, _ = mgr_entries[0]
        resolved = os.path.join(_PLUGIN_ROOT, dir_name, "openbao_secrets_manager.py")
        assert os.path.isfile(resolved), (
            f"factory_common.py references {dir_name}/openbao_secrets_manager.py "
            f"but file not found at {resolved}"
        )

    def test_ac05_no_stale_helpers_directory_references(self):
        """AC-05: No stale helpers directory references in factory chain sources.

        After the rename to openbao_helpers/, no os.path.join(plugin_dir, "helpers", ...)
        should remain in factory_loader.py or factory_common.py.
        """
        stale_pattern = re.compile(r'os\.path\.join\([^)]*"helpers"[^)]*\)')
        for name, path in _FACTORY_CHAIN_FILES.items():
            if name not in ("factory_loader.py", "factory_common.py"):
                continue
            source = Path(path).read_text()
            matches = stale_pattern.findall(source)
            assert not matches, (
                f"{name} still contains stale helpers os.path.join references: {matches}"
            )

    def test_ac06_full_init_chain_all_paths_resolve(self):
        """AC-06: Walk the full init chain and verify every hop resolves.

        Simulates the factory_loader -> factory_common -> config/client/manager
        path resolution chain without importing or executing any code.
        """
        resolved_paths: list[str] = []

        # Hop 1: factory_loader.py -> factory_common.py
        loader_src = Path(_FACTORY_CHAIN_FILES["factory_loader.py"]).read_text()
        loader_targets = _extract_os_join_targets(loader_src)
        fc_entries = [(d, f) for d, f in loader_targets if f == "factory_common.py"]
        assert fc_entries, "factory_loader.py: no factory_common.py reference"
        hop1 = os.path.join(_PLUGIN_ROOT, fc_entries[0][0], fc_entries[0][1])
        assert os.path.isfile(hop1), f"Hop 1 failed: {hop1} does not exist"
        resolved_paths.append(hop1)

        # Hops 2-4: factory_common.py -> config, client, manager
        fc_src = Path(_FACTORY_CHAIN_FILES["factory_common.py"]).read_text()
        fc_targets = _extract_os_join_targets(fc_src)
        expected_files = {"config.py", "openbao_client.py", "openbao_secrets_manager.py"}
        found_files = {f for _, f in fc_targets}
        assert expected_files.issubset(found_files), (
            f"factory_common.py missing references to: {expected_files - found_files}"
        )

        for dir_name, file_name in fc_targets:
            if file_name in expected_files:
                hop_path = os.path.join(_PLUGIN_ROOT, dir_name, file_name)
                assert os.path.isfile(hop_path), f"Hop failed: {hop_path} does not exist"
                resolved_paths.append(hop_path)

        # All 4 hops resolved
        assert len(resolved_paths) >= 4, (
            f"Expected 4 resolved paths, got {len(resolved_paths)}: {resolved_paths}"
        )
