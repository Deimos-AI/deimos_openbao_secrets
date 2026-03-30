# Copyright 2024 DeimosAI
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""CI secret surface scan pytest integration tests (R-05)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def repo_root() -> Path:
    """Repository root (parent of tests/ directory)."""
    return Path(__file__).parent.parent.resolve()


def _scanner(repo_root: Path):
    """Import ci_secret_surface_scan via importlib for isolation."""
    spec = importlib.util.spec_from_file_location(
        "ci_secret_surface_scan",
        repo_root / "tests" / "ci_secret_surface_scan.py",
    )
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_no_raw_credentials_in_tracked_json(repo_root: Path) -> None:
    """Assert no unmasked Basic/Bearer credentials in tracked JSON/YAML files.

    R-05: raw credentials must never be committed.
    """
    scanner = _scanner(repo_root)
    findings = scanner.check_raw_credentials(repo_root)
    assert findings == [], f"Raw credentials in tracked files: {findings}"


def test_no_new_undeclared_secret_surfaces(repo_root: Path) -> None:
    """Assert no new JSON files with auth headers outside known_secret_surfaces.json.

    All credential-bearing JSON files must be registered after review.
    """
    scanner = _scanner(repo_root)
    known = scanner.load_known_surfaces(repo_root)
    known_list = (
        list(known.get("mcp_servers", []))
        + list(known.get("plugin_configs", []))
    )
    new_targets = scanner.discover_new_targets(repo_root, known_list)
    assert new_targets == [], (
        f"Undeclared credential surfaces -- add to known_secret_surfaces.json: {new_targets}"
    )


def test_placeholder_scope_enforcement(repo_root: Path) -> None:
    """Assert bao-placeholder tokens only appear in extensions/ and tests/."""
    scanner = _scanner(repo_root)
    findings = scanner.check_placeholder_scope(repo_root)
    assert findings == [], (
        f"Bao placeholder in unexpected scope (only extensions/ and tests/ allowed): {findings}"
    )
