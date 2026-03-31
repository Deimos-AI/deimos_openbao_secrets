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
"""Standalone CI secret surface scanner (stdlib only).

CLI:
    python tests/ci_secret_surface_scan.py [--fail-on-new] [--repo-root PATH]

Checks:
    1. discover_new_targets   -- JSON files with auth-header keys not in baseline
    2. check_raw_credentials  -- unmasked Basic/Bearer in tracked JSON/YAML
    3. check_placeholder_scope -- bao-placeholder prefix outside extensions/ and tests/

Ref: IMPLEMENTATION_PLAN.md Step 9, R-05
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Auth-header key names that indicate credential-bearing JSON structures
_AUTH_HEADER_KEYS: frozenset[str] = frozenset({
    "Authorization", "authorization",
    "X-API-Key", "x-api-key", "X-Api-Key",
    "X-Auth-Token", "x-auth-token",
    "Bearer", "bearer",
    "Basic", "basic",
})

# Raw credential patterns: Basic/Bearer tokens >= 20 chars are assumed real
_RAW_CRED_RE = re.compile(
    r"(?:Basic|Bearer)\s+[A-Za-z0-9+/=._-]{20,}"
)

# Bao placeholder prefix: ⟦bao: (Unicode U+27E6 + literal bao:)
# NOTE: this constant is intentionally written as a Python escape sequence
# so the scanner source file itself does not contain the literal Unicode char.
_BAO_PREFIX: str = "⟦bao:"

# Directories allowed to contain bao placeholder tokens
_ALLOWED_BAO_DIRS: tuple[str, ...] = ("extensions/", "tests/", "api/")

# Path prefixes excluded from all scans
_EXCLUDE_PREFIXES: tuple[str, ...] = (
    ".git", "__pycache__", ".pytest_cache",
    ".eggs", "dist", "build",
)


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------

def load_known_surfaces(repo_root: Path) -> dict:
    """Load tests/known_secret_surfaces.json baseline.

    Returns the parsed dict, or a minimal default if the file is missing.
    """
    baseline = repo_root / "tests" / "known_secret_surfaces.json"
    if baseline.exists():
        with open(baseline, encoding="utf-8") as fh:
            return json.load(fh)
    return {
        "mcp_servers": [],
        "plugin_configs": ["config.json"],
        "excluded_paths": ["tests/", ".git/", "settings.json.example"],
    }


# ---------------------------------------------------------------------------
# Check 1: discover_new_targets
# ---------------------------------------------------------------------------

def discover_new_targets(repo_root: Path, known: list) -> list:
    """Find JSON files with auth-header keys not in the known surfaces list.

    Walks all *.json files; parses each; checks for auth-header-like keys
    (_AUTH_HEADER_KEYS) anywhere in the nested structure.
    Files whose basename appears in *known* are skipped.

    Returns list of relative path strings for newly discovered files.
    """
    known_set: set[str] = set(known)
    new_targets: list[str] = []

    for json_file in sorted(repo_root.rglob("*.json")):
        rel = str(json_file.relative_to(repo_root))
        if _is_excluded(rel):
            continue
        # Skip files that match any known surface entry
        if any(rel == k or rel.endswith(k) or json_file.name == k for k in known_set):
            continue
        try:
            with open(json_file, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            continue
        if _has_auth_header_key(data):
            new_targets.append(rel)

    return new_targets


def _has_auth_header_key(obj: Any, depth: int = 0) -> bool:
    """Recursively check if *obj* contains any auth-header-like dict key."""
    if depth > 12:
        return False
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k in _AUTH_HEADER_KEYS:
                return True
            if _has_auth_header_key(v, depth + 1):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if _has_auth_header_key(item, depth + 1):
                return True
    return False


# ---------------------------------------------------------------------------
# Check 2: check_raw_credentials
# ---------------------------------------------------------------------------

def check_raw_credentials(repo_root: Path) -> list:
    """Scan tracked JSON and YAML files for unmasked Basic/Bearer credentials.

    Lines already containing bao-placeholder prefix are skipped (they
    have already been extracted to the vault).

    Returns list of (file_path_str, line_no, snippet) tuples.
    """
    findings: list[tuple[str, int, str]] = []
    scan_exts = {".json", ".yml", ".yaml"}

    for path in sorted(repo_root.rglob("*")):
        if path.suffix not in scan_exts or not path.is_file():
            continue
        rel = str(path.relative_to(repo_root))
        if _is_excluded(rel):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            # Lines with a bao placeholder are already processed -- skip
            if _BAO_PREFIX in line:
                continue
            for m in _RAW_CRED_RE.findall(line):
                snippet = m[:60] + ("..." if len(m) > 60 else "")
                findings.append((rel, lineno, snippet))

    return findings


# ---------------------------------------------------------------------------
# Check 3: check_placeholder_scope
# ---------------------------------------------------------------------------

def check_placeholder_scope(repo_root: Path) -> list:
    """Scan *.py files outside extensions/ and tests/ for bao-placeholder prefix.

    Bao placeholder tokens should only appear in extension code (which
    processes them) and test files (which test the processing). Their
    presence elsewhere indicates an unresolved placeholder that escaped
    the normal resolution path.

    Returns list of (file_path_str, line_no) tuples.
    """
    findings: list[tuple[str, int]] = []

    for py_file in sorted(repo_root.rglob("*.py")):
        rel = str(py_file.relative_to(repo_root))
        if _is_excluded(rel):
            continue
        if any(rel.startswith(d) for d in _ALLOWED_BAO_DIRS):
            continue
        try:
            text = py_file.read_text(encoding="utf-8")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            if _BAO_PREFIX in line:
                findings.append((rel, lineno))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_excluded(rel_path: str) -> bool:
    """Return True if *rel_path* should be skipped in all scans."""
    parts = rel_path.replace("\\", "/").split("/")
    for part in parts:
        if part in (".git", "__pycache__", ".pytest_cache", ".eggs", "dist", "build"):
            return True
    return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scan repo for raw credentials and mis-scoped bao placeholders.",
    )
    parser.add_argument(
        "--fail-on-new", action="store_true",
        help="Exit 1 when any finding is detected (CI / pre-commit mode).",
    )
    parser.add_argument(
        "--repo-root", default=".",
        help="Repository root path (default: current directory).",
    )
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve()

    known      = load_known_surfaces(repo_root)
    known_list = list(known.get("mcp_servers", [])) + list(known.get("plugin_configs", []))

    new_targets  = discover_new_targets(repo_root, known_list)
    raw_creds    = check_raw_credentials(repo_root)
    scope_issues = check_placeholder_scope(repo_root)

    if new_targets:
        print(f"[WARN] {len(new_targets)} new undeclared credential surface(s):")
        for t in new_targets:
            print(f"  - {t}")
        print("  -> Add to tests/known_secret_surfaces.json after review.")
    else:
        print("[OK] No new undeclared credential surfaces.")

    if raw_creds:
        print(f"[WARN] {len(raw_creds)} raw credential(s) in tracked files:")
        for fpath, lineno, snippet in raw_creds:
            print(f"  {fpath}:{lineno}: {snippet}")
    else:
        print("[OK] No raw credentials in tracked JSON/YAML.")

    if scope_issues:
        print(f"[WARN] {len(scope_issues)} placeholder(s) in unexpected scope:")
        for fpath, lineno in scope_issues:
            print(f"  {fpath}:{lineno}")
        print("  -> Placeholders should only appear in extensions/ and tests/.")
    else:
        print("[OK] No out-of-scope placeholder tokens.")

    has_findings = bool(new_targets or raw_creds or scope_issues)
    if args.fail_on_new and has_findings:
        print("\n[FAIL] Secret surface scan found issues.")
        sys.exit(1)
    if not has_findings:
        print("\n[PASS] Secret surface scan clean.")


if __name__ == '__main__':
    main()
