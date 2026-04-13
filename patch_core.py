#!/usr/bin/env python3
"""
patch_core.py — idempotent patch for Agent Zero PR #1394 + ANSI regex fix.

PR #1394  helpers/plugins.py
    save_plugin_config → call_plugin_hook gets hook_context={'caller': 'ui'}
    get_plugin_config  → call_plugin_hook gets hook_context={'caller': 'agent'}

Behaviour
---------
- Creates <file>.bak backup before first write to each file.
- Each change is individually idempotent: detected via a unique sentinel
  string; prints SKIP and does nothing if already present.
- Prints OK / SKIP / FAIL per change.
- Runs py_compile on each patched file; exits non-zero on any failure.
- No external dependencies — pure stdlib.

Also includes shell_ssh.py ANSI regex fix.
Commit 65156262 was a rename refactor only — it did NOT contain the regex fix.
The fix is preserved here as a working-tree patch.

Once PR #1394 merges upstream, this file can be deleted entirely.
"""

import sys
import shutil
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ROOT = Path("/a0")

FILES = {
    "shell_ssh": ROOT / "plugins" / "code_execution" / "helpers" / "shell_ssh.py",
    "plugins": ROOT / "helpers" / "plugins.py",
}

_backed_up: set[str] = set()
_any_fail = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def log(tag: str, label: str, change_id: str, detail: str = "") -> None:
    line = f"{tag:<4} {label} / {change_id}"
    if detail:
        line += f": {detail}"
    print(line)


def _backup(path: Path) -> None:
    key = str(path)
    if key in _backed_up:
        return
    bak = Path(str(path) + ".bak")
    if not bak.exists():
        shutil.copy2(path, bak)
        print(f"  Created backup: {bak}")
    else:
        print(f"  Backup already exists, skipping: {bak}")
    _backed_up.add(key)


def apply(
    path: Path,
    label: str,
    change_id: str,
    *,
    search: str,
    replacement: str,
    already_done_check: str,
) -> bool:
    """Apply one string-replacement change to *path*.

    Returns True  on OK or SKIP.
    Returns False on FAIL (anchor not found).
    """
    global _any_fail
    content = path.read_text(encoding="utf-8")

    # Idempotency gate
    if already_done_check in content:
        log("SKIP", label, change_id, "already present")
        return True

    # Anchor check
    if search not in content:
        log("FAIL", label, change_id, "anchor string not found — upstream changed?")
        _any_fail = True
        return False

    _backup(path)
    path.write_text(content.replace(search, replacement, 1), encoding="utf-8")
    log("  OK", label, change_id)
    return True


def _check(path: Path) -> None:
    global _any_fail
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", str(path)],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print(f"   Syntax OK: {path}")
    else:
        print(f"  Syntax error in {path.name}:")
        print(result.stderr.strip())
        _any_fail = True


# ---------------------------------------------------------------------------
# shell_ssh.py — ANSI regex fix
# ---------------------------------------------------------------------------
def patch_shell_ssh() -> None:
    """Fix buggy ANSI regex in clean_string().

    The upstream regex uses [@-Z] range which includes A-Z (0x41-0x5A),
    stripping uppercase letters from PTY output.
    Fix: replace with CSI-only regex.
    """
    path = FILES["shell_ssh"]
    if not path.exists():
        log("SKIP", "shell_ssh.py", "ANSI-REGEX-001", "file not found")
        return

    code = path.read_text(encoding="utf-8")
    sentinel = "# ANSI-REGEX-FIXED"
    if sentinel in code:
        log("SKIP", "shell_ssh.py", "ANSI-REGEX-001", "already patched")
        return

    # Buggy: r"\x1b(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])"
    # Fixed: r"\x1b\[[0-?]*[ -/]*[@-~]"
    old = r'(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])'
    new = r'\[[0-?]*[ -/]*[@-~]'

    if old not in code:
        log("SKIP", "shell_ssh.py", "ANSI-REGEX-001", "buggy pattern not found")
        return

    _backup(path)
    code = code.replace(old, new, 1)
    path.write_text(code, encoding="utf-8")
    log("  OK", "shell_ssh.py", "ANSI-REGEX-001", "replaced [@-Z] with CSI-only regex")


# ---------------------------------------------------------------------------
# PR #1394 — helpers/plugins.py
# ---------------------------------------------------------------------------
def patch_plugins() -> None:
    path = FILES["plugins"]
    label = "plugins.py"

    #  save_plugin_config: add hook_context={'caller': 'ui'}
    apply(
        path, label, ":save_plugin_config:hook_context_ui",
        search=(
            "    new_settings = call_plugin_hook(\n"
            "        plugin_name,\n"
            '        "save_plugin_config",\n'
            "        default=settings,\n"
            "        project_name=project_name,\n"
            "        agent_profile=agent_profile,\n"
            "        settings=settings,\n"
            "    )"
        ),
        replacement=(
            "    new_settings = call_plugin_hook(\n"
            "        plugin_name,\n"
            '        "save_plugin_config",\n'
            "        default=settings,\n"
            "        project_name=project_name,\n"
            "        agent_profile=agent_profile,\n"
            "        settings=settings,\n"
            "        hook_context={'caller': 'ui'},\n"
            "    )"
        ),
        already_done_check="hook_context={'caller': 'ui'}",
    )

    #  get_plugin_config: add hook_context={'caller': 'agent'}
    apply(
        path, label, ":get_plugin_config:hook_context_agent",
        search=(
            "    # call plugin hook to modify the standard result if needed\n"
            "    result = call_plugin_hook(\n"
            "        plugin_name,\n"
            '        "get_plugin_config",\n'
            "        default=result,\n"
            "        agent=agent,\n"
            "        project_name=project_name,\n"
            "        agent_profile=agent_profile,\n"
            "    )"
        ),
        replacement=(
            "    # call plugin hook to modify the standard result if needed\n"
            "    result = call_plugin_hook(\n"
            "        plugin_name,\n"
            '        "get_plugin_config",\n'
            "        default=result,\n"
            "        agent=agent,\n"
            "        project_name=project_name,\n"
            "        agent_profile=agent_profile,\n"
            "        hook_context={'caller': 'agent'},\n"
            "    )"
        ),
        already_done_check="hook_context={'caller': 'agent'}",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    global _any_fail

    print("=" * 66)
    print("patch_core.py — Agent Zero PR #1394 + ANSI fix patcher")
    print("=" * 66)

    # Preflight: all target files must exist
    for name, path in FILES.items():
        if not path.exists():
            print(f"  Target file not found: {path}")
            _any_fail = True
    if _any_fail:
        print("\n  Aborting: target file(s) missing.")
        sys.exit(1)

    print()
    print("--- shell_ssh.py ANSI regex fix ---")
    patch_shell_ssh()

    print()
    print("--- PR #1394 — helpers/plugins.py ---")
    patch_plugins()

    print()
    print("--- Syntax verification ---")
    for path in FILES.values():
        _check(path)

    print()
    if _any_fail:
        print("  One or more changes failed — review output above.")
        sys.exit(1)
    else:
        print("  All changes applied and syntax verified. Backed-up .bak files exist.")
        sys.exit(0)


if __name__ == "__main__":
    main()
