"""helpers/secrets_scanner.py — Read-only secret key discovery scanners.

Three scan sources produce ScanEntry records (key names only — no values stored
or logged anywhere in this module).

Satisfies: AC-01 to AC-05 (REM-017)
"""
from __future__ import annotations

import fnmatch
import glob
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

__all__ = ["ScanEntry", "env_scan", "a0proj_scan", "mcp_scan"]

# AC-02: regex for env-file ALL_CAPS keys (key >= 3 chars)
ENV_KEY_RE = re.compile(r'^([A-Z][A-Z0-9_]{2,})=(.+)$', re.MULTILINE)

# AC-03, AC-04: bare ALL_CAPS identifier (3+ chars)
ALL_CAPS_RE = re.compile(r'^[A-Z][A-Z0-9_]{2,}$')

# AC-04: MCP secret-like key patterns (fnmatch, case-insensitive)
MCP_SECRET_PATTERNS = ["*_key", "*_token", "*_secret", "*_password"]

# AC-02: max file size before skipping
_MAX_FILE_BYTES = 10 * 1024 * 1024  # 10 MB


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ScanEntry:  # AC-01: no value field by design
    """A discovered secret key name — value field intentionally absent (AC-01, AC-05)."""

    key: str
    source: Literal["env_scan", "a0proj_scan", "mcp_scan"]
    context: str   # sanitized relative path
    discovered_at: str  # ISO 8601 UTC


# ---------------------------------------------------------------------------
# env_scan — AC-02
# ---------------------------------------------------------------------------

def env_scan(scan_root: str) -> list[ScanEntry]:  # AC-01: public function
    """Walk scan_root for .env files; extract ALL_CAPS key names only.

    Satisfies: AC-02, AC-05
    Never stores, logs, or returns secret values.
    """
    entries: list[ScanEntry] = []
    scan_root = os.path.normpath(scan_root)

    for dirpath, _dirnames, filenames in os.walk(scan_root):
        for fname in filenames:
            # AC-02: match files with .env extension OR named exactly .env
            if not (fname == ".env" or fname.endswith(".env")):
                continue
            fpath = os.path.join(dirpath, fname)

            # AC-02: skip files > 10 MB
            try:
                if os.path.getsize(fpath) > _MAX_FILE_BYTES:
                    logger.debug("env_scan: skipping large file: %s", fpath)
                    continue
            except OSError as exc:
                logger.debug("env_scan: stat failed %s: %s", fpath, exc)
                continue

            # AC-02: relative path for context — no absolute paths in output
            rel_path = os.path.relpath(fpath, scan_root)

            try:
                with open(fpath, encoding="utf-8") as fh:
                    content = fh.read()
            except PermissionError as exc:  # AC-02: catch and continue
                logger.debug("env_scan: permission denied %s: %s", fpath, exc)
                continue
            except UnicodeDecodeError as exc:  # AC-02
                logger.debug("env_scan: decode error %s: %s", fpath, exc)
                continue
            except OSError as exc:  # AC-02
                logger.debug("env_scan: os error %s: %s", fpath, exc)
                continue

            for m in ENV_KEY_RE.finditer(content):
                key = m.group(1)  # AC-05: extract key only
                # m.group(2) is the raw value — NEVER stored, logged, or forwarded
                entries.append(ScanEntry(
                    key=key,
                    source="env_scan",
                    context=rel_path,
                    discovered_at=_now_iso(),
                ))

    return entries


# ---------------------------------------------------------------------------
# a0proj_scan — AC-03
# ---------------------------------------------------------------------------

def _walk_all_string_values(data: object) -> list[str]:  # AC-03: scalar walk
    """Recursively extract all string scalar values from a YAML/JSON structure."""
    results: list[str] = []
    if isinstance(data, dict):
        for v in data.values():
            results.extend(_walk_all_string_values(v))
    elif isinstance(data, list):
        for item in data:
            results.extend(_walk_all_string_values(item))
    elif isinstance(data, str):
        results.append(data)
    return results


def a0proj_scan(search_roots: list[str]) -> list[ScanEntry]:  # AC-01: public
    """Walk search_roots for .a0proj/ directories; extract secret key references.

    Detects:
    - bare ALL_CAPS identifiers in env files and YAML/JSON scalar values
    - $bao: prefixed references (extracts the key name after the prefix)

    Deduplicates by (key, context). Satisfies: AC-03, AC-05
    """
    import yaml  # PyYAML — available in A0 runtime

    entries: list[ScanEntry] = []
    seen: set[tuple[str, str]] = set()  # AC-03: dedup by (key, context)

    def _add(key: str, context: str) -> None:
        pair = (key, context)
        if pair not in seen:
            seen.add(pair)
            entries.append(ScanEntry(
                key=key,
                source="a0proj_scan",
                context=context,
                discovered_at=_now_iso(),
            ))

    for search_root in search_roots:
        search_root = os.path.normpath(search_root)
        for dirpath, dirnames, _filenames in os.walk(search_root):
            if ".a0proj" not in dirnames:
                continue
            a0proj_dir = os.path.join(dirpath, ".a0proj")
            context_root = dirpath  # context relative to parent of .a0proj

            for sub_dir, _, sub_files in os.walk(a0proj_dir):
                for fname in sub_files:
                    fpath = os.path.join(sub_dir, fname)
                    # AC-03: context = relative path from parent of .a0proj
                    rel_ctx = os.path.relpath(fpath, context_root)

                    # AC-03: variables.env and *.env files
                    if fname == "variables.env" or fname.endswith(".env"):
                        try:
                            with open(fpath, encoding="utf-8") as fh:
                                content = fh.read()
                            for m in ENV_KEY_RE.finditer(content):
                                key = m.group(1)  # value (group 2) discarded
                                _add(key, rel_ctx)
                        except (PermissionError, UnicodeDecodeError, OSError) as exc:
                            logger.debug("a0proj_scan: skipping %s: %s", fpath, exc)
                        continue

                    # AC-03: JSON and YAML files
                    if fname.endswith(".json") or fname.endswith(".yaml") or fname.endswith(".yml"):
                        try:
                            with open(fpath, encoding="utf-8") as fh:
                                raw = fh.read()
                            if fname.endswith(".json"):
                                data = json.loads(raw)
                            else:
                                data = yaml.safe_load(raw) or {}
                        except Exception as exc:
                            logger.debug("a0proj_scan: skipping %s: %s", fpath, exc)
                            continue

                        # AC-03: bare ALL_CAPS string values + $bao: refs
                        for val in _walk_all_string_values(data):
                            if ALL_CAPS_RE.match(val):
                                _add(val, rel_ctx)
                            elif val.startswith("$bao:"):
                                key = val[len("$bao:"):]
                                if key:  # non-empty after prefix
                                    _add(key, rel_ctx)

    return entries


# ---------------------------------------------------------------------------
# mcp_scan — AC-04
# ---------------------------------------------------------------------------

def mcp_scan(paths: list[str]) -> list[ScanEntry]:  # AC-01: public
    """Scan MCP settings files for secret-bearing keys.

    Resolves glob patterns in paths, reads JSON (fallback YAML), traverses
    mcpServers[*].headers and mcpServers[*].env sub-dicts.

    Satisfies: AC-04, AC-05
    """
    import yaml  # PyYAML

    entries: list[ScanEntry] = []

    def _key_matches(key: str) -> bool:  # AC-04: pattern matching
        # fnmatch case-insensitive OR bare ALL_CAPS
        return (
            any(fnmatch.fnmatch(key.lower(), pat) for pat in MCP_SECRET_PATTERNS)
            or ALL_CAPS_RE.match(key) is not None
        )

    for path_pattern in paths:
        # AC-04: resolve glob patterns (including ** recursive)
        resolved: list[str] = []
        try:
            if "**" in path_pattern:
                resolved = glob.glob(path_pattern, recursive=True)
            else:
                resolved = glob.glob(path_pattern)
        except Exception as exc:
            logger.warning("mcp_scan: glob failed for %s: %s", path_pattern, exc)
            continue

        # Also try pathlib glob for absolute patterns with **
        if not resolved and path_pattern.startswith("/"):
            try:
                stripped = path_pattern.lstrip("/")
                resolved = [str(x) for x in Path("/").glob(stripped)]
            except Exception:
                pass

        # Treat as literal path if glob found nothing
        if not resolved:
            if os.path.isfile(path_pattern):
                resolved = [path_pattern]
            else:
                logger.warning("mcp_scan: no files matched: %s", path_pattern)
                continue

        for fpath in resolved:
            fname = os.path.basename(fpath)  # AC-04: context = filename only
            try:
                with open(fpath, encoding="utf-8") as fh:
                    raw = fh.read()
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    try:
                        data = yaml.safe_load(raw) or {}
                    except Exception as exc:
                        logger.warning("mcp_scan: YAML parse error %s: %s", fpath, exc)
                        continue
            except FileNotFoundError as exc:
                logger.warning("mcp_scan: file not found %s: %s", fpath, exc)
                continue
            except (PermissionError, UnicodeDecodeError, OSError) as exc:
                logger.warning("mcp_scan: cannot read %s: %s", fpath, exc)
                continue
            except Exception as exc:  # AC-04: no exception propagated
                logger.warning("mcp_scan: unexpected error %s: %s", fpath, exc)
                continue

            if not isinstance(data, dict):
                continue

            mcp_servers = data.get("mcpServers", {})
            if not isinstance(mcp_servers, dict):
                continue

            for _server_name, server_cfg in mcp_servers.items():
                if not isinstance(server_cfg, dict):
                    continue
                for sub_key in ("headers", "env"):  # AC-04: headers + env
                    sub_dict = server_cfg.get(sub_key, {})
                    if not isinstance(sub_dict, dict):
                        continue
                    for key in sub_dict:
                        if _key_matches(key):
                            # AC-05: only key name, never value
                            entries.append(ScanEntry(
                                key=key,
                                source="mcp_scan",
                                context=fname,
                                discovered_at=_now_iso(),
                            ))

    return entries
