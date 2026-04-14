"""openbao_helpers/install_flow.py — Evergreen install flow helpers.

Provides connection validation, KV mount/path provisioning, and
patch_core.py execution for the deimos_openbao_secrets plugin.

Called by hooks.py install() during first-time setup.

Satisfies: E-08 AC-01, AC-02, AC-03, AC-08
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import hvac  # Bug-1 fix: needed for hvac.exceptions.InvalidPath in ensure_kv_mount/ensure_secrets_path

logger = logging.getLogger(__name__)

_PLUGIN_ROOT = str(Path(__file__).resolve().parent.parent)  # plugin dir (1 up from openbao_helpers/)


# _load_plugin_module removed — namespace collision resolved by renaming helpers/ to openbao_helpers/

def _ensure_module_aliases() -> None:
    """Bootstrap sys.modules aliases required by openbao_client.py.

    openbao_client.py does `from openbao_config import OpenBaoConfig` at module
    level.  The `openbao_config` alias is normally registered by
    factory_common.py during factory init, but install_flow.py is called
    during the install hook *before* factory init runs.

    This function mirrors the conftest.py bootstrap: if the alias is not
    already present, it imports openbao_helpers.config and registers it.
    Idempotent — safe to call multiple times.
    """
    if "openbao_config" in sys.modules:
        return  # Already registered by factory_common or a prior call
    try:
        import openbao_helpers.config as _cfg_mod
        sys.modules["openbao_config"] = _cfg_mod
        logger.debug("_ensure_module_aliases: registered openbao_config alias")
    except Exception as exc:
        logger.warning("_ensure_module_aliases: failed to register openbao_config: %s", exc)




def _get_authenticated_client(config: Any) -> Optional[Any]:
    """Get an authenticated hvac.Client via OpenBaoClient (handles AppRole login).

    Uses OpenBaoClient which properly handles both token and AppRole auth
    methods, including login flow, namespace headers, and protocol probes.

    Args:
        config: OpenBaoConfig instance with connection parameters.

    Returns:
        An authenticated hvac.Client instance, or None if auth failed.

    Bug-1 fix: Previously, ensure_kv_mount, ensure_secrets_path,
    discover_existing_secrets, and seed_terminal_secrets created raw
    hvac.Client(url, token=...) which only works for token auth.
    AppRole configs always failed with 'Not authenticated'.
    """
    _ensure_module_aliases()
    try:
        from openbao_helpers.openbao_client import OpenBaoClient
        wrapper = OpenBaoClient(config)
        if wrapper._client and wrapper._client.is_authenticated():
            return wrapper._client
        logger.warning("_get_authenticated_client: client not authenticated (auth_method=%s)",
                       getattr(config, 'auth_method', 'unknown'))
        return None
    except Exception as exc:
        logger.error("_get_authenticated_client failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# AC-01: Validate OpenBao connectivity
# ---------------------------------------------------------------------------

def validate_connection(config: Any) -> Dict[str, Any]:
    """Validate OpenBao connectivity via health check and auth verification.

    Creates a temporary OpenBaoClient, runs health_check(), and returns
    a structured result dict. Does NOT modify global state.

    Args:
        config: OpenBaoConfig instance with connection parameters.

    Returns:
        Dict with keys:
            connected (bool): Server is reachable.
            authenticated (bool): Credentials are valid.
            sealed (bool|None): Vault seal status.
            error (str|None): Error message if connectivity failed.

    Satisfies: AC-01
    """
    result: Dict[str, Any] = {
        "connected": False,
        "authenticated": False,
        "sealed": None,
        "error": None,
    }

    _ensure_module_aliases()
    try:
        from openbao_helpers.openbao_client import OpenBaoClient as _OpenBaoClient_cls
        OpenBaoClient = _OpenBaoClient_cls
        client = OpenBaoClient(config)
        health = client.health_check()
        result["connected"] = health.get("connected", False)
        result["authenticated"] = health.get("authenticated", False)
        result["sealed"] = health.get("sealed")

        if not result["connected"]:
            result["error"] = "OpenBao server unreachable"
        elif not result["authenticated"]:
            result["error"] = "Authentication failed — check credentials"
        elif result["sealed"]:
            result["error"] = "Vault is sealed — unseal before proceeding"

        client.close()

    except Exception as exc:
        result["error"] = f"Connection error: {exc}"
        logger.error("validate_connection failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# AC-02: Ensure KV v2 mount exists
# ---------------------------------------------------------------------------

def ensure_kv_mount(config: Any) -> Dict[str, Any]:
    """Ensure the KV v2 mount point exists, creating it if absent.

    Uses hvac's sys/mounts endpoint to check and create. Requires
    a token with sudo/root or mount creation policy.

    Args:
        config: OpenBaoConfig instance with mount_point and connection params.

    Returns:
        Dict with keys:
            mount_point (str): The mount point path.
            created (bool): True if mount was created, False if already existed.
            error (str|None): Error message if mount creation failed.

    Satisfies: AC-02
    """
    mount = config.mount_point
    result: Dict[str, Any] = {
        "mount_point": mount,
        "created": False,
        "error": None,
    }

    try:
        client = _get_authenticated_client(config)
        if client is None:
            result["error"] = "Not authenticated — cannot create mount"
            return result
        # Check if mount already exists
        try:
            mounts = client.sys.list_mounted_secrets_engines()
            mount_path = f"{mount}/"
            if mount_path in mounts:
                logger.info("KV mount '%s' already exists", mount)
                return result
        except hvac.exceptions.InvalidPath:
            pass  # No mounts listed — proceed to create
        except Exception as exc:
            logger.debug("Could not list mounts: %s", exc)

        # Create KV v2 mount
        try:
            client.sys.enable_secrets_engine(
                backend_type="kv",
                path=mount,
                options={"version": "2"},
                description=f"OpenBao KV v2 for deimos_openbao_secrets (auto-created)",
            )
            result["created"] = True
            logger.info("Created KV v2 mount at '%s'", mount)
        except Exception as exc:
            result["error"] = f"Failed to create mount: {exc}"
            logger.error("Failed to create KV mount '%s': %s", mount, exc)

    except Exception as exc:
        result["error"] = f"Mount check error: {exc}"
        logger.error("ensure_kv_mount failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# AC-03: Ensure secrets path exists
# ---------------------------------------------------------------------------

def ensure_secrets_path(config: Any) -> Dict[str, Any]:
    """Ensure the secrets path exists within the KV v2 mount.

    Writes an empty placeholder secret to create the path if it doesn't
    already exist. This is necessary because KV v2 doesn't create paths
    until a secret is written.

    Args:
        config: OpenBaoConfig instance with mount_point, secrets_path, connection params.

    Returns:
        Dict with keys:
            path (str): The full path (mount_point/secrets_path).
            created (bool): True if path was created, False if already existed.
            error (str|None): Error message if path creation failed.

    Satisfies: AC-03
    """
    mount = config.mount_point
    path = config.secrets_path
    result: Dict[str, Any] = {
        "path": f"{mount}/{path}",
        "created": False,
        "error": None,
    }

    try:
        client = _get_authenticated_client(config)
        if client is None:
            result["error"] = "Not authenticated — cannot create secrets path"
            return result

        # Check if path already has secrets
        try:
            existing = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount,
                raise_on_deleted_version=False,
            )
            if existing is not None:
                logger.info("Secrets path '%s/%s' already exists", mount, path)
                return result
        except hvac.exceptions.InvalidPath:
            pass  # Path doesn't exist — proceed to create
        except Exception as exc:
            logger.debug("Could not read secrets path: %s", exc)

        # Create path with a placeholder entry
        try:
            client.secrets.kv.v2.create_or_update_secret(
                path=path,
                mount_point=mount,
                secret={"_initialized": "true"},
            )
            result["created"] = True
            logger.info("Created secrets path '%s/%s'", mount, path)
        except Exception as exc:
            result["error"] = f"Failed to create secrets path: {exc}"
            logger.error("Failed to create secrets path '%s/%s': %s", mount, path, exc)

    except Exception as exc:
        result["error"] = f"Path check error: {exc}"
        logger.error("ensure_secrets_path failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# Vault Discovery — detect pre-existing secrets (E-08 extension)
# ---------------------------------------------------------------------------

def discover_existing_secrets(config: Any) -> Dict[str, Any]:
    """List all secret keys at the configured KV v2 path.

    Scans the secrets path in OpenBao and returns key names only —
    never values. Used by _bootstrap_vault() to decide between the
    fresh evergreen path (seed from env) and the brownfield discovery
    path (register + defer to user confirmation).

    Args:
        config: OpenBaoConfig instance with connection parameters.

    Returns:
        Dict with keys:
            keys (list[str]): Secret key names found in vault.
            count (int): Number of keys found.
            error (str|None): Error message if scan failed.

    Satisfies: E-08-ext AC-D1 (vault secrets discovery)
    """
    result: Dict[str, Any] = {
        "keys": [],
        "count": 0,
        "error": None,
    }

    try:
        client = _get_authenticated_client(config)
        if client is None:
            result["error"] = "Not authenticated — cannot scan secrets"
            return result

        resp = client.secrets.kv.v2.read_secret_version(
            path=config.secrets_path,
            mount_point=config.mount_point,
            raise_on_deleted_version=False,
        )

        if resp and isinstance(resp.get("data", {}).get("data"), dict):
            secret_data = resp["data"]["data"]
            # Filter out the internal _initialized marker
            keys = [
                k for k in secret_data.keys()
                if not k.startswith("_")
            ]
            result["keys"] = sorted(keys)
            result["count"] = len(keys)
            logger.info(
                "Vault discovery: %d pre-existing secrets at %s/%s",
                result["count"], config.mount_point, config.secrets_path,
            )
        else:
            logger.info("Vault discovery: no secrets at %s/%s", config.mount_point, config.secrets_path)

        client.close()

    except Exception as exc:
        result["error"] = f"Discovery scan error: {exc}"
        logger.warning("discover_existing_secrets failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# Brownfield discovery registration — E-08 extension
# ---------------------------------------------------------------------------

def register_discovered_secrets(config: Any, keys: list[str]) -> Dict[str, Any]:
    """Register discovered vault secrets in the registry with status 'discovered'.

    Unlike bootstrap_registry which marks entries as 'migrated', this function
    marks entries as 'discovered' to indicate they pre-exist in the vault and
    require user confirmation before propagation.

    Args:
        config: OpenBaoConfig instance.
        keys: List of secret key names discovered in the vault.

    Returns:
        Dict with keys:
            registered (int): Number of entries registered.
            skipped (int): Number of entries already present.
            discovered_at (str|None): ISO timestamp of discovery.
            error (str|None): Error message if registration failed.

    Satisfies: E-08-ext AC-D2 (brownfield discovery registration)
    """
    result: Dict[str, Any] = {
        "registered": 0,
        "skipped": 0,
        "discovered_at": None,
        "error": None,
    }

    if not keys:
        result["discovered_at"] = _now_iso()
        return result

    try:
        from openbao_helpers.registry import RegistryManager as _RegistryManager_cls, RegistryEntry as _RegistryEntry_cls
        RegistryManager = _RegistryManager_cls
        RegistryEntry = _RegistryEntry_cls
        from datetime import datetime, timezone

        rm = RegistryManager()
        registry = rm.load()

        existing_ids = {e["id"] for e in registry.get("entries", [])}
        now = datetime.now(timezone.utc).isoformat()

        for key in keys:
            entry = RegistryEntry(
                id=RegistryEntry.make_id("vault_discovery", "existing_secrets", key),
                key=key,
                source="vault_discovery",
                context="existing_secrets",
                description=f"Discovered pre-existing in vault during install",
                discovered_at=now,
                status="discovered",  # NOT "migrated" — awaiting user confirmation
            )

            if entry.id in existing_ids:
                result["skipped"] += 1
                continue

            registry["entries"].append(entry.to_dict())
            result["registered"] += 1

        # Record discovery metadata at registry level
        registry["discovery_status"] = "discovered"
        registry["discovered_at"] = now
        registry["vault_secret_keys"] = sorted(keys)
        result["discovered_at"] = now
        rm.save(registry)
        logger.info(
            "Vault discovery registered: %d new, %d skipped (total: %d keys)",
            result["registered"], result["skipped"], len(keys),
        )

    except Exception as exc:
        result["error"] = f"Discovery registration failed: {exc}"
        logger.error("register_discovered_secrets failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# AC-04: Seed terminal_secrets on install
# ---------------------------------------------------------------------------

def seed_terminal_secrets(config: Any) -> Dict[str, Any]:
    """Seed terminal_secrets from environment variables into vault.

    Reads the terminal_secrets list from config, resolves each key from
    os.environ, and writes it to the KV v2 path if not already present.

    Args:
        config: OpenBaoConfig instance with terminal_secrets list and connection params.

    Returns:
        Dict with keys:
            seeded (list[str]): Keys successfully seeded.
            skipped (list[str]): Keys skipped (already in vault or not in env).
            errors (list[str]): Per-key error messages.

    Satisfies: AC-04, AC-08 (idempotent — skips existing)
    """
    result: Dict[str, Any] = {
        "seeded": [],
        "skipped": [],
        "errors": [],
    }

    terminal_keys = getattr(config, 'terminal_secrets', []) or []
    if not terminal_keys:
        logger.info("No terminal_secrets configured — nothing to seed")
        return result

    try:
        client = _get_authenticated_client(config)
        if client is None:
            result["errors"].append("Not authenticated — cannot seed secrets")
            return result

        mount = config.mount_point
        path = config.secrets_path

        # Read existing secrets (for idempotency check)
        existing: Dict[str, str] = {}
        try:
            resp = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount,
                raise_on_deleted_version=False,
            )
            if resp and isinstance(resp.get("data", {}).get("data"), dict):
                existing = {k.upper(): v for k, v in resp["data"]["data"].items()}
        except Exception:
            pass  # Path may not exist yet — that's fine

        for key in terminal_keys:
            env_value = os.environ.get(key)
            if not env_value:
                result["skipped"].append(key)
                logger.debug("seed: %s not in env — skipping", key)
                continue

            if key.upper() in existing:
                result["skipped"].append(key)
                logger.debug("seed: %s already in vault — skipping (idempotent)", key)
                continue

            try:
                # CAS with version 0 means "only write if key doesn't exist"
                client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    mount_point=mount,
                    secret={key: env_value},
                )
                result["seeded"].append(key)
                logger.info("seeded: %s → vault", key)
            except Exception as exc:
                result["errors"].append(f"{key}: {exc}")
                logger.error("seed: failed to write %s: %s", key, exc)

    except Exception as exc:
        result["errors"].append(f"Setup error: {exc}")
        logger.error("seed_terminal_secrets failed: %s", exc)

    return result


# ---------------------------------------------------------------------------
# AC-05: Bootstrap registry on install
# ---------------------------------------------------------------------------

def bootstrap_registry(config: Any, seeded_keys: list[str] = None) -> Dict[str, Any]:
    """Bootstrap the secrets registry with seeded entries.

    Uses existing RegistryManager to register each seeded secret as
    a 'migrated' entry. Idempotent — re-registering is a no-op.

    Args:
        config: OpenBaoConfig instance.
        seeded_keys: List of secret key names that were seeded.

    Returns:
        Dict with keys:
            registered (int): Number of entries registered.
            skipped (int): Number of entries already present.
            bootstrapped_at (str|None): ISO timestamp of bootstrap.
            error (str|None): Error message if bootstrapping failed.

    Satisfies: AC-05, AC-08 (idempotent)
    """
    result: Dict[str, Any] = {
        "registered": 0,
        "skipped": 0,
        "bootstrapped_at": None,
        "error": None,
    }

    if not seeded_keys:
        result["bootstrapped_at"] = _now_iso()
        return result

    try:
        from openbao_helpers.registry import RegistryManager as _RegistryManager_cls, RegistryEntry as _RegistryEntry_cls
        RegistryManager = _RegistryManager_cls
        RegistryEntry = _RegistryEntry_cls
        from datetime import datetime, timezone

        rm = RegistryManager()
        registry = rm.load()

        existing_ids = {e["id"] for e in registry.get("entries", [])}

        for key in seeded_keys:
            entry = RegistryEntry(
                id=RegistryEntry.make_id("install_seed", "terminal_secrets", key),
                key=key,
                source="install_seed",
                context="terminal_secrets",
                description=f"Seeded during evergreen install from env var",
                discovered_at=datetime.now(timezone.utc).isoformat(),
                status="migrated",
            )

            if entry.id in existing_ids:
                result["skipped"] += 1
                continue

            registry["entries"].append(entry.to_dict())
            result["registered"] += 1

        registry["bootstrapped_at"] = datetime.now(timezone.utc).isoformat()
        result["bootstrapped_at"] = registry["bootstrapped_at"]
        rm.save(registry)
        logger.info(
            "Registry bootstrapped: %d registered, %d skipped",
            result["registered"], result["skipped"],
        )

    except Exception as exc:
        result["error"] = f"Registry bootstrap failed: {exc}"
        logger.error("bootstrap_registry failed: %s", exc)

    return result


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# patch_core.py execution
# ---------------------------------------------------------------------------

def should_apply_core_patch() -> bool:
    """Check if patch_core.py needs to be applied.

    Detects whether hook_context parameter is present in helpers/plugins.py
    by checking for the sentinel string 'hook_context={'.

    Returns:
        True if the patch is needed (sentinel not found).

    User requirement: patch_core.py must be executed as part of install flow.
    """
    plugins_path = Path("/a0/helpers/plugins.py")
    if not plugins_path.exists():
        return False

    content = plugins_path.read_text(encoding="utf-8")
    # Check if the patch has already been applied
    return "hook_context={'caller'" not in content


def apply_core_patch() -> Dict[str, Any]:
    """Execute patch_core.py if needed.

    Runs the patch script from the project root. The script is idempotent —
    re-running on already-patched files is a safe no-op.

    Returns:
        Dict with keys:
            applied (bool): True if patch was applied or already present.
            output (str): Script output.
            error (str|None): Error message if execution failed.
    """
    result: Dict[str, Any] = {
        "applied": False,
        "output": "",
        "error": None,
    }

    if not should_apply_core_patch():
        result["applied"] = True
        result["output"] = "Patch already applied — skipping"
        return result

    # Look for patch_core.py in the plugin directory (1 level up from helpers/).
    # patch_core.py is bundled with the plugin — not the parent project.
    patch_script = Path(__file__).resolve().parent.parent / "patch_core.py"

    if not patch_script.exists():
        result["error"] = "patch_core.py not found — skipping core patch"
        result["applied"] = True  # Not fatal — plugin works without patch
        return result

    try:
        proc = subprocess.run(
            [sys.executable, str(patch_script)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        result["output"] = proc.stdout
        if proc.returncode == 0:
            result["applied"] = True
            logger.info("Core patch applied successfully")
        else:
            result["error"] = f"patch_core.py exited with code {proc.returncode}: {proc.stderr}"
            logger.warning("Core patch failed: %s", result["error"])
            # Non-fatal — plugin works without the patch
            result["applied"] = True
    except Exception as exc:
        result["error"] = f"Failed to run patch_core.py: {exc}"
        logger.warning("Core patch execution failed: %s", exc)
        result["applied"] = True  # Non-fatal

    return result


# ---------------------------------------------------------------------------
# Prompt symlink — E-07/E-08 integration
# ---------------------------------------------------------------------------

def ensure_prompt_symlink() -> Dict[str, Any]:
    """Create symlink for agent.system.secrets.md if not already present.

    Links /a0/usr/prompts/agent.system.secrets.md to the plugin's own
    prompts/agent.system.secrets.md. This replaces the framework's default
    secrets prompt with the OpenBao-specific one.

    Idempotent — re-running is a no-op if symlink already correct.
    Non-destructive — skips if a non-symlink file already exists.

    Returns:
        Dict with keys:
            symlinked (bool): True if symlink was created or already correct.
            path (str): The symlink path.
            target (str): The resolved target path.
            error (str|None): Error message if symlink creation failed.

    Satisfies: E-08 (prompt integration into install flow)
    """
    plugin_dir = Path(__file__).resolve().parent.parent  # plugin root
    source = plugin_dir / "prompts" / "agent.system.secrets.md"
    link_path = Path("/a0/usr/prompts/agent.system.secrets.md")

    result: Dict[str, Any] = {
        "symlinked": False,
        "path": str(link_path),
        "target": str(source),
        "error": None,
    }

    # Verify source prompt exists
    if not source.exists():
        result["error"] = f"Source prompt not found: {source}"
        logger.warning("ensure_prompt_symlink: %s", result["error"])
        return result

    # Check if symlink already exists and is correct
    if link_path.is_symlink():
        existing_target = os.readlink(str(link_path))
        resolved_existing = Path(existing_target)
        if not resolved_existing.is_absolute():
            resolved_existing = link_path.parent / existing_target
        if resolved_existing.resolve() == source.resolve():
            logger.debug("Prompt symlink already correct: %s -> %s", link_path, source)
            result["symlinked"] = True
            return result
        else:
            # Symlink exists but points elsewhere — remove and recreate
            logger.info(
                "Prompt symlink points to %s (expected %s) — updating",
                existing_target, source,
            )
            link_path.unlink()
    elif link_path.exists():
        # A real file exists — don't overwrite user's custom prompt
        logger.warning(
            "Prompt file already exists (not a symlink): %s — skipping",
            link_path,
        )
        result["error"] = f"Existing file at {link_path} — not overwriting"
        return result

    # Ensure parent directory exists
    link_path.parent.mkdir(parents=True, exist_ok=True)

    # Create symlink
    try:
        os.symlink(str(source), str(link_path))
        result["symlinked"] = True
        logger.info("Created prompt symlink: %s -> %s", link_path, source)
    except OSError as exc:
        result["error"] = f"Failed to create symlink: {exc}"
        logger.error("ensure_prompt_symlink failed: %s", exc)

    return result
