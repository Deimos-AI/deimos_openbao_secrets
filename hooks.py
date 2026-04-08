"""Plugin lifecycle hooks for deimos_openbao_secrets.

Called by the Agent Zero framework via helpers.plugins.call_plugin_hook().
See plugins/README.md for the hooks.py contract.

Available hooks:
    install()            -- called after plugin install/update (via plugin installer)
    uninstall()          -- called before plugin deletion
    save_plugin_config() -- called when plugin config is saved from the UI
    get_plugin_config()  -- called when plugin config is read for the UI
"""

import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

_PLUGIN_DIR = Path(__file__).parent
_REQUIREMENTS = _PLUGIN_DIR / "requirements.txt"


# ---------------------------------------------------------------------------
# API Routes (auto-discovered by Agent Zero from the api/ directory)
# ---------------------------------------------------------------------------
# POST /api/plugins/deimos_openbao_secrets/health        -> api/health.py
# POST /api/plugins/deimos_openbao_secrets/secrets     -> api/secrets.py
# POST /api/plugins/deimos_openbao_secrets/rotate_mcp  -> api/rotate_mcp.py
# POST /api/plugins/deimos_openbao_secrets/sync_plugins -> api/sync_plugins.py
# GET/POST /api/plugins/deimos_openbao_secrets/bootstrap -> api/bootstrap.py
# POST /api/plugins/deimos_openbao_secrets/propagate -> api/propagate.py
# POST /api/plugins/deimos_openbao_secrets/config_meta -> api/config_meta.py::ConfigMeta
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# REM-033 AC-01/AC-02: Dependency auto-install at plugin load time.
#
# Called at module level so it fires on every hooks.py import (plugin activation
# or any code that imports hooks).  Delegates to helpers/deps.py which has a
# module-level `_installed` boolean guard -- subsequent calls are free no-ops.
# Errors are caught and logged as warnings so a transient pip failure never
# prevents the plugin from loading.
# ---------------------------------------------------------------------------

def _ensure_deps_at_load() -> None:
    """Install missing plugin dependencies when hooks.py is first imported.

    Satisfies: AC-01, AC-02 (REM-033)
    """
    try:
        plugin_root = str(_PLUGIN_DIR)
        if plugin_root not in sys.path:
            sys.path.insert(0, plugin_root)
        from helpers.deps import ensure_dependencies  # noqa: PLC0415
        ensure_dependencies()
    except Exception as exc:  # pragma: no cover
        logger.warning("REM-033: dependency pre-install warning: %s", exc)


_ensure_deps_at_load()


# ---------------------------------------------------------------------------
# REM-033 AC-03/AC-04: Key normalisation -- Alpine.js compound <-> snake_case
#
# Problem: Alpine.js x-model binds to compound-lowercase keys (authmethod,
# mountpoint, etc.).  When the user clicks Save the framework serialises the
# Alpine config object directly to config.json using those same keys.
# helpers/config.py::load_config() expects snake_case OpenBaoConfig field
# names (auth_method, mount_point, etc.) -- mismatched keys are silently
# dropped and the dataclass resolves to wrong defaults (e.g. auth_method
# defaults to 'token' even when the UI shows 'approle').
#
# Fix: intercept in save_plugin_config() and normalise compound -> snake_case
# before the framework writes config.json.  Reverse in get_plugin_config() so
# the UI re-reads values correctly from the now-snake_case file.
# ---------------------------------------------------------------------------

_KEY_REMAP: "dict[str, str]" = {
    # Alpine.js compound key         ->  OpenBaoConfig snake_case field name
    "authmethod":               "auth_method",
    "mountpoint":               "mount_point",
    "secretspath":              "secrets_path",
    "tlsverify":                "tls_verify",
    "tlscacert":                "tls_ca_cert",
    "cachettl":                 "cache_ttl",
    "retryattempts":            "retry_attempts",
    "circuitbreakerthreshold":  "circuit_breaker_threshold",
    "circuitbreakerrecovery":   "circuit_breaker_recovery",
    "fallbacktoenv":            "fallback_to_env",
    "hardfailonavailable":     "hard_fail_on_unavailable",
    "terminalsecrets":          "terminal_secrets",
    "roleid":                   "role_id",
    "secretidenv":              "secret_id_env",
    "secretidfile":             "secret_id_file",
    "vaultprojecttemplate":     "vault_project_template",
    "vaultnamespace":           "vault_namespace",
    "vaulttokenfile":           "vault_token_file",
}

# Reverse map: snake_case -> Alpine.js compound format (used by get_plugin_config)
_KEY_REVERSE: "dict[str, str]" = {v: k for k, v in _KEY_REMAP.items()}


def normalize_config_keys(data: dict) -> dict:
    """Normalise Alpine.js compound/camelCase keys to snake_case for config.json.

    Idempotent: snake_case keys absent from the remap dict pass through
    unchanged, so a dict that is already normalised is safe to call again.

    Example::

        normalize_config_keys({"authmethod": "approle", "mountpoint": "secret"})
        # -> {"auth_method": "approle", "mount_point": "secret"}

    Satisfies: AC-03, AC-04 (REM-033)
    """
    return {_KEY_REMAP.get(k, k): v for k, v in data.items()}


def denormalize_config_keys(data: dict) -> dict:
    """Convert snake_case config keys back to Alpine.js compound format for the UI.

    Allows get_plugin_config() to return values that Alpine.js x-model bindings
    (config.authmethod, config.mountpoint, etc.) can populate correctly after
    config.json has been written with snake_case keys.

    Keys not in the reverse map (e.g. 'enabled', 'url') pass through unchanged.

    Satisfies: AC-03 (REM-033) -- round-trip fidelity for get_plugin_config.
    """
    return {_KEY_REVERSE.get(k, k): v for k, v in data.items()}


# ---------------------------------------------------------------------------
# Lifecycle: install
# ---------------------------------------------------------------------------

def install():
    """Install plugin dependencies into the framework runtime.

    Called automatically by the plugin installer after:
      - install_from_git()
      - install_from_zip()
      - update_from_git()

    Reads requirements.txt and installs into the current Python
    environment (the A0 framework venv, typically /opt/venv-a0).
    """
    if not _REQUIREMENTS.exists():
        logger.warning("requirements.txt not found at %s -- skipping", _REQUIREMENTS)
        return

    logger.info("Installing deimos_openbao_secrets dependencies from %s", _REQUIREMENTS)
    try:
        subprocess.check_call(
            [
                sys.executable, "-m", "pip", "install",
                "--quiet",
                "-r", str(_REQUIREMENTS),
            ],
            timeout=120,
        )
        logger.info("deimos_openbao_secrets dependencies installed successfully")
    except subprocess.CalledProcessError as exc:
        logger.error("Failed to install dependencies: %s", exc)
        raise
    except subprocess.TimeoutExpired:
        logger.error("Timeout installing dependencies (120s)")
        raise


# ---------------------------------------------------------------------------
# Lifecycle: save_plugin_config
# ---------------------------------------------------------------------------

def save_plugin_config(result=None, settings=None, **kwargs):
    """Hook called by A0 framework during config save.

    REM-033 AC-03/AC-04: Normalises Alpine.js compound/camelCase keys to
    snake_case before the framework writes config.json.  Without this
    normalisation the dict is persisted verbatim and load_config() silently
    drops every compound key, resolving OpenBaoConfig to wrong defaults
    (e.g. auth_method defaults to 'token' even when 'approle' was set in UI).

    Example transformation::

        {"authmethod": "approle", "mountpoint": "secret"}
        -> {"auth_method": "approle", "mount_point": "secret"}

    Idempotent: already-snake_case dicts pass through unchanged.

    **kwargs absorbs extra args the framework may pass (e.g. default=).
    """
    raw: dict = settings or {}
    return normalize_config_keys(raw)


# ---------------------------------------------------------------------------
# Lifecycle: get_plugin_config
# ---------------------------------------------------------------------------

def get_plugin_config(result=None, **kwargs):
    """Hook called by A0 framework during config load.

    REM-033 AC-03/AC-04: After merging default_config.yaml under the saved
    config.json, denormalises any snake_case keys back to Alpine.js compound
    format so that x-model bindings (config.authmethod, config.mountpoint,
    etc.) populate correctly in the UI.

    Merge order (lower priority listed first):
      1. default_config.yaml  -- already in Alpine.js compound format
      2. saved config.json (result) -- now snake_case after REM-033 fix;
         denormalised to compound before merging so UI defaults are
         correctly overridden by the saved values.

    **kwargs absorbs extra args the framework passes (e.g. agent=, default=).
    """
    import yaml  # noqa: PLC0415 -- PyYAML is a framework dependency, always present

    # Load defaults (already in Alpine.js compound format from default_config.yaml)
    defaults: dict = {}
    default_path = _PLUGIN_DIR / "default_config.yaml"
    if default_path.exists():
        with open(default_path) as fh:
            defaults = yaml.safe_load(fh) or {}

    # result from the framework may be:
    #   - snake_case  (post-REM-033 config.json)
    #   - compound    (legacy config.json from before REM-033)
    # denormalize_config_keys() converts snake_case -> Alpine.js compound;
    # already-compound keys pass through unchanged (not in _KEY_REVERSE).
    if result and isinstance(result, dict):
        denormalized = denormalize_config_keys(result)
        merged = {**defaults, **denormalized}
    else:
        merged = defaults

    # E-04: Apply env var overrides so displayed values + Test Connection reflect
    # actual env state. Without this, Alpine config shows defaults/config.json
    # values even when OPENBAO_* env vars are active (e.g. url=127.0.0.1:8200
    # instead of the real OPENBAO_URL). Credential values are never included.
    try:
        import importlib.util as _ilu
        import sys as _sys
        from dataclasses import asdict as _asdict
        _mod_name = "_deimos_openbao_secrets_config_hook"
        _spec = _ilu.spec_from_file_location(_mod_name, _PLUGIN_DIR / "helpers" / "config.py")
        _mod = _ilu.module_from_spec(_spec)
        _sys.modules[_mod_name] = _mod
        try:
            _spec.loader.exec_module(_mod)
        finally:
            _sys.modules.pop(_mod_name, None)
        _cfg = _mod.load_config(str(_PLUGIN_DIR))
        _sources = getattr(_cfg, "_sources", {})
        _CRED = frozenset({"role_id", "secret_id", "token"})
        _cfg_dict = _asdict(_cfg)
        for _field, _src in _sources.items():
            if _src == "env" and _field not in _CRED:
                merged[_field] = _cfg_dict.get(_field, merged.get(_field))
    except Exception:
        pass  # Non-fatal: display degradation only — never break config load

    return merged
