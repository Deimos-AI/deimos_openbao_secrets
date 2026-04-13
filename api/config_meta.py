"""
ConfigMeta ApiHandler — exposes field-level source metadata to the settings UI.

Endpoint: POST /api/plugins/deimos_openbao_secrets/config_meta
Request:  {} (body ignored — reads live environment state)
Response: {"ok": true, "env_overrides": ["url", "auth_method", ...]}

Security: only field NAMES are returned. Values are never read into the response.
         Credential field names (role_id, secret_id, token) appear in env_overrides
         when set via env — confirming the credential is active without exposing it.
"""
from __future__ import annotations
import importlib.util
from pathlib import Path
from helpers.api import ApiHandler, Request, Response  # noqa: F401

_PLUGIN_DIR = Path(__file__).resolve().parent.parent

# Fields containing credentials — names may appear in response, values NEVER may
_CREDENTIAL_FIELDS = frozenset({"role_id", "secret_id", "token"})


def _get_config_module():
    """Load helpers/config.py via importlib to avoid A0 helpers/ namespace collision."""
    mod_name = "deimos_openbao_secrets_config"
    spec = importlib.util.spec_from_file_location(
        mod_name,
        _PLUGIN_DIR / "openbao_helpers" / "config.py",
    )
    mod = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[mod_name] = mod  # required for Python 3.13 dataclass __module__ resolution
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop(mod_name, None)
    return mod


def load_config(plugin_dir: str):
    """Delegate to plugin's helpers/config.py::load_config()."""
    return _get_config_module().load_config(plugin_dir)


class ConfigMeta(ApiHandler):
    """Return list of field names whose values are sourced from OPENBAO_* env vars.

    Consumed by the settings UI (config.html) on page init to render ENV badges
    and set readonly/disabled state on env-overridden fields.
    """

    async def process(self, input: dict, request) -> dict:
        cfg = load_config(str(_PLUGIN_DIR))
        sources: dict = getattr(cfg, "_sources", {})

        # Build env_overrides list: field names with source == "env" only.
        # Values are deliberately never read or returned here.
        env_overrides = [
            field_name
            for field_name, src in sources.items()
            if src == "env"
        ]

        return {"ok": True, "env_overrides": env_overrides}
