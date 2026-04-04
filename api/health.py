"""Health check and connection test API for Deimos OpenBao plugin.

Endpoint: POST /api/plugins/deimos_openbao_secrets/health

Verifies connectivity AND credentials using ONLY the configured auth method.
"""
import importlib
import importlib.util
import logging
import os
import subprocess
import sys
from pathlib import Path
from helpers.api import ApiHandler, Request, Response
# ---------------------------------------------------------------------------
# Plugin helper bootstrap — load helpers/config.py via importlib.util.
# A0's importmodule() loads api/ files without plugin root on sys.path.
# `from helpers.config import load_config` resolves to A0's /a0/helpers/
# which has no config.py → ModuleNotFoundError → Flask 500 HTML response
# → browser JSON.parse fails: "Unexpected token '<', <!doctype ..."
# Fix: use find_plugin_dir() (A0 helpers.plugins — always safe) to resolve
# the path at runtime and load via importlib.util with a unique module key.
# Shares the same sys.modules cache key as api/secrets.py — one exec per process.
# ---------------------------------------------------------------------------
_PLUGIN_CFG_MODULE = "deimos_openbao_secrets_helpers_config"


def _get_config_module():
    """Load plugin's helpers/config.py, cached in sys.modules."""
    if _PLUGIN_CFG_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir  # A0's helpers.plugins — always safe
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            raise ImportError("deimos_openbao_secrets plugin dir not found via find_plugin_dir()")
        config_path = os.path.join(plugin_dir, "helpers", "config.py")
        if not os.path.exists(config_path):
            raise ImportError(f"helpers/config.py not found at: {config_path}")
        spec = importlib.util.spec_from_file_location(_PLUGIN_CFG_MODULE, config_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_PLUGIN_CFG_MODULE] = mod  # register before exec_module (circular import guard)
        spec.loader.exec_module(mod)
    return sys.modules[_PLUGIN_CFG_MODULE]


def load_config(plugin_dir: str):
    """Delegate to plugin's helpers/config.py::load_config()."""
    return _get_config_module().load_config(plugin_dir)

logger = logging.getLogger(__name__)

_PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _ensure_hvac():
    try:
        importlib.import_module("hvac")
        return True
    except ImportError:
        pass
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "hvac>=2.1.0"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=120,
        )
        importlib.import_module("hvac")
        return True
    except Exception as exc:
        logger.error("Failed to install hvac: %s", exc)
        return False


class TestConnection(ApiHandler):
    """Test OpenBao connectivity and authentication."""

    @classmethod
    def requires_api_key(cls):
        return False

    @classmethod
    def requires_auth(cls):
        return True

    @classmethod
    def requires_csrf(cls):
        return False

    async def process(self, input, request):
        if not _ensure_hvac():
            return {"ok": False, "error": "hvac library not installed"}

        import hvac

        cfg_input = input.get("config", {})
        url = cfg_input.get("url", "")
        timeout = cfg_input.get("timeout", 10)
        tls_verify = cfg_input.get("tls_verify", True)
        tls_ca_cert = cfg_input.get("tls_ca_cert", "")

        if not url:
            return {"ok": False, "error": "No OpenBao URL configured"}

        try:
            verify = tls_ca_cert if tls_ca_cert else tls_verify
            client = hvac.Client(url=url, verify=verify, timeout=timeout)

            # Step 1: Health check (no auth required)
            health = client.sys.read_health_status(method="GET")
            health_info = {}
            if isinstance(health, dict):
                health_info = {
                    "initialized": health.get("initialized"),
                    "sealed": health.get("sealed"),
                    "version": health.get("version", "unknown"),
                }
                if health.get("sealed"):
                    return {
                        "ok": False,
                        "error": "OpenBao is SEALED",
                        "data": {**health_info, "authenticated": False}
                    }

            # Step 2: Auth using ONLY the configured method
            plugin_cfg = load_config(str(_PLUGIN_DIR))  # REM-003: canonical config loader
            auth_method = plugin_cfg.auth_method  # REM-003: attribute access on OpenBaoConfig (dict→dataclass)

            if auth_method == "token":
                token = os.environ.get("OPENBAO_TOKEN", "")
                if not token:
                    return {
                        "ok": False,
                        "error": "OPENBAO_TOKEN not set in Docker environment",
                        "data": {**health_info, "authenticated": False, "auth_method": "token"}
                    }
                client.token = token

            elif auth_method == "approle":
                role_id = os.environ.get("OPENBAO_ROLE_ID", "")
                secret_id = os.environ.get("OPENBAO_SECRET_ID", "")
                if not role_id:
                    return {
                        "ok": False,
                        "error": "OPENBAO_ROLE_ID not set in Docker environment",
                        "data": {**health_info, "authenticated": False, "auth_method": "approle"}
                    }
                try:
                    result = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
                    client.token = result["auth"]["client_token"]
                except Exception as auth_exc:
                    return {
                        "ok": False,
                        "error": "AppRole login failed: " + str(auth_exc),
                        "data": {**health_info, "authenticated": False, "auth_method": "approle"}
                    }
            else:
                return {
                    "ok": False,
                    "error": "Unknown auth method: " + str(auth_method),
                    "data": {**health_info, "authenticated": False}
                }

            # Verify the token works
            if client.is_authenticated():
                return {
                    "ok": True,
                    "data": {
                        "status": "connected and authenticated",
                        **health_info,
                        "authenticated": True,
                        "auth_method": auth_method,
                    }
                }
            else:
                return {
                    "ok": False,
                    "error": "Authentication failed (token invalid or expired)",
                    "data": {**health_info, "authenticated": False, "auth_method": auth_method}
                }

        except Exception as exc:
            return {"ok": False, "error": str(exc)}
