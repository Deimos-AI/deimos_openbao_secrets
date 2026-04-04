"""Secrets CRUD API for Deimos OpenBao plugin.

Endpoint: POST /api/plugins/deimos_openbao_secrets/secrets

Actions: list, get, set, delete, bulk_set

LLM Isolation: This endpoint runs entirely between browser and OpenBao.
No LLM is involved at any point.
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
# Solution: use find_plugin_dir() (A0's own helpers.plugins — always safe)
# to locate the file and load via importlib.util with a unique module key.
# sys.modules caching ensures exec_module is called only once per process.
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

# Plugin directory — resolved from this file's location
_PLUGIN_DIR = Path(__file__).resolve().parent.parent


def _ensure_hvac() -> bool:
    """Ensure hvac is installed."""
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



def _get_client():
    """Create an authenticated hvac client from config + env vars."""
    import hvac

    cfg = load_config(str(_PLUGIN_DIR))  # REM-003: canonical config loader replaces _load_config()

    url = cfg.url  # REM-003: attribute access on OpenBaoConfig
    if not url:
        raise RuntimeError("OpenBao URL not configured")

    tls_verify = cfg.tls_verify  # REM-003: attribute access on OpenBaoConfig
    tls_ca_cert = cfg.tls_ca_cert
    timeout = cfg.timeout

    verify = tls_ca_cert if tls_ca_cert else tls_verify
    client = hvac.Client(url=url, verify=verify, timeout=timeout)

    # Auth from env vars
    token = os.environ.get("OPENBAO_TOKEN", "")
    if token:
        client.token = token
    else:
        role_id = os.environ.get("OPENBAO_ROLE_ID", "")
        secret_id = os.environ.get("OPENBAO_SECRET_ID", "")
        if role_id:
            result = client.auth.approle.login(role_id=role_id, secret_id=secret_id)
            client.token = result["auth"]["client_token"]
        else:
            raise RuntimeError(
                "No credentials found. Set OPENBAO_TOKEN or OPENBAO_ROLE_ID/OPENBAO_SECRET_ID "
                "as Docker environment variables."
            )

    if not client.is_authenticated():
        raise RuntimeError("OpenBao authentication failed")

    return client, cfg


def _get_path(cfg, project_name: str = "") -> str:
    """Build the secrets path, optionally scoped to a project."""
    path = cfg.secrets_path  # REM-003: attribute access on OpenBaoConfig
    if project_name:
        path = f"{path}/{project_name}"
    return path


class SecretsManager(ApiHandler):

    @classmethod
    def requires_csrf(cls) -> bool:
        return False
    """CRUD operations for OpenBao secrets."""

    async def process(self, input: dict, request: Request) -> dict | Response:
        if not _ensure_hvac():
            return {"ok": False, "error": "Failed to install hvac library"}

        try:
            client, cfg = _get_client()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

        import hvac.exceptions

        mount = cfg.mount_point  # REM-003: attribute access on OpenBaoConfig
        project_name = input.get("project_name", "")
        path = _get_path(cfg, project_name)
        action = input.get("action", "")

        try:
            if action == "list":
                return self._list(client, mount, path)
            elif action == "get":
                return self._get(client, mount, path, input.get("key", ""))
            elif action == "set":
                return self._set(client, mount, path, input.get("pairs", []))
            elif action == "delete":
                return self._delete(client, mount, path, input.get("key", ""))
            elif action == "bulk_set":
                return self._bulk_set(client, mount, path, input.get("text", ""))
            else:
                return {"ok": False, "error": f"Unknown action: {action}"}
        except hvac.exceptions.Forbidden:
            return {"ok": False, "error": "Permission denied. Check token permissions."}
        except hvac.exceptions.InvalidPath:
            if action == "list":
                return {"ok": True, "secrets": []}
            return {"ok": False, "error": "Path not found in OpenBao"}
        except Exception as exc:
            logger.error("Secrets API error (%s): %s", action, exc)
            return {"ok": False, "error": str(exc)}

    def _read_all(self, client, mount: str, path: str) -> dict:
        """Read all secrets at path. Returns empty dict if path doesn't exist."""
        import hvac.exceptions
        try:
            resp = client.secrets.kv.v2.read_secret_version(
                path=path, mount_point=mount, raise_on_deleted_version=False
            )
            return resp.get("data", {}).get("data", {}) or {}
        except (hvac.exceptions.InvalidPath, Exception):
            return {}

    def _list(self, client, mount: str, path: str) -> dict:
        """List secret key names (values masked)."""
        data = self._read_all(client, mount, path)
        secrets = [{"key": k, "has_value": bool(data[k])} for k in sorted(data.keys())]
        return {"ok": True, "secrets": secrets}

    def _get(self, client, mount: str, path: str, key: str) -> dict:
        """Read a single secret value (for reveal)."""
        if not key:
            return {"ok": False, "error": "Key is required"}
        data = self._read_all(client, mount, path)
        if key not in data:
            return {"ok": False, "error": f"Key not found: {key}"}
        return {"ok": True, "key": key, "value": data[key]}

    def _set(self, client, mount: str, path: str, pairs: list) -> dict:
        """Write key-value pairs (read-modify-write to preserve existing)."""
        if not pairs:
            return {"ok": False, "error": "No key-value pairs provided"}
        current = self._read_all(client, mount, path)
        for pair in pairs:
            k = pair.get("key", "").strip()
            v = pair.get("value", "")
            if k:
                current[k] = v
        client.secrets.kv.v2.create_or_update_secret(
            path=path, secret=current, mount_point=mount
        )
        return {"ok": True, "message": f"Saved {len(pairs)} secret(s)"}

    def _delete(self, client, mount: str, path: str, key: str) -> dict:
        """Delete a key (read-modify-write)."""
        if not key:
            return {"ok": False, "error": "Key is required"}
        data = self._read_all(client, mount, path)
        if key not in data:
            return {"ok": False, "error": f"Key not found: {key}"}
        del data[key]
        client.secrets.kv.v2.create_or_update_secret(
            path=path, secret=data, mount_point=mount
        )
        return {"ok": True, "message": f"Deleted: {key}"}

    def _bulk_set(self, client, mount: str, path: str, text: str) -> dict:
        """Parse KEY=VALUE pairs from text (one per line) and write to OpenBao."""
        if not text or not text.strip():
            return {"ok": False, "error": "No text provided"}
        pairs = []
        errors = []
        for i, line in enumerate(text.strip().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                errors.append(f"Line {i}: no ‘=’ found")
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if not key:
                errors.append(f"Line {i}: empty key")
                continue
            pairs.append({"key": key, "value": value})
        if errors:
            return {"ok": False, "error": "Parse errors: " + "; ".join(errors)}
        if not pairs:
            return {"ok": False, "error": "No valid KEY=VALUE pairs found"}
        return self._set(client, mount, path, pairs)
