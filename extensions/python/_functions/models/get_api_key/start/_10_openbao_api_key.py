"""OpenBao extension for API key resolution.

Intercepts models.get_api_key() via @extensible to resolve API keys
from OpenBao KV v2 before falling through to the default os.getenv()
lookup.

Extension point: _functions/models/get_api_key/start
Priority: 10 (runs before any higher-numbered extensions)

REM-020-fix: uses importlib.util absolute-path loading for factory_loader
to avoid helpers namespace collision with A0's own helpers package.
"""
import logging
from helpers.extension import Extension

logger = logging.getLogger(__name__)

_FL_MODULE_NAME = "openbao_secrets_factory_loader"


def _load_openbao_manager():
    """Load factory_loader via importlib absolute path and return manager.

    Uses importlib.util.spec_from_file_location so the plugin's helpers/
    subpackage is found by absolute path rather than via the A0 helpers
    namespace (which has no factory_loader). sys.modules caching prevents
    re-execution on repeated calls (singleton safety).

    REM-020-fix: restores the dynamic loader removed in REM-020.
    """
    import importlib.util
    import os
    import sys
    from helpers.plugins import find_plugin_dir  # A0 helpers.plugins — always resolvable

    if _FL_MODULE_NAME in sys.modules:
        return sys.modules[_FL_MODULE_NAME].get_openbao_manager()

    plugin_dir = find_plugin_dir("deimos_openbao_secrets")
    if not plugin_dir:
        return None

    fl_path = os.path.join(plugin_dir, "openbao_helpers", "factory_loader.py")
    if not os.path.exists(fl_path):
        return None

    spec = importlib.util.spec_from_file_location(_FL_MODULE_NAME, fl_path)
    fl_mod = importlib.util.module_from_spec(spec)
    sys.modules[_FL_MODULE_NAME] = fl_mod  # cache before exec — circular import safety
    spec.loader.exec_module(fl_mod)
    return fl_mod.get_openbao_manager()


class OpenBaoApiKey(Extension):
    """Resolve API keys from OpenBao secrets backend.

    When OpenBao is configured and contains the requested key,
    short-circuits the default dotenv lookup by setting data["result"].

    Falls through silently when:
    - OpenBao plugin is not configured/available
    - The requested key is not in OpenBao
    - Any error occurs during lookup
    """

    def execute(self, **kwargs) -> None:
        data = kwargs.get("data", {})

        try:
            manager = _load_openbao_manager()
            if manager is None:
                return  # No OpenBao — fall through to dotenv

            # Extract the service name from args
            args = data.get("args", ())
            if not args:
                return
            service = args[0]
            if not service:
                return

            # Load secrets and look up the API key
            # Match the same lookup patterns as models.get_api_key()
            secrets = manager.load_secrets()
            if not secrets:
                return

            service_upper = service.upper()
            key = (
                secrets.get(f"API_KEY_{service_upper}")
                or secrets.get(f"{service_upper}_API_KEY")
                or secrets.get(f"{service_upper}_API_TOKEN")
            )

            if key and key not in ("None", "NA", ""):
                # Handle comma-separated round-robin keys
                if "," in key:
                    import models
                    api_keys = [k.strip() for k in key.split(",") if k.strip()]
                    models.api_keys_round_robin[service] = (
                        models.api_keys_round_robin.get(service, -1) + 1
                    )
                    key = api_keys[
                        models.api_keys_round_robin[service] % len(api_keys)
                    ]

                data["result"] = key
                logger.debug(
                    "OpenBao resolved API key for service '%s'.",
                    service,
                )

        except Exception as exc:
            logger.debug("OpenBao API key extension skipped: %s", exc)
