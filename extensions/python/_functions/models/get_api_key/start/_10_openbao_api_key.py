"""OpenBao extension for API key resolution.

Intercepts models.get_api_key() via @extensible to resolve API keys
from OpenBao KV v2 before falling through to the default os.getenv()
lookup.

Extension point: _functions/models/get_api_key/start
Priority: 10 (runs before any higher-numbered extensions)
"""
import logging
from helpers.extension import Extension

logger = logging.getLogger(__name__)


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
            manager = self._get_openbao_manager()
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

    def _get_openbao_manager(self):
        """Lazily load and return the OpenBao manager singleton."""
        import importlib.util
        import os
        import sys
        from helpers.plugins import find_plugin_dir

        _FC_MODULE_NAME = "openbao_secrets_factory_common"

        # Use cached module if already loaded — prevents re-exec and singleton reset
        if _FC_MODULE_NAME in sys.modules:
            return sys.modules[_FC_MODULE_NAME].get_openbao_manager()

        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            return None

        fc_path = os.path.join(plugin_dir, "helpers", "factory_common.py")
        if not os.path.exists(fc_path):
            return None

        spec = importlib.util.spec_from_file_location(_FC_MODULE_NAME, fc_path)
        fc_mod = importlib.util.module_from_spec(spec)
        sys.modules[_FC_MODULE_NAME] = fc_mod  # cache before exec to handle circular imports
        spec.loader.exec_module(fc_mod)

        return fc_mod.get_openbao_manager()
