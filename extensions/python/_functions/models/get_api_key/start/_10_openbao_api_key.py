"""OpenBao extension for API key resolution.

Intercepts models.get_api_key() via @extensible to resolve API keys
from OpenBao KV v2 before falling through to the default os.getenv()
lookup.

Extension point: _functions/models/get_api_key/start
Priority: 10 (runs before any higher-numbered extensions)
"""
import logging

from helpers.extension import Extension
from helpers.factory_loader import _get_openbao_manager

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
            manager = _get_openbao_manager()
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
