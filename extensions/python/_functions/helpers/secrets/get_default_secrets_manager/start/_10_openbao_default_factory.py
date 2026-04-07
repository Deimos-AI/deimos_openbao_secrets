"""OpenBao factory extension for framework settings secret access.

Intercepts get_default_secrets_manager() via @extensible to return
OpenBaoSecretsManager when OpenBao is configured and available.
"""
import logging
from helpers.extension import Extension

logger = logging.getLogger(__name__)


class OpenBaoDefaultFactory(Extension):
    """Replace default SecretsManager with OpenBao-backed manager.

    This extension is sync-only (get_default_secrets_manager is sync).
    self.agent may be None since the function receives AgentContext, not Agent.
    """

    def execute(self, **kwargs) -> None:  # AC-02 (REM-020)
        data = kwargs.get("data", {})

        try:
            # AC-02: single source of truth via factory_loader
            from helpers.factory_loader import get_openbao_manager
            manager = get_openbao_manager()
            if manager is not None:
                data["result"] = manager  # Short-circuit the original function
        except Exception as exc:
            logger.debug("OpenBao factory extension skipped: %s", exc)
