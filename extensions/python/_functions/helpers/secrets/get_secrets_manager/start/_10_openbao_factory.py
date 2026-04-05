"""OpenBao factory extension for agent runtime secret access.

Intercepts get_secrets_manager() via @extensible to return
OpenBaoSecretsManager when OpenBao is configured and available.
"""
import logging
from helpers.extension import Extension

logger = logging.getLogger(__name__)


class OpenBaoFactory(Extension):
    """Replace default SecretsManager with OpenBao-backed manager.

    This extension is sync-only (get_secrets_manager is sync).
    self.agent may be None since the function receives AgentContext, not Agent.
    """

    def execute(self, **kwargs) -> None:
        data = kwargs.get("data", {})

        try:
            manager = self._get_openbao_manager()
            if manager is not None:
                data["result"] = manager  # Short-circuit the original function
        except Exception as exc:
            logger.debug("OpenBao factory extension skipped: %s", exc)

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
