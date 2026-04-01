"""OpenBao factory extension for agent runtime secret access.

Intercepts get_secrets_manager() via @extensible to return
OpenBaoSecretsManager when OpenBao is configured and available.
"""
import importlib.util
import logging
import os
import sys

from helpers.extension import Extension

logger = logging.getLogger(__name__)

# Unique sys.modules key — must NOT start with 'helpers.' to avoid
# collision with A0's real helpers/ package on disk.
_FACTORY_LOADER_MODULE = "deimos_openbao_secrets_factory_loader"


def _get_openbao_manager():
    """Dynamically load and delegate to factory_loader._get_openbao_manager().

    Uses a unique module name to avoid collision with A0's helpers/ package.
    sys.modules caching means factory_loader.py is only executed once.
    """
    if _FACTORY_LOADER_MODULE not in sys.modules:
        from helpers.plugins import find_plugin_dir  # A0's real helpers.plugins — OK
        plugin_dir = find_plugin_dir("deimos_openbao_secrets")
        if not plugin_dir:
            return None
        fl_path = os.path.join(plugin_dir, "helpers", "factory_loader.py")
        if not os.path.exists(fl_path):
            return None
        spec = importlib.util.spec_from_file_location(_FACTORY_LOADER_MODULE, fl_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_FACTORY_LOADER_MODULE] = mod  # register before exec to handle circular imports
        spec.loader.exec_module(mod)
    return sys.modules[_FACTORY_LOADER_MODULE]._get_openbao_manager()


class OpenBaoFactory(Extension):
    """Replace default SecretsManager with OpenBao-backed manager.

    This extension is sync-only (get_secrets_manager is sync).
    self.agent may be None since the function receives AgentContext, not Agent.
    """

    def execute(self, **kwargs) -> None:
        data = kwargs.get("data", {})

        try:
            manager = _get_openbao_manager()
            if manager is not None:
                data["result"] = manager  # Short-circuit the original function
        except Exception as exc:
            logger.debug("OpenBao factory extension skipped: %s", exc)
