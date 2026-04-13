"""OpenBao factory extension for framework settings secret access.

Intercepts get_default_secrets_manager() via @extensible to return
OpenBaoSecretsManager when OpenBao is configured and available.

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


class OpenBaoDefaultFactory(Extension):
    """Replace default SecretsManager with OpenBao-backed manager.

    This extension is sync-only (get_default_secrets_manager is sync).
    self.agent may be None since the function receives AgentContext, not Agent.
    """

    def execute(self, **kwargs) -> None:
        data = kwargs.get("data", {})

        try:
            manager = _load_openbao_manager()
            if manager is not None:
                data["result"] = manager  # Short-circuit the original function
        except Exception as exc:
            logger.debug("OpenBao factory extension skipped: %s", exc)
