"""OpenBao factory extension for framework settings secret access.

Intercepts get_default_secrets_manager() via @extensible to return OpenBaoSecretsManager
when OpenBao is configured and available.

See Issue #5: https://192.168.200.52:3000/deimosAI/a0-plugin-openbao-secrets/issues/5
"""
from python.helpers.extension import Extension


class OpenBaoDefaultFactory(Extension):
    """Replace default SecretsManager with OpenBao-backed manager.

    This extension is sync-only (the factory functions are sync).
    self.agent may be None since factory functions receive AgentContext, not Agent.
    """

    def execute(self, **kwargs) -> None:
        """Intercept factory call and optionally replace the result.

        Sets data["result"] to short-circuit the original function
        when OpenBao is configured and available.
        """
        # Implementation in Issue #5 — requires Issues #3 and #4 first
        pass
