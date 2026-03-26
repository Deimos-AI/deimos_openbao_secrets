"""Mask secret values from all tool output before display/logging.

Subscribes to the tool_output_update extension point (added in tool.py)
to intercept and mask any known secret values before they reach any
output channel: PrintStyle.stream, set_progress, log.update.

This is the openbao plugin's contribution to Solution D (issue #16).
"""
from helpers.extension import Extension
from helpers.secrets import get_secrets_manager
import logging

logger = logging.getLogger(__name__)


class MaskToolOutputSecrets(Extension):

    async def execute(self, ctx: dict | None = None, **kwargs):
        if not self.agent or not ctx:
            return
        content = ctx.get("content", "")
        if not content:
            return
        try:
            secrets_mgr = get_secrets_manager(self.agent.context)
            ctx["content"] = secrets_mgr.mask_values(content)
        except Exception as e:
            logger.debug(f"Secret masking in tool output skipped: {e}")
