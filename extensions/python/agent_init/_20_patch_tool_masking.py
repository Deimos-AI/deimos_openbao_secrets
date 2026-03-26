"""Patch Tool class to mask secrets in all output channels.

Applies three patches to helpers.tool.Tool at agent_init time:

1. set_progress() — sync-safe hybrid: masks immediately, returns awaitable noop
   Fixes: code_execution_tool.py calling set_progress() without await

2. before_execution() — builds masked_args BEFORE get_log_object()
   Fixes: raw secrets stored in log object kvps and shown in chat window preview

3. get_log_object() — accepts optional kvps param
   Supports: before_execution passing pre-masked kvps

Portability:
   Works on any A0 instance with this plugin enabled.
   No framework changes required.
   Defence-in-depth alongside tool_output_update hook.
"""
from helpers.extension import Extension, call_extensions_async
import inspect
import logging

logger = logging.getLogger(__name__)


class PatchToolMasking(Extension):

    def execute(self, **kwargs):
        if not self.agent:
            return
        try:
            from helpers.tool import Tool
            from helpers.print_style import PrintStyle

            # ── 1. set_progress — sync-safe hybrid ──────────────────────────
            def _masked_set_progress(tool_self, content: str | None):
                content = content or ""
                try:
                    from helpers.secrets import get_secrets_manager
                    secrets_mgr = get_secrets_manager(tool_self.agent.context)
                    content = secrets_mgr.mask_values(content)
                except Exception as e:
                    logger.debug(f"set_progress masking skipped: {e}")
                tool_self.progress = content

                async def _noop():
                    pass

                return _noop()

            # ── 2. get_log_object — accepts optional kvps param ──────────────
            def _get_log_object(tool_self, kvps=None):
                if tool_self.method:
                    heading = f"icon://construction {tool_self.agent.agent_name}: Using tool '{tool_self.name}:{tool_self.method}'"
                else:
                    heading = f"icon://construction {tool_self.agent.agent_name}: Using tool '{tool_self.name}'"
                effective_kvps = kvps if kvps is not None else tool_self.args
                return tool_self.agent.context.log.log(
                    type="tool",
                    heading=heading,
                    content="",
                    kvps=effective_kvps,
                    _tool_name=tool_self.name
                )

            # ── 3. before_execution — masked_args before log object ──────────
            async def _before_execution(tool_self, **bkwargs):
                PrintStyle(
                    font_color="#1B4F72", padding=True,
                    background_color="white", bold=True
                ).print(f"{tool_self.agent.agent_name}: Using tool '{tool_self.name}'")

                # Build masked args BEFORE creating log object
                masked_args = {}
                if tool_self.args and isinstance(tool_self.args, dict):
                    for key, value in tool_self.args.items():
                        ctx = {"content": str(value) if not isinstance(value, str) else value}
                        await call_extensions_async("tool_output_update", tool_self.agent, ctx=ctx)
                        masked_args[key] = ctx["content"]

                # Call get_log_object with kvps if the method accepts it.
                # Tool subclasses (e.g. CodeExecution, input.py) may override
                # get_log_object(self) without a kvps parameter — use inspect
                # to detect this and fall back gracefully.
                _log_sig = inspect.signature(tool_self.get_log_object)
                if 'kvps' in _log_sig.parameters:
                    tool_self.log = tool_self.get_log_object(kvps=masked_args)
                else:
                    tool_self.log = tool_self.get_log_object()

                for key, display_value in masked_args.items():
                    orig_value = tool_self.args[key]
                    PrintStyle(font_color="#85C1E9", bold=True).stream(tool_self.nice_key(key) + ": ")
                    PrintStyle(
                        font_color="#85C1E9",
                        padding=isinstance(orig_value, str) and "\n" in orig_value
                    ).stream(display_value)
                    PrintStyle().print()

            # ── Apply patches ────────────────────────────────────────────────
            Tool.set_progress = _masked_set_progress
            Tool.get_log_object = _get_log_object
            Tool.before_execution = _before_execution
            logger.info("Patched Tool.set_progress, get_log_object, before_execution for secrets masking")

        except Exception as e:
            logger.error(f"Failed to patch Tool for secrets masking: {e}")
