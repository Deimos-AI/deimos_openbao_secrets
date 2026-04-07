# Extension Hooks Reference

The plugin registers extensions at these Agent Zero hook points:

## Agent Initialization Hooks

| Hook Point | File | Purpose |
|-----------|------|---------|
| `agent_init` (priority 05) | `_05_openbao_secrets_resolver.py` | **Surface C** — Hooks `get_secrets_manager()`, returns `OpenBaoSecretsManager` as the primary `§§secret()` backend |
| `agent_init` (priority 10) | `_10_start_auth_proxy.py` | **Layer 1** — Starts embedded auth proxy, sets LLM provider env vars to `proxy-a0` sentinel |
| `agent_init` (priority 20) | `_20_openbao_mcp_header_resolver.py` | **Surface B** — Resolves `[bao-ref:REDACTED]` placeholders in MCP headers at HTTP transport time |

## Plugin Config Hooks

| Hook Point | File | Purpose |
|-----------|------|---------|
| `plugin_config` (priority 10) | `_10_openbao_plugin_config.py` | **Surface A** — Intercepts `save_plugin_config` / `get_plugin_config`. Extracts matched secret fields to OpenBao on save; resolves placeholders on read |

## Tool Execution Hooks

| Hook Point | File | Purpose |
|-----------|------|---------|
| `tool_execute_before` (priority 05) | `_05_openbao_shell_transform.py` | **Layer 2** — Resolves `⟦bao:KEY⟧` placeholders before shell commands execute. Hard error on unresolved placeholder — never passed to shell. |
| `tool_execute_before` (priority 15) | `_15_inject_terminal_secrets.py` | Injects resolved secret values into the terminal subprocess environment |
| `tool_execute_after` (priority 10) | `_10_openbao_mcp_scan.py` | **Surface B** — Scans `mcp_servers.json` on write; extracts auth headers to OpenBao with atomic rollback |
| `tool_execute_after` (priority 15) | `_15_cleanup_terminal_secrets.py` | Strips injected terminal secrets after command completes |

## History & Output Hooks

| Hook Point | File | Purpose |
|-----------|------|---------|
| `hist_add_before` (priority 10) | `_10_openbao_mask_history.py` | **Layer 3** — Scans every message before LLM history; replaces known secret values AND bao placeholder tokens with redacted aliases |
| `tool_output_update` (priority 10) | `_10_openbao_mask_output.py` | **Layer 3** — Masks secret values in tool output before LLM sees it |

## Factory Function Hooks

| Hook Point | File | Purpose |
|-----------|------|---------|
| `get_secrets_manager` | `_10_openbao_factory.py` | Returns singleton `OpenBaoSecretsManager` via `factory_common.get_openbao_manager()` |
| `get_default_secrets_manager` | `_10_openbao_default_factory.py` | Returns singleton default secrets manager |
| `get_project_secrets_manager` | `_10_openbao_project_factory.py` | Returns project-scoped secrets manager with PSK two-tier resolution |
| `get_api_key` | `_10_openbao_api_key.py` | Round-robin API key resolution from OpenBao |
