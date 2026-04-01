# OpenBao Secrets Plugin for Agent Zero

Replaces Agent Zero's default `.env`-based secrets management with [OpenBao](https://openbao.org/) KV v2 as the secrets backend.

## Status

**v0.1.0 — Replace Mode** (in development)

> **Dependency:** Requires upstream PRs merged into `agent0ai/agent-zero:development`:
> - [#1377](https://github.com/agent0ai/agent-zero/pull/1377) — `extra_env` + `tool` in `tool_execute` extensions
> - [#1379](https://github.com/agent0ai/agent-zero/pull/1379) — sidebar extension points
> - [#1394](https://github.com/agent0ai/agent-zero/pull/1394) — PR-A `hook_context`
> - [#1395](https://github.com/agent0ai/agent-zero/pull/1395) — PR-B+C `@extensible` on `set_settings` + `resolve_mcp_server_headers`

---

## Architecture — Four-Layer Secret Prevention

The plugin implements a defence-in-depth strategy across three intercepting layers and three credential surfaces.
Plaintext secrets **never** appear in `os.environ`, tool arguments, or LLM history.

| Layer | File | What it does |
|---|---|---|
| L1 — Proxy env | `helpers/auth_proxy.py` + `agent_init/_10_start_auth_proxy.py` | LLM provider env vars set to dummy `proxy-a0`. Real keys fetched from OpenBao and injected into outbound HTTP headers at proxy time — never in `os.environ` |
| L2 — Shell transform | `tool_execute_before/_05_openbao_shell_transform.py` | Before any shell command runs, replaces placeholder patterns so shell receives `$KEY_NAME` references resolved from a clean subprocess env |
| L3 — History mask | `hist_add_before/_10_openbao_mask_history.py` | Scans every message before LLM history; replaces known secret values AND bao placeholder tokens with redacted form |
| Surface A — Plugin config | `plugin_config/_10_openbao_plugin_config.py` | Intercepts `save_plugin_config` hook; extracts matched secret fields to OpenBao KV v2; replaces values with bao placeholders on disk |
| Surface B — MCP headers | `tool_execute_after/_10_openbao_mcp_scan.py` + `agent_init/_20_openbao_mcp_header_resolver.py` | Scans `mcp_servers.json` on write; extracts auth headers to OpenBao; resolves placeholders at HTTP transport time |
| Surface C — §§secret() | `agent_init/_05_openbao_secrets_resolver.py` | Hooks `get_secrets_manager()`; returns `OpenBaoSecretsManager` as primary backend; `.env` becomes fallback-only |

### Resilience Stack

| Pattern | Library | Purpose |
|---|---|---|
| Retry | `tenacity` | Exponential backoff + jitter for transient failures |
| Circuit Breaker | `circuitbreaker` | Fail-fast when OpenBao is down |
| TTL Cache | Built-in | Avoid per-request API calls |
| Timeout | `httpx` | Bounded HTTP operations |
| Token Renewal | `hvac` | Lazy renewal on 403 / near-expiry |

### Bootstrap Credentials

Order of precedence for `vault_token`:

1. **Docker secrets mount:** `/run/secrets/vault_token` (preferred for production)
2. **`vault_token_file` config field:** path to `chmod 600` file
3. **Inline `vault_token` in `config.json`** (development only)

> `vault_token` is **NEVER** read from `os.environ`.

---

## Configuration

All fields are defined in `default_config.yaml` and may be overridden in the per-project `config.json`.

| Field | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable the OpenBao backend |
| `url` | `http://127.0.0.1:8200` | OpenBao server URL |
| `auth_method` | `token` | Authentication method: `token` or `approle` |
| `mount_point` | `secret` | KV v2 mount point |
| `secrets_path` | `agentzero` | Path within the KV v2 mount |
| `tls_verify` | `true` | Verify TLS certificates |
| `tls_ca_cert` | `""` | Path to CA certificate bundle |
| `timeout` | `10.0` | HTTP timeout in seconds |
| `cache_ttl` | `300` | Secret cache time-to-live in seconds |
| `retry_attempts` | `3` | Max retry attempts (tenacity) |
| `circuit_breaker_threshold` | `5` | Consecutive failures before circuit opens |
| `circuit_breaker_recovery` | `60` | Circuit breaker recovery window in seconds |
| `fallback_to_env` | `true` | Fall back to `.env` on auth/transient failure |
| `fallback_to_env_on_error` | `false` | `false` = hard fail with `OpenBaoUnavailableError`; `true` = graceful `.env` fallback |
| `vault_namespace` | `""` | OpenBao 2.5.x OSS namespace — empty string = root namespace (default, backwards compatible) |
| `vault_token_file` | `""` | Bootstrap token file path (preferred over inline token for production). Falls back to inline `vault_token` config value if empty or file missing. |
| `secret_field_patterns` | `["*key*", "*token*", "*secret*", "*password*", "*auth*"]` | **Surface A** — fnmatch patterns matched against plugin config dict keys (case-insensitive). Matched fields containing string values are extracted to OpenBao on save. |
| `mcp_header_scan_patterns` | `["Authorization", "X-API-Key", "X-Auth-Token"]` | **Surface B** — Header keys in `mcpServers[*].headers` matching these names are extracted to OpenBao |
| `mcp_scan_paths` | `["**/mcp_servers.json", "**/.a0proj/mcp_servers.json"]` | **Surface B** — Explicit MCP file scan targets (never wildcards — must be explicit paths) |

---

## Failure Modes

| Scenario | Behaviour |
|---|---|
| OpenBao unreachable, `fallback_to_env_on_error=false` (default) | Hard fail: `OpenBaoUnavailableError` |
| OpenBao unreachable, `fallback_to_env_on_error=true` | Graceful fallback to `.env` |
| KV write fails during Surface B scan | Atomic rollback — original file unchanged; exception raised |
| `bao` placeholder in shell arg | Hard error — never silently passed to shell |
| MCP credential rotation needed | Click **Refresh MCP Credentials** in plugin settings, or `POST /api/plugins/deimos_openbao_secrets/rotate_mcp` |
| Namespace token expires | `OpenBaoUnavailableError` on next KV read |
| Plugin own config intercepted (bug) | Prevented by bootstrapping exclusion guard |

---

## Gotchas

1. **This plugin is an OpenBao CLIENT.** It never handles unseal keys. Configure auto-unseal at the OpenBao server level (AWS KMS, GCP CKMS, Azure Key Vault, or Transit auto-unseal).
2. **Unseal is per server instance** — all namespaces share the same seal state.
3. **`vault_token` is NEVER accepted from `os.environ`.** Use `vault_token_file` (Docker secrets mount at `/run/secrets/vault_token`) or inline config only.
4. **Namespaces require OpenBao 2.5.x+ OSS** (confirmed working). Set `vault_namespace` in per-project `config.json` for tenant isolation.
5. **The `⟦bao:…⟧` placeholder scheme** (Unicode brackets) is intentionally distinct from the `§§secret()` scheme to prevent interference with the framework's own unmask layer.
6. **MCP credential rotation** requires clicking **Refresh MCP Credentials** or calling the `rotate_mcp` endpoint — agent restart not required.
7. **If `.env` stores shell variable references** (e.g. `GITEA_TOKEN=$GITEA_TOKEN`), Surface C bypasses them and serves the real value from OpenBao directly.
8. **Do NOT use literal `⟦bao:…⟧` placeholder characters in `code_execution_tool` args** — the shell guard will raise `ValueError`. Use Unicode escapes in Python source if needed.

---

## OpenBao Target

| Parameter | Value |
|---|---|
| Version | v2.5.x OSS (namespace support confirmed) |
| Secrets Engine | KV v2 (versioned) |
| Auth Method | Token (primary), AppRole (alternative) |
| Python Client | `hvac` (Vault API-compatible) |
| Docker Image | `ghcr.io/openbao/openbao:2.5.x` |

## Project Structure

```
plugin.yaml                          # Plugin metadata
default_config.yaml                  # All configuration fields with defaults
requirements.txt                     # Python dependencies
hooks.py                             # Plugin lifecycle hooks
helpers/
  config.py                          # Configuration loading and validation
  openbao_client.py                  # Resilient hvac client wrapper
  openbao_secrets_manager.py         # SecretsManager subclass
  auth_proxy.py                      # Reverse proxy for LLM provider auth (L1)
  factory_common.py                  # Shared manager singleton factory
  deps.py                            # Auto-install dependencies
extensions/python/
  agent_init/
    _05_openbao_secrets_resolver.py      # Surface C — §§secret() OpenBao backend
    _10_start_auth_proxy.py              # L1 — start auth proxy, inject dummy env
    _20_openbao_mcp_header_resolver.py   # Surface B — resolve ⟦bao:⟧ at transport
  tool_execute_before/
    _05_openbao_shell_transform.py       # L2 — resolve placeholders before shell
  tool_execute_after/
    _10_openbao_mcp_scan.py              # Surface B — scan/vault MCP headers on write
  hist_add_before/
    _10_openbao_mask_history.py          # L3 — mask secrets + bao tokens from history
  plugin_config/
    _10_openbao_plugin_config.py         # Surface A — intercept plugin config saves
api/
  health.py                          # GET /health — liveness check
  rotate_mcp.py                      # POST /rotate_mcp — MCP credential rotation
  secrets.py                         # Secrets management API
webui/
  config.html                        # Plugin settings UI
tests/
  conftest.py                        # sys.modules bootstrap for bare-name imports
  test_config.py                     # Configuration unit tests (25 tests)
  test_openbao_client.py             # Client resilience tests (22 tests)
  test_openbao_manager.py            # Manager behaviour tests (20 tests)
  test_placeholder_mask.py           # Placeholder masking tests (5 tests)
  test_secret_surfaces.py            # Surface integration tests (3 tests)
  ci_secret_surface_scan.py          # CI scan — detect raw secret exposure
  verify_checks.py                   # Acceptance check runner
```

## Development

### Prerequisites

```bash
pip install hvac tenacity circuitbreaker aiohttp pytest
```

### Run Tests

```bash
pytest tests/ -v
```

## Issue Tracker

See [Gitea milestone v0.1.0](http://192.168.200.52:3000/deimosAI/a0-plugin-openbao-secrets/milestone/17) for all planned work.

## License

Apache 2.0
