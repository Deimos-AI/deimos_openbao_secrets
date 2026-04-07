# Configuration Reference

All fields are defined in `default_config.yaml` and may be overridden in the per-project `config.json`.
Environment variables take priority over `config.json` values where noted.

## Core Settings

| Field | Default | Env Var | Description |
|-------|---------|---------|-------------|
| `enabled` | `false` | — | Enable the OpenBao backend |
| `url` | `http://127.0.0.1:8200` | — | OpenBao server URL. **Use `https://` in production.** |
| `auth_method` | `token` | — | Authentication method: `token` or `approle` |
| `mount_point` | `secret` | — | KV v2 mount point |
| `secrets_path` | `agentzero` | — | Path within the KV v2 mount |

## TLS Settings

| Field | Default | Description |
|-------|---------|-------------|
| `tls_verify` | `true` | Verify TLS certificates |
| `tls_ca_cert` | `""` | Path to CA certificate bundle |

## Connection & Resilience

| Field | Default | Description |
|-------|---------|-------------|
| `timeout` | `10.0` | HTTP timeout in seconds |
| `cache_ttl` | `300` | Secret cache time-to-live in seconds. Rotated secrets may be stale for up to this duration. |
| `retry_attempts` | `3` | Max retry attempts (tenacity) |
| `circuit_breaker_threshold` | `5` | Consecutive failures before circuit opens |
| `circuit_breaker_recovery` | `60` | Circuit breaker recovery window in seconds |

## Failover Behaviour

| Field | Default | Description |
|-------|---------|-------------|
| `fallback_to_env` | `true` | Allow graceful degradation to `.env` when OpenBao is unavailable |
| `hard_fail_on_unavailable` | `true` | `true` = raise `OpenBaoUnavailableError` (default); `false` = graceful `.env` fallback |

> **Important:** `hard_fail_on_unavailable=true` (default) takes precedence over `fallback_to_env`. To enable graceful `.env` fallback, set `hard_fail_on_unavailable=false`.

## Namespace & Token

| Field | Default | Description |
|-------|---------|-------------|
| `vault_namespace` | `""` | OpenBao 2.5.x OSS namespace. Empty string = root namespace. |
| `vault_token_file` | `""` | Bootstrap token file path. Preferred over inline `vault_token` for production. |

## Surface A — Plugin Config Interception

| Field | Default | Description |
|-------|---------|-------------|
| `secret_field_patterns` | `["*key*", "*token*", "*secret*", "*password*", "*auth*"]` | fnmatch patterns matched against plugin config dict keys (case-insensitive). Matched fields containing string values are extracted to OpenBao on save. |

## Surface B — MCP Header Scanning

| Field | Default | Description |
|-------|---------|-------------|
| `mcp_header_scan_patterns` | `["Authorization", "X-API-Key", "X-Auth-Token"]` | Header keys in `mcpServers[*].headers` matching these names are extracted to OpenBao |
| `mcp_scan_paths` | `["**/mcp_servers.json", "**/.a0proj/mcp_servers.json"]` | Explicit MCP file scan targets (must be explicit paths, not wildcards) |

## Cross-Plugin Discovery

| Field | Default | Description |
|-------|---------|-------------|
| `plugin_sync_enabled` | `true` | Enable the `sync-plugins` endpoint for cross-plugin secret discovery. Set `false` in hardened environments. |

## Terminal Secrets Injection

| Field | Default | Description |
|-------|---------|-------------|
| `terminal_secrets` | `["API_KEY_ZAI_CODING", "API_KEY_OPENAI", ...]` | List of secret keys to inject into `os.environ` before `code_execution_tool` runs. Agents can then reference these as `os.environ["KEY"]` (Python), `process.env.KEY` (Node.js), or `$KEY` (terminal). Add any secret name from the OpenBao `secrets_path` here. |

Default value (from `default_config.yaml`):

```yaml
terminal_secrets:
  - API_KEY_ZAI_CODING
  - API_KEY_OPENAI
  - API_KEY_OPENROUTER
  - OPENROUTER_API_KEY
  - API_KEY_A0_VENICE
  - API_KEY_STRAICO
  - GH_TOKEN
  - GITEA_TOKEN
  - OPENPROJECT_API_KEY
```

## Bootstrap — Secrets Registry

| Field | Default | Env Var | Description |
|-------|---------|---------|-------------|
| `registry_path` | `""` | `OPENBAO_REGISTRY_PATH` | Path to the secrets registry YAML file. Empty = auto-derive from project root. |
| `env_scan_root` | `"/a0"` | — | Filesystem root for `.env` file scan during bootstrap (env_scan source). |

## Authentication

### Token Auth (Default)

The simplest method. Provide a Vault/OpenBao token via one of the bootstrap methods below.

```json
{
  "auth_method": "token",
  "vault_token_file": "/run/secrets/vault_token"
}
```

### AppRole Auth (Recommended for Production)

AppRole is the recommended auth method for production. The session token is held in memory only
and renewed automatically. No static token is stored on disk.

#### Vault-Side Setup (one-time)

```bash
# Enable AppRole
vault auth enable approle

# Create policy
vault policy write agentzero-policy - <<EOF
path "secret/data/agentzero" { capabilities = ["read"] }
path "secret/data/agentzero-*" { capabilities = ["read"] }
EOF

# Create role
vault write auth/approle/role/agentzero     token_policies="agentzero-policy"     token_ttl=1h     token_max_ttl=4h

# Get role_id (non-sensitive — safe in config or env)
vault read auth/approle/role/agentzero/role-id

# Get secret_id (sensitive — put in env var, never in repo)
vault write -f auth/approle/role/agentzero/secret-id
```

#### Plugin Configuration

```json
{ "auth_method": "approle" }
```

Set credentials via environment (recommended) or plugin settings UI:

| Credential | Env Var | config.json key | Sensitive? |
|-----------|---------|-----------------|------------|
| role_id | `OPENBAO_ROLE_ID` (overrides) | `role_id` (written by UI) | No |
| secret_id | `OPENBAO_SECRET_ID` | never stored as value | Yes |

Env vars take priority over config.json values.
Token is held in memory only and renewed automatically via the existing renewal loop.

### Bootstrap Credentials

Order of precedence for `vault_token`:

1. **Docker secrets mount:** `/run/secrets/vault_token` (preferred for production)
2. **`vault_token_file` config field:** path to `chmod 600` file
3. **Inline `vault_token` in `config.json`** (development only)

> `vault_token` is **NEVER** read from `os.environ`.
