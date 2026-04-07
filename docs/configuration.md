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


## Headless / Docker Configuration

All plugin settings can be provided entirely through `OPENBAO_*` environment variables,
making it possible to run Agent Zero with the OpenBao plugin in fully headless mode —
no Web UI interaction required. This is the recommended approach for Docker, Kubernetes,
and CI deployments.

### Priority Chain

```
Environment variables (OPENBAO_*)  >  config.json  >  dataclass defaults
```

Environment variables always take the highest priority and override any values in
`config.json`. If neither source provides a value, the dataclass default is used.

### Complete Environment Variable Reference

| Env Var | Field | Type | Default | Description |
|---------|-------|------|---------|-------------|
| `OPENBAO_ENABLED` | `enabled` | bool | `false` | Enable the OpenBao backend |
| `OPENBAO_URL` | `url` | str | `http://127.0.0.1:8200` | OpenBao server URL |
| `OPENBAO_AUTH_METHOD` | `auth_method` | str | `token` | Auth method: `token` or `approle` |
| `OPENBAO_ROLE_ID` | `role_id` | str | `""` | AppRole role ID |
| `OPENBAO_SECRET_ID` | `secret_id` | str | `""` | AppRole secret ID |
| `OPENBAO_SECRET_ID_ENV` | `secret_id_env` | str | `OPENBAO_SECRET_ID` | Name of the env var holding the secret_id (see note below) |
| `OPENBAO_SECRET_ID_FILE` | `secret_id_file` | str | `""` | Path to a file containing the secret_id (see note below) |
| `OPENBAO_TOKEN` | `token` | str | `""` | Direct auth token |
| `OPENBAO_MOUNT_POINT` | `mount_point` | str | `secret` | KV v2 mount point |
| `OPENBAO_SECRETS_PATH` | `secrets_path` | str | `agentzero` | Path within the KV v2 mount |
| `OPENBAO_PROJECT_TEMPLATE` | `vault_project_template` | str | `agentzero-{project_slug}` | Vault path template for project-scoped secrets |
| `OPENBAO_TLS_VERIFY` | `tls_verify` | bool | `true` | Verify TLS certificates |
| `OPENBAO_TLS_CA_CERT` | `tls_ca_cert` | str | `""` | Path to CA certificate bundle |
| `OPENBAO_TIMEOUT` | `timeout` | float | `10.0` | HTTP request timeout (seconds) |
| `OPENBAO_CACHE_TTL` | `cache_ttl` | int | `300` | Secret cache TTL (seconds) |
| `OPENBAO_RETRY_ATTEMPTS` | `retry_attempts` | int | `3` | Max retry attempts |
| `OPENBAO_CB_THRESHOLD` | `circuit_breaker_threshold` | int | `5` | Failures before circuit opens |
| `OPENBAO_CB_RECOVERY` | `circuit_breaker_recovery` | int | `60` | Circuit breaker recovery window (seconds) |
| `OPENBAO_FALLBACK_TO_ENV` | `fallback_to_env` | bool | `true` | Allow `.env` fallback when OpenBao unavailable |
| `OPENBAO_HARD_FAIL_ON_UNAVAILABLE` | `hard_fail_on_unavailable` | bool | `true` | Raise error on unavailability (overrides `fallback_to_env`) |
| `OPENBAO_VAULT_NAMESPACE` | `vault_namespace` | str | `""` | OpenBao namespace (empty = root) |
| `OPENBAO_VAULT_TOKEN_FILE` | `vault_token_file` | str | `""` | Bootstrap token file path |
| `OPENBAO_REGISTRY_PATH` | `registry_path` | str | `""` | Secrets registry YAML path |

### Docker Compose Example

```yaml
version: "3.8"

services:
  openbao:
    image: ghcr.io/openbao/openbao:2.5
    ports:
      - "8200:8200"
    cap_add:
      - IPC_LOCK
    volumes:
      - openbao-data:/data

  agent-zero:
    image: agent-zero:latest
    depends_on:
      - openbao
    environment:
      # --- OpenBao Plugin (headless config) ---
      OPENBAO_ENABLED: "true"
      OPENBAO_URL: "http://openbao:8200"
      OPENBAO_AUTH_METHOD: approle
      OPENBAO_ROLE_ID: "${OPENBAO_ROLE_ID}"
      OPENBAO_SECRET_ID_FILE: "/run/secrets/openbao_secret_id"
      OPENBAO_MOUNT_POINT: secret
      OPENBAO_SECRETS_PATH: agentzero
      OPENBAO_TLS_VERIFY: "false"
      OPENBAO_HARD_FAIL_ON_UNAVAILABLE: "false"
    secrets:
      - openbao_secret_id
    volumes:
      - ./plugins:/app/usr/plugins

secrets:
  openbao_secret_id:
    file: ./secrets/openbao_secret_id.txt

volumes:
  openbao-data:
```

### Notes on `secret_id_env` and `secret_id_file`

These two fields provide flexibility for providing the AppRole `secret_id` in
containerised environments where direct environment variables may not be ideal:

- **`OPENBAO_SECRET_ID_ENV`** — Customise which environment variable name holds the
  `secret_id`. Defaults to `OPENBAO_SECRET_ID`. Use this when your orchestration
  platform injects credentials under a different variable name (e.g.
  `OPENBAO_SECRET_ID_ENV=MY_PLATFORM_SECRET` tells the plugin to read
  `os.environ["MY_PLATFORM_SECRET"]`).

- **`OPENBAO_SECRET_ID_FILE`** — Read the `secret_id` from a file path instead of an
  environment variable. This is the recommended approach for Docker Swarm / Kubernetes
  secrets mounts. Set to a path like `/run/secrets/openbao_secret_id` and the plugin
  will read the file contents at authentication time. The file is read on every auth
  attempt (no caching), so rotating the mounted secret is picked up automatically.

The resolution order in `openbao_client.py` is:

```
config.secret_id  →  env var named by secret_id_env  →  file at secret_id_file
```

The first non-empty value wins.
> `vault_token` is **NEVER** read from `os.environ`.
