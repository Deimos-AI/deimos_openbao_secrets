# API Endpoints

All endpoints are under `/api/plugins/deimos_openbao_secrets/` and require `POST` method.

## Health Check — `/health`

Tests connectivity and credentials against the configured OpenBao server using **only** the configured auth method.

**Request:**

```json
{
  "config": {
    "url": "https://vault.example.com:8200",
    "auth_method": "token",
    "vault_token": "s.xxxx"
  }
}
```

**Response (success):**

```json
{
  "ok": true,
  "message": "OpenBao connection successful",
  "version": "2.5.0"
}
```

**Response (failure):**

```json
{
  "ok": false,
  "error": "Connection refused at https://vault.example.com:8200"
}
```

> **SSRF protection:** URL parameters are validated for scheme (`http`/`https` only) and blocked hosts (`169.254.169.254`, `localhost`, `127.0.0.1`, `::1`, `metadata.google.internal`, and the entire `169.254.*` link-local range).

## Secrets CRUD — `/secrets`

Manage secrets stored in OpenBao KV v2. All operations are scoped by `mount_point` and `secrets_path` from config.

**Authentication:** `requires_auth = true` — session cookie required.

### List Keys

```json
{
  "action": "list",
  "project_name": ""
}
```

**Response:**

```json
{
  "ok": true,
  "keys": ["OPENAI_API_KEY", "GH_TOKEN", "LANGFUSE_PUBLIC_KEY"]
}
```

### Get Key Value

```json
{
  "action": "get",
  "key": "OPENAI_API_KEY",
  "project_name": ""
}
```

**Response:**

```json
{
  "ok": true,
  "key": "OPENAI_API_KEY",
  "value": "sk-..."
}
```

> **Warning:** This returns plaintext secret values. Ensure your Agent Zero instance is not exposed to untrusted networks.

### Set Key/Value Pairs

```json
{
  "action": "set",
  "pairs": [
    {"key": "NEW_API_KEY", "value": "sk-new-..."}
  ],
  "project_name": ""
}
```

### Delete Key

```json
{
  "action": "delete",
  "key": "OLD_API_KEY",
  "project_name": ""
}
```

### Bulk Set (dotenv format)

```json
{
  "action": "bulk_set",
  "text": "NEW_KEY=sk-new
ANOTHER_KEY=ghp-xxx",
  "project_name": ""
}
```

## MCP Credential Rotation — `/rotate_mcp`

Resolves all `[bao-ref:REDACTED]…⟧` placeholders in the running MCP configuration to live values from OpenBao, then forces MCP reconnection with fresh auth headers.

The `mcp_servers` setting on disk retains placeholder strings unchanged. Only the in-memory `MCPConfig` instance receives live credential values.

**Request:**

```json
{}
```

**Response (success):**

```json
{
  "ok": true,
  "resolved_count": 3,
  "message": "MCP credentials rotated successfully"
}
```

## Cross-Plugin Sync — `/secrets` (action: `sync_plugins`)

Discovers secrets declared by other plugins (via their `plugin.yaml` `secrets:` field) and syncs values from `.env` to OpenBao. Enabled only when `plugin_sync_enabled: true`.

## Bootstrap — `/bootstrap`

First-install secrets registry bootstrap endpoint. Scans the filesystem for declared and discovered secrets, builds a registry, and provides status information.

**Source:** `api/bootstrap.py` (REM-017)

**CSRF:** `requires_csrf = false`

### Status Action

Returns whether the secrets registry exists and how many entries it contains.

**Request:**

```json
{
  "action": "status"
}
```

**Response:**

```json
{
  "ok": true,
  "bootstrap_needed": true,
  "registry_path": "/a0/usr/projects/my-project/.a0proj/secrets-registry.yaml",
  "entry_count": 0
}
```

### Scan Action

Runs all three scan sources (`.env` files, `.a0proj` directories, MCP server configs), deduplicates results, and optionally writes the registry file.

**Scan sources:**

| Source | What it scans | Config key |
|--------|--------------|------------|
| `env_scan` | `.env` files under `env_scan_root` (default `/a0`) | `env_scan_root` |
| `a0proj_scan` | `.a0proj/` directories for project configs | `a0proj_search_roots` |
| `mcp_scan` | MCP server JSON files for auth headers | `mcp_scan_paths` |

**Request:**

```json
{
  "action": "scan"
}
```

**Response (success):**

```json
{
  "ok": true,
  "entries": [
    {
      "id": "env:dotenv:API_KEY_OPENAI",
      "source": "env",
      "context": ".env",
      "key": "API_KEY_OPENAI",
      "status": "discovered"
    }
  ],
  "total": 5,
  "written": true
}
```

**Dry-run mode:** Set `"dry_run": true` in the request to scan without writing the registry file.
