# OpenBao Secrets Plugin for Agent Zero

[![Version](https://img.shields.io/badge/version-v0.9.0--beta-blue)](#) [![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE) [![Tests](https://img.shields.io/badge/tests-386%20passing-brightgreen)](#)

> **Upstream dependencies** — required PRs for `agent0ai/agent-zero:development`:
> - [#1377](https://github.com/agent0ai/agent-zero/pull/1377) — `extra_env` + `tool` in `tool_execute` extensions *(pending merge)*
> - [#1394](https://github.com/agent0ai/agent-zero/pull/1394) — `hook_context` in plugin config hooks *(pending merge)*
>
> **Already merged:**
> - ~~[#1379](https://github.com/agent0ai/agent-zero/pull/1379)~~ — sidebar extension points *(merged — commit `d357c24d`)*
> - ~~[#1395](https://github.com/agent0ai/agent-zero/pull/1395)~~ — `@extensible` on `set_settings` + `resolve_mcp_server_headers` *(merged — commit `d1196324`)*


## TL;DR

Replaces Agent Zero's default `.env`-based secrets management with [OpenBao](https://openbao.org/) (Vault-compatible) KV v2 as the authoritative secrets backend. Plaintext secrets never appear in `os.environ`, tool arguments, LLM history, or on-disk configuration. Designed for teams running self-hosted LLM infrastructure who need production-grade secret management.

## Features

- **Auth proxy** — LLM provider keys fetched from OpenBao at request time; only a `proxy-a0` sentinel in `os.environ`
- **3 credential surfaces** — plugin config (Surface A), MCP auth headers (Surface B), `§§secret()` framework (Surface C)
- **Automatic masking** — secrets stripped from LLM history and tool output before any model sees them
- **MCP scanning** — auto-discovers and vaults MCP server auth headers with atomic rollback
- **Project-scoped secrets** — per-project overrides via two-tier vault path hierarchy
- **Terminal injection** — resolved secrets injected into subprocess environments for shell commands
- **CAS protection** — KV v2 versioned storage prevents accidental overwrites
- **Resilience** — retry with exponential backoff, circuit breaker, TTL cache, bounded timeouts

## Quick Start

**Prerequisites:** Agent Zero with upstream `@extensible` hooks, OpenBao v2.5.x+ with KV v2, Python 3.11+

```bash
# 1. Clone into plugins directory
cd /path/to/agent-zero
mkdir -p usr/plugins
git clone http://your-gitea/deimosAI/deimos_openbao_secrets.git usr/plugins/deimos_openbao_secrets

# 2. Install dependencies
cd usr/plugins/deimos_openbao_secrets
pip install -r requirements.txt

# 3. Configure
cp config.json.example config.json
```

Edit `config.json` with your OpenBao server details:

```json
{
  "url": "https://vault.example.com:8200",
  "enabled": true,
  "auth_method": "token",
  "mount_point": "secret",
  "secrets_path": "agentzero"
}
```

Provision your vault token via Docker secrets (`/run/secrets/vault_token`) or `vault_token_file` — never inline in production.

```bash
# 4. Seed secrets
vault kv put secret/agentzero OPENAI_API_KEY="sk-..." GH_TOKEN="ghp_..."

# 5. Verify
curl -X POST http://localhost:5000/api/plugins/deimos_openbao_secrets/health \
  -H 'Content-Type: application/json' \
  -d '{"config": {"url": "https://vault.example.com:8200"}}'
```

Enable in UI: Settings → Plugins → Enable `deimos_openbao_secrets`.

## OpenBao Compatibility

| Parameter | Value |
|---|---|
| Version | v2.5.x OSS (namespace support confirmed) |
| Secrets Engine | KV v2 (versioned) |
| Auth Methods | Token (default), AppRole (production) |
| Python Client | `hvac` (Vault API-compatible) |
| Docker Image | `ghcr.io/openbao/openbao:2.5.x` |

Also compatible with HashiCorp Vault v1.15+.


## Architecture Overview

The plugin intercepts secrets at every stage of the agent lifecycle through three layers: an auth proxy that replaces `os.environ` keys with sentinels, a shell transform that resolves placeholders before command execution, and a history masker that strips secrets from LLM-visible context. Three credential surfaces (plugin config, MCP headers, framework secrets) are each handled by dedicated extension hooks. All secret values are stored in and retrieved from OpenBao KV v2.

→ **Full architecture with diagrams:** [docs/architecture.md](docs/architecture.md)

## Configuration Quick Ref

| Field | Default | Description |
|-------|---------|-------------|
| `url` | `http://127.0.0.1:8200` | OpenBao server URL |
| `auth_method` | `token` | `token` or `approle` |
| `mount_point` | `secret` | KV v2 mount point |
| `enabled` | `false` | Enable the OpenBao backend |
| `hard_fail_on_unavailable` | `true` | Raise error when OpenBao is down |
| `fallback_to_env` | `true` | Allow `.env` fallback (overridden by `hard_fail_on_unavailable`) |

→ **Full config reference including TLS, resilience, terminal secrets, AppRole auth:** [docs/configuration.md](docs/configuration.md)

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | Full architecture, layers, surfaces, data flow diagrams |
| [Configuration](docs/configuration.md) | Complete config reference + authentication methods |
| [API Reference](docs/api-reference.md) | All API endpoints with request/response schemas |
| [Extension Hooks](docs/extension-hooks.md) | Extension hooks reference (14 entry points) |
| [Secret Resolution](docs/secret-resolution.md) | Resolution paths, auth proxy, CAS, decision table |
| [Project-Scoped Secrets](docs/project-scoped-secrets.md) | Two-tier vault hierarchy and provisioning |
| [Security Model](docs/security-model.md) | Auth proxy, masking, SSRF guards, path sanitization |
| [Failure Modes](docs/failure-modes.md) | Failure scenarios and recovery guidance |
| [Gotchas](docs/gotchas.md) | Known gotchas and architectural limitations |
| [Upgrading](docs/upgrading.md) | Migration guide and breaking changes |
| [Development](docs/development.md) | Dev setup, test suite (386 tests), CI, contributing |

## License

Apache 2.0 — see [LICENSE](LICENSE) for details.
