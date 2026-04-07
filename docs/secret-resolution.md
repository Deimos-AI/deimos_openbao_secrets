# Secret Resolution

The plugin exposes **two distinct secret resolution paths** with different
semantics. Choosing the wrong path causes silent authentication failures.

## Path A — `§§secret()` aliases (LLM API calls only)

When the plugin starts, `_inject_proxy_env()` sets only LLM API key environment
variables — `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY` — to the
sentinel value `proxy-a0`. Other credentials such as `GH_TOKEN` are **not** set by
the proxy and must be retrieved via `resolve_secret()` (see REM-004). An embedded
auth-proxy at `127.0.0.1:{port}` intercepts outbound LLM API calls and transparently
replaces the sentinel with the real token from OpenBao at request time.

**This path only works for LLM API calls routed through the auth proxy.**
Git push, GitHub REST API, curl, and any other direct HTTP will receive
`proxy-a0` as the credential and fail authentication silently.

## Path B — `resolve_secret()` (git, HTTP APIs, direct tool use)

For **any context that is not an LLM API call**, use `resolve_secret()`:

```python
from deimos_openbao_secrets import resolve_secret

# Resolve a global secret -- always returns the real value
gh_token = resolve_secret("GH_TOKEN")
# => "gho_trcd..."  (real 40-char token, never "proxy-a0")

# Resolve with PSK project-specific override
lf_key = resolve_secret("LANGFUSE_PUBLIC_KEY", project_slug="my-project")
# => project-scoped value if present in vault, global value otherwise
```

**Resolution order:**

1. **OpenBao** — `get_openbao_manager().get_secret(key, project_slug)`
   - `project_slug` provided: project vault path checked first (PSK two-tier).
   - `proxy-a0` sentinel treated as absent (never returned).
2. **`os.environ`** — `.env` fallback when OpenBao is unavailable.
   - `proxy-a0` sentinel treated as absent (never returned).
3. **`None`** — key absent from all backends.

**Decision table:**

| Caller context | Correct path |
|---|---|
| LLM API call (OpenAI, Anthropic, OpenRouter) | `§§secret()` alias |
| `git push` / `git clone` over HTTPS | `resolve_secret("GH_TOKEN")` |
| GitHub REST API call | `resolve_secret("GH_TOKEN")` |
| Any direct HTTP call with auth header | `resolve_secret("MY_KEY")` |
| Shell command via `code_execution_tool` | `resolve_secret("MY_KEY")` |

## Safety Net — `hist_add_before` Masking

Regardless of which resolution path retrieved a secret value, all known secret values are
automatically masked before they enter agent history.
`extensions/python/hist_add_before/_10_openbao_mask_history.py` runs before every message
is written to history and replaces live secret values with secret-alias placeholder tokens.
Coverage includes:

- Global secrets from `secret/data/agentzero`
- Project-scoped secrets from `secret/data/agentzero-{project_slug}` (PSK-005)

No consumer action required. The masking layer is transparent and universal.

> **Rule:** Use the auth proxy for LLM API keys — automatic and transparent. Use `resolve_secret()` for everything else — explicit retrieval is the contract.
