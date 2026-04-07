# Security Model

## Auth Proxy (Layer 1)

The embedded reverse proxy (`helpers/auth_proxy.py`) runs on `127.0.0.1:{random_port}` and intercepts all outbound LLM API calls:

1. LLM provider env vars (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`) are set to the sentinel value `proxy-a0` at startup
2. When the LLM SDK makes an HTTP request, it hits the auth proxy instead of the real provider
3. The proxy fetches the real API key from OpenBao, replaces the sentinel in the `Authorization` header, and forwards the request to the upstream provider
4. The response is relayed back unchanged

**Key property:** The real API key is never present in `os.environ` — only the sentinel `proxy-a0` lives there.

## Masking Layers (Layer 3)

Two independent masking passes ensure secrets never enter LLM visible context:

- **`hist_add_before`** — masks secrets before they enter agent history
- **`tool_output_update`** — masks secrets in tool output before LLM sees it

Both layers scan for all known secret values from OpenBao (global + project-scoped) and replace them with redacted aliases.

## CAS Protection

Surface A and Surface B use KV v2's versioned storage to prevent accidental overwrites:

- Atomic rollback on write failure — original file unchanged
- Idempotency guards prevent re-extraction of already-vaulted values
- SHA-256 dedup avoids storing duplicate secret values in the vault

## SSRF Guards

The `health.py` endpoint validates user-supplied URLs:

- Scheme allowlist: `http`, `https` only
- Blocked hosts: `169.254.169.254`, `metadata.google.internal`, `localhost`, `127.0.0.1`, `::1` (IPv6 loopback)
- Blocked ranges: entire `169.254.*` link-local range (cloud IMDS protection)

## Path Sanitization

All user-supplied path components (project names, plugin names) pass through `_sanitize_component()` which strips:

- Path separators (`/`, `\`)
- Dot-dot sequences (`..`)
- Non-safe characters (only alphanumeric, `_`, `.`, `-` allowed)
