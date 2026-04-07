# Failure Modes

| Scenario | Behaviour | Recovery |
|----------|-----------|----------|
| OpenBao unreachable, `hard_fail_on_unavailable=true` (default) | Hard fail: `OpenBaoUnavailableError` | Fix OpenBao connectivity, or set `hard_fail_on_unavailable=false` to enable `.env` fallback |
| OpenBao unreachable, `hard_fail_on_unavailable=false` | Graceful fallback to `.env` | Resolve OpenBao outage; secrets served from `.env` in the interim |
| KV write fails during Surface B scan | Atomic rollback — original file unchanged; exception raised | Check OpenBao logs for write permission issues |
| `bao` placeholder in shell arg, OpenBao unavailable | Hard error — never silently passed to shell | Fix OpenBao or remove the placeholder reference |
| MCP credential rotation needed | Click **Refresh MCP Credentials** in plugin settings, or `POST /api/plugins/deimos_openbao_secrets/rotate_mcp` | No agent restart required |
| Namespace token expires | `OpenBaoUnavailableError` on next KV read | Re-authenticate or re-provision token |
| Plugin own config intercepted (self-referential loop) | Prevented by bootstrapping exclusion guard | N/A — automatic |
| `write_if_absent` concurrent calls on same key | Last writer wins (no KV v2 CAS lock) | Avoid concurrent sync operations on the same vault path |
| `_vault_read` receives `Forbidden` (403) | **Re-raises the exception** — permission denied is surfaced, not silently swallowed | Ensure vault token has not expired; check token permissions |
| `secret_field_patterns` matches non-secret fields (e.g. `"*auth*"` matches `auth_method`) | Non-secret config values extracted to vault as if they were secrets | Tighten patterns — use more specific patterns like `"*api_key*"`, `"*api_token*"` |
| AppRole auth fails with fallback token present | Silent downgrade to static token auth | Remove fallback token from config when using AppRole exclusively |
| Cached secrets stale after rotation (up to `cache_ttl` seconds) | Rotated/revoked secrets continue to be served from cache | Reduce `cache_ttl`, or restart agent to force cache clear |
