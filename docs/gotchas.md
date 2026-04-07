# Gotchas

## Critical Behaviour Quirks

1. **This plugin is an OpenBao CLIENT.** It never handles unseal keys. Configure auto-unseal at the OpenBao server level (AWS KMS, GCP CKMS, Azure Key Vault, or Transit auto-unseal).

2. **Unseal is per server instance** — all namespaces share the same seal state.

3. **`vault_token` is NEVER accepted from `os.environ`.** Use `vault_token_file` (Docker secrets mount at `/run/secrets/vault_token`) or inline config only.

4. **The `⟦bao:…⟧` placeholder scheme** (Unicode brackets U+27E6/U+27E7) is intentionally distinct from the `§§secret()` scheme to prevent interference with the framework's own unmask layer.

5. **Do NOT use literal `⟦bao:…⟧` placeholder characters in `code_execution_tool` args** — the shell guard will raise `ValueError`. Use Unicode escapes in Python source if needed.

6. **MCP credential rotation** requires clicking **Refresh MCP Credentials** or calling the `rotate_mcp` endpoint — agent restart not required.

7. **If `.env` stores shell variable references** (e.g. `GITEA_TOKEN=$GITEA_TOKEN`), Surface C bypasses them and serves the real value from OpenBao directly.

## Configuration Pitfalls

8. **`hard_fail_on_unavailable=true` (default) overrides `fallback_to_env=true`.** To enable graceful `.env` fallback, you must set `hard_fail_on_unavailable=false`. Having both as `true` means hard fail always wins.

9. **`secret_field_patterns: ["*auth*"]` matches non-secret fields.** The pattern `*auth*` matches `auth_method`, `auth_url`, `oauth_redirect` — legitimate non-secret config fields get extracted to vault and replaced with placeholders, breaking plugin configuration. Use specific patterns.

10. **`cache_ttl: 300` means rotated secrets may be stale for up to 5 minutes.** There is no mechanism to force cache invalidation across running agents without restart.

11. **Circuit breaker is applied to a locally-scoped inner function** — circuit state is never shared across calls. The circuit breaker never actually opens. OpenBao is retried on every cache miss even when fully down. This is a known architectural limitation.

## Security Considerations

12. **`_is_bao_ref` bare ALL_CAPS regex has been tightened (MED-01).** The regex now requires `^[A-Z][A-Z0-9_]{7,}$` (minimum 8 characters total) **and** at least 2 underscores. Common config values like `NONE`, `TRUE`, `FALSE`, `DEBUG`, `INFO`, `TOKEN`, `HTTPS`, `JSON`, `ENABLED`, `APPROLE` **no longer match** the bare ALL_CAPS form. Use the explicit `$bao:KEY` prefix format for guaranteed matching.

13. **Masking iteration order can leak substring secrets.** If Secret A's value is a substring of Secret B's value, and A is iterated first, B's remainder can leak into history. The fix is to sort by descending value length — scheduled for a future release.

14. **`deps.py` no longer auto-installs packages (MED-05).** It only checks that dependencies are importable. If a dependency is missing, it logs an error with install instructions and returns `False`. Install pinned versions explicitly via `pip install -r requirements.txt`.

15. **`SyncPlugins` transmits secret values over the network.** If `config.json` uses an `http://` URL, all migrated secrets are transmitted in plaintext. Use `https://` for all vault communication.

16. **AuthProxy forwards all non-hop-by-hop headers to upstream providers.** Internal framework headers (session tokens, debug headers) may be logged by third-party LLM providers.

## Integration Notes

17. **`hvac` private API access in `vault_io.py`.** The code accesses `manager._bao_client._client` and `bao._config.mount_point` — private attributes with no stability guarantee. An `hvac` minor version bump could silently break all vault I/O.

18. **Dynamic importlib loader fragility.** `factory_common.py` loads modules via `importlib.util.spec_from_file_location`. On hot-plugin-update, old module instances in `sys.modules` shadow new code silently. Restart the agent after plugin updates.

19. **`_init_attempted` is only set for permanent failures, not transient ones.** Permanent failures include: missing dependencies, plugin not installed, and explicitly disabled. Transient failures (config validation errors, module loading issues, network errors) are retried up to `OPENBAO_FACTORY_MAX_RETRIES` (default 3) with exponential backoff before locking out. After exhausting retries, the factory locks out permanently — call `reset()` or restart to retry. Set `hard_fail_on_unavailable: false` to allow graceful fallback. (F-09 — resolved in v0.9.0-beta.)

20. **Test mock format diverges from production.** `conftest.py` uses `"secret_alias(KEY)"` for masked values, while production uses the real placeholder format. Masking bugs producing subtly wrong formats would pass tests but fail in production.

---

## Known Issues & Architectural Limitations

These are documented quirks and limitations — known at v0.1.0 and acknowledged as part of the architecture.

### SSRF Protection Blocks Localhost (F-07)

**What:** `api/health.py` blocks connections to `localhost`, `127.0.0.1`, `::1`, and the entire `169.254.*` link-local range as part of the SSRF protection guard. The health endpoint will reject any URL that resolves to a loopback or link-local address.

**Why:** Intentional production security posture — allowing arbitrary server-side HTTP requests to loopback addresses is a classic SSRF vector.

**Impact:** Developers running OpenBao on the same host as Agent Zero cannot test vault connectivity via the health endpoint using `http://localhost:8200` or `http://127.0.0.1:8200`.

**Workaround:**
- Use the Docker host gateway IP (e.g. `http://172.17.0.1:8200`) instead of `localhost`
- Use a custom DNS entry or hostname that resolves to a non-loopback address
- Test vault connectivity directly with `bao status` or `curl` from within the container

---

### Circuit Breaker Scope (F-08)

**What:** The circuit breaker is scoped to each `OpenBaoClient` instance, not shared globally across requests. Failure counts do not accumulate across separate invocations.

**Why:** Architectural limitation — a global circuit breaker would require shared state across async contexts, introducing its own complexity and race conditions.

**Impact:** The circuit breaker does not protect against cascading failures in the way a global breaker would. If the vault is unavailable, each request independently probes it rather than fast-failing based on accumulated failure state from prior requests.

**Planned improvement:** A future release may introduce a process-level singleton or shared circuit breaker state via `asyncio`-safe globals.

---

### ✅ Transient Init Failures — Fixed (F-09)

**Status:** Resolved in v0.9.0-beta.

**What was wrong:** `factory_common.py` used `_init_attempted=True` for all failure types including transient ones (config validation errors, module loading failures, network errors). This meant a single transient failure during boot permanently disabled the OpenBao factory for the entire process lifetime.

**Root cause:** Config validation errors (e.g., env vars not yet propagated) were classified as permanent failures, setting `_init_attempted=True` and preventing any retry.

**Fix:** The factory now classifies failures as PERMANENT or TRANSIENT:
- **Permanent** (immediate lockout): deps missing, plugin not found, plugin explicitly disabled.
- **Transient** (retryable): config validation errors, module loading failures, network errors, `ImportError`, general `Exception`.

Transient failures are retried up to `OPENBAO_FACTORY_MAX_RETRIES` (default 3) with exponential backoff (`OPENBAO_FACTORY_RETRY_BACKOFF`, default 1.0s base). After exhausting retries, the factory locks out permanently. Call `reset()` or restart to retry.
