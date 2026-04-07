# Development

## Prerequisites

```bash
pip install hvac tenacity circuitbreaker aiohttp pytest
```

## Run Tests

```bash
# Run full test suite
cd /path/to/deimos_openbao_secrets
pytest tests/ -v

# Run specific test file
pytest tests/test_surface_a.py -v

# Run with coverage
pytest tests/ -v --tb=short -q
```

**Current test suite:** 386 tests passing, 0 regressions.

## Test Architecture

Tests use `importlib.util.spec_from_file_location` for module loading (matching the production importlib pattern) and mock the following:

- `hvac.Client` — OpenBao API responses
- `helpers.extension` / `helpers.plugins` — Agent Zero framework hooks
- `sys.modules` — Module caching for factory singletons

No running OpenBao instance is required for tests. All vault interactions are mocked.

## Adding New Extensions

1. Create a new file in the appropriate `extensions/python/<hook_point>/` directory
2. Use the naming convention `_NN_description.py` where `NN` is the priority number (lower = earlier execution)
3. The function signature must match the hook point's expected signature
4. Add corresponding tests in `tests/`

## CI Pipeline

The `.github/workflows/plugin-lint.yml` workflow runs on push:

- Lint: syntax validation
- Secret surface scan: `ci_secret_surface_scan.py` detects raw secret exposure

## Project Structure

```
plugin.yaml                          # Plugin metadata
hooks.py                             # Plugin lifecycle hooks + Alpine.js key normalisation
default_config.yaml                  # All configuration fields with defaults
config.json.example                  # Operational config template
requirements.txt                     # Python dependencies
helpers/
  config.py                          # Configuration loading and validation
  openbao_client.py                  # Resilient hvac client wrapper
  openbao_secrets_manager.py         # SecretsManager subclass (Surface C backend)
  auth_proxy.py                      # Reverse proxy for LLM provider auth (L1)
  factory_common.py                  # Shared manager singleton factory
  factory_loader.py                  # Factory module loader (REM-001)
  vault_io.py                        # Vault read/write/atomic-rollback primitives (REM-002)
  secrets_scanner.py                 # First-install env/a0proj/mcp secret scanner (REM-017)
  registry.py                        # Secrets registry manager — YAML, atomic write (REM-017)
  deps.py                            # Dependency importability check (MED-05: no auto-install)
api/
  health.py                          # POST /health — liveness + credential check
  secrets.py                         # POST /secrets — CRUD + sync-plugins
  rotate_mcp.py                      # POST /rotate_mcp — MCP credential rotation
  sync_plugins.py                    # POST /secrets (action: sync_plugins) — cross-plugin sync
  bootstrap.py                       # POST /bootstrap — first-install registry scan (REM-017)
extensions/python/
  agent_init/
    _05_openbao_secrets_resolver.py      # Surface C — §§secret() OpenBao backend
    _10_start_auth_proxy.py              # L1 — start auth proxy, inject dummy env
    _20_openbao_mcp_header_resolver.py   # Surface B — resolve ⟦bao:⟧ at transport
  plugin_config/
    _10_openbao_plugin_config.py         # Surface A — intercept plugin config saves
  tool_execute_before/
    _05_openbao_shell_transform.py       # L2 — resolve placeholders before shell
    _15_inject_terminal_secrets.py       # Inject secrets into terminal subprocess env
  tool_execute_after/
    _10_openbao_mcp_scan.py              # Surface B — scan/vault MCP headers on write
    _15_cleanup_terminal_secrets.py      # Strip injected terminal secrets after command
  hist_add_before/
    _10_openbao_mask_history.py          # L3 — mask secrets + bao tokens from history
  tool_output_update/
    _10_openbao_mask_output.py           # L3 — mask secrets in tool output
  _functions/
    helpers/secrets/get_secrets_manager/start/
      _10_openbao_factory.py             # Singleton manager factory
    helpers/secrets/get_default_secrets_manager/start/
      _10_openbao_default_factory.py     # Default secrets manager factory
    helpers/secrets/get_project_secrets_manager/start/
      _10_openbao_project_factory.py     # Project-scoped secrets manager factory
    models/get_api_key/start/
      _10_openbao_api_key.py             # Round-robin API key resolution
webui/
  config.html                        # Plugin settings UI (Alpine.js)
tests/
  conftest.py                        # sys.modules bootstrap for bare-name imports
  test_config.py                     # Configuration unit tests
  test_openbao_client.py             # Client resilience tests
  test_openbao_manager.py            # Manager behaviour tests
  test_auth_proxy.py                 # Auth proxy tests (REM-009)
  test_factory_common.py             # Factory singleton tests (REM-010)
  test_surface_a.py                  # Surface A integration tests (REM-011)
  test_surface_a_ref_resolution.py   # Surface A reference resolution tests (REM-014)
  test_surface_b.py                  # Surface B integration tests (REM-012)
  test_api_health.py                 # Health endpoint tests (REM-013)
  test_api_secrets.py                # Secrets CRUD endpoint tests (REM-013)
  test_api_rotate_mcp.py             # MCP rotation endpoint tests (REM-013)
  test_api_sync_plugins.py           # Cross-plugin sync tests (REM-014)
  test_api_bootstrap.py              # Bootstrap endpoint tests (REM-017)
  test_vault_io_write_if_absent.py   # Vault I/O atomicity tests (REM-014)
  test_masking_strategy.py           # Masking strategy unit tests
  test_placeholder_mask.py           # Placeholder masking tests
  test_approle_auth.py               # AppRole authentication tests
  test_secret_resolver.py            # Secret resolver tests
  test_psk_resolution.py             # Project-scoped secret resolution tests
  test_secret_surfaces.py            # Secret surface integration tests
  test_secrets_scanner.py            # Secrets scanner tests (REM-017)
  test_registry.py                   # Registry manager tests (REM-017)
  test_protocol_mismatch.py          # Protocol mismatch tests (REM-018)
  test_issue_19_runtime_conditional.py  # Runtime-conditional alias token tests (REM-019)
  test_adversarial_hardening.py      # Adversarial hardening tests (REM-016)
  test_extension_loader_regression.py   # Extension loader regression tests
  ci_secret_surface_scan.py          # CI scan — detect raw secret exposure
  verify_checks.py                   # Test verification utilities
```
