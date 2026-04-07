# Upgrading

## REM-008 — `fallback_to_env_on_error` Renamed

The `fallback_to_env_on_error` config key has been **renamed** to `hard_fail_on_unavailable`
with **inverted semantics**:

| Old key | Old value | New key | New value | Behaviour |
|---------|-----------|---------|-----------|----------|
| `fallback_to_env_on_error` | `false` (default) | `hard_fail_on_unavailable` | `true` (default) | Hard fail: raises `OpenBaoUnavailableError` |
| `fallback_to_env_on_error` | `true` | `hard_fail_on_unavailable` | `false` | Graceful fallback to `.env` |

**Action required:** If you have `fallback_to_env_on_error` set in your `config.json`,
`default_config.yaml`, or `OPENBAO_FALLBACK_TO_ENV_ON_ERROR` env var, rename the key
and invert the boolean value. The `OPENBAO_FALLBACK_TO_ENV_ON_ERROR` env var is replaced
by `OPENBAO_HARD_FAIL_ON_UNAVAILABLE`.

## REM-032 — `config.json` Key Format Change (snake_case alignment)

Prior to REM-032, the settings modal wrote compound config keys in flat/camelCase format
(e.g. `authmethod`, `mountpoint`). `load_config()` now requires snake_case keys matching
the `OpenBaoConfig` dataclass field names exactly.

**Affected keys:**

| Old key (camelCase) | New key (snake_case) |
|---|---|
| `authmethod` | `auth_method` |
| `mountpoint` | `mount_point` |
| `secretspath` | `secrets_path` |
| `tlsverify` | `tls_verify` |
| `tlscacert` | `tls_ca_cert` |
| `cachettl` | `cache_ttl` |
| `retryattempts` | `retry_attempts` |
| `circuitbreakerthreshold` | `circuit_breaker_threshold` |
| `circuitbreakerrecovery` | `circuit_breaker_recovery` |
| `fallbacktoenv` | `fallback_to_env` |
| `terminalsecrets` | `terminal_secrets` |
| `roleid` | `role_id` |
| `secretidenv` | `secret_id_env` |
| `secretidfile` | `secret_id_file` |

**To migrate an existing `config.json`**, run this one-time script from the plugin root:

```bash
cd /path/to/deimos_openbao_secrets
python -c "
import json
with open('config.json') as f:
    data = json.load(f)
remap = {
    'authmethod': 'auth_method', 'mountpoint': 'mount_point',
    'secretspath': 'secrets_path', 'tlsverify': 'tls_verify',
    'tlscacert': 'tls_ca_cert', 'cachettl': 'cache_ttl',
    'retryattempts': 'retry_attempts',
    'circuitbreakerthreshold': 'circuit_breaker_threshold',
    'circuitbreakerrecovery': 'circuit_breaker_recovery',
    'fallbacktoenv': 'fallback_to_env', 'terminalsecrets': 'terminal_secrets',
    'roleid': 'role_id', 'secretidenv': 'secret_id_env',
    'secretidfile': 'secret_id_file',
}
fixed = {remap.get(k, k): v for k, v in data.items()}
with open('config.json', 'w') as f:
    json.dump(fixed, f, indent=2)
print('Migrated keys:', [k for k in data if k in remap])
"
```

New installations (settings saved after REM-032) are not affected — the modal now writes
correct snake_case keys automatically.
