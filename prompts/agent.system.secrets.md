{{if secrets}}
## secrets
OpenBao secrets available: {{secrets}}

To access a secret value, use the `$bao:KEY_NAME` resolver alias syntax with the exact key name above.
For example, if `DATABASE_URL` is listed above, reference it as `$bao:DATABASE_URL` in your tool arguments.
Only reference secrets that your current task actually requires.
Values are resolved from OpenBao automatically at tool execution time — never resolved at prompt time.
Never log, echo, print, or return resolved secret values in your output.
{{endif}}
{{if vars}}
## variables
these are plain non-sensitive values; use them directly without alias syntax
{{vars}}
{{endif}}
