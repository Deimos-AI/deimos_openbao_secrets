{{if secrets}}
## secrets
OpenBao secrets available: {{secrets}}

To access a secret value, use the resolver alias syntax with the exact key name above.
Only reference secrets that your current task actually requires.
Values are resolved from OpenBao automatically at tool execution time.
Never log, echo, print, or return resolved secret values in your output.
{{endif}}
{{if vars}}
## variables
these are plain non-sensitive values; use them directly without alias syntax
{{vars}}
{{endif}}
