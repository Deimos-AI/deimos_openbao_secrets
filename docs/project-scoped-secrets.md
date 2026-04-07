# Project-Scoped Secrets

The plugin supports **per-project secret overrides** using a two-tier vault path hierarchy:

    secret/data/agentzero                      <- global (shared across all agent contexts)
    secret/data/agentzero-{project_slug}       <- project override (active project only)

## Resolution Rule

1. When a project is active, the plugin checks the project-specific vault path first
2. Key found there — that value is used (project override wins)
3. Key absent or project vault document does not exist — global path used as fallback
4. No active project — only the global path is consulted (unchanged behaviour)

Consumer plugins (`langfuse_observation`, `straico`, etc.) require **no changes** — resolution is transparent.

## Project Slug Derivation

The project slug is the final path component of `agent.context.project`:

    # agent.context.project = "/a0/usr/projects/deimos-openbao-project"
    # project_slug          = "deimos-openbao-project"

## Provisioning a Project Vault Document

Create a project-specific document containing only the keys that differ from the global set:

    vault kv put secret/agentzero-deimos-openbao-project       LANGFUSE_PUBLIC_KEY="pk-lf-proj-xxxx"       LANGFUSE_SECRET_KEY="sk-lf-proj-xxxx"

The project vault document **does not need to replicate globally shared credentials** — only include keys that should differ from the global `secret/agentzero` document.

## Configuration Reference

| Config Field | Env Var | Default | Description |
|---|---|---|---|
| `vault_project_template` | `OPENBAO_PROJECT_TEMPLATE` | `agentzero-{project_slug}` | Naming template for project vault paths. Uses Python `str.format()` with `{project_slug}` as the substitution placeholder. |

Custom template example:

    export OPENBAO_PROJECT_TEMPLATE="myorg-{project_slug}"
    # Resolves to: secret/data/myorg-deimos-openbao-project
