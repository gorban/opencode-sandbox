---
name: oc-sandbox-authoring
description: Step-by-step authoring guide and concrete examples for Sandbox Types, nested Bundles, 0-MCP service dependencies, [local] conditional acquisition, and standing Personas.
---

# Authoring Sandbox Types, Bundles, and Personas

Always preview changes with `plan_preview` before calling `config_propose_revision`.

## Pattern 1: 0-MCP App Development Sandbox with PostgreSQL

A bundle does NOT need any MCP servers to spin up a database for app development:

```toml
schema_version = 1
kind = "bundle@1"
id = "team/backend-pg"
description = "Python + PostgreSQL 17 app development bundle with zero MCPs."
requires_services = ["builtin/postgres"]
instructions = [
  "PostgreSQL 17 is running on 127.0.0.1:5432; authenticate via PGPASSFILE at /run/secrets/oc-pgpass."
]

[mise_tools]
"core:python" = "3.13.18"
"aqua:astral-sh/uv" = "0.13.6"
```

## Pattern 2: `[local]` Conditional Service Acquisition (API -> Transitive Postgres)

When a tool or bundle declares `[mcp.<name>.local]` or `[[local_services]]`, leaving `API_ENDPOINT` blank automatically pulls in `builtin/api-demo` AND its transitive `cap:db.postgres@^17.0` (`builtin/postgres`). Supplying a remote `https://staging.example.com/mcp` prunes both local services automatically (while keeping Postgres if another active bundle still requires it):

```toml
schema_version = 1
kind = "bundle@1"
id = "team/orders-api"
description = "Orders API client with automatic local API + Postgres fallback."

[mcp.orders]
type = "remote"
url = "http://127.0.0.1:8080/mcp"
tools = ["get_order", "cancel_order"]

[mcp.orders.headers]
Authorization = "Bearer {file:/run/secrets/orders_token}"

[mcp.orders.local]
binding_key = "ORDERS_API_ENDPOINT"
service = "builtin/api-demo"
url = "http://127.0.0.1:8080/mcp"
```

## Pattern 3: Standing Personas & Role-Filtered MCPs

- Only **one** primary `persona` is allowed per Sandbox Type. To override a base bundle's persona, declare `[composition] replace = ["persona"]`.
- Use `allowed_mcp_tools` / `denied_mcp_tools` on a persona to minimize tool surface (for example, keeping a `security-reviewer` persona strictly read-only even when inheriting an API bundle).
- Put detailed multi-step workflows in `skills` (progressive disclosure) rather than stuffing large prose into `instructions` (16 KiB total cap).
