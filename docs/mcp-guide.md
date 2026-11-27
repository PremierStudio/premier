# Premier MCP Guide

`premier mcp` provides two complementary Model Context Protocol (`2025-06-18`, `2025-03-26`, and `2024-11-05`, JSON-RPC 2.0 over stdio) surfaces for AI coding agents (Claude Code, Codex, Cursor) alongside an HTTP control-plane gateway in `premier serve`:

1. **`premier mcp gateway` (Recommended — Unified Policy & Tool Action Gateway):** Exposes a single MCP endpoint that fans out to upstream `[mcp_servers.<name>]` servers (both `stdio` and Streamable `http_sse`) **plus** Premier's 5 built-in policy/schema/overlay tools and 2 resources. Every tool listing and call is filtered through default-deny `[[mcp_rules]]`, `permissions(human) ∩ permissions(agent_profile)`, argument guardrails, SHA-256/TOFU tool-poisoning & rug-pull pinning, host-side `use ≠ read` credential injection, and response secret redaction.
2. **`premier mcp serve` (Read-Only Policy & Schema Inspector):** Lightweight stdio server exposing only Premier's 5 built-in read-only inspection tools and 2 metadata resources with zero secret backend access and zero upstream network/process connections.

Pairing either server with `premier agent run --policy .access.toml --profile <name>` gives AI coding agents full awareness of what paths, secret capabilities, and MCP tools they are authorized to use—while enforcing **zero raw secrets (`use ≠ read`)** at the host egress proxy and kernel sandbox boundary.

---

## Security Model

1. **Default-deny tool routing + `premier agent run` cage enforcement.**
   Prompt-level awareness is never a security boundary on its own. Upstream MCP tools are hidden and uncallable unless explicitly allowed by `[[mcp_rules]]` (and `allow_mcp_tools` when an agent profile is active). Pair `premier mcp gateway` (or `premier mcp serve`) with `premier agent run --policy .access.toml --profile <name> -- <agent>` so direct HTTP/HTTPS traffic from the agent is also confined by the host egress proxy and OS sandbox. (If `--policy` is omitted, `premier agent run` also auto-loads `.access.toml` from the current directory and fails closed if it cannot parse.)
2. **Strict `permissions(human) ∩ permissions(agent_profile)` binding.**
   Both `premier mcp gateway` and `premier mcp serve` bind to the `--principal`, `--group`, and `--agent-profile` flags configured at startup (and `/v1/mcp/rpc` binds to the server-authenticated session/token). Tool calls carrying identity-override arguments (`principal`, `principals`, `groups`, `agent_profile`, `as_agent`, `_premier_principal`, `principal_override`, `agent_profile_override`) are rejected.
3. **Zero raw secrets (`use ≠ read`) and exfiltration blocking.**
   - Built-in `premier_env_schema` and `premier://env/schema` return only schema metadata—never raw secret values or vault/key paths.
   - Upstream MCP server credentials (`env`, `bearer_header`, `header`) are resolved for `Capability::USE` and injected host-side only after verifying `.env.schema` `mcp_servers` (and `egress.hosts` for `http_sse`) bindings.
   - Agent `premier_cap_v1_*` placeholder tokens are blocked if passed into external MCP tool arguments (`ExfiltrationBlocked`), and any reflected secrets (raw, URL-encoded, hex, JSON-escaped, or Base64) are scrubbed from upstream tool schemas, responses, and errors.
4. **Clean stdio framing & safe JIT handling.**
   `premier mcp serve` and `premier mcp gateway` write all logs strictly to `stderr` (ANSI disabled), keeping `stdout` pure single-line JSON-RPC 2.0 frames. Lines are capped at 2 MiB, `head_toml` at 256 KiB, `paths` at 500 entries, and `changed_files` at 200 entries. If the working-tree `.access.toml` differs from `HEAD:.access.toml`, a warning is emitted to `stderr`. Because `stdin` carries JSON-RPC traffic, `premier mcp gateway` never prompts interactively on `stdin`: `jit`-mode tools fail closed (`DenyAll`) unless `--auto-approve-jit` is explicitly passed in a non-agent session (combining `--auto-approve-jit` with `--agent-profile` is refused) or calls are routed through `premier serve` (`/v1/mcp/rpc`) with the Studio Approval Hub (where access tokens can also be minted server-bound to a single `agent_profile`).

---

## Quick Config Generation

`premier mcp config` writes **strictly valid, directly parseable JSON** (for Claude Code and Cursor) or **TOML** (for Codex) to `stdout`, and prints the matching shell-quoted `premier agent run` wrapper command to `stderr` (or standalone to `stdout` when `--wrapper` is passed).

### Unified Policy Gateway (`--gateway`, Recommended)

Generate ready-to-paste client configs wired to `premier mcp gateway` and the matching `premier agent run` command:

```sh
# Claude Code (.mcp.json)
premier mcp config --gateway --client claude-code --agent-profile ui-agent --principal @alice --group web --env dev --backend age > .mcp.json

# OpenAI Codex CLI (~/.codex/config.toml)
premier mcp config --gateway --client codex --agent-profile ui-agent --principal @alice --policy .access.toml --env dev --backend age >> ~/.codex/config.toml

# Cursor (.cursor/mcp.json)
premier mcp config --gateway --client cursor --agent-profile ui-agent --principal @alice --server-policy /etc/premier/server.toml --env dev --backend age > .cursor/mcp.json

# Print only the shell-quoted `premier agent run` wrapper command
premier mcp config --gateway --client claude-code --agent-profile ui-agent --principal @alice --wrapper
```

Optional `--env <name>`, `--backend <env|keychain|age>` (defaults to `age` when generating `--gateway` configs), and `--server-policy <path>` flags are emitted on both the `premier mcp gateway` arguments and the `premier agent run` wrapper command.

### Read-Only Built-In Inspector (No Upstream Servers)

Omit `--gateway` to generate configs for the standalone read-only `premier mcp serve` binary:

```sh
premier mcp config --client claude-code --agent-profile ui-agent --principal @alice
premier mcp config --client codex --agent-profile ui-agent --principal @alice
premier mcp config --client cursor --agent-profile ui-agent --principal @alice
```

### `premier mcp config` Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--client <claude-code\|codex\|cursor>` | `claude-code` | Target MCP client format. |
| `--principal <str>` | *(none)* | Human principal forwarded to `mcp serve` and `agent run`. |
| `--group <str>` | *(repeatable)* | Group memberships forwarded to `mcp serve` and `agent run`. |
| `--agent-profile <str>` | *(none)* | Delegated agent profile forwarded to `mcp serve` and `agent run`. |
| `--policy <path>` | *(none; `.access.toml` in wrapper)* | Repository policy path forwarded to `mcp serve` and `agent run`. |
| `--server-policy <path>` | *(none)* | Optional server override policy forwarded to `mcp serve` and `agent run`. |
| `--wrapper` | `false` | Print only the shell-quoted `premier agent run` command to `stdout`. |
| `--gateway` | `false` | Generate configs for `premier mcp gateway` (unified upstream-server gateway) instead of read-only `premier mcp serve`. |
| `--env <name>` | *(none)* | Target environment forwarded to `mcp gateway` and `agent run`. |
| `--backend <env\|keychain\|age>` | `age` with `--gateway` | Secret backend forwarded to `mcp gateway` and `agent run`. |

---

## Client Setup

### Claude Code

Add to `.mcp.json` at the repository root (or `~/.claude.json`):

```json
{
  "mcpServers": {
    "premier-gateway": {
      "type": "stdio",
      "command": "premier",
      "args": [
        "mcp",
        "gateway",
        "--principal",
        "@alice",
        "--agent-profile",
        "ui-agent",
        "--env",
        "dev",
        "--backend",
        "age"
      ]
    }
  }
}
```

Launch Claude Code inside Premier's capability-proxied cage:

```sh
premier agent run --policy .access.toml --principal @alice --profile ui-agent --env dev --backend age -- claude
```

### Codex CLI

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.premier_gateway]
command = "premier"
args = ["mcp", "gateway", "--principal", "@alice", "--agent-profile", "ui-agent", "--env", "dev", "--backend", "age"]
```

Launch Codex inside Premier's capability-proxied cage:

```sh
premier agent run --policy .access.toml --principal @alice --profile ui-agent --env dev --backend age -- codex
```

### Cursor

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "premier-gateway": {
      "command": "premier",
      "args": [
        "mcp",
        "gateway",
        "--principal",
        "@alice",
        "--agent-profile",
        "ui-agent",
        "--env",
        "dev",
        "--backend",
        "age"
      ]
    }
  }
}
```

Launch Cursor's CLI agent inside Premier's capability-proxied cage:

```sh
premier agent run --policy .access.toml --principal @alice --profile ui-agent --env dev --backend age -- cursor-agent
```

*(If you only want the 5 read-only built-in tools without upstream MCP servers, use server key `"premier"` / `[mcp_servers.premier]` with `["mcp", "serve", ...]` as generated by `premier mcp config` without `--gateway`.)*

---

## Policy Configuration (`.access.toml`)

### 1. Upstream Server Registry (`[mcp_servers.<name>]`)

Declare upstream MCP servers in `.access.toml` (or `--server-policy`, where server-layer definitions override repo-layer entries of the same name and merge `pinned_tool_hashes` with server pins winning):

```toml
# Remote Streamable HTTP / SSE MCP server with host-injected Bearer token
[mcp_servers.github]
transport = "http_sse"
url = "https://mcp.github.example/mcp"
zone = "platform"
description = "GitHub issues and PR automation"
default_approval = "jit"
jit_ttl_secs = 300
timeout_secs = 30
pin_on_first_use = true
credentials = [
  { inject = "bearer_header", secret = "GITHUB_MCP_TOKEN", header = "Authorization" }
]

[mcp_servers.github.pinned_tool_hashes]
list_issues = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

# Local stdio MCP server (spawned with cleared env + baseline OS PATH + bound credentials only)
[mcp_servers.postgres]
transport = "stdio"
command = "mcp-server-postgres"
args = ["--read-only"]
env = { PGSSLMODE = "require" }
credentials = [
  { inject = "env", secret = "READONLY_DB_URL", env_var = "DATABASE_URL" }
]
```

Supported `credentials` bindings (`use ≠ read`):
- `{ inject = "env", secret = "<VAR>", env_var = "<OPTIONAL_ENV_NAME>" }` — sets an environment variable on a `stdio` child process (defaults to `secret`'s own name).
- `{ inject = "bearer_header", secret = "<VAR>", header = "Authorization" }` — sends `Authorization: Bearer <secret>` (or custom header) to an `http_sse` upstream.
- `{ inject = "header", secret = "<VAR>", header = "X-Api-Key", prefix = "" }` — sends `<header>: <prefix><secret>` to an `http_sse` upstream.

### 2. Tool Authorization Rules (`[[mcp_rules]]`)

MCP tools are **default-deny**. Within a layer `deny` overrides `allow`, and `server` overrides `repo`. Upstream tools are addressed and exposed as `<server>:<tool>` (the gateway also accepts `<server>__<tool>` on `tools/call` for clients that sanitize colons):

```toml
[[mcp_rules]]
id = "allow-github-read"
effect = "allow"
principals = ["authenticated"]
tools = ["github:list_*", "github:get_*"]
refs = ["*"]
risk = "read"
approval = "auto"
reason = "Read-only GitHub issue/PR queries"

[[mcp_rules]]
id = "allow-github-pr-write"
effect = "allow"
principals = ["group:eng"]
tools = ["github:create_pull_request"]
risk = "write"
approval = "jit"
jit_ttl_secs = 120
required_secrets = ["GITHUB_MCP_TOKEN"]
arg_constraints = [
  { kind = "allowed_values", arg = "base", values = ["main", "develop"] },
  { kind = "forbid_arg", arg = "maintainer_can_modify" }
]

[[mcp_rules]]
id = "deny-all-deletes"
effect = "deny"
principals = ["*"]
tools = ["*:delete_*", "*:drop_*"]
reason = "Destructive deletes are blocked across all MCP servers"
```

Risk & approval semantics:
- `risk`: `"read"` (default) < `"write"` < `"destructive"`. When multiple rules match, the highest risk applies.
- `approval`: `"auto"` < `"jit"` < `"deny"`. Defaults to `"auto"` for `read` risk and `"jit"` for `write` / `destructive` risk when omitted. `destructive` tools default to single-use (`jit_ttl_secs = 0`) and never reuse cached JIT grants.

### 3. Argument Guardrails (`arg_constraints`)

Every `arg_constraints` entry on matching `allow` rules is validated fail-closed before a call reaches the upstream server. Dotted `arg` paths (e.g. `query.path`) inspect both literal keys and nested JSON objects:

| `kind` | Fields | Enforcement |
| --- | --- | --- |
| `path_zone` | `arg`, `capability` (default `"read"`), `allow_globs`, `deny_globs` | Requires `arg` (string or non-empty string array) to be a valid normalized `RepoPath`, blocks reserved `.git`, `git~1`, `.premier`, and `.premier-local` components, checks that `human ∩ agent_profile` holds `capability` on that path in `.access.toml`, and enforces `deny_globs` / `allow_globs`. |
| `pattern` | `arg`, `allow_patterns`, `deny_patterns`, `case_insensitive` | Collapses runs of ASCII whitespace to single spaces (so `DROP\n\tTABLE` normalizes to `DROP TABLE`) and evaluates glob patterns (`*` spans `/` and spaces). Never echoes rejected argument values in error messages. |
| `allowed_values` | `arg`, `values` | Requires `arg` to be present, scalar, and equal to one of `values`. |
| `forbid_arg` | `arg` | Rejects the call if `arg` is present (non-null). |

### 4. Delegated Agent Profiles (`allow_mcp_tools` / `deny_mcp_tools`)

When `--agent-profile <name>` is active, effective tool authority is strictly `permissions(human) ∩ permissions(agent_profile)`. An agent profile must explicitly allow the `<server>:<tool>` pattern, and `deny_mcp_tools` always overrides `allow_mcp_tools`:

```toml
[[agent_profiles]]
name = "ui-agent"
allow_paths = ["apps/web/**", "README.md"]
deny_paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write"]
allow_secret_use = ["GITHUB_MCP_TOKEN"]
allow_egress_hosts = ["registry.npmjs.org"]
allow_mcp_tools = ["github:list_*", "github:get_*", "github:create_pull_request"]
deny_mcp_tools = ["github:create_pull_request"]
```

---

## `.env.schema` `mcp_servers` Secret Binding

Secrets injected into MCP servers must be declared in `.env.schema`. Every MCP-bound secret must explicitly opt in via `mcp_servers` listing the exact MCP server names (empty `mcp_servers` is refused, and wildcards, `:`, `/`, and whitespace are rejected at schema parse time). Secrets carrying an `[vars.<NAME>.egress]` section are rejected on `stdio` servers and may only be injected into `http_sse` servers whose host matches `egress.hosts`:

```toml
version = 1
repo_id = "acme/platform"

[vars.GITHUB_MCP_TOKEN]
type = "secret"
sensitivity = "restricted"
zone = "platform"
mcp_servers = ["github"]

[vars.GITHUB_MCP_TOKEN.egress]
hosts = ["mcp.github.example"]
```

Before connecting to an MCP server or running a tool with `required_secrets`, the gateway verifies all three conditions:
1. Every bound secret exists in `.env.schema` and `VarSpec::allows_mcp_server` permits the server name (and, for `http_sse` upstreams when `egress` is present, the upstream URL's hostname matches `egress.hosts`).
2. The session's `human ∩ agent_profile` identity holds `Capability::USE` on `secrets/<zone>/<VAR>` (or `secrets/<VAR>`).
3. A secret value resolved cleanly from the configured backend (`env`, `keychain`, or `age`).

If any check fails, the upstream server is marked unavailable for that session—it is never spawned or dialed, and its tools are omitted from `tools/list`.

---

## Tool-Poisoning & Rug-Pull Pinning

Upstream MCP servers can change tool descriptions after initial review ("rug pull") or embed hidden prompt-injection instructions in tool/parameter descriptions ("tool poisoning"). `McpGateway` defends every upstream tool through `ToolPinRegistry`:

1. **Canonical SHA-256 Definition Hashing:** Computes SHA-256 over canonical sorted-key JSON of `{ name, description, inputSchema, annotations }`.
2. **Policy Pins (`pinned_tool_hashes`, Server vs. Repo Layer):** When `[mcp_servers.<name>.pinned_tool_hashes]` in the **Server** policy pins a tool's SHA-256 hex digest, any mismatch quarantines the tool with a critical `policy_pin_mismatch` alert (and an exact Server-layer match is treated as explicitly admin-approved). Repository-layer `pinned_tool_hashes` still enforce hash matching, **never** bypass existing quarantine entries, and still run `scan_tool_poisoning`.
3. **Heuristic Poisoning Scan (`scan_tool_poisoning`):** Scans tool `name`, `description`, `inputSchema`, and `annotations` text for zero-width, soft-hyphen, Unicode tag-block (`U+E0000..U+E007F`), and bidirectional control characters, prompt-injection tags/phrases (`<important>`, `<system>`, `ignore previous instructions`, `exfiltrate`, `.premier/age.key`, `~/.ssh/id_`, etc.), and secret-movement directives (`tool_poisoning_heuristic`).
4. **Trust-on-First-Use (TOFU) & Drift Quarantine:** When `pin_on_first_use = true` (default), clean unpinned tools permitted for the caller record their initial hash in the pin registry (`.premier-local/mcp-pins.json` in CLI; `.premier/mcp-pins.json` in `premier serve`). Disallowed tools never create TOFU pins or drift alerts, and any later change to an observed tool's definition quarantines the tool and raises a critical `rug_pull_detected` alert.
5. **No Direct-Call Bypass:** Calling `tools/call` on a tool that was never fetched via `tools/list` triggers an immediate upstream fetch and pin/poisoning verification before argument validation or execution. Quarantined tools are hidden from `tools/list` and refused on `tools/call`.

---

## CLI Reference

### `premier mcp gateway` Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--policy <path>` | `.access.toml` | Repository access policy file (missing file falls back to default-deny). |
| `--server-policy <path>` | *(none)* | Optional org/server override policy (always wins over repo `.access.toml`). |
| `--schema <path>` | `.env.schema` | Environment & secret capability schema file (missing file falls back to empty schema). |
| `--overlays <path>` | `.premier/overlays.toml` | Local/team overlay manifest for built-in leak checks. |
| `--principal <str>` | `@local` | Human principal evaluated for this gateway session. |
| `--group <str>` | *(repeatable)* | Group memberships for the configured principal. |
| `--agent-profile <str>` | *(none)* | Delegated agent profile (`effective = human ∩ agent_profile`). |
| `--branch <str>` | Current Git branch (`main` if detached) | Ref evaluated for path, secret, and MCP tool rules. |
| `--env <str>` | `dev` | Target environment (`dev`, `preview`, `staging`, `prod`) for secret resolution. |
| `--backend <kind>` | `env` | Secret backend (`env`, `keychain`, or `age`). |
| `--vault <path>` | `.premier-local/vault.toml` | Sovereign `age` AEAD vault path (used when `--backend age`). |
| `--age-key <path>` | `.premier-local/age.key` | Age X25519 identity key path (used when `--backend age`). |
| `--audit <path>` | `.premier-local/audit.jsonl` | Structured JSONL audit log path (zero raw secrets). |
| `--pins <path>` | `.premier-local/mcp-pins.json` | Persisted TOFU pins, observed tool hashes, and drift alerts. |
| `--auto-approve-jit` | `false` | Auto-approve `approval = "jit"` MCP tool calls in interactive human sessions (refused if `--agent-profile` is set; otherwise `jit` fails closed over stdio). |
| `--allow-loopback-http` | `false` | Allow plain `http://` and loopback addresses (`127.0.0.1`, `::1`, `localhost`) for `http_sse` upstreams. |
| `--allow-private-upstreams` | `false` | Allow RFC 1918, CGNAT, and IPv6 ULA addresses for `http_sse` upstreams. |
| `--no-builtin-tools` | `false` | Expose only configured upstream `[mcp_servers.*]` tools (omit built-in `premier_*` tools/resources). |

### `premier mcp serve` Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--policy <path>` | `.access.toml` | Repository access policy file (missing file falls back to default-deny; warns on `stderr` if working tree differs from `HEAD:.access.toml`). |
| `--server-policy <path>` | *(none)* | Optional org/server override policy (always wins over repo `.access.toml`). |
| `--schema <path>` | `.env.schema` | Environment & egress capability schema file. |
| `--overlays <path>` | `.premier/overlays.toml` | Local/team overlay manifest (TOML/JSON) merged with the overlays stored in the workspace's SQLite `premier.db` (`repo_state` table); a legacy `.premier/state.json` is migrated into it on first read. |
| `--principal <str>` | `@local` | Human principal evaluated for this MCP session. |
| `--group <str>` | *(repeatable)* | Group memberships for the configured principal. |
| `--agent-profile <str>` | *(none)* | Delegated agent profile (`effective = human ∩ agent_profile`). |
| `--branch <str>` | Current Git branch (`main` if detached) | Default branch/ref for policy evaluations and diffs. |

---

## Built-In MCP Tools & Resources

Served by `premier mcp serve`, by `premier mcp gateway` (unless `--no-builtin-tools` is set), and by `premier serve` `/v1/mcp/rpc`:

| Tool | Inputs | Description |
| --- | --- | --- |
| `premier_access_explain` | `path` (required), `ref_name` (optional) | Explains effective capabilities (`traverse`, `list`, `read`, `write`, `use`), `synthesized_traverse`, and matched rule traces strictly under the configured `human ∩ agent_profile` identity. Rejects caller identity overrides with `-32602`. |
| `premier_policy_summary` | *(none)* | Returns the compiled policy SHA-256 fingerprint, zone/rule counts, declared agent profile names, default permissions, and active session binding. |
| `premier_env_schema` | *(none)* | Lists declared `.env.schema` variables, types, sensitivity levels, required environments, egress hosts/methods/path prefixes, approval mode, and placeholder prefix (`premier_cap_v1_`). Never returns raw secret values or vault paths. |
| `premier_overlays_check` | `paths: string[]` (required, max 500) | Validates candidate commit paths against `OverlayGuard` (built-in `AGENTS.local.md` and `.premier-local/**` guards, `.premier/overlays.toml`, and the overlays stored in `premier.db`) so overlay files never leak into public commits. |
| `premier_policy_diff` | `head_toml` (required, max 256 KiB), `paths` (required, max 500); `changed_files` (optional, max 200), `ref_name` (optional) | Read-only simulation computing an `AccessImpactDiff` (including path and MCP tool escalations) and untrusted instruction-file quarantine alerts against the active `.access.toml` strictly for the configured `human ∩ agent_profile` session identity (preserving active `--server-policy` overrides and rejecting arbitrary `principals` overrides). |

| Resource URI | MIME Type | Description |
| --- | --- | --- |
| `premier://policy/summary` | `application/json` | Same metadata payload as `premier_policy_summary` (zero secrets). |
| `premier://env/schema` | `application/json` | Same metadata payload as `premier_env_schema` (zero secrets or vault paths). |

---

## `premier-server` `/v1/mcp/*` HTTP API

When running `premier serve`, the control plane exposes an HTTP MCP gateway backed by the repository's committed `.access.toml`, `.env.schema`, encrypted vault, `ToolPinRegistry` (persisted in `.premier/mcp-pins.json` / `--state-dir`), and live Studio `ApprovalHub` (SSE stream `/v1/events/stream`):

| Method & Path | Access | Purpose |
| --- | --- | --- |
| `GET /v1/mcp/gateways` | Authenticated | Lists declared `[mcp_servers.*]` entries visible to the caller, transport metadata, credential variable names/injection kinds (never secret values), and observed tool pin statuses (`pinned`, `tofu`, `unverified`, `quarantined`). |
| `POST /v1/mcp/explain` | Owner (browser session) | Dry-run evaluation of `CompiledPolicy::evaluate_mcp_tool` and `validate_mcp_args` for `{ principal, agent_profile?, server, tool, arguments?, ref_name? }`, returning the allow/deny verdict, risk level, approval mode, TTL, required secrets, constraints, and matched rule traces. |
| `GET /v1/mcp/alerts` | Owner (browser session) | Lists `ToolDriftAlert` records (`policy_pin_mismatch`, `rug_pull_detected`, `tool_poisoning_heuristic`) with expected vs. observed hashes/descriptions and quarantine status. |
| `POST /v1/mcp/alerts/{id}/approve` | Owner (browser session) | Accepts the observed tool definition, updates its TOFU pin hash, and lifts quarantine. |
| `POST /v1/mcp/alerts/{id}/dismiss` | Owner (browser session) | Marks a drift alert resolved without trusting the new definition (keeping quarantine active by default unless `{ "keep_quarantined": false }` is supplied). |
| `POST /v1/mcp/rpc` | Authenticated (session or token) | Streamable HTTP JSON-RPC 2.0 MCP endpoint (`initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`). Identity is strictly bound to the authenticated account + server directory groups (narrowed by optional agent profile), with `jit` calls routed to the Studio Approval Hub. |
