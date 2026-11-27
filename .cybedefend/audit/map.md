# Security Audit Map — Premier

## Guarantees

1. **Path & Zone Confidentiality (`traverse` vs `list` vs `read` vs `write` vs `use`):** An unauthenticated or unauthorized principal never receives restricted tree metadata, file names, search hits, blame lines, blob bytes, or existence signals across Git Smart HTTP/SSH, REST APIs, MCP tools, or agent sandboxes (`AGENTS.md`, `crates/premier-policy/src/trie.rs`, `crates/premier-git-bridge/src/projector.rs`).
2. **Branch & Ref Confidentiality + Anti-CFOR:** Private branches (`refs/premier-private/*`) and restricted tags are filtered per principal via `can_see_ref`, raw `uploadpack.allow*SHA1InWant` and cross-scope `have`/ACK existence oracles are disabled, and pushing onto a branch requires visibility and write rights without leaking ancestry (`crates/premier-git-bridge/src/projector.rs`, `crates/premier-git-bridge/src/receive_pack.rs`).
3. **Server Overrides Repo & Deny Overrides Allow:** Server-layer policies override `.access.toml`, deny always overrides allow, imported `.access.toml` files remain held by `PENDING_POLICY` until explicitly reviewed/saved by an owner, and reserved/case-folded/symlink paths (`.git`, `.gitmodules`, `.premier`, `.premier-local`, `.access.toml`, `.env.schema`, 8.3/HFS+/NTFS aliases) are rejected across pushes, squash-declassify, writes, and symlinks (`crates/premier-git-bridge/src/{lib.rs,receive_pack.rs}`, `crates/premier-server/src/repos.rs:435`).
4. **Secret Capability Separation (`use != read`):** Secrets live in host/KMS/Keychain/age vaults or host-only FIFOs and are swapped into TLS requests to declared hosts inside `premier-proxy` / `premier-mcp-gateway`; agents only see ephemeral `premier_cap_v1_*` placeholders, raw/URL-encoded/Base64 reflections are scrubbed, and `POST /v1/traces*` scrubs unlocked vault values pre-persistence (`crates/premier-proxy/src/lib.rs`, `crates/premier-server/src/traces.rs:63-142`).
5. **Authentication, Session Binding & CSRF:** Every `/v1/*` route (except `/v1/auth/status`, `/v1/auth/setup`, `/v1/auth/login`) and `/git/*` write/auth route enforces `auth::gate`, unsafe browser-cookie requests require same-origin `Origin`, owner administration (`owner(...)`) requires BOTH `Role::Owner` AND a browser session (never a `prm_` access token), and SSE event streams terminate on logout, demotion, account disablement, or server shutdown (`crates/premier-server/src/auth.rs:1219-1344`, `crates/premier-server/src/lib.rs:3457-3490`).
6. **AI Agent Lethal Trifecta (`permissions(human) ∩ permissions(agent_task)`):** Agent sessions require a sandbox (`bwrap` on Linux unless explicitly opted into `--allow-unsandboxed`), drop Linux capabilities (`--cap-drop ALL`), keep `.git` read-only, enforce per-profile capability intersection across files, MCP tools (including schema TOFU pinning + drift quarantine), and OIDC workload tokens (`crates/premier-proxy/src/{sandbox.rs,mcp_gateway/mod.rs}`, `crates/premier-server/src/lifecycle.rs:1117`).

Surfaces: ai-agents, identity-and-http, browser, messaging-and-rpc, data-lifecycle, infrastructure, native-and-local
Families: rights, identity, input-trusted-too-early, flows, limits-and-time, files, data-that-leaves, dangerous-calls, configuration

## Flows

1. **Browser Authentication & Account Lifecycle:** `GET /v1/auth/status` -> `POST /v1/auth/setup` (first owner only) / `POST /v1/auth/login` (Argon2id + per-IP/account lockout + optional TOTP -> `HttpOnly` `SameSite=Lax` cookie; rejects cross-origin writes without bearer) -> `/v1/auth/*` (browser session enforced in `gate` at `crates/premier-server/src/auth.rs:1275`) -> `POST /v1/auth/logout` (session deleted in SQLite + SSE ticks close within 100ms).
2. **Git Smart-HTTP & SSH Transport:** Client authenticates in `auth::gate` (`crates/premier-server/src/auth.rs:1228`) or `SshServer` publickey-only (`crates/premier-ssh/src/lib.rs:1211`) -> `hide_from_strangers` hides invisible non-default repos (`crates/premier-server/src/repos.rs:402`) -> upload-pack projects only authorized trees/refs & filters `have`/want OIDs against projected commits (`crates/premier-git-bridge/src/projector.rs`) -> receive-pack enforces `can_see_ref`, policy/config integrity, firewall scan, and private branch creation (`crates/premier-git-bridge/src/receive_pack.rs`).
3. **OIDC Workload Identity Delegation:** Authenticated caller calls `POST /v1/oidc/token` (`crates/premier-server/src/lifecycle.rs:1117`) -> `effective_principal`, explicit `can_see_ref` branch check, `human ∩ agent_profile`, and `PREMIER_OIDC_ALLOWED_AUDIENCES` check -> EdDSA JWT signed with persistent key (`oidc.key`) -> `POST /v1/oidc/verify` validates signature, `exp`, `nbf`, `iss`, `aud`, and revocation list (`crates/premier-server/src/lifecycle.rs:1251`).
4. **Policy-Unified MCP Gateway:** Caller invokes `POST /v1/mcp/rpc` (`crates/premier-server/src/mcp_gateway.rs:663`) -> `auth::gate` + `can_see_ref` -> `McpGateway` caps JSON-RPC batches at 32 (`crates/premier-proxy/src/mcp_gateway/mod.rs:45`), verifies TOFU tool schema hash on `tools/call`, scans descriptions for normalized poisoning patterns, blocks identity-override args, injects host-side credentials only on schema-bound TLS/stdio upstreams (`PREMIER_ALLOW_REPO_STDIO_MCP=1` required for repo stdio), and scrubs outputs.
5. **Egress Capability Proxy & Agent Cage:** Owner spawns session -> `runner` enforces sandbox availability (`bwrap` or explicit `PREMIER_ALLOW_UNSANDBOXED_AGENTS=1`) -> host starts `EgressProxyServer` with combined system + ephemeral CA (`SSL_CERT_FILE`), binds loopback/Unix socket -> placeholder `premier_cap_v1_*` swapped only over verified TLS to declared hosts after SSRF/IP checks (`crates/premier-secrets/src/lib.rs`) and optional JIT approval (`crates/premier-proxy/src/proxy.rs`).
6. **Backup, Restore & Audit Chain:** Owner with browser session downloads `GET /v1/backup` (`crates/premier-server/src/ops.rs`) preserving `premier.db`, overlays, vaults, `.premier-local/audit.jsonl`, and `.premier-local/audit.jsonl.head` -> CLI `premier restore` unpacks safely under `0o600` (`write_private`) without trusting archive paths outside root.

## AI-Agents Surface Mapping

- **Identities acted with:** `Principal::Anonymous` (unauthenticated `/git/repo.git` read only), `@<user>` human `DelegatedIdentity`, `@<user> ∩ <agent_profile>` token/OIDC identity, `service:github` (explicit owner GitHub companion).
- **Tools / capabilities exposed:** Builtin read/policy MCP tools + configured upstream HTTP-SSE / owner-approved stdio MCP tools (`McpGateway`), Git fetch/push, and HTTP capability proxy endpoints `/cap/{token}/{var}/*`.
- **Untrusted text sources:** Repository trees, commit messages, PR comments, review steering notes, MCP upstream tool descriptions/schemas, and `/v1/traces/ingest` hook payloads. All quarantined or scrubbed prior to prompt/storage/display.
- **Outputs:** Projected Git packs, JSON API responses, SSE events, Studio React SPA (HTML escaped + `script-src 'self'`), and scrubbed trace spans.

## Entry Points

| Entry point | Who may call it | Reads / changes | The check that enforces it (file:line) | Verdict |
|---|---|---|---|---|
| `GET /health` | Unauthenticated returns version/ok; authenticated returns sandbox mode; owner adds host details | Reads auth header/cookie, sandbox capabilities | Manual `auth::request_user` + `user.role == Role::Owner` at `crates/premier-server/src/lib.rs:2040-2056` | ok |
| `GET /livez` | Any caller (liveness probe) | Returns static JSON `status: ok` | Read-only static response (`crates/premier-server/src/lib.rs:1802`) | ok |
| `GET /readyz` | Any caller (readiness probe) | Probes SQLite writability, `git --version`, optional SSH TCP bind | Rate-limited + 3s `readiness_probe` cache (`crates/premier-server/src/lib.rs:1806-1893`) | ok |
| `GET /metrics` | Any caller on loopback/internal network (blocked `404` by `deploy/Caddyfile` externally) | Reads atomic counters & anonymous trace/session counts | `WorkloadGauges::collect` uses `Principal::Anonymous` (`crates/premier-server/src/lib.rs:1904-1921`), `deploy/Caddyfile` blocks `/metrics` | ok |
| `GET /.well-known/openid-configuration` | Any caller | Returns public OIDC discovery JSON | Public standard metadata (`crates/premier-server/src/lib.rs:1164`) | ok |
| `GET /.well-known/jwks.json` | Any caller | Returns public Ed25519 verification keys | Public JWKS only (`crates/premier-server/src/lib.rs:1167`) | ok |
| `GET /v1/policy/summary` | Any authenticated user; policy TOML text only to owner browser session | Reads compiled repo/server policy | `auth::gate` (`auth.rs:1219`) + `auth::owner_only()` hides TOML for non-owners (`crates/premier-server/src/lib.rs:2064-2080`) | ok |
| `PUT /v1/policy/repo` | Owner browser session only | Validates & commits `.access.toml`, clears pending marker | `owner(...)` -> `auth::require_owner` + `require_browser_session` (`auth.rs:1299`, `lib.rs:1171`) | ok |
| `GET /v1/repo/tree` | Authenticated user | Lists visible files at authorized ref | `auth::gate` (`auth.rs:1219`) + `hide_from_strangers` (`repos.rs:402`) + policy `LIST` filter in `repo_tree_handler` (`lib.rs:2203`) | ok |
| `GET /v1/repo/file` | Authenticated user | Reads single file at authorized ref | `auth::gate` (`auth.rs:1219`) + `content_source` ref visibility + policy `READ` check (`lib.rs:2533`) | ok |
| `PUT /v1/repo/file` | Authenticated user with `WRITE` and browser session | Writes file on writable ref | `auth::gate` (`auth.rs:1219`) + `require_browser_session` & path/policy `WRITE` check (`handlers_v1.rs:384-470`) | ok |
| `DELETE /v1/repo/file` | Authenticated user with `WRITE` and browser session | Deletes file on writable ref | `auth::gate` (`auth.rs:1219`) + `require_browser_session` & path/policy `WRITE` check (`handlers_v1.rs:411-595`) | ok |
| `GET /v1/repo/search` | Authenticated user | Fixed-string `git grep -F` across readable files only | `auth::gate` (`auth.rs:1219`) + `content_source` + per-path `READ` filter (`handlers_v1.rs:77-153`) | ok |
| `GET /v1/repo/blame` | Authenticated user | Returns blame lines filtered by `READ` capability | `auth::gate` (`auth.rs:1219`) + `handlers_v1::repo_blame_handler` (`handlers_v1.rs:236`) | ok |
| `POST /v1/access/explain` | Owner browser session only | Evaluates policy capability decision | `owner(...)` -> `auth::require_owner` (`lib.rs:1182`, `auth.rs:1299`) | ok |
| `POST /v1/access/diff` | Owner browser session only | Diffs policy impact & instruction quarantine | `owner(...)` -> `auth::require_owner` (`lib.rs:1183`, `auth.rs:1299`) | ok |
| `POST /v1/access/scan` | Owner browser session only | Runs declassification firewall scan | `owner(...)` -> `auth::require_owner` (`lib.rs:1184`, `auth.rs:1299`) | ok |
| `GET /v1/quarantine` | Owner browser session only | Lists instruction quarantine queue | `owner(...)` -> `auth::require_owner` (`lib.rs:1186`, `auth.rs:1299`) | ok |
| `POST /v1/quarantine/approve` | Owner browser session only | Approves instruction file hash | `owner(...)` -> `auth::require_owner` + `require_browser_session` (`lib.rs:1190`, `firewall.rs:316`) | ok |
| `POST /v1/quarantine/reject` | Owner browser session only | Rejects instruction file hash | `owner(...)` -> `auth::require_owner` + `require_browser_session` (`lib.rs:1194`, `firewall.rs:998`) | ok |
| `POST /v1/policy/diff` | Owner browser session only | Diffs base/head policy | `owner(...)` -> `auth::require_owner` (`lib.rs:1197`, `auth.rs:1299`) | ok |
| `POST /v1/policy/propose` | Owner browser session only | Proposes policy intent rules | `owner(...)` -> `auth::require_owner` + `owner_only` (`lib.rs:1199`, `lib.rs:2866`) | ok |
| `POST /v1/policy/explain-secrets` | Owner browser session only | Explains secret capabilities per principal | `owner(...)` -> `auth::require_owner` + `owner_only` (`lib.rs:1203`, `lib.rs:3032`) | ok |
| `GET /v1/env/schema` | Authenticated user | Returns schema metadata allowed for caller (`USE`) | `auth::gate` + `owner_only` / principal filtering (`lib.rs:3077-3120`) | ok |
| `GET /v1/env/dashboard` | Authenticated user | Returns secret lifecycle view scoped to caller | `auth::gate` + `effective_principal` filtering (`lib.rs:3083`) | ok |
| `GET /v1/secrets/status` | Owner browser session only | Returns secret backend metadata (no values) | `owner(...)` + `owner_only` (`lib.rs:1210`, `handlers_v1.rs:1988`) | ok |
| `POST /v1/secrets/set` | Owner browser session only | Stores secret in vault/keychain | `owner(...)` -> `auth::require_owner` (`lib.rs:1214`, `handlers_v1.rs:2018`) | ok |
| `DELETE /v1/secrets/{key}` | Owner browser session only | Deletes secret from vault/keychain | `owner(...)` -> `auth::require_owner` (`lib.rs:1218`, `handlers_v1.rs:2076`) | ok |
| `POST /v1/secrets/{key}/rotate` | Owner browser session only | Rotates secret via SSRF-checked webhook | `owner(...)` -> `auth::require_owner` (`lib.rs:1222`, `lifecycle.rs:819`) | ok |
| `GET /v1/secrets/rotations` | Owner browser session only | Lists rotation receipts | `owner(...)` -> `auth::require_owner` (`lib.rs:1226`, `lifecycle.rs:884`) | ok |
| `GET /v1/secrets/kms/status` | Owner browser session only | Returns KMS & Key Transparency health | `owner(...)` -> `auth::require_owner` (`lib.rs:1230`, `lifecycle.rs:498`) | ok |
| `POST /v1/secrets/kms/rotate-dek` | Owner browser session only | Rotates envelope KMS data encryption key | `owner(...)` -> `auth::require_owner` (`lib.rs:1234`, `lifecycle.rs:538`) | ok |
| `POST /v1/secrets/kms/migrate` | Owner browser session only | Migrates sovereign age vault to KMS envelope | `owner(...)` -> `auth::require_owner` (`lib.rs:1238`, `lifecycle.rs:504`) | ok |
| `GET /v1/oidc/discovery` | Authenticated user | Returns OIDC issuer discovery metadata | `auth::gate` (`auth.rs:1219`) | ok |
| `POST /v1/oidc/token` | Authenticated user | Issues short-lived EdDSA workload JWT (`human ∩ agent`) | `auth::gate` + `can_see_ref` + `PREMIER_OIDC_ALLOWED_AUDIENCES` (`lifecycle.rs:1117`) | ok |
| `POST /v1/oidc/verify` | Authenticated user | Verifies OIDC token signature, expiry, revocation, claims | `auth::gate` (`auth.rs:1219`, `lifecycle.rs:1251`) | ok |
| `POST /v1/security/offboard` | Owner browser session only | Revokes principal sessions/tokens/SSH keys/OIDC & rotates secrets | `owner(...)` -> `auth::require_owner` (`lib.rs:1245`, `lifecycle.rs:1578`) | ok |
| `GET /v1/security/offboard/receipts` | Owner browser session only | Lists offboarding receipts | `owner(...)` -> `auth::require_owner` (`lib.rs:1249`) | ok |
| `POST /v1/auth/offboard` | Owner browser session only | Alias for `POST /v1/security/offboard` | `owner(...)` + account_mgmt browser session guard (`auth.rs:1275`, `lib.rs:1253`) | ok |
| `GET /v1/audit` | Owner browser session only | Queries filtered tamper-evident audit events | `owner(...)` -> `auth::require_owner` (`lib.rs:1255`) | ok |
| `GET /v1/audit/export` | Owner browser session only | Streams full audit JSONL log | `owner(...)` -> `auth::require_owner` (`lib.rs:1256`, `ops.rs:186`) | ok |
| `GET /v1/settings` | Authenticated user | Returns read-only workspace settings & SSH URL | `auth::gate` (`auth.rs:1219`, `ops.rs:86`) | ok |
| `PATCH /v1/settings` | Owner browser session only | Updates validated `audit_retention_days` setting | `owner(...)` + `ops::require_session` (`lib.rs:1259`, `ops.rs:103`) | ok |
| `GET /v1/backup` | Owner browser session only | Builds private backup archive preserving audit log & head | `owner(...)` -> `auth::require_owner` (`lib.rs:1261`) | ok |
| `GET /v1/approvals` | Authenticated user (scoped: owners see all, members see own) | Lists pending JIT egress approvals | `auth::gate` + `owner_only` / principal scoping (`lib.rs:3180-3210`) | ok |
| `POST /v1/approvals/{id}/decide` | Owner browser session only | Approves or denies pending JIT request | `owner(...)` -> `auth::require_owner` (`lib.rs:1265`) | ok |
| `GET /v1/approvals/suggestions` | Owner browser session only | Lists policy learning suggestions | `owner(...)` -> `auth::require_owner` (`lib.rs:1269`) | ok |
| `POST /v1/approvals/suggestions/{id}/preview` | Owner browser session only | Previews policy rule suggestion diff | `owner(...)` -> `auth::require_owner` (`lib.rs:1273`) | ok |
| `POST /v1/approvals/suggestions/{id}/apply` | Owner browser session only | Applies suggested policy rule | `owner(...)` -> `auth::require_owner` (`lib.rs:1277`) | ok |
| `POST /v1/approvals/suggestions/{id}/dismiss` | Owner browser session only | Dismisses policy suggestion | `owner(...)` -> `auth::require_owner` (`lib.rs:1281`) | ok |
| `GET /v1/events/stream` | Authenticated user | SSE stream filtered per viewer & terminated on logout/shutdown | `auth::gate` + `request_user` entitlement recheck + `shutdown_ticks` (`lib.rs:3285-3490`) | ok |
| `GET /v1/traces` | Authenticated user | Lists scrubbed agent traces visible for caller branch/zone | `auth::gate` + `visible_sessions` branch visibility + trace ACL (`traces.rs:144-195`) | ok |
| `GET /v1/traces/blame` | Authenticated user | Searches trace spans filtered by branch visibility & zone ACL | `auth::gate` + `visible_sessions` + zone ACL (`traces.rs:144-215`) | ok |
| `POST /v1/traces/ingest` | Authenticated caller (`256 KiB` cap + rate limit) | Scrubs unlocked vault secrets & stores hash-chained span | `auth::gate` + `repository_redactor` + `scrub_span` (`traces.rs:63-142`, `traces.rs:219`) | ok |
| `POST /v1/traces/sample` | Owner browser session only | Seeds demo trace spans | `owner(...)` -> `auth::require_owner` (`lib.rs:1289`) | ok |
| `DELETE /v1/traces/{session_id}` | Owner browser session only | Deletes recorded trace session | `owner(...)` -> `auth::require_owner` (`lib.rs:1293`) | ok |
| `GET /v1/mcp/gateways` | Authenticated user | Lists permitted MCP servers/tools (hides rules from members) | `auth::gate` + `Lens` policy/secret/pin filtering (`mcp_gateway.rs:207-378`) | ok |
| `POST /v1/mcp/explain` | Owner browser session only | Explains MCP tool decision, pin, args & credentials | `owner(...)` -> `auth::require_owner` (`lib.rs:1297`) | ok |
| `GET /v1/mcp/alerts` | Owner browser session only | Lists MCP TOFU drift/poisoning quarantine alerts | `owner(...)` -> `auth::require_owner` (`lib.rs:1301`) | ok |
| `POST /v1/mcp/alerts/{id}/approve` | Owner browser session only | Approves drifted MCP tool schema pin | `owner(...)` -> `auth::require_owner` (`lib.rs:1305`) | ok |
| `POST /v1/mcp/alerts/{id}/dismiss` | Owner browser session only | Dismisses MCP drift alert | `owner(...)` -> `auth::require_owner` (`lib.rs:1309`) | ok |
| `POST /v1/mcp/rpc` | Authenticated caller | Executes policy/pin-gated MCP JSON-RPC call | `auth::gate` + `can_see_ref` + `PREMIER_ALLOW_REPO_STDIO_MCP` + `McpGateway` (`mcp_gateway.rs:663`) | ok |
| `GET /v1/agents/sessions` | Authenticated user | Lists agent sessions | `auth::gate` + `owner_only \|\| principal == actor_principal` (`handlers_v1.rs:1926`, `2293`) | ok |
| `POST /v1/agents/sessions` | Owner browser session only | Spawns sandboxed agent session | `owner(...)` -> `auth::require_owner` (`lib.rs:1316`, `handlers_v1.rs:2332`) | ok |
| `DELETE /v1/agents/sessions/{id}` | Owner browser session only | Discards stopped session workspace | `owner(...)` -> `auth::require_owner` (`lib.rs:1320`) | ok |
| `GET /v1/agents/sessions/{id}/diff` | Owner browser session only | Returns unified diff of agent workspace | `owner(...)` -> `auth::require_owner` (`lib.rs:1324`) | ok |
| `POST /v1/agents/sessions/{id}/stop` | Owner browser session only | Stops agent session | `owner(...)` -> `auth::require_owner` (`lib.rs:1328`) | ok |
| `POST /v1/agents/sessions/{id}/commit` | Owner browser session only | Commits allowed agent session edits | `owner(...)` -> `auth::require_owner` (`lib.rs:1332`) | ok |
| `POST /v1/agents/sessions/{id}/budget` | Owner browser session only | Raises session autonomy budget | `owner(...)` -> `auth::require_owner` (`lib.rs:1336`, `lifecycle.rs:155`) | ok |
| `GET /v1/agents/sessions/{id}/provenance` | Authenticated user (scoped by ownership/owner) | Returns filtered session provenance transcript | `auth::gate` + owner or session principal check (`handlers_v1.rs:1926`, `lanes.rs:2013`) | ok |
| `GET /v1/lanes` | Authenticated user | Lists agent lanes visible to viewer | `auth::gate` + `lane_visible_to` (`lanes.rs:251`, `lanes.rs:296`) | ok |
| `POST /v1/lanes` | Owner browser session only | Creates isolated agent lane | `owner(...)` -> `auth::require_owner` (`lib.rs:1344`, `lanes.rs:352`) | ok |
| `GET /v1/lanes/{lane_id}` | Authenticated user | Reads single lane visible to viewer | `auth::gate` + `lane_visible_to` (`lanes.rs:251`, `lanes.rs:316`) | ok |
| `DELETE /v1/lanes/{lane_id}` | Owner browser session only | Deletes agent lane | `owner(...)` -> `auth::require_owner` (`lib.rs:1348`, `lanes.rs:1326`) | ok |
| `POST /v1/lanes/{lane_id}/rebase` | Owner browser session only | Rebases agent lane | `owner(...)` -> `auth::require_owner` (`lib.rs:1352`, `lanes.rs:785`) | ok |
| `POST /v1/lanes/{lane_id}/resolve` | Owner browser session only | Resolves agent lane conflict | `owner(...)` -> `auth::require_owner` (`lib.rs:1356`, `lanes.rs:863`) | ok |
| `POST /v1/agents/sessions/{id}/pause` | Owner browser session only | Pauses running session | `owner(...)` -> `auth::require_owner` (`lib.rs:1360`) | ok |
| `POST /v1/agents/sessions/{id}/checkpoint` | Owner browser session only | Checkpoints running session workspace | `owner(...)` -> `auth::require_owner` (`lib.rs:1364`) | ok |
| `POST /v1/agents/sessions/{id}/resume` | Owner browser session only | Resumes paused session | `owner(...)` -> `auth::require_owner` (`lib.rs:1368`) | ok |
| `GET /v1/agents/sessions/{id}/workspace/files` | Owner browser session only | Lists files in agent session workspace | `owner(...)` -> `auth::require_owner` (`lib.rs:1372`) | ok |
| `GET /v1/agents/sessions/{id}/workspace/file` | Owner browser session only | Reads file in agent session workspace | `owner(...)` -> `auth::require_owner` (`lib.rs:1377`) | ok |
| `PUT /v1/agents/sessions/{id}/workspace/file` | Owner browser session only | Edits file in agent session workspace | `owner(...)` -> `auth::require_owner` (`lib.rs:1378`) | ok |
| `GET /v1/hygiene/insights` | Owner browser session only | Lists workspace hygiene insights | `owner(...)` + `owner_only` (`hygiene.rs:170`) | ok |
| `POST /v1/hygiene/dismiss` | Owner browser session only | Dismisses hygiene insight | `owner(...)` + `owner_only` (`hygiene.rs:208`) | ok |
| `POST /v1/hygiene/restore` | Owner browser session only | Restores hygiene insight | `owner(...)` + `owner_only` (`hygiene.rs:223`) | ok |
| `GET /v1/overlays` | Owner browser session only | Lists encrypted team/personal overlays | `owner(...)` -> `auth::require_owner` (`lib.rs:1393`) | ok |
| `POST /v1/overlays/check` | Owner browser session only | Checks paths against push-guard | `owner(...)` -> `auth::require_owner` (`lib.rs:1394`) | ok |
| `POST /v1/overlays/mount` | Owner browser session only | Mounts encrypted overlay | `owner(...)` -> `auth::require_owner` (`lib.rs:1397`, `handlers_v1.rs:2169`) | ok |
| `POST /v1/overlays/unmount` | Owner browser session only | Unmounts overlay | `owner(...)` -> `auth::require_owner` (`lib.rs:1401`, `handlers_v1.rs:2250`) | ok |
| `GET /v1/branches` | Authenticated user | Lists visible branches only | `auth::gate` + `can_see_ref` filtering (`lib.rs:3638`) | ok |
| `GET /v1/worktable` | Authenticated user | Returns visible branches/lanes/reviews summary | `auth::gate` + visibility filtering (`worktable.rs:139`) | ok |
| `POST /v1/branches/create` | Authenticated user (members capped & restricted to personal visibility on visible bases) | Creates private branch ref | `auth::gate` + `resolve_accessible_refs` + non-owner checks (`handlers_v1.rs:951-1035`) | ok |
| `POST /v1/branches/publish` | Owner browser session only | Runs Squash-Declassify publish | `owner(...)` -> `auth::require_owner` (`lib.rs:1411`, `handlers_v1.rs:1236`) | ok |
| `DELETE /v1/branches/{*name}` | Owner browser session only | Deletes branch ref & visibility metadata | `owner(...)` -> `auth::require_owner` (`lib.rs:1415`, `handlers_v1.rs:1120`) | ok |
| `POST /v1/branches/visibility` | Owner browser session only | Updates branch visibility ACL (propagates save errors) | `owner(...)` -> `auth::require_owner` (`lib.rs:1419`) | ok |
| `POST /v1/branches/squash-preview` | Authenticated user | Previews squash-declassify diff for visible ref | `auth::gate` + `can_see_ref` & `READ` filtering (`lib.rs:3904`) | ok |
| `GET /v1/commits` | Authenticated user | Lists commits projected for caller | `auth::gate` + `content_source` & projected history (`lib.rs:4914`) | ok |
| `GET /v1/commits/{oid}` | Authenticated user | Returns projected commit diff only | `auth::gate` + projected OID validation (`lib.rs:5106`) | ok |
| `GET /v1/attestations/{oid}` | Authenticated user | Returns projection attestation if caller sees OID | `auth::gate` + OID visibility (`lib.rs:5082`) | ok |
| `GET /v1/reviews` | Authenticated user | Lists reviews on visible branches | `auth::gate` + visibility filtering (`lib.rs:5281`) | ok |
| `POST /v1/reviews` | Authenticated user | Opens review on visible branch | `auth::gate` + `effective_principal` + branch visibility (`handlers_v1.rs:1521`) | ok |
| `POST /v1/reviews/{change_id}/comments` | Authenticated user | Adds comment on visible review | `auth::gate` + `effective_principal` + review visibility (`handlers_v1.rs:1785`) | ok |
| `POST /v1/reviews/{change_id}/verdict` | Authenticated user | Records review verdict on visible review | `auth::gate` + visibility/role check (`handlers_v1.rs:1937`) | ok |
| `GET /v1/reviews/{change_id}/interdiff` | Authenticated user | Returns zone-projected review interdiff | `auth::gate` + projection/visibility checks (`lanes.rs:1407`) | ok |
| `POST /v1/reviews/{change_id}/steer` | Owner browser session only | Steers active review lane | `owner(...)` -> `auth::require_owner` (`lib.rs:1443`, `lanes.rs:1612`) | ok |
| `GET /git/repo.git/info/refs` | Anonymous or authenticated (`service=git-receive-pack` requires auth) | Advertises projected refs only | `auth::gate` (`auth.rs:1228-1244`) + `hide_from_strangers` (`repos.rs:402`) + projection (`handlers_v1.rs:2517`) | ok |
| `POST /git/repo.git/git-upload-pack` | Anonymous or authenticated | Projects requested refs/packfile (anti-CFOR & OID-isolated) | `auth::gate` + `hide_from_strangers` + `GIT_FETCH_BODY_LIMIT` (`lib.rs:1451`) + `projector.rs` | ok |
| `POST /git/repo.git/git-receive-pack` | Authenticated writer only | Receives pushed objects/refs via policy, firewall, and branch visibility | `auth::gate` (`needs_account`) + push slots + `receive_pack.rs` (`handlers_v1.rs:2569`) | ok |
| `GET /git/auth/repo.git/info/refs` | Authenticated user only | Same as above with mandatory identity challenge | `auth::gate` (`path.starts_with("/git/auth/")` requires account at `auth.rs:1233`) | ok |
| `POST /git/auth/repo.git/git-upload-pack` | Authenticated user only | Authenticated fetch projection | `auth::gate` (`needs_account` at `auth.rs:1233`) + `hide_from_strangers` + `projector.rs` | ok |
| `POST /git/auth/repo.git/git-receive-pack` | Authenticated user only | Authenticated push validation | `auth::gate` (`needs_account` at `auth.rs:1233`) + `receive_pack.rs` | ok |
| `GET /v1/auth/status` | Any caller (CSRF exempt GET) | Reports setup/login state | Public auth bootstrap endpoint (`auth.rs:1258`, `1622`) | ok |
| `POST /v1/auth/setup` | Unauthenticated ONLY when zero accounts exist | Creates initial owner account (Argon2id >=10 chars) | `auth::gate` CSRF `same_origin` (`auth.rs:1263`) + single-setup check (`auth.rs:1642`) | ok |
| `POST /v1/auth/login` | Unauthenticated/public with lockout + optional TOTP | Verifies Argon2id password & TOTP, issues `HttpOnly` cookie | `auth::gate` CSRF `same_origin` + lockout/semaphore (`auth.rs:39-50`, `1686`) | ok |
| `POST /v1/auth/logout` | Authenticated browser session | Revokes current session in SQLite | `auth::gate` (`account_mgmt` rejects tokens at `auth.rs:1275`) + `logout_handler` (`1775`) | ok |
| `POST /v1/auth/password` | Authenticated browser session | Verifies current password, updates hash, revokes sessions | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `password_handler` (`1802`) | ok |
| `PATCH /v1/auth/profile` | Authenticated browser session | Updates caller display name | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `profile_handler` (`1836`) | ok |
| `GET /v1/auth/sessions` | Authenticated browser session | Lists caller's own active sessions | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `list_sessions_handler` (`1854`) | ok |
| `POST /v1/auth/sessions/revoke-others` | Authenticated browser session | Revokes caller's other sessions | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `1911` | ok |
| `DELETE /v1/auth/sessions/{id}` | Authenticated browser session | Revokes caller's specified session | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `1880` | ok |
| `GET /v1/auth/tokens` | Authenticated browser session | Lists caller's own API tokens (hashes never returned) | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `1932` | ok |
| `POST /v1/auth/tokens` | Authenticated browser session | Mints `prm_` token (scoped optionally by agent profile) | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `1958` | ok |
| `DELETE /v1/auth/tokens/{id}` | Authenticated browser session | Revokes caller's token | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `2022` | ok |
| `GET /v1/auth/ssh-keys` | Authenticated browser session | Lists caller's registered SSH keys | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `2050` | ok |
| `POST /v1/auth/ssh-keys` | Authenticated browser session | Validates & stores caller's SSH public key | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `2074` | ok |
| `DELETE /v1/auth/ssh-keys/{id}` | Authenticated browser session | Revokes caller's SSH public key | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `2088` | ok |
| `POST /v1/auth/totp/begin` | Authenticated browser session | Generates pending TOTP secret | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `2102` | ok |
| `POST /v1/auth/totp/enable` | Authenticated browser session | Verifies TOTP code & enables 2FA | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `2144` | ok |
| `POST /v1/auth/totp/disable` | Authenticated browser session | Requires password & disables 2FA | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `2209` | ok |
| `POST /v1/auth/totp/recovery-codes` | Authenticated browser session | Regenerates hashed recovery codes | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `2175` | ok |
| `GET /v1/auth/events` | Authenticated browser session | Lists caller's own auth audit events (all if owner) | `auth::gate` (`account_mgmt` browser-only `auth.rs:1275`) + `2237` | ok |
| `GET /v1/users` | Owner browser session only | Lists workspace user accounts | `owner(...)` + `account_mgmt` (`lib.rs:1509`, `auth.rs:2277`) | ok |
| `POST /v1/users` | Owner browser session only | Creates workspace user account | `owner(...)` + `account_mgmt` (`lib.rs:1509`, `auth.rs:2295`) | ok |
| `PATCH /v1/users/{username}` | Owner browser session only | Updates user role/disabled flag & revokes sessions if disabled | `owner(...)` + `account_mgmt` (`lib.rs:1513`, `auth.rs:2333`) | ok |
| `DELETE /v1/users/{username}` | Owner browser session only | Deletes non-last owner user account | `owner(...)` + `account_mgmt` (`lib.rs:1513`, `auth.rs:2397`) | ok |
| `GET /v1/directory` | Authenticated user | Returns directory principals/groups scoped to caller | `auth::gate` + `owner_only` / principal scoping (`directory.rs:307`) | ok |
| `PUT /v1/directory/principals/{principal}` | Owner browser session only | Sets directory principal groups | `owner(...)` -> `auth::require_owner` (`lib.rs:1519`, `directory.rs:330`) | ok |
| `DELETE /v1/directory/principals/{principal}` | Owner browser session only | Removes directory principal mapping | `owner(...)` -> `auth::require_owner` (`lib.rs:1519`, `directory.rs:372`) | ok |
| `GET /v1/github/status` | Owner browser session only | Returns GitHub companion connection status (no token) | `owner(...)` + `ops::require_session` (`lib.rs:1522`, `github.rs:2038`) | ok |
| `PUT /v1/github/config` | Owner browser session only | Configures encrypted GitHub PAT & allowlisted enterprise hosts | `owner(...)` + `ops::require_session` (`lib.rs:1525`, `github.rs:2048`) | ok |
| `DELETE /v1/github/config` | Owner browser session only | Disconnects GitHub companion & deletes encrypted token | `owner(...)` + `ops::require_session` (`lib.rs:1525`, `github.rs:2057`) | ok |
| `POST /v1/github/pr/preview` | Owner browser session only | Previews Squash-Declassify PR diff | `owner(...)` + `ops::require_session` (`lib.rs:1529`, `github.rs:2068`) | ok |
| `POST /v1/github/pr/publish` | Owner browser session only | Pushes sanitized PR branch & creates GitHub PR | `owner(...)` + `ops::require_session` (`lib.rs:1533`, `github.rs:2081`) | ok |
| `POST /v1/github/sync/out` | Owner browser session only | Syncs authorized public zone to GitHub | `owner(...)` + `ops::require_session` (`lib.rs:1535`, `github.rs:2091`) | ok |
| `POST /v1/github/sync/in` | Owner browser session only | Imports GitHub changes cleanly through firewall | `owner(...)` + `ops::require_session` (`lib.rs:1536`, `github.rs:2101`) | ok |
| `SSH exec git-upload-pack / git-receive-pack` | Public-key authenticated SSH users only | Serves projected upload-pack or push receive-pack | Publickey-only (`premier-ssh/src/lib.rs:1185-1242`), command allowlist & PTY/shell/forwarding refusal (`1244-1370`) | ok |
| `Proxy /cap/{token}/{var}/* & HTTPS CONNECT` | Per-session bearer/Basic proxy token on loopback/Unix socket | Swaps placeholder for secret only on schema-declared TLS hosts | Constant-time token check, SSRF IP block, TLS+port enforcement, body/base64 scrubbing (`premier-proxy/src/proxy.rs`) | ok |
| `CLI premier * (init, doctor, access, overlay, env, run, proxy, agent, mcp, branch, github, auth, backup, restore, serve, trace)` | Local workspace operator running `premier` | Operates local repository, state SQLite, vaults, sandboxes, MCP stdio server | OS user DAC + `--allow-unsandboxed` explicit opt-in, stdin secret inputs, private file mode `0o600` (`crates/premier-cli/src/main.rs:62-835`) | ok |
