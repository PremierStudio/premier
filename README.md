# Premier

Premier is a self-hosted source-control server that ordinary `git` clients can clone from and push to.
It decides, per person, which files and which branches they receive, and it enforces that on the server: a clone contains only what the policy allows.
It also keeps secrets in a vault and lets an AI agent use a secret through a proxy without ever seeing its value.

## What works today

- **Git over HTTP and SSH.** `git clone`, `git fetch` and `git push` (including `--force-with-lease`, `git push --delete`, and lightweight or annotated tags under `refs/tags/*`) against a server-side projection of the repository. Files, branches and tags pointing to commits you may not see are left out of the history you receive. Enable the optional pure-Rust SSH listener with `--ssh-bind` / `PREMIER_SSH_BIND` (public-key auth, same projected engine).
- **Path access rules** in `.access.toml`: allow and deny rules over principals, path globs and branches, with five capabilities (`traverse`, `list`, `read`, `write`, `use`). Deny overrides allow. An optional server policy overrides the repository's.
- **Private branches and Squash-Declassify publish.** A branch can be public, visible to everyone signed in, restricted to a list of people and groups, or personal. Publishing lands public changes onto a target branch as one squashed commit with 3-way line-level merging for non-overlapping text edits, while scrubbing restricted paths and refusing overlapping or binary conflicts.
- **Accounts.** Owners and members, passwords, two-factor (TOTP) with recovery codes, sessions, access tokens, SSH keys, login lockout.
- **Several repositories** behind one server and one set of accounts. Create an empty one or import one from an `https://` URL.
- **The Studio**, a web UI served by the same process: browse code as yourself or truthfully **"View as"** someone else across Files, Branches, and Secrets with safe Markdown preview, a responsive branch switcher, and deep-linkable URLs; run and stop/kill agent sessions, inspect inline unified diffs, commit a session to a new branch and open Review with line-anchored inline comments, Prompt Blame, and Publish handoff; approve live secret requests from any page via the Global Floating JIT Approval popover; edit and test the policy, and manage branches, secrets, users and settings.
- **Secret vault, agent sessions, and MCP.** Secrets are declared in `.env.schema` and stored encrypted on the server (or in a local sovereign `age` vault via `premier env set --stdin` using `.premier-local/age.key` or `PREMIER_AGE_IDENTITY`). An agent session gets placeholder tokens; a local proxy swaps in the real value only on requests to the hosts the schema allows, and scrubs it from the session's output. `premier mcp serve` and `premier mcp config` expose Premier's policy evaluator, `.env.schema` metadata (zero raw secrets), overlay leak guard, and policy impact diff to Claude Code, Codex, and Cursor.
- **Envelope KMS and OIDC federation.** Vault entries are encrypted under per-vault AES-256-GCM data keys wrapped by a separate KEK (`PREMIER_KMS_KEY`, `PREMIER_KMS_URI`, or HashiCorp Vault Transit), with optional read-through from Vault KV v2 or 1Password Connect. `premier env kms status|migrate|rotate-dek` manages it. The control plane signs short-lived workload tokens (EdDSA / Ed25519 JWTs scoped to `human ∩ agent_profile`, with an RFC 8693 `act` claim for delegated agents) and publishes the verification keys at `/.well-known/jwks.json` and discovery at `/.well-known/openid-configuration`. `premier env oidc-token` mints one.
- **Dual-phase secret rotation and Key Transparency.** Variables with `[vars.X.rotation]` rotate through signed `prepare` → vault write → `commit` webhooks (with `rollback` on failure) via `premier env rotate`, and one-click offboarding dispatches rotation or records manual revocation. Vault recipients and key identifiers are bound into an append-only hash-chained Key Transparency log that fails closed on tampering or a silent key swap.
- **GitHub Companion.** `premier github connect|status|preview-pr|publish-pr|disconnect` (and the Studio) project a policy zone to GitHub as a single Squash-Declassify commit and pull request, and sync zones in and out, without ever sending paths the policy hides.
- **Agent traces.** The `premier-trace` crate records agent runs as per-span SHA-256 hash chains with secret scrubbing and a causal-blame graph. Hooks and OTLP/HTTP JSON ingest feed it; `premier trace list|verify|hook-config` inspects it, and the Studio's **Traces** tab shows the inspector (timeline, diffs, security, raw spans).
- **Durable control plane.** Control-plane state is persisted in SQLite (WAL mode), and `premier backup --out <file>` (or **Settings → Workspace → Download backup**) takes a per-repository archive that `premier restore` puts back.
- **Production operations.** `/health`, `/livez` (liveness) and `/readyz` (readiness) endpoints, Prometheus metrics at `/metrics`, structured logs with `premier serve --log-format json`, a request id (`X-Request-Id`) on every response, security headers (`nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Content-Security-Policy`), and rate limiting. A hardened systemd unit, a Docker image, and Windows notes are in [docs/ssh-and-deploy.md](docs/ssh-and-deploy.md).
- **1-command HTTPS deployment.** `deploy/docker-compose.yml` and `deploy/Caddyfile` run Premier behind Caddy with automatic Let's Encrypt TLS, pinned trusted-proxy headers, unbuffered SSE/Git streaming, and optional SSH.
- **Audit log**, with retention and export.

## Designed, not built

`docs/architecture-blueprint.md` describes the full design. These parts of it are not in the code:

- A lazy virtual filesystem (FUSE, ProjFS, FSKit). `premier doctor` only reports whether the host has them.
- A native `jj`-compatible client and protocol, and the Bonsai/Prolly-tree storage engine. Premier stores history in a normal Git repository on disk.
- HSM-backed key wrapping and SPIFFE identities. Envelope KMS, OIDC workload tokens and RFC 8693 delegation ship; the sovereign `age` vault key is a file next to the vault (CLI commands can also supply it via `PREMIER_AGE_IDENTITY`).
- Provider-specific rotation adapters. Rotation runs through your own signed webhooks; Premier ships no per-provider integrations.
- GitHub as a full mirror. GitHub Companion publishes policy zones as squashed pull requests and syncs zones; it does not mirror history Premier hides.
- Built-in TLS. Put a reverse proxy in front for HTTPS (such as the bundled Caddy Compose stack in `deploy/`).
- Transparency-logged (Sigstore-style) projection attestations.

## Quick start

### Run the server in 60 seconds (Docker, no `sudo`)

Named Docker volumes need no host directories and no `chown`. The first command creates the default repository inside its volume; the second starts the server.

```sh
docker run --rm -v premier-repo:/srv/repo ghcr.io/premierstudio/premier:latest git init -q -b main /srv/repo

docker run -d --name premier -p 7420:7420 \
  -v premier-repo:/srv/repo \
  -v premier-state:/var/lib/premier \
  -v premier-repos:/srv/repos \
  ghcr.io/premierstudio/premier:latest
```

`premier-state` holds accounts, vaults, keys and audit logs, `premier-repos` holds repositories you create in the Studio, and `premier-repo` is the default repository. They survive `docker rm` and image upgrades. The container runs as uid `10001`, never root.

1. Open `http://localhost:7420`. The Studio shows **Create the owner account**. Pick a username and a password of at least 10 characters.
2. Go to **Settings → Access tokens**, name a token and choose **Create token**. Copy it now; it is shown once. It starts with `prm_`.
3. Open the repository menu in the top bar and choose **New repository…**. Name it, for example `notes`.
4. Push an existing project from its folder. When `git` asks for a password, paste the token.

```sh
git remote add premier http://<username>@localhost:7420/git/auth/notes.git
git push -u premier main
```

To clone it somewhere else:

```sh
git clone http://<username>@localhost:7420/git/auth/notes.git
```

There are two URL shapes for every repository:

- `/git/auth/<name>.git` always asks for credentials.
- `/git/<name>.git` serves the anonymous view when no credentials are sent. With the starter policy anonymous callers get nothing, and for a repository like `notes` the server answers "repository not found".

A new repository starts with a policy that gives owners everything and everyone else nothing. [docs/getting-started.md](docs/getting-started.md) shows how to add a member and grant access.

### Install the `premier` CLI

Prebuilt binaries are attached to every [release](https://github.com/PremierStudio/premier/releases). The installers download the archive for your platform and verify its SHA-256 checksum.

```sh
# Linux and macOS
curl -fsSL https://raw.githubusercontent.com/PremierStudio/premier/main/deploy/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/PremierStudio/premier/main/deploy/install.ps1 | iex
```

With a Rust toolchain (1.89 or newer) you can install from crates.io instead. `cargo binstall premier-cli` fetches the same release binary; `cargo install premier-cli` compiles it. A binary built by `cargo install` does not include the Studio web UI: Git, the API and the CLI work, and `PREMIER_STATIC_UI_DIR` can point at the `ui/` folder of a release archive.

```sh
cargo install premier-cli
```

### Start a Premier repository

`premier init` prepares the current directory: it runs `git init -b main` if it is not a repository yet and writes a starter `.access.toml` (owners get everything, everyone else nothing) and `.env.schema`. Running it again leaves existing files alone.

```sh
mkdir my-project && cd my-project
premier init
git add .access.toml .env.schema && git commit -m "Add Premier policy"
premier serve --bind 127.0.0.1:7420
```

The server enforces the `.access.toml` and `.env.schema` committed on the default branch, not the working copy. Use `premier access` to evaluate and diff policies, and `premier doctor` to check the host.

### Personal and team overlays

`premier overlay` mounts files that sit on top of a branch for one person or one team, such as local agent instructions or editor settings, without ever entering public history. Overlay content is kept encrypted in the state directory, not in the working tree, and the push guard refuses any commit that would include it.

```sh
premier overlay mount AGENTS.local.md --file ./my-notes.md          # personal (default)
premier overlay mount .vscode/settings.json --scope team:backend --file ./settings.json
premier overlay list --principal @local --group backend
premier overlay check-push AGENTS.local.md src/main.rs               # exits 1 if an overlay would leak
premier overlay unmount AGENTS.local.md
```

The [MCP guide](docs/mcp-guide.md) shows how agents use the same push guard through `premier_overlays_check`.

## Production deployment

For a server other people use, put Premier behind HTTPS and decide where its data lives.

- **HTTPS in one command.** `deploy/docker-compose.yml` and `deploy/Caddyfile` run Premier behind Caddy with automatic Let's Encrypt certificates. See [docs/ssh-and-deploy.md](docs/ssh-and-deploy.md).
- **Host directories instead of volumes.** If you bind-mount host directories (for example `/srv/premier/repo`, `/srv/premier/repos`, `/srv/premier/state`), they must be owned by the container's user: `sudo chown -R 10001:10001 <dirs>`, and the repository directory must be initialized with `git init -b main` first. The [admin guide](docs/admin-guide.md#docker) has the full command.
- **Agent-session sandbox on Linux.** Agent sessions run inside bubblewrap (`bwrap`), which needs two extra Docker options: `--security-opt seccomp=unconfined --security-opt systempaths=unconfined`. Without them the server refuses agent sessions; everything else works. See [Docker and seccomp](docs/admin-guide.md#docker-and-seccomp) and [docs/security.md](docs/security.md).
- **No Docker.** A hardened systemd unit and Windows service notes are in [docs/ssh-and-deploy.md](docs/ssh-and-deploy.md).

## Documentation

- [Getting started](docs/getting-started.md): first run, two-factor, repositories, a first member and a first rule.
- [Policy guide](docs/policy-guide.md): the `.access.toml` format, with worked examples.
- [MCP guide](docs/mcp-guide.md): `premier mcp serve` and `premier mcp config` for Claude Code, Codex, and Cursor.
- [SSH & deployment](docs/ssh-and-deploy.md): HTTPS Docker Compose stack, systemd and Windows deployment, health/readiness/metrics, backup and restore, and pure-Rust Git over SSH.
- [Admin guide](docs/admin-guide.md): installation, flags, HTTPS, backup, recovery, troubleshooting.
- [Security](docs/security.md): what Premier protects, and its known limits.
- [Architecture blueprint](docs/architecture-blueprint.md) and [research synthesis](docs/research-synthesis.md): the design this is built towards.
- [AGENTS.md](AGENTS.md): engineering invariants for contributors.
- [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md): how to contribute, how to report a vulnerability, and what changed.

## Repository layout

| Path | Contents |
| --- | --- |
| `crates/premier-cli` | The `premier` binary: `init`, `serve`, `backup`, `restore`, `auth`, `access`, `overlay`, `env`, `run`, `proxy`, `agent`, `mcp`, `branch`, `github`, `trace`, `doctor`. |
| `crates/premier` | Umbrella library crate that re-exports the crates below. |
| `crates/premier-server` | HTTP API, accounts, repositories, backup, agent session runner. |
| `crates/premier-git-bridge` | Projected Git fetch, push, force-push, tags, and Squash-Declassify 3-way merge engine. |
| `crates/premier-ssh` | Pure-Rust Git-over-SSH transport (public-key auth, strict exec allow-list, projected packs). |
| `crates/premier-policy` | `.access.toml` parser and evaluator. |
| `crates/premier-secrets` | `.env.schema`, the encrypted vault, output redaction. |
| `crates/premier-proxy` | The egress proxy that swaps placeholders for secrets, and the agent sandbox. |
| `crates/premier-overlay` | Overlay manifest and the push guard for overlay files. |
| `crates/premier-trace` | Agent trace store: hash-chained spans, scrubbing, OTLP/hook ingest, causal blame. |
| `crates/premier-core` | Shared types: principals, capabilities, paths. |
| `apps/web` | The Studio (React, built with Vite). |
| `deploy` | Docker Compose + Caddy HTTPS stack, and the hardened `premier.service` systemd unit. |
| `fixtures/demo` | Sample policy and secret schema fixtures (`.access.toml`, `server-policy.toml`, `.env.schema`). |
| `Dockerfile` | Builds the Studio and the binary into one image. |
| `.github/workflows` | CI (fmt, clippy, tests, Studio build) and tagged releases (binaries, checksums, GHCR image). |

To run from source instead of Docker or a release binary:

```sh
pnpm --dir apps/web install && pnpm --dir apps/web build
cargo run -p premier-cli -- serve --bind 127.0.0.1:7420
```

The server treats the directory it starts in as the default repository and looks for the Studio build in `apps/web/dist` under it. To serve a different directory, start there and point `PREMIER_STATIC_UI_DIR` at the built `dist` folder.

Run the Studio's tests with `pnpm --dir apps/web test:all` (unit, component and Node tests, no server needed). `pnpm --dir apps/web test:smoke` probes a running server's health, OIDC, metrics, security-header and UI-bundle endpoints (`PREMIER_URL` or `--url`, default `http://127.0.0.1:7420`).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
