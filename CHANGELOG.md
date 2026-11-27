# Changelog

All notable changes to Premier are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-27

First public release.

### Added

- **Git over HTTP and SSH** against a per-caller server-side projection: clone, fetch, push, force-with-lease, branch and tag deletion. Hidden files, branches and tags are left out of the history a caller receives. Optional pure-Rust SSH listener.
- **`.access.toml` policy engine** with `traverse`, `list`, `read`, `write` and `use` capabilities, deny-overrides-allow, and server policy overriding repository policy.
- **Private branches and Squash-Declassify publishing** with 3-way line-level merging and restricted-path scrubbing.
- **Accounts**: owners and members, passwords, TOTP two-factor with recovery codes, sessions, access tokens, SSH keys and login lockout. Multiple repositories per server.
- **The Studio** web UI: browse as yourself or "View as" another person, agent sessions, review with inline comments, Prompt Blame, policy editing and impact diff, secrets, branches, users and settings.
- **Secret vault** declared by `.env.schema`, with envelope KMS (local KEK, `PREMIER_KMS_URI` or HashiCorp Vault Transit), Vault KV v2 and 1Password Connect read-through, and a sovereign `age` mode with a Key Transparency log.
- **Capability-proxied agent sessions**: placeholders instead of secrets, a host-side egress proxy, output scrubbing, autonomy budgets, a bubblewrap sandbox on Linux and Job Object limits on Windows.
- **OIDC workload identity**: EdDSA (Ed25519) tokens scoped to `human ∩ agent_profile` with an RFC 8693 `act` claim, JWKS and discovery endpoints.
- **Dual-phase secret rotation** over signed webhooks, and one-click offboarding.
- **Typed overlays**: encrypted personal and team files mounted over a branch, with a push guard (`premier overlay`).
- **MCP**: `premier mcp serve`/`config` for Claude Code, Codex and Cursor, and a policy-unified MCP gateway with tool pinning and quarantine.
- **GitHub Companion** for publishing policy zones as squashed pull requests.
- **Agent traces** with hash-chained spans, scrubbing, OTLP and hook ingest, and an inspector in the Studio.
- **Operations**: SQLite (WAL) control-plane state, backup and restore, `/livez`, `/readyz`, `/health`, Prometheus `/metrics`, JSON logs, security headers, rate limiting, a Docker image, a Caddy HTTPS Compose stack and a hardened systemd unit.

[Unreleased]: https://github.com/PremierStudio/premier/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PremierStudio/premier/releases/tag/v0.1.0
