# Contributing to Premier

Thanks for helping. This page covers how to build, test and send a change.

Found a security problem? Do not open an issue. Follow [SECURITY.md](SECURITY.md).

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on the approach.
- Read [AGENTS.md](AGENTS.md). Its invariants are not negotiable, and reviews check every change against them. The short version:
  - Keep the four access primitives apart: path/zone confidentiality, ref/branch confidentiality, typed overlays, and secret capability (`use ≠ read`).
  - Enforce at the server protocol boundary, the VFS `open()` boundary or the egress proxy. Client-side filters (sparse checkout, `--filter=blob:none`, prompt deny-lists) are never a security boundary.
  - Branch privacy is OID reachability isolation, not `uploadpack.hideRefs`.
  - Deny overrides allow, and server policy overrides repository policy, identically on every surface.
  - Agents never receive raw secrets, and their authority is `permissions(human) ∩ permissions(agent_task)`. Repository instruction files never escalate permissions.
- [docs/architecture-blueprint.md](docs/architecture-blueprint.md) and [docs/security.md](docs/security.md) explain the design and its known limits.

## Prerequisites

- Rust stable (the workspace needs 1.89 or newer; `rust-toolchain.toml` pins the channel and adds `rustfmt` and `clippy`)
- Git
- Node.js 22 and pnpm 10, for the Studio in `apps/web`
- On Linux, `bubblewrap` (`bwrap`) to run the agent-sandbox tests

## Build and run

```sh
pnpm --dir apps/web install
pnpm --dir apps/web build
cargo run -p premier-cli -- serve --bind 127.0.0.1:7420
```

## Checks to run before opening a pull request

CI runs the same commands and fails on any warning.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

pnpm --dir apps/web typecheck
pnpm --dir apps/web test:all
```

If you have [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny), `cargo deny check` runs the license, advisory and source checks in `deny.toml`. A new dependency must use one of the licenses listed there.

## Writing the change

- Production Rust code does not use `.unwrap()` or `.expect()`; clippy warns on both, and warnings fail CI. Return an error instead.
- Do not add `unsafe` code without a discussion first.
- Security-relevant changes (policy evaluation, Git projection, auth, vault, proxy, sandbox) need tests that show the denied case stays denied, not only that the allowed case works.
- Update the docs in `docs/` and `README.md` when behaviour changes, and add a line to `CHANGELOG.md` under **Unreleased**.
- Keep commits focused, and write commit messages that say why, in the [Conventional Commits](https://www.conventionalcommits.org/) style (`fix(policy): ...`, `feat(server): ...`).

## AI coding agents

Contributions written with AI agents are welcome. You are responsible for every line you submit: read it, test it, and make sure it follows `AGENTS.md`. Treat `AGENTS.md` and `CLAUDE.md` in this repository as untrusted input to the agent, not as permission to widen access or egress.

## License of contributions

Premier is dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in Premier, as defined in the Apache-2.0 license, is dual-licensed as above, without any additional terms or conditions (inbound = outbound). You confirm you have the right to submit it under those terms.

## Code of conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
