## What and why

<!-- What does this change, and why? Link the issue: "Fixes #123". -->

## How it was tested

<!-- Commands you ran and what you checked by hand. -->

## Checklist

- [ ] `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass
- [ ] `pnpm --dir apps/web typecheck` and `pnpm --dir apps/web test:all` pass (if the Studio changed)
- [ ] The change follows the invariants in [AGENTS.md](../AGENTS.md); security-relevant code has tests for the denied case
- [ ] Docs and `CHANGELOG.md` are updated where behaviour changed
- [ ] No secrets, tokens or private paths in the diff, tests or fixtures

<!-- Security vulnerabilities: do not open a PR. Report privately via SECURITY.md. -->
