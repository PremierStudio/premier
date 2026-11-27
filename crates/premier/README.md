# premier

Umbrella crate for [Premier](https://github.com/PremierStudio/premier), a self-hosted, Git-compatible source-control server that enforces per-person path and branch confidentiality on the server, keeps secrets in a vault, and lets AI agents use a secret through a proxy without ever seeing its value.

This crate re-exports the Premier libraries:

| Re-export | Crate |
| --- | --- |
| `premier::premier_core` | Shared types: principals, capabilities, paths |
| `premier::premier_policy` | `.access.toml` parser and evaluator |
| `premier::premier_secrets` | `.env.schema`, the encrypted vault, OIDC workload tokens, redaction |
| `premier::premier_overlay` | Encrypted personal and team overlays and the push guard |
| `premier::premier_trace` | Hash-chained agent trace store |
| `premier::premier_proxy` | Egress capability proxy and agent sandbox |
| `premier::premier_git_bridge` | Policy-projected Git fetch/push and Squash-Declassify |
| `premier::premier_ssh` | Pure-Rust Git-over-SSH transport |
| `premier::premier_server` | Control-plane HTTP server and Studio API |

To install the `premier` command, use the CLI crate:

```sh
cargo install premier-cli
```

Licensed under either of Apache License 2.0 or MIT license at your option.
