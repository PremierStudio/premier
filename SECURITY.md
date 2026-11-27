# Security policy

Premier is an access-control and secret-brokering system, so we treat security reports as our highest priority.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a suspected vulnerability.**

Report it privately through GitHub's coordinated disclosure form:

**<https://github.com/PremierStudio/premier/security/advisories/new>**

Please include:

- the affected version or commit, and how Premier was run (Docker image, release binary, `cargo install`, source);
- the component (Git transport, policy engine, Studio, vault, egress proxy, agent sandbox, MCP gateway, SSH, GitHub Companion);
- steps to reproduce, or a proof of concept, and the impact you observed;
- whether the issue is already public anywhere.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledgement of your report | within **48 hours** |
| Triage: confirmed or not, severity, and a plan | within **7 days** |
| Fix and advisory for critical and high severity issues | as fast as we can, usually within 30 days |

We will keep you updated while we work on it, agree a disclosure date with you, and credit you in the advisory unless you ask us not to. We ask that you give us a reasonable chance to ship a fix before disclosing publicly, and that you do not access, change or keep data that is not yours while testing.

## Supported versions

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |
| anything older | No |

Security fixes land on `main` and ship in a new `0.1.x` release, the `ghcr.io/premierstudio/premier` image and the crates on crates.io.

## Scope

In scope: anything that lets a caller receive file contents, file names, object IDs, branches, tags, reviews, traces or secret values the policy should hide from them; bypasses of authentication, two-factor, access tokens or SSH key auth; ways for an agent session to read a raw secret, escape its sandbox or egress proxy, or widen its own permissions; tampering with the audit log, Key Transparency log or trace hash chains that goes undetected; and server-side request forgery from imports, rotation webhooks, KMS or GitHub Companion.

Known, documented limits are not vulnerabilities by themselves. They are listed in [docs/security.md](docs/security.md#known-limitations).

## Security architecture in brief

Premier enforces access at the server's protocol boundary, never through client-side filters:

- **Path and branch confidentiality.** Each clone or fetch is built from a per-caller projection of the repository. Objects, files, branches and tags the policy hides are not in the pack, and unauthorized object IDs are not acknowledged.
- **Policy.** `.access.toml` rules are deny-overrides-allow, and a server policy overrides the repository's. The same evaluator decides Git transport, the Studio, search, traces and the MCP tools.
- **Secrets: use is not read.** Values are encrypted in a vault (envelope KMS or a local `age` key). Agent sessions get placeholders; the egress proxy swaps in the real value only on requests to hosts the schema allows and scrubs it from output.
- **Agents.** An agent's authority is `permissions(human) ∩ permissions(agent_profile)`, carried in short-lived EdDSA (Ed25519) workload tokens with an RFC 8693 `act` claim. On Linux, sessions run in a bubblewrap sandbox whose only network is its own proxy.

[docs/security.md](docs/security.md) describes the threat model and the known limits in full.
