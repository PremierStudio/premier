# AGENTS.md — Premier Engineering Guidelines

This repository houses **Premier**, a post-Git, Git-compatible source control and capability platform designed around granular access control, native secret brokering, and AI-agent-safe workflows.

## Non-Negotiable Architectural Invariants

1. **Never conflate the four access primitives:**
   - **Path/Zone Confidentiality** (who receives tree metadata & blob bytes)
   - **Ref/Branch Confidentiality** (who sees an in-flight branch, PR, CI run, or embargo)
   - **Typed Overlays** (team/personal files mounted on top of a branch, never pushed publicly)
   - **Secret Capability (`use ≠ read`)** (invoking an authenticated external service without ever exposing the raw secret to a process or LLM context)
2. **Never rely on client-voluntary filters as a security boundary:**
   - Git sparse-checkout, `--filter=blob:none`, and prompt-level agent deny-lists are **not** access controls.
   - Enforcement must happen at the server protocol boundary, kernel/VFS `open()` boundary, or host-side egress proxy boundary.
3. **Never ship `uploadpack.hideRefs` alone as branch privacy:**
   - Always enforce per-scope OID reachability isolation, disable `have`/ACK existence oracles for unauthorized OIDs, disallow raw `allow*SHA1InWant` across scopes, and never expose shared fork alternates (anti-CFOR).
4. **Deny overrides Allow, and server policies override in-repo policies:**
   - `.access.toml` policies must compile to deterministic prefix-trie bitmasks evaluated identically across VCS transport, VFS hydration, code search, AST indexing, blame, webhooks, CI logs, and AI RAG indices.
   - Separate `traverse` from `list` and `read` so structural ancestor traversal never leaks restricted filenames or hashes.
5. **Respect the Iron Law of Revocation:**
   - Offline client-side encryption cannot revoke access to historical commits once cloned. Default to server-mediated KMS/OIDC wrapping + automated provider rotation webhooks on offboarding; treat offline SOPS/`age` mode as an explicit sovereign/air-gapped tier with Key Transparency.
6. **Treat AI coding agents under the Lethal Trifecta:**
   - Agents never receive raw secrets on disk, in `process.env`, or in LLM transcripts.
   - Effective agent authority is strictly `permissions(human) ∩ permissions(agent_task)`. Shipped today: short-lived EdDSA OIDC workload tokens with RFC 8693 token-exchange delegation (`act` claim). Planned (Phase 2): SPIFFE SVID workload identities.
   - Repo-resident instruction files (`CLAUDE.md`, `AGENTS.md`) are untrusted code surfaces and may never silently escalate permissions or egress allow-lists.

## Reference Docs

- Full specification: `docs/architecture-blueprint.md`
- Research & prior-art ledger: `docs/research-synthesis.md`
