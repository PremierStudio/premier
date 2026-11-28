# Premier — Platform Architecture & Feature Blueprint

> **Mission:** Eliminate source control's 100%-or-0% access boundary without sacrificing Git compatibility, developer ergonomics, or AI-agent safety.

---

## 1. Core Architectural Thesis

Traditional Git couples content identity (Merkle DAG commit/tree SHA) to full tree visibility and binds security to the repository clone boundary. Attempts to patch around this fail along predictable fault lines:
- **Client-side file encryption (`git-crypt`, `SOPS`, `dotenvx`):** leaks filenames/hashes in Git trees, cannot revoke access to already-cloned history, breaks 3-way merges/`blame` on opaque blobs, and collapses the moment an AI agent holds the decryption key.
- **Ref hiding (`uploadpack.hideRefs`):** leaks OID existence via `have`/ACK oracles, `allow*SHA1InWant`, reachability bitmap conflicts, and cross-fork object pools (CFOR).
- **Split repos & Copybara:** fractures atomic commits, breaks PR/CI continuity, and creates permanent sync toil.
- **Standalone secret vaults (Doppler, Infisical, 1Password):** live outside repo ACLs and PR diffs, trigger Shadow IT (`.env` in Slack/Teams), and expose entire vaults or `process.env` to coding agents.

Premier solves this by decoupling **canonical storage** from **materialized views** and modeling **four orthogonal access primitives** over one unified history.

---

## 2. The Four-Plane Architecture

### Plane 1: Principals & Zero-Trust Identity
- **External / OSS Contributors:** Standard `git` clients cloning a projected public view.
- **Core Teammates:** Native `jj`-compatible CLI + lazy VFS (`FUSE` / macOS `FSKit` / Windows `ProjFS`).
- **AI Coding Agents:** Isolated microVM / OS sandbox with sparse Zone mounts, hard `open()` denial on restricted paths, and placeholder capability handles only.
- **CI / CD & Production Workloads:** Keyless OIDC / SPIFFE SVIDs (short-lived 5-minute tokens).
- **Delegated Agent Authority:** `effective_permissions = permissions(human) ∩ permissions(agent_task)` using SPIFFE workload identity (`act`) + OAuth 2.0 Token Exchange (RFC 8693 / IETF WIMSE `sub`). An agent can narrow a human's scope, never escalate it.

### Plane 2: Protocol Bridges & Enforcement Boundaries
1. **Reversible Projected Git Bridge (Josh-Inspired):**
   - Projects ACL-authorized subtrees/zones into valid, `fsck`-clean standalone Git DAGs with incrementally cached bidirectional push/pull.
   - **Projection Attestations:** Solves Josh's broken `gpgsig` limitation by verifying original author signatures pre-projection and issuing transparency-logged attestation trailers (Sigstore/Fulcio-style) on rewritten commits.
2. **Native VFS & Cloud Protocol:**
   - Lazy blob hydration (CitC / EdenFS model); unauthorized paths never cross the wire and return kernel `ENOENT`/`EACCES`.
   - Native multi-TB binary streaming + optional per-path exclusive file locks (`+lock`) without Git LFS or Perforce's read-only checkout friction.
3. **Secret Capability Egress Proxy ("Use Without Reading"):**
   - Default-deny sandbox egress routed through a host/sidecar proxy.
   - Agent holds deterministic placeholder tokens (`STRIPE_API_KEY=cap_proxy_...`). On allow-listed outbound requests matching schema-declared host/path/method/rate rules, the proxy swaps in the real secret from KMS/Vault, writes an audit record, and scrubs echoed secrets from responses and traces.

### Plane 3: Four Orthogonal Access Surfaces

#### 3.1 Zones & Path ACLs ("The Visibility Twin of `CODEOWNERS`")
- **Policy Evaluation:** Explicit **Deny-overrides-Allow** (rejecting Perforce's "last-line-wins" footgun), compiled into fast prefix-trie bitmasks. Checked into `.access.toml` for PR review, **strictly overridable by server/org policies**.
- **Five Capabilities:** `traverse` (structural ancestor walk without listing siblings), `list`, `read`, `write`, `use`. Separating `traverse` from `list`/`read` avoids SVN's parent-directory copy/branch trap while eliminating filename leaks.
- **Bidirectional Zones:** Define named projections (`zone:public`, `zone:billing`, `zone:contractor-acme`, `zone:agent-ui`). Supports both *private paths inside a public repo* and *continuous public package publishing from a private monorepo* (natively replacing Copybara).
- **Cross-Boundary Declassification Gate:** Moving a file from private to public requires Zone Owner approval and automatically scrubs restricted `copyfrom` ancestry for unauthorized readers (eliminating SVN `CVE-2021-28544` leaks) while preserving full lineage for authorized users.
- **Build Encapsulation vs. Security:** Separate Blaze-style import/build `visibility` rules from security ACLs.
- **Interactive Policy Dry-Run (`explain`):** `forge access explain <principal> <path> --ref <ref>` plus automatic **Access Impact Diffs** on every PR editing `.access.toml`.

#### 3.2 Private Branches, Private Changes & Embargoed Releases
- **Orthogonal Visibility & Readiness (Gerrit model):** Every branch/change carries independent `visibility` (`public` | `org` | `restricted:[principals]` | `personal`) and `readiness` (`wip` | `ready`).
- **Native Private Branches in Public Repos:**
  - `forge branch create launch-v3 --private --allow @alice,@bob,@carol`
  - Full PR reviews, immutable Review Rounds, isolated CI runners, preview deploys, and clean rebases against public `main`—with zero ref advertisement, zero OID reachability, and zero contribution-graph side channels.
- **Embargo & Squash-Declassify Workflow:** Develop, review, CI-test, and ship hotfixes/security advisories directly from a private branch before public disclosure; click **Publish / Squash-Declassify** to pass a **Visibility Escalation Gate** and optionally collapse sensitive intermediate commits/messages into a clean public landing commit.

#### 3.3 Typed Overlays (`branch + private/local files`)
- **Team Overlays (`overlay:team-core`):** Versioned non-public files (`.run` launch files, internal playbooks, private test fixtures) automatically projected onto authorized working trees and structurally excluded from public commits/pushes.
- **Personal Synced Overlays (`overlay:me`, E2EE):** Carries personal `AGENTS.local.md`, editor tweaks, and local overrides cleanly across machines and cloud sandboxes—scoped per repository, never polluting global context or shared history.

#### 3.4 Native, Zero-3rd-Party Secret Management
- **Schema-in-Repo (`.env.schema`):** Typed, PR-diffable contract declaring variable names, types, defaults, validation constraints, sensitivity tier, allowed egress domains, and automated rotator hooks. Missing values across `dev → preview → staging → prod` fail in PR review.
- **Hierarchical Inheritance:** `org → repo → zone → environment (dev/preview/staging/prod) → branch/PR → personal override`.
- **Write Access ≠ Secret Read Access:** Repository push privileges never confer secret read permissions.
- **Two Explicit Cryptographic Modes:**
  1. **Default — Forge KMS / BYOK Vault:** HSM/KMS-wrapped values (or BYOK AWS/GCP KMS, OpenBao/Vault, 1Password connector). Instant offboarding revocation + dual-phase signed **Auto-Rotation Webhooks** to external issuers.
  2. **Sovereign / Air-Gapped Mode — Native Format-Preserving AEAD (`SOPS`/`age`):** Plaintext keys, per-value AEAD with path+key-bound AAD, Shamir `t`-of-`n` quorum, SOPS-aware merge driver, safe `textconv` diff (never `cachetextconv`), and **Key Transparency** (KEYTRANS / Sigstore-style) preventing silent public-key swaps.
- **Zero Plaintext on Disk Locally:** Virtual **FIFO named pipe** `.env` mounts (1Password Environments pattern) or `forge run -- <cmd>` with stdout/stderr redaction—physically uncommittable to Git.
- **Keyless CI/Prod + Kill-Switch:** Default OIDC/SPIFFE federation, pre-receive Push Protection + Partner Auto-Revocation, and Fossil-style **`shun`** for emergency artifact excision.

### Plane 4: Canonical Storage, Unified Indices & Post-Git UX
- **Bonsai / Prolly-Tree Store + Ref-CAS:** Scales to 5,000+ concurrent agent writers with single-object reads and strict anti-CFOR tenant reachability isolation.
- **ACL-Unified Derived Indices:** Code Search, AST/symbol navigation, blame, webhooks, CI logs, and AI RAG indices all evaluate the exact same compiled ACL bitmask.
- **Jujutsu + GitButler Local Ergonomics:** Working-copy-as-a-commit, first-class conflicts (stored as data; rebases never block mid-flight), universal `undo` via operation log, live oplog cloud sync across devices, and parallel virtual lanes + CoW worktrees (`.worktreeinclude` for `node_modules`/`target`).
- **Unified `Change` & Immutable Review Rounds:** One `Change-Id` surviving rebases/amends, immutable Rounds with crisp interdiffs, agent-speed merge queues, and **ACL-scoped Prompt/Session Provenance** ("blame the prompt" without leaking private chats).

---

## 3. AI-Agent Security Cage ("Kitchen Without the Keys to the Safe")

1. **Two-Phase Sandbox Execution:** Setup phase installs dependencies with temporary private registry auth → strips secrets and cuts arbitrary internet before the agent loop starts.
2. **Hard Filesystem Isolation:** Sparse Zone projection + FUSE/OverlayFS masking restricted paths, `~/.ssh`, `~/.aws`, and `.env*` (OS-level `ENOENT`/`EACCES`).
3. **Egress Capability Proxy + Per-Capability TTL Approval:** Placeholder tokens swapped on the wire for allow-listed hosts only; sensitive new capabilities request a 1-click biometric/UI approval scoped to one capability and TTL—never unlocking the full vault.
4. **Secret-Free Testing Loop:** Copy-on-write ephemeral database branches (synthetic/anonymized data) + Testcontainers + local HTTP mocks; privileged integration suites run in a remote gated runner returning redacted pass/fail logs only.
5. **Untrusted Instruction Quarantine:** `CLAUDE.md` / `AGENTS.md` pinned by repo owners, highlighted in red on PR diffs, and barred from escalating tool permissions or proxy egress policies.
6. **Agent Branch Fencing:** Agents commit as attested bot/delegated identities (`agent[bot]` + `Co-Authored-By`), restricted to `agent/*` lanes, blocked from editing `.access.toml`, CI workflows, or self-merging.

---

## 4. Phased Rollout & Go-to-Market Wedge

Solving GitHub's network moat requires meeting teams where they already are:

### Phase 1 — Drop-In GitHub Companion & Agent Security Wedge
- Keep public repos on GitHub for stars, issues, and community distribution.
- Attach Premier as an overlay/proxy providing:
  - **Private branches on public GitHub repos** + Squash-Declassify PR publishing.
  - **Bidirectional Zones** syncing clean public slices to GitHub (replacing Copybara & dual repos).
  - **Typed Overlays** (team `.run`/docs + personal synced `AGENTS.local.md`).
  - **Native `.env.schema` + FIFO local dev + AI Agent Egress Capability Proxy**.

### Phase 2 — Full Post-Git Native Forge
- Open-source core + self-hostable single binary / Kubernetes deployment with BYOK KMS and portable/federated identity.
- Native `jj`/VFS protocol, Bonsai/Prolly-tree + Ref-CAS engine, immutable Change-Id Review Rounds, and full ACL-unified code search & session provenance.
