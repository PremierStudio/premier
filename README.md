<p align="center">
  <img src="docs/assets/premier-hero.png" alt="Premier agent traces converging into verified evidence" width="100%" />
</p>

<h1 align="center">Premier</h1>

<p align="center">
  <strong>The flight recorder for AI agents.</strong><br />
  Record what your agents did, inspect why they did it, and keep the evidence.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@premierstudio/premier"><img src="https://img.shields.io/npm/v/%40premierstudio%2Fpremier?style=flat-square&color=7c83ff" alt="npm version" /></a>
  <a href="https://github.com/PremierStudio/premier/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/PremierStudio/premier/ci.yml?branch=main&style=flat-square&label=build" alt="build status" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-6d7cff?style=flat-square" alt="Apache 2.0 license" /></a>
  <img src="https://img.shields.io/badge/macOS%20%7C%20Linux-supported-111827?style=flat-square" alt="macOS and Linux" />
</p>

<p align="center">
  <a href="https://premier.dev/docs"><strong>Documentation</strong></a> ·
  <a href="https://premier.dev/docs/install">Installation</a> ·
  <a href="https://premier.dev/docs/adapters">Agent integrations</a> ·
  <a href="https://premier.dev/docs/record">Audit your agents</a>
</p>

---

## See the whole run

Agents make decisions across models, tools, terminals, subagents, approvals, and handoffs. Premier turns that activity into a portable, verifiable trace you can investigate locally.

<p align="center">
  <img src="docs/assets/premier-agent-trace-viewer.png" alt="Premier investigating a multi-agent failure" width="100%" />
</p>

## Start in thirty seconds

```sh
npm install --global @premierstudio/premier
premier record -- your-agent run
premier open
```

Or pin Premier inside a project:

```sh
npm install --save-dev @premierstudio/premier
npx premier record -- npm test
```

Premier is script-free: installation does not run lifecycle scripts or download executables from arbitrary URLs. The npm launcher selects the signed native package for your platform.

## Works with the agents you already use

| Agent | Native structured capture |
| --- | :---: |
| Claude Code | ✓ |
| OpenAI Codex | ✓ |
| Gemini CLI | ✓ |
| Grok | ✓ |
| Kimi | ✓ |
| OpenCode | ✓ |
| Droid / GLM | ✓ |

```sh
premier record --adapter auto -- codex exec --json "review this repository"
premier record --adapter claude -- claude -p --output-format stream-json "fix the failing test"
premier record --pty -- your-interactive-agent
```

Unknown harness? Premier can record any process immediately, then accept typed evidence through its JavaScript SDK, CLI emitter, shell helper, or local HTTP collector.

## Evidence, not vibes

- **Reconstruct the run** — terminal output, model calls, tools, approvals, delegation, messages, joins, timing, and exit semantics.
- **Follow causality** — actor identity, parent events, spans, correlations, and cross-links stay attached to the evidence.
- **Find the failure** — filter issues, compare runs, inspect topology, query locally, and export a reviewed evidence package.
- **Keep control** — traces are local-first, portable, integrity-checked, redactable, and optionally encrypted.

## Instrument your own harness

Install the tiny emitter:

```sh
npm install @premierstudio/trace
```

```ts
import { premier } from "@premierstudio/trace";

await premier.spawn("researcher", { task: "find the first divergence" });
await premier.model("researcher", {
  provider: "openai",
  model: "gpt-5",
  usage: { input_tokens: 1200, output_tokens: 400, total_tokens: 1600 },
});
```

Premier injects a loopback collector URL and per-run bearer token into every recorded process. Your harness emits the facts it knows; Premier handles storage, integrity, redaction, recovery, and investigation.

[Read the instrumentation guide →](https://premier.dev/docs/sdk)

## Built for sensitive evidence

- Local loopback collection by default
- Structured secret redaction before journal writes
- Explicit terminal redaction rules
- XChaCha20-Poly1305 trace encryption
- Tamper detection and recovery for interrupted runs
- Signed release archives and npm trusted publishing with provenance
- No npm install scripts

Review every trace before sharing it. Premier cannot reliably identify secrets hidden inside arbitrary unlabelled terminal text.

## Explore

| Guide | What you will do |
| --- | --- |
| [Install Premier](https://premier.dev/docs/install) | Choose global, project-local, or signed archive installation. |
| [Connect an agent](https://premier.dev/docs/adapters) | Capture Claude, Codex, Gemini, Grok, Kimi, OpenCode, and Droid. |
| [Audit local sessions](https://premier.dev/docs/record) | Record and investigate real agent activity on your machine. |
| [Instrument a harness](https://premier.dev/docs/sdk) | Emit typed agent, model, tool, approval, and delegation evidence. |
| [Release security](docs/releasing.md) | Verify signatures, checksums, SBOMs, and provenance. |

## Build from source

```sh
npm install
npm run build
cargo test --workspace
cargo run -p premier-cli --bin premier -- demo
```

Premier is open source under the [Apache License 2.0](LICENSE).
