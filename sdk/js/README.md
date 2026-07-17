# @premierstudio/trace

Minimal first-party emitter for [Premier Agent Trace](https://github.com/PremierStudio/agent-trace).

## Install

```sh
npm install @premierstudio/trace
# from a source checkout:
npm install ./sdk/js
```

## Usage

Run your agent under `premier record` so the collector env is injected:

```sh
premier record -- node agent.js
```

```ts
import { emit, premier, isPremierActive } from "@premierstudio/trace";

if (isPremierActive()) {
  await premier.spawn("researcher", { task: "find the first divergence" });
  await premier.model("researcher", {
    provider: "openai",
    model: "gpt-5",
    usage: { input_tokens: 1200, output_tokens: 400, total_tokens: 1600 },
    response: "…",
  });
  await emit({
    kind: "tool.execution",
    actor_id: "coder",
    status: "ok",
    payload: { tool: "rg", query: "reconcileInvoice" },
  });
}
```

When Premier is not recording, `emit` returns `null` unless `{ required: true }`.

## Premier Cloud

Always-on and deployed agents can emit without a local `premier record` process. Create a project ingestion key in the Premier dashboard and set:

```sh
PREMIER_COLLECTOR_URL=https://premier.dev/api/ingest/v1/events
PREMIER_COLLECTOR_TOKEN=prem_ing_…
PREMIER_TRACE_ID=<unique-run-or-conversation-id>
PREMIER_RUN_NAME="Production support agent"
PREMIER_ENVIRONMENT=production
```

The SDK includes the trace identity and run metadata on every event. Optional
`PREMIER_REPOSITORY`, `PREMIER_BRANCH`, and `PREMIER_STARTED_AT` variables are
attached the same way. Store the ingestion key in a server-side secret manager;
never ship it to a browser.

## CLI alternative

```sh
premier emit --kind agent.spawn --actor researcher --status running
```
