import { test } from "node:test";
import assert from "node:assert/strict";
import { emit, isPremierActive, premierEnv, PremierNotActiveError } from "../dist/index.js";

test("isPremierActive requires both collector env vars", () => {
  assert.equal(isPremierActive({}), false);
  assert.equal(
    isPremierActive({
      PREMIER_COLLECTOR_URL: "http://127.0.0.1:9/v1/events",
      PREMIER_COLLECTOR_TOKEN: "tok",
    }),
    true,
  );
});

test("premierEnv throws a clear error when inactive", () => {
  assert.throws(() => premierEnv({}), (err) => err instanceof PremierNotActiveError);
});

test("emit no-ops when inactive unless required", async () => {
  assert.equal(await emit({ kind: "agent.spawn" }, { env: {} }), null);
  await assert.rejects(
    () => emit({ kind: "agent.spawn" }, { env: {}, required: true }),
    PremierNotActiveError,
  );
});

test("emit posts JSON with bearer token", async () => {
  const calls = [];
  const fakeFetch = async (url, init) => {
    calls.push({ url, init });
    return {
      ok: true,
      async json() {
        return { event_id: "evt-1", trace_id: "tr-1", kind: "agent.spawn" };
      },
    };
  };
  const result = await emit(
    { kind: "agent.spawn", actor_id: "researcher", payload: { task: "find" } },
    {
      env: {
        PREMIER_TRACE_ID: "always-on-42",
        PREMIER_COLLECTOR_URL: "http://127.0.0.1:4318/v1/events",
        PREMIER_COLLECTOR_TOKEN: "secret",
        PREMIER_RUN_NAME: "Production support agent",
        PREMIER_REPOSITORY: "premier/support-agent",
        PREMIER_BRANCH: "main",
        PREMIER_ENVIRONMENT: "production",
      },
      fetch: fakeFetch,
    },
  );
  assert.equal(result.event_id, "evt-1");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "http://127.0.0.1:4318/v1/events");
  assert.equal(calls[0].init.headers.Authorization, "Bearer secret");
  const body = JSON.parse(calls[0].init.body);
  assert.equal(body.kind, "agent.spawn");
  assert.equal(body.actor_id, "researcher");
  assert.equal(body.source, "premier-sdk");
  assert.equal(body.trace_id, "always-on-42");
  assert.deepEqual(body.run, {
    name: "Production support agent",
    repository: "premier/support-agent",
    branch: "main",
    environment: "production",
  });
});

test("emit normalizes fractional and invalid duration_ms for the u64 collector", async () => {
  const env = {
    PREMIER_TRACE_ID: "tr",
    PREMIER_COLLECTOR_URL: "http://127.0.0.1:4318/v1/events",
    PREMIER_COLLECTOR_TOKEN: "secret",
  };
  const bodies = [];
  const fakeFetch = async (_url, init) => {
    bodies.push(JSON.parse(init.body));
    return { ok: true, async json() { return { event_id: "e", trace_id: "tr", kind: "k", sequence: 1 }; } };
  };
  await emit({ kind: "tool.execution", duration_ms: 12.75 }, { env, fetch: fakeFetch });
  await emit({ kind: "tool.execution", duration_ms: -3.2 }, { env, fetch: fakeFetch });
  await emit({ kind: "tool.execution", duration_ms: Number.POSITIVE_INFINITY }, { env, fetch: fakeFetch });
  assert.equal(bodies[0].duration_ms, 13);
  assert.equal(bodies[1].duration_ms, 0);
  assert.equal("duration_ms" in bodies[2], false);
});
