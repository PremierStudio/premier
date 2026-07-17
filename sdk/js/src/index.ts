/**
 * Premier first-party emitter SDK.
 *
 * Under `premier record -- <command>`, the CLI injects:
 *   PREMIER_TRACE_ID, PREMIER_COLLECTOR_URL, PREMIER_COLLECTOR_TOKEN
 *
 * Call `emit(...)` from agent runtimes to attach typed multi-actor evidence.
 */

export type PremierEventInput = {
  kind: string;
  source?: string;
  actor_id?: string;
  actor_type?: string;
  parent_event_id?: string;
  span_id?: string;
  parent_span_id?: string;
  correlation_id?: string;
  status?: string;
  duration_ms?: number;
  links?: string[];
  payload?: Record<string, unknown>;
  /**
   * RFC3339 producer timestamp, stored verbatim as the event timestamp.
   * When omitted, the collector records its own receipt time instead.
   */
  timestamp?: string;
};

/**
 * Collector acknowledgement for one accepted event. `sequence` is the
 * collector-assigned journal order. The local recorder echoes the full stored
 * event (including `payload_json`); Premier Cloud batch ingestion returns only
 * the required fields.
 */
export type PremierEvent = {
  event_id: string;
  trace_id: string;
  kind: string;
  sequence: number;
  timestamp?: string;
  source?: string;
  payload_json?: string;
  actor_id?: string;
  actor_type?: string;
  parent_event_id?: string;
  span_id?: string;
  parent_span_id?: string;
  correlation_id?: string;
  status?: string;
  duration_ms?: number;
  links?: string[];
};

export class PremierNotActiveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PremierNotActiveError";
  }
}

export function isPremierActive(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return Boolean(env.PREMIER_COLLECTOR_URL && env.PREMIER_COLLECTOR_TOKEN);
}

export function premierEnv(env: NodeJS.ProcessEnv = process.env): {
  traceId: string | undefined;
  collectorUrl: string;
  collectorToken: string;
} {
  const collectorUrl = env.PREMIER_COLLECTOR_URL;
  const collectorToken = env.PREMIER_COLLECTOR_TOKEN;
  if (!collectorUrl || !collectorToken) {
    throw new PremierNotActiveError(
      "Premier collector is not active. Run your process under `premier record -- <command>`.",
    );
  }
  return {
    traceId: env.PREMIER_TRACE_ID,
    collectorUrl,
    collectorToken,
  };
}

/**
 * Emit a typed event to the local Premier collector.
 * No-ops (returns null) when Premier is not recording, unless `required` is true.
 */
export async function emit(
  event: PremierEventInput,
  options: { required?: boolean; env?: NodeJS.ProcessEnv; fetch?: typeof fetch } = {},
): Promise<PremierEvent | null> {
  const env = options.env ?? process.env;
  if (!isPremierActive(env)) {
    if (options.required) {
      premierEnv(env);
    }
    return null;
  }
  const { traceId, collectorUrl, collectorToken } = premierEnv(env);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) {
    throw new Error("fetch is not available in this runtime");
  }

  const body: Record<string, unknown> = {
    trace_id: traceId,
    run: {
      name: env.PREMIER_RUN_NAME,
      repository: env.PREMIER_REPOSITORY,
      branch: env.PREMIER_BRANCH,
      environment: env.PREMIER_ENVIRONMENT,
      started_at: env.PREMIER_STARTED_AT,
    },
    source: "premier-sdk",
    ...event,
  };
  // The local collector stores duration_ms as an unsigned integer, so
  // fractional timings (performance.now() deltas) must be normalized here
  // rather than rejected mid-run with a 400.
  if (typeof event.duration_ms === "number") {
    if (Number.isFinite(event.duration_ms)) {
      body.duration_ms = Math.min(
        Math.max(0, Math.round(event.duration_ms)),
        Number.MAX_SAFE_INTEGER,
      );
    } else {
      delete body.duration_ms;
    }
  }

  const response = await fetchImpl(collectorUrl, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${collectorToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Premier collector rejected event (${response.status}): ${text || response.statusText}`,
    );
  }

  return (await response.json()) as PremierEvent;
}

/** Convenience helpers for common agent evidence kinds. */
export const premier = {
  isActive: isPremierActive,
  emit,
  spawn(actor: string, payload: Record<string, unknown> = {}, extra: Partial<PremierEventInput> = {}) {
    return emit({
      kind: "agent.spawn",
      actor_id: actor,
      actor_type: extra.actor_type ?? "subagent",
      status: extra.status ?? "running",
      payload,
      ...extra,
    });
  },
  model(
    actor: string,
    payload: Record<string, unknown>,
    extra: Partial<PremierEventInput> = {},
  ) {
    return emit({
      kind: "model.response",
      actor_id: actor,
      actor_type: extra.actor_type ?? "agent",
      status: extra.status ?? "ok",
      payload,
      ...extra,
    });
  },
  tool(
    actor: string,
    payload: Record<string, unknown>,
    extra: Partial<PremierEventInput> = {},
  ) {
    return emit({
      kind: "tool.execution",
      actor_id: actor,
      actor_type: extra.actor_type ?? "agent",
      status: extra.status ?? "ok",
      payload,
      ...extra,
    });
  },
  approval(
    actor: string,
    payload: Record<string, unknown>,
    extra: Partial<PremierEventInput> = {},
  ) {
    return emit({
      kind: "approval.request",
      actor_id: actor,
      actor_type: extra.actor_type ?? "agent",
      status: extra.status ?? "pending",
      payload,
      ...extra,
    });
  },
};
