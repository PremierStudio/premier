export interface JournalFile {
  path: string;
  sha256: string;
  event_count: number;
}

export type IntegrityStatus = 'live' | 'verified' | 'invalid';

export interface ProcessTermination {
  kind: 'exit' | 'signal' | 'interrupted';
  exit_code?: number | null;
  signal?: number | null;
  signal_name?: string | null;
  core_dumped?: boolean;
}

export interface TraceDiagnostic {
  severity: 'warning';
  code: string;
  message: string;
  event_id?: string;
  sequence?: number;
}

export interface TraceManifest {
  format_version: number;
  trace_id: string;
  name?: string | null;
  command: string[];
  started_at: string;
  ended_at: string | null;
  exit_code: number | null;
  journal: JournalFile | null;
  capabilities?: string[];
  summary?: TraceListSummary;
  /** Directory basename; unique across copied artifacts that share a trace_id. */
  artifact?: string;
  integrity?: IntegrityStatus;
  integrity_detail?: string | null;
  /** Structured recorder termination metadata (available on newer artifacts). */
  termination?: ProcessTermination;
  /** Advisory semantic validation findings; unknown/custom event kinds remain valid. */
  diagnostics?: TraceDiagnostic[];
}

export interface TraceListSummary {
  display_name: string | null;
  actor_count: number;
  issue_count: number;
  event_count: number;
}

export interface TraceEvent {
  event_id: string;
  trace_id: string;
  sequence: number;
  timestamp: string;
  kind: string;
  source: string;
  payload_json: string;
  actor_id: string;
  actor_type: string;
  parent_event_id: string;
  span_id: string;
  parent_span_id: string;
  correlation_id: string;
  status: string;
  duration_ms: number;
  links: string[];
}

/**
 * Decode payload_json into a plain object safe for Object.entries / inspector rows.
 * JSON null, arrays, and scalars are wrapped so the workspace never white-screens.
 */
export function eventPayload(event: TraceEvent): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(event.payload_json);
    if (parsed === null) return { value: null };
    if (Array.isArray(parsed)) return { items: parsed };
    if (typeof parsed === 'object') return parsed as Record<string, unknown>;
    return { value: parsed };
  } catch {
    return { raw: event.payload_json };
  }
}

/** Stable list key that survives copied .atrace directories with colliding trace_ids. */
export function listKey(trace: Pick<TraceManifest, 'trace_id' | 'artifact'>): string {
  return trace.artifact || trace.trace_id;
}

export type EventCategory = 'all' | 'agent' | 'model' | 'tool' | 'approval' | 'process' | 'error';

export interface EventFilters {
  search: string;
  category: EventCategory;
  actorId: string | null;
  errorsOnly: boolean;
  /** When set, only events sharing this correlation_id remain in scope. */
  correlationId: string | null;
}

export interface AssistantAvailability {
  provider: string;
  label: string;
  installed: boolean;
  available: boolean;
  reason?: string;
}

export type AssistantMessageRole = 'user' | 'assistant';

export interface AssistantHistoryMessage {
  role: AssistantMessageRole;
  content: string;
}

export interface AssistantRequest {
  provider: string;
  prompt: string;
  selected_event_id?: string;
  history?: AssistantHistoryMessage[];
}

export interface AssistantResponse {
  provider: string;
  answer: string;
  elapsed_ms: number;
}
