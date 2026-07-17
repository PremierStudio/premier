import type { EventCategory, EventFilters, TraceEvent, TraceManifest } from './types';

export type ActorRole = 'process' | 'agent' | 'subagent' | 'human' | 'system';

export interface AgentSummary {
  id: string;
  type: ActorRole;
  events: number;
  errors: number;
  firstSequence: number;
  status: string;
}

export interface ActorInventory {
  processes: number;
  agents: number;
  subagents: number;
  humans: number;
  systems: number;
}

export interface RunHealth {
  label: 'Running' | 'Awaiting approval' | 'Blocked' | 'Needs attention' | 'Interrupted' | 'Failed' | 'Passed' | 'Unverified';
  tone: 'running' | 'warning' | 'error' | 'success';
  detail: string;
}

export interface TimelineEvent extends TraceEvent {
  lane: number;
  parentLane: number | null;
  depth: number;
  elapsedMs: number;
}

export function actorId(event: TraceEvent): string {
  return event.actor_id || 'root';
}

export function actorRole(event: TraceEvent): ActorRole {
  const type = event.actor_type?.trim().toLowerCase();
  if (type === 'process' || type === 'human' || type === 'subagent' || type === 'system') return type;
  if (type === 'agent') return actorId(event) === 'root' && event.kind.startsWith('process.') ? 'process' : 'agent';
  if (event.kind.startsWith('process.')) return 'process';
  return actorId(event) === 'root' ? 'process' : 'agent';
}

/**
 * The one authoritative issue predicate for the viewer.
 * Keep this aligned with the recorder summary contract in premier-cli.
 */
export function isIssue(event: TraceEvent): boolean {
  const status = event.status.trim().toLowerCase();
  const kind = event.kind.trim().toLowerCase();
  return ['error', 'failed', 'denied', 'blocked'].includes(status)
    || kind.includes('error')
    || kind.includes('fail');
}

export function categoryOf(event: TraceEvent): EventCategory {
  if (isIssue(event)) return 'error';
  const prefix = event.kind.split('.')[0] as EventCategory;
  return ['agent', 'model', 'tool', 'approval', 'process'].includes(prefix) ? prefix : 'agent';
}

/** The recorded family stays stable even when an event is also an issue. */
export function familyOf(event: TraceEvent): Exclude<EventCategory, 'all' | 'error'> | 'agent' {
  const prefix = event.kind.split('.')[0] as Exclude<EventCategory, 'all' | 'error'>;
  return ['agent', 'model', 'tool', 'approval', 'process'].includes(prefix) ? prefix : 'agent';
}

export function summarizeAgents(events: TraceEvent[]): AgentSummary[] {
  const actors = new Map<string, AgentSummary>();
  for (const event of events) {
    const id = actorId(event);
    const current = actors.get(id) ?? {
      id,
      type: actorRole(event),
      events: 0,
      errors: 0,
      firstSequence: event.sequence,
      status: 'ok'
    };
    current.events += 1;
    if (categoryOf(event) === 'error' || ['failed', 'denied', 'blocked'].includes(event.status)) {
      current.errors += 1;
      current.status = 'error';
    } else if (['running', 'pending'].includes(event.status) && current.status !== 'error') {
      current.status = event.status;
    }
    actors.set(id, current);
  }
  return [...actors.values()].sort((a, b) => a.firstSequence - b.firstSequence);
}

export function actorInventory(events: TraceEvent[]): ActorInventory {
  const inventory: ActorInventory = { processes: 0, agents: 0, subagents: 0, humans: 0, systems: 0 };
  for (const actor of summarizeAgents(events)) {
    if (actor.type === 'process') inventory.processes += 1;
    else if (actor.type === 'agent') inventory.agents += 1;
    else if (actor.type === 'subagent') inventory.subagents += 1;
    else if (actor.type === 'human') inventory.humans += 1;
    else inventory.systems += 1;
  }
  return inventory;
}

export function runHealth(trace: TraceManifest, events: TraceEvent[]): RunHealth {
  if (trace.integrity === 'invalid') {
    return {
      label: 'Unverified',
      tone: 'error',
      detail: trace.integrity_detail?.trim() || 'Journal failed integrity verification'
    };
  }
  const errorCount = events.filter((event) => categoryOf(event) === 'error').length;
  const deniedCount = events.filter((event) => ['denied', 'blocked'].includes(event.status)).length;
  const pendingCount = events.filter((event) => event.status === 'pending').length;
  if (trace.termination?.kind === 'interrupted') {
    return { label: 'Interrupted', tone: 'warning', detail: 'Recovered after recorder interruption' };
  }
  if (trace.termination?.kind === 'signal') {
    const signal = trace.termination.signal_name?.trim() || (trace.termination.signal ? `signal ${trace.termination.signal}` : 'a signal');
    return { label: 'Failed', tone: 'error', detail: `Terminated by ${signal}` };
  }
  if (trace.exit_code !== null && trace.exit_code !== 0) {
    return { label: 'Failed', tone: 'error', detail: `Exit ${trace.exit_code}${errorCount ? ` · ${errorCount} error${errorCount === 1 ? '' : 's'}` : ''}` };
  }
  if (deniedCount) return { label: 'Blocked', tone: 'error', detail: `${deniedCount} denied or blocked operation${deniedCount === 1 ? '' : 's'}` };
  if (errorCount) return { label: 'Needs attention', tone: 'warning', detail: `${errorCount} recorded error${errorCount === 1 ? '' : 's'} despite a clean exit` };
  if (pendingCount) return { label: 'Awaiting approval', tone: 'warning', detail: `${pendingCount} pending decision${pendingCount === 1 ? '' : 's'}` };
  if (trace.ended_at === null || trace.integrity === 'live') return { label: 'Running', tone: 'running', detail: 'Trace is still receiving evidence' };
  const verified = trace.integrity === 'verified' ? ' · integrity verified' : '';
  return { label: 'Passed', tone: 'success', detail: `Clean exit with no recorded errors${verified}` };
}

function compact(value: unknown): string {
  let output: string;
  if (Array.isArray(value)) output = value.map(String).join(', ');
  else if (typeof value === 'object' && value !== null) output = JSON.stringify(value);
  else output = String(value);
  return output.replace(/\s+/g, ' ').trim();
}

function first(payload: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = payload[key];
    if (value !== undefined && value !== null && value !== '') return compact(value);
  }
  return null;
}

export function eventSummary(event: TraceEvent): string {
  let payload: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(event.payload_json);
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      if (parsed === null) return 'null payload';
      if (Array.isArray(parsed)) return compact(parsed);
      return compact(parsed);
    }
    payload = parsed as Record<string, unknown>;
  } catch {
    return event.payload_json.trim() || event.source;
  }
  const kind = event.kind.toLowerCase();
  if (kind === 'session.start') {
    const goal = first(payload, ['goal']);
    const command = Array.isArray(payload.command) ? payload.command.map(String) : null;
    const executable = command?.[0] ?? first(payload, ['command']);
    const shellWrapper = command && ['sh', 'bash', 'zsh'].includes(command[0]) && command[1] === '-c';
    return goal ? `Goal: ${goal}` : shellWrapper ? 'Shell trace recording started' : executable ? `Started ${executable}` : 'Trace recording started';
  }
  if (kind.includes('stdout') || kind.includes('stderr')) return first(payload, ['text'])?.replace(/\s+/g, ' ').trim() || 'Empty output';
  if (kind.startsWith('model.')) {
    const model = first(payload, ['model']);
    const content = first(payload, ['summary', 'text', 'content', 'response']);
    const tokens = first(payload, ['tokens', 'total_tokens']);
    return [model, content, tokens ? `${tokens} tokens` : null].filter(Boolean).join(' · ') || 'Model response captured';
  }
  if (kind.startsWith('tool.')) {
    const tool = first(payload, ['tool', 'name', 'command']) || event.source;
    const result = payload.failed !== undefined ? `failed: ${compact(payload.failed)}`
      : payload.error !== undefined ? `error: ${compact(payload.error)}`
      : payload.query !== undefined ? `query: ${compact(payload.query)}`
      : payload.checks !== undefined ? compact(payload.checks)
      : payload.missing !== undefined ? `${compact(payload.missing)} missing`
      : payload.matches !== undefined ? `${compact(payload.matches)} matches`
      : payload.files_changed !== undefined ? `${compact(payload.files_changed)} files changed`
      : first(payload, ['result', 'summary']);
    return result ? `${tool} · ${result}` : tool;
  }
  if (kind === 'approval.request') {
    const operation = first(payload, ['operation', 'action']) || 'operation';
    const target = first(payload, ['files', 'resource', 'scope']);
    const reason = first(payload, ['reason']);
    return [`Request ${operation}`, target, reason].filter(Boolean).join(' · ');
  }
  if (kind === 'approval.decision') {
    const scope = first(payload, ['scope']);
    const receipt = first(payload, ['receipt', 'approval_receipt']);
    return [`${event.status || 'decision'}`, scope, receipt ? `receipt ${receipt}` : null].filter(Boolean).join(' · ');
  }
  if (kind.startsWith('agent.')) {
    const content = first(payload, ['task', 'finding', 'outcome', 'result', 'input', 'scope', 'action', 'message']);
    const delegates = first(payload, ['delegates', 'joined', 'to']);
    if (kind === 'agent.delegation' && delegates) return [`Delegated to ${delegates}`, content].filter(Boolean).join(' · ');
    if (kind === 'agent.join' && delegates) return [`Joined ${delegates}`, content].filter(Boolean).join(' · ');
    if (kind === 'agent.message' && delegates) return [`Sent to ${delegates}`, content].filter(Boolean).join(' · ');
    return content || event.source;
  }
  if (kind === 'process.exit' || typeof payload.exit_code === 'number') return `Exited with status ${payload.exit_code}`;
  return first(payload, ['summary', 'text', 'message', 'operation', 'command']) || event.source;
}

export function timelineLayout(events: TraceEvent[]): { lanes: string[]; events: TimelineEvent[] } {
  const lanes = [...new Set(events.map(actorId))];
  const startedAt = events.length ? Date.parse(events[0].timestamp) : 0;
  const byEvent = new Map(events.map((event) => [event.event_id, event]));
  const firstBySpan = new Map<string, TraceEvent>();
  for (const event of events) if (event.span_id && !firstBySpan.has(event.span_id)) firstBySpan.set(event.span_id, event);
  const depthMemo = new Map<string, number>();
  const depthOf = (event: TraceEvent, seen = new Set<string>()): number => {
    if (depthMemo.has(event.event_id)) return depthMemo.get(event.event_id)!;
    if (seen.has(event.event_id)) return 0;
    seen.add(event.event_id);
    const parent = byEvent.get(event.parent_event_id) ?? firstBySpan.get(event.parent_span_id);
    const depth = parent && parent.event_id !== event.event_id ? Math.min(depthOf(parent, seen) + 1, 8) : 0;
    depthMemo.set(event.event_id, depth);
    return depth;
  };
  return {
    lanes,
    events: events.map((event) => {
      const parent = byEvent.get(event.parent_event_id) ?? firstBySpan.get(event.parent_span_id);
      return {
        ...event,
        lane: lanes.indexOf(actorId(event)),
        parentLane: parent ? lanes.indexOf(actorId(parent)) : null,
        depth: depthOf(event),
        elapsedMs: Math.max(0, Date.parse(event.timestamp) - startedAt)
      };
    })
  };
}

export function filterEvents(events: TraceEvent[], filters: EventFilters): TraceEvent[] {
  const query = filters.search.trim().toLowerCase();
  return events.filter((event) => {
    if (filters.actorId && actorId(event) !== filters.actorId) return false;
    if (filters.correlationId && event.correlation_id !== filters.correlationId) return false;
    if (filters.errorsOnly && !isIssue(event)) return false;
    if (filters.category === 'error' && !isIssue(event)) return false;
    if (filters.category !== 'all' && filters.category !== 'error' && familyOf(event) !== filters.category) return false;
    if (!query) return true;
    return [event.kind, event.source, actorId(event), event.status, event.correlation_id, event.payload_json]
      .join(' ')
      .toLowerCase()
      .includes(query);
  });
}

export function countByCategory(events: TraceEvent[], category: EventCategory): number {
  if (category === 'all') return events.length;
  if (category === 'error') return events.filter(isIssue).length;
  return events.filter((event) => familyOf(event) === category).length;
}

export function isProcessNoise(event: TraceEvent): boolean {
  return ['process.stdout', 'process.stderr'].includes(event.kind) && !isIssue(event);
}

export function materialEvent(events: TraceEvent[]): TraceEvent | null {
  return events.find(isIssue)
    ?? events.find((event) => event.kind.startsWith('approval.'))
    ?? events.find((event) => event.kind.startsWith('tool.') || event.kind.startsWith('model.'))
    ?? events.find((event) => event.kind === 'agent.join' || event.kind === 'agent.delegation')
    ?? events.find((event) => !isProcessNoise(event))
    ?? events[0]
    ?? null;
}
