import { actorId, actorRole, filterEvents, isIssue, type ActorRole } from './analysis';
import type { EventFilters, TraceEvent } from './types';

export type EvidenceConfidence = 'recorded' | 'high' | 'observation-only';
export type RelationshipSource = 'parent-event' | 'parent-span';

export interface ArchitectureWindow {
  startMs: number;
  endMs: number;
  durationMs: number;
}

export interface ArchitectureActor {
  id: string;
  role: ActorRole;
  eventCount: number;
  issueCount: number;
  eventKinds: Record<string, number>;
  firstSequence: number;
  /** Overall first-to-last envelope of observed activity. */
  window: ArchitectureWindow | null;
  /**
   * Contiguous activity segments after idle gaps are split.
   * Prefer rendering these over the full envelope so late-starting or intermittent
   * agents do not look continuously active from the run origin.
   */
  segments: ArchitectureWindow[];
  confidence: EvidenceConfidence;
  source: 'actor-id' | 'fallback-root';
}

export interface ArchitectureConnection {
  id: string;
  sourceActorId: string;
  targetActorId: string;
  eventCount: number;
  issueCount: number;
  eventKinds: Record<string, number>;
  eventIds: string[];
  sources: RelationshipSource[];
  confidence: 'recorded' | 'high';
  parentEvidenceInScope: boolean;
}

export interface ArchitectureConcurrencySample {
  timestampMs: number;
  activeActorIds: string[];
  activeActorCount: number;
  activeEventCount: number;
}

export interface ArchitectureCoPresence {
  actorIds: [string, string];
  overlap: ArchitectureWindow;
  explicitlyConnected: boolean;
  confidence: 'observation-only';
  source: 'temporal-overlap';
  isRelationship: false;
}

export interface UnresolvedParent {
  eventId: string;
  actorId: string;
  reference: string;
  referenceType: 'parent-event' | 'parent-span';
  reason: 'missing' | 'ambiguous-span' | 'source-outside-scope';
}

export interface ArchitectureInference {
  actors: ArchitectureActor[];
  connections: ArchitectureConnection[];
  concurrency: ArchitectureConcurrencySample[];
  coPresence: ArchitectureCoPresence[];
  unlinkedActorIds: string[];
  unresolvedParents: UnresolvedParent[];
  scope: {
    inputEventCount: number;
    eventCount: number;
    filtered: boolean;
    temporalEventCount: number;
    startMs: number | null;
    endMs: number | null;
  };
}

export interface ArchitectureInferenceOptions {
  filters?: EventFilters;
  predicate?: (event: TraceEvent) => boolean;
}

interface ActorAccumulator {
  actor: ArchitectureActor;
  starts: number[];
  ends: number[];
}

function timestampOf(event: TraceEvent): number | null {
  const timestamp = Date.parse(event.timestamp);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function intervalOf(event: TraceEvent): ArchitectureWindow | null {
  const startMs = timestampOf(event);
  if (startMs === null) return null;
  const durationMs = Number.isFinite(event.duration_ms) ? Math.max(0, event.duration_ms) : 0;
  return { startMs, endMs: startMs + durationMs, durationMs };
}

function increment(counts: Record<string, number>, key: string): void {
  counts[key] = (counts[key] ?? 0) + 1;
}

function mergeIntervals(intervals: ArchitectureWindow[]): ArchitectureWindow[] {
  if (!intervals.length) return [];
  const sorted = [...intervals].sort((a, b) => a.startMs - b.startMs || a.endMs - b.endMs);
  const merged: ArchitectureWindow[] = [{ ...sorted[0] }];
  for (let index = 1; index < sorted.length; index += 1) {
    const current = sorted[index];
    const last = merged[merged.length - 1];
    if (current.startMs <= last.endMs) {
      last.endMs = Math.max(last.endMs, current.endMs);
      last.durationMs = Math.max(0, last.endMs - last.startMs);
    } else {
      merged.push({ ...current });
    }
  }
  return merged;
}

/** Split idle gaps so intermittent agents are not painted as continuous from first to last. */
export function activitySegments(
  intervals: ArchitectureWindow[],
  gapMs: number
): ArchitectureWindow[] {
  const merged = mergeIntervals(intervals);
  if (merged.length <= 1) return merged;
  const segments: ArchitectureWindow[] = [];
  let current = { ...merged[0] };
  for (let index = 1; index < merged.length; index += 1) {
    const next = merged[index];
    if (next.startMs <= current.endMs + gapMs) {
      current.endMs = Math.max(current.endMs, next.endMs);
      current.durationMs = Math.max(0, current.endMs - current.startMs);
    } else {
      segments.push(current);
      current = { ...next };
    }
  }
  segments.push(current);
  return segments;
}

/** Prefer orchestrator / main agent as the starting plane of the actor list. */
export function orchestratorRank(actor: Pick<ArchitectureActor, 'id' | 'role'>): number {
  const id = actor.id.trim().toLowerCase();
  const orchestratorNames = [
    'coordinator',
    'orchestrator',
    'supervisor',
    'conductor',
    'manager',
    'main',
    'primary',
    'root',
    'planner'
  ];
  if (orchestratorNames.some((name) => id === name || id.startsWith(`${name}-`) || id.endsWith(`-${name}`))) {
    return 0;
  }
  if (actor.role === 'agent') return 1;
  if (actor.role === 'process' && id === 'root') return 2;
  if (actor.role === 'human') return 3;
  if (actor.role === 'system') return 4;
  if (actor.role === 'subagent') return 5;
  if (actor.role === 'process') return 6;
  return 7;
}

function compareActors(a: ArchitectureActor, b: ArchitectureActor): number {
  const rank = orchestratorRank(a) - orchestratorRank(b);
  if (rank !== 0) return rank;
  const aStart = a.window?.startMs ?? Number.POSITIVE_INFINITY;
  const bStart = b.window?.startMs ?? Number.POSITIVE_INFINITY;
  if (aStart !== bStart) return aStart - bStart;
  return a.firstSequence - b.firstSequence;
}

function scopedEvents(events: TraceEvent[], options: ArchitectureInferenceOptions): TraceEvent[] {
  let scoped = options.filters ? filterEvents(events, options.filters) : [...events];
  if (options.predicate) scoped = scoped.filter(options.predicate);
  return scoped;
}

/**
 * Builds an evidence-backed architecture model from recorded trace events.
 * Only parent_event_id and unambiguous parent_span_id references become connections.
 * Temporal overlap is returned separately and is never promoted to a relationship.
 */
export function inferArchitecture(
  events: TraceEvent[],
  options: ArchitectureInferenceOptions = {}
): ArchitectureInference {
  const scoped = scopedEvents(events, options).sort((a, b) => a.sequence - b.sequence);
  const scopedIds = new Set(scoped.map((event) => event.event_id));
  const actors = new Map<string, ActorAccumulator>();

  for (const event of scoped) {
    const id = actorId(event);
    const accumulator = actors.get(id) ?? {
      actor: {
        id,
        role: actorRole(event),
        eventCount: 0,
        issueCount: 0,
        eventKinds: {},
        firstSequence: event.sequence,
        window: null,
        segments: [],
        confidence: event.actor_id ? 'recorded' : 'high',
        source: event.actor_id ? 'actor-id' : 'fallback-root'
      },
      starts: [],
      ends: []
    };
    // Prefer first-seen role when it is more specific than a later generic label.
    if (accumulator.actor.role === 'process' && actorRole(event) !== 'process') {
      accumulator.actor.role = actorRole(event);
    }
    accumulator.actor.eventCount += 1;
    accumulator.actor.issueCount += isIssue(event) ? 1 : 0;
    increment(accumulator.actor.eventKinds, event.kind);
    accumulator.actor.firstSequence = Math.min(accumulator.actor.firstSequence, event.sequence);
    const interval = intervalOf(event);
    if (interval) {
      accumulator.starts.push(interval.startMs);
      accumulator.ends.push(interval.endMs);
    }
    actors.set(id, accumulator);
  }

  const allStarts = [...actors.values()].flatMap((entry) => entry.starts);
  const allEnds = [...actors.values()].flatMap((entry) => entry.ends);
  const runStart = allStarts.length ? Math.min(...allStarts) : 0;
  const runEnd = allEnds.length ? Math.max(...allEnds) : runStart;
  const runSpan = Math.max(0, runEnd - runStart);
  // Gap threshold: idle stretches beyond 8% of the run (min 400ms, max 30s) break activity segments.
  const gapMs = Math.min(30_000, Math.max(400, runSpan * 0.08));

  for (const accumulator of actors.values()) {
    if (!accumulator.starts.length) continue;
    const intervals = accumulator.starts.map((startMs, index) => {
      const endMs = accumulator.ends[index] ?? startMs;
      return { startMs, endMs, durationMs: Math.max(0, endMs - startMs) };
    });
    const segments = activitySegments(intervals, gapMs);
    accumulator.actor.segments = segments;
    const startMs = segments[0]?.startMs ?? Math.min(...accumulator.starts);
    const endMs = segments.at(-1)?.endMs ?? Math.max(...accumulator.ends);
    accumulator.actor.window = { startMs, endMs, durationMs: Math.max(0, endMs - startMs) };
  }

  const byEvent = new Map(events.map((event) => [event.event_id, event]));
  const bySpan = new Map<string, TraceEvent[]>();
  for (const event of events) {
    if (!event.span_id) continue;
    const entries = bySpan.get(event.span_id) ?? [];
    entries.push(event);
    bySpan.set(event.span_id, entries);
  }

  const connections = new Map<string, ArchitectureConnection>();
  const unresolvedParents: UnresolvedParent[] = [];
  for (const event of scoped) {
    let parent: TraceEvent | undefined;
    let source: RelationshipSource | undefined;
    let reference = '';
    let unresolvedReason: UnresolvedParent['reason'] | undefined;

    if (event.parent_event_id) {
      reference = event.parent_event_id;
      source = 'parent-event';
      parent = byEvent.get(reference);
      if (!parent) unresolvedReason = 'missing';
    } else if (event.parent_span_id) {
      reference = event.parent_span_id;
      source = 'parent-span';
      const candidates = bySpan.get(reference) ?? [];
      const parentActors = new Set(candidates.map(actorId));
      if (parentActors.size === 1) parent = candidates.sort((a, b) => a.sequence - b.sequence)[0];
      else unresolvedReason = candidates.length ? 'ambiguous-span' : 'missing';
    }

    if (!source) continue;
    if (!parent) {
      unresolvedParents.push({ eventId: event.event_id, actorId: actorId(event), reference, referenceType: source, reason: unresolvedReason ?? 'missing' });
      continue;
    }
    const sourceActorId = actorId(parent);
    const targetActorId = actorId(event);
    if (sourceActorId === targetActorId) continue;
    if (!actors.has(sourceActorId)) {
      unresolvedParents.push({ eventId: event.event_id, actorId: targetActorId, reference, referenceType: source, reason: 'source-outside-scope' });
      continue;
    }
    const id = `${sourceActorId}\u0000${targetActorId}`;
    const connection = connections.get(id) ?? {
      id,
      sourceActorId,
      targetActorId,
      eventCount: 0,
      issueCount: 0,
      eventKinds: {},
      eventIds: [],
      sources: [],
      confidence: source === 'parent-event' ? 'recorded' : 'high',
      parentEvidenceInScope: true
    };
    connection.eventCount += 1;
    connection.issueCount += isIssue(event) ? 1 : 0;
    increment(connection.eventKinds, event.kind);
    connection.eventIds.push(event.event_id);
    if (!connection.sources.includes(source)) connection.sources.push(source);
    if (source === 'parent-event') connection.confidence = 'recorded';
    connection.parentEvidenceInScope &&= scopedIds.has(parent.event_id);
    connections.set(id, connection);
  }

  const temporalEvents = scoped
    .map((event) => ({ event, interval: intervalOf(event) }))
    .filter((entry): entry is { event: TraceEvent; interval: ArchitectureWindow } => entry.interval !== null);
  const boundaryMap = new Map<number, { starts: typeof temporalEvents; ends: typeof temporalEvents }>();
  for (const entry of temporalEvents) {
    const startBoundary = boundaryMap.get(entry.interval.startMs) ?? { starts: [], ends: [] };
    startBoundary.starts.push(entry);
    boundaryMap.set(entry.interval.startMs, startBoundary);
    const endBoundary = boundaryMap.get(entry.interval.endMs) ?? { starts: [], ends: [] };
    endBoundary.ends.push(entry);
    boundaryMap.set(entry.interval.endMs, endBoundary);
  }
  const boundaries = [...boundaryMap.keys()].sort((a, b) => a - b);
  const active = new Map<string, TraceEvent>();
  const concurrency = boundaries.map((timestampMs) => {
    const boundary = boundaryMap.get(timestampMs)!;
    for (const { event } of boundary.starts) active.set(event.event_id, event);
    const activeActorIds = [...new Set([...active.values()].map(actorId))];
    const sample = { timestampMs, activeActorIds, activeActorCount: activeActorIds.length, activeEventCount: active.size };
    for (const { event } of boundary.ends) active.delete(event.event_id);
    return sample;
  });

  const actorList = [...actors.values()].map(({ actor }) => actor).sort(compareActors);
  const connectedActors = new Set([...connections.values()].flatMap((edge) => [edge.sourceActorId, edge.targetActorId]));
  const coPresence: ArchitectureCoPresence[] = [];
  for (let index = 0; index < actorList.length; index += 1) {
    const left = actorList[index];
    if (!left.window) continue;
    for (let peerIndex = index + 1; peerIndex < actorList.length; peerIndex += 1) {
      const right = actorList[peerIndex];
      if (!right.window) continue;
      const startMs = Math.max(left.window.startMs, right.window.startMs);
      const endMs = Math.min(left.window.endMs, right.window.endMs);
      if (startMs > endMs) continue;
      const explicitlyConnected = connections.has(`${left.id}\u0000${right.id}`) || connections.has(`${right.id}\u0000${left.id}`);
      coPresence.push({
        actorIds: [left.id, right.id],
        overlap: { startMs, endMs, durationMs: Math.max(0, endMs - startMs) },
        explicitlyConnected,
        confidence: 'observation-only',
        source: 'temporal-overlap',
        isRelationship: false
      });
    }
  }

  return {
    actors: actorList,
    connections: [...connections.values()],
    concurrency,
    coPresence,
    unlinkedActorIds: actorList.filter((actor) => !connectedActors.has(actor.id)).map((actor) => actor.id),
    unresolvedParents,
    scope: {
      inputEventCount: events.length,
      eventCount: scoped.length,
      filtered: scoped.length !== events.length,
      temporalEventCount: temporalEvents.length,
      startMs: boundaries[0] ?? null,
      endMs: boundaries.at(-1) ?? null
    }
  };
}
