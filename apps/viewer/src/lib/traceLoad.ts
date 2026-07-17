import type { TraceEvent, TraceManifest } from './types';

export interface TraceLoadResult {
  trace: TraceManifest;
  events: TraceEvent[];
  selectedEvent: TraceEvent | null;
}

export interface EventRequest {
  eventId?: string | null;
  eventSequence?: number | null;
}

/**
 * Atomic load commit: only apply a completed fetch when it still matches the
 * latest requested epoch. Prevents run A events under run B's identity.
 */
export function shouldCommitLoad(requestEpoch: number, currentEpoch: number): boolean {
  return requestEpoch === currentEpoch;
}

export function resolveSelectedEvent(
  events: TraceEvent[],
  scopedEvents: TraceEvent[],
  request: EventRequest | undefined,
  materialEvent: (events: TraceEvent[]) => TraceEvent | null
): TraceEvent | null {
  // Requested identity is a trust boundary: resolve that exact event or none.
  if (request?.eventId) {
    return events.find((event) => event.event_id === request.eventId) ?? null;
  }
  if (request?.eventSequence !== undefined && request.eventSequence !== null) {
    return events.find((event) => event.sequence === request.eventSequence) ?? null;
  }
  return materialEvent(scopedEvents);
}

export function mergeLiveEvent(events: TraceEvent[], incoming: TraceEvent): TraceEvent[] {
  if (events.some((event) => event.event_id === incoming.event_id)) return events;
  return [...events, incoming];
}

/** Merge a burst of stream events in one array rebuild (dedupes by event_id). */
export function mergeLiveEvents(events: TraceEvent[], incoming: TraceEvent[]): TraceEvent[] {
  if (!incoming.length) return events;
  const seen = new Set(events.map((event) => event.event_id));
  const appended: TraceEvent[] = [];
  for (const event of incoming) {
    if (seen.has(event.event_id)) continue;
    seen.add(event.event_id);
    appended.push(event);
  }
  return appended.length ? [...events, ...appended] : events;
}

export function applyTraceComplete(
  current: TraceManifest | null,
  complete: TraceManifest
): TraceManifest | null {
  if (!current || current.trace_id !== complete.trace_id) return current;
  return { ...current, ...complete };
}
