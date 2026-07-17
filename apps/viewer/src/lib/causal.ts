import type { TraceEvent } from './types';

export interface RelatedEventTarget {
  id: string;
  kind: 'parent' | 'child' | 'link' | 'correlation';
  present: boolean;
  event?: TraceEvent;
}

export function findEventById(events: TraceEvent[], id: string): TraceEvent | undefined {
  return events.find((event) => event.event_id === id || event.span_id === id);
}

export function childEvents(events: TraceEvent[], parentId: string): TraceEvent[] {
  return events.filter((event) => event.parent_event_id === parentId);
}

export function correlationPeers(events: TraceEvent[], correlationId: string): TraceEvent[] {
  if (!correlationId) return [];
  return events.filter((event) => event.correlation_id === correlationId);
}

export function resolveRelatedTarget(
  events: TraceEvent[],
  id: string
): { found: TraceEvent | null; missing: boolean } {
  if (!id) return { found: null, missing: false };
  const found = findEventById(events, id) ?? null;
  return { found, missing: !found };
}

export function relatedSummary(event: TraceEvent, events: TraceEvent[]) {
  const parent = event.parent_event_id
    ? resolveRelatedTarget(events, event.parent_event_id)
    : { found: null, missing: false };
  const children = childEvents(events, event.event_id);
  const peers = event.correlation_id ? correlationPeers(events, event.correlation_id) : [];
  const links = event.links.map((id) => resolveRelatedTarget(events, id));
  return {
    parent,
    children,
    peers: peers.filter((peer) => peer.event_id !== event.event_id),
    links,
    missingParent: Boolean(event.parent_event_id && parent.missing)
  };
}
