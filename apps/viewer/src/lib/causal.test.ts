import { describe, expect, it } from 'vitest';
import { childEvents, correlationPeers, relatedSummary, resolveRelatedTarget } from './causal';
import type { TraceEvent } from './types';

const event = (overrides: Partial<TraceEvent>): TraceEvent => ({
  event_id: 'e1',
  trace_id: 't1',
  sequence: 1,
  timestamp: '2026-01-01T00:00:00Z',
  kind: 'agent.turn',
  source: 'sdk',
  payload_json: '{}',
  actor_id: 'agent',
  actor_type: 'agent',
  parent_event_id: '',
  span_id: 's1',
  parent_span_id: '',
  correlation_id: '',
  status: 'ok',
  duration_ms: 0,
  links: [],
  ...overrides
});

describe('causal navigation', () => {
  it('finds children by parent_event_id', () => {
    const parent = event({ event_id: 'parent', sequence: 1 });
    const child = event({ event_id: 'child', sequence: 2, parent_event_id: 'parent' });
    expect(childEvents([parent, child], 'parent')).toEqual([child]);
  });

  it('groups correlation peers excluding self', () => {
    const a = event({ event_id: 'a', correlation_id: 'corr-1', sequence: 1 });
    const b = event({ event_id: 'b', correlation_id: 'corr-1', sequence: 2 });
    const c = event({ event_id: 'c', correlation_id: 'other', sequence: 3 });
    expect(correlationPeers([a, b, c], 'corr-1')).toHaveLength(2);
    expect(relatedSummary(a, [a, b, c]).peers.map((peer) => peer.event_id)).toEqual(['b']);
  });

  it('marks missing parents explicitly', () => {
    const orphan = event({ event_id: 'orphan', parent_event_id: 'gone', sequence: 1 });
    const summary = relatedSummary(orphan, [orphan]);
    expect(summary.missingParent).toBe(true);
    expect(resolveRelatedTarget([orphan], 'gone')).toEqual({ found: null, missing: true });
  });

  it('handles empty ids and empty correlation gracefully', () => {
    expect(resolveRelatedTarget([], '')).toEqual({ found: null, missing: false });
    expect(correlationPeers([event({ event_id: 'a' })], '')).toEqual([]);
    const root = event({ event_id: 'root', parent_event_id: '', correlation_id: '' });
    expect(relatedSummary(root, [root]).missingParent).toBe(false);
    expect(relatedSummary(root, [root]).peers).toEqual([]);
  });
});
