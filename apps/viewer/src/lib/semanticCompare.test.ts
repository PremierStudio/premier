import { describe, expect, it } from 'vitest';
import { compareTraces } from './semanticCompare';
import type { TraceEvent } from './types';

const event = (traceId: string, sequence: number, kind: string, overrides: Partial<TraceEvent> = {}): TraceEvent => ({
  event_id: `${traceId}-${sequence}`,
  trace_id: traceId,
  sequence,
  timestamp: `2026-07-15T12:00:0${sequence}.000Z`,
  kind,
  source: 'sdk',
  payload_json: '{}',
  actor_id: 'coordinator',
  actor_type: 'agent',
  parent_event_id: '',
  span_id: `${traceId}-span-${sequence}`,
  parent_span_id: '',
  correlation_id: `${traceId}-generated-id`,
  status: 'ok',
  duration_ms: 10,
  links: [],
  ...overrides
});

describe('compareTraces', () => {
  it('aligns semantically equivalent events despite regenerated ids and correlations', () => {
    const baseline = [event('a', 1, 'tool.execution', { payload_json: '{"tool":"search","query":"alpha"}' })];
    const current = [event('b', 9, 'tool.execution', { payload_json: '{"tool":"search","query":"alpha"}' })];
    const result = compareTraces(baseline, current);
    expect(result.items).toHaveLength(1);
    expect(result.items[0]).toMatchObject({ status: 'unchanged', baseline: { event_id: 'a-1' }, current: { event_id: 'b-9' } });
  });

  it('reports curated payload, status, duration, token, and cost deltas on aligned calls', () => {
    const baseline = [event('a', 1, 'model.response', { duration_ms: 200, payload_json: '{"model":"gpt-5","response":"old","usage":{"total_tokens":100},"cost_usd":0.1}' })];
    const current = [event('b', 1, 'model.response', { status: 'warning', duration_ms: 500, payload_json: '{"model":"gpt-5.1","response":"new","usage":{"total_tokens":160},"cost_usd":0.18}' })];
    const item = compareTraces(baseline, current).items[0];
    expect(item.status).toBe('changed');
    expect(item.deltas.durationMs).toEqual({ before: 200, after: 500, delta: 300 });
    expect(item.deltas.totalTokens).toEqual({ before: 100, after: 160, delta: 60 });
    expect(item.deltas.costUsd).toEqual({ before: 0.1, after: 0.18, delta: 0.08 });
    expect(item.changes.map((change) => change.field)).toEqual(expect.arrayContaining(['status', 'payload.model', 'payload.response']));
  });

  it('classifies different tool identities as removed and added instead of a false change', () => {
    const baseline = [event('a', 1, 'tool.execution', { payload_json: '{"tool":"grep"}' })];
    const current = [event('b', 1, 'tool.execution', { payload_json: '{"tool":"browser"}' })];
    const result = compareTraces(baseline, current);
    expect(result.counts).toMatchObject({ added: 1, removed: 1, changed: 0, unchanged: 0 });
    expect(result.items.map((item) => item.status)).toEqual(['removed', 'added']);
  });

  it('aligns repeated semantic calls by occurrence and preserves insertion order', () => {
    const baseline = [
      event('a', 1, 'tool.execution', { payload_json: '{"tool":"search","query":"one"}' }),
      event('a', 2, 'tool.execution', { payload_json: '{"tool":"search","query":"two"}' })
    ];
    const current = [
      event('b', 1, 'tool.execution', { payload_json: '{"tool":"search","query":"one"}' }),
      event('b', 2, 'tool.execution', { payload_json: '{"tool":"search","query":"changed"}' }),
      event('b', 3, 'tool.execution', { payload_json: '{"tool":"search","query":"three"}' })
    ];
    const result = compareTraces(baseline, current);
    expect(result.items.map((item) => item.status)).toEqual(['unchanged', 'changed', 'added']);
    expect(result.items[1].changes).toContainEqual(expect.objectContaining({ field: 'payload.query', before: 'two', after: 'changed' }));
  });
});
