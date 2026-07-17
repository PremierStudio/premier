import { describe, expect, it } from 'vitest';
import { eventPayload, listKey, type TraceEvent, type TraceManifest } from './types';

const baseEvent = (payload_json: string): TraceEvent => ({
  event_id: 'e1',
  trace_id: 't1',
  sequence: 1,
  timestamp: '2026-01-01T00:00:00Z',
  kind: 'session.start',
  source: 'test',
  payload_json,
  actor_id: 'root',
  actor_type: 'process',
  parent_event_id: '',
  span_id: 's',
  parent_span_id: '',
  correlation_id: '',
  status: 'ok',
  duration_ms: 0,
  links: []
});

describe('eventPayload', () => {
  it('returns objects as records', () => {
    expect(eventPayload(baseEvent('{"tool":"rg"}'))).toEqual({ tool: 'rg' });
  });

  it('survives JSON null without throwing', () => {
    expect(eventPayload(baseEvent('null'))).toEqual({ value: null });
    expect(() => Object.entries(eventPayload(baseEvent('null')))).not.toThrow();
  });

  it('wraps arrays and scalars', () => {
    expect(eventPayload(baseEvent('[1,2]'))).toEqual({ items: [1, 2] });
    expect(eventPayload(baseEvent('"hello"'))).toEqual({ value: 'hello' });
    expect(eventPayload(baseEvent('42'))).toEqual({ value: 42 });
    expect(eventPayload(baseEvent('true'))).toEqual({ value: true });
  });

  it('returns raw text for invalid JSON', () => {
    expect(eventPayload(baseEvent('{broken'))).toEqual({ raw: '{broken' });
  });
});

describe('listKey', () => {
  const manifest = (overrides: Partial<TraceManifest> = {}): TraceManifest => ({
    format_version: 1,
    trace_id: 'shared-id',
    command: ['agent'],
    started_at: '2026-01-01T00:00:00Z',
    ended_at: '2026-01-01T00:00:01Z',
    exit_code: 0,
    journal: null,
    ...overrides
  });

  it('prefers artifact when present so copied traces stay unique', () => {
    expect(listKey(manifest({ artifact: 'original.atrace' }))).toBe('original.atrace');
    expect(listKey(manifest({ artifact: 'copy.atrace' }))).toBe('copy.atrace');
  });

  it('falls back to trace_id', () => {
    expect(listKey(manifest())).toBe('shared-id');
  });
});
