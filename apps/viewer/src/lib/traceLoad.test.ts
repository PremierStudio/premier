import { describe, expect, it } from 'vitest';
import {
  applyTraceComplete,
  mergeLiveEvent,
  mergeLiveEvents,
  resolveSelectedEvent,
  shouldCommitLoad
} from './traceLoad';
import type { TraceEvent, TraceManifest } from './types';

const event = (sequence: number, id = `e${sequence}`): TraceEvent => ({
  event_id: id,
  trace_id: 't1',
  sequence,
  timestamp: '2026-01-01T00:00:00Z',
  kind: 'tool.execution',
  source: 'sdk',
  payload_json: '{}',
  actor_id: 'agent',
  actor_type: 'agent',
  parent_event_id: '',
  span_id: 's',
  parent_span_id: '',
  correlation_id: '',
  status: 'ok',
  duration_ms: 0,
  links: []
});

const manifest = (id: string, ended = true): TraceManifest => ({
  format_version: 1,
  trace_id: id,
  command: ['agent'],
  started_at: '2026-01-01T00:00:00Z',
  ended_at: ended ? '2026-01-01T00:00:01Z' : null,
  exit_code: ended ? 0 : null,
  journal: ended ? { path: 'events/000001.events.pb.zst', sha256: 'abc', event_count: 1 } : null
});

describe('shouldCommitLoad', () => {
  it('accepts only the latest epoch', () => {
    expect(shouldCommitLoad(3, 3)).toBe(true);
    expect(shouldCommitLoad(2, 3)).toBe(false);
  });
});

describe('resolveSelectedEvent', () => {
  it('uses the desired sequence when still in scope', () => {
    const events = [event(1), event(2)];
    const selected = resolveSelectedEvent(events, events, { eventSequence: 2 }, () => events[0]);
    expect(selected?.sequence).toBe(2);
  });

  it('keeps the requested event instead of substituting when it is out of scope', () => {
    const events = [event(1), event(2)];
    const scoped = [events[0]];
    const selected = resolveSelectedEvent(events, scoped, { eventSequence: 2 }, (items) => items[0] ?? null);
    expect(selected?.sequence).toBe(2);
  });

  it('prefers a stable event id over a legacy sequence', () => {
    const events = [event(1, 'stable'), event(2, 'other')];
    const selected = resolveSelectedEvent(events, events, { eventId: 'stable', eventSequence: 2 }, () => events[1]);
    expect(selected?.event_id).toBe('stable');
  });

  it('uses material event when no desired sequence is provided', () => {
    const events = [event(1), event(2)];
    const selected = resolveSelectedEvent(events, events, undefined, (items) => items[1] ?? null);
    expect(selected?.sequence).toBe(2);
  });

  it('returns no selection when a requested event is missing entirely', () => {
    const events = [event(1)];
    const selected = resolveSelectedEvent(events, events, { eventSequence: 99 }, (items) => items[0] ?? null);
    expect(selected).toBeNull();
  });
});

describe('mergeLiveEvent', () => {
  it('appends unique events and ignores duplicates', () => {
    const first = mergeLiveEvent([], event(1));
    expect(first).toHaveLength(1);
    expect(mergeLiveEvent(first, event(1))).toHaveLength(1);
    expect(mergeLiveEvent(first, event(2))).toHaveLength(2);
  });
});

describe('mergeLiveEvents', () => {
  it('appends a burst in one rebuild and dedupes by event_id', () => {
    const base = [event(1)];
    const next = mergeLiveEvents(base, [event(1), event(2), event(3), event(2)]);
    expect(next.map((item) => item.event_id)).toEqual(['e1', 'e2', 'e3']);
  });

  it('returns the same array reference when nothing new arrives', () => {
    const base = [event(1)];
    expect(mergeLiveEvents(base, [])).toBe(base);
    expect(mergeLiveEvents(base, [event(1)])).toBe(base);
  });
});

describe('applyTraceComplete', () => {
  it('merges complete manifest onto the matching live run', () => {
    const live = manifest('t1', false);
    const complete = { ...manifest('t1', true), integrity: 'verified' as const };
    const next = applyTraceComplete(live, complete);
    expect(next?.ended_at).toBeTruthy();
    expect(next?.integrity).toBe('verified');
  });

  it('ignores complete events for a different run', () => {
    const current = manifest('a', false);
    expect(applyTraceComplete(current, manifest('b', true))).toEqual(current);
    expect(applyTraceComplete(null, manifest('a', true))).toBeNull();
  });
});
