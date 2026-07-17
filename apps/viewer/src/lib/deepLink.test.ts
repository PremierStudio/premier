import { describe, expect, it } from 'vitest';
import {
  clearScopeFilters,
  defaultInvestigationState,
  parseInvestigationParams,
  scopeIsActive,
  serializeInvestigationUrl
} from './deepLink';

describe('deep link serializer', () => {
  it('round-trips filters, view, window, and correlation', () => {
    const state = {
      traceId: 'trace-1',
      eventId: 'event-stable-12',
      eventSequence: null,
      filters: {
        search: 'billing',
        category: 'tool' as const,
        actorId: 'coder',
        errorsOnly: true,
        correlationId: 'approval-patch-01'
      },
      viewMode: 'analytics' as const,
      windowStart: 10.5,
      windowEnd: 40.25
    };
    const href = serializeInvestigationUrl('http://127.0.0.1:4317/', state);
    const parsed = parseInvestigationParams(new URL(href).searchParams);
    expect(parsed).toEqual(state);
  });

  it('prefers a stable event id while accepting legacy sequence links', () => {
    const stableHref = serializeInvestigationUrl('http://127.0.0.1:4317/?event=9', {
      ...defaultInvestigationState(),
      traceId: 't1',
      eventId: '019f-event-id',
      eventSequence: 9
    });
    const stable = new URL(stableHref);
    expect(stable.searchParams.get('event_id')).toBe('019f-event-id');
    expect(stable.searchParams.has('event')).toBe(false);
    expect(parseInvestigationParams(stable.searchParams).eventId).toBe('019f-event-id');

    const legacy = parseInvestigationParams(new URLSearchParams('trace=t1&event=9'));
    expect(legacy.eventId).toBeNull();
    expect(legacy.eventSequence).toBe(9);
  });

  it('omits default timeline view and empty scope', () => {
    const href = serializeInvestigationUrl('http://127.0.0.1:4317/', {
      ...defaultInvestigationState(),
      traceId: 't1',
      eventId: null,
      eventSequence: 2
    });
    const url = new URL(href);
    expect(url.searchParams.get('trace')).toBe('t1');
    expect(url.searchParams.get('event')).toBe('2');
    expect(url.searchParams.has('view')).toBe(false);
    expect(url.searchParams.has('q')).toBe(false);
    expect(url.searchParams.has('corr')).toBe(false);
  });

  it('accepts URL objects as the base', () => {
    const href = serializeInvestigationUrl(new URL('http://127.0.0.1:4317/workspace'), {
      ...defaultInvestigationState(),
      traceId: 't9',
      eventId: null,
      eventSequence: undefined
    });
    expect(href).toContain('/workspace');
    expect(new URL(href).searchParams.get('trace')).toBe('t9');
    expect(new URL(href).searchParams.has('event')).toBe(false);
  });

  it('clears optional params when values are empty', () => {
    const seeded = serializeInvestigationUrl('http://127.0.0.1:4317/?trace=old&event=9&q=x&corr=c&view=map&from=1&to=2', {
      ...defaultInvestigationState(),
      traceId: null,
      eventId: null,
      eventSequence: null,
      filters: {
        search: '',
        category: 'all',
        actorId: null,
        errorsOnly: false,
        correlationId: null
      },
      viewMode: 'timeline',
      windowStart: null,
      windowEnd: null
    });
    const params = new URL(seeded).searchParams;
    expect(params.has('trace')).toBe(false);
    expect(params.has('event')).toBe(false);
    expect(params.has('q')).toBe(false);
    expect(params.has('corr')).toBe(false);
    expect(params.has('view')).toBe(false);
    expect(params.has('from')).toBe(false);
  });

  it('preserves scope when only event changes (inspector copy contract)', () => {
    const base = serializeInvestigationUrl('http://127.0.0.1:4317/', {
      traceId: 't1',
      eventId: null,
      eventSequence: 1,
      filters: {
        search: 'ledger',
        category: 'agent',
        actorId: 'reviewer',
        errorsOnly: false,
        correlationId: 'workstream'
      },
      viewMode: 'map',
      windowStart: 0,
      windowEnd: 100
    });
    const next = serializeInvestigationUrl(base, {
      ...parseInvestigationParams(new URL(base).searchParams),
      eventId: 'event-12',
      eventSequence: 12
    });
    const params = new URL(next).searchParams;
    expect(params.get('event_id')).toBe('event-12');
    expect(params.has('event')).toBe(false);
    expect(params.get('q')).toBe('ledger');
    expect(params.get('kind')).toBe('agent');
    expect(params.get('actor')).toBe('reviewer');
    expect(params.get('corr')).toBe('workstream');
    expect(params.get('view')).toBe('map');
    expect(params.get('from')).toBe('0');
    expect(params.get('to')).toBe('100');
  });
});

describe('clear scope', () => {
  it('clears all filter facets including correlation', () => {
    expect(
      clearScopeFilters({
        search: 'x',
        category: 'error',
        actorId: 'a',
        errorsOnly: true,
        correlationId: 'c'
      })
    ).toEqual({
      search: '',
      category: 'all',
      actorId: null,
      errorsOnly: false,
      correlationId: null
    });
  });

  it('detects active scope from filters or time window', () => {
    expect(scopeIsActive(clearScopeFilters({
      search: '', category: 'all', actorId: null, errorsOnly: false, correlationId: null
    }), null)).toBe(false);
    expect(scopeIsActive({
      search: '', category: 'all', actorId: null, errorsOnly: false, correlationId: 'c'
    }, null)).toBe(true);
    expect(scopeIsActive(clearScopeFilters({
      search: '', category: 'all', actorId: null, errorsOnly: false, correlationId: null
    }), 10)).toBe(true);
  });
});
