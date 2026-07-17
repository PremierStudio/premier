import type { EventCategory, EventFilters } from './types';

export type ViewMode = 'timeline' | 'analytics' | 'map';

export interface InvestigationState {
  traceId?: string | null;
  /** Stable event identity used by newly generated links. */
  eventId?: string | null;
  /** Legacy sequence locator retained for old shared links. */
  eventSequence?: number | null;
  filters: EventFilters;
  viewMode: ViewMode;
  windowStart: number | null;
  windowEnd: number | null;
}

const emptyFilters = (): EventFilters => ({
  search: '',
  category: 'all',
  actorId: null,
  errorsOnly: false,
  correlationId: null
});

export function defaultInvestigationState(): InvestigationState {
  return {
    filters: emptyFilters(),
    viewMode: 'timeline',
    windowStart: null,
    windowEnd: null
  };
}

/** Serialize investigation scope into a URL. Used by app copy + inspector copy. */
export function serializeInvestigationUrl(
  base: string | URL,
  state: InvestigationState
): string {
  const url = new URL(typeof base === 'string' ? base : base.toString());
  const params = url.searchParams;

  if (state.traceId) params.set('trace', state.traceId);
  else params.delete('trace');

  if (state.eventId) {
    params.set('event_id', state.eventId);
    params.delete('event');
  } else if (state.eventSequence !== undefined && state.eventSequence !== null) {
    params.delete('event_id');
    params.set('event', String(state.eventSequence));
  } else {
    params.delete('event_id');
    params.delete('event');
  }

  const { filters } = state;
  if (filters.actorId) params.set('actor', filters.actorId);
  else params.delete('actor');
  if (filters.category !== 'all') params.set('kind', filters.category);
  else params.delete('kind');
  if (filters.search) params.set('q', filters.search);
  else params.delete('q');
  if (filters.errorsOnly) params.set('errors', '1');
  else params.delete('errors');
  if (filters.correlationId) params.set('corr', filters.correlationId);
  else params.delete('corr');

  if (state.viewMode === 'timeline') params.delete('view');
  else params.set('view', state.viewMode);

  if (state.windowStart !== null && state.windowEnd !== null) {
    params.set('from', String(Number(state.windowStart.toFixed(3))));
    params.set('to', String(Number(state.windowEnd.toFixed(3))));
  } else {
    params.delete('from');
    params.delete('to');
  }

  return url.toString();
}

export function parseInvestigationParams(params: URLSearchParams): InvestigationState {
  const requestedCategory = params.get('kind');
  const requestedView = params.get('view');
  const requestedFrom = Number(params.get('from'));
  const requestedTo = Number(params.get('to'));
  const eventParam = params.get('event');

  let windowStart: number | null = null;
  let windowEnd: number | null = null;
  if (
    params.has('from') &&
    params.has('to') &&
    Number.isFinite(requestedFrom) &&
    Number.isFinite(requestedTo) &&
    requestedFrom >= 0
  ) {
    windowStart = Math.min(requestedFrom, requestedTo);
    windowEnd = Math.max(requestedFrom, requestedTo);
  }

  return {
    traceId: params.get('trace'),
    eventId: params.get('event_id'),
    eventSequence:
      eventParam !== null && Number.isFinite(Number(eventParam)) ? Number(eventParam) : null,
    filters: {
      search: params.get('q') ?? '',
      category: (['agent', 'model', 'tool', 'approval', 'process', 'error'] as EventCategory[]).includes(
        (requestedCategory ?? '') as EventCategory
      )
        ? (requestedCategory as EventCategory)
        : 'all',
      actorId: params.get('actor'),
      errorsOnly: params.get('errors') === '1',
      correlationId: params.get('corr')
    },
    viewMode: (['timeline', 'analytics', 'map'] as ViewMode[]).includes(
      (requestedView ?? '') as ViewMode
    )
      ? (requestedView as ViewMode)
      : 'timeline',
    windowStart,
    windowEnd
  };
}

export function clearScopeFilters(filters: EventFilters): EventFilters {
  return {
    ...filters,
    search: '',
    category: 'all',
    actorId: null,
    errorsOnly: false,
    correlationId: null
  };
}

export function scopeIsActive(
  filters: EventFilters,
  windowStart: number | null
): boolean {
  return Boolean(
    filters.search ||
      filters.actorId ||
      filters.category !== 'all' ||
      filters.errorsOnly ||
      filters.correlationId ||
      windowStart !== null
  );
}
