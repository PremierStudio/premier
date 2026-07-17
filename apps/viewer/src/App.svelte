<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api } from './lib/api';
  import type { EventFilters, TraceEvent, TraceManifest } from './lib/types';
  import { listKey } from './lib/types';
  import { filterEvents, isIssue, materialEvent, runHealth } from './lib/analysis';
  import { applyTraceComplete, mergeLiveEvents, resolveSelectedEvent, shouldCommitLoad, type EventRequest } from './lib/traceLoad';
  import { readViewSession, writeViewSession, clearViewSession } from './lib/viewSession';
  import TraceList from './lib/TraceList.svelte';
  import EventTimeline from './lib/EventTimeline.svelte';
  import Inspector from './lib/Inspector.svelte';
  import RunOverview from './lib/RunOverview.svelte';
  import FilterBar from './lib/FilterBar.svelte';
  import SplitHandle from './lib/SplitHandle.svelte';
  import RowResizeHandle from './lib/RowResizeHandle.svelte';
  import TraceAnalytics from './lib/TraceAnalytics.svelte';
  import ArchitectureView from './lib/ArchitectureView.svelte';
  import LocalAssistant from './lib/LocalAssistant.svelte';
  import PremierSelect from './lib/PremierSelect.svelte';
  import InvestigationSummary from './lib/InvestigationSummary.svelte';
  import TraceComparison from './lib/TraceComparison.svelte';
  import { deriveRunIdentity } from './lib/runIdentity';
  import { focusTrap } from './lib/interactions';
  import { findEventById } from './lib/causal';
  import {
    clearScopeFilters,
    parseInvestigationParams,
    scopeIsActive,
    serializeInvestigationUrl,
    type ViewMode
  } from './lib/deepLink';

  const layoutKey = 'premier.viewer.workspace.v1';
  const defaultLeftWidth = 260;
  const defaultRightWidth = 420;
  const defaultTimeNavigatorHeight = 184;
  const leftRailWidth = 48;
  const rightRailWidth = 52;
  const leftLimits = { min: 180, max: 420 };
  const rightLimits = { min: 360, max: 640 };
  const timeNavigatorLimits = { min: 148, max: 420 };
  const emptyFilters = (): EventFilters => ({
    search: '', category: 'all', actorId: null, errorsOnly: false, correlationId: null
  });

  /** Restore last investigation paint so hard refresh does not flash empty chrome. */
  const bootParams = typeof window !== 'undefined' ? new URLSearchParams(window.location.search) : null;
  const bootInvestigation = bootParams ? parseInvestigationParams(bootParams) : null;
  const bootSession = bootInvestigation ? readViewSession(bootInvestigation.traceId) : null;
  const bootEventRequest: EventRequest | undefined = bootInvestigation?.eventId || bootInvestigation?.eventSequence !== null
    ? { eventId: bootInvestigation?.eventId, eventSequence: bootInvestigation?.eventSequence }
    : bootSession?.selectedSequence
      ? { eventSequence: bootSession.selectedSequence }
      : undefined;
  const bootSelected = bootSession
    ? resolveSelectedEvent(
      bootSession.events,
      filterEvents(bootSession.events, bootInvestigation?.filters ?? emptyFilters()),
      bootEventRequest,
      materialEvent
    )
    : null;

  let traces = $state<TraceManifest[]>(bootSession?.traces ?? []);
  let events = $state<TraceEvent[]>(bootSession?.events ?? []);
  let selectedTrace = $state<TraceManifest | null>(bootSession?.selectedTrace ?? null);
  let selectedEvent = $state<TraceEvent | null>(bootSelected);
  let loading = $state(!bootSession);
  let error = $state<string | null>(null);
  let fatalError = $state<string | null>(null);
  let live = $state(false);
  let streamState = $state<'recorded' | 'connecting' | 'live' | 'reconnecting' | 'disconnected'>('recorded');
  let actionFeedback = $state('');
  let replaying = $state(false);
  let replayTimer: number | null = null;
  let compareOpen = $state(false);
  let baselineId = $state('');
  let comparisonLoading = $state(false);
  let comparisonError = $state('');
  let comparison = $state<{ baseline: TraceManifest; baselineEvents: TraceEvent[] } | null>(null);
  let closeStream: (() => void) | null = null;
  let loadEpoch = 0;
  let traceLoading = $state(Boolean(bootSession));
  /** Dim evidence only when the painted payload is not a warm stand-in for the request. */
  let contentStale = $state(false);
  /** Optimistic selection while a run is loading (stale-while-revalidate). */
  let pendingTraceId = $state<string | null>(bootSession?.selectedTrace.trace_id ?? null);
  let liveFlushTimer: number | null = null;
  let pendingLiveEvents: TraceEvent[] = [];
  let filters = $state<EventFilters>(bootInvestigation?.filters ?? emptyFilters());
  let workspaceElement = $state<HTMLDivElement | null>(null);
  let runShellElement = $state<HTMLDivElement | null>(null);
  let leftWidth = $state(defaultLeftWidth);
  let rightWidth = $state(defaultRightWidth);
  let timeNavigatorHeight = $state(defaultTimeNavigatorHeight);
  let leftCollapsed = $state(false);
  let rightCollapsed = $state(false);
  let viewMode = $state<ViewMode>(bootInvestigation?.viewMode ?? 'timeline');
  let assistantOpen = $state(false);
  let moreOpen = $state(false);
  let moreButton = $state<HTMLButtonElement>();
  let moreMenu = $state<HTMLDivElement>();
  let runsSheetOpen = $state(false);
  let shortcutsOpen = $state(false);
  let relatedFeedback = $state('');
  let missingEventReference = $state<string | null>(
    bootEventRequest && !bootSelected ? describeEventRequest(bootEventRequest) : null
  );
  let architectureWindowStart = $state<number | null>(bootInvestigation?.windowStart ?? null);
  let architectureWindowEnd = $state<number | null>(bootInvestigation?.windowEnd ?? null);
  let pollTimer: number | null = null;
  let sessionWriteTimer: number | null = null;
  let windowedEvents = $derived(timeScopedEvents(events));
  let windowedVisibleEvents = $derived(filterEvents(windowedEvents, filters));
  let categoryCounts = $derived.by(() => Object.fromEntries(
    (['all', 'agent', 'model', 'tool', 'approval', 'process', 'error'] as const).map((category) => [
      category,
      filterEvents(windowedEvents, { ...filters, category, errorsOnly: false }).length
    ])
  ) as Record<EventFilters['category'], number>);
  let rightCompact = $derived(rightCollapsed || !selectedEvent);
  let filtersActive = $derived(scopeIsActive(filters, architectureWindowStart));

  function traceTimeBounds(input: TraceEvent[]): { start: number; span: number } | null {
    const timestamps = input.map((event) => Date.parse(event.timestamp)).filter(Number.isFinite);
    if (!timestamps.length) return null;
    const start = Math.min(...timestamps);
    const end = Math.max(...input.map((event) => {
      const timestamp = Date.parse(event.timestamp);
      return Number.isFinite(timestamp) ? timestamp + Math.max(0, event.duration_ms || 0) : start;
    }));
    return { start, span: Math.max(1, end - start) };
  }

  function normalizedWindow(input: TraceEvent[], startMs: number, endMs: number): [number, number] {
    const bounds = traceTimeBounds(input);
    const span = bounds?.span ?? 1;
    const minimum = Math.max(1, span / 500);
    let start = Math.max(0, Math.min(span, Math.min(startMs, endMs)));
    let end = Math.max(0, Math.min(span, Math.max(startMs, endMs)));
    if (end - start < minimum) {
      if (start + minimum <= span) end = start + minimum;
      else start = Math.max(0, end - minimum);
    }
    return [start, end];
  }

  function timeScopedEvents(input: TraceEvent[]): TraceEvent[] {
    if (architectureWindowStart === null || architectureWindowEnd === null || !input.length) return input;
    const bounds = traceTimeBounds(input);
    if (!bounds) return input;
    const [from, to] = normalizedWindow(input, architectureWindowStart, architectureWindowEnd);
    return input.filter((event) => {
      const timestamp = Date.parse(event.timestamp);
      const offset = timestamp - bounds.start;
      const endOffset = offset + Math.max(0, event.duration_ms || 0);
      return Number.isFinite(offset) && offset <= to && endOffset >= from;
    });
  }

  function runTitle(trace: TraceManifest): string {
    return deriveRunIdentity(trace, { goal: trace.summary?.display_name }).title;
  }

  function safeNumber(value: unknown, fallback: number, min: number, max: number) {
    return typeof value === 'number' && Number.isFinite(value) ? Math.min(max, Math.max(min, value)) : fallback;
  }

  function restoreLayout() {
    try {
      const saved = JSON.parse(localStorage.getItem(layoutKey) ?? '{}') as Record<string, unknown>;
      leftWidth = safeNumber(saved.leftWidth, defaultLeftWidth, leftLimits.min, leftLimits.max);
      rightWidth = safeNumber(saved.rightWidth, defaultRightWidth, rightLimits.min, rightLimits.max);
      timeNavigatorHeight = safeNumber(saved.timeNavigatorHeight, defaultTimeNavigatorHeight, timeNavigatorLimits.min, timeNavigatorLimits.max);
      leftCollapsed = saved.leftCollapsed === true;
      rightCollapsed = saved.rightCollapsed === true;
    } catch {
      // Ignore malformed or unavailable storage and retain the safe defaults.
    }
  }

  function persistLayout() {
    try {
      localStorage.setItem(layoutKey, JSON.stringify({ leftWidth, rightWidth, timeNavigatorHeight, leftCollapsed, rightCollapsed }));
    } catch {
      // Private browsing and storage policies must not break the workspace.
    }
  }

  function resizePane(side: 'left' | 'right', requested: number) {
    const ownLimits = side === 'left' ? leftLimits : rightLimits;
    const otherWidth = side === 'left' ? (rightCompact ? rightRailWidth : rightWidth) : (leftCollapsed ? leftRailWidth : leftWidth);
    const available = workspaceElement?.clientWidth;
    const responsiveMax = available ? available - otherWidth - 336 : ownLimits.max;
    const effectiveMax = Math.max(ownLimits.min, Math.min(ownLimits.max, responsiveMax));
    const next = Math.min(effectiveMax, Math.max(ownLimits.min, requested));
    if (side === 'left') leftWidth = next;
    else rightWidth = next;
    persistLayout();
  }

  function resizeTimeNavigator(requested: number) {
    const available = runShellElement?.clientHeight;
    const responsiveMax = available && available > 400 ? available - 48 - 180 : timeNavigatorLimits.max;
    const effectiveMax = Math.max(timeNavigatorLimits.min, Math.min(timeNavigatorLimits.max, responsiveMax));
    timeNavigatorHeight = Math.min(effectiveMax, Math.max(timeNavigatorLimits.min, requested));
    persistLayout();
  }

  function togglePane(side: 'left' | 'right') {
    if (side === 'left') leftCollapsed = !leftCollapsed;
    else rightCollapsed = !rightCollapsed;
    persistLayout();
  }

  function restoreRightPane() {
    if (rightCollapsed) togglePane('right');
  }

  function issueEvent(items = windowedVisibleEvents): TraceEvent | null {
    return items.find(isIssue) ?? null;
  }

  function showFeedback(message: string) {
    actionFeedback = message;
    window.setTimeout(() => { if (actionFeedback === message) actionFeedback = ''; }, 2200);
  }

  function persistSessionSoon() {
    if (!selectedTrace) return;
    if (sessionWriteTimer !== null) window.clearTimeout(sessionWriteTimer);
    sessionWriteTimer = window.setTimeout(() => {
      sessionWriteTimer = null;
      if (!selectedTrace) return;
      writeViewSession({
        traces,
        selectedTrace,
        events,
        selectedSequence: selectedEvent?.sequence ?? null
      });
    }, 120);
  }

  function sameEventIds(before: TraceEvent[], after: TraceEvent[]): boolean {
    if (before.length !== after.length) return false;
    for (let index = 0; index < before.length; index += 1) {
      if (before[index]?.event_id !== after[index]?.event_id) return false;
    }
    return true;
  }

  function describeEventRequest(request: EventRequest): string {
    return request.eventId ? `Event ${request.eventId}` : `Event sequence ${request.eventSequence}`;
  }

  function writeUrl(traceId = selectedTrace?.trace_id, event = selectedEvent, mode: 'push' | 'replace' = 'replace') {
    const href = serializeInvestigationUrl(window.location.href, {
      traceId,
      eventId: event?.event_id ?? null,
      eventSequence: null,
      filters,
      viewMode,
      windowStart: architectureWindowStart,
      windowEnd: architectureWindowEnd
    });
    window.history[mode === 'push' ? 'pushState' : 'replaceState']({}, '', href);
  }

  function clearScope() {
    filters = emptyFilters();
    architectureWindowStart = null;
    architectureWindowEnd = null;
    const scoped = filterEvents(events, filters);
    if (!selectedEvent || !scoped.some((event) => event.event_id === selectedEvent?.event_id)) {
      selectedEvent = materialEvent(scoped);
    }
    writeUrl();
  }

  async function refreshTraces() {
    try {
      const next = await api.traces();
      traces = next;
      if (!selectedTrace && next.length) await applyLocationState();
      showFeedback(next.length ? `Loaded ${next.length} run${next.length === 1 ? '' : 's'}` : 'No traces yet');
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Unable to refresh traces.';
    }
  }

  function setViewMode(next: ViewMode) {
    viewMode = next;
    writeUrl(selectedTrace?.trace_id, selectedEvent, 'push');
  }

  function setArchitectureWindow(startMs: number | null, endMs: number | null) {
    if (startMs !== null && endMs !== null) {
      [architectureWindowStart, architectureWindowEnd] = normalizedWindow(events, startMs, endMs);
    } else {
      architectureWindowStart = null;
      architectureWindowEnd = null;
    }
    const inRange = filterEvents(timeScopedEvents(events), filters);
    if (!selectedEvent || !inRange.some((event) => event.event_id === selectedEvent?.event_id)) selectedEvent = materialEvent(inRange);
    writeUrl();
  }

  function clearLiveBatch() {
    if (liveFlushTimer !== null) {
      window.clearTimeout(liveFlushTimer);
      liveFlushTimer = null;
    }
    pendingLiveEvents = [];
  }

  function flushLiveBatch(epoch: number) {
    if (liveFlushTimer !== null) {
      window.clearTimeout(liveFlushTimer);
      liveFlushTimer = null;
    }
    if (!shouldCommitLoad(epoch, loadEpoch) || !pendingLiveEvents.length) {
      pendingLiveEvents = [];
      return;
    }
    const batch = pendingLiveEvents;
    pendingLiveEvents = [];
    const hadSelection = Boolean(selectedEvent);
    events = mergeLiveEvents(events, batch);
    if (!hadSelection) selectedEvent = batch[0] ?? null;
    persistSessionSoon();
  }

  function enqueueLiveEvent(epoch: number, event: TraceEvent) {
    if (!shouldCommitLoad(epoch, loadEpoch)) return;
    pendingLiveEvents.push(event);
    if (liveFlushTimer !== null) return;
    // Coalesce stream bursts (~12fps) so the ruler/timeline don't thrash mid-frame.
    liveFlushTimer = window.setTimeout(() => flushLiveBatch(epoch), 80);
  }

  async function selectTrace(trace: TraceManifest, eventRequest?: EventRequest, pushHistory = false) {
    stopReplay();
    const switching = Boolean(selectedTrace && selectedTrace.trace_id !== trace.trace_id);
    const warmPaint = !switching && selectedTrace?.trace_id === trace.trace_id && events.length > 0;
    if (switching) {
      architectureWindowStart = null;
      architectureWindowEnd = null;
      filters = emptyFilters();
    }
    closeStream?.();
    closeStream = null;
    clearLiveBatch();
    const epoch = ++loadEpoch;
    // Stale-while-revalidate: keep previous evidence painted until the new payload
    // commits atomically. Only dim when the paint is not already this run.
    pendingTraceId = trace.trace_id;
    traceLoading = true;
    contentStale = !warmPaint;
    live = false;
    streamState = trace.ended_at ? 'recorded' : 'connecting';
    error = null;
    fatalError = null;
    missingEventReference = null;
    try {
      const [detail, nextEvents] = await Promise.all([
        api.trace(trace.trace_id).catch(() => trace),
        api.events(trace.trace_id)
      ]);
      if (!shouldCommitLoad(epoch, loadEpoch)) return;
      const committed: TraceManifest = { ...trace, ...detail };
      let nextWindowStart = architectureWindowStart;
      let nextWindowEnd = architectureWindowEnd;
      if (nextWindowStart !== null && nextWindowEnd !== null) {
        [nextWindowStart, nextWindowEnd] = normalizedWindow(nextEvents, nextWindowStart, nextWindowEnd);
      }
      architectureWindowStart = nextWindowStart;
      architectureWindowEnd = nextWindowEnd;
      const scopedEvents = filterEvents(
        nextWindowStart !== null && nextWindowEnd !== null
          ? nextEvents.filter((event) => {
              const bounds = traceTimeBounds(nextEvents);
              if (!bounds) return true;
              const timestamp = Date.parse(event.timestamp);
              const offset = timestamp - bounds.start;
              const endOffset = offset + Math.max(0, event.duration_ms || 0);
              return Number.isFinite(offset) && offset <= nextWindowEnd! && endOffset >= nextWindowStart!;
            })
          : nextEvents,
        filters
      );
      const nextSelected = resolveSelectedEvent(nextEvents, scopedEvents, eventRequest, materialEvent);
      missingEventReference = eventRequest && !nextSelected ? describeEventRequest(eventRequest) : null;
      // Atomic commit of identity + evidence. Skip event array churn when ids match.
      selectedTrace = committed;
      if (!sameEventIds(events, nextEvents)) events = nextEvents;
      if (selectedEvent?.event_id !== nextSelected?.event_id) selectedEvent = nextSelected;
      pendingTraceId = null;
      if (!missingEventReference) writeUrl(committed.trace_id, selectedEvent, pushHistory ? 'push' : 'replace');
      persistSessionSoon();
      if (!committed.ended_at) {
        closeStream = api.stream(
          committed.trace_id,
          (event) => enqueueLiveEvent(epoch, event),
          (state) => {
            if (!shouldCommitLoad(epoch, loadEpoch)) return;
            live = state === 'live';
            streamState = state;
          },
          (complete) => {
            if (!shouldCommitLoad(epoch, loadEpoch)) return;
            flushLiveBatch(epoch);
            selectedTrace = applyTraceComplete(selectedTrace, complete);
            live = false;
            streamState = 'recorded';
            traces = traces.map((item) =>
              item.trace_id === complete.trace_id ? { ...item, ...complete } : item
            );
            persistSessionSoon();
          }
        );
      } else {
        live = false;
        streamState = 'recorded';
      }
    } catch (cause) {
      if (!shouldCommitLoad(epoch, loadEpoch)) return;
      pendingTraceId = null;
      streamState = 'disconnected';
      error = cause instanceof Error ? cause.message : 'Unable to load trace.';
      if (warmPaint) {
        // Keep the session paint on a failed revalidate so hard refresh stays usable offline.
        selectedTrace = { ...selectedTrace!, ...trace };
      } else {
        selectedTrace = trace;
        events = [];
        selectedEvent = null;
        clearViewSession();
      }
    } finally {
      if (shouldCommitLoad(epoch, loadEpoch)) {
        traceLoading = false;
        contentStale = false;
        if (pendingTraceId === trace.trace_id) pendingTraceId = null;
      }
    }
  }

  function selectEvent(event: TraceEvent) {
    missingEventReference = null;
    selectedEvent = event;
    if (selectedTrace) writeUrl(selectedTrace.trace_id, event);
  }

  function inspectEvent(event: TraceEvent) {
    if (!windowedVisibleEvents.some((candidate) => candidate.event_id === event.event_id)) {
      filters = emptyFilters();
      architectureWindowStart = null;
      architectureWindowEnd = null;
      showFeedback('Scope cleared to reveal the selected evidence');
    }
    selectEvent(event);
  }

  function closeInspector() {
    missingEventReference = null;
    selectedEvent = null;
    if (selectedTrace) writeUrl(selectedTrace.trace_id, null);
  }

  function openRunOverview() {
    missingEventReference = null;
    selectedEvent = null;
    if (selectedTrace) writeUrl(selectedTrace.trace_id, null, 'replace');
  }

  function changeFilters(next: EventFilters) {
    filters = next;
    const nextVisible = filterEvents(timeScopedEvents(events), next);
    if (!selectedEvent || !nextVisible.some((event) => event.event_id === selectedEvent?.event_id)) {
      selectedEvent = materialEvent(nextVisible);
    }
    writeUrl();
  }

  function selectActor(actorId: string | null) {
    changeFilters({ ...filters, actorId });
  }

  function selectRelated(id: string) {
    const related = findEventById(events, id);
    if (related) {
      relatedFeedback = '';
      selectEvent(related);
      return;
    }
    relatedFeedback = `Not in journal: ${id}`;
    showFeedback(relatedFeedback);
  }

  function filterByCorrelation(correlationId: string) {
    filters = { ...filters, correlationId };
    const nextVisible = filterEvents(timeScopedEvents(events), filters);
    if (!selectedEvent || !nextVisible.some((event) => event.event_id === selectedEvent?.event_id)) {
      selectedEvent = materialEvent(nextVisible);
    }
    writeUrl();
    showFeedback(`Scoped to correlation ${correlationId}`);
  }

  async function copyLink() {
    writeUrl();
    await navigator.clipboard.writeText(window.location.href);
    showFeedback('Deep link copied');
  }

  async function shareTrace() {
    if (navigator.share && selectedTrace) {
      await navigator.share({ title: runTitle(selectedTrace), url: window.location.href });
      showFeedback('Local link shared');
    } else {
      await copyLink();
    }
  }

  function redactString(value: string): string {
    return value
      .replace(/(bearer\s+)[a-z0-9._~+/=-]+/gi, '$1[REDACTED]')
      .replace(/((?:api[_-]?key|token|password|secret)\s*[=:]\s*)[^\s,;]+/gi, '$1[REDACTED]');
  }

  function safeExportValue(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(safeExportValue);
    if (typeof value === 'string') {
      try {
        const decoded = JSON.parse(value) as unknown;
        if (decoded && typeof decoded === 'object') return JSON.stringify(safeExportValue(decoded));
      } catch {
        // Plain strings still receive token-pattern masking below.
      }
      return redactString(value);
    }
    if (!value || typeof value !== 'object') return value;
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => {
      const normalized = key.toLowerCase().replace(/[- ]/g, '_');
      const sensitive = /password|secret|token|authorization|cookie|api_key|private_key/.test(normalized);
      return [key, sensitive ? '[REDACTED BY PREMIER]' : safeExportValue(child)];
    }));
  }

  function exportJson() {
    if (!selectedTrace) return;
    const artifact = JSON.stringify(safeExportValue({ manifest: selectedTrace, events }), null, 2);
    const url = URL.createObjectURL(new Blob([artifact], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${runTitle(selectedTrace).replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').toLowerCase()}.redacted.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    showFeedback('Redacted JSON export created');
  }

  function focusIssue() {
    const issues = windowedVisibleEvents.filter(isIssue);
    if (!issues.length) return;
    const current = issues.findIndex((event) => event.event_id === selectedEvent?.event_id);
    selectEvent(issues[(current + 1) % issues.length]);
  }

  function stopReplay() {
    if (replayTimer) window.clearInterval(replayTimer);
    replayTimer = null;
    replaying = false;
  }

  function toggleReplay() {
    if (replaying) return stopReplay();
    if (!windowedVisibleEvents.length) return;
    replaying = true;
    let index = Math.max(0, windowedVisibleEvents.findIndex((event) => event.event_id === selectedEvent?.event_id));
    selectEvent(windowedVisibleEvents[index]);
    replayTimer = window.setInterval(() => {
      index += 1;
      if (index >= windowedVisibleEvents.length) return stopReplay();
      selectEvent(windowedVisibleEvents[index]);
    }, 700);
  }

  async function compareAgainst(traceId: string) {
    baselineId = traceId;
    comparison = null;
    comparisonError = '';
    const baseline = traces.find((trace) => trace.trace_id === traceId);
    if (!baseline) return;
    comparisonLoading = true;
    try {
      const baselineEvents = await api.events(traceId);
      comparison = { baseline, baselineEvents };
    } catch (cause) {
      comparisonError = cause instanceof Error ? cause.message : 'Unable to compare traces.';
    } finally {
      comparisonLoading = false;
    }
  }

  function openCompare() {
    compareOpen = true;
    const initial = traces.find((trace) => trace.trace_id !== selectedTrace?.trace_id && trace.command[0] === selectedTrace?.command[0])
      ?? traces.find((trace) => trace.trace_id !== selectedTrace?.trace_id);
    if (initial) void compareAgainst(initial.trace_id);
  }

  function closeMore(restoreFocus = false) {
    moreOpen = false;
    if (restoreFocus) queueMicrotask(() => moreButton?.focus());
  }

  function toggleMore() {
    moreOpen = !moreOpen;
    if (moreOpen) queueMicrotask(() => moreMenu?.querySelector<HTMLButtonElement>('[role="menuitem"]')?.focus());
  }

  function navigateMore(event: KeyboardEvent) {
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      return closeMore(true);
    }
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const items = [...(moreMenu?.querySelectorAll<HTMLButtonElement>('[role="menuitem"]:not(:disabled)') ?? [])];
    if (!items.length) return;
    const current = Math.max(0, items.indexOf(document.activeElement as HTMLButtonElement));
    const index = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (current + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
    items[index]?.focus();
  }

  function handleDocumentPointerdown(event: PointerEvent) {
    if (moreOpen && !moreMenu?.contains(event.target as Node) && !moreButton?.contains(event.target as Node)) closeMore();
  }

  function handleKeydown(event: KeyboardEvent) {
    const target = event.target as HTMLElement | null;
    if (event.key === 'Escape') {
      if (shortcutsOpen) shortcutsOpen = false;
      else if (runsSheetOpen) runsSheetOpen = false;
      else if (moreOpen) closeMore(true);
      else if (assistantOpen) assistantOpen = false;
      else if (compareOpen) compareOpen = false;
      else closeInspector();
      return;
    }
    if (target?.matches('input, textarea, select, button, [contenteditable="true"]')) return;
    if (event.key === '?' || (event.key === '/' && event.shiftKey)) {
      event.preventDefault();
      shortcutsOpen = !shortcutsOpen;
      return;
    }
    if ((event.key === 'j' || event.key === 'k') && windowedVisibleEvents.length) {
      event.preventDefault();
      const current = Math.max(0, windowedVisibleEvents.findIndex((item) => item.event_id === selectedEvent?.event_id));
      const next = event.key === 'j' ? Math.min(windowedVisibleEvents.length - 1, current + 1) : Math.max(0, current - 1);
      selectEvent(windowedVisibleEvents[next]);
    }
  }

  function parseRequestedState(params: URLSearchParams) {
    const state = parseInvestigationParams(params);
    viewMode = state.viewMode;
    architectureWindowStart = state.windowStart;
    architectureWindowEnd = state.windowEnd;
    filters = state.filters;
  }

  async function applyLocationState() {
    const params = new URLSearchParams(window.location.search);
    parseRequestedState(params);
    const requestedId = params.get('trace');
    const requested = requestedId ? traces.find((trace) => trace.trace_id === requestedId) : traces[0];
    if (!requested) {
      selectedTrace = null;
      selectedEvent = null;
      events = [];
      fatalError = requestedId ? `Trace ${requestedId} was not found. Choose an available run or check the shared link.` : null;
      clearViewSession();
      return;
    }
    const state = parseInvestigationParams(params);
    const eventRequest: EventRequest | undefined = state.eventId || state.eventSequence !== null
      ? { eventId: state.eventId, eventSequence: state.eventSequence }
      : undefined;
    await selectTrace(requested, eventRequest);
  }

  function handlePopState() {
    void applyLocationState();
  }

  function handleResize() {
    if (!workspaceElement || workspaceElement.clientWidth <= 1180) return;
    resizePane('left', leftWidth);
    if (!rightCompact) resizePane('right', rightWidth);
    resizeTimeNavigator(timeNavigatorHeight);
  }

  onMount(async () => {
    restoreLayout();
    window.addEventListener('popstate', handlePopState);
    window.addEventListener('resize', handleResize);
    document.addEventListener('pointerdown', handleDocumentPointerdown, true);
    try {
      traces = await api.traces();
      await applyLocationState();
    } catch (cause) {
      error = cause instanceof Error ? cause.message : 'Unable to connect to Premier.';
    } finally {
      loading = false;
    }
    pollTimer = window.setInterval(() => {
      void api.traces().then((next) => {
        if (next.length !== traces.length || next.some((item, index) => item.trace_id !== traces[index]?.trace_id || item.ended_at !== traces[index]?.ended_at)) {
          traces = next;
        }
      }).catch(() => undefined);
    }, 4000);
  });
  onDestroy(() => {
    closeStream?.();
    clearLiveBatch();
    stopReplay();
    if (pollTimer) window.clearInterval(pollTimer);
    if (sessionWriteTimer !== null) window.clearTimeout(sessionWriteTimer);
    window.removeEventListener('popstate', handlePopState);
    window.removeEventListener('resize', handleResize);
    document.removeEventListener('pointerdown', handleDocumentPointerdown, true);
  });
</script>

<svelte:window onkeydown={handleKeydown} />

<svelte:head><title>{selectedTrace ? `${runTitle(selectedTrace)} · Premier` : 'Premier Trace Viewer'}</title></svelte:head>

<main>
  <a class="skip-link" href="#main-content">Skip to evidence</a>
  <header class="app-bar" inert={assistantOpen || compareOpen || runsSheetOpen || shortcutsOpen}>
    <div class="brand" aria-label="Premier Trace">
      <span class="brand-mark" aria-hidden="true">
        <svg class="brand-mark-glyph" fill="none" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
          <path
            d="M538 813Q543 820 562.5 814.5Q582 809 602.0 795.5Q622 782 636.0 763.0Q650 744 643 725Q600 672 558.0 611.0Q516 550 477.5 483.5Q439 417 404.5 348.0Q370 279 341 212Q353 210 365.5 209.0Q378 208 392 208Q444 208 502.0 225.0Q560 242 616.5 272.5Q673 303 724.5 346.0Q776 389 815.5 440.0Q855 491 879.5 549.5Q904 608 907 670Q906 698 896.5 732.0Q887 766 860.5 795.0Q834 824 786.0 843.5Q738 863 661 864Q594 860 525.5 823.0Q457 786 393.0 729.0Q329 672 273.0 602.5Q217 533 176.5 464.0Q136 395 113.5 333.5Q91 272 94 232Q95 215 79.0 217.0Q63 219 43.0 233.5Q23 248 6.5 272.5Q-10 297 -10 325Q-10 330 -9.0 337.5Q-8 345 -5 353H-6Q22 454 84.0 550.5Q146 647 233.0 723.5Q320 800 428.5 848.5Q537 897 657 903H656Q677 906 697.0 907.0Q717 908 737 908Q818 908 874.0 887.0Q930 866 965.0 832.5Q1000 799 1015.5 756.0Q1031 713 1031 668Q1031 591 1000.0 523.5Q969 456 918.0 399.5Q867 343 800.5 299.5Q734 256 664.0 226.5Q594 197 524.5 182.5Q455 168 397 170Q360 171 327 179Q291 90 266.5 10.5Q242 -69 234 -131Q234 -121 223.0 -104.5Q212 -88 198.0 -74.0Q184 -60 171.5 -52.0Q159 -44 156 -51Q159 3 178.5 74.0Q198 145 229 225Q175 268 166 327Q167 335 179.0 345.0Q191 355 213 365Q228 309 250 277Q280 350 316.5 424.5Q353 499 391.0 569.0Q429 639 466.5 701.5Q504 764 538 813Z"
            fill="currentColor"
            transform="translate(10.66 10.7) scale(0.041 -0.041) translate(10 -908)"
          />
        </svg>
      </span>
      <span class="brand-wordmark" aria-hidden="true">Premier</span>
      <span class="brand-product" aria-hidden="true">Trace</span>
    </div>
    <div class="trace-context" aria-label="Current run">
      {#if selectedTrace}
        <div class="trace-identity">
          <strong>{runTitle(selectedTrace)}</strong>
          <code aria-label={`Trace ID ${selectedTrace.trace_id}`}>{selectedTrace.trace_id}</code>
        </div>
        <RunOverview trace={selectedTrace} {events} compact={true} />
      {:else}<span>LOCAL WORKSPACE</span>{/if}
    </div>
    <div class="app-actions">
      {#if actionFeedback}<span class="action-feedback" role="status">{actionFeedback}</span>{/if}
      <button class="action-button runs-sheet-trigger" onclick={() => runsSheetOpen = true} title="Browse all runs">Runs</button>
      <button class="action-button assistant-trigger" data-active={assistantOpen} onclick={() => assistantOpen = true}>Ask AI</button>
      {#if issueEvent()}<button class="action-button action-primary" onclick={focusIssue} title="Jump to the next recorded issue">Next issue</button>{/if}
      <div class="action-menu" class:open={moreOpen}>
        <button bind:this={moreButton} class="menu-trigger" aria-label="More" aria-haspopup="menu" aria-expanded={moreOpen} onclick={toggleMore}>More</button>
        {#if moreOpen}<div bind:this={moreMenu} role="menu" tabindex="-1" aria-label="More trace actions" onkeydown={navigateMore}>
          <button role="menuitem" onclick={() => { closeMore(); void copyLink(); }}><span>Copy link</span><small>Deep link with filters and time window</small></button>
          <button role="menuitem" onclick={() => { closeMore(); exportJson(); }}><span>Export safe JSON</span><small>Redacts common secret and credential fields</small></button>
          <button role="menuitem" onclick={() => { closeMore(); void shareTrace(); }}><span>Share local link</span><small>Open the system share sheet</small></button>
          <button role="menuitem" onclick={() => { closeMore(); shortcutsOpen = true; }}><span>Keyboard shortcuts</span><small>Press ? anytime</small></button>
          <hr />
          <button role="menuitem" onclick={() => { closeMore(); openCompare(); }} disabled={traces.length < 2}><span>Compare runs</span><small>Semantic field, latency, token, and cost deltas</small></button>
          <button role="menuitem" onclick={() => { closeMore(); toggleReplay(); }}><span>{replaying ? 'Stop slideshow' : 'Slideshow'}</span><small>700ms step through scoped events</small></button>
          {#if issueEvent()}<button role="menuitem" onclick={() => { closeMore(); focusIssue(); }}><span>Next issue</span><small>Jump to the next scoped issue</small></button>{/if}
          <button role="menuitem" onclick={() => { closeMore(); togglePane('left'); }}><span>{leftCollapsed ? 'Expand' : 'Compact'} runs</span><small>Toggle the run browser rail</small></button>
          <button role="menuitem" onclick={() => { closeMore(); togglePane('right'); }}><span>{rightCollapsed ? 'Expand' : 'Compact'} inspector</span><small>Toggle the evidence rail</small></button>
          <hr />
          <button role="menuitem" onclick={() => { closeMore(); runsSheetOpen = true; }}><span>Browse all runs</span><small>Full list for mobile and tablet</small></button>
          <button role="menuitem" onclick={() => { closeMore(); void refreshTraces(); }}><span>Refresh runs</span><small>Rescan the trace directory</small></button>
        </div>{/if}
      </div>
    </div>
    <div class="connection" class:live class:recorded={streamState === 'recorded'} class:disconnected={streamState === 'reconnecting' || streamState === 'disconnected'} title={streamState === 'reconnecting' ? 'The live stream dropped. The browser is retrying automatically.' : undefined} role="status" aria-live="polite"><span></span>{streamState === 'live' ? 'STREAMING' : streamState === 'recorded' ? 'RECORDED' : streamState === 'reconnecting' ? 'RECONNECTING' : streamState === 'disconnected' ? 'DISCONNECTED' : 'CONNECTING'}</div>
  </header>

  {#if loading}
    <section class="loading-shell" aria-label="Loading trace workspace" aria-busy="true">
      <div class="loading-time">
        <div><span class="skeleton skeleton-time-title"></span><span class="skeleton skeleton-time-actions"></span></div>
        <span class="skeleton skeleton-density"></span>
        <span class="skeleton skeleton-lane"></span><span class="skeleton skeleton-lane"></span><span class="skeleton skeleton-lane"></span>
      </div>
      <div class="loading-overview">
        <div class="loading-metrics"><span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line"></span><span class="skeleton skeleton-line"></span></div>
      </div>
      <div class="loading-filters"><span class="skeleton skeleton-search"></span><span class="skeleton skeleton-tabs"></span><span class="skeleton skeleton-count"></span></div>
      <div class="loading-workspace">
        <div class="loading-runs"><span class="skeleton skeleton-heading"></span>{#each Array(5) as _}<span class="skeleton skeleton-row"></span>{/each}</div>
        <div class="loading-events"><span class="skeleton skeleton-heading"></span>{#each Array(7) as _}<span class="skeleton skeleton-event"></span>{/each}</div>
        <div class="loading-detail"><span class="skeleton skeleton-heading"></span><span class="skeleton skeleton-detail"></span><span class="skeleton skeleton-detail short"></span></div>
      </div>
    </section>
  {:else if fatalError}
    <section class="state-screen error"><span class="state-icon">!</span><strong>Trace not found</strong><span>{fatalError}</span><button onclick={() => { const url = new URL(window.location.href); url.searchParams.delete('trace'); url.searchParams.delete('event'); history.pushState({}, '', url); void applyLocationState(); }}>Open the latest available run</button></section>
  {:else if error && traces.length === 0}
    <section class="state-screen error"><span class="state-icon">!</span><strong>Viewer unavailable</strong><span>{error}</span><button onclick={() => location.reload()}>Try again</button></section>
  {:else if traces.length === 0}
    <section class="state-screen empty-onboarding" id="main-content">
      <span class="state-icon">⌁</span>
      <strong>No traces yet</strong>
      <span>Start with the multi-agent demo for a full investigation surface, or record any command with Premier on PATH.</span>
      <div class="empty-actions">
        <button type="button" onclick={() => void refreshTraces()}>Refresh runs</button>
      </div>
      <div class="empty-commands">
        <code>premier demo</code>
        <code>premier open .premier/traces/multi-agent-demo.atrace</code>
        <code>premier record -- npm test</code>
        <code>premier record -- your-agent run</code>
      </div>
      <p class="empty-note">Process recordings capture stdout/stderr automatically. Under <code>premier record</code>, emit typed agent events with <code>premier emit</code> or the <code>@premierstudio/trace</code> package for the full multi-actor experience.</p>
    </section>
  {:else}
    {#if compareOpen && selectedTrace}
      <div class="compare-overlay" role="presentation" onclick={(event) => { if (event.currentTarget === event.target) compareOpen = false; }}>
        <div class="compare-panel" role="dialog" aria-modal="true" aria-labelledby="compare-title" tabindex="-1" use:focusTrap={{ onEscape: () => compareOpen = false, initialFocus: '.inspector-close' }}>
          <div class="compare-header"><div><span>Regression analysis</span><strong id="compare-title">Compare runs</strong></div><button class="inspector-close" onclick={() => compareOpen = false} aria-label="Close comparison">×</button></div>
          <div class="compare-controls"><label>Baseline<PremierSelect label="Comparison baseline" value={baselineId} options={traces.filter((trace) => trace.trace_id !== selectedTrace?.trace_id).map((trace) => ({ value: trace.trace_id, label: runTitle(trace), description: `${trace.summary?.event_count ?? trace.journal?.event_count ?? 0} recorded events` }))} onchange={(value) => void compareAgainst(value)} /></label><span>Candidate<strong>{runTitle(selectedTrace)}</strong></span></div>
          {#if comparisonLoading}<div class="compare-divergence">Loading baseline evidence…</div>
          {:else if comparisonError}<div class="compare-divergence error">{comparisonError}</div>
          {:else if comparison}
            <div class="compare-content"><TraceComparison baseline={comparison.baseline} current={selectedTrace} baselineEvents={comparison.baselineEvents} currentEvents={events} onselectCurrent={(event) => { compareOpen = false; inspectEvent(event); }} /></div>
          {/if}
        </div>
      </div>
    {/if}
    {#if assistantOpen && selectedTrace}
      <div class="assistant-overlay" role="presentation" onclick={(event) => { if (event.currentTarget === event.target) assistantOpen = false; }}>
        <div class="assistant-drawer" role="dialog" aria-modal="true" aria-label="Ask your local AI" tabindex="-1" use:focusTrap={{ onEscape: () => assistantOpen = false, initialFocus: '.assistant-close' }}>
          <LocalAssistant traceId={selectedTrace.trace_id} {selectedEvent} onclose={() => assistantOpen = false} />
        </div>
      </div>
    {/if}
    {#if runsSheetOpen}
      <div class="runs-sheet-overlay" role="presentation" onclick={(event) => { if (event.currentTarget === event.target) runsSheetOpen = false; }}>
        <div class="runs-sheet" role="dialog" aria-modal="true" aria-label="All runs" tabindex="-1" use:focusTrap={{ onEscape: () => runsSheetOpen = false, initialFocus: '.runs-sheet-close' }}>
          <div class="runs-sheet-header">
            <div><span>Runs</span><strong>{traces.length} available</strong></div>
            <button type="button" class="runs-sheet-close inspector-close" onclick={() => runsSheetOpen = false} aria-label="Close runs">×</button>
          </div>
          <div class="runs-sheet-body">
            <TraceList traces={traces} selectedId={pendingTraceId ?? selectedTrace?.trace_id ?? null} onselect={(trace) => { runsSheetOpen = false; void selectTrace(trace, undefined, true); }} />
          </div>
        </div>
      </div>
    {/if}
    {#if shortcutsOpen}
      <div class="shortcuts-overlay" role="presentation" onclick={(event) => { if (event.currentTarget === event.target) shortcutsOpen = false; }}>
        <div class="shortcuts-panel" role="dialog" aria-modal="true" aria-labelledby="shortcuts-title" tabindex="-1" use:focusTrap={{ onEscape: () => shortcutsOpen = false }}>
          <div class="shortcuts-header"><strong id="shortcuts-title">Keyboard shortcuts</strong><button type="button" class="inspector-close" onclick={() => shortcutsOpen = false} aria-label="Close shortcuts">×</button></div>
          <dl class="shortcuts-list">
            <div><dt>j / k</dt><dd>Next / previous event in scope</dd></div>
            <div><dt>?</dt><dd>Toggle this help</dd></div>
            <div><dt>Esc</dt><dd>Close dialogs and inspector</dd></div>
            <div><dt>Arrow keys</dt><dd>Move within focused lists</dd></div>
          </dl>
        </div>
      </div>
    {/if}
    <div class="run-shell" class:trace-loading={traceLoading} class:content-stale={contentStale} class:shell-enter={!bootSession} id="main-content" inert={assistantOpen || compareOpen || runsSheetOpen || shortcutsOpen} aria-busy={traceLoading} bind:this={runShellElement} style={`--time-navigator:${selectedTrace ? timeNavigatorHeight : 0}px`}>
      {#if traceLoading}
        <div class="trace-load-progress" role="status" aria-live="polite">
          <span class="trace-load-bar" aria-hidden="true"></span>
          <span class="sr-only">Loading run evidence…</span>
        </div>
      {/if}
      {#if selectedTrace}
        <div class="time-navigator" aria-label="Run time navigator">
          <ArchitectureView
            {events}
            focusEvents={windowedVisibleEvents}
            selectedEventId={selectedEvent?.event_id ?? null}
            selectedActor={filters.actorId}
            {live}
            timeOnly={true}
            compact={true}
            showHeader={false}
            showDiagram={false}
            windowStartMs={architectureWindowStart}
            windowEndMs={architectureWindowEnd}
            onwindow={setArchitectureWindow}
            onactor={selectActor}
            onselect={selectEvent}
          />
          <RowResizeHandle label="run activity" value={timeNavigatorHeight} min={timeNavigatorLimits.min} max={timeNavigatorLimits.max} defaultValue={defaultTimeNavigatorHeight} onresize={resizeTimeNavigator} />
          {#if missingEventReference}
            <div class="missing-evidence-banner" role="alert">
              <span class="missing-evidence-icon" aria-hidden="true">!</span>
              <span><strong>Linked event not found</strong><small>{missingEventReference} is not present in this run. The link may reference older or incomplete evidence.</small></span>
              <button type="button" onclick={openRunOverview}>Open run overview</button>
            </div>
          {/if}
        </div>
      {/if}
      {#if relatedFeedback}<div class="relation-banner" role="status">{relatedFeedback}</div>{/if}
      <FilterBar
        {filters}
        counts={categoryCounts}
        visible={windowedVisibleEvents.length}
        total={events.length}
        windowActive={architectureWindowStart !== null}
        onchange={changeFilters}
        onclearScope={clearScope}
      />
      <div
        class="workspace"
        class:left-collapsed={leftCollapsed}
        class:right-collapsed={rightCollapsed}
        class:no-inspector-selection={!selectedEvent}
        style={`--trace-pane: ${leftCollapsed ? leftRailWidth : leftWidth}px; --left-divider: ${leftCollapsed ? 0 : 8}px; --inspector-pane: ${rightCompact ? rightRailWidth : rightWidth}px; --right-divider: ${rightCompact ? 0 : 8}px;`}
        bind:this={workspaceElement}
      >
        <TraceList {traces} selectedId={pendingTraceId ?? selectedTrace?.trace_id ?? null} onselect={(trace) => void selectTrace(trace, undefined, true)} compact={leftCollapsed} onrestore={() => togglePane('left')} />
        <SplitHandle side="left" label="trace list" value={leftWidth} min={leftLimits.min} max={leftLimits.max} collapsed={leftCollapsed} onresize={(value) => resizePane('left', value)} oncollapse={() => togglePane('left')} />
        <section class="evidence-main" aria-label="Trace visualization workspace">
          <div class="evidence-view-toolbar">
            <div class="view-tabs" aria-label="Trace view">
              <button class:active={viewMode === 'timeline'} aria-pressed={viewMode === 'timeline'} onclick={() => setViewMode('timeline')}>Events</button>
              <button class:active={viewMode === 'analytics'} aria-pressed={viewMode === 'analytics'} onclick={() => setViewMode('analytics')}>Analytics</button>
              <button class:active={viewMode === 'map'} aria-pressed={viewMode === 'map'} onclick={() => setViewMode('map')}>System</button>
            </div>
            <span class="view-purpose">
              {viewMode === 'timeline' ? 'Inspect recorded events and their causal handoffs.' : viewMode === 'analytics' ? 'Find activity spikes, issue windows, and latency-heavy operations.' : 'Inspect the evidence-derived agent architecture.'}
            </span>
          </div>
          <div class="evidence-view" class:system-mode={viewMode === 'map'}>
            {#if error}
              <section class="inline-error"><strong>Trace could not be opened</strong><span>{error}</span></section>
            {:else}
              {#if viewMode === 'timeline'}
                <div class="mode-content events-mode">
                  <InvestigationSummary trace={selectedTrace!} {events} onselect={inspectEvent} />
                  <EventTimeline events={windowedVisibleEvents} selectedSequence={selectedEvent?.sequence ?? null} onselect={selectEvent} />
                </div>
              {:else if viewMode === 'analytics'}
                <div class="mode-content analytics-mode"><TraceAnalytics events={windowedVisibleEvents} selectedEventId={selectedEvent?.event_id ?? null} {live} filtered={filtersActive} onreset={clearScope} onselect={selectEvent} /></div>
              {:else}
                <ArchitectureView
                  {events}
                  focusEvents={windowedVisibleEvents}
                  selectedEventId={selectedEvent?.event_id ?? null}
                  selectedActor={filters.actorId}
                  {live}
                  showRuler={false}
                  showDiagram={true}
                  windowStartMs={architectureWindowStart}
                  windowEndMs={architectureWindowEnd}
                  onwindow={setArchitectureWindow}
                  onactor={selectActor}
                  onselect={inspectEvent}
                />
              {/if}
            {/if}
          </div>
        </section>
        <SplitHandle side="right" label="event inspector" value={rightWidth} min={rightLimits.min} max={rightLimits.max} collapsed={rightCompact} onresize={(value) => resizePane('right', value)} oncollapse={() => togglePane('right')} />
        {#if selectedEvent}<button class="inspector-scrim" aria-label="Dismiss event inspector backdrop" onclick={closeInspector}></button>{/if}
        <Inspector event={selectedEvent} events={events} onclose={closeInspector} onnavigate={selectRelated} oncorrelation={filterByCorrelation} compact={rightCompact} onrestore={restoreRightPane} />
      </div>
    </div>
  {/if}
</main>
