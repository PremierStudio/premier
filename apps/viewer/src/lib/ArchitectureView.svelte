<script lang="ts">
  import AgentTopology from './AgentTopology.svelte';
  import { actorId, eventSummary, isIssue } from './analysis';
  import { inferArchitecture } from './architectureInference';
  import type { TraceEvent } from './types';

  let {
    events,
    selectedEventId = null,
    selectedActor = null,
    live = false,
    compact = false,
    timeOnly = false,
    showHeader = true,
    showRuler = true,
    showDiagram = true,
    focusEvents = null,
    windowStartMs = null,
    windowEndMs = null,
    onwindow,
    onactor,
    onselect
  }: {
    events: TraceEvent[];
    selectedEventId?: string | null;
    selectedActor?: string | null;
    live?: boolean;
    compact?: boolean;
    timeOnly?: boolean;
    showHeader?: boolean;
    showRuler?: boolean;
    showDiagram?: boolean;
    focusEvents?: TraceEvent[] | null;
    windowStartMs?: number | null;
    windowEndMs?: number | null;
    onwindow: (startMs: number | null, endMs: number | null) => void;
    onactor: (actorId: string | null) => void;
    onselect: (event: TraceEvent) => void;
  } = $props();

  type Bin = { startMs: number; endMs: number; count: number; issues: number; event: TraceEvent | null };
  type DragMode = 'new' | 'start' | 'end' | null;

  let densityElement = $state<HTMLDivElement>();
  let dragMode = $state<DragMode>(null);
  let dragAnchor = $state<number | null>(null);
  let draftStart = $state<number | null>(null);
  let draftEnd = $state<number | null>(null);
  /** Keep the global run clock compact; actor lanes are an intentional drill-down. */
  let detailsExpanded = $state(false);

  let keyboardBin = $state(0);
  let dragOriginX = 0;
  let suppressBinClick = false;

  function timeOf(event: TraceEvent): number {
    const parsed = Date.parse(event.timestamp);
    return Number.isFinite(parsed) ? parsed : event.sequence;
  }

  function issue(event: TraceEvent): boolean {
    return isIssue(event);
  }

  function formatDuration(ms: number): string {
    if (ms < 1) return '<1 ms';
    if (ms < 1_000) return `${Math.round(ms)} ms`;
    if (ms < 60_000) return `${(ms / 1_000).toFixed(ms < 10_000 ? 1 : 0)} s`;
    return `${(ms / 60_000).toFixed(1)} min`;
  }

  function percent(value: number, span: number): number {
    return Math.max(0, Math.min(100, value / Math.max(1, span) * 100));
  }

  function activateEvent(keyEvent: KeyboardEvent, event: TraceEvent): void {
    if (keyEvent.key !== 'Enter' && keyEvent.key !== ' ') return;
    keyEvent.preventDefault();
    onselect(event);
  }

  const architectureModel = $derived.by(() => inferArchitecture(events));
  const view = $derived.by(() => {
    const ordered = [...events].sort((a, b) => timeOf(a) - timeOf(b) || a.sequence - b.sequence);
    const model = architectureModel;
    if (!ordered.length) return { ordered, model, start: 0, end: 0, span: 1, bins: [] as Bin[], windowEvents: [] as TraceEvent[], selected: null as TraceEvent | null, hottest: null as Bin | null, firstIssue: null as TraceEvent | null, maxBin: 1 };
    const start = timeOf(ordered[0]);
    const end = Math.max(start, ...ordered.map((event) => timeOf(event) + Math.max(0, event.duration_ms || 0)));
    const span = Math.max(1, end - start);
    const binCount = Math.min(24, Math.max(10, Math.ceil(Math.sqrt(ordered.length) * 2.4)));
    const bins: Bin[] = Array.from({ length: binCount }, (_, index) => ({
      startMs: index / binCount * span,
      endMs: (index + 1) / binCount * span,
      count: 0,
      issues: 0,
      event: null
    }));
    for (const event of ordered) {
      const offset = timeOf(event) - start;
      const index = Math.min(binCount - 1, Math.floor(offset / span * binCount));
      bins[index].count += 1;
      bins[index].issues += issue(event) ? 1 : 0;
      if (!bins[index].event || issue(event) || event.duration_ms > (bins[index].event?.duration_ms ?? 0)) bins[index].event = event;
    }
    const maxBin = Math.max(1, ...bins.map((bin) => bin.count));
    const hottest = [...bins].sort((a, b) => b.count - a.count || b.issues - a.issues)[0] ?? null;
    const firstIssue = [...ordered].reverse().find(issue) ?? null;
    const hasWindow = windowStartMs !== null && windowEndMs !== null;
    const windowEvents = hasWindow
      ? ordered.filter((event) => {
          const offset = timeOf(event) - start;
          const eventEnd = offset + Math.max(0, event.duration_ms || 0);
          return offset <= windowEndMs! && eventEnd >= windowStartMs!;
        })
      : ordered;
    const selected = ordered.find((event) => event.event_id === selectedEventId) ?? null;
    return { ordered, model, start, end, span, bins, maxBin, hottest, firstIssue, windowEvents, selected };
  });

  const activeWindowLabel = $derived(windowStartMs !== null && windowEndMs !== null
    ? `${formatDuration(windowStartMs)}–${formatDuration(windowEndMs)}`
    : 'Entire run');
  const focusIds = $derived(new Set((focusEvents ?? events).map((event) => event.event_id)));
  const focusActive = $derived(focusEvents !== null && focusEvents.length !== events.length);
  const displayedStart = $derived(dragMode ? draftStart : windowStartMs);
  const displayedEnd = $derived(dragMode ? draftEnd : windowEndMs);
  const rulerActors = $derived.by(() => {
    if (!timeOnly || view.model.actors.length <= 4) return view.model.actors;
    return [...view.model.actors]
      .sort((a, b) => Number(b.id === selectedActor) - Number(a.id === selectedActor)
        || view.ordered.filter((event) => actorId(event) === b.id).length - view.ordered.filter((event) => actorId(event) === a.id).length)
      .slice(0, 4);
  });

  function focusedInBin(bin: Bin): number {
    return (focusEvents ?? events).filter((event) => {
      const offset = timeOf(event) - view.start;
      return offset >= bin.startMs && offset <= bin.endMs;
    }).length;
  }

  function chooseBin(bin: Bin): void {
    if (suppressBinClick) return;
    onwindow(bin.startMs, bin.endMs);
    if (bin.event) onselect(bin.event);
  }

  function navigateDensity(event: KeyboardEvent): void {
    if (!view.bins.length || !['ArrowLeft', 'ArrowRight', 'Home', 'End', 'Enter', ' '].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'Home') keyboardBin = 0;
    else if (event.key === 'End') keyboardBin = view.bins.length - 1;
    else if (event.key === 'ArrowLeft') keyboardBin = Math.max(0, keyboardBin - 1);
    else if (event.key === 'ArrowRight') keyboardBin = Math.min(view.bins.length - 1, keyboardBin + 1);
    else chooseBin(view.bins[keyboardBin]);
  }

  function focusHotWindow(): void {
    if (view.hottest) chooseBin(view.hottest);
  }

  function focusIssueWindow(): void {
    if (!view.firstIssue) return;
    const offset = timeOf(view.firstIssue) - view.start;
    const bin = view.bins.find((candidate, index) => offset >= candidate.startMs && (offset < candidate.endMs || index === view.bins.length - 1));
    if (bin) onwindow(bin.startMs, bin.endMs);
    onselect(view.firstIssue);
  }

  function pointerOffset(clientX: number): number {
    if (!densityElement) return 0;
    const rect = densityElement.getBoundingClientRect();
    return Math.max(0, Math.min(view.span, (clientX - rect.left) / Math.max(1, rect.width) * view.span));
  }

  function beginBrush(event: PointerEvent, mode: DragMode = 'new'): void {
    if (event.button !== 0 || !densityElement) return;
    if (mode !== 'new') event.stopPropagation();
    const offset = pointerOffset(event.clientX);
    dragMode = mode;
    dragOriginX = event.clientX;
    dragAnchor = offset;
    if (mode === 'new') draftStart = draftEnd = offset;
    else {
      draftStart = windowStartMs ?? 0;
      draftEnd = windowEndMs ?? view.span;
    }
    densityElement.setPointerCapture(event.pointerId);
  }

  function moveBrush(event: PointerEvent): void {
    if (!dragMode || dragAnchor === null) return;
    const offset = pointerOffset(event.clientX);
    if (dragMode === 'new') {
      draftStart = Math.min(dragAnchor, offset);
      draftEnd = Math.max(dragAnchor, offset);
    } else if (dragMode === 'start') draftStart = Math.min(offset, (draftEnd ?? view.span) - Math.max(1, view.span / 500));
    else draftEnd = Math.max(offset, (draftStart ?? 0) + Math.max(1, view.span / 500));
  }

  function endBrush(event: PointerEvent): void {
    if (!dragMode) return;
    moveBrush(event);
    const moved = Math.abs(event.clientX - dragOriginX);
    if ((dragMode !== 'new' || moved >= 5) && draftStart !== null && draftEnd !== null) {
      suppressBinClick = true;
      onwindow(Math.max(0, draftStart), Math.min(view.span, draftEnd));
      window.setTimeout(() => { suppressBinClick = false; }, 100);
    }
    dragMode = null;
    dragAnchor = null;
    if (densityElement?.hasPointerCapture(event.pointerId)) densityElement.releasePointerCapture(event.pointerId);
  }

  function cancelBrush(event: PointerEvent): void {
    dragMode = null;
    dragAnchor = null;
    draftStart = windowStartMs;
    draftEnd = windowEndMs;
    if (densityElement?.hasPointerCapture(event.pointerId)) densityElement.releasePointerCapture(event.pointerId);
  }

  function adjustHandle(edge: 'start' | 'end', event: KeyboardEvent): void {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const step = view.span / (event.shiftKey ? 10 : 100);
    const start = windowStartMs ?? 0;
    const end = windowEndMs ?? view.span;
    if (edge === 'start') {
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? Math.max(0, end - step) : Math.max(0, Math.min(end - step, start + (event.key === 'ArrowLeft' ? -step : step)));
      onwindow(next, end);
    } else {
      const next = event.key === 'End' ? view.span : event.key === 'Home' ? Math.min(view.span, start + step) : Math.min(view.span, Math.max(start + step, end + (event.key === 'ArrowLeft' ? -step : step)));
      onwindow(start, next);
    }
  }
</script>

<section class="architecture-view" class:compact class:time-only={timeOnly} aria-labelledby={showHeader ? 'architecture-title' : 'ruler-title'}>
  {#if showHeader}<header class="architecture-header">
    <div>
      <span class="eyebrow">Evidence-derived system</span>
      <h2 id="architecture-title">{showRuler ? 'Architecture + time' : 'Agent architecture'}</h2>
    </div>
    <div class="detection-summary" aria-label="Architecture detection summary">
      <span>{view.model.actors.length} actor{view.model.actors.length === 1 ? '' : 's'}</span>
      <span>{view.model.connections.filter((connection) => connection.confidence === 'recorded').length} recorded link{view.model.connections.filter((connection) => connection.confidence === 'recorded').length === 1 ? '' : 's'}</span>
      <span>{view.model.connections.filter((connection) => connection.confidence === 'high').length} derived link{view.model.connections.filter((connection) => connection.confidence === 'high').length === 1 ? '' : 's'}</span>
      {#if live}<strong><i></i>Live</strong>{/if}
    </div>
  </header>{/if}

  {#if !view.ordered.length}
    <div class="empty" role="status">
      <strong>No architecture evidence yet</strong>
      <span>Record actor IDs plus delegation, spawn, or parent links to reconstruct the system.</span>
    </div>
  {:else}
    {#if showRuler}<section class="orchestration-ruler" aria-labelledby="ruler-title">
      <div class="ruler-heading">
        <div><span>{timeOnly ? 'Run activity' : 'Orchestration ruler'}</span><strong id="ruler-title">Observed activity over {formatDuration(view.span)}{focusActive ? ` · ${focusEvents?.length ?? 0} of ${events.length} events in focus` : ''}</strong><small>Drag across the chart to crop · drag handles to refine</small></div>
        <div class="ruler-actions">
          <button class:active={windowStartMs === null} onclick={() => onwindow(null, null)}>{windowStartMs === null ? 'Entire run' : 'Reset range'}</button>
          <button onclick={focusHotWindow}>Hot window</button>
          <button onclick={focusIssueWindow} disabled={!view.firstIssue}>Failure window</button>
          <button onclick={() => view.bins[keyboardBin] && chooseBin(view.bins[keyboardBin])} onkeydown={navigateDensity} aria-label={`Step through time windows. Bin ${keyboardBin + 1} of ${view.bins.length}. Use Left and Right arrows, then Enter to focus.`}>Step range</button>
          {#if timeOnly}<button class:active={detailsExpanded} aria-pressed={detailsExpanded} onclick={() => detailsExpanded = !detailsExpanded}>{detailsExpanded ? 'Hide actors' : 'Actors'}</button>{/if}
        </div>
      </div>

      <div class="density" class:brushing={dragMode !== null} bind:this={densityElement} role="group" aria-label="Event density time series. Drag to select a range, or use Step range for keyboard control." onpointerdown={beginBrush} onpointermove={moveBrush} onpointerup={endBrush} onpointercancel={cancelBrush}>
        <div class="density-grid" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
        <div class="density-bars" style={`grid-template-columns:repeat(${view.bins.length},minmax(0,1fr))`}>
          {#each view.bins as bin, index (`bin-${index}`)}
            <button
              class:selected={windowStartMs === bin.startMs && windowEndMs === bin.endMs}
              class:issue={bin.issues > 0}
              class:filtered-out={focusActive && focusedInBin(bin) === 0}
              tabindex="-1"
              style={`--height:${Math.max(4, bin.count / view.maxBin * 100)}%`}
              aria-label={`${bin.count} event${bin.count === 1 ? '' : 's'}${bin.issues ? `, ${bin.issues} issue${bin.issues === 1 ? '' : 's'}` : ''}, ${formatDuration(bin.startMs)} to ${formatDuration(bin.endMs)}. Focus this window`}
              onclick={() => chooseBin(bin)}
            ><span></span></button>
          {/each}
        </div>
        {#if displayedStart !== null && displayedEnd !== null}
          <div class="range-wash" style={`--left:${percent(displayedStart, view.span)}%;--width:${percent(displayedEnd - displayedStart, view.span)}%`} aria-hidden="true"><span>{formatDuration(displayedStart)}–{formatDuration(displayedEnd)}</span></div>
          <button class="range-handle start" role="slider" aria-orientation="horizontal" aria-valuemin={0} aria-valuemax={displayedEnd} aria-valuenow={displayedStart} aria-valuetext={formatDuration(displayedStart)} style={`--left:${percent(displayedStart, view.span)}%`} aria-label="Range start" onpointerdown={(event) => beginBrush(event, 'start')} onkeydown={(event) => adjustHandle('start', event)}></button>
          <button class="range-handle end" role="slider" aria-orientation="horizontal" aria-valuemin={displayedStart} aria-valuemax={view.span} aria-valuenow={displayedEnd} aria-valuetext={formatDuration(displayedEnd)} style={`--left:${percent(displayedEnd, view.span)}%`} aria-label="Range end" onpointerdown={(event) => beginBrush(event, 'end')} onkeydown={(event) => adjustHandle('end', event)}></button>
        {/if}
        {#if view.selected}
          <div class="playhead" style={`--left:${percent(timeOf(view.selected) - view.start, view.span)}%`} aria-hidden="true"><span></span></div>
        {/if}
      </div>

      <div class="axis" aria-hidden="true"><span>Start</span><span>+{formatDuration(view.span / 2)}</span><span>+{formatDuration(view.span)}</span></div>
      <div class="sr-only" aria-live="polite">{activeWindowLabel}. {view.windowEvents.length} events in the selected range.</div>

      {#if !timeOnly || detailsExpanded}<div class="actor-ribbons" aria-label="Actor activity ribbons">
        {#each rulerActors as actor (actor.id)}
          <div class="actor-ribbon" class:selected={selectedActor === actor.id} class:filtered-out={focusActive && !view.ordered.some((event) => actorId(event) === actor.id && focusIds.has(event.event_id))}>
            <button class="actor-label" onclick={() => onactor(selectedActor === actor.id ? null : actor.id)} aria-label={`${selectedActor === actor.id ? 'Clear focus on' : 'Focus'} ${actor.id}, ${actor.role}`}>
              <strong>{actor.id}</strong><span>{actor.role}</span>
            </button>
            <div class="ribbon-track">
              {#each (actor.segments?.length ? actor.segments : actor.window ? [actor.window] : []) as segment, segmentIndex (`${actor.id}-seg-${segmentIndex}-${segment.startMs}`)}
                <span
                  class="lifecycle"
                  style={`--left:${percent(segment.startMs - view.start, view.span)}%;--width:${Math.max(.6, percent(Math.max(segment.durationMs, view.span * 0.004), view.span))}%`}
                  title={`${actor.id} active ${formatDuration(segment.startMs - view.start)}–${formatDuration(segment.endMs - view.start)} (${formatDuration(segment.durationMs)})`}
                ></span>
              {/each}
              {#each view.ordered.filter((event) => actorId(event) === actor.id) as event (event.event_id)}
                <button
                  class="event-tick"
                  class:issue={issue(event)}
                  class:selected={event.event_id === selectedEventId}
                  class:filtered-out={focusActive && !focusIds.has(event.event_id)}
                  tabindex="-1"
                  style={`--left:${percent(timeOf(event) - view.start, view.span)}%`}
                  aria-label={`${actor.id}, ${event.kind}, sequence ${event.sequence}, ${formatDuration(timeOf(event) - view.start)}. ${eventSummary(event)}`}
                  onclick={() => onselect(event)}
                  onkeydown={(keyEvent) => activateEvent(keyEvent, event)}
                ><span></span></button>
              {/each}
              {#if view.selected}<i class="lane-playhead" style={`--left:${percent(timeOf(view.selected) - view.start, view.span)}%`} aria-hidden="true"></i>{/if}
            </div>
          </div>
        {/each}
        {#if rulerActors.length < view.model.actors.length}<div class="actor-overflow"><span>+{view.model.actors.length - rulerActors.length} quieter actor{view.model.actors.length - rulerActors.length === 1 ? '' : 's'} summarized</span><strong>Open System for the complete architecture</strong></div>{/if}
      </div>{/if}

      <div class="ruler-footer">
        <div class="ruler-legend" aria-label="Time ruler legend">
          <span><i class="legend-event"></i>Collector receipt event</span>
          <span><i class="legend-life"></i>Observed activity segments (not assumed continuous)</span>
          <span><i class="legend-issue"></i>Issue</span>
          <span><i class="legend-range"></i>Selected range</span>
        </div>
        <strong>{activeWindowLabel} · {view.windowEvents.length} event{view.windowEvents.length === 1 ? '' : 's'}</strong>
      </div>
    </section>{/if}

    {#if showDiagram}
      <div class="architecture-scope">
        <div><span>Diagram scope</span><strong>{activeWindowLabel}</strong><small>{windowStartMs === null ? 'All recorded evidence' : 'Only actors and links observed in this window'}</small></div>
        {#if focusActive}<div class="focus-truth"><span>Active focus</span><strong>{focusEvents?.length ?? 0} of {events.length} events highlighted</strong><small>Filters dim evidence; they do not rewrite the topology</small></div>{/if}
        <div><span>Timing truth</span><strong>Collector receipt time</strong><small>Actor bands are derived—not execution latency</small></div>
        {#if view.model.unresolvedParents.length}<div class="warning"><span>Coverage</span><strong>{view.model.unresolvedParents.length} unresolved parent{view.model.unresolvedParents.length === 1 ? '' : 's'}</strong><small>No relationship was invented</small></div>{/if}
      </div>

      {#if view.windowEvents.length}
        <AgentTopology events={view.windowEvents} focusEvents={focusEvents === null ? null : view.windowEvents.filter((event) => focusIds.has(event.event_id))} {selectedActor} {onactor} {onselect} />
      {:else}
        <div class="window-empty" role="status"><strong>No evidence in this range</strong><button onclick={() => onwindow(null, null)}>Clear range</button></div>
      {/if}
    {/if}
  {/if}
</section>

<style>
  .architecture-view { min-width: 0; min-height: 100%; container-type: inline-size; color: var(--text, #f5f7fa); background: #050505; }
  .architecture-view.time-only { height:100%;min-height:0; }
  .architecture-header { min-height: 58px; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 11px 16px; border: 1px solid rgba(255,255,255,.075); border-bottom: 0; border-radius: 12px 12px 0 0; background: linear-gradient(90deg, rgba(111,123,247,.1), rgba(15,19,27,.94) 42%, rgba(8,10,14,.98)); }
  .eyebrow { display: block; color: #9eaaff; font-size: 9px; font-weight: 800; letter-spacing: .13em; text-transform: uppercase; }
  h2 { margin: 2px 0 0; font: 720 17px/1.2 'IBM Plex Sans Variable', sans-serif; letter-spacing: -.015em; }
  .detection-summary { display: flex; min-width: 0; align-items: center; flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
  .detection-summary span, .detection-summary strong { padding: 4px 7px; border: 1px solid rgba(255,255,255,.08); border-radius: 999px; color: #8796aa; background: rgba(255,255,255,.025); font-size: 9px; font-weight: 700; }
  .detection-summary strong { display: inline-flex; align-items: center; gap: 5px; color: #8de3bc; }
  .detection-summary strong i { width: 5px; height: 5px; border-radius: 50%; background: #63dca5; box-shadow: 0 0 9px rgba(99,220,165,.5); }
  .empty, .window-empty { display: grid; min-height: 260px; place-content: center; justify-items: center; gap: 8px; padding: 30px; border: 1px solid rgba(255,255,255,.075); color: #7f8da1; text-align: center; }
  .empty strong, .window-empty strong { color: #dfe6f0; font-size: 14px; }
  .empty span { max-width: 420px; font-size: 11px; line-height: 1.5; }
  .orchestration-ruler { position: relative; min-width: 0; border: 1px solid rgba(255,255,255,.075); background: linear-gradient(180deg, rgba(15,20,29,.98), rgba(7,9,13,.99)); box-shadow: 0 18px 45px rgba(0,0,0,.24); }
  .architecture-view.time-only .orchestration-ruler { height:100%;min-height:0;display:flex;flex-direction:column;overflow:hidden; }
  .architecture-view.time-only .density { min-height:54px;flex:1 1 68px; }
  .architecture-view.time-only .actor-ribbons { min-height:0;flex:0 1 auto;overflow:auto; }
  .ruler-heading { min-height: 48px; display: flex; align-items: center; justify-content: space-between; gap: 14px; padding: 8px 12px; border-bottom: 1px solid rgba(255,255,255,.06); }
  .ruler-heading > div:first-child span, .architecture-scope span { display: block; color: #74849a; font-size: 8px; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
  .ruler-heading > div:first-child strong { display: block; margin-top: 3px; color: #dfe5ee; font-size: 11px; }
  .ruler-heading > div:first-child small { display: block; margin-top: 2px; color: #66758a; font-size: 8px; line-height: 1.25; }
  .ruler-actions { display: flex; align-items: center; gap: 5px; }
  .ruler-actions button, .window-empty button { min-height: 28px; padding: 0 8px; border: 1px solid #303c50; border-radius: 5px; color: #9eabbc; background: #111722; font-size: 9px; font-weight: 700; cursor: pointer; }
  .ruler-actions button:hover, .ruler-actions button.active, .window-empty button:hover { border-color: #5a78c7; color: white; background: rgba(111,123,247,.15); }
  .ruler-actions button:disabled { opacity: .4; cursor: not-allowed; }
  .density { position: relative; height: 68px; margin: 8px 12px 0; overflow: hidden; border: 1px solid rgba(255,255,255,.055); border-radius: 6px; background: rgba(2,4,7,.64); cursor: crosshair; touch-action: none; user-select: none; }
  .density.brushing { border-color: rgba(126,163,255,.55); box-shadow: 0 0 0 3px rgba(111,123,247,.1); }
  .density-grid { position: absolute; inset: 0; display: grid; grid-template-columns: repeat(4,1fr); }
  .density-grid i { border-right: 1px solid rgba(255,255,255,.045); }
  .density-bars { position: absolute; z-index: 2; inset: 5px 4px 4px; display: grid; grid-template-columns: repeat(var(--bins, 1),1fr); grid-auto-flow: column; align-items: end; gap: 2px; }
  .density-bars button { position: relative; height: 100%; padding: 0; border: 0; border-radius: 2px; background: transparent; cursor: pointer; }
  .density-bars button span { position: absolute; right: 0; bottom: 0; left: 0; height: var(--height); border-radius: 2px 2px 0 0; background: linear-gradient(180deg, #7799ff, rgba(111,123,247,.28)); box-shadow: 0 0 12px rgba(111,123,247,.14); transition: height .28s ease, opacity .18s ease, filter .18s ease, background .18s ease; }
  .density-bars button.filtered-out span { opacity: .18; filter: saturate(.4); }
  .density-bars button:hover span, .density-bars button:focus-visible span { background: #8ca9ff; }
  .density-bars button.issue span { box-shadow: inset 0 3px #ff7c78, 0 0 12px rgba(255,124,120,.18); }
  .density-bars button.selected { background: rgba(111,123,247,.16); }
  .range-wash { position: absolute; z-index: 3; top: 0; bottom: 0; left: var(--left); width: var(--width); border-right: 1px solid rgba(126,163,255,.72); border-left: 1px solid rgba(126,163,255,.72); background: rgba(111,123,247,.18); box-shadow: inset 0 0 18px rgba(111,123,247,.1); pointer-events: none; }
  .range-wash span { position: absolute; top: 4px; left: 50%; max-width: calc(100% - 10px); transform: translateX(-50%); overflow: hidden; padding: 2px 5px; border: 1px solid rgba(126,163,255,.32); border-radius: 3px; color: #dce5ff; background: rgba(8,12,20,.88); font: 8px 'IBM Plex Mono', monospace; white-space: nowrap; text-overflow: ellipsis; }
  .range-handle { position: absolute; z-index: 6; top: 0; bottom: 0; left: clamp(14px, var(--left), calc(100% - 14px)); width: 24px; padding: 0; transform: translateX(-50%); border: 0; background: transparent; cursor: ew-resize; touch-action: none; }
  .range-handle::before { content: ''; position: absolute; top: 50%; left: 9px; width: 6px; height: 24px; transform: translateY(-50%); border: 1px solid #9ab3ff; border-radius: 3px; background: #1a2a51; box-shadow: 0 4px 14px rgba(0,0,0,.45); }
  .range-handle::after { content: ''; position: absolute; top: 50%; left: 11px; width: 2px; height: 10px; transform: translateY(-50%); border-right: 1px solid rgba(255,255,255,.6); border-left: 1px solid rgba(255,255,255,.6); }
  .range-handle:hover::before, .range-handle:focus-visible::before { border-color: white; background: #3152a0; }
  .playhead, .lane-playhead { position: absolute; z-index: 4; top: 0; bottom: 0; left: var(--left); width: 1px; background: #a7bbff; box-shadow: 0 0 10px rgba(102,145,255,.7); pointer-events: none; transition: left .2s ease; }
  .playhead span { position: absolute; top: 0; left: -4px; width: 9px; height: 6px; background: #a7bbff; clip-path: polygon(0 0,100% 0,50% 100%); }
  .axis { display: flex; justify-content: space-between; padding: 3px 12px 7px; color: #657387; font: 8px 'IBM Plex Mono', monospace; }
  .actor-ribbons { border-top: 1px solid rgba(255,255,255,.055); }
  .actor-ribbon { min-width: 0; display: grid; grid-template-columns: minmax(104px, 145px) minmax(0,1fr); min-height: 29px; border-bottom: 1px solid rgba(255,255,255,.045); }
  .actor-ribbon.selected { background: rgba(111,123,247,.055); }
  .actor-ribbon.filtered-out { opacity: .34; }
  .actor-overflow { min-height: 24px; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 0 12px; border-bottom: 1px solid rgba(255,255,255,.045); color: #68778c; background: rgba(255,255,255,.012); font-size: 8px; }
  .actor-overflow strong { color: #8293ad; font-weight: 700; }
  .actor-label { min-width: 0; display: flex; align-items: center; justify-content: space-between; gap: 6px; padding: 0 9px; border: 0; border-right: 1px solid rgba(255,255,255,.055); color: #d3dbe7; background: transparent; cursor: pointer; }
  .actor-label strong { min-width: 0; overflow: hidden; font-size: 9px; white-space: nowrap; text-overflow: ellipsis; }
  .actor-label span { color: #65758b; font-size: 8px; text-transform: uppercase; }
  .ribbon-track { position: relative; min-width: 0; margin: 6px 12px; background: linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px); background-size: 25% 100%; }
  .lifecycle { position: absolute; top: 6px; left: var(--left); width: var(--width); min-width: 3px; height: 4px; border-radius: 999px; background: rgba(158,170,255,.44); box-shadow: 0 0 9px rgba(111,123,247,.22); transition: left .28s ease, width .28s ease; }
  .event-tick { position: absolute; z-index: 2; top: 3px; left: var(--left); width: 7px; height: 13px; padding: 0; transform: translateX(-50%); border: 0; background: transparent; cursor: pointer; }
  .event-tick span { display: block; width: 5px; height: 5px; margin: 4px auto; border: 1px solid #93a8d0; background: #151c27; transform: rotate(45deg); transition: border-color .15s ease, background .15s ease, box-shadow .15s ease; }
  .event-tick.filtered-out { opacity: .16; }
  .event-tick.issue span { border-color: #ff7c78; background: #592b2b; box-shadow: 0 0 7px rgba(255,124,120,.45); }
  .event-tick.selected span { border-color: white; background: #9eaaff; box-shadow: 0 0 0 3px rgba(158,170,255,.18), 0 0 10px #6f7bf7; }
  .lane-playhead { z-index: 1; }
  .ruler-footer { min-width: 0; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 8px 12px; }
  .ruler-footer > strong { flex: 0 0 auto; color: #aab6c7; font-size: 9px; }
  .ruler-legend { min-width: 0; display: flex; flex-wrap: wrap; gap: 8px 13px; color: #718096; font-size: 8px; }
  .ruler-legend span { display: inline-flex; align-items: center; gap: 5px; }
  .ruler-legend i { display: inline-block; flex: 0 0 auto; }
  .legend-event { width: 6px; height: 6px; border: 1px solid #93a8d0; transform: rotate(45deg); }
  .legend-life { width: 15px; height: 3px; border-radius: 999px; background: rgba(158,170,255,.55); }
  .legend-issue { width: 2px; height: 10px; background: #ff7c78; }
  .legend-range { width: 14px; height: 9px; border: 1px solid rgba(126,163,255,.6); background: rgba(111,123,247,.16); }
  .architecture-scope { display: grid; grid-template-columns: repeat(auto-fit,minmax(190px,1fr)); margin-top: 10px; border: 1px solid rgba(255,255,255,.075); border-bottom: 0; border-radius: 12px 12px 0 0; background: rgba(255,255,255,.018); }
  .architecture-scope > div { min-width: 0; padding: 9px 12px; border-right: 1px solid rgba(255,255,255,.055); }
  .architecture-scope > div:last-child { border-right: 0; }
  .architecture-scope strong, .architecture-scope small { display: block; min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .architecture-scope strong { margin-top: 3px; color: #dfe5ee; font-size: 10px; }
  .architecture-scope small { margin-top: 2px; color: #718096; font-size: 8px; }
  .architecture-scope .warning strong { color: #f0bd76; }
  .architecture-view > :global(.topology) { border-radius: 0 0 12px 12px; }
  .architecture-view.compact .architecture-header { min-height: 44px; padding-block: 7px; }
  .architecture-view.compact .architecture-header h2 { font-size: 14px; }
  .architecture-view.compact .density { height: 54px; }
  .architecture-view.compact .actor-ribbon { min-height: 25px; }
  .architecture-view.compact .ruler-footer { padding-block: 6px; }
  button:focus-visible { outline: 2px solid #7c9cff; outline-offset: 2px; }
  .sr-only { position: absolute; width: 1px; height: 1px; padding: 0; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }

  @container (max-width: 440px) {
    .architecture-header, .ruler-heading, .ruler-footer { align-items: flex-start; flex-direction: column; }
    .detection-summary { justify-content: flex-start; }
    .ruler-actions { width: 100%; display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); }
    .ruler-actions button { min-height: 44px; }
    .actor-ribbon { min-height: 44px; }
    .actor-ribbon { grid-template-columns: 105px minmax(0,1fr); }
    .architecture-scope { display: flex; min-height: 52px; grid-template-columns: none; overflow-x: auto; overflow-y: hidden; scrollbar-width: thin; }
    .architecture-scope > div { flex: 0 0 min(72vw, 240px); display: grid; align-content: center; padding-block: 6px; border-right: 1px solid rgba(255,255,255,.055); border-bottom: 0; }
    .architecture-scope > div:last-child { border-right: 0; border-bottom: 0; }
    .architecture-scope strong { margin-top: 1px; }
    .architecture-scope small { margin-top: 1px; }
    .ruler-footer > strong { flex: 0 1 auto; }
    .architecture-view.time-only .ruler-heading { align-items: center; flex-direction: row; }
    .architecture-view.time-only .ruler-heading > div:first-child span,
    .architecture-view.time-only .ruler-heading > div:first-child small { display: none; }
    .architecture-view.time-only .ruler-actions { width: auto; display: flex; min-width: 0; overflow-x: auto; }
    .architecture-view.time-only .ruler-actions button { min-width: max-content; min-height: 36px; }
  }
  .architecture-view.compact .architecture-header { min-height: 32px; display: flex; padding: 4px 10px; }
  .architecture-view.compact .architecture-header .detection-summary { display: none; }
  .architecture-view.compact .architecture-header h2 { font-size: 12px; }
  .architecture-view.compact .ruler-footer { display: none; }
  .architecture-view.compact { min-height: 0; }
  .architecture-view.compact .ruler-heading { min-height: 40px; padding-block: 5px; }
  .architecture-view.compact .density { height: 42px; }
  .architecture-view.compact .actor-ribbon { min-height: 22px; }
  .architecture-view.compact .ruler-actions button { min-height: 28px; }
  .architecture-view.time-only { min-height: 0; background: #07090d; }
  .architecture-view.time-only .orchestration-ruler { border-width: 0 0 1px; box-shadow: none; }
  .architecture-view.time-only .ruler-heading { padding-inline: 14px; }
  @media (prefers-reduced-motion: reduce) {
    .density-bars button span,
    .playhead,
    .lane-playhead,
    .lifecycle,
    .event-tick span { transition: none; }
  }
  @media (max-height: 650px) {
    .architecture-view.time-only .density { height: 32px; min-height: 32px; flex-basis: 32px; }
    .architecture-view.time-only .actor-ribbon { min-height: 20px; }
  }
</style>
