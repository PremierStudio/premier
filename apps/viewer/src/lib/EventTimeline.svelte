<script lang="ts">
  import { tick } from 'svelte';
  import type { TraceEvent } from './types';
  import { actorId, actorRole, categoryOf, eventSummary, isProcessNoise, timelineLayout } from './analysis';
  import { eventPayload } from './types';
  import BrandIcon from './BrandIcon.svelte';
  import { Bot, Wrench, ShieldCheck, SquareTerminal, Sparkles, CircleAlert } from '@lucide/svelte';

  function familyIcon(event: TraceEvent) {
    const category = categoryOf(event);
    if (category === 'error') return CircleAlert;
    if (category === 'model') return Sparkles;
    if (category === 'tool') return Wrench;
    if (category === 'approval') return ShieldCheck;
    if (category === 'process') return SquareTerminal;
    return Bot;
  }

  function modelMeta(event: TraceEvent): { provider: string | null; model: string | null } {
    if (categoryOf(event) !== 'model' && !event.kind.startsWith('model.') && !event.kind.startsWith('llm.')) {
      return { provider: null, model: null };
    }
    const payload = eventPayload(event);
    const provider = typeof payload.provider === 'string' ? payload.provider : typeof payload.vendor === 'string' ? payload.vendor : null;
    const model = typeof payload.model === 'string' ? payload.model : typeof payload.model_id === 'string' ? payload.model_id : null;
    return { provider, model };
  }

  let { events, selectedSequence, onselect }: {
    events: TraceEvent[];
    selectedSequence: number | null;
    onselect: (event: TraceEvent) => void;
  } = $props();

  const rowHeight = 64;
  const overscan = 8;
  let showRawProcess = $state(false);
  let scrollElement = $state<HTMLDivElement>();
  let scrollTop = $state(0);
  let viewportHeight = $state(500);

  function aggregateProcess(input: TraceEvent[]) {
    if (showRawProcess) return { events: input, counts: new Map<string, number>() };
    const output: TraceEvent[] = [];
    const counts = new Map<string, number>();
    for (let index = 0; index < input.length;) {
      const current = input[index];
      if (!isProcessNoise(current)) {
        output.push(current);
        index += 1;
        continue;
      }
      const group = [current];
      let cursor = index + 1;
      while (cursor < input.length && group.length < 100) {
        const candidate = input[cursor];
        if (!isProcessNoise(candidate) || candidate.kind !== current.kind || actorId(candidate) !== actorId(current)) break;
        group.push(candidate);
        cursor += 1;
      }
      if (group.length >= 3) {
        const representative = group.find((event) => event.sequence === selectedSequence) ?? group[group.length - 1];
        output.push(representative);
        counts.set(representative.event_id, group.length);
      } else output.push(...group);
      index = cursor;
    }
    return { events: output, counts };
  }

  let processed = $derived.by(() => aggregateProcess(events));
  let displayEvents = $derived(processed.events);
  let layout = $derived(timelineLayout(displayEvents));
  let virtualized = $derived(displayEvents.length > 300);
  let windowStart = $derived(virtualized ? Math.max(0, Math.floor(scrollTop / rowHeight) - overscan) : 0);
  let windowEnd = $derived(virtualized ? Math.min(layout.events.length, Math.ceil((scrollTop + viewportHeight) / rowHeight) + overscan) : layout.events.length);
  let renderedEvents = $derived(layout.events.slice(windowStart, windowEnd));
  let expandedEvents = $state<Set<string>>(new Set());

  function navigate(event: KeyboardEvent, index: number) {
    let target = index;
    if (event.key === 'ArrowDown') target = Math.min(index + 1, displayEvents.length - 1);
    else if (event.key === 'ArrowUp') target = Math.max(index - 1, 0);
    else if (event.key === 'Home') target = 0;
    else if (event.key === 'End') target = displayEvents.length - 1;
    else return;
    event.preventDefault();
    const next = displayEvents[target];
    onselect(next);
    if (virtualized && scrollElement) scrollElement.scrollTop = target * rowHeight;
    void tick().then(() => scrollElement?.querySelector<HTMLElement>(`[data-event-id="${CSS.escape(next.event_id)}"]`)?.focus());
  }

  function activate(event: KeyboardEvent, index: number) {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    onselect(displayEvents[index]);
  }

  function toggleSummary(eventId: string) {
    const next = new Set(expandedEvents);
    if (next.has(eventId)) next.delete(eventId);
    else next.add(eventId);
    expandedEvents = next;
  }

  function updateViewport() {
    if (!scrollElement) return;
    scrollTop = scrollElement.scrollTop;
    viewportHeight = scrollElement.clientHeight;
  }

  // Center on selection only when the selected sequence changes — never fight user scroll.
  let lastCenteredSequence = $state<number | null>(null);
  $effect(() => {
    const sequence = selectedSequence;
    if (sequence === null || !scrollElement) return;
    if (sequence === lastCenteredSequence) return;
    viewportHeight = scrollElement.clientHeight || viewportHeight;
    const index = displayEvents.findIndex((event) => event.sequence === sequence);
    if (index < 0) return;
    if (virtualized) {
      scrollElement.scrollTop = Math.max(0, index * rowHeight - viewportHeight / 2);
      updateViewport();
    }
    lastCenteredSequence = sequence;
  });
</script>

<section class="timeline" class:virtualized aria-label="Trace events">
  <div class="panel-heading">
    <span>Event timeline</span>
    <div><span>{events.length} event{events.length === 1 ? '' : 's'} · {layout.lanes.length} actor{layout.lanes.length === 1 ? '' : 's'}{virtualized ? ' · windowed rendering' : ''}</span>{#if processed.counts.size || showRawProcess}<button onclick={() => showRawProcess = !showRawProcess}>{showRawProcess ? 'Collapse runtime' : 'Show raw runtime'}</button>{/if}</div>
  </div>
  {#if events.length === 0}
    <div class="timeline-scroll filtered-empty" role="status"><strong>No matching evidence</strong><span>Clear or broaden the active filters.</span></div>
  {:else}
    <div class="timeline-scroll" bind:this={scrollElement} onscroll={updateViewport} role="listbox" aria-label="Events" aria-orientation="vertical">
      <div class="lane-key">
        <span>Step</span>
        <span>Actor</span>
        <span>Event</span>
        <span>Status</span>
      </div>
      {#if virtualized && windowStart > 0}<div class="virtual-spacer" style={`height:${windowStart * rowHeight}px`} aria-hidden="true"></div>{/if}
      {#each renderedEvents as event, localIndex (event.event_id)}
        {@const index = windowStart + localIndex}
        {@const FamilyIcon = familyIcon(event)}
        {@const model = modelMeta(event)}
        <div
          class:active={event.sequence === selectedSequence}
          class:error={categoryOf(event) === 'error'}
          data-event-id={event.event_id}
          onclick={() => onselect(displayEvents[index])}
          onkeydown={(keyEvent) => { navigate(keyEvent, index); activate(keyEvent, index); }}
          aria-selected={event.sequence === selectedSequence}
          role="option"
          tabindex={event.sequence === selectedSequence || (selectedSequence === null && index === 0) ? 0 : -1}
        >
          <span class="sequence">{String(event.sequence).padStart(3, '0')}</span>
          <span class="event-actor" title={`${actorRole(event)} ${actorId(event)}`}><strong>{actorId(event)}</strong><small>{actorRole(event) === 'subagent' ? 'sub-agent' : actorRole(event)}</small></span>
          <span class="event-copy" style={`padding-left:${Math.min(event.depth || 0, 6) * 10}px`}>
            <span class="event-title">
              {#if model.provider || model.model}
                <BrandIcon provider={model.provider} model={model.model} size={13} />
              {:else}
                <span class="family-icon" data-category={categoryOf(event)}><FamilyIcon size={12} strokeWidth={1.9} aria-hidden="true" /></span>
              {/if}
              <strong>{event.kind}</strong>
              {#if (event.depth || 0) > 0}<span class="depth-badge" title={`Causal depth ${event.depth}`}>d{event.depth}</span>{/if}
            </span>
            <small class:expanded={expandedEvents.has(event.event_id)}>{eventSummary(event)}</small>
            {#if processed.counts.has(event.event_id)}<span class="process-group">{processed.counts.get(event.event_id)} consecutive {event.kind === 'process.stderr' ? 'stderr' : 'stdout'} lines collapsed</span>{/if}
            {#if !virtualized && eventSummary(event).length > 108}
              <button type="button" class="summary-toggle" aria-expanded={expandedEvents.has(event.event_id)} onclick={(clickEvent) => { clickEvent.stopPropagation(); toggleSummary(event.event_id); }}>
                {expandedEvents.has(event.event_id) ? 'Show less' : 'Read full summary'}
              </button>
            {/if}
          </span>
          <span class="event-status" data-status={event.status || categoryOf(event)}>{event.status || 'recorded'}</span>
          {#if event.duration_ms > 0}<span class="duration">{event.duration_ms >= 1000 ? `${(event.duration_ms / 1000).toFixed(2)} s` : `${event.duration_ms} ms`}</span>{/if}
          {#if event.elapsedMs > 0}<time datetime={event.timestamp} title={new Date(event.timestamp).toLocaleTimeString([], { hour12: false, fractionalSecondDigits: 3 })}>+{event.elapsedMs >= 1000 ? `${(event.elapsedMs / 1000).toFixed(2)} s` : `${event.elapsedMs} ms`}</time>{/if}
        </div>
      {/each}
      {#if virtualized && windowEnd < layout.events.length}<div class="virtual-spacer" style={`height:${(layout.events.length - windowEnd) * rowHeight}px`} aria-hidden="true"></div>{/if}
    </div>
  {/if}
</section>

<style>
  .panel-heading span:first-child { color: #b7c1d0; }
  .panel-heading > div { min-width: 0; display: flex; align-items: center; gap: 8px; }
  .panel-heading > div > span { min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .panel-heading button { min-height: 28px; padding: 0 8px; border: 1px solid #34425a; border-radius: 5px; color: #b9c7d9; background: #111722; font-size: 9px; white-space: nowrap; cursor: pointer; }
  .timeline-scroll { padding-top: 0; }
  .lane-key { position: sticky; z-index: 1; top: 0; display: grid; grid-template-columns: 38px minmax(96px, 140px) minmax(0, 1fr) auto; gap: 12px; align-items: center; min-height: 34px; padding: 0 14px; border-bottom: 1px solid var(--line); color: var(--muted); background: rgba(5, 5, 5, .96); font-size: 10px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
  .timeline [role='option'] { display: grid; grid-template-columns: 38px minmax(96px, 140px) minmax(0, 1fr) auto auto auto; gap: 12px; min-height: 55px; align-items: center; padding: 7px 14px; border-bottom: 1px solid rgba(35, 42, 55,.42); cursor: pointer; }
  .timeline.virtualized [role='option'] { height: 64px; overflow: hidden; }
  .virtual-spacer { width: 100%; pointer-events: none; }
  .timeline [role='option']:hover { background: rgba(255,255,255,.025); }
  .timeline [role='option']:focus-visible { outline: 2px solid var(--focus); outline-offset: -2px; }
  .timeline [role='option'].active { background: var(--blue-soft); box-shadow: inset 2px 0 var(--blue); }
  .timeline [role='option'].error { box-shadow: inset 2px 0 #ff716d; }
  .event-title { display: flex; align-items: center; gap: 8px; min-width: 0; }
  .event-title strong { flex: 0 1 auto; overflow-wrap: anywhere; white-space: normal; }
  .family-icon { display: inline-grid; place-items: center; width: 16px; height: 16px; flex: 0 0 auto; border-radius: 4px; color: #8ea8e0; background: rgba(111,123,247,.1); }
  .family-icon[data-category='error'] { color: #ff9b98; background: rgba(255,113,109,.1); }
  .family-icon[data-category='tool'] { color: #8fd8d3; background: rgba(99,215,210,.1); }
  .family-icon[data-category='approval'] { color: #f0c88a; background: rgba(240,185,104,.1); }
  .family-icon[data-category='process'] { color: #a8b4c4; background: rgba(255,255,255,.05); }
  .family-icon[data-category='model'] { color: #c4a7ff; background: rgba(168,130,255,.12); }
  .depth-badge { flex: 0 0 auto; padding: 1px 5px; border: 1px solid rgba(127,164,255,.28); border-radius: 3px; color: #8ea8e0; background: rgba(111,123,247,.08); font: 700 9px 'IBM Plex Mono', monospace; }
  .event-actor { min-width: 0; }
  .event-actor strong, .event-actor small { display: block; overflow: hidden; text-overflow: ellipsis; }
  .event-actor strong { color: #cbd5e5; font: 700 11px 'IBM Plex Mono', monospace; white-space: nowrap; }
  .event-actor small { margin-top: 3px; color: #758298; font-size: 9px; letter-spacing: .06em; text-transform: uppercase; }
  .event-copy small { display: -webkit-box; overflow: hidden; color: #9aa6b8; line-height: 1.35; white-space: normal; overflow-wrap: anywhere; line-clamp: 2; -webkit-box-orient: vertical; -webkit-line-clamp: 2; }
  .event-copy small.expanded { display: block; overflow: visible; line-clamp: unset; -webkit-line-clamp: unset; }
  .timeline .summary-toggle { display: inline-block; width: auto; min-height: 0; margin-top: 5px; padding: 0; border: 0; color: var(--blue-strong); background: transparent; font: 700 11px 'Source Sans 3 Variable', 'Source Sans 3', sans-serif; cursor: pointer; }
  .process-group { display: block; width: max-content; max-width: 100%; margin-top: 5px; padding: 2px 6px; border: 1px solid rgba(99,215,210,.22); border-radius: 4px; color: #8fd8d3; background: rgba(99,215,210,.06); font-size: 9px; }
  .summary-toggle:hover { color: #dce4ff; text-decoration: underline; }
  .event-status { padding: 3px 6px; border: 1px solid #3b4a64; border-radius: 4px; color: #c3d0e7; background: #121a27; font: 700 9px 'IBM Plex Mono', monospace; text-transform: uppercase; white-space: nowrap; }
  .event-status[data-status='error'], .event-status[data-status='failed'], .event-status[data-status='denied'], .event-status[data-status='blocked'] { border-color: rgba(255,113,109,.45); color: #ffaaa6; background: rgba(255,113,109,.08); }
  .event-status[data-status='ok'], .event-status[data-status='approved'] { border-color: rgba(95,214,160,.4); color: #91e3bd; background: rgba(95,214,160,.07); }
  .sequence, time { font-size: 10px; }
  @media (max-width: 680px) {
    .lane-key { grid-template-columns: 26px minmax(76px, 94px) minmax(0, 1fr); padding-inline: 10px; gap: 8px; }
    .lane-key span:last-child { display: none; }
    .timeline [role='option'] { grid-template-columns: 26px minmax(76px, 94px) minmax(0, 1fr); padding-inline: 10px; gap: 8px; }
    .event-status, .duration, .timeline time { display: none; }
  }
</style>
