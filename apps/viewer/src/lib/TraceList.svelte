<script lang="ts">
  import { deriveRunIdentity } from './runIdentity';
  import { listKey, type TraceManifest } from './types';
  import { PanelLeftOpen } from '@lucide/svelte';

  type RunFilter = 'all' | 'issues' | 'live';

  let { traces, selectedId, onselect, compact = false, onrestore = () => undefined }: {
    traces: TraceManifest[];
    selectedId: string | null;
    onselect: (trace: TraceManifest) => void;
    compact?: boolean;
    onrestore?: () => void;
  } = $props();

  let filter = $state<RunFilter>('all');
  let matchingTraces = $derived(traces.filter((trace) => {
    if (filter === 'issues') return ['error', 'warning'].includes(health(trace).tone);
    if (filter === 'live') return trace.ended_at === null;
    return true;
  }));
  let visibleTraces = $derived.by(() => {
    const selected = traces.find((trace) => trace.trace_id === selectedId);
    return selected && !matchingTraces.some((trace) => trace.trace_id === selected.trace_id)
      ? [selected, ...matchingTraces]
      : matchingTraces;
  });

  function duration(trace: TraceManifest): string {
    if (!trace.ended_at) return 'Live';
    const milliseconds = Math.max(0, Date.parse(trace.ended_at) - Date.parse(trace.started_at));
    if (milliseconds < 1000) return `${milliseconds} ms`;
    if (milliseconds < 60_000) return `${(milliseconds / 1000).toFixed(1)} s`;
    return `${Math.floor(milliseconds / 60_000)}m ${Math.round((milliseconds % 60_000) / 1000)}s`;
  }

  function title(trace: TraceManifest): string {
    return deriveRunIdentity(trace, { goal: trace.summary?.display_name }).title;
  }

  function when(trace: TraceManifest): string {
    const date = new Date(trace.started_at);
    const today = new Date();
    const sameDay = date.toDateString() === today.toDateString();
    const yesterday = new Date(today);
    yesterday.setDate(today.getDate() - 1);
    if (sameDay) return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    if (date.toDateString() === yesterday.toDateString()) return `Yesterday, ${date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`;
    return date.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
  }

  function eventCount(trace: TraceManifest): number | null {
    return trace.summary?.event_count ?? trace.journal?.event_count ?? null;
  }

  function health(trace: TraceManifest): { label: string; tone: 'success' | 'warning' | 'error' | 'live' } {
    if (trace.integrity === 'invalid') return { label: 'Unverified', tone: 'error' };
    if (trace.exit_code !== null && trace.exit_code !== 0) return { label: 'Failed', tone: 'error' };
    if ((trace.summary?.issue_count ?? 0) > 0) return { label: 'Needs attention', tone: 'warning' };
    if (!trace.ended_at || trace.integrity === 'live') return { label: 'Running', tone: 'live' };
    return { label: 'Passed', tone: 'success' };
  }

  function outcome(trace: TraceManifest): string {
    const state = health(trace).label;
    const issues = trace.summary?.issue_count ?? 0;
    const actors = trace.summary?.actor_count ?? 0;
    return [
      state,
      issues > 0 ? `${issues} issue${issues === 1 ? '' : 's'}` : null,
      actors > 0 ? `${actors} actor${actors === 1 ? '' : 's'}` : null,
    ].filter(Boolean).join(' · ');
  }

  function selectByKeyboard(event: KeyboardEvent, index: number) {
    let next = index;
    if (event.key === 'ArrowDown') next = Math.min(visibleTraces.length - 1, index + 1);
    else if (event.key === 'ArrowUp') next = Math.max(0, index - 1);
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = visibleTraces.length - 1;
    else return;
    event.preventDefault();
    const trace = visibleTraces[next];
    if (!trace) return;
    onselect(trace);
    (event.currentTarget as HTMLElement).closest('.trace-scroll')
      ?.querySelectorAll<HTMLButtonElement>('.trace-select')[next]?.focus();
  }
</script>

<aside class="trace-list" class:compact aria-label="Runs">
  {#if compact}
    <div class="rail-header"><button type="button" onclick={onrestore} aria-label="Expand runs" title="Expand runs"><PanelLeftOpen size={18} strokeWidth={1.8} aria-hidden="true" /></button></div>
    <div class="rail-scroll" aria-label="Run status rail">
      {#each traces as trace (listKey(trace))}
        <button
          type="button"
          class="rail-run"
          class:active={trace.trace_id === selectedId}
          aria-pressed={trace.trace_id === selectedId}
          aria-label={`${title(trace)}. ${outcome(trace)}. ${eventCount(trace) ?? 0} events.`}
          title={`${title(trace)} · ${outcome(trace)}`}
          onclick={() => onselect(trace)}
        ><span class="status-mark" data-tone={health(trace).tone} aria-hidden="true"></span></button>
      {/each}
    </div>
  {:else}
  <div class="run-list-header">
    <div><strong>Runs</strong><span>{traces.length}</span></div>
    <div class="run-filters" aria-label="Filter runs">
      <button class:active={filter === 'all'} aria-pressed={filter === 'all'} onclick={() => filter = 'all'}>All</button>
      <button class:active={filter === 'issues'} aria-pressed={filter === 'issues'} onclick={() => filter = 'issues'}>Issues</button>
      <button class:active={filter === 'live'} aria-pressed={filter === 'live'} onclick={() => filter = 'live'}>Live</button>
    </div>
  </div>
  <div class="trace-scroll">
    {#each visibleTraces as trace, index (listKey(trace))}
      <button
        class="trace-select"
        class:active={trace.trace_id === selectedId}
        aria-pressed={trace.trace_id === selectedId}
        aria-label={`${title(trace)}. ${outcome(trace)}. ${eventCount(trace) ?? 0} events.`}
        onclick={() => onselect(trace)}
        onkeydown={(event) => selectByKeyboard(event, index)}
      >
        <span class="status-mark" data-tone={health(trace).tone} aria-hidden="true"></span>
        <span class="run-copy">
          <span class="run-title-line">
            <strong>{title(trace)}</strong>
            {#if !trace.ended_at}<span class="live-badge">Live</span>{/if}
            {#if trace.trace_id === selectedId && !matchingTraces.some((item) => item.trace_id === trace.trace_id)}<span class="outside-badge">Pinned</span>{/if}
          </span>
          <span class="run-outcome" data-tone={health(trace).tone}>{outcome(trace)}</span>
          <span class="run-foot" title={new Date(trace.started_at).toLocaleString()}>
            <time datetime={trace.started_at}>{when(trace)}</time>
            <span aria-hidden="true">·</span><span>{trace.ended_at ? `captured ${duration(trace)}` : duration(trace)}</span>
            {#if eventCount(trace) !== null}<span aria-hidden="true">·</span><span>{eventCount(trace)} events</span>{/if}
          </span>
        </span>
        <span class="open-cue" aria-hidden="true">›</span>
      </button>
    {:else}
      <div class="run-empty" role="status">
        <strong>No {filter === 'all' ? '' : filter} runs</strong>
        <span>Choose another run filter.</span>
      </div>
    {/each}
  </div>
  {/if}
</aside>

<style>
  .trace-list { container-type: inline-size; display: grid; grid-template-rows: auto minmax(0, 1fr); background: #050505; }
  .trace-list.compact {
    width: 100%;
    min-width: 0;
    max-width: 100%;
    box-sizing: border-box;
    grid-template-rows: 52px minmax(0, 1fr);
    overflow: hidden;
    border-right: 1px solid var(--line);
    background: #07090d;
    /* Contain paint so hover fills and icons cannot bleed outside the compact rail. */
    contain: layout paint;
  }
  .rail-header {
    display: grid;
    place-items: center;
    width: 100%;
    min-width: 0;
    height: 52px;
    box-sizing: border-box;
    border-bottom: 1px solid var(--line);
    overflow: hidden;
  }
  /* Fully reset button chrome so global list-row styles cannot leak into the rail. */
  .rail-header button,
  .rail-run {
    box-sizing: border-box;
    width: 100%;
    min-width: 0;
    max-width: 100%;
    min-height: 0 !important;
    height: 44px;
    display: flex !important;
    align-items: center;
    justify-content: center;
    gap: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
    border: 0 !important;
    border-radius: 0;
    color: #8593a8;
    background: transparent !important;
    box-shadow: none !important;
    text-align: center;
    cursor: pointer;
    overflow: hidden;
    grid-template-columns: none !important;
  }
  .rail-header button {
    height: 52px;
  }
  .rail-header button:hover,
  .rail-run:hover {
    color: white;
    background: rgba(111,123,247, 0.14) !important;
    box-shadow: none !important;
  }
  .rail-scroll {
    min-height: 0;
    min-width: 0;
    width: 100%;
    overflow-x: hidden;
    overflow-y: auto;
  }
  .rail-run {
    position: relative;
    height: 44px;
    min-height: 44px !important;
    border-bottom: 1px solid var(--line-soft) !important;
  }
  .rail-run.active,
  .rail-run[aria-pressed='true'] {
    color: #c8d5ff;
    background: rgba(111,123,247, 0.16) !important;
    box-shadow: inset 2px 0 0 var(--blue) !important;
  }
  .rail-run .status-mark {
    display: block;
    width: 9px;
    height: 9px;
    margin: 0 !important;
    flex: none;
  }
  .rail-header button :global(svg) {
    display: block;
    width: 16px;
    height: 16px;
    max-width: 16px;
    max-height: 16px;
    overflow: visible;
    flex: none;
  }
  .run-list-header { display: grid; gap: 9px; padding: 12px 12px 10px; border-bottom: 1px solid var(--line); background: #08090b; }
  .run-list-header > div:first-child { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .run-list-header strong { color: #d8e0ea; font-family: 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; font-size: 11px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
  .run-list-header > div:first-child span { color: var(--muted); font: 10px 'IBM Plex Mono', monospace; }
  .run-filters { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 3px; padding: 3px; border: 1px solid var(--line); border-radius: 5px; background: #050505; }
  .run-filters button { min-width: 0; min-height: 27px; padding: 0 6px; border: 0; border-radius: 3px; color: var(--muted); background: transparent; font-size: 10px; font-weight: 700; cursor: pointer; }
  .run-filters button:hover { color: #e4e9f0; background: rgba(255,255,255,.035); }
  .run-filters button.active { color: white; background: #171b23; box-shadow: inset 0 -2px var(--blue); }
  .trace-scroll { min-height: 0; height: auto; overflow-y: auto; }
  .trace-list .trace-select { position: relative; width: 100%; min-width: 0; min-height: 98px; display: grid; grid-template-columns: 9px minmax(0, 1fr) 12px; gap: 10px; align-items: start; padding: 13px 10px 13px 14px; border: 0; border-bottom: 1px solid var(--line-soft); color: inherit; text-align: left; background: transparent; cursor: pointer; }
  .trace-list .trace-select:hover { background: #0b0d11; }
  .trace-list .trace-select.active { background: linear-gradient(90deg, rgba(111,123,247,.16), rgba(111,123,247,.045)); box-shadow: inset 3px 0 var(--blue); }
  .status-mark { width: 8px; height: 8px; margin-top: 5px; border: 2px solid currentColor; border-radius: 50%; color: var(--green); background: transparent; }
  .status-mark[data-tone='error'] { color: var(--red); background: var(--red); box-shadow: 0 0 9px rgba(255,124,120,.22); }
  .status-mark[data-tone='warning'] { color: var(--amber); background: var(--amber); }
  .status-mark[data-tone='live'] { color: var(--blue-strong); box-shadow: 0 0 10px rgba(158,170,255,.35); }
  .run-copy { min-width: 0; display: grid; gap: 5px; }
  .run-title-line { min-width: 0; display: flex; align-items: flex-start; gap: 7px; }
  .run-title-line strong { min-width: 0; flex: 1 1 auto; color: #f1f4f8; font-family: 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; font-size: 13px; font-weight: 700; line-height: 1.3; overflow-wrap: break-word; }
  .live-badge { flex: 0 0 auto; padding: 2px 5px; border: 1px solid rgba(158,170,255,.38); border-radius: 3px; color: #b8c0ff; background: rgba(111,123,247,.13); font-size: 9px; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
  .outside-badge { flex: 0 0 auto; padding: 2px 5px; border: 1px solid rgba(245,188,104,.38); border-radius: 3px; color: #f1c984; background: rgba(245,188,104,.08); font-size: 8px; font-weight: 800; letter-spacing: .06em; text-transform: uppercase; }
  .run-outcome { color: #aeb9c8; font-size: 11px; font-weight: 650; line-height: 1.35; }
  .run-outcome[data-tone='error'] { color: #ff9b98; }
  .run-outcome[data-tone='warning'] { color: #f2c57f; }
  .run-outcome[data-tone='live'] { color: #b8c0ff; }
  .run-outcome[data-tone='success'] { color: #8ddab6; }
  .run-foot { min-width: 0; display: flex; flex-wrap: wrap; gap: 3px 5px; color: var(--muted); font-size: 10px; line-height: 1.35; }
  .open-cue { align-self: center; color: #5e6a7b; font-size: 18px; transition: color .12s ease, transform .12s ease; }
  .trace-select:hover .open-cue, .trace-select.active .open-cue { color: var(--blue-strong); transform: translateX(2px); }
  .run-empty { display: grid; place-content: center; gap: 5px; min-height: 150px; padding: 20px; color: var(--muted); text-align: center; }
  .run-empty strong { color: #c9d1dc; font-size: 13px; }
  .run-empty span { font-size: 11px; }

  @container (max-width: 239px) {
    .run-list-header { padding-inline: 9px; }
    .trace-list .trace-select { min-height: 86px; grid-template-columns: 8px minmax(0, 1fr); padding-inline: 10px; gap: 8px; }
    .open-cue { display: none; }
    .run-title-line strong { font-size: 12px; }
    .run-outcome { font-size: 10px; }
    .run-foot span:last-child, .run-foot span:nth-last-child(2) { display: none; }
  }
</style>
