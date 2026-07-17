<script lang="ts">
  import { Activity, ArrowRight, Check, CircleMinus, CirclePlus, GitCompareArrows, TriangleAlert } from '@lucide/svelte';
  import { eventSummary, isIssue, runHealth } from './analysis';
  import { compareTraces, type ComparisonItem, type NumericDelta } from './semanticCompare';
  import type { TraceEvent, TraceManifest } from './types';

  let {
    baseline,
    current,
    baselineEvents,
    currentEvents,
    onselectCurrent = () => undefined
  }: {
    baseline: TraceManifest;
    current: TraceManifest;
    baselineEvents: TraceEvent[];
    currentEvents: TraceEvent[];
    onselectCurrent?: (event: TraceEvent) => void;
  } = $props();

  let comparison = $derived(compareTraces(baselineEvents, currentEvents));
  let baselineHealth = $derived(runHealth(baseline, baselineEvents));
  let currentHealth = $derived(runHealth(current, currentEvents));
  let baselineIssues = $derived(baselineEvents.filter(isIssue).length);
  let currentIssues = $derived(currentEvents.filter(isIssue).length);
  let differences = $derived.by(() => {
    const order = { changed: 0, added: 1, removed: 2, unchanged: 3 } as const;
    return comparison.items.filter((item) => item.status !== 'unchanged')
      .sort((a, b) => order[a.status] - order[b.status] || (a.current ?? a.baseline)!.sequence - (b.current ?? b.baseline)!.sequence);
  });

  function runName(trace: TraceManifest): string {
    return trace.name?.trim() || trace.summary?.display_name?.trim() || trace.trace_id;
  }

  function eventFor(item: ComparisonItem): TraceEvent {
    return item.current ?? item.baseline!;
  }

  function value(value: unknown): string {
    if (value === undefined) return 'Not captured';
    if (value === null) return 'null';
    if (typeof value === 'string') return value || 'Empty';
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    const serialized = JSON.stringify(value);
    return serialized.length > 80 ? `${serialized.slice(0, 77)}…` : serialized;
  }

  function signed(value: number, unit: string, digits = 0): string {
    const sign = value > 0 ? '+' : value < 0 ? '−' : '';
    return `${sign}${Math.abs(value).toFixed(digits)}${unit}`;
  }

  function durationDelta(delta: NumericDelta): string {
    if (Math.abs(delta.delta) < 1_000) return signed(delta.delta, ' ms');
    return signed(delta.delta / 1_000, ' s', 1);
  }

  function tokenDelta(delta: NumericDelta): string {
    return Math.abs(delta.delta) < 1_000 ? signed(delta.delta, ' tok') : signed(delta.delta / 1_000, 'k tok', 1);
  }

  function costDelta(delta: NumericDelta): string {
    const sign = delta.delta > 0 ? '+' : delta.delta < 0 ? '−' : '';
    const digits = Math.abs(delta.delta) < 0.01 ? 4 : 2;
    return `${sign}$${Math.abs(delta.delta).toFixed(digits)}`;
  }
</script>

<section class="comparison" aria-label="Trace comparison">
  <header class="comparison-head">
    <div><GitCompareArrows size={15} /><span>Semantic comparison</span></div>
    <small>Generated IDs, timestamps, and correlation noise are excluded.</small>
  </header>

  <div class="run-pair">
    <article class="run-summary" aria-label="Baseline run summary">
      <div class="run-role">Baseline</div>
      <strong title={runName(baseline)}>{runName(baseline)}</strong>
      <div class="run-metrics">
        <span data-tone={baselineHealth.tone}>{baselineHealth.label}</span>
        <small><Activity size={11} />{baselineEvents.length} event{baselineEvents.length === 1 ? '' : 's'}</small>
        <small class:issue={baselineIssues > 0}><TriangleAlert size={11} />{baselineIssues} issue{baselineIssues === 1 ? '' : 's'}</small>
      </div>
    </article>
    <div class="direction" aria-hidden="true"><ArrowRight size={16} /></div>
    <article class="run-summary current" aria-label="Current run summary">
      <div class="run-role">Current</div>
      <strong title={runName(current)}>{runName(current)}</strong>
      <div class="run-metrics">
        <span data-tone={currentHealth.tone}>{currentHealth.label}</span>
        <small><Activity size={11} />{currentEvents.length} event{currentEvents.length === 1 ? '' : 's'}</small>
        <small class:issue={currentIssues > 0}><TriangleAlert size={11} />{currentIssues} issue{currentIssues === 1 ? '' : 's'}</small>
      </div>
    </article>
  </div>

  <div class="counts" aria-label="Comparison totals">
    <div class="changed" aria-label="Changed events"><span>Changed</span><strong>{comparison.counts.changed}</strong></div>
    <div class="added" aria-label="Added events"><span>Added</span><strong>{comparison.counts.added}</strong></div>
    <div class="removed" aria-label="Removed events"><span>Removed</span><strong>{comparison.counts.removed}</strong></div>
    <div class="unchanged" aria-label="Unchanged events"><span>Unchanged</span><strong>{comparison.counts.unchanged}</strong></div>
  </div>

  {#if baselineEvents.length === 0 && currentEvents.length === 0}
    <div class="empty-state">
      <GitCompareArrows size={22} />
      <strong>No evidence to compare</strong>
      <p>Both traces are empty. Capture events before evaluating a regression.</p>
    </div>
  {:else if differences.length === 0}
    <div class="empty-state success">
      <Check size={22} />
      <strong>No meaningful differences</strong>
      <p>Semantic evidence matches; generated IDs and ordering noise are ignored.</p>
    </div>
  {:else}
    <div class="difference-list" aria-label="Meaningful differences">
      <header><span>Evidence changes</span><small>{differences.length} difference{differences.length === 1 ? '' : 's'}</small></header>
      {#each differences as item, index (item.key)}
        {@const event = eventFor(item)}
        <article class="difference" data-status={item.status} data-testid={`comparison-${item.status}-${index}`}>
          <div class="difference-main">
            <div class="status-icon" aria-hidden="true">
              {#if item.status === 'added'}<CirclePlus size={15} />{:else if item.status === 'removed'}<CircleMinus size={15} />{:else}<GitCompareArrows size={15} />{/if}
            </div>
            <div class="event-copy">
              <span><b>{item.status}</b><em>{event.actor_id || 'root'}</em></span>
              <strong>{event.kind}</strong>
              <small>{eventSummary(event)}</small>
            </div>
            {#if item.current}
              <button type="button" onclick={() => onselectCurrent(item.current!)} aria-label={`Inspect current event ${item.current.kind}`}>
                Inspect <ArrowRight size={13} />
              </button>
            {/if}
          </div>

          {#if item.changes.length || item.deltas.durationMs || item.deltas.totalTokens || item.deltas.costUsd}
            <div class="change-detail">
              {#if item.changes.length}
                <div class="fields">
                  {#each item.changes.slice(0, 5) as change (change.field)}
                    <div class="field">
                      <code>{change.field}</code>
                      <span title={value(change.before)}>{value(change.before)}</span>
                      <ArrowRight size={11} />
                      <span title={value(change.after)}>{value(change.after)}</span>
                    </div>
                  {/each}
                  {#if item.changes.length > 5}<small class="more">+{item.changes.length - 5} more field changes</small>{/if}
                </div>
              {/if}
              <div class="delta-list" aria-label="Operational deltas">
                {#if item.deltas.durationMs}<span data-tone={item.deltas.durationMs.delta > 0 ? 'worse' : 'better'}>{durationDelta(item.deltas.durationMs)}</span>{/if}
                {#if item.deltas.totalTokens}<span data-tone={item.deltas.totalTokens.delta > 0 ? 'worse' : 'better'}>{tokenDelta(item.deltas.totalTokens)}</span>{/if}
                {#if item.deltas.costUsd}<span data-tone={item.deltas.costUsd.delta > 0 ? 'worse' : 'better'}>{costDelta(item.deltas.costUsd)}</span>{/if}
              </div>
            </div>
          {/if}
        </article>
      {/each}
    </div>
  {/if}
</section>

<style>
  .comparison { min-width: 0; display: grid; color: #dce5f2; border: 1px solid #253044; border-radius: 10px; background: #0c1119; overflow: hidden; }
  .comparison-head { min-width: 0; display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 42px; padding: 8px 12px; border-bottom: 1px solid #202a3a; background: #101722; }
  .comparison-head > div { display: inline-flex; align-items: center; gap: 7px; color: #a4bcf7; font-size: 11px; font-weight: 760; }
  .comparison-head small { overflow: hidden; color: #77869b; font-size: 9px; text-overflow: ellipsis; white-space: nowrap; }
  .run-pair { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) 32px minmax(0, 1fr); align-items: stretch; border-bottom: 1px solid #202a3a; }
  .run-summary { min-width: 0; display: grid; gap: 5px; padding: 12px 14px; background: #0f151f; }
  .run-summary.current { background: linear-gradient(110deg, rgba(62,100,204,.1), #0f151f 55%); }
  .run-role { color: #708096; font-size: 9px; font-weight: 750; letter-spacing: .07em; text-transform: uppercase; }
  .run-summary > strong { overflow: hidden; color: #edf2f8; font-size: 13px; text-overflow: ellipsis; white-space: nowrap; }
  .direction { display: grid; place-items: center; color: #53647d; border-inline: 1px solid #202a3a; background: #0b1017; }
  .run-metrics { min-width: 0; display: flex; flex-wrap: wrap; align-items: center; gap: 5px 10px; }
  .run-metrics span { color: #9fb5e9; font-size: 9px; font-weight: 750; }
  .run-metrics span[data-tone='success'] { color: #75d8aa; }
  .run-metrics span[data-tone='error'] { color: #ff8b86; }
  .run-metrics span[data-tone='warning'] { color: #efbc70; }
  .run-metrics small { display: inline-flex; align-items: center; gap: 3px; color: #7e8ca0; font-size: 9px; }
  .run-metrics small.issue { color: #ea918d; }
  .counts { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border-bottom: 1px solid #202a3a; }
  .counts > div { min-width: 0; display: flex; align-items: baseline; justify-content: space-between; gap: 6px; padding: 8px 12px; border-left: 1px solid #202a3a; }
  .counts > div:first-child { border-left: 0; }
  .counts span { color: #78879b; font-size: 9px; font-weight: 700; }
  .counts strong { color: #cfd9e8; font-size: 13px; }
  .counts .changed strong { color: #f1be73; }
  .counts .added strong { color: #74d8a8; }
  .counts .removed strong { color: #ff8b86; }
  .empty-state { min-height: 145px; display: grid; place-items: center; align-content: center; gap: 7px; padding: 24px; color: #738299; text-align: center; }
  .empty-state strong { color: #cbd5e4; font-size: 12px; }
  .empty-state p { max-width: 420px; margin: 0; color: #718096; font-size: 10px; line-height: 1.45; }
  .empty-state.success { color: #73d7a7; }
  .difference-list { min-width: 0; }
  .difference-list > header { display: flex; align-items: center; justify-content: space-between; min-height: 34px; padding: 0 12px; color: #c7d2e2; border-bottom: 1px solid #202a3a; background: #0f151f; font-size: 10px; font-weight: 720; }
  .difference-list > header small { color: #748399; font-size: 9px; font-weight: 600; }
  .difference { min-width: 0; border-top: 1px solid rgba(34,44,59,.8); }
  .difference:first-of-type { border-top: 0; }
  .difference-main { min-width: 0; display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 9px; padding: 9px 12px; }
  .status-icon { display: grid; place-items: center; width: 27px; height: 27px; color: #e8b969; border: 1px solid rgba(232,185,105,.25); border-radius: 7px; background: rgba(232,185,105,.07); }
  .difference[data-status='added'] .status-icon { color: #6ed4a2; border-color: rgba(110,212,162,.25); background: rgba(110,212,162,.07); }
  .difference[data-status='removed'] .status-icon { color: #f1837e; border-color: rgba(241,131,126,.25); background: rgba(241,131,126,.07); }
  .event-copy { min-width: 0; display: grid; gap: 1px; }
  .event-copy > span { display: flex; align-items: center; gap: 6px; }
  .event-copy b { color: #d4a95f; font-size: 8px; letter-spacing: .05em; text-transform: uppercase; }
  .difference[data-status='added'] .event-copy b { color: #68c99b; }
  .difference[data-status='removed'] .event-copy b { color: #e47d78; }
  .event-copy em { color: #68788e; font-size: 8px; font-style: normal; }
  .event-copy strong, .event-copy small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .event-copy strong { color: #dce4ef; font-size: 10.5px; }
  .event-copy small { color: #748298; font-size: 9px; }
  button { display: inline-flex; align-items: center; gap: 4px; min-height: 27px; padding: 0 8px; color: #b8caf2; border: 1px solid #30436d; border-radius: 6px; background: #14213c; font: inherit; font-size: 9px; font-weight: 720; cursor: pointer; }
  button:hover { color: #edf3ff; border-color: #5473b8; background: #1b305c; }
  button:focus-visible { outline: 2px solid #7da1ff; outline-offset: 2px; }
  .change-detail { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: end; gap: 10px; padding: 0 12px 10px 48px; }
  .fields { min-width: 0; display: grid; gap: 3px; }
  .field { min-width: 0; display: grid; grid-template-columns: minmax(80px, .7fr) minmax(0, 1fr) auto minmax(0, 1fr); align-items: center; gap: 6px; }
  .field code { overflow: hidden; color: #8394b0; font: 8.5px/1.3 'IBM Plex Mono', monospace; text-overflow: ellipsis; white-space: nowrap; }
  .field span { overflow: hidden; padding: 2px 5px; color: #9aa8bb; border-radius: 4px; background: #121a26; font-size: 8.5px; text-overflow: ellipsis; white-space: nowrap; }
  .field :global(svg) { color: #53637a; }
  .more { color: #68778d; font-size: 8px; }
  .delta-list { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 4px; }
  .delta-list span { padding: 3px 6px; color: #7edbac; border: 1px solid rgba(93,205,154,.25); border-radius: 999px; background: rgba(93,205,154,.07); font-size: 8px; font-weight: 750; white-space: nowrap; }
  .delta-list span[data-tone='worse'] { color: #f1bd70; border-color: rgba(241,189,112,.27); background: rgba(241,189,112,.07); }
  @media (max-width: 700px) {
    .comparison-head { align-items: flex-start; }
    .comparison-head small { white-space: normal; text-align: right; }
    .run-pair { grid-template-columns: minmax(0, 1fr) 24px minmax(0, 1fr); }
    .run-summary { padding: 10px; }
    .run-metrics { display: grid; gap: 3px; }
    .counts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .counts > div:nth-child(3) { border-left: 0; border-top: 1px solid #202a3a; }
    .counts > div:nth-child(4) { border-top: 1px solid #202a3a; }
    .change-detail { grid-template-columns: minmax(0, 1fr); padding-left: 12px; }
    .delta-list { justify-content: flex-start; }
  }
  @media (max-width: 440px) {
    .comparison-head { display: grid; gap: 3px; }
    .comparison-head small { text-align: left; }
    .run-pair { grid-template-columns: 1fr; }
    .direction { min-height: 24px; border: 0; border-block: 1px solid #202a3a; }
    .direction :global(svg) { transform: rotate(90deg); }
    .run-summary > strong { white-space: normal; overflow-wrap: anywhere; }
    .difference-main { grid-template-columns: auto minmax(0, 1fr); }
    .difference-main button { grid-column: 1 / -1; justify-content: center; width: 100%; }
    .field { grid-template-columns: minmax(72px, .7fr) minmax(0, 1fr); }
    .field :global(svg) { display: none; }
    .field span:last-child { grid-column: 2; }
  }
</style>
