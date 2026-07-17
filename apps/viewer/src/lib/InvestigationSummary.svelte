<script lang="ts">
  import { ArrowRight, ChevronDown, CircleAlert, CircleDollarSign, Gauge, Route, Search, ShieldAlert } from '@lucide/svelte';
  import { buildInvestigationSummary } from './investigation';
  import type { TraceEvent, TraceManifest } from './types';

  let { trace, events, onselect = () => undefined }: {
    trace: TraceManifest;
    events: TraceEvent[];
    onselect?: (event: TraceEvent) => void;
  } = $props();

  let summary = $derived(buildInvestigationSummary(trace, events));
  let expanded = $state(false);

  function duration(value: number | null): string | null {
    if (value === null) return null;
    if (value < 1_000) return `${Math.round(value)} ms`;
    if (value < 60_000) return `${(value / 1_000).toFixed(value < 10_000 ? 1 : 0)} s`;
    return `${(value / 60_000).toFixed(1)} min`;
  }

  function cost(value: number | null): string | null {
    if (value === null) return null;
    return value < 0.01 ? `$${value.toFixed(4)}` : `$${value.toFixed(2)}`;
  }

  function tokens(value: number | null): string | null {
    if (value === null) return null;
    return value >= 1_000 ? `${(value / 1_000).toFixed(value >= 10_000 ? 0 : 1)}k tok` : `${value} tok`;
  }
</script>

<section class="investigation" aria-label="Investigation summary" data-expanded={expanded}>
  <header class="summary-head">
    <div class="eyebrow"><Search size={13} strokeWidth={2.2} /> Investigation</div>
    <div class="outcome" data-tone={summary.outcome.tone}>
      <span>{summary.outcome.label}</span>
      <small>{summary.outcome.detail}</small>
    </div>
    <button
      class="details-toggle"
      type="button"
      aria-expanded={expanded}
      aria-label={`${expanded ? 'Hide' : 'Show'} investigation details`}
      onclick={() => expanded = !expanded}
    >
      Details <ChevronDown size={13} />
    </button>
  </header>

  <div class="cause-row">
    <div class="cause-mark" data-confidence={summary.cause.confidence}><CircleAlert size={18} /></div>
    <div class="cause-copy">
      <span>Likely cause <em>{summary.cause.confidence} confidence</em></span>
      <strong>{summary.cause.title}</strong>
      <p>{summary.cause.detail}</p>
    </div>
    {#if summary.recommendedEvent}
      <button class="next" type="button" onclick={() => onselect(summary.recommendedEvent!.event)} aria-label="Inspect recommended event">
        Inspect evidence <ArrowRight size={14} />
      </button>
    {/if}
  </div>

  <div class="evidence-grid">
    <section class="evidence-section chain" aria-labelledby="failure-chain-title">
      <header><Route size={14} /><h3 id="failure-chain-title">{summary.chainKind === 'failure' ? 'Failure chain' : 'Critical path'}</h3><span>{summary.failureChain.length}</span></header>
      {#if summary.failureChain.length}
        <ol>
          {#each summary.failureChain as item (item.event.event_id)}
            <li data-relation={item.relation}>
              <button type="button" onclick={() => onselect(item.event)} title={item.summary}>
                <i>{item.rank}</i>
                <span><strong>{item.event.kind}</strong><small>{item.summary}</small></span>
              </button>
            </li>
          {/each}
        </ol>
      {:else}
        <p class="empty">No causal chain was recorded.</p>
      {/if}
    </section>

    <section class="evidence-section" aria-labelledby="hotspots-title">
      <header><Gauge size={14} /><h3 id="hotspots-title">Slow &amp; expensive</h3><span>{summary.hotspots.length}</span></header>
      {#if summary.hotspots.length}
        <ol class="hotspots">
          {#each summary.hotspots as item (item.event.event_id)}
            <li>
              <button type="button" onclick={() => onselect(item.event)} title={item.label}>
                <i>{item.rank}</i>
                <span><strong>{item.event.kind}</strong><small>{item.label}</small></span>
                <div class="metrics">
                  {#if duration(item.durationMs)}<b>{duration(item.durationMs)}</b>{/if}
                  {#if cost(item.costUsd)}<b><CircleDollarSign size={10} />{cost(item.costUsd)}</b>{/if}
                  {#if tokens(item.totalTokens)}<b>{tokens(item.totalTokens)}</b>{/if}
                </div>
              </button>
            </li>
          {/each}
        </ol>
      {:else}
        <p class="empty">No latency, cost, or token evidence was captured.</p>
      {/if}
    </section>

    <section class="evidence-section gaps" aria-labelledby="gaps-title">
      <header><ShieldAlert size={14} /><h3 id="gaps-title">Missing evidence</h3><span>{summary.gaps.length}</span></header>
      {#if summary.gaps.length}
        <ul>
          {#each summary.gaps as gap (gap.id)}
            <li data-severity={gap.severity}>
              <i></i><span><strong>{gap.label}</strong><small>{gap.detail}</small></span>
            </li>
          {/each}
        </ul>
      {:else}
        <div class="complete"><span>Evidence coverage looks complete</span><small>No obvious instrumentation gaps were detected.</small></div>
      {/if}
    </section>
  </div>
</section>

<style>
  .investigation { min-width: 0; display: grid; gap: 0; color: #dce5f2; background: #0d121a; border: 1px solid #253044; border-radius: 10px; overflow: hidden; }
  .summary-head { min-width: 0; display: flex; align-items: center; justify-content: space-between; gap: 16px; min-height: 42px; padding: 8px 12px; border-bottom: 1px solid #202a3a; background: #101722; }
  .eyebrow { display: inline-flex; align-items: center; gap: 7px; color: #9db9ff; font-size: 11px; font-weight: 760; letter-spacing: .02em; }
  .outcome { min-width: 0; display: flex; align-items: baseline; justify-content: flex-end; gap: 8px; color: #f0f5fb; }
  .outcome span { font-size: 11px; font-weight: 760; }
  .outcome small { min-width: 0; overflow: hidden; color: #7f8da2; font-size: 10px; text-overflow: ellipsis; white-space: nowrap; }
  .outcome[data-tone='error'] span { color: #ff8d88; }
  .outcome[data-tone='warning'] span { color: #f0be72; }
  .outcome[data-tone='success'] span { color: #72dbaa; }
  .outcome[data-tone='running'] span { color: #7da1ff; }
  .details-toggle { display: inline-flex; align-items: center; gap: 4px; min-height: 28px; padding: 0 8px; color: #aebbd0; border: 1px solid #2d394c; border-radius: 7px; background: #141c28; font-size: 9px; font-weight: 720; cursor: pointer; }
  .details-toggle :global(svg) { transition: transform .16s ease; }
  .investigation[data-expanded='true'] .details-toggle :global(svg) { transform: rotate(180deg); }
  .cause-row { min-width: 0; display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: center; gap: 10px; padding: 12px; border-bottom: 1px solid #202a3a; background: linear-gradient(100deg, rgba(71,111,222,.1), transparent 45%); }
  .cause-mark { display: grid; place-items: center; width: 34px; height: 34px; color: #f0be72; border: 1px solid rgba(240,190,114,.25); border-radius: 9px; background: rgba(240,190,114,.08); }
  .cause-mark[data-confidence='high'] { color: #ff8d88; border-color: rgba(255,141,136,.26); background: rgba(255,141,136,.08); }
  .cause-copy { min-width: 0; display: grid; gap: 2px; }
  .cause-copy > span { color: #8998ad; font-size: 10px; font-weight: 700; }
  .cause-copy em { margin-left: 5px; color: #65748a; font-size: 9px; font-style: normal; font-weight: 600; }
  .cause-copy strong { overflow: hidden; color: #f2f6fb; font-size: 13px; text-overflow: ellipsis; white-space: nowrap; }
  .cause-copy p { margin: 0; overflow: hidden; color: #9ba8bb; font-size: 10.5px; line-height: 1.35; text-overflow: ellipsis; white-space: nowrap; }
  button { font: inherit; }
  .next { display: inline-flex; align-items: center; gap: 6px; min-height: 30px; padding: 0 10px; color: #e8efff; border: 1px solid #3c5caa; border-radius: 7px; background: #1c3674; font-size: 10px; font-weight: 750; cursor: pointer; }
  .next:hover { border-color: #6f94f3; background: #254690; }
  .next:focus-visible, li button:focus-visible { outline: 2px solid #7ea2ff; outline-offset: -2px; }
  .evidence-grid { min-width: 0; display: none; grid-template-columns: repeat(3, minmax(0, 1fr)); max-height: min(44dvh, 360px); overflow: auto; }
  .investigation[data-expanded='true'] .evidence-grid { display: grid; }
  .evidence-section { min-width: 0; border-left: 1px solid #202a3a; }
  .evidence-section:first-child { border-left: 0; }
  .evidence-section > header { display: flex; align-items: center; gap: 7px; min-height: 36px; padding: 0 10px; color: #8298c6; border-bottom: 1px solid #202a3a; }
  .evidence-section h3 { flex: 1; margin: 0; color: #cbd5e4; font-size: 10.5px; font-weight: 760; }
  .evidence-section header > span { display: grid; place-items: center; min-width: 19px; height: 18px; padding: 0 5px; color: #8e9caf; border: 1px solid #2a3547; border-radius: 9px; background: #141c28; font-size: 9px; }
  ol, ul { margin: 0; padding: 0; list-style: none; }
  li { min-width: 0; border-top: 1px solid rgba(33,43,58,.72); }
  li:first-child { border-top: 0; }
  li button { width: 100%; min-width: 0; display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: center; gap: 8px; padding: 8px 10px; color: inherit; border: 0; background: transparent; text-align: left; cursor: pointer; }
  li button:hover { background: rgba(87,124,216,.09); }
  li i { display: grid; place-items: center; width: 18px; height: 18px; color: #7f91aa; border: 1px solid #2d394c; border-radius: 50%; font-size: 8px; font-style: normal; font-weight: 750; }
  li[data-relation='cause'] i { color: #ff9a95; border-color: rgba(255,122,117,.45); background: rgba(255,122,117,.1); }
  li span { min-width: 0; display: grid; gap: 2px; }
  li strong, li small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  li strong { color: #d9e2ee; font-size: 10px; font-weight: 700; }
  li small { color: #738198; font-size: 9px; }
  .hotspots button { grid-template-columns: auto minmax(0, 1fr) auto; }
  .metrics { display: flex; flex-direction: column; align-items: flex-end; gap: 2px; }
  .metrics b { display: inline-flex; align-items: center; gap: 2px; color: #9eadd0; font-size: 8px; font-weight: 700; white-space: nowrap; }
  .gaps li { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: start; gap: 8px; padding: 8px 10px; }
  .gaps li > i { width: 6px; height: 6px; margin-top: 4px; border: 0; background: #71829b; }
  .gaps li[data-severity='high'] > i { background: #ff817c; box-shadow: 0 0 0 3px rgba(255,129,124,.1); }
  .gaps li[data-severity='medium'] > i { background: #efba6c; }
  .empty, .complete { margin: 0; padding: 14px 10px; color: #718096; font-size: 10px; line-height: 1.45; }
  .complete { display: grid; gap: 3px; }
  .complete span { color: #79d7aa; font-weight: 700; }
  .complete small { color: #738198; font-size: 9px; }
  @media (max-width: 860px) {
    .evidence-grid { grid-template-columns: 1fr; }
    .evidence-section { border-left: 0; border-top: 1px solid #202a3a; }
    .cause-copy p, .outcome small { white-space: normal; }
  }
  @media (max-width: 680px) {
    .summary-head { min-height: 38px; gap: 8px; padding: 5px 8px; }
    .outcome small { display: none; }
    .cause-row { grid-template-columns: minmax(0, 1fr) auto; min-height: 44px; gap: 8px; padding: 6px 8px; }
    .cause-mark, .cause-copy p { display: none; }
    .cause-copy strong { font-size: 11px; }
    .next { min-height: 28px; }
    .evidence-grid { max-height: min(44dvh, 320px); }
  }
  @media (max-width: 540px) {
    .eyebrow { font-size: 10px; }
    .outcome { display: none; }
    .details-toggle { margin-left: auto; }
    .cause-copy strong { white-space: nowrap; }
  }
</style>
