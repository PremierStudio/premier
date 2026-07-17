<script lang="ts">
  import { categoryOf, eventSummary } from './analysis';
  import ModelUsage from './ModelUsage.svelte';
  import { modelUsage } from './modelUsage';
  import type { EventCategory, TraceEvent } from './types';

  let { events, selectedEventId = null, live = false, filtered = false, onreset = () => undefined, onselect }: {
    events: TraceEvent[];
    selectedEventId?: string | null;
    live?: boolean;
    filtered?: boolean;
    onreset?: () => void;
    onselect: (event: TraceEvent) => void;
  } = $props();

  type AnalyticsCategory = Exclude<EventCategory, 'all'>;
  type Point = { x: number; y: number; count: number; event: TraceEvent; start: number; end: number };

  const categories: AnalyticsCategory[] = ['agent', 'model', 'tool', 'approval', 'process', 'error'];
  const categoryLabels: Record<AnalyticsCategory, string> = {
    agent: 'Agent', model: 'Model', tool: 'Tool', approval: 'Approval', process: 'Process', error: 'Issue'
  };
  const categoryColors: Record<AnalyticsCategory, string> = {
    agent: 'var(--blue-strong, #9eaaff)', model: 'var(--purple, #c59aff)', tool: 'var(--amber, #f5bc68)',
    approval: 'var(--cyan, #66d8d5)', process: 'var(--green, #63dca5)', error: 'var(--red, #ff7c78)'
  };

  const left = 42;
  const right = 706;
  const top = 24;
  const bottom = 178;

  function timestamp(event: TraceEvent): number {
    const parsed = Date.parse(event.timestamp);
    return Number.isFinite(parsed) ? parsed : event.sequence;
  }

  function issue(event: TraceEvent): boolean {
    return categoryOf(event) === 'error';
  }

  function formatDuration(ms: number): string {
    if (ms < 1) return '<1 ms';
    if (ms < 1_000) return `${Math.round(ms)} ms`;
    if (ms < 60_000) return `${(ms / 1_000).toFixed(ms < 10_000 ? 1 : 0)} s`;
    return `${(ms / 60_000).toFixed(1)} min`;
  }

  function relativeTime(ms: number, start: number): string {
    const elapsed = Math.max(0, ms - start);
    return elapsed === 0 ? 'start' : `+${formatDuration(elapsed)}`;
  }

  function selectFromKeyboard(event: KeyboardEvent, traceEvent: TraceEvent): void {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onselect(traceEvent);
    }
  }

  function percentile(values: number[], value: number): number | null {
    if (!values.length) return null;
    const index = Math.min(values.length - 1, Math.ceil(value * values.length) - 1);
    return values[index];
  }

  const analytics = $derived.by(() => {
    const ordered = [...events].sort((a, b) => timestamp(a) - timestamp(b) || a.sequence - b.sequence);
    if (!ordered.length) return null;

    const start = timestamp(ordered[0]);
    const rawEnd = Math.max(...ordered.map((event) => timestamp(event) + Math.max(0, event.duration_ms || 0)));
    const end = Math.max(start, rawEnd);
    const span = Math.max(1, end - start);
    const binCount = ordered.length === 1 ? 1 : Math.min(24, Math.max(8, Math.ceil(Math.sqrt(ordered.length) * 2)));
    const bins: TraceEvent[][] = Array.from({ length: binCount }, () => []);
    for (const event of ordered) {
      const index = binCount === 1 ? 0 : Math.min(binCount - 1, Math.floor(((timestamp(event) - start) / span) * binCount));
      bins[index].push(event);
    }
    const maxCount = Math.max(1, ...bins.map((bin) => bin.length));
    const binWidth = span / binCount;
    const points: Point[] = bins.map((bin, index) => {
      const representative = bin.find(issue) ?? [...bin].sort((a, b) => b.duration_ms - a.duration_ms)[0] ?? ordered[Math.min(index, ordered.length - 1)];
      return {
        x: binCount === 1 ? (left + right) / 2 : left + (index / (binCount - 1)) * (right - left),
        y: bottom - (bin.length / maxCount) * (bottom - top),
        count: bin.length,
        event: representative,
        start: start + index * binWidth,
        end: start + (index + 1) * binWidth
      };
    });
    const line = points.map((point, index) => `${index ? 'L' : 'M'} ${point.x} ${point.y}`).join(' ');
    const area = points.length === 1
      ? `M ${points[0].x - 16} ${bottom} L ${points[0].x - 16} ${points[0].y} L ${points[0].x + 16} ${points[0].y} L ${points[0].x + 16} ${bottom} Z`
      : `M ${points[0].x} ${bottom} ${line.replace(/^M/, 'L')} L ${points[points.length - 1].x} ${bottom} Z`;

    const mixCounts = categories.map((category) => ({
      category,
      count: ordered.filter((event) => categoryOf(event) === category).length
    })).filter((item) => item.count > 0);
    let mixOffset = 0;
    const mix = mixCounts.map((item) => {
      const offset = mixOffset / ordered.length * 100;
      mixOffset += item.count;
      return { ...item, offset };
    });
    const latency = categories.map((category) => {
      const categoryEvents = ordered.filter((event) => categoryOf(event) === category);
      return {
        category,
        total: categoryEvents.reduce((sum, event) => sum + Math.max(0, event.duration_ms || 0), 0),
        slowest: [...categoryEvents].sort((a, b) => b.duration_ms - a.duration_ms)[0]
      };
    }).filter((item) => item.total > 0).sort((a, b) => b.total - a.total);
    const maxLatency = Math.max(1, ...latency.map((item) => item.total));
    const issues = ordered.filter(issue);
    const durations = ordered.map((event) => Math.max(0, event.duration_ms || 0)).filter(Boolean).sort((a, b) => a - b);
    const p50 = percentile(durations, .5);
    const p95 = percentile(durations, .95);
    const p99 = percentile(durations, .99);
    const usage = modelUsage(ordered);
    const modelCalls = usage.calls.length;
    const tokensCaptured = usage.rollups.some((row) => row.hasTotal);
    const costCaptured = usage.rollups.some((row) => row.hasCost);
    const tokens = usage.rollups.reduce((sum, row) => sum + row.total, 0);
    const cost = usage.rollups.reduce((sum, row) => sum + row.costUsd, 0);
    const peak = [...points].sort((a, b) => b.count - a.count)[0];
    const dominantLatency = latency[0] ?? null;
    const issueWindows = issues.map((event) => ({
      event,
      x: left + ((timestamp(event) - start) / span) * (right - left)
    }));
    return { ordered, start, end, span, points, line, area, mix, latency, maxLatency, issues, peak, dominantLatency, issueWindows, binWidth, p50, p95, p99, tokens, cost, tokensCaptured, costCaptured, modelCalls };
  });
</script>

<section class="analytics" aria-labelledby="analytics-title">
  <header>
    <div>
      <span class="eyebrow">Visual trace analysis</span>
      <h2 id="analytics-title">Run pulse</h2>
    </div>
    {#if live}<span class="live"><i aria-hidden="true"></i>Live</span>{/if}
  </header>

  {#if !analytics}
    <div class="empty" role="status">
      <svg viewBox="0 0 48 32" aria-hidden="true"><path d="M2 23h8l5-13 7 19 6-14 5 8h13" /></svg>
      <strong>{filtered ? 'No evidence in the current scope' : 'Waiting for trace activity'}</strong>
      <span>{filtered ? 'The run contains evidence, but the selected time range or filters exclude it.' : 'The activity curve, issue windows, latency, and event mix will appear as evidence arrives.'}</span>
      {#if filtered}<button onclick={onreset}>Reset scope</button>{/if}
    </div>
  {:else}
    <div class="signal-summary" aria-label="Trace analytics summary">
      <div>
        <span>Peak activity</span>
        <strong>{analytics.peak.count} event{analytics.peak.count === 1 ? '' : 's'}</strong>
        <small>{relativeTime(analytics.peak.start, analytics.start)} · {formatDuration(analytics.binWidth)} window</small>
      </div>
      <div class:attention={analytics.issues.length > 0}>
        <span>Issue rate</span>
        <strong>{analytics.issues.length ? `${Math.round(analytics.issues.length / analytics.ordered.length * 100)}%` : '0%'}</strong>
        <small>{analytics.issues.length ? `${analytics.issues.length} issue events · first ${relativeTime(timestamp(analytics.issues[0]), analytics.start)}` : 'No failed or blocked events'}</small>
      </div>
      <div>
        <span>Event latency p95</span>
        <strong>{analytics.p95 !== null ? formatDuration(analytics.p95) : 'Not recorded'}</strong>
        <small>{analytics.p50 !== null && analytics.p99 !== null ? `p50 ${formatDuration(analytics.p50)} · p99 ${formatDuration(analytics.p99)}` : 'Events reported no duration'}</small>
      </div>
      <div>
        <span>Model usage</span>
        {#if analytics.modelCalls > 0}
          <strong>{analytics.tokensCaptured ? `${analytics.tokens.toLocaleString()} tokens` : `${analytics.modelCalls} call${analytics.modelCalls === 1 ? '' : 's'}`}</strong>
          <small>{analytics.costCaptured ? `$${analytics.cost.toFixed(4)} recorded cost` : 'Usage ledger below'}</small>
        {:else}
          <strong>None in scope</strong>
          <small>No model.* events with provider usage</small>
        {/if}
      </div>
    </div>

    {#if analytics.modelCalls > 0}
      <ModelUsage {events} {selectedEventId} {onselect} />
    {/if}

    <div class="analytics-grid">
      <article class="activity-card">
        <div class="card-heading">
          <div><h3>Activity over time</h3><p>Density by time window; issue markers sit below the curve.</p></div>
          <span>{formatDuration(analytics.span)} total</span>
        </div>
        <div class="chart-wrap">
          <svg class="activity-chart" viewBox="0 0 748 224" preserveAspectRatio="none" aria-label="Trace activity over time">
            <defs>
              <linearGradient id="pulse-fill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0" stop-color="var(--blue-strong, #9eaaff)" stop-opacity=".34" />
                <stop offset="1" stop-color="var(--blue, #6f7bf7)" stop-opacity=".015" />
              </linearGradient>
            </defs>
            <g class="grid" aria-hidden="true">
              <line x1={left} y1="24" x2={right} y2="24" /><line x1={left} y1="101" x2={right} y2="101" /><line x1={left} y1={bottom} x2={right} y2={bottom} />
            </g>
            <path class="area" d={analytics.area} />
            {#if analytics.points.length > 1}<path class="curve" d={analytics.line} />{/if}
            {#each analytics.points as point, index (`point-${index}`)}
              {#if point.count > 0}
                <circle
                  class="point"
                  class:selected={point.event.event_id === selectedEventId}
                  cx={point.x} cy={point.y} r={point.event.event_id === selectedEventId ? 6 : 4}
                  tabindex="0" role="button"
                  aria-label={`${point.count} event${point.count === 1 ? '' : 's'} at ${relativeTime(point.start, analytics.start)}. Open ${eventSummary(point.event)}`}
                  onclick={() => onselect(point.event)}
                  onkeydown={(event) => selectFromKeyboard(event, point.event)}
                ><title>{point.count} event{point.count === 1 ? '' : 's'} · {relativeTime(point.start, analytics.start)}</title></circle>
              {/if}
            {/each}
            <g class="issues">
              <line x1={left} y1="202" x2={right} y2="202" />
              {#each analytics.issueWindows as marker (marker.event.event_id)}
                <circle
                  class:selected={marker.event.event_id === selectedEventId}
                  cx={marker.x} cy="202" r="5" tabindex="0" role="button"
                  aria-label={`Issue at ${relativeTime(timestamp(marker.event), analytics.start)}. Open ${eventSummary(marker.event)}`}
                  onclick={() => onselect(marker.event)}
                  onkeydown={(event) => selectFromKeyboard(event, marker.event)}
                ><title>{eventSummary(marker.event)}</title></circle>
              {/each}
            </g>
          </svg>
          <div class="axis" aria-hidden="true"><span>Start</span><span>{formatDuration(analytics.span / 2)}</span><span>{formatDuration(analytics.span)}</span></div>
        </div>
        <div class="chart-legend"><span><i class="pulse-key"></i>Event density</span><span><i class="issue-key"></i>Issue event</span><small>Choose a point to inspect evidence</small></div>
      </article>

      <div class="breakdowns">
        <article class="latency-card">
          <div class="card-heading"><div><h3>Latency by category</h3><p>Cumulative recorded duration.</p></div></div>
          {#if analytics.latency.length}
            <div class="latency-list">
              {#each analytics.latency as item (item.category)}
                <button onclick={() => item.slowest && onselect(item.slowest)} disabled={!item.slowest} aria-label={`Inspect slowest ${categoryLabels[item.category]} event`}>
                  <span class="bar-label"><span><i style={`--category:${categoryColors[item.category]}`}></i>{categoryLabels[item.category]}</span><strong>{formatDuration(item.total)}</strong></span>
                  <span class="bar-track"><i style={`--width:${(item.total / analytics.maxLatency) * 100}%;--category:${categoryColors[item.category]}`}></i></span>
                </button>
              {/each}
            </div>
          {:else}<p class="no-data">No event durations were recorded.</p>{/if}
        </article>

        <article class="mix-card">
          <div class="card-heading"><div><h3>Event mix</h3><p>What the run spent its steps doing.</p></div></div>
          <div class="mix-layout">
            <div class="donut" style={`--total:${analytics.ordered.length}`} aria-hidden="true">
              <svg viewBox="0 0 42 42">
                <circle class="donut-track" cx="21" cy="21" r="15.9" />
                {#each analytics.mix as item (item.category)}
                  <circle cx="21" cy="21" r="15.9" pathLength="100" stroke={categoryColors[item.category]}
                    stroke-dasharray={`${item.count / analytics.ordered.length * 100} ${100 - item.count / analytics.ordered.length * 100}`}
                    stroke-dashoffset={-item.offset} />
                {/each}
              </svg>
              <span><strong>{analytics.ordered.length}</strong><small>events</small></span>
            </div>
            <ul aria-label="Event category distribution">
              {#each analytics.mix as item (item.category)}
                <li><span><i style={`--category:${categoryColors[item.category]}`}></i>{categoryLabels[item.category]}</span><strong>{Math.round(item.count / analytics.ordered.length * 100)}%</strong><small>{item.count}</small></li>
              {/each}
            </ul>
          </div>
        </article>
      </div>
    </div>
  {/if}
</section>

<style>
  .analytics { min-width: 0; height: 100%; min-height: 100%; display: flex; flex-direction: column; container-type: inline-size; color: var(--text, #f5f7fa); background: var(--surface, #050505); }
  header { min-height: 58px; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 12px 16px; border-bottom: 1px solid var(--line, rgba(255,255,255,.09)); }
  .eyebrow { display: block; color: var(--blue-strong, #9eaaff); font-size: 9px; font-weight: 750; letter-spacing: .13em; text-transform: uppercase; }
  h2, h3, p { margin: 0; }
  h2 { margin-top: 2px; font-size: 16px; font-weight: 720; letter-spacing: -.015em; }
  .live { display: flex; align-items: center; gap: 7px; color: #9ce5c3; font-size: 10px; font-weight: 750; letter-spacing: .09em; text-transform: uppercase; }
  .live i { width: 7px; height: 7px; border-radius: 50%; background: var(--green, #63dca5); box-shadow: 0 0 0 4px rgba(99,220,165,.09), 0 0 14px rgba(99,220,165,.46); animation: breathe 1.8s ease-in-out infinite; }
  .empty { min-height: 292px; flex: 1 1 auto; display: grid; place-content: center; justify-items: center; gap: 7px; padding: 36px; color: var(--muted, #8a9ab0); text-align: center; background: radial-gradient(circle at 50% 45%, rgba(111,123,247,.09), transparent 32%); }
  .empty svg { width: 48px; fill: none; stroke: var(--blue-strong, #9eaaff); stroke-width: 1.7; filter: drop-shadow(0 0 10px rgba(111,123,247,.3)); }
  .empty strong { margin-top: 5px; color: var(--text-secondary, #c8d1de); font-size: 14px; }
  .empty span { max-width: 390px; font-size: 12px; line-height: 1.55; }
  .empty button { min-height: 36px; margin-top: 5px; padding: 0 12px; border: 1px solid #5274d8; border-radius: 6px; color: white; background: #6f7bf7; cursor: pointer; }
  .signal-summary { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border-bottom: 1px solid var(--line, rgba(255,255,255,.09)); background: rgba(255,255,255,.012); }
  .signal-summary > div { min-width: 0; display: grid; gap: 3px; padding: 12px 16px; border-right: 1px solid var(--line-soft, rgba(255,255,255,.055)); }
  .signal-summary > div:last-child { border-right: 0; }
  .signal-summary span { color: var(--muted, #8a9ab0); font-size: 9px; font-weight: 750; letter-spacing: .1em; text-transform: uppercase; }
  .signal-summary strong { color: var(--text, #f5f7fa); font-size: 14px; font-weight: 700; }
  .signal-summary small { overflow-wrap: anywhere; color: var(--muted, #8a9ab0); font-size: 10px; }
  .signal-summary .attention strong { color: var(--red, #ff7c78); }
  .analytics-grid { min-width: 0; min-height: 240px; flex: 1 0 240px; display: grid; grid-template-columns: minmax(360px, 1.65fr) minmax(228px, .85fr); align-items: stretch; gap: 1px; background: var(--line, rgba(255,255,255,.09)); }
  article { min-width: 0; background: linear-gradient(145deg, rgba(255,255,255,.018), transparent 48%), rgba(11,14,19,.92); backdrop-filter: blur(16px); }
  .activity-card { min-height: 0; display: grid; grid-template-rows: auto minmax(136px, 1fr) auto; padding-bottom: 12px; }
  .card-heading { min-height: 58px; display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; padding: 13px 16px 8px; }
  .card-heading h3 { color: var(--text-secondary, #c8d1de); font-size: 12px; font-weight: 720; }
  .card-heading p { margin-top: 3px; color: var(--muted, #8a9ab0); font-size: 10px; line-height: 1.4; }
  .card-heading > span { color: var(--muted-strong, #a6b3c4); font: 10px 'IBM Plex Mono', monospace; white-space: nowrap; }
  .chart-wrap { min-width: 0; min-height: 0; display: grid; grid-template-rows: minmax(0, 1fr) auto; padding: 0 12px; }
  .activity-chart { display: block; width: 100%; height: 100%; min-height: 136px; overflow: visible; }
  .grid line { stroke: rgba(255,255,255,.055); stroke-width: 1; vector-effect: non-scaling-stroke; stroke-dasharray: 2 6; }
  .area { fill: url(#pulse-fill); }
  .curve { fill: none; stroke: var(--blue-strong, #9eaaff); stroke-width: 2; vector-effect: non-scaling-stroke; filter: drop-shadow(0 0 5px rgba(158,170,255,.35)); }
  .point { fill: var(--panel, #0b0e13); stroke: #90adff; stroke-width: 2; vector-effect: non-scaling-stroke; cursor: pointer; transition: r .12s ease, fill .12s ease; }
  .point:hover, .point:focus, .point.selected { fill: var(--blue-strong, #9eaaff); outline: none; }
  .point:focus-visible, .issues circle:focus-visible { stroke: white; stroke-width: 3; }
  .issues line { stroke: rgba(255,124,120,.25); stroke-width: 1; vector-effect: non-scaling-stroke; }
  .issues circle { fill: var(--red, #ff7c78); stroke: #ffc0bd; stroke-width: 1; vector-effect: non-scaling-stroke; cursor: pointer; }
  .issues circle.selected { stroke: white; stroke-width: 3; }
  .axis { display: flex; justify-content: space-between; margin: -2px 3.5% 0 4%; color: var(--muted, #8a9ab0); font: 9px 'IBM Plex Mono', monospace; }
  .chart-legend { display: flex; align-items: center; gap: 14px; padding: 10px 16px 0; color: var(--muted-strong, #a6b3c4); font-size: 10px; }
  .chart-legend span { display: flex; align-items: center; gap: 6px; }
  .chart-legend i { display: block; width: 14px; height: 3px; border-radius: 3px; }
  .pulse-key { background: var(--blue-strong, #9eaaff); box-shadow: 0 0 7px rgba(158,170,255,.35); }
  .chart-legend .issue-key { width: 6px; height: 6px; border-radius: 50%; background: var(--red, #ff7c78); }
  .chart-legend small { margin-left: auto; color: var(--muted, #8a9ab0); }
  .breakdowns { min-width: 0; min-height: 0; display: grid; grid-template-rows: minmax(90px, .62fr) minmax(149px, 1.38fr); gap: 1px; background: var(--line, rgba(255,255,255,.09)); }
  .latency-card, .mix-card { min-width: 0; min-height: 0; display: flex; flex-direction: column; }
  .latency-list { display: grid; align-content: center; gap: 4px; flex: 1 1 auto; padding: 0 16px 15px; }
  .latency-list button { min-width: 0; display: grid; gap: 5px; padding: 4px 0; border: 0; color: inherit; text-align: left; background: transparent; cursor: pointer; }
  .latency-list button:hover .bar-track, .latency-list button:focus-visible .bar-track { background: rgba(255,255,255,.09); }
  .latency-list button:focus-visible { outline: 2px solid var(--focus, #aab4ff); outline-offset: 3px; }
  .bar-label { min-width: 0; display: flex; align-items: center; justify-content: space-between; gap: 10px; color: var(--muted-strong, #a6b3c4); font-size: 10px; }
  .bar-label > span { display: flex; align-items: center; gap: 7px; }
  .bar-label i, .mix-layout li i { width: 6px; height: 6px; border-radius: 2px; background: var(--category); box-shadow: 0 0 8px color-mix(in srgb, var(--category) 40%, transparent); }
  .bar-label strong { color: var(--text-secondary, #c8d1de); font: 9px 'IBM Plex Mono', monospace; }
  .bar-track { height: 5px; overflow: hidden; border-radius: 5px; background: rgba(255,255,255,.055); transition: background .12s ease; }
  .bar-track i { display: block; width: var(--width); height: 100%; border-radius: inherit; background: linear-gradient(90deg, color-mix(in srgb, var(--category) 65%, transparent), var(--category)); box-shadow: 0 0 9px color-mix(in srgb, var(--category) 25%, transparent); transition: width .28s ease; }
  .no-data { flex: 1 1 auto; display: grid; align-content: center; padding: 4px 16px 18px; color: var(--muted, #8a9ab0); font-size: 11px; }
  .mix-layout { min-width: 0; min-height: 0; flex: 1 1 auto; display: grid; grid-template-columns: 112px minmax(0, 1fr); align-items: center; gap: 10px; padding: 0 16px 16px; }
  .donut { position: relative; width: 106px; height: 106px; }
  .donut svg { width: 100%; height: 100%; transform: rotate(-90deg); filter: drop-shadow(0 10px 18px rgba(0,0,0,.28)); }
  .donut circle { fill: none; stroke-width: 4.2; }
  .donut .donut-track { stroke: rgba(255,255,255,.055); }
  .donut > span { position: absolute; inset: 0; display: grid; place-content: center; text-align: center; }
  .donut strong { font-size: 18px; line-height: 1; }
  .donut small { margin-top: 4px; color: var(--muted, #8a9ab0); font-size: 9px; letter-spacing: .08em; text-transform: uppercase; }
  .mix-layout ul { min-width: 0; display: grid; gap: 6px; margin: 0; padding: 0; list-style: none; }
  .mix-layout li { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto 25px; align-items: center; gap: 7px; color: var(--muted-strong, #a6b3c4); font-size: 10px; }
  .mix-layout li > span { min-width: 0; display: flex; align-items: center; gap: 7px; }
  .mix-layout li strong { color: var(--text-secondary, #c8d1de); font-size: 10px; }
  .mix-layout li small { color: var(--muted, #8a9ab0); font: 9px 'IBM Plex Mono', monospace; text-align: right; }
  @keyframes breathe { 50% { opacity: .55; transform: scale(.82); } }
  @container (max-width: 680px) {
    .signal-summary > div { padding: 9px 12px; }
    .mix-layout { grid-template-columns: 82px minmax(0, 1fr); gap: 7px; padding-inline: 12px; }
    .donut { width: 76px; height: 76px; }
    .mix-layout li { gap: 4px; }
  }
  @container (max-width: 600px) {
    .analytics { height: auto; min-height: 100%; }
    .signal-summary { grid-template-columns: 1fr 1fr; }
    .signal-summary > div { border-bottom: 1px solid var(--line-soft, rgba(255,255,255,.055)); }
    .signal-summary > div:last-child { grid-column: 1 / -1; border-bottom: 0; }
    .analytics-grid { min-height: 0; flex: 0 0 auto; }
    .analytics-grid, .breakdowns { grid-template-columns: 1fr; }
    .breakdowns { grid-template-rows: minmax(140px, auto) minmax(210px, auto); }
    .activity-card { min-height: 318px; grid-template-rows: auto minmax(178px, 1fr) auto; }
    .activity-chart { min-height: 178px; }
    .chart-legend { flex-wrap: wrap; }
    .chart-legend small { width: 100%; margin-left: 0; }
  }
  @media (prefers-reduced-motion: reduce) { .live i { animation: none; } }
</style>
