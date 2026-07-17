<script lang="ts">
  import type { TraceEvent, TraceManifest } from './types';
  import { actorInventory, countByCategory, runHealth } from './analysis';

  let { trace, events, compact = false }: {
    trace: TraceManifest;
    events: TraceEvent[];
    /** Inline chips for the app bar next to the run title. */
    compact?: boolean;
  } = $props();

  let inventory = $derived(actorInventory(events));
  let health = $derived(runHealth(trace, events));
  let errors = $derived(countByCategory(events, 'error'));
  let tools = $derived(countByCategory(events, 'tool'));
  let models = $derived(countByCategory(events, 'model'));
  let participants = $derived(inventory.agents + inventory.subagents + inventory.humans + inventory.processes + inventory.systems);
  let participantDetail = $derived(
    `${inventory.agents} coordinator${inventory.agents === 1 ? '' : 's'} · ${inventory.subagents} delegate${inventory.subagents === 1 ? '' : 's'} · ${inventory.humans} human${inventory.humans === 1 ? '' : 's'} · ${inventory.processes} runtime · ${inventory.systems} system`
  );
  let evidenceLabel = $derived(errors ? `${errors} issue${errors === 1 ? '' : 's'}` : `${events.length} event${events.length === 1 ? '' : 's'}`);
  let evidenceDetail = $derived(
    `${events.length} captured · ${models} model${models === 1 ? '' : 's'} · ${tools} tool${tools === 1 ? '' : 's'}${trace.integrity === 'verified' ? ' · verified' : trace.integrity === 'invalid' ? ' · integrity failed' : trace.integrity === 'live' ? ' · live' : ''}`
  );
</script>

{#if compact}
  <div class="run-stats" aria-label="Run overview">
    <span class="stat outcome" data-tone={health.tone} title={health.detail}>
      <small>Outcome</small>
      <strong>{health.label}</strong>
    </span>
    <span class="stat" title={participantDetail}>
      <small>Actors</small>
      <strong>{participants}</strong>
    </span>
    <span class="stat" class:error={errors > 0 || trace.integrity === 'invalid'} title={evidenceDetail}>
      <small>Evidence</small>
      <strong>{evidenceLabel}</strong>
    </span>
  </div>
  {#if trace.integrity === 'invalid'}
    <div class="integrity-banner compact" role="status" title={trace.integrity_detail || 'Journal failed integrity verification'}>
      <strong>Integrity failed</strong>
    </div>
  {/if}
{:else}
  <section class="run-overview" aria-label="Run overview">
    <div class="run-metrics">
      <div class="outcome"><span>Outcome</span><strong data-tone={health.tone}>{health.label}</strong><small title={health.detail}>{health.detail}</small></div>
      <div class="participants"><span>Participants</span><strong>{participants}</strong><small>{participantDetail}</small></div>
      <div class="evidence"><span>Evidence</span><strong class:error={errors > 0 || trace.integrity === 'invalid'}>{evidenceLabel}</strong><small>{evidenceDetail}</small></div>
    </div>
    {#if trace.integrity === 'invalid'}
      <div class="integrity-banner" role="status">
        <strong>Integrity check failed</strong>
        <span>{trace.integrity_detail || 'This journal does not match its manifest digest. Treat outcome labels as untrusted; raw events remain available for forensics.'}</span>
      </div>
    {/if}
  </section>
{/if}

<style>
  .run-stats {
    min-width: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    margin-top: 6px;
  }
  .run-stats .stat {
    min-width: 0;
    display: inline-flex;
    align-items: baseline;
    gap: 6px;
    max-width: 100%;
    padding: 3px 8px;
    border: 1px solid #2a3547;
    border-radius: 999px;
    background: rgba(16, 22, 32, 0.9);
    color: #c5d0e0;
    line-height: 1.2;
  }
  .run-stats .stat small {
    color: #7f8da1;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: .06em;
    text-transform: uppercase;
  }
  .run-stats .stat strong {
    color: #edf2f8;
    font-size: 11px;
    font-weight: 750;
    white-space: nowrap;
  }
  .run-stats .stat.outcome[data-tone='success'] { border-color: rgba(95,214,160,.35); background: rgba(95,214,160,.08); }
  .run-stats .stat.outcome[data-tone='success'] strong { color: #79ddb0; }
  .run-stats .stat.outcome[data-tone='warning'] { border-color: rgba(240,185,104,.35); background: rgba(240,185,104,.08); }
  .run-stats .stat.outcome[data-tone='warning'] strong { color: #f0b968; }
  .run-stats .stat.outcome[data-tone='running'] { border-color: rgba(158,170,255,.4); background: rgba(111,123,247,.1); }
  .run-stats .stat.outcome[data-tone='running'] strong { color: var(--blue-strong); }
  .run-stats .stat.outcome[data-tone='error'],
  .run-stats .stat.error { border-color: rgba(255,113,109,.4); background: rgba(255,113,109,.08); }
  .run-stats .stat.outcome[data-tone='error'] strong,
  .run-stats .stat.error strong { color: #ff8580; }
  .integrity-banner.compact {
    display: inline-flex;
    align-items: center;
    margin-top: 6px;
    margin-left: 6px;
    padding: 3px 8px;
    border: 1px solid rgba(255,113,109,.4);
    border-radius: 999px;
    background: rgba(255,113,109,.1);
    color: #ffaaa6;
    font-size: 10px;
  }
  .integrity-banner.compact strong { font-size: 10px; font-weight: 750; }

  .run-overview { grid-template-columns: minmax(0, 1fr); }
  .integrity-banner { display: grid; gap: 4px; margin: 0 0 8px; padding: 10px 14px; border: 1px solid rgba(255,113,109,.35); border-radius: 6px; background: rgba(255,113,109,.08); color: #ffc2bf; }
  .integrity-banner strong { color: #ffaaa6; font-size: 12px; }
  .integrity-banner span { color: #d7c0be; font-size: 11px; line-height: 1.45; }
  .run-metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); overflow: hidden; border-right: 0; }
  .run-metrics div { gap: 4px; padding-inline: 14px; }
  .run-metrics strong { overflow: visible; white-space: normal; text-overflow: clip; overflow-wrap: anywhere; line-height: 1.35; }
  .run-metrics small { color: #8290a4; font-size: 9px; line-height: 1.4; white-space: normal; overflow-wrap: anywhere; }
  .run-metrics strong[data-tone='success'] { color: #79ddb0; }
  .run-metrics strong[data-tone='warning'] { color: #f0b968; }
  .run-metrics strong[data-tone='running'] { color: var(--blue-strong); }
  .run-metrics strong[data-tone='error'] { color: #ff8580; }
</style>
