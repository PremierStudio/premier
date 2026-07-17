<script lang="ts">
  import { modelUsage, type ModelCallUsage, type PromptRole } from './modelUsage';
  import BrandIcon from './BrandIcon.svelte';
  import type { TraceEvent } from './types';

  let { events, selectedEventId = null, onselect }: {
    events: TraceEvent[];
    selectedEventId?: string | null;
    onselect: (event: TraceEvent) => void;
  } = $props();

  const roleLabels: Record<PromptRole, string> = {
    system: 'System', developer: 'Developer', user: 'User', tool: 'Tool schema', assistant: 'Assistant'
  };

  const usage = $derived(modelUsage(events));
  const totals = $derived.by(() => usage.rollups.reduce((total, row) => ({
    calls: total.calls + row.calls,
    input: total.input + row.input,
    output: total.output + row.output,
    cacheRead: total.cacheRead + row.cacheRead,
    cacheWrite: total.cacheWrite + row.cacheWrite,
    reasoning: total.reasoning + row.reasoning,
    tokens: total.tokens + row.total,
    cost: total.cost + row.costUsd,
    hasInput: total.hasInput || row.hasInput,
    hasOutput: total.hasOutput || row.hasOutput,
    hasCache: total.hasCache || row.hasCacheRead || row.hasCacheWrite,
    hasReasoning: total.hasReasoning || row.hasReasoning,
    hasTokens: total.hasTokens || row.hasTotal,
    hasCost: total.hasCost || row.hasCost
  }), { calls: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0, reasoning: 0, tokens: 0, cost: 0, hasInput: false, hasOutput: false, hasCache: false, hasReasoning: false, hasTokens: false, hasCost: false }));

  function tokens(value: number, captured: boolean): string {
    return captured ? value.toLocaleString() : '—';
  }

  function cost(value: number, captured: boolean): string {
    return captured ? `$${value.toFixed(value >= 1 ? 2 : 4)}` : '—';
  }

  function contextLabel(call: ModelCallUsage): string {
    if (!call.prompts.length) return 'Prompt content not captured';
    return [...new Set(call.prompts.map((prompt) => roleLabels[prompt.role]))].join(' · ');
  }
</script>

{#if usage.calls.length}
<section class="usage" aria-labelledby="model-usage-title">
  <header>
    <div><span>Model evidence</span><h3 id="model-usage-title">Context, tokens & cost</h3><p>Provider-reported usage for recorded model calls in this scope.</p></div>
    <strong>{usage.calls.length} call{usage.calls.length === 1 ? '' : 's'}</strong>
  </header>

    <div class="usage-totals" aria-label="Model usage totals">
      <div><span>Total tokens</span><strong>{tokens(totals.tokens, totals.hasTokens)}</strong><small>{totals.calls} recorded call{totals.calls === 1 ? '' : 's'}</small></div>
      <div><span>Input</span><strong>{tokens(totals.input, totals.hasInput)}</strong><small>Provider-reported context</small></div>
      <div><span>Output</span><strong>{tokens(totals.output, totals.hasOutput)}</strong><small>Generated completion</small></div>
      <div><span>Cache</span><strong>{tokens(totals.cacheRead + totals.cacheWrite, totals.hasCache)}</strong><small>{totals.hasCache ? `${totals.cacheRead.toLocaleString()} read · ${totals.cacheWrite.toLocaleString()} write` : 'No cache breakdown'}</small></div>
      <div><span>Reasoning</span><strong>{tokens(totals.reasoning, totals.hasReasoning)}</strong><small>Included in output when reported</small></div>
      <div><span>Recorded cost</span><strong>{cost(totals.cost, totals.hasCost)}</strong><small>Provider or collector supplied</small></div>
    </div>

    <div class="rollup" role="table" aria-label="Usage by model and actor">
      <div class="rollup-head" role="row"><span role="columnheader">Model / actor</span><span role="columnheader">Calls</span><span role="columnheader">Input</span><span role="columnheader">Output</span><span role="columnheader">Cache</span><span role="columnheader">Total</span><span role="columnheader">Cost</span></div>
      {#each usage.rollups as row (row.key)}
        <div class="rollup-row" role="row">
          <span role="cell" class="model-identity"><BrandIcon provider={row.provider} model={row.model} size={14} /><span><strong>{row.model}</strong><small>{row.provider ? `${row.provider} · ` : ''}{row.actor}</small></span></span>
          <span role="cell">{row.calls}</span>
          <span role="cell">{tokens(row.input, row.hasInput)}</span>
          <span role="cell">{tokens(row.output, row.hasOutput)}</span>
          <span role="cell">{tokens(row.cacheRead + row.cacheWrite, row.hasCacheRead || row.hasCacheWrite)}</span>
          <span role="cell">{tokens(row.total, row.hasTotal)}</span>
          <span role="cell">{cost(row.costUsd, row.hasCost)}</span>
        </div>
      {/each}
    </div>

    <div class="calls">
      <div class="calls-heading"><strong>Model-call ledger</strong><span>Expand a call to inspect captured context.</span></div>
      {#each usage.calls as call (call.event.event_id)}
        <details class:selected={call.event.event_id === selectedEventId}>
          <summary>
            <span class="sequence">#{call.event.sequence}</span>
            <span class="identity"><BrandIcon provider={call.provider} model={call.model} size={15} /><span><strong>{call.model}</strong><small>{call.actor}{call.provider ? ` · ${call.provider}` : ''}</small></span></span>
            <span class="context"><strong>{contextLabel(call)}</strong><small>{call.prompts.length ? `${call.prompts.reduce((sum, prompt) => sum + prompt.characters, 0).toLocaleString()} captured characters${call.toolSchemaCount ? ` · ${call.toolSchemaCount} tool schema${call.toolSchemaCount === 1 ? '' : 's'}` : ''}` : 'Instrumentation gap'}</small></span>
            <span class="token"><strong>{call.tokens.total === null ? '—' : call.tokens.total.toLocaleString()}</strong><small>tokens</small></span>
            <span class="token"><strong>{call.costUsd === null ? '—' : cost(call.costUsd, true)}</strong><small>cost</small></span>
          </summary>
          <div class="call-detail">
            <div class="call-usage">
              <span><small>Input</small><strong>{call.tokens.input === null ? 'Not reported' : call.tokens.input.toLocaleString()}</strong></span>
              <span><small>Output</small><strong>{call.tokens.output === null ? 'Not reported' : call.tokens.output.toLocaleString()}</strong></span>
              <span><small>Cache read</small><strong>{call.tokens.cacheRead === null ? 'Not reported' : call.tokens.cacheRead.toLocaleString()}</strong></span>
              <span><small>Reasoning</small><strong>{call.tokens.reasoning === null ? 'Not reported' : call.tokens.reasoning.toLocaleString()}</strong></span>
              <button onclick={() => onselect(call.event)}>Open event #{call.event.sequence}</button>
            </div>
            {#if call.prompts.length}
              <div class="prompt-grid">
                {#each call.prompts as prompt, index (`${prompt.role}-${prompt.source}-${index}`)}
                  <article data-role={prompt.role}>
                    <header><strong>{roleLabels[prompt.role]}</strong><span>{prompt.tokens === null ? `${prompt.characters.toLocaleString()} chars · role tokens not reported` : `${prompt.tokens.toLocaleString()} tokens`}</span></header>
                    <pre>{prompt.text}</pre>
                  </article>
                {/each}
                {#if call.response}<article data-role="assistant"><header><strong>Recorded response</strong><span>{call.response.length.toLocaleString()} chars</span></header><pre>{call.response}</pre></article>{/if}
              </div>
            {:else}
              <p class="missing-context">Token totals were recorded, but prompt roles and tool schemas were not. Premier will not infer system or user content from unrelated logs.</p>
            {/if}
          </div>
        </details>
      {/each}
    </div>
</section>
{/if}

<style>
  .usage { min-width: 0; border-bottom: 1px solid var(--line, rgba(255,255,255,.09)); background: #080b10; }
  .usage > header { min-width: 0; min-height: 62px; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 12px 16px; border-bottom: 1px solid var(--line-soft, rgba(255,255,255,.055)); }
  .usage > header div { min-width: 0; }
  .usage > header span { color: #9eaaff; font-size: 8px; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
  h3, p { margin: 0; }
  h3 { margin-top: 2px; color: #e8edf5; font-size: 14px; }
  .usage > header p { margin-top: 3px; color: #7e8ba0; font-size: 10px; }
  .usage > header > strong { flex: 0 0 auto; padding: 5px 8px; border: 1px solid rgba(158,170,255,.25); border-radius: 999px; color: #b8c8ff; background: rgba(111,123,247,.08); font-size: 10px; }
  .usage-totals { display: grid; grid-template-columns: repeat(6,minmax(0,1fr)); border-bottom: 1px solid var(--line-soft, rgba(255,255,255,.055)); }
  .usage-totals > div { min-width: 0; display: grid; gap: 2px; padding: 10px 12px; border-right: 1px solid var(--line-soft, rgba(255,255,255,.055)); }
  .usage-totals > div:last-child { border-right: 0; }
  .usage-totals span, .call-usage small { color: #77869b; font-size: 8px; font-weight: 750; letter-spacing: .08em; text-transform: uppercase; }
  .usage-totals strong { color: #f0f4fa; font: 700 14px 'IBM Plex Mono', monospace; }
  .usage-totals small { overflow-wrap: anywhere; color: #748196; font-size: 9px; }
  .rollup { min-width: 0; overflow-x: auto; border-bottom: 1px solid var(--line-soft, rgba(255,255,255,.055)); }
  .rollup-head, .rollup-row { min-width: 720px; display: grid; grid-template-columns: minmax(210px,1fr) 55px repeat(5,80px); gap: 8px; align-items: center; padding: 7px 14px; }
  .rollup-head { color: #6f7d91; background: rgba(255,255,255,.015); font-size: 8px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
  .rollup-row { border-top: 1px solid rgba(255,255,255,.04); color: #aeb9c9; font: 10px 'IBM Plex Mono', monospace; }
  .rollup-row > span:not(:first-child) { text-align: right; }
  .rollup-row span:first-child, .model-identity { min-width: 0; display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 8px; align-items: center; }
  .rollup-row span:first-child strong, .model-identity strong { overflow-wrap: anywhere; color: #dce4ef; font: 650 11px 'IBM Plex Sans Variable', sans-serif; }
  .rollup-row span:first-child small, .model-identity small { display: block; color: #748196; font-size: 9px; }
  .calls { min-width: 0; padding: 10px 12px 12px; }
  .calls-heading { display: flex; justify-content: space-between; gap: 12px; padding: 2px 2px 8px; color: #748196; font-size: 9px; }
  .calls-heading strong { color: #cdd6e3; font-size: 10px; }
  details { min-width: 0; overflow: hidden; border: 1px solid rgba(255,255,255,.075); border-radius: 7px; background: rgba(255,255,255,.018); }
  details + details { margin-top: 6px; }
  details.selected { border-color: rgba(158,170,255,.52); box-shadow: inset 2px 0 #9eaaff; }
  summary { min-width: 0; display: grid; grid-template-columns: 14px 44px minmax(140px,.7fr) minmax(220px,1.3fr) 78px 78px; gap: 10px; align-items: center; padding: 9px 11px; cursor: pointer; list-style: none; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: '›'; color: #8090a7; transition: transform .12s ease; }
  details[open] summary::before { transform: rotate(90deg); }
  .sequence { grid-column: 2; color: #748196; font: 9px 'IBM Plex Mono', monospace; }
  .identity, .context, .token { min-width: 0; display: grid; gap: 2px; }
  .identity { grid-template-columns: auto minmax(0, 1fr); gap: 8px; align-items: center; }
  .identity > span { min-width: 0; display: grid; gap: 2px; }
  .identity strong, .context strong { overflow: hidden; color: #dce4ef; font-size: 11px; white-space: nowrap; text-overflow: ellipsis; }
  .identity small, .context small, .token small { overflow: hidden; color: #748196; font-size: 9px; white-space: nowrap; text-overflow: ellipsis; }
  .token { text-align: right; }
  .token strong { color: #b9c9ff; font: 700 11px 'IBM Plex Mono', monospace; }
  .call-detail { padding: 10px; border-top: 1px solid rgba(255,255,255,.06); background: rgba(2,4,7,.42); }
  .call-usage { display: grid; grid-template-columns: repeat(4,minmax(90px,1fr)) auto; gap: 8px; align-items: stretch; margin-bottom: 10px; }
  .call-usage span { display: grid; gap: 2px; padding: 7px 8px; border: 1px solid rgba(255,255,255,.06); border-radius: 5px; }
  .call-usage strong { color: #cfd8e5; font: 10px 'IBM Plex Mono', monospace; }
  .call-usage button { padding: 0 10px; border: 1px solid #3b4f79; border-radius: 5px; color: #c8d5ef; background: #121a29; font-size: 9px; cursor: pointer; }
  .prompt-grid { min-width: 0; display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 8px; }
  .prompt-grid article { min-width: 0; overflow: hidden; border: 1px solid rgba(255,255,255,.07); border-radius: 6px; background: #080b10; }
  .prompt-grid article > header { display: flex; justify-content: space-between; gap: 10px; padding: 7px 9px; border-bottom: 1px solid rgba(255,255,255,.055); }
  .prompt-grid article > header strong { color: #cfd8e5; font-size: 10px; }
  .prompt-grid article > header span { color: #748196; font-size: 8px; }
  .prompt-grid article[data-role='system'] { border-color: rgba(197,154,255,.2); }
  .prompt-grid article[data-role='developer'] { border-color: rgba(158,170,255,.22); }
  .prompt-grid article[data-role='user'] { border-color: rgba(99,220,165,.2); }
  pre { max-height: 190px; margin: 0; overflow: auto; padding: 9px; color: #aeb9c9; font: 9px/1.55 'IBM Plex Mono', monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
  .missing-context { padding: 11px; border: 1px dashed rgba(255,255,255,.1); color: #8290a4; font-size: 10px; line-height: 1.5; }
  @container (max-width: 760px) {
    .usage-totals { grid-template-columns: repeat(3,minmax(0,1fr)); }
    .usage-totals > div:nth-child(3) { border-right: 0; }
    .usage-totals > div:nth-child(-n+3) { border-bottom: 1px solid var(--line-soft, rgba(255,255,255,.055)); }
    summary { grid-template-columns: 12px 36px minmax(120px,.75fr) minmax(150px,1.25fr) 66px; }
    summary .token:last-child { display: none; }
    .call-usage { grid-template-columns: repeat(2,minmax(0,1fr)); }
    .call-usage button { min-height: 36px; }
  }
  @container (max-width: 520px) {
    .usage-totals { grid-template-columns: repeat(2,minmax(0,1fr)); }
    .usage-totals > div { border-bottom: 1px solid var(--line-soft, rgba(255,255,255,.055)); }
    .usage-totals > div:nth-child(even) { border-right: 0; }
    summary { grid-template-columns: 12px 30px minmax(0,1fr) 62px; }
    summary .context { grid-column: 3; }
    summary .identity { grid-column: 3; }
    .prompt-grid { grid-template-columns: 1fr; }
  }
</style>
