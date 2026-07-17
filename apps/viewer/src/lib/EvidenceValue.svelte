<script lang="ts">
  import { ChevronDown, ChevronUp } from '@lucide/svelte';
  let { value, limit = 700 }: { value: unknown; limit?: number } = $props();
  let expanded = $state(false);

  const text = $derived(format(value));
  const isLong = $derived(text.length > limit);
  const visible = $derived(expanded || !isLong ? text : `${text.slice(0, limit).trimEnd()}\n…`);

  function format(current: unknown): string {
    if (current === null) return 'null';
    if (current === undefined) return '—';
    if (typeof current === 'string') return current;
    if (typeof current === 'number' || typeof current === 'boolean') return String(current);
    return JSON.stringify(current, null, 2);
  }
</script>

<div class="evidence-value" class:expanded>
  <pre>{visible}</pre>
  {#if isLong}
    <button type="button" class="value-toggle" aria-expanded={expanded} onclick={() => (expanded = !expanded)}>
      {#if expanded}<ChevronUp size={14} aria-hidden="true" />Collapse value{:else}<ChevronDown size={14} aria-hidden="true" />Show complete value <span>{text.length.toLocaleString()} characters</span>{/if}
    </button>
  {/if}
</div>

<style>
  .evidence-value { min-width: 0; }
  pre { margin: 8px 0 0; overflow: auto; color: #c8d0dc; font: 11.5px/1.65 'IBM Plex Mono', monospace; overflow-wrap: anywhere; white-space: pre-wrap; }
  .value-toggle { width: 100%; min-height: 34px; display: flex; align-items: center; gap: 7px; margin-top: 8px; padding: 0 9px; border: 1px solid #2a3547; border-radius: 5px; color: var(--blue-strong); background: #0e141e; font: 700 11px 'Source Sans 3 Variable', 'Source Sans 3', sans-serif; text-align: left; cursor: pointer; }
  .value-toggle span { margin-left: auto; color: #8190a5; font-size: 10px; font-weight: 600; }
  .value-toggle:hover { border-color: #4a5f8d; color: #e5ebff; background: #151d2b; }
  .value-toggle:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
</style>
