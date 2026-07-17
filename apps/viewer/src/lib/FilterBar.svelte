<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { EventCategory, EventFilters } from './types';
  import { clearScopeFilters, scopeIsActive } from './deepLink';

  let {
    filters,
    counts,
    visible,
    total,
    windowActive = false,
    onchange,
    onclearScope
  }: {
    filters: EventFilters;
    counts: Record<EventCategory, number>;
    visible: number;
    total: number;
    windowActive?: boolean;
    onchange: (filters: EventFilters) => void;
    /** Clears filters + time window together. */
    onclearScope?: () => void;
  } = $props();

  const categories: { value: EventCategory; label: string }[] = [
    { value: 'all', label: 'all events' },
    { value: 'agent', label: 'agents' },
    { value: 'model', label: 'models' },
    { value: 'tool', label: 'tools' },
    { value: 'approval', label: 'decisions' },
    { value: 'process', label: 'runtime' },
    { value: 'error', label: 'issues' }
  ];
  let active = $derived(scopeIsActive(filters, windowActive ? 1 : null));
  let activeLabel = $derived(categories.find((category) => category.value === filters.category)?.label ?? 'events');
  let scopedTotal = $derived(counts.all);
  let searchValue = $state('');
  let searchTimer: number | null = null;

  $effect(() => {
    if (filters.search !== searchValue && searchTimer === null) searchValue = filters.search;
  });

  function updateSearch(value: string) {
    searchValue = value;
    if (searchTimer) window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => {
      searchTimer = null;
      onchange({ ...filters, search: searchValue });
    }, 180);
  }

  function clearScope() {
    if (onclearScope) onclearScope();
    else onchange(clearScopeFilters(filters));
  }

  onDestroy(() => { if (searchTimer) window.clearTimeout(searchTimer); });
</script>

<section class="filter-bar" aria-label="Event filters">
  <label class="search"><span aria-hidden="true">⌕</span><input id="event-search" name="event-search" value={searchValue} oninput={(event) => updateSearch(event.currentTarget.value)} placeholder="Search this run…" aria-label="Search events" /></label>
  <div class="category-tabs" aria-label="Event categories">
    {#each categories as category}
      {@const count = counts[category.value] ?? 0}
      <button
        class:active={filters.category === category.value}
        class:unavailable={category.value !== 'all' && count === 0}
        aria-label={category.label}
        aria-pressed={filters.category === category.value}
        disabled={category.value !== 'all' && count === 0}
        title={category.value !== 'all' && count === 0 ? `No ${category.label} in the current scope` : `${count} ${category.label}`}
        onclick={() => onchange({ ...filters, category: category.value, errorsOnly: false })}
      ><span>{category.label}</span><b aria-hidden="true">{count}</b></button>
    {/each}
  </div>
  <div class="filter-summary" aria-live="polite">
    <span class="filter-count">
      <span>
        <strong>{visible}</strong> {activeLabel}
        {#if filters.actorId} · {filters.actorId}{/if}
        {#if filters.correlationId} · corr {filters.correlationId}{/if}
        {#if windowActive} · time crop{/if}
      </span>
      <small>{scopedTotal} scoped · {total} total</small>
    </span>
    {#if filters.correlationId}
      <button class="clear-filters correlation-chip" onclick={() => onchange({ ...filters, correlationId: null })} title="Clear correlation filter">Correlation ✕</button>
    {/if}
    {#if active}<button class="clear-filters" onclick={clearScope}>Clear scope</button>{/if}
  </div>
</section>
