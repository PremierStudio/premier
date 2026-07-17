<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import type { TraceEvent } from './types';
  import { eventPayload } from './types';
  import { actorId, categoryOf, eventSummary } from './analysis';
  import { relatedSummary, resolveRelatedTarget } from './causal';
  import { parseInvestigationParams, serializeInvestigationUrl } from './deepLink';
  import EvidenceValue from './EvidenceValue.svelte';
  import BrandIcon from './BrandIcon.svelte';
  import { focusTrap } from './interactions';
  import {
    Activity, Bot, Braces, Check, ChevronRight, CircleAlert, Clock3, Code2,
    Copy, FileInput, FileOutput, Fingerprint, GitBranch, Inbox, Info, Link2,
    PanelRightOpen, Radio, ShieldCheck, Sparkles, SquareTerminal, UserRound, Wrench, X
  } from '@lucide/svelte';

  type Tab = 'overview' | 'data' | 'relationships' | 'raw';
  type Entry = [string, unknown];

  let {
    event,
    events = [],
    onclose,
    onnavigate,
    oncorrelation,
    compact = false,
    onrestore = () => undefined
  }: {
    event: TraceEvent | null;
    events?: TraceEvent[];
    onclose?: () => void;
    /** Select an event by its stable event ID. */
    onnavigate?: (eventId: string) => void;
    /** Scope the timeline to this correlation id. */
    oncorrelation?: (correlationId: string) => void;
    compact?: boolean;
    onrestore?: () => void;
  } = $props();

  let activeTab = $state<Tab>('overview');
  let copied = $state<'link' | 'event' | 'payload' | 'failed' | null>(null);
  let overlayMode = $state(false);
  let copyTimer: ReturnType<typeof setTimeout> | undefined;

  const payload = $derived(event ? eventPayload(event) : {});
  const entries = $derived(Object.entries(payload));
  const inputEntries = $derived(entries.filter(([key]) => /^(input|inputs|arg|args|arguments|command|prompt|request|parameters|params|query|url|body|task|goal|instruction|instructions)$/i.test(key)));
  const effectEntries = $derived(entries.filter(([key]) => /^(effect|effects|change|changes|mutation|mutations|files|artifacts)$/i.test(key)));
  const authorityEntries = $derived(entries.filter(([key]) => /^(approval|approval_receipt|approved|authority|decision|denied|permission|permissions|policy|scope|risk|reason|receipt|grant|grantee|approver|nonce|expires|expires_after|constraint|constraints)$/i.test(key)));
  const outputEntries = $derived(entries.filter(([key]) => /^(output|outputs|result|results|response|text|stdout|stderr|error|errors|message|summary|content|outcome|joined|delegates|exit_code|exitCode)$/i.test(key)));
  const classifiedKeys = $derived(new Set([...inputEntries, ...effectEntries, ...authorityEntries, ...outputEntries].map(([key]) => key)));
  const summaryEntries = $derived(entries.filter(([key]) => !classifiedKeys.has(key)));
  const primaryEvidence = $derived(event && categoryOf(event) === 'approval'
    ? authorityEntries.find(([key]) => /^(receipt|approval_receipt)$/i.test(key)) ?? authorityEntries[0]
    : outputEntries[0] ?? effectEntries[0] ?? inputEntries[0] ?? authorityEntries[0]);
  const showPrimaryEvidence = $derived(Boolean(primaryEvidence && event && (
    typeof primaryEvidence[1] !== 'string'
    || primaryEvidence[1].trim().replace(/\s+/g, ' ').toLowerCase() !== eventDescription(event).trim().replace(/\s+/g, ' ').toLowerCase()
  )));
  const overviewEntries = $derived(entries
    .filter(([key]) => key !== primaryEvidence?.[0])
    .slice(0, 3));

  const tabs = [
    { id: 'overview' as const, label: 'Overview', icon: Info },
    { id: 'data' as const, label: 'Data', icon: Braces },
    { id: 'relationships' as const, label: 'Relations', icon: GitBranch },
    { id: 'raw' as const, label: 'Raw', icon: Code2 }
  ];

  const relations = $derived(event ? relatedSummary(event, events) : null);
  const causalCount = $derived(event
    ? [event.parent_event_id, event.span_id, event.parent_span_id, event.correlation_id, ...event.links].filter(Boolean).length
      + (relations?.children.length ?? 0)
    : 0);

  function tabCount(tab: Tab): number | null {
    if (tab === 'data') return entries.length;
    if (tab === 'relationships') return causalCount;
    return null;
  }

  $effect(() => {
    if (event?.event_id) {
      activeTab = 'overview';
      copied = null;
    }
  });

  onDestroy(() => clearTimeout(copyTimer));
  onMount(() => {
    if (!window.matchMedia) return;
    const query = window.matchMedia('(max-width: 1180px)');
    const update = () => (overlayMode = query.matches);
    update();
    query.addEventListener('change', update);
    return () => query.removeEventListener('change', update);
  });

  function label(key: string): string {
    return key.replace(/[_-]+/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function eventTitle(current: TraceEvent): string {
    const named = payload.tool_name ?? payload.tool ?? payload.model ?? payload.operation ?? payload.action ?? payload.name ?? payload.task ?? payload.goal;
    if (typeof named === 'string' && named.trim()) return named;
    return current.kind.replace(/[._-]+/g, ' ');
  }

  function eventDescription(current: TraceEvent): string {
    const summary = eventSummary(current);
    return summary.length > 240 ? `${summary.slice(0, 237)}…` : summary;
  }

  let relatedMissing = $state<string | null>(null);

  function eventUrl(current: TraceEvent): string {
    const state = parseInvestigationParams(new URL(window.location.href).searchParams);
    return serializeInvestigationUrl(window.location.href, {
      ...state,
      traceId: current.trace_id,
      eventId: current.event_id,
      eventSequence: null
    });
  }

  function openRelated(id: string) {
    const result = resolveRelatedTarget(events, id);
    if (result.found) {
      relatedMissing = null;
      onnavigate?.(result.found.event_id);
    } else {
      relatedMissing = id;
    }
  }

  $effect(() => {
    if (event?.event_id) relatedMissing = null;
  });

  function eventFamily(current: TraceEvent): string {
    const prefix = current.kind.split(/[._-]/)[0]?.toLowerCase();
    if (['agent', 'model', 'tool', 'approval', 'process'].includes(prefix)) return prefix;
    return categoryOf(current) === 'error' ? 'event' : categoryOf(current);
  }

  function eventFamilyIcon(current: TraceEvent) {
    if (['error', 'failed', 'denied'].includes(current.status) || current.kind.endsWith('.error')) return CircleAlert;
    const family = eventFamily(current);
    if (family === 'agent') return Bot;
    if (family === 'model') return Sparkles;
    if (family === 'tool') return Wrench;
    if (family === 'approval') return ShieldCheck;
    if (family === 'process') return SquareTerminal;
    return Activity;
  }

  async function writeClipboard(value: string, type: 'link' | 'event' | 'payload') {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else {
        const textarea = document.createElement('textarea');
        textarea.value = value;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        const succeeded = document.execCommand('copy');
        textarea.remove();
        if (!succeeded) throw new Error('Copy command failed');
      }
      copied = type;
    } catch {
      copied = 'failed';
    }
    clearTimeout(copyTimer);
    copyTimer = setTimeout(() => (copied = null), 1800);
  }

  function durationLabel(current: TraceEvent): string {
    if (!current.duration_ms) return 'Not captured';
    if (current.duration_ms < 1_000) return `${current.duration_ms} ms`;
    return `${(current.duration_ms / 1_000).toFixed(current.duration_ms < 10_000 ? 1 : 0)} s`;
  }

  function close() {
    if (event && onclose) onclose();
  }

  function handleKeydown(keyEvent: KeyboardEvent) {
    if (keyEvent.key === 'Escape' && event && onclose) {
      keyEvent.preventDefault();
      close();
    }
  }

  function handleTabKeydown(keyEvent: KeyboardEvent, tab: Tab) {
    const currentIndex = tabs.findIndex((candidate) => candidate.id === tab);
    let nextIndex: number | undefined;
    if (keyEvent.key === 'ArrowRight') nextIndex = (currentIndex + 1) % tabs.length;
    if (keyEvent.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    if (keyEvent.key === 'Home') nextIndex = 0;
    if (keyEvent.key === 'End') nextIndex = tabs.length - 1;
    if (nextIndex === undefined) return;
    keyEvent.preventDefault();
    activeTab = tabs[nextIndex].id;
    document.getElementById(`inspector-tab-${activeTab}`)?.focus();
  }

  function openRailTab(tab: Tab) {
    activeTab = tab;
    onrestore();
    window.setTimeout(() => document.getElementById(`inspector-tab-${tab}`)?.focus(), 0);
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<div
  class="inspector"
  class:drawer={Boolean(onclose)}
  role={overlayMode ? 'dialog' : 'complementary'}
  aria-modal={overlayMode ? 'true' : undefined}
  aria-labelledby="inspector-title"
  tabindex="-1"
  use:focusTrap={{ enabled: overlayMode && Boolean(event), onEscape: close, initialFocus: '.close-button' }}
  class:compact-rail={compact && !overlayMode}
>
  {#if compact && !overlayMode}
    <div class="inspector-rail" aria-label="Compact event inspector">
      {#if event}
        <button class="rail-expand" type="button" onclick={onrestore} aria-label="Expand event inspector" title="Expand event inspector"><PanelRightOpen size={18} strokeWidth={1.8} aria-hidden="true" /></button>
        {@const RailFamilyIcon = eventFamilyIcon(event)}
        <span class="rail-status" data-status={event.status || categoryOf(event)} title={`${eventTitle(event)} · ${event.status || 'recorded'}`}><RailFamilyIcon size={16} strokeWidth={1.8} aria-hidden="true" /><b>#{event.sequence}</b></span>
        <div class="rail-tabs" aria-label="Inspector sections">
          {#each tabs as tab}
            {@const RailTabIcon = tab.icon}
            <button type="button" class:active={activeTab === tab.id} onclick={() => openRailTab(tab.id)} aria-label={`Open ${tab.label}`} title={tab.label}><RailTabIcon size={16} strokeWidth={1.8} aria-hidden="true" /></button>
          {/each}
        </div>
      {:else}
        <span class="rail-empty" title="Select an event to inspect"><Activity size={18} strokeWidth={1.7} aria-hidden="true" /></span>
      {/if}
    </div>
  {:else}
  <header class="inspector-header">
    <div class="title-group">
      <span class="eyebrow" id="inspector-title">Event inspector</span>
      {#if event}
        <strong title={eventTitle(event)}>{eventTitle(event)}</strong>
        <span class="event-number"><span>{event.kind}</span><b>#{event.sequence}</b></span>
      {:else}
        <strong>No event selected</strong>
      {/if}
    </div>
    {#if event}
      <div class="header-actions">
        <button class="icon-button" class:confirmed={copied === 'link'} onclick={() => writeClipboard(eventUrl(event), 'link')} aria-label={copied === 'link' ? 'Event link copied' : 'Copy event link'} title="Copy deep link">
          {#if copied === 'link'}<Check size={16} strokeWidth={2.2} aria-hidden="true" />{:else}<Link2 size={16} strokeWidth={1.9} aria-hidden="true" />{/if}
        </button>
        <button class="icon-button" class:confirmed={copied === 'event'} onclick={() => writeClipboard(JSON.stringify(event, null, 2), 'event')} aria-label={copied === 'event' ? 'Event JSON copied' : 'Copy event JSON'} title="Copy event JSON">
          {#if copied === 'event'}<Check size={16} strokeWidth={2.2} aria-hidden="true" />{:else}<Braces size={16} strokeWidth={1.9} aria-hidden="true" />{/if}
        </button>
        {#if onclose}<button class="icon-button close-button" onclick={close} aria-label="Close inspector" title="Close inspector (Esc)"><X size={18} strokeWidth={1.9} aria-hidden="true" /></button>{/if}
      </div>
    {/if}
  </header>

  {#if copied === 'failed'}<div class="copy-error" role="status"><CircleAlert size={14} aria-hidden="true" />Clipboard unavailable. Use the Raw tab to select the value manually.</div>{/if}

  {#if event}
    <div class="tab-list" role="tablist" aria-label="Event evidence">
      {#each tabs as tab}
        {@const TabIcon = tab.icon}
        {@const count = tabCount(tab.id)}
        <button
          id={`inspector-tab-${tab.id}`}
          role="tab"
          aria-selected={activeTab === tab.id}
          aria-controls={`inspector-panel-${tab.id}`}
          class:active={activeTab === tab.id}
          tabindex={activeTab === tab.id ? 0 : -1}
          onclick={() => (activeTab = tab.id)}
          onkeydown={(keyEvent) => handleTabKeydown(keyEvent, tab.id)}
        ><TabIcon size={14} strokeWidth={1.8} aria-hidden="true" /><span>{tab.label}</span>{#if count !== null && count > 0}<b>{count}</b>{/if}</button>
      {/each}
    </div>

    <div
      class="tab-panel"
      id={`inspector-panel-${activeTab}`}
      role="tabpanel"
      aria-labelledby={`inspector-tab-${activeTab}`}
      tabindex="0"
    >
      {#if activeTab === 'overview'}
        {@const FamilyIcon = eventFamilyIcon(event)}
        {@const modelProvider = typeof payload.provider === 'string' ? payload.provider : typeof payload.vendor === 'string' ? payload.vendor : null}
        {@const modelName = typeof payload.model === 'string' ? payload.model : typeof payload.model_id === 'string' ? payload.model_id : null}
        <section class="hero-summary" aria-label="Event summary">
          <div class="summary-heading">
            <span class="category-mark" data-category={eventFamily(event)}>
              {#if modelProvider || modelName}
                <BrandIcon provider={modelProvider} model={modelName} size={12} />
              {:else}
                <FamilyIcon size={12} strokeWidth={2} aria-hidden="true" />
              {/if}
              {eventFamily(event)}
            </span>
            <span class="status-badge" data-status={event.status || categoryOf(event)}><i aria-hidden="true"></i>{event.status || 'recorded'}</span>
          </div>
          {#if modelName}<div class="model-chip"><BrandIcon provider={modelProvider} model={modelName} size={13} /><strong>{modelName}</strong>{#if modelProvider}<span>{modelProvider}</span>{/if}</div>{/if}
          <p>{eventDescription(event)}</p>
          <div class="summary-facts">
            <div><UserRound size={15} strokeWidth={1.8} aria-hidden="true" /><span>Actor</span><strong>{actorId(event)}</strong><small>{event.actor_type || 'process'}</small></div>
            <div><Clock3 size={15} strokeWidth={1.8} aria-hidden="true" /><span>Duration</span><strong>{durationLabel(event)}</strong><small>Observed {new Date(event.timestamp).toLocaleTimeString()}</small></div>
            <div><Radio size={15} strokeWidth={1.8} aria-hidden="true" /><span>Source</span><strong>{event.source || 'Unknown'}</strong><small>Capture producer</small></div>
            <div><Fingerprint size={15} strokeWidth={1.8} aria-hidden="true" /><span>Sequence</span><strong>Event {event.sequence}</strong><small>Recorded order</small></div>
          </div>
          {#if event.correlation_id}
            <div class="summary-correlation">
              <Fingerprint size={14} strokeWidth={1.8} aria-hidden="true" />
              <span>Correlation</span>
              {#if oncorrelation}
                <button type="button" class="correlation-filter" onclick={() => oncorrelation?.(event.correlation_id)} title="Filter timeline to this correlation">
                  <code>{event.correlation_id}</code>
                  <span>Filter</span>
                </button>
              {:else}
                <code>{event.correlation_id}</code>
              {/if}
            </div>
          {/if}
        </section>

        {#if primaryEvidence && showPrimaryEvidence}
          <section class="evidence-section">
            <h3><Activity size={14} aria-hidden="true" />Primary evidence</h3>
            <div class="evidence-card"><span>{label(primaryEvidence[0])}</span><EvidenceValue value={primaryEvidence[1]} /></div>
          </section>
        {/if}

        {#if overviewEntries.length}
          <section class="evidence-section overview-evidence">
            <div class="section-title">
              <h3><Braces size={14} aria-hidden="true" />Evidence at a glance</h3>
              <button class="text-action" onclick={() => (activeTab = 'data')}>View all <ChevronRight size={14} aria-hidden="true" /></button>
            </div>
            <div class="evidence-stack">
              {#each overviewEntries as [key, value]}
                <div class="evidence-card"><span>{label(key)}</span><EvidenceValue {value} limit={220} /></div>
              {/each}
            </div>
          </section>
        {/if}

        {#if causalCount}
          <section class="evidence-section overview-relations">
            <div class="section-title">
              <h3><GitBranch size={14} aria-hidden="true" />Trace context <b>{causalCount}</b></h3>
              <button class="text-action" onclick={() => (activeTab = 'relationships')}>Explore <ChevronRight size={14} aria-hidden="true" /></button>
            </div>
            <dl class="field-list causal-list">
              <div><dt>Event ID</dt><dd><code>{event.event_id}</code></dd></div>
              {#if event.parent_event_id}<div><dt>Parent event</dt><dd><code>{event.parent_event_id}</code></dd></div>{/if}
              {#if event.parent_span_id}<div><dt>Parent span</dt><dd><code>{event.parent_span_id}</code></dd></div>{/if}
              {#if event.correlation_id}<div><dt>Correlation</dt><dd><code>{event.correlation_id}</code></dd></div>{/if}
            </dl>
          </section>
        {/if}

      {:else if activeTab === 'data'}
        {#if entries.length}
          {#if inputEntries.length}<section class="evidence-section"><h3><FileInput size={14} aria-hidden="true" />Request & input <b>{inputEntries.length}</b></h3><div class="evidence-stack">{#each inputEntries as [key, value]}<div class="evidence-card"><span>{label(key)}</span><EvidenceValue {value} /></div>{/each}</div></section>{/if}
          {#if outputEntries.length}<section class="evidence-section"><h3><FileOutput size={14} aria-hidden="true" />Result <b>{outputEntries.length}</b></h3><div class="evidence-stack">{#each outputEntries as [key, value]}<div class="evidence-card"><span>{label(key)}</span><EvidenceValue {value} /></div>{/each}</div></section>{/if}
          {#if effectEntries.length}<section class="evidence-section effects"><h3><Activity size={14} aria-hidden="true" />Effects <b>{effectEntries.length}</b></h3><div class="evidence-stack">{#each effectEntries as [key, value]}<div class="evidence-card"><span>{label(key)}</span><EvidenceValue {value} /></div>{/each}</div></section>{/if}
          {#if authorityEntries.length}<section class="evidence-section"><h3><ShieldCheck size={14} aria-hidden="true" />Authority & policy <b>{authorityEntries.length}</b></h3><dl class="field-list authority-list">{#each authorityEntries as [key, value]}<div><dt>{label(key)}</dt><dd><EvidenceValue {value} limit={360} /></dd></div>{/each}</dl></section>{/if}
          {#if summaryEntries.length}<section class="evidence-section"><h3><Info size={14} aria-hidden="true" />Additional fields <b>{summaryEntries.length}</b></h3><dl class="field-list">{#each summaryEntries as [key, value]}<div><dt>{label(key)}</dt><dd><EvidenceValue {value} limit={360} /></dd></div>{/each}</dl></section>{/if}
        {:else}
          <section class="evidence-section"><div class="section-empty"><Inbox size={22} strokeWidth={1.5} aria-hidden="true" /><strong>No structured payload</strong><span>This event contains envelope metadata only. The complete event remains available in Raw.</span></div></section>
        {/if}

      {:else if activeTab === 'relationships'}
        <section class="evidence-section relationship-section">
          <h3><GitBranch size={14} aria-hidden="true" />Evidence relationships {#if causalCount}<b>{causalCount}</b>{/if}</h3>
          {#if relatedMissing}
            <div class="relation-missing" role="status"><strong>Not in journal</strong><span>No event matches <code>{relatedMissing}</code>. The reference may be outside this trace or never recorded.</span></div>
          {/if}
          {#if causalCount || relations?.children.length}
          <dl class="field-list causal-list">
            <div><dt>Event ID</dt><dd><code>{event.event_id}</code></dd></div>
            {#if event.parent_event_id}
              <div>
                <dt>Parent event</dt>
                <dd>
                  {#if relations?.missingParent}
                    <span class="missing-ref"><code>{event.parent_event_id}</code><em>not in journal</em></span>
                  {:else if onnavigate}
                    <button class="evidence-link" onclick={() => openRelated(event.parent_event_id)}><code>{event.parent_event_id}</code><span>Open <ChevronRight size={14} aria-hidden="true" /></span></button>
                  {:else}
                    <code>{event.parent_event_id}</code>
                  {/if}
                </dd>
              </div>
            {/if}
            {#if event.span_id}<div><dt>Span</dt><dd><code>{event.span_id}</code></dd></div>{/if}
            {#if event.parent_span_id}<div><dt>Parent span</dt><dd><code>{event.parent_span_id}</code></dd></div>{/if}
            {#if event.correlation_id}
              <div>
                <dt>Correlation</dt>
                <dd>
                  {#if oncorrelation}
                    <button class="evidence-link" onclick={() => oncorrelation?.(event.correlation_id)}><code>{event.correlation_id}</code><span>Filter <ChevronRight size={14} aria-hidden="true" /></span></button>
                  {:else}
                    <code>{event.correlation_id}</code>
                  {/if}
                </dd>
              </div>
            {/if}
            {#each relations?.children ?? [] as child}
              <div><dt>Child event</dt><dd>{#if onnavigate}<button class="evidence-link" onclick={() => openRelated(child.event_id)}><code>{child.event_id}</code><span>{child.kind} <ChevronRight size={14} aria-hidden="true" /></span></button>{:else}<code>{child.event_id}</code>{/if}</dd></div>
            {/each}
            {#each event.links as link}
              <div>
                <dt>Linked evidence</dt>
                <dd>
                  {#if resolveRelatedTarget(events, link).missing}
                    <span class="missing-ref"><code>{link}</code><em>not in journal</em></span>
                  {:else if onnavigate}
                    <button class="evidence-link" onclick={() => openRelated(link)}><code>{link}</code><span>Open <ChevronRight size={14} aria-hidden="true" /></span></button>
                  {:else}
                    <code>{link}</code>
                  {/if}
                </dd>
              </div>
            {/each}
          </dl>
          {:else}
            <div class="section-empty"><GitBranch size={22} strokeWidth={1.5} aria-hidden="true" /><strong>No linked evidence</strong><span>This event has no recorded parent, span, correlation, or linked event identifiers.</span></div>
          {/if}
        </section>

      {:else}
        <section class="evidence-section raw-section">
          <div class="section-title"><h3><Braces size={14} aria-hidden="true" />Decoded payload</h3><button class="text-action" onclick={() => writeClipboard(JSON.stringify(payload, null, 2), 'payload')}>{#if copied === 'payload'}<Check size={14} aria-hidden="true" />Copied{:else}<Copy size={14} aria-hidden="true" />Copy payload{/if}</button></div>
          <pre>{JSON.stringify(payload, null, 2)}</pre>
        </section>
        <section class="evidence-section raw-section">
          <div class="section-title"><h3><Code2 size={14} aria-hidden="true" />Event envelope</h3><button class="text-action" onclick={() => writeClipboard(JSON.stringify({ ...event, payload_json: undefined }, null, 2), 'event')}>{#if copied === 'event'}<Check size={14} aria-hidden="true" />Copied{:else}<Copy size={14} aria-hidden="true" />Copy envelope{/if}</button></div>
          <pre>{JSON.stringify({ ...event, payload_json: undefined }, null, 2)}</pre>
        </section>
      {/if}
    </div>
  {:else}
    <div class="inspector-empty"><span aria-hidden="true"><Activity size={22} strokeWidth={1.6} /></span><strong>Select an event</strong><p>Choose evidence in the timeline, time ruler, charts, or architecture canvas to inspect its data and causal chain.</p></div>
  {/if}
  {/if}
</div>

<style>
  .inspector { position: relative; display: flex; min-width: 0; min-height: 0; flex-direction: column; overflow: hidden; color: #dce3ec; background: #080b11; }
  .inspector.compact-rail { border-left: 1px solid #202a39; background: #07090d; }
  .inspector-rail { height: 100%; display: flex; align-items: center; flex-direction: column; overflow: hidden; }
  .rail-expand, .rail-tabs button { width: 100%; min-height: 48px; display: grid; place-items: center; padding: 0; border: 0; border-bottom: 1px solid #202a39; color: #8492a7; background: transparent; cursor: pointer; }
  .rail-expand:hover, .rail-tabs button:hover { color: white; background: rgba(111,123,247,.12); }
  .rail-status { width: 100%; display: grid; justify-items: center; gap: 4px; padding: 12px 4px; border-bottom: 1px solid #202a39; color: #a7b5c8; }
  .rail-status[data-status='error'], .rail-status[data-status='failed'], .rail-status[data-status='denied'] { color: #ff8f8b; }
  .rail-status b { font: 8px 'IBM Plex Mono', monospace; }
  .rail-tabs { width: 100%; }
  .rail-tabs button.active { color: #c8d5ff; background: rgba(111,123,247,.17); box-shadow: inset -2px 0 var(--blue); }
  .rail-empty { width: 100%; min-height: 52px; display: grid; place-items: center; color: #4f5c70; }
  .inspector-header { flex: 0 0 auto; min-width: 0; min-height: 74px; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px 10px 16px; border-bottom: 1px solid #202a39; background: rgba(8,11,17,.94); backdrop-filter: blur(18px); }
  .title-group { min-width: 0; display: flex; flex-direction: column; align-items: flex-start; gap: 2px; }
  .eyebrow { color: #8190a5; font-size: 10px; font-weight: 750; letter-spacing: .1em; text-transform: uppercase; }
  .title-group strong { min-width: 0; overflow: hidden; color: #f3f6fa; font-family: 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; font-size: 15px; font-weight: 750; line-height: 1.35; white-space: nowrap; text-overflow: ellipsis; }
  .event-number { min-width: 0; display: flex; align-items: center; gap: 6px; color: #8190a5; font: 10px 'IBM Plex Mono', monospace; }
  .event-number span { min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .event-number b { flex: 0 0 auto; color: #aebbd0; font-weight: 500; }
  .header-actions { flex: 0 0 auto; display: flex; gap: 5px; }
  .icon-button { width: 36px; height: 36px; display: grid; place-items: center; padding: 0; border: 1px solid #2a3547; border-radius: 6px; color: #aeb9c9; background: #0e141e; cursor: pointer; }
  .icon-button:hover { border-color: #49628f; color: white; background: #141c29; }
  .icon-button.confirmed { border-color: rgba(99,220,165,.35); color: #8fe0b8; background: rgba(99,220,165,.08); }
  .close-button { display: grid; }
  .copy-error { flex: 0 0 auto; display: flex; align-items: center; gap: 7px; padding: 8px 12px; border-bottom: 1px solid rgba(255,124,120,.25); color: #ffaaa6; background: rgba(255,124,120,.08); font-size: 11px; }
  .tab-list { flex: 0 0 auto; min-width: 0; display: grid; grid-template-columns: repeat(4, minmax(max-content,1fr)); overflow-x: auto; border-bottom: 1px solid #202a39; background: #070a0f; scrollbar-width: thin; }
  .tab-list button { min-width: 76px; min-height: 46px; display: flex; align-items: center; justify-content: center; gap: 6px; padding: 0 9px; border: 0; border-bottom: 2px solid transparent; color: #8190a5; background: transparent; font-size: 11px; font-weight: 700; cursor: pointer; white-space: nowrap; }
  .tab-list button b { min-width: 17px; padding: 1px 5px; border-radius: 999px; color: #9cabc0; background: rgba(255,255,255,.055); font: 9px 'IBM Plex Mono', monospace; }
  .tab-list button:hover { color: #d5dce6; background: #111620; }
  .tab-list button.active { border-bottom-color: #4c7dff; color: #f0f4fb; background: rgba(76,125,255,.13); }
  .tab-list button.active b { color: #c4d2ff; background: rgba(76,125,255,.18); }
  .tab-panel { flex: 1 1 auto; min-width: 0; min-height: 0; overflow-y: auto; outline: none; background: #080b11; scrollbar-color: #334157 transparent; }
  .hero-summary { padding: 17px 16px 16px; border-bottom: 1px solid #202a39; background: #0a0e15; }
  .summary-heading { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
  .category-mark, .status-badge { display: inline-flex; min-height: 24px; align-items: center; gap: 6px; padding: 3px 7px; border: 1px solid rgba(255,255,255,.12); border-radius: 999px; color: #c5d0df; background: #111722; font: 700 9px 'IBM Plex Mono', monospace; text-transform: uppercase; }
  .status-badge i { width: 6px; height: 6px; border-radius: 50%; background: #778498; }
  .category-mark[data-category='tool'] { border-color: rgba(240,185,104,.45); color: #f0c784; }
  .category-mark[data-category='model'] { border-color: rgba(198,141,255,.45); color: #d4aaff; }
  .category-mark[data-category='error'] { border-color: rgba(255,113,109,.45); color: #ffaaa6; }
  .status-badge[data-status='error'], .status-badge[data-status='failed'], .status-badge[data-status='denied'] { border-color: rgba(255,113,109,.45); color: #ffaaa6; background: rgba(255,113,109,.08); }
  .status-badge[data-status='error'] i, .status-badge[data-status='failed'] i, .status-badge[data-status='denied'] i { background: var(--red); box-shadow: 0 0 8px rgba(255,124,120,.45); }
  .status-badge[data-status='ok'], .status-badge[data-status='approved'] { border-color: rgba(95,214,160,.4); color: #91e3bd; background: rgba(95,214,160,.07); }
  .status-badge[data-status='ok'] i, .status-badge[data-status='approved'] i { background: var(--green); box-shadow: 0 0 8px rgba(99,220,165,.35); }
  .hero-summary p { margin: 15px 0 16px; color: #b7c1cf; font-size: 13px; line-height: 1.58; }
  .summary-facts { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1px; border: 1px solid #202a39; border-radius: 7px; overflow: hidden; background: #202a39; }
  .model-chip { display: inline-flex; align-items: center; gap: 7px; margin-top: 10px; padding: 6px 9px; border: 1px solid rgba(168,130,255,.22); border-radius: 6px; color: #d7c8ff; background: rgba(168,130,255,.08); font-size: 11px; }
  .model-chip strong { color: #ece4ff; font-weight: 700; }
  .model-chip span { color: #9b8cc0; font-size: 10px; text-transform: uppercase; letter-spacing: .06em; }
  .summary-correlation { display: grid; grid-template-columns: 16px auto minmax(0, 1fr); gap: 8px; align-items: center; margin-top: 10px; padding: 9px 10px; border: 1px solid #202a39; border-radius: 6px; color: #8190a5; background: #0e141e; font-size: 10px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
  .summary-correlation code { color: #c3cedd; font: 10px/1.5 'IBM Plex Mono', monospace; letter-spacing: 0; overflow-wrap: anywhere; text-transform: none; }
  .correlation-filter { min-width: 0; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center; padding: 0; border: 0; background: transparent; color: inherit; cursor: pointer; text-align: left; }
  .correlation-filter span { color: var(--blue-strong); font-size: 10px; letter-spacing: .06em; text-transform: uppercase; }
  .correlation-filter:hover span { text-decoration: underline; }
  .relation-missing, .missing-ref { display: grid; gap: 4px; }
  .relation-missing { margin-bottom: 10px; padding: 10px 12px; border: 1px solid rgba(240,185,104,.35); border-radius: 6px; background: rgba(240,185,104,.08); color: #f0c88a; font-size: 11px; }
  .missing-ref { color: #c3cedd; }
  .missing-ref em { color: #f0b968; font-style: normal; font-size: 10px; letter-spacing: .04em; text-transform: uppercase; }
  .summary-facts div { min-width: 0; display: grid; grid-template-columns: 18px minmax(0,1fr); gap: 2px 7px; align-content: start; padding: 11px; background: #0e141e; }
  .summary-facts div > :global(svg) { grid-row: 1 / 4; margin-top: 1px; color: #6c98ff; }
  .summary-facts span, .evidence-card > span { color: var(--muted); font-size: 10px; font-weight: 700; letter-spacing: .07em; text-transform: uppercase; }
  .summary-facts strong { min-width: 0; overflow: hidden; color: #e5ebf2; font-size: 12px; font-weight: 700; line-height: 1.45; text-overflow: ellipsis; white-space: nowrap; }
  .summary-facts small { color: var(--muted); font-size: 10px; line-height: 1.45; overflow-wrap: anywhere; }
  .evidence-section { min-width: 0; padding: 16px; border-bottom: 1px solid #202a39; }
  .evidence-section h3 { display: flex; min-width: 0; align-items: center; gap: 7px; margin: 0 0 11px; color: #cbd5e2; font-family: 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; font-size: 11px; font-weight: 750; letter-spacing: .055em; text-transform: uppercase; }
  .evidence-section h3 > :global(svg) { flex: 0 0 auto; color: #6c98ff; }
  .evidence-section h3 b { margin-left: auto; padding: 2px 6px; border-radius: 999px; color: #9fb4ef; background: rgba(76,125,255,.11); font: 9px 'IBM Plex Mono', monospace; }
  .evidence-stack { display: grid; gap: 8px; }
  .overview-evidence .section-title, .overview-relations .section-title { margin-bottom: 11px; }
  .overview-evidence .evidence-card { padding-block: 9px; }
  .overview-relations .causal-list { padding-inline: 10px; }
  .evidence-card { min-width: 0; padding: 11px; border: 1px solid #202a39; border-radius: 6px; background: #0a0e15; }
  .raw-section pre { margin: 8px 0 0; overflow: auto; color: #c8d0dc; font: 11.5px/1.65 'IBM Plex Mono', monospace; overflow-wrap: anywhere; white-space: pre-wrap; }
  .effects .evidence-card { border-left: 2px solid #63d7d2; }
  .field-list { margin: 0; }
  .field-list > div { display: grid; grid-template-columns: 86px minmax(0, 1fr); gap: 10px; padding: 9px 0; border-bottom: 1px solid var(--line-soft); }
  .field-list > div:last-child { border-bottom: 0; }
  .field-list dt { color: #8190a5; font-size: 11px; font-weight: 650; }
  .field-list dd { min-width: 0; margin: 0; color: #d1d9e4; font-size: 12px; line-height: 1.58; overflow-wrap: anywhere; white-space: pre-wrap; }
  .authority-list dd { color: #9fdcd3; }
  .causal-list { border: 1px solid #202a39; border-radius: 7px; padding: 0 10px; background: #0a0e15; }
  .causal-list code { min-width: 0; font: 11px/1.55 'IBM Plex Mono', monospace; overflow-wrap: anywhere; }
  .evidence-link { width: 100%; min-width: 0; display: flex; justify-content: space-between; gap: 8px; padding: 0; border: 0; color: var(--blue-strong); background: transparent; font: inherit; text-align: left; cursor: pointer; overflow-wrap: anywhere; }
  .evidence-link:hover { color: white; text-decoration: underline; }
  .evidence-link span { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 2px; color: var(--blue-strong); font: 700 10px 'Source Sans 3 Variable', sans-serif; text-transform: uppercase; }
  .section-empty { display: grid; justify-items: center; gap: 7px; padding: 22px 16px; border: 1px dashed #2a3547; border-radius: 7px; color: #748196; background: rgba(14,20,30,.45); text-align: center; }
  .section-empty > :global(svg) { margin-bottom: 2px; color: #60708a; }
  .section-empty strong { color: #b7c0ce; font-size: 12px; }
  .section-empty span { max-width: 280px; font-size: 11px; line-height: 1.5; }
  .section-title { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
  .section-title h3 { margin: 0; }
  .text-action { min-height: 32px; display: inline-flex; align-items: center; gap: 6px; padding: 0 9px; border: 1px solid #2a3547; border-radius: 5px; color: #b4c0d0; background: #0e141e; font-size: 10px; cursor: pointer; }
  .text-action:hover { border-color: #49628f; color: white; background: #141c29; }
  .raw-section pre { max-height: none; padding: 12px; overflow-x: auto; overflow-y: visible; border: 1px solid #202a39; border-radius: 7px; background: #05080d; color: #b8c3d2; }
  .inspector-empty { height: 100%; display: grid; place-content: center; justify-items: center; padding: 30px; color: #778498; text-align: center; }
  .inspector-empty > span { display: grid; width: 42px; height: 42px; place-items: center; margin-bottom: 12px; border: 1px solid var(--line); color: var(--blue-strong); background: rgba(111,123,247,.1); font-size: 20px; }
  .inspector-empty strong { color: #cbd3de; font-size: 12px; }
  .inspector-empty p { max-width: 210px; margin: 7px 0 0; font-size: 10px; line-height: 1.6; }

  @media (max-width: 1180px) {
    .close-button { display: grid; }
    .inspector.drawer { position: fixed; isolation: isolate; z-index: 9; top: 80px; right: 0; bottom: 0; width: min(480px, 94vw); height: auto; border-left: 1px solid #202a39; background: #080b11; box-shadow: -24px 0 56px rgba(0,0,0,.58); }
  }
  @media (max-width: 680px) {
    .inspector-header { min-height: 72px; padding-right: 10px; }
    .inspector.drawer { top: auto; left: 0; right: 0; bottom: 0; width: 100%; height: auto; min-height: min(520px, calc(100dvh - 64px)); max-height: calc(100dvh - 64px); border: 0; border-top: 1px solid #39445a; border-radius: 12px 12px 0 0; box-shadow: 0 -18px 50px rgba(0,0,0,.55); }
    .icon-button { width: 44px; height: 44px; }
    .tab-list button { min-height: 48px; font-size: 10.5px; }
    .tab-panel { padding-bottom: env(safe-area-inset-bottom); }
    .title-group strong { display: -webkit-box; overflow: hidden; white-space: normal; line-clamp: 2; -webkit-box-orient: vertical; -webkit-line-clamp: 2; }
  }
  @media (max-width: 360px) {
    .header-actions .icon-button:nth-child(2) { display: none; }
    .tab-list { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .tab-list button { min-width: 0; gap: 4px; padding-inline: 4px; font-size: 10px; }
    .tab-list button b { display: none; }
  }
  @media (max-width: 280px) {
    .header-actions .icon-button:first-child { display: none; }
    .tab-list button { gap: 2px; padding-inline: 2px; font-size: 9px; }
    .tab-list button :global(svg) { display: none; }
    .summary-facts { grid-template-columns: 1fr; }
    .field-list > div { grid-template-columns: 1fr; gap: 4px; }
  }
</style>
