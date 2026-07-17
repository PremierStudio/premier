<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from './api';
  import { eventSummary } from './analysis';
  import { renderAssistantMarkdown } from './markdown';
  import PremierSelect from './PremierSelect.svelte';
  import type {
    AssistantAvailability,
    AssistantHistoryMessage,
    TraceEvent
  } from './types';

  let { traceId, selectedEvent = null, onclose }: {
    traceId: string;
    selectedEvent?: TraceEvent | null;
    onclose?: () => void;
  } = $props();

  type Scope = 'run' | 'event';
  type ChatMessage = AssistantHistoryMessage & { id: number; provider?: string; elapsedMs?: number };

  const MAX_DISPLAY_MESSAGES = 12;
  const MAX_RETAINED_MESSAGES = 24;
  const MAX_HISTORY_CHARS = 12_000;
  const sendShortcutLabel = typeof navigator !== 'undefined' && navigator.platform.includes('Mac') ? '⌘' : 'Ctrl';
  const starters = [
    'Summarize the run and identify the highest-impact issue.',
    'Explain the critical path and where time was spent.',
    'What evidence should I inspect next, and why?'
  ];

  let providers = $state<AssistantAvailability[]>([]);
  let provider = $state('');
  let scope = $state<Scope>('run');
  let prompt = $state('');
  let messages = $state<ChatMessage[]>([]);
  let loadingProviders = $state(true);
  let waiting = $state(false);
  let loadError = $state('');
  let sendError = $state('');
  let providerNotice = $state('');
  let messageId = 0;
  let textarea: HTMLTextAreaElement;

  const availableProviders = $derived(providers.filter((item) => item.available));
  const unavailableProviders = $derived(providers.filter((item) => !item.available));
  const selectedProvider = $derived(providers.find((item) => item.provider === provider) ?? null);
  const displayedMessages = $derived(messages.slice(-MAX_DISPLAY_MESSAGES));
  const hiddenMessageCount = $derived(Math.max(0, messages.length - displayedMessages.length));
  const canSubmit = $derived(Boolean(traceId && provider && prompt.trim() && !waiting && selectedProvider?.available));

  $effect(() => {
    if (!selectedEvent && scope === 'event') scope = 'run';
  });

  onMount(loadProviders);

  async function loadProviders(): Promise<void> {
    loadingProviders = true;
    loadError = '';
    try {
      providers = await api.assistants();
      if (!providers.some((item) => item.provider === provider && item.available)) {
        provider = providers.find((item) => item.available)?.provider ?? '';
      }
    } catch (error) {
      loadError = error instanceof Error ? error.message : 'Could not discover local assistants.';
    } finally {
      loadingProviders = false;
    }
  }

  function useStarter(starter: string): void {
    prompt = starter;
    textarea?.focus();
  }

  function changeProvider(next: string): void {
    if (next !== provider && messages.length) {
      messages = [];
      sendError = '';
      providerNotice = 'Conversation cleared because each provider receives its own context.';
    }
    provider = next;
  }

  async function submit(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    const question = prompt.trim();
    if (!canSubmit || !question) return;

    const priorHistory = boundedHistory(messages);
    const userMessage: ChatMessage = { id: ++messageId, role: 'user', content: question };
    messages = [...messages, userMessage].slice(-MAX_RETAINED_MESSAGES);
    prompt = '';
    sendError = '';
    waiting = true;
    try {
      const response = await api.askAssistant(traceId, {
        provider,
        prompt: question,
        history: priorHistory,
        ...(scope === 'event' && selectedEvent ? { selected_event_id: selectedEvent.event_id } : {})
      });
      const answerMessage: ChatMessage = {
        id: ++messageId,
        role: 'assistant',
        content: response.answer,
        provider: response.provider,
        elapsedMs: response.elapsed_ms
      };
      messages = [...messages, answerMessage].slice(-MAX_RETAINED_MESSAGES);
    } catch (error) {
      messages = messages.filter((message) => message.id !== userMessage.id);
      sendError = error instanceof Error ? error.message : 'The local assistant did not respond.';
      prompt = question;
    } finally {
      waiting = false;
    }
  }

  function boundedHistory(input: ChatMessage[]): AssistantHistoryMessage[] {
    const result: AssistantHistoryMessage[] = [];
    let remaining = MAX_HISTORY_CHARS;
    for (const message of input.slice(-MAX_DISPLAY_MESSAGES).reverse()) {
      if (remaining === 0) break;
      const content = message.content.slice(0, remaining);
      result.unshift({ role: message.role, content });
      remaining -= content.length;
    }
    return result;
  }

  function submitShortcut(event: KeyboardEvent): void {
    if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
      event.preventDefault();
      textarea?.form?.requestSubmit();
    }
  }

  function elapsedLabel(ms: number): string {
    return ms < 1_000 ? `${ms} ms` : `${(ms / 1_000).toFixed(1)} s`;
  }
</script>

<section class="assistant-workspace" aria-labelledby="assistant-title">
  <header class="assistant-header">
    <div class="assistant-identity">
      <span class="assistant-mark" aria-hidden="true">
        <svg viewBox="0 0 24 24"><path d="M12 3.5a8.5 8.5 0 1 0 8.5 8.5M12 1v5m0 12v5M1 12h5m12 0h5"/><circle cx="12" cy="12" r="2.5"/></svg>
      </span>
      <div>
        <span class="eyebrow">Trace copilot</span>
        <h2 id="assistant-title">Ask your local AI</h2>
      </div>
    </div>
    {#if selectedProvider}
      <span class="privacy-note"><i aria-hidden="true"></i>{selectedProvider.label} CLI</span>
    {/if}
    {#if onclose}<button class="assistant-close" type="button" onclick={onclose}>Close AI workspace</button>{/if}
  </header>

  <div class="assistant-controls">
    <div class="provider-control">
      <label for="assistant-provider">Local provider</label>
      {#if loadingProviders}
        <div class="provider-loading" role="status"><span aria-hidden="true"></span>Discovering installed CLIs…</div>
      {:else if loadError}
        <div class="provider-error" role="alert">
          <span>{loadError}</span>
          <button type="button" onclick={loadProviders}>Retry</button>
        </div>
      {:else}
        <PremierSelect
          label="Local provider"
          value={provider}
          options={availableProviders.length
            ? availableProviders.map((item) => ({
                value: item.provider,
                label: item.label,
                description: item.provider === 'claude'
                  ? 'Anthropic · verified local CLI'
                  : item.provider === 'codex'
                    ? 'OpenAI · verified local CLI'
                    : 'Capability-checked local CLI'
              }))
            : [{ value: '', label: 'No safe provider available', disabled: true }]}
          disabled={!availableProviders.length || waiting}
          onchange={changeProvider}
        />
      {/if}
    </div>

    <fieldset class="scope-control">
      <legend>Context scope</legend>
      <div class="scope-options">
        <label class:active={scope === 'run'}>
          <input type="radio" name="assistant-scope" value="run" bind:group={scope} disabled={waiting} />
          <span><strong>Run context</strong><small>Manifest + recent events</small></span>
        </label>
        <label class:active={scope === 'event'} class:disabled={!selectedEvent}>
          <input type="radio" name="assistant-scope" value="event" bind:group={scope} disabled={!selectedEvent || waiting} />
          <span><strong>Selected event</strong><small>{selectedEvent ? `#${selectedEvent.sequence} · ${eventSummary(selectedEvent)}` : 'Select an event first'}</small></span>
        </label>
      </div>
    </fieldset>
    <p class="context-disclosure">Premier redacts sensitive field names, bounds the context, and invokes the selected CLI with its verified read-only/tool-deny flags. The provider may still use its configured account and network.</p>
  </div>

  {#if unavailableProviders.length && !loadingProviders}
    <details class="unavailable-providers">
      <summary>{unavailableProviders.length} unavailable provider{unavailableProviders.length === 1 ? '' : 's'}</summary>
      <ul>
        {#each unavailableProviders as item (item.provider)}
          <li><strong>{item.label}</strong><span>{item.reason ?? (item.installed ? 'Safe invocation is unavailable.' : 'CLI is not installed.')}</span></li>
        {/each}
      </ul>
    </details>
  {/if}

  <div class="conversation" aria-live="polite" aria-busy={waiting}>
    {#if providerNotice}<div class="provider-notice" role="status">{providerNotice}</div>{/if}
    {#if hiddenMessageCount > 0}
      <div class="history-boundary">{hiddenMessageCount} earlier message{hiddenMessageCount === 1 ? '' : 's'} hidden</div>
    {/if}
    {#if displayedMessages.length === 0}
      <div class="conversation-empty">
        <span aria-hidden="true">⌁</span>
        <strong>Interrogate the evidence</strong>
        <p>Ask for a diagnosis, a causal explanation, or the next evidence worth inspecting. The selected scope is attached by Premier.</p>
      </div>
    {:else}
      {#each displayedMessages as message (message.id)}
        <article class:answer={message.role === 'assistant'} class="message">
          <div class="message-meta">
            <strong>{message.role === 'assistant' ? providers.find((item) => item.provider === message.provider)?.label ?? message.provider ?? 'Assistant' : 'You'}</strong>
            {#if message.elapsedMs !== undefined}<span>{elapsedLabel(message.elapsedMs)}</span>{/if}
          </div>
          {#if message.role === 'assistant'}
            <div class="markdown-content">{@html renderAssistantMarkdown(message.content)}</div>
          {:else}
            <p>{message.content}</p>
          {/if}
        </article>
      {/each}
    {/if}
    {#if waiting}
      <div class="waiting-message" role="status">
        <span aria-hidden="true"><i></i><i></i><i></i></span>
        <div><strong>{selectedProvider?.label ?? 'Local assistant'} is analyzing the trace</strong><small>This can take up to 45 seconds.</small></div>
      </div>
    {/if}
  </div>

  <div class="starter-row" aria-label="Prompt starters">
    {#each starters as starter, index (starter)}
      <button type="button" onclick={() => useStarter(starter)} disabled={waiting || !availableProviders.length}>
        <span>{index + 1}</span>{starter}
      </button>
    {/each}
  </div>

  <form class="composer" onsubmit={submit}>
    <label for="assistant-prompt">Question for your local AI</label>
    <div class="composer-field" class:error={Boolean(sendError)}>
      <textarea
        id="assistant-prompt"
        name="assistant-prompt"
        bind:this={textarea}
        bind:value={prompt}
        onkeydown={submitShortcut}
        maxlength="6000"
        rows="3"
        placeholder={availableProviders.length ? 'Ask what happened, why it happened, or what to inspect next…' : 'Install or enable a safe local provider to ask about this trace.'}
        disabled={waiting || !availableProviders.length}
      ></textarea>
      <div class="composer-footer">
        <span>{prompt.length.toLocaleString()} / 6,000 · {sendShortcutLabel} Enter to send</span>
        <button type="submit" disabled={!canSubmit}>
          {#if waiting}<i class="send-spinner" aria-hidden="true"></i>Waiting{:else}Ask {selectedProvider?.label ?? 'assistant'}<span aria-hidden="true">↗</span>{/if}
        </button>
      </div>
    </div>
    {#if sendError}<p class="send-error" role="alert"><strong>Request failed.</strong> {sendError} Your question is still in the composer.</p>{/if}
  </form>
</section>

<style>
  .assistant-workspace { --assistant-line: rgba(255,255,255,.075); width: 100%; height: 100%; min-width: 0; min-height: 0; display: grid; grid-template-rows: auto auto auto minmax(0, 1fr) auto auto; overflow: hidden; border: 1px solid var(--assistant-line); border-radius: 10px; color: #e9edf4; background: linear-gradient(145deg, rgba(20,27,39,.86), rgba(7,9,13,.96) 42%, rgba(7,8,11,.98)); box-shadow: inset 0 1px rgba(255,255,255,.06), 0 22px 58px rgba(0,0,0,.3); font-family: 'Source Sans 3 Variable', 'Source Sans 3', sans-serif; backdrop-filter: blur(22px); }
  .assistant-header { grid-row: 1; min-width: 0; min-height: 68px; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 12px 16px; border-bottom: 1px solid var(--assistant-line); background: linear-gradient(90deg, rgba(111,123,247,.12), rgba(255,255,255,.014) 40%, transparent); }
  .assistant-identity { min-width: 0; display: flex; align-items: center; gap: 11px; }
  .assistant-mark { flex: 0 0 auto; width: 34px; height: 34px; display: grid; place-items: center; border: 1px solid rgba(158,170,255,.38); border-radius: 8px; color: #83a3ff; background: rgba(111,123,247,.15); box-shadow: inset 0 1px rgba(255,255,255,.1), 0 8px 24px rgba(25,51,127,.18); }
  .assistant-mark svg { width: 21px; fill: none; stroke: currentColor; stroke-width: 1.5; }
  .eyebrow { display: block; color: #7e8da3; font-size: 9px; font-weight: 800; letter-spacing: .14em; text-transform: uppercase; }
  h2 { margin: 2px 0 0; color: #f4f7fb; font: 750 16px/1.2 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; }
  .privacy-note { flex: 0 0 auto; display: inline-flex; align-items: center; gap: 6px; color: #9eabc0; font-size: 10px; font-weight: 650; }
  .privacy-note i { width: 6px; height: 6px; border-radius: 50%; background: #63dca5; box-shadow: 0 0 10px rgba(99,220,165,.45); }
  .assistant-close { flex: 0 0 auto; min-height: 30px; padding: 0 9px; border: 1px solid #354156; border-radius: 6px; color: #b8c3d3; background: #111722; font-size: 10px; font-weight: 700; cursor: pointer; }
  .assistant-close:hover { border-color: #596b89; color: white; }
  .assistant-controls { grid-row: 2; min-width: 0; display: grid; grid-template-columns: minmax(160px,.65fr) minmax(300px,1.35fr); gap: 14px; padding: 13px 16px; border-bottom: 1px solid var(--assistant-line); background: rgba(3,5,8,.28); }
  label, legend { color: #8391a6; font-size: 9px; font-weight: 800; letter-spacing: .1em; text-transform: uppercase; }
  .provider-control { min-width: 0; display: grid; align-content: start; gap: 6px; }
  textarea:focus-visible { border-color: #9eaaff; box-shadow: 0 0 0 3px rgba(111,123,247,.18); }
  .provider-loading, .provider-error { min-height: 42px; display: flex; align-items: center; gap: 8px; color: #9aa7b9; font-size: 11px; }
  .provider-loading > span { width: 13px; height: 13px; border: 2px solid #344159; border-top-color: #9eaaff; border-radius: 50%; animation: spin .8s linear infinite; }
  .provider-error { justify-content: space-between; color: #ffaaa6; }
  .provider-error button { padding: 5px 8px; border: 1px solid #744944; border-radius: 4px; color: #ffc0bc; background: rgba(255,113,109,.08); cursor: pointer; }
  fieldset { min-width: 0; margin: 0; padding: 0; border: 0; }
  legend { margin-bottom: 6px; }
  .scope-options { min-width: 0; display: grid; grid-template-columns: 1fr 1fr; gap: 6px; }
  .scope-options label { min-width: 0; min-height: 42px; display: flex; align-items: center; gap: 8px; padding: 6px 9px; border: 1px solid #2c3749; border-radius: 6px; color: inherit; background: rgba(12,17,25,.8); cursor: pointer; text-transform: none; letter-spacing: 0; }
  .scope-options label:hover { border-color: #435572; }
  .scope-options label.active { border-color: rgba(158,170,255,.55); background: rgba(111,123,247,.12); box-shadow: inset 0 -2px #6f7bf7; }
  .scope-options label.disabled { opacity: .48; cursor: not-allowed; }
  .scope-options input { flex: 0 0 auto; width: 14px; height: 14px; accent-color: #9eaaff; }
  .scope-options span { min-width: 0; }
  .scope-options strong, .scope-options small { display: block; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .scope-options strong { color: #dce3ed; font-size: 11px; }
  .scope-options small { margin-top: 2px; color: #7f8da1; font-size: 9px; font-weight: 500; }
  .context-disclosure { grid-column: 1 / -1; margin: -2px 0 0; color: #718096; font-size: 9px; line-height: 1.45; }
  .unavailable-providers { grid-row: 3; border-bottom: 1px solid var(--assistant-line); background: rgba(8,11,16,.64); }
  .unavailable-providers summary { padding: 8px 16px; color: #7f8da1; font-size: 10px; cursor: pointer; }
  .unavailable-providers ul { display: grid; gap: 7px; margin: 0; padding: 0 16px 11px 34px; }
  .unavailable-providers li { color: #8795a9; font-size: 10px; line-height: 1.35; }
  .unavailable-providers li strong { margin-right: 6px; color: #b7c1cf; }
  .conversation { grid-row: 4; min-width: 0; min-height: 0; overflow-y: auto; overscroll-behavior: contain; padding: 14px 16px; scrollbar-color: #354156 transparent; }
  .conversation-empty { height: 100%; min-height: 100px; display: grid; place-content: center; justify-items: center; gap: 5px; padding: 20px; text-align: center; }
  .conversation-empty > span { color: #9eaaff; font-size: 28px; }
  .conversation-empty strong { color: #dfe6f0; font-size: 13px; }
  .conversation-empty p { max-width: 410px; margin: 0; color: #7f8da1; font-size: 11px; line-height: 1.55; }
  .history-boundary { margin: 0 auto 10px; color: #687589; font-size: 9px; text-align: center; }
  .provider-notice { margin: 0 0 10px; padding: 7px 9px; border: 1px solid rgba(158,170,255,.2); border-radius: 6px; color: #91a3bd; background: rgba(111,123,247,.07); font-size: 10px; text-align: center; }
  .message { max-width: min(86%, 680px); margin: 0 0 12px auto; padding: 10px 12px; border: 1px solid rgba(158,170,255,.24); border-radius: 8px 8px 2px 8px; background: rgba(111,123,247,.1); }
  .message.answer { margin-right: auto; margin-left: 0; border-color: var(--assistant-line); border-radius: 8px 8px 8px 2px; background: rgba(255,255,255,.026); box-shadow: inset 2px 0 #6f7bf7; }
  .message-meta { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .message-meta strong { color: #aebbd0; font-size: 9px; font-weight: 750; letter-spacing: .06em; text-transform: uppercase; }
  .message-meta span { color: #657388; font: 9px 'IBM Plex Mono', monospace; }
  .message > p { margin: 5px 0 0; color: #d9e0e9; font-size: 12px; line-height: 1.58; white-space: pre-wrap; overflow-wrap: anywhere; }
  .markdown-content { min-width: 0; margin-top: 9px; color: #d9e0e9; font-size: 12px; line-height: 1.62; overflow-wrap: anywhere; }
  .markdown-content :global(> :first-child) { margin-top: 0; }
  .markdown-content :global(> :last-child) { margin-bottom: 0; }
  .markdown-content :global(h1), .markdown-content :global(h2), .markdown-content :global(h3), .markdown-content :global(h4) { margin: 18px 0 7px; color: #f2f5fa; font-family: 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; font-weight: 720; line-height: 1.25; letter-spacing: -.012em; }
  .markdown-content :global(h1) { padding-bottom: 8px; border-bottom: 1px solid rgba(255,255,255,.09); font-size: 18px; }
  .markdown-content :global(h2) { padding-left: 9px; border-left: 2px solid #6790ff; font-size: 15px; }
  .markdown-content :global(h3) { color: #dfe6f1; font-size: 13px; }
  .markdown-content :global(h4) { color: #cbd5e3; font-size: 12px; }
  .markdown-content :global(p) { margin: 7px 0 11px; }
  .markdown-content :global(strong) { color: #f0f4fa; font-weight: 720; }
  .markdown-content :global(em) { color: #b9c6da; }
  .markdown-content :global(ul), .markdown-content :global(ol) { display: grid; gap: 5px; margin: 8px 0 12px; padding-left: 21px; }
  .markdown-content :global(li) { padding-left: 2px; }
  .markdown-content :global(li::marker) { color: #789bff; font-weight: 700; }
  .markdown-content :global(li > p) { margin: 0; }
  .markdown-content :global(code) { padding: 1px 5px; border: 1px solid rgba(126,163,255,.18); border-radius: 4px; color: #c4d2ff; background: rgba(65,105,225,.1); font: 10.5px/1.5 'IBM Plex Mono', monospace; overflow-wrap: anywhere; }
  .markdown-content :global(pre) { max-width: 100%; margin: 10px 0 13px; overflow: auto; border: 1px solid #263247; border-radius: 7px; background: #080c12; box-shadow: inset 3px 0 #315bcf; }
  .markdown-content :global(pre code) { display: block; min-width: max-content; padding: 11px 13px; border: 0; border-radius: 0; color: #d5deeb; background: transparent; font-size: 10px; line-height: 1.6; overflow-wrap: normal; }
  .markdown-content :global(blockquote) { margin: 10px 0; padding: 8px 11px; border-left: 2px solid #5277dc; color: #aebbd0; background: rgba(65,105,225,.065); }
  .markdown-content :global(blockquote p) { margin: 0; }
  .markdown-content :global(a) { color: #8caaff; text-decoration-color: rgba(140,170,255,.42); text-underline-offset: 2px; }
  .markdown-content :global(a:hover) { color: #b8c9ff; text-decoration-color: currentColor; }
  .markdown-content :global(hr) { height: 1px; margin: 15px 0; border: 0; background: rgba(255,255,255,.09); }
  .markdown-content :global(table) { display: block; width: 100%; max-width: 100%; margin: 10px 0 13px; overflow-x: auto; border-collapse: collapse; font-size: 10px; }
  .markdown-content :global(th), .markdown-content :global(td) { padding: 6px 8px; border: 1px solid #263247; text-align: left; white-space: nowrap; }
  .markdown-content :global(th) { color: #c7d2e2; background: #111722; }
  .markdown-content :global(.markdown-image-label) { color: #78879d; font-style: italic; }
  .waiting-message { display: flex; align-items: center; gap: 10px; margin-top: 4px; color: #aeb9c8; }
  .waiting-message > span { display: flex; gap: 3px; padding: 8px 10px; border: 1px solid var(--assistant-line); border-radius: 8px 8px 8px 2px; background: rgba(255,255,255,.025); }
  .waiting-message i { width: 4px; height: 4px; border-radius: 50%; background: #9eaaff; animation: pulse 1.1s infinite ease-in-out; }
  .waiting-message i:nth-child(2) { animation-delay: .16s; }.waiting-message i:nth-child(3) { animation-delay: .32s; }
  .waiting-message strong, .waiting-message small { display: block; }
  .waiting-message strong { font-size: 11px; }.waiting-message small { margin-top: 2px; color: #718096; font-size: 9px; }
  .starter-row { grid-row: 5; min-width: 0; display: flex; gap: 6px; overflow-x: auto; padding: 10px 16px 0; border-top: 1px solid var(--assistant-line); }
  .starter-row button { flex: 0 0 auto; max-width: 250px; display: flex; align-items: center; gap: 7px; padding: 7px 9px; border: 1px solid #293548; border-radius: 6px; color: #9eacbf; text-align: left; background: rgba(13,19,28,.8); font-size: 9px; cursor: pointer; }
  .starter-row button:hover { border-color: #496086; color: #d9e2ef; background: rgba(111,123,247,.09); }
  .starter-row button:disabled { opacity: .42; cursor: not-allowed; }
  .starter-row button span { flex: 0 0 auto; width: 16px; height: 16px; display: grid; place-items: center; border-radius: 4px; color: #9db3f2; background: rgba(111,123,247,.16); font: 8px 'IBM Plex Mono', monospace; }
  .composer { grid-row: 6; padding: 10px 16px 16px; }
  .composer > label { display: block; margin-bottom: 6px; }
  .composer-field { overflow: hidden; border: 1px solid #344156; border-radius: 8px; background: rgba(10,14,20,.96); box-shadow: inset 0 1px rgba(255,255,255,.025); }
  .composer-field:focus-within { border-color: #9eaaff; box-shadow: 0 0 0 3px rgba(111,123,247,.15); }
  .composer-field.error { border-color: rgba(255,113,109,.55); }
  textarea { box-sizing: border-box; width: 100%; min-height: 72px; max-height: 170px; resize: vertical; display: block; padding: 10px 11px 6px; border: 0; outline: 0; color: #e6ebf2; background: transparent; font: 12px/1.5 'Source Sans 3 Variable', sans-serif; }
  textarea::placeholder { color: #5f6d80; }
  .composer-footer { min-width: 0; min-height: 38px; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 5px 6px 6px 11px; border-top: 1px solid rgba(255,255,255,.045); }
  .composer-footer > span { min-width: 0; overflow: hidden; color: #667489; font-size: 9px; white-space: nowrap; text-overflow: ellipsis; }
  .composer-footer button { min-height: 29px; display: inline-flex; align-items: center; gap: 7px; padding: 0 10px; border: 1px solid #567df0; border-radius: 5px; color: white; background: #6f7bf7; font-size: 10px; font-weight: 700; cursor: pointer; }
  .composer-footer button:hover { background: #4f5bd5; }.composer-footer button:disabled { border-color: #2e3848; color: #637085; background: #171d27; cursor: not-allowed; }
  .send-spinner { width: 10px; height: 10px; border: 1px solid rgba(255,255,255,.35); border-top-color: white; border-radius: 50%; animation: spin .8s linear infinite; }
  .send-error { margin: 7px 2px 0; color: #e89b97; font-size: 10px; line-height: 1.4; }.send-error strong { color: #ffb3af; }
  button:focus-visible, summary:focus-visible, .scope-options label:has(input:focus-visible) { outline: 2px solid #7c9cff; outline-offset: 2px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes pulse { 0%,70%,100% { opacity: .3; transform: translateY(0); } 35% { opacity: 1; transform: translateY(-2px); } }
  @media (max-width: 720px) { .assistant-controls { grid-template-columns: 1fr; }.scope-options { grid-template-columns: 1fr; }.privacy-note { display: none; }.message { max-width: 94%; }.starter-row button { max-width: 220px; } }
  @media (max-height: 620px) {
    .assistant-workspace { grid-template-rows: auto auto 0 minmax(40px, 1fr) 0 auto; overflow: hidden; }
    .assistant-header { min-height: 52px; padding-block: 8px; background: rgba(9, 13, 20, .98); }
    .assistant-controls { grid-template-columns: minmax(130px, .55fr) minmax(280px, 1.45fr); gap: 8px; padding-block: 8px; }
    .context-disclosure { display: none; }
    .unavailable-providers { display: none; }
    .scope-options { grid-template-columns: 1fr 1fr; }
    .scope-options label { height: 36px; min-height: 36px; }
    .conversation { min-height: 0; padding-block: 8px; }
    .conversation-empty { min-height: 54px; padding: 8px; }
    .conversation-empty > span, .conversation-empty p { display: none; }
    .starter-row { display: none; }
    .composer { padding-block: 6px 8px; }
    textarea { min-height: 44px; height: 44px; padding-block: 7px 4px; resize: none; }
    .composer-footer { min-height: 32px; }
  }
  @media (prefers-reduced-motion: reduce) { .provider-loading > span, .send-spinner, .waiting-message i { animation: none; } }
</style>
