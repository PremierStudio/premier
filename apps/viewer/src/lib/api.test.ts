import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';

afterEach(() => vi.unstubAllGlobals());

describe('assistant API', () => {
  it('posts the provider, history, and selected event to the encoded trace route', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      provider: 'claude', answer: 'Inspect event 8.', elapsed_ms: 42
    }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    vi.stubGlobal('fetch', fetch);

    await api.askAssistant('trace/id', {
      provider: 'claude',
      prompt: 'What failed?',
      selected_event_id: 'event-8',
      history: [{ role: 'user', content: 'Summarize it.' }]
    });

    expect(fetch).toHaveBeenCalledWith('/api/traces/trace%2Fid/assistant', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({
        provider: 'claude', prompt: 'What failed?', selected_event_id: 'event-8',
        history: [{ role: 'user', content: 'Summarize it.' }]
      })
    }));
  });

  it('surfaces the backend error instead of replacing it with a generic status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: 'assistant did not respond within 45 seconds' }),
      { status: 504, headers: { 'Content-Type': 'application/json' } }
    )));

    await expect(api.askAssistant('trace', { provider: 'claude', prompt: 'Help' }))
      .rejects.toThrow('assistant did not respond within 45 seconds');
  });
});

describe('request helpers', () => {
  it('loads a single trace detail and events list', async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ trace_id: 't1', integrity: 'verified' }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify([{ event_id: 'e1' }]), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    await expect(api.trace('t/1')).resolves.toMatchObject({ integrity: 'verified' });
    await expect(api.events('t/1')).resolves.toEqual([{ event_id: 'e1' }]);
    expect(fetch).toHaveBeenNthCalledWith(1, '/api/traces/t%2F1', expect.any(Object));
    expect(fetch).toHaveBeenNthCalledWith(2, '/api/traces/t%2F1/events', expect.any(Object));
  });

  it('maps 401 responses to an authentication message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 401 })));
    await expect(api.traces()).rejects.toThrow('Authentication is required.');
  });

  it('falls back to status text when the error body is not JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('nope', { status: 500 })));
    await expect(api.assistants()).rejects.toThrow('Request failed (500).');
  });

  it('ignores non-string error fields in JSON error bodies', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ error: { nested: true } }),
      { status: 502, headers: { 'Content-Type': 'application/json' } }
    )));
    await expect(api.traces()).rejects.toThrow('Request failed (502).');
  });
});

describe('stream API', () => {
  class FakeEventSource {
    static instances: FakeEventSource[] = [];
    onopen: ((event: Event) => void) | null = null;
    onerror: ((event: Event) => void) | null = null;
    private listeners = new Map<string, Array<(event: MessageEvent) => void>>();
    closed = false;
    url: string;

    constructor(url: string) {
      this.url = url;
      FakeEventSource.instances.push(this);
    }

    addEventListener(type: string, listener: (event: MessageEvent) => void) {
      const list = this.listeners.get(type) ?? [];
      list.push(listener);
      this.listeners.set(type, list);
    }

    dispatch(type: string, data: unknown) {
      for (const listener of this.listeners.get(type) ?? []) {
        listener({ data: JSON.stringify(data) } as MessageEvent);
      }
    }

    close() {
      this.closed = true;
    }
  }

  afterEach(() => {
    FakeEventSource.instances = [];
  });

  it('emits live events and records on trace.complete without reconnect thrash', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const events: unknown[] = [];
    const states: string[] = [];
    const completes: unknown[] = [];

    const close = api.stream(
      'trace-1',
      (event) => events.push(event),
      (state) => states.push(state),
      (manifest) => completes.push(manifest)
    );

    const source = FakeEventSource.instances[0];
    source.onopen?.(new Event('open'));
    source.dispatch('trace.event', { event_id: 'e1', sequence: 1 });
    source.dispatch('trace.complete', {
      trace_id: 'trace-1',
      ended_at: '2026-01-01T00:00:02Z',
      integrity: 'verified'
    });
    source.onerror?.(new Event('error'));

    expect(events).toHaveLength(1);
    expect(completes[0]).toMatchObject({ integrity: 'verified' });
    expect(states).toEqual(['live', 'recorded']);
    expect(source.closed).toBe(true);
    close();
  });

  it('reports reconnecting while the stream is still open', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    api.stream('trace-1', () => undefined, (state) => states.push(state));
    const source = FakeEventSource.instances[0];
    source.onopen?.(new Event('open'));
    source.onerror?.(new Event('error'));
    expect(states).toEqual(['live', 'reconnecting']);
  });

  it('manual close after complete stays recorded', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const states: string[] = [];
    const close = api.stream('trace-1', () => undefined, (state) => states.push(state));
    const source = FakeEventSource.instances[0];
    source.dispatch('trace.complete', { trace_id: 'trace-1', integrity: 'verified' });
    close();
    expect(states).toEqual(['recorded']);
    expect(source.closed).toBe(true);
  });

  it('ignores events after the stream has been closed', () => {
    vi.stubGlobal('EventSource', FakeEventSource as unknown as typeof EventSource);
    const events: unknown[] = [];
    const states: string[] = [];
    const close = api.stream('trace-1', (event) => events.push(event), (state) => states.push(state));
    const source = FakeEventSource.instances[0];
    close();
    close(); // second close is a no-op
    source.onopen?.(new Event('open'));
    source.dispatch('trace.event', { event_id: 'late' });
    source.dispatch('trace.complete', { trace_id: 'trace-1' });
    source.onerror?.(new Event('error'));
    expect(events).toEqual([]);
    expect(states).toEqual(['disconnected']);
  });
});
