import type {
  AssistantAvailability,
  AssistantRequest,
  AssistantResponse,
  TraceEvent,
  TraceManifest
} from './types';

export type StreamState = 'connecting' | 'live' | 'reconnecting' | 'recorded' | 'disconnected';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { Accept: 'application/json', ...init?.headers }
  });
  if (!response.ok) {
    let detail = '';
    try {
      const body = await response.json() as { error?: unknown };
      if (typeof body.error === 'string') detail = body.error;
    } catch {
      // Non-JSON proxy and server errors still receive a useful status fallback.
    }
    const message = response.status === 401
      ? 'Authentication is required.'
      : detail || `Request failed (${response.status}).`;
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}

export const api = {
  traces: () => request<TraceManifest[]>('/api/traces'),
  trace: (traceId: string) => request<TraceManifest>(`/api/traces/${encodeURIComponent(traceId)}`),
  assistants: () => request<AssistantAvailability[]>('/api/assistants'),
  askAssistant: (traceId: string, body: AssistantRequest) => request<AssistantResponse>(
    `/api/traces/${encodeURIComponent(traceId)}/assistant`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }
  ),
  events: (traceId: string) => request<TraceEvent[]>(`/api/traces/${encodeURIComponent(traceId)}/events`),
  stream: (
    traceId: string,
    onEvent: (event: TraceEvent) => void,
    onState: (state: StreamState) => void,
    onComplete?: (manifest: TraceManifest) => void
  ) => {
    const source = new EventSource(`/api/traces/${encodeURIComponent(traceId)}/stream`);
    let closed = false;
    let completed = false;

    const close = (state: StreamState = 'disconnected') => {
      if (closed) return;
      closed = true;
      source.close();
      onState(state);
    };

    source.onopen = () => {
      if (!closed) onState('live');
    };
    source.addEventListener('trace.event', (message) => {
      if (closed) return;
      onEvent(JSON.parse((message as MessageEvent).data) as TraceEvent);
    });
    source.addEventListener('trace.complete', (message) => {
      if (closed) return;
      completed = true;
      const manifest = JSON.parse((message as MessageEvent).data) as TraceManifest;
      onComplete?.(manifest);
      close('recorded');
    });
    source.onerror = () => {
      if (closed || completed) return;
      // EventSource reconnects automatically; surface reconnecting until complete arrives.
      onState('reconnecting');
    };
    return () => close(completed ? 'recorded' : 'disconnected');
  }
};
