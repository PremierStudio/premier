import { fireEvent, render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import TraceAnalytics from './TraceAnalytics.svelte';
import type { TraceEvent } from './types';

function traceEvent(
  sequence: number,
  kind = 'tool.execution',
  options: Partial<TraceEvent> = {}
): TraceEvent {
  return {
    event_id: `event-${sequence}`,
    trace_id: 'trace-analytics',
    sequence,
    timestamp: new Date(Date.parse('2026-07-13T20:00:00Z') + sequence * 1_000).toISOString(),
    kind,
    source: 'test-harness',
    payload_json: JSON.stringify({ tool: `tool-${sequence}`, summary: `event ${sequence}` }),
    actor_id: 'coordinator',
    actor_type: 'agent',
    parent_event_id: '',
    span_id: `span-${sequence}`,
    parent_span_id: '',
    correlation_id: '',
    status: 'ok',
    duration_ms: sequence * 10,
    links: [],
    ...options
  };
}

describe('TraceAnalytics', () => {
  it('explains the empty live state without inventing metrics', () => {
    render(TraceAnalytics, { props: { events: [], live: true, onselect: vi.fn() } });

    expect(screen.getByRole('status')).toHaveTextContent('Waiting for trace activity');
    expect(screen.getByText('Live')).toBeInTheDocument();
    expect(screen.queryByText('Peak activity')).not.toBeInTheDocument();
  });

  it('renders a useful single-event state and selects its chart point by keyboard', async () => {
    const onselect = vi.fn();
    const onlyEvent = traceEvent(1, 'agent.spawn', { duration_ms: 0 });
    render(TraceAnalytics, { props: { events: [onlyEvent], onselect } });

    expect(screen.getByText('1 event')).toBeInTheDocument();
    expect(screen.getByText('Not recorded')).toBeInTheDocument();
    expect(screen.getByText('None in scope')).toBeInTheDocument();
    expect(screen.queryByText('Model evidence')).not.toBeInTheDocument();
    expect(screen.getByText('No event durations were recorded.')).toBeInTheDocument();

    const point = screen.getByRole('button', { name: /1 event at start/i });
    await fireEvent.keyDown(point, { key: 'Enter' });
    expect(onselect).toHaveBeenCalledWith(onlyEvent);
  });

  it('shows issue timing, latency leaders, and truthful event mix', () => {
    const events = [
      traceEvent(0, 'agent.spawn', { duration_ms: 20 }),
      traceEvent(1, 'tool.execution', { duration_ms: 400 }),
      traceEvent(2, 'model.response', { duration_ms: 200 }),
      traceEvent(3, 'tool.error', { status: 'error', duration_ms: 50 }),
      traceEvent(4, 'process.exit', { duration_ms: 0 })
    ];
    render(TraceAnalytics, { props: { events, onselect: vi.fn() } });

    expect(screen.getByText('Issue rate').parentElement).toHaveTextContent('20%');
    expect(screen.getByText('Event latency p95').parentElement).toHaveTextContent('400 ms');
    const mix = screen.getByRole('list', { name: 'Event category distribution' });
    expect(mix).toHaveTextContent('Agent20%');
    expect(mix).toHaveTextContent('Issue20%');
    expect(screen.getByRole('button', { name: /Issue at \+3\.0 s/i })).toBeInTheDocument();
  });

  it('uses chart and latency interactions to open the underlying real event', async () => {
    const user = userEvent.setup();
    const onselect = vi.fn();
    const slowTool = traceEvent(1, 'tool.execution', { duration_ms: 950 });
    const issue = traceEvent(2, 'agent.error', { status: 'failed', duration_ms: 20 });
    const events = [traceEvent(0, 'agent.spawn'), slowTool, issue, traceEvent(3, 'model.response', { duration_ms: 40 })];
    render(TraceAnalytics, { props: { events, selectedEventId: issue.event_id, onselect } });

    await user.click(screen.getByRole('button', { name: /Inspect slowest Tool event/i }));
    expect(onselect).toHaveBeenLastCalledWith(slowTool);

    await user.click(screen.getByRole('button', { name: /Issue at \+2\.0 s/i }));
    expect(onselect).toHaveBeenLastCalledWith(issue);
  });

  it('shows token attribution and captured system, developer, user, and tool context', async () => {
    const user = userEvent.setup();
    const onselect = vi.fn();
    const model = traceEvent(1, 'model.response', {
      payload_json: JSON.stringify({
        provider: 'openai', model: 'gpt-test', system_prompt: 'System contract', developer_prompt: 'Developer instruction',
        messages: [{ role: 'user', content: 'User request' }], tools: [{ name: 'search', input_schema: { type: 'object' } }],
        usage: { input_tokens: 100, output_tokens: 40, total_tokens: 140, input_tokens_details: { cached_tokens: 25 }, input_tokens_by_role: { system: 20, developer: 30, user: 10, tool: 40 }, cost_usd: .003 },
        response: 'Recorded answer'
      })
    });
    render(TraceAnalytics, { props: { events: [model], onselect } });

    expect(screen.getByText('Context, tokens & cost')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Usage by model and actor' })).toHaveTextContent('gpt-test');
    expect(screen.getByLabelText('Model usage totals')).toHaveTextContent('140');
    await user.click(screen.getByText('System · Developer · User · Tool schema'));
    expect(screen.getByText('System contract')).toBeInTheDocument();
    expect(screen.getByText('Developer instruction')).toBeInTheDocument();
    expect(screen.getByText('User request')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Open event #1' }));
    expect(onselect).toHaveBeenCalledWith(model);
  });
});
