import { fireEvent, render, screen, within } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import TraceComparison from './TraceComparison.svelte';
import type { TraceEvent, TraceManifest } from './types';

const manifest = (traceId: string, overrides: Partial<TraceManifest> = {}): TraceManifest => ({
  format_version: 1, trace_id: traceId, name: traceId === 'base' ? 'Baseline run' : 'Current run', command: ['codex'],
  started_at: '2026-07-15T12:00:00Z', ended_at: '2026-07-15T12:00:04Z', exit_code: 0, journal: null, ...overrides
});

const event = (traceId: string, sequence: number, kind: string, overrides: Partial<TraceEvent> = {}): TraceEvent => ({
  event_id: `${traceId}-${sequence}`, trace_id: traceId, sequence, timestamp: `2026-07-15T12:00:0${sequence}Z`, kind,
  source: 'sdk', payload_json: '{}', actor_id: 'coordinator', actor_type: 'agent', parent_event_id: '',
  span_id: `${traceId}-span-${sequence}`, parent_span_id: '', correlation_id: `${traceId}-job`, status: 'ok', duration_ms: 10, links: [], ...overrides
});

describe('TraceComparison', () => {
  it('renders run health, semantic counts, field changes, and operational deltas', async () => {
    const onselectCurrent = vi.fn();
    const baselineEvents = [
      event('base', 1, 'model.response', { duration_ms: 200, payload_json: '{"model":"gpt-5","response":"old","usage":{"total_tokens":100},"cost_usd":0.1}' }),
      event('base', 2, 'tool.execution', { payload_json: '{"tool":"grep"}' })
    ];
    const currentEvents = [
      event('current', 1, 'model.response', { duration_ms: 500, status: 'warning', payload_json: '{"model":"gpt-5.1","response":"new","usage":{"total_tokens":160},"cost_usd":0.18}' }),
      event('current', 2, 'tool.execution', { payload_json: '{"tool":"browser"}' })
    ];
    render(TraceComparison, { props: { baseline: manifest('base'), current: manifest('current'), baselineEvents, currentEvents, onselectCurrent } });

    expect(screen.getByRole('region', { name: 'Trace comparison' })).toBeInTheDocument();
    expect(screen.getByText('Baseline run')).toBeInTheDocument();
    expect(screen.getByText('Current run')).toBeInTheDocument();
    expect(screen.getByLabelText('Changed events')).toHaveTextContent('1');
    expect(screen.getByLabelText('Added events')).toHaveTextContent('1');
    expect(screen.getByLabelText('Removed events')).toHaveTextContent('1');

    const changed = screen.getByTestId('comparison-changed-0');
    expect(within(changed).getByText('payload.model')).toBeInTheDocument();
    expect(within(changed).getByText('+300 ms')).toBeInTheDocument();
    expect(within(changed).getByText('+60 tok')).toBeInTheDocument();
    expect(within(changed).getByText('+$0.08')).toBeInTheDocument();
    await fireEvent.click(within(changed).getByRole('button', { name: /inspect current event/i }));
    expect(onselectCurrent).toHaveBeenCalledWith(expect.objectContaining({ event_id: 'current-1' }));
  });

  it('renders issue metrics truthfully for each side', () => {
    const baselineEvents = [event('base', 1, 'tool.error', { status: 'error' })];
    const currentEvents = [event('current', 1, 'tool.execution')];
    render(TraceComparison, {
      props: {
        baseline: manifest('base', { exit_code: 1 }), current: manifest('current'), baselineEvents, currentEvents
      }
    });
    const baselineCard = screen.getByLabelText('Baseline run summary');
    expect(baselineCard).toHaveTextContent('Failed');
    expect(baselineCard).toHaveTextContent('1 issue');
    const currentCard = screen.getByLabelText('Current run summary');
    expect(currentCard).toHaveTextContent('Passed');
    expect(currentCard).toHaveTextContent('0 issues');
  });

  it('shows a useful no-difference state when regenerated ids are the only changes', () => {
    render(TraceComparison, {
      props: {
        baseline: manifest('base'), current: manifest('current'),
        baselineEvents: [event('base', 1, 'tool.execution', { payload_json: '{"tool":"search","query":"same"}' })],
        currentEvents: [event('current', 9, 'tool.execution', { payload_json: '{"tool":"search","query":"same"}' })]
      }
    });
    expect(screen.getByText('No meaningful differences')).toBeInTheDocument();
    expect(screen.getByText(/generated ids and ordering noise are ignored/i)).toBeInTheDocument();
  });

  it('handles empty traces without offering dead navigation', () => {
    render(TraceComparison, { props: { baseline: manifest('base'), current: manifest('current'), baselineEvents: [], currentEvents: [] } });
    expect(screen.getByText('No evidence to compare')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /inspect current event/i })).not.toBeInTheDocument();
  });
});
