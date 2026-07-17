import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import InvestigationSummary from './InvestigationSummary.svelte';
import type { TraceEvent, TraceManifest } from './types';

const trace: TraceManifest = {
  format_version: 1, trace_id: 'trace-a', command: ['codex'], started_at: '2026-07-15T12:00:00Z',
  ended_at: '2026-07-15T12:00:04Z', exit_code: 1, journal: null
};

const event = (sequence: number, kind: string, overrides: Partial<TraceEvent> = {}): TraceEvent => ({
  event_id: `event-${sequence}`, trace_id: 'trace-a', sequence, timestamp: `2026-07-15T12:00:0${sequence}Z`, kind,
  source: 'sdk', payload_json: '{}', actor_id: 'coordinator', actor_type: 'agent', parent_event_id: '',
  span_id: `span-${sequence}`, parent_span_id: '', correlation_id: 'job', status: 'ok', duration_ms: 0, links: [], ...overrides
});

describe('InvestigationSummary', () => {
  it('renders ranked investigation evidence and selects the recommended event', async () => {
    const onselect = vi.fn();
    const events = [
      event(1, 'tool.execution', { duration_ms: 2300, payload_json: '{"tool":"deploy"}' }),
      event(2, 'tool.error', { parent_event_id: 'event-1', status: 'error', payload_json: '{"tool":"deploy","error":"denied"}' })
    ];
    render(InvestigationSummary, { props: { trace, events, onselect } });

    expect(screen.getByRole('region', { name: 'Investigation summary' })).toBeInTheDocument();
    expect(screen.getByText('Likely cause')).toBeInTheDocument();
    expect(screen.getByText('Failure chain')).toBeInTheDocument();
    expect(screen.getByText('Slow & expensive')).toBeInTheDocument();
    await fireEvent.click(screen.getByRole('button', { name: /inspect recommended event/i }));
    expect(onselect).toHaveBeenCalledWith(expect.objectContaining({ event_id: 'event-2' }));
  });

  it('provides a compact truthful empty state for an active trace', () => {
    render(InvestigationSummary, { props: { trace: { ...trace, ended_at: null, exit_code: null, integrity: 'live' }, events: [] } });
    expect(screen.getByText('Waiting for evidence')).toBeInTheDocument();
    expect(screen.getByText('No events captured')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /inspect recommended event/i })).not.toBeInTheDocument();
  });

  it('lets compact viewports reveal and collapse the supporting evidence', async () => {
    render(InvestigationSummary, { props: { trace, events: [event(1, 'tool.error', { status: 'error' })] } });
    const toggle = screen.getByRole('button', { name: /show investigation details/i });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await fireEvent.click(toggle);
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    expect(toggle).toHaveAccessibleName(/hide investigation details/i);
  });
});
