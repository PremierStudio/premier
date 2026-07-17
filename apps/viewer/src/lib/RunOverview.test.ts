import { render, screen } from '@testing-library/svelte';
import { expect, it } from 'vitest';
import RunOverview from './RunOverview.svelte';
import type { TraceEvent, TraceManifest } from './types';

const trace: TraceManifest = {
  format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: '', exit_code: 0, journal: null
};

function event(sequence: number, id: string, type: string, kind: string, status = 'ok'): TraceEvent {
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-1', sequence, timestamp: '2026-07-13T12:00:01Z', kind,
    source: 'sdk', payload_json: '{}', actor_id: id, actor_type: type, parent_event_id: '', span_id: `span-${sequence}`,
    parent_span_id: '', correlation_id: '', status, duration_ms: 0, links: []
  };
}

it('shows truthful actor roles and semantic run health in compact header chips', () => {
  const events = [
    event(1, 'root', 'process', 'process.stdout'),
    event(2, 'coordinator', 'agent', 'agent.turn'),
    event(3, 'researcher', 'subagent', 'model.response'),
    event(4, 'brad', 'human', 'approval.decision'),
    event(5, 'reviewer', 'subagent', 'tool.error', 'error')
  ];
  render(RunOverview, { props: { trace, events, compact: true } });
  expect(screen.getByText('Needs attention')).toBeInTheDocument();
  expect(screen.getByLabelText('Run overview')).toHaveTextContent('Actors');
  expect(screen.getByLabelText('Run overview')).toHaveTextContent('5');
  expect(screen.getByText('1 issue')).toBeInTheDocument();
});

it('surfaces an integrity chip for invalid journals instead of Passed', () => {
  render(RunOverview, {
    props: {
      compact: true,
      trace: {
        ...trace,
        integrity: 'invalid',
        integrity_detail: 'journal digest mismatch',
        exit_code: 0
      },
      events: [event(1, 'root', 'process', 'process.exit')]
    }
  });
  expect(screen.getByText('Unverified')).toBeInTheDocument();
  expect(screen.getByText('Integrity failed')).toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveAttribute('title', 'journal digest mismatch');
});
