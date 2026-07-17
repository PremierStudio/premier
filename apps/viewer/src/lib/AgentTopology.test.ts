import { fireEvent, render, screen } from '@testing-library/svelte';
import { expect, it, vi } from 'vitest';
import AgentTopology from './AgentTopology.svelte';
import type { TraceEvent } from './types';

function event(
  sequence: number,
  actor: string,
  type: string,
  kind = 'agent.turn',
  parentEvent = '',
  span = `span-${sequence}`,
  parentSpan = '',
  status = 'ok'
): TraceEvent {
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-1', sequence, timestamp: `2026-07-13T12:00:0${sequence}Z`, kind,
    source: 'sdk', payload_json: '{}', actor_id: actor, actor_type: type, parent_event_id: parentEvent,
    span_id: span, parent_span_id: parentSpan, correlation_id: '', status, duration_ms: 0, links: []
  };
}

it('shows labeled actors, roles, evidence counts, issues, and an explanatory legend', () => {
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation', '', 'delegate'),
    event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1', 'audit'),
    event(3, 'auditor', 'subagent', 'tool.error', 'event-2', 'audit-tool', '', 'error')
  ];
  render(AgentTopology, { props: { events, selectedActor: null, onactor: vi.fn() } });

  expect(screen.getByRole('heading', { name: 'Agent topology' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /coordinator, Coordinator, 1 event, no issues/ })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /auditor, Delegated agent, 2 events, 1 issue/ })).toBeInTheDocument();
  expect(screen.getByLabelText('Map scope')).toHaveTextContent('3 supplied events');
  expect(screen.getByLabelText('Map scope')).toHaveTextContent('recorded parent event or parent span');
  expect(screen.getByLabelText('Topology legend')).toHaveTextContent('Blue arrow: parent-to-child event flow');
  expect(screen.getByLabelText('Topology legend')).toHaveTextContent('Dashed node: delegated agent');
});

it('derives cross-actor edges from parent events and parent spans and makes them actionable', async () => {
  const onselect = vi.fn();
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation', '', 'delegation'),
    event(2, 'auditor', 'subagent', 'agent.spawn', '', 'audit', 'delegation'),
    event(3, 'auditor', 'subagent', 'tool.execution', 'event-1', 'tool'),
    event(4, 'coordinator', 'agent', 'agent.join', 'event-3', 'join')
  ];
  render(AgentTopology, { props: { events, onactor: vi.fn(), onselect } });

  const outbound = screen.getByRole('button', { name: /coordinator to auditor: 2 linked events/i });
  await fireEvent.click(outbound);
  expect(onselect).toHaveBeenCalledWith(events[1]);

  const inbound = screen.getByRole('button', { name: /auditor to coordinator: 1 linked event/i });
  await fireEvent.keyDown(inbound, { key: 'Enter' });
  expect(onselect).toHaveBeenLastCalledWith(events[3]);
});

it('names the event kinds behind an aggregated route and exposes every exact handoff', async () => {
  const onselect = vi.fn();
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation', '', 'delegation'),
    event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1', 'audit'),
    event(3, 'auditor', 'subagent', 'tool.error', 'event-1', 'audit-tool', '', 'error')
  ];
  render(AgentTopology, { props: { events, onactor: vi.fn(), onselect } });

  const route = screen.getByRole('button', {
    name: /coordinator to auditor: 2 linked events, agent\.spawn · tool\.error, 1 issue.*representative event tool\.error, sequence 3/i
  });
  await fireEvent.click(route);
  expect(onselect).toHaveBeenLastCalledWith(events[2]);

  const ledger = screen.getByLabelText('Exact handoff evidence');
  expect(ledger).toHaveTextContent('agent.spawn · tool.error');
  expect(ledger).toHaveTextContent('2 events · 1 issue');
  await fireEvent.click(screen.getByText('coordinator', { selector: '.route strong' }));

  const exactSpawn = screen.getByRole('button', { name: /inspect handoff event agent\.spawn, sequence 2/i });
  const exactError = screen.getByRole('button', { name: /inspect handoff event tool\.error, sequence 3/i });
  await fireEvent.click(exactSpawn);
  expect(onselect).toHaveBeenLastCalledWith(events[1]);
  await fireEvent.click(exactError);
  expect(onselect).toHaveBeenLastCalledWith(events[2]);
});

it('selects actors and exposes selection state', async () => {
  const onactor = vi.fn();
  const events = [event(1, 'solo', 'agent')];
  const { rerender } = render(AgentTopology, { props: { events, selectedActor: null, onactor } });
  const actor = screen.getByRole('button', { name: /solo, Coordinator/ });
  await fireEvent.click(actor);
  expect(onactor).toHaveBeenCalledWith('solo');

  await rerender({ events, selectedActor: 'solo', onactor });
  expect(screen.getByRole('button', { name: /solo, Coordinator/ })).toHaveAttribute('aria-pressed', 'true');
  expect(screen.getByText(/one actor, so there are no cross-actor causal links/i)).toBeInTheDocument();
});

it('renders a useful empty state', () => {
  render(AgentTopology, { props: { events: [], onactor: vi.fn() } });
  expect(screen.getByRole('status')).toHaveTextContent('No actors recorded');
  expect(screen.getByRole('status')).toHaveTextContent('parent links');
});

it('provides a pannable, resettable canvas with a minimap', async () => {
  const events = [
    event(1, 'coordinator', 'agent', 'agent.delegation', '', 'delegation'),
    event(2, 'auditor', 'subagent', 'agent.spawn', 'event-1', 'audit')
  ];
  render(AgentTopology, { props: { events, onactor: vi.fn() } });

  const canvas = screen.getByLabelText('Architecture canvas');
  expect(screen.getByLabelText('Architecture minimap')).toBeInTheDocument();
  await fireEvent.click(screen.getByRole('button', { name: 'Zoom in' }));
  await fireEvent.click(screen.getByRole('button', { name: 'Pan right' }));
  expect(canvas).toHaveAttribute('data-zoom', '1.25');
  expect(canvas).toHaveAttribute('data-pan-x', '-80');

  await fireEvent.pointerDown(canvas, { clientX: 100, clientY: 100, pointerId: 1 });
  await fireEvent.pointerMove(canvas, { clientX: 130, clientY: 125, pointerId: 1 });
  await fireEvent.pointerUp(canvas, { clientX: 130, clientY: 125, pointerId: 1 });
  expect(canvas).toHaveAttribute('data-pan-x', '-50');
  expect(canvas).toHaveAttribute('data-pan-y', '25');

  await fireEvent.click(screen.getByRole('button', { name: 'Reset map view' }));
  expect(canvas).toHaveAttribute('data-zoom', '1');
  expect(canvas).toHaveAttribute('data-pan-x', '0');
  expect(canvas).toHaveAttribute('data-pan-y', '0');
});
