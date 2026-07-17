import { fireEvent, render, screen } from '@testing-library/svelte';
import { expect, it, vi } from 'vitest';
import ArchitectureView from './ArchitectureView.svelte';
import type { TraceEvent } from './types';

function event(sequence: number, actor: string, kind: string, second: number, parentSpan = '', span = `span-${sequence}`, status = 'ok'): TraceEvent {
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-1', sequence,
    timestamp: `2026-07-13T12:00:${String(second).padStart(2, '0')}.000Z`, kind, source: 'test', payload_json: '{}',
    actor_id: actor, actor_type: actor === 'coordinator' ? 'agent' : 'subagent', parent_event_id: '', span_id: span,
    parent_span_id: parentSpan, correlation_id: '', status, duration_ms: 0, links: []
  };
}

const events = [
  event(1, 'coordinator', 'agent.delegation', 0, '', 'delegate'),
  event(2, 'researcher', 'agent.spawn', 2, 'delegate', 'research'),
  event(3, 'researcher', 'tool.error', 8, 'research', 'tool', 'error'),
  event(4, 'coordinator', 'agent.join', 10, 'research', 'join')
];

it('combines evidence-derived architecture with a synchronized time ruler', () => {
  render(ArchitectureView, { props: { events, onwindow: vi.fn(), onactor: vi.fn(), onselect: vi.fn() } });
  expect(screen.getByRole('heading', { name: 'Architecture + time' })).toBeInTheDocument();
  expect(screen.getByLabelText('Architecture detection summary')).toHaveTextContent('2 actors');
  expect(screen.getByLabelText('Architecture detection summary')).toHaveTextContent('derived link');
  expect(screen.getByLabelText('Actor activity ribbons')).toHaveTextContent('researcher');
  expect(screen.getByLabelText('Time ruler legend')).toHaveTextContent('Collector receipt event');
  expect(screen.getByText('Collector receipt time')).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Agent topology' })).toBeInTheDocument();
});

it('focuses a real time window and selects its representative evidence', async () => {
  const onwindow = vi.fn();
  const onselect = vi.fn();
  render(ArchitectureView, { props: { events, onwindow, onactor: vi.fn(), onselect } });
  const issueWindow = screen.getByRole('button', { name: 'Failure window' });
  await fireEvent.click(issueWindow);
  expect(onwindow).toHaveBeenCalled();
  expect(onselect).toHaveBeenCalledWith(events[2]);
});

it('selects exact event ticks and actor labels', async () => {
  const onselect = vi.fn();
  const onactor = vi.fn();
  render(ArchitectureView, { props: { events, selectedEventId: 'event-2', onwindow: vi.fn(), onactor, onselect } });
  await fireEvent.click(screen.getByRole('button', { name: /researcher, agent\.spawn, sequence 2/i }));
  expect(onselect).toHaveBeenCalledWith(events[1]);
  await fireEvent.click(screen.getByRole('button', { name: /Focus researcher/i }));
  expect(onactor).toHaveBeenCalledWith('researcher');
});

it('renders an honest empty state', () => {
  render(ArchitectureView, { props: { events: [], onwindow: vi.fn(), onactor: vi.fn(), onselect: vi.fn() } });
  expect(screen.getByRole('status')).toHaveTextContent('No architecture evidence yet');
});

it('keeps a stable run clock while visibly focusing filtered evidence', async () => {
  render(ArchitectureView, { props: { events, focusEvents: [events[2]], timeOnly: true, showHeader: false, showDiagram: false, onwindow: vi.fn(), onactor: vi.fn(), onselect: vi.fn() } });
  expect(screen.getByText('Observed activity over 10 s · 1 of 4 events in focus')).toBeInTheDocument();
  expect(screen.queryByLabelText('Actor activity ribbons')).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Actors' })).toHaveAttribute('aria-pressed', 'false');
  await fireEvent.click(screen.getByRole('button', { name: 'Actors' }));
  expect(screen.getByLabelText('Actor activity ribbons')).toBeInTheDocument();
  expect(document.querySelectorAll('.event-tick.filtered-out')).toHaveLength(3);
  expect(screen.getByRole('button', { name: 'Hide actors' })).toHaveAttribute('aria-pressed', 'true');
});

it('brushes a custom time crop and exposes keyboard-adjustable range handles', async () => {
  const onwindow = vi.fn();
  const { container, rerender } = render(ArchitectureView, { props: { events, timeOnly: true, showHeader: false, showDiagram: false, onwindow, onactor: vi.fn(), onselect: vi.fn() } });
  const density = container.querySelector('.density') as HTMLDivElement;
  density.getBoundingClientRect = () => ({ x: 0, y: 0, left: 0, right: 200, top: 0, bottom: 42, width: 200, height: 42, toJSON: () => ({}) });
  density.setPointerCapture = vi.fn();
  density.hasPointerCapture = vi.fn(() => false);
  await fireEvent.pointerDown(density, { button: 0, clientX: 40, pointerId: 1 });
  await fireEvent.pointerMove(density, { clientX: 140, pointerId: 1 });
  await fireEvent.pointerUp(density, { clientX: 140, pointerId: 1 });
  expect(onwindow).toHaveBeenCalledWith(2000, 7000);

  await rerender({ events, timeOnly: true, showHeader: false, showDiagram: false, windowStartMs: 2000, windowEndMs: 7000, onwindow, onactor: vi.fn(), onselect: vi.fn() });
  await fireEvent.keyDown(screen.getByRole('slider', { name: 'Range start' }), { key: 'ArrowRight' });
  expect(onwindow).toHaveBeenLastCalledWith(2100, 7000);
});

it('abandons a cancelled crop without changing the active range', async () => {
  const onwindow = vi.fn();
  const { container } = render(ArchitectureView, { props: { events, timeOnly: true, showHeader: false, showDiagram: false, onwindow, onactor: vi.fn(), onselect: vi.fn() } });
  const density = container.querySelector('.density') as HTMLDivElement;
  density.getBoundingClientRect = () => ({ x: 0, y: 0, left: 0, right: 200, top: 0, bottom: 42, width: 200, height: 42, toJSON: () => ({}) });
  density.setPointerCapture = vi.fn();
  density.hasPointerCapture = vi.fn(() => false);
  await fireEvent.pointerDown(density, { button: 0, clientX: 30, pointerId: 2 });
  await fireEvent.pointerMove(density, { clientX: 150, pointerId: 2 });
  await fireEvent.pointerCancel(density, { clientX: 150, pointerId: 2 });
  expect(onwindow).not.toHaveBeenCalled();
});

it('renders architecture without coupling it to a second time ruler', () => {
  render(ArchitectureView, { props: { events, showRuler: false, onwindow: vi.fn(), onactor: vi.fn(), onselect: vi.fn() } });
  expect(screen.getByRole('heading', { name: 'Agent architecture' })).toBeInTheDocument();
  expect(screen.queryByText('Orchestration ruler', { exact: true })).not.toBeInTheDocument();
  expect(screen.getByRole('heading', { name: 'Agent topology' })).toBeInTheDocument();
});
