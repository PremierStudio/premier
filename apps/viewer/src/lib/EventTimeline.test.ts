import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import EventTimeline from './EventTimeline.svelte';
import type { TraceEvent } from './types';

const event: TraceEvent = {
  event_id: 'event-1', trace_id: 'trace-1', sequence: 2,
  timestamp: '2026-07-13T12:00:01Z', kind: 'process.stdout', source: 'command',
  payload_json: JSON.stringify({ text: 'test output\n' }),
  actor_id: 'researcher', actor_type: 'subagent', parent_event_id: 'parent-1',
  span_id: 'search', parent_span_id: 'research', correlation_id: '', status: 'ok',
  duration_ms: 42, links: []
};

it('summarizes output and selects an event', async () => {
  const onselect = vi.fn();
  render(EventTimeline, { props: { events: [event], selectedSequence: null, onselect } });
  const option = screen.getByRole('option', { name: /process.stdout/i });
  expect(option).toHaveTextContent('test output');
  await userEvent.click(option);
  expect(onselect).toHaveBeenCalledWith(event);
});

it('shows complete actor names without a causal graph', () => {
  render(EventTimeline, { props: { events: [event], selectedSequence: null, onselect: vi.fn() } });
  expect(screen.getByText('researcher')).toBeInTheDocument();
  expect(screen.queryByText('RES')).not.toBeInTheDocument();
  expect(screen.queryByRole('img')).not.toBeInTheDocument();
  expect(screen.getByText('sub-agent')).toBeInTheDocument();
});

it('uses roving focus and arrow keys to inspect adjacent evidence', async () => {
  const onselect = vi.fn();
  const next = { ...event, event_id: 'event-2', sequence: 3, kind: 'tool.execution', payload_json: JSON.stringify({ tool: 'rg', matches: 7 }) };
  render(EventTimeline, { props: { events: [event, next], selectedSequence: event.sequence, onselect } });
  const options = screen.getAllByRole('option');
  options[0].focus();
  await userEvent.keyboard('{ArrowDown}');
  expect(onselect).toHaveBeenLastCalledWith(next);
  expect(options[1]).toHaveFocus();
  expect(options[1]).toHaveAccessibleName(expect.stringContaining('rg · 7 matches'));
});

it('does not put an empty-state message inside a listbox', () => {
  render(EventTimeline, { props: { events: [], selectedSequence: null, onselect: vi.fn() } });
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  expect(screen.getByRole('status')).toHaveTextContent('No matching evidence');
});

it('discloses long summaries without replacing row selection', async () => {
  const onselect = vi.fn();
  const longText = `Beginning ${'full captured evidence '.repeat(12)}ending`;
  const verbose = { ...event, payload_json: JSON.stringify({ text: longText }) };
  render(EventTimeline, { props: { events: [verbose], selectedSequence: null, onselect } });
  const toggle = screen.getByRole('button', { name: 'Read full summary' });
  expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await userEvent.click(toggle);
  expect(toggle).toHaveAttribute('aria-expanded', 'true');
  expect(screen.getByText(longText)).toHaveClass('expanded');
  expect(onselect).not.toHaveBeenCalled();
});

it('bounds the rendered DOM for a ten-thousand-event trace', () => {
  const events = Array.from({ length: 10_000 }, (_, index): TraceEvent => ({
    ...event,
    event_id: `event-${index}`,
    sequence: index,
    kind: 'tool.execution',
    actor_id: `actor-${index % 6}`,
    payload_json: JSON.stringify({ tool: 'verify', index })
  }));
  render(EventTimeline, { props: { events, selectedSequence: null, onselect: vi.fn() } });
  expect(screen.getByText(/windowed rendering/)).toBeInTheDocument();
  expect(screen.getAllByRole('option').length).toBeLessThan(100);
});

it('allows mouse scrolling away from an early selection in a virtualized timeline', async () => {
  const events = Array.from({ length: 500 }, (_, index): TraceEvent => ({
    ...event,
    event_id: `event-${index}`,
    sequence: index,
    kind: 'tool.execution',
    actor_id: `actor-${index % 6}`,
    payload_json: JSON.stringify({ tool: 'verify', index })
  }));
  const { container } = render(EventTimeline, {
    props: { events, selectedSequence: 0, onselect: vi.fn() }
  });
  const scroller = container.querySelector('.timeline-scroll') as HTMLDivElement;
  expect(scroller).toBeTruthy();
  Object.defineProperty(scroller, 'clientHeight', { configurable: true, value: 400 });
  scroller.scrollTop = 0;
  scroller.dispatchEvent(new Event('scroll'));

  scroller.scrollTop = 12_000;
  scroller.dispatchEvent(new Event('scroll'));
  await Promise.resolve();

  // Selection stays early, but the viewport must not snap scrollTop back to 0.
  expect(scroller.scrollTop).toBe(12_000);
  expect(screen.getByText(/windowed rendering/)).toBeInTheDocument();
});
