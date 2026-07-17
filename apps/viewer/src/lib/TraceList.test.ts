import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import TraceList from './TraceList.svelte';
import type { TraceManifest } from './types';

const trace: TraceManifest = {
  format_version: 1,
  trace_id: 'trace-1',
  command: ['npm', 'test'],
  started_at: '2026-07-13T12:00:00Z',
  ended_at: '2026-07-13T12:00:02Z',
  exit_code: 0,
  journal: { path: 'events/one.pb.zst', sha256: 'abc', event_count: 4 },
  summary: { display_name: null, actor_count: 2, issue_count: 0, event_count: 4 }
};

describe('TraceList', () => {
  it('renders trace evidence and selects a run', async () => {
    const onselect = vi.fn();
    render(TraceList, { props: { traces: [trace], selectedId: null, onselect } });
    const button = screen.getByRole('button', { name: /npm test/i });
    expect(button).toHaveTextContent('4');
    await userEvent.click(button);
    expect(onselect).toHaveBeenCalledWith(trace);
  });

  it('exposes the active trace as pressed', () => {
    render(TraceList, { props: { traces: [trace], selectedId: trace.trace_id, onselect: vi.fn() } });
    expect(screen.getByRole('button', { name: /npm test/i })).toHaveAttribute('aria-pressed', 'true');
  });

  it('keeps raw shell invocations out of run navigation', () => {
    const shell = {
      ...trace,
      trace_id: 'shell',
      command: ['sh', '-c', 'printf a-very-long-and-important-command'],
      summary: { display_name: 'Establish the takeover baseline', actor_count: 3, issue_count: 1, event_count: 11 }
    };
    render(TraceList, { props: { traces: [shell], selectedId: null, onselect: vi.fn() } });
    expect(screen.getByText('Establish the takeover baseline')).toBeInTheDocument();
    expect(screen.getByText('Needs attention · 1 issue · 3 actors')).toBeInTheDocument();
    expect(screen.queryByText(/printf a-very-long/)).not.toBeInTheDocument();
    expect(screen.queryByText('Command')).not.toBeInTheDocument();
  });

  it('filters run navigation by issues and live state', async () => {
    const issue = { ...trace, trace_id: 'issue', name: 'Needs review', summary: { display_name: null, actor_count: 2, issue_count: 2, event_count: 8 } };
    const live = { ...trace, trace_id: 'live', name: 'Live repair', ended_at: null, exit_code: null };
    render(TraceList, { props: { traces: [trace, issue, live], selectedId: null, onselect: vi.fn() } });
    await userEvent.click(screen.getByRole('button', { name: 'Issues' }));
    expect(screen.getByText('Needs review')).toBeInTheDocument();
    expect(screen.queryByText('npm run')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Live' }));
    expect(screen.getByText('Live repair')).toBeInTheDocument();
  });

  it('supports arrow-key run navigation', async () => {
    const onselect = vi.fn();
    const second = { ...trace, trace_id: 'trace-2', name: 'Second run' };
    render(TraceList, { props: { traces: [trace, second], selectedId: null, onselect } });
    const first = screen.getByRole('button', { name: /npm test/i });
    first.focus();
    await userEvent.keyboard('{ArrowDown}');
    expect(onselect).toHaveBeenCalledWith(second);
    expect(screen.getByRole('button', { name: /Second run/i })).toHaveFocus();
  });

  it('keeps run selection useful in the compact rail', async () => {
    const onselect = vi.fn();
    const onrestore = vi.fn();
    const { container } = render(TraceList, { props: { traces: [trace], selectedId: trace.trace_id, onselect, compact: true, onrestore } });
    await userEvent.click(screen.getByRole('button', { name: 'Expand runs' }));
    expect(onrestore).toHaveBeenCalledOnce();
    const run = screen.getByRole('button', { name: /npm test/i });
    expect(run).toHaveAttribute('aria-pressed', 'true');
    expect(run).toHaveClass('rail-run');
    expect(container.querySelector('.trace-list.compact')).toBeTruthy();
    expect(container.querySelector('.run-list-header')).toBeNull();
    await userEvent.click(run);
    expect(onselect).toHaveBeenCalledWith(trace);
  });
});
