import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import Inspector from './Inspector.svelte';
import type { TraceEvent } from './types';

const event: TraceEvent = {
  event_id: 'event-1', trace_id: 'trace-1', sequence: 2,
  timestamp: '2026-07-13T12:00:01Z', kind: 'process.stdout', source: 'command',
  payload_json: JSON.stringify({ text: 'captured' }),
  actor_id: 'coder', actor_type: 'subagent', parent_event_id: 'parent-1',
  span_id: 'patch', parent_span_id: 'implementation', correlation_id: 'approval-1',
  status: 'ok', duration_ms: 176, links: ['evidence-1']
};

describe('Inspector', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/');
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) }
    });
  });

  it('summarizes captured evidence once instead of duplicating the primary value', () => {
    render(Inspector, { props: { event } });
    expect(screen.queryByRole('heading', { name: 'Primary evidence' })).not.toBeInTheDocument();
    expect(screen.getAllByText('captured')).toHaveLength(1);
    expect(screen.getByText('coder')).toBeInTheDocument();
    expect(screen.queryByText('Decoded payload')).not.toBeInTheDocument();
  });

  it('survives a JSON null payload without white-screening', async () => {
    const nullPayload = { ...event, payload_json: 'null' };
    render(Inspector, { props: { event: nullPayload } });
    expect(screen.getByText('coder')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('tab', { name: /Data/ }));
    expect(screen.getByText(/null/i)).toBeInTheDocument();
  });

  it('surfaces missing parents instead of silently no-oping', async () => {
    const orphan = { ...event, parent_event_id: 'missing-parent', links: ['also-missing'] };
    render(Inspector, { props: { event: orphan, events: [orphan], onnavigate: vi.fn() } });
    await userEvent.click(screen.getByRole('tab', { name: /Relations/i }));
    expect(screen.getAllByText(/not in journal/i).length).toBeGreaterThan(0);
  });

  it('organizes input, output, effects, authority, and raw evidence', async () => {
    const richEvent = {
      ...event,
      kind: 'tool.call',
      payload_json: JSON.stringify({
        tool_name: 'apply_patch', input: { patch: 'change' }, result: 'done',
        effects: ['src/App.svelte'], approval: 'granted'
      })
    };
    render(Inspector, { props: { event: richEvent } });
    expect(screen.getAllByText('apply_patch').length).toBeGreaterThan(0);

    await userEvent.click(screen.getByRole('tab', { name: /Data/ }));
    expect(screen.getByRole('heading', { name: /Request & input/ })).toBeInTheDocument();
    expect(screen.getByText(/"patch": "change"/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Result/ })).toBeInTheDocument();
    expect(screen.getByText('done')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Effects/ })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /Authority & policy/ })).toBeInTheDocument();
    expect(screen.getByText('granted')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('tab', { name: 'Raw' }));
    expect(screen.getByRole('heading', { name: 'Decoded payload' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Event envelope' })).toBeInTheDocument();
  });

  it('treats receipts and expiry as authority evidence and promotes the decision summary', async () => {
    const approvalEvent = {
      ...event,
      kind: 'approval.decision',
      status: 'approved',
      payload_json: JSON.stringify({ receipt: 'apr_01J', expires_after: 'single mutation', scope: 'src/billing.ts' })
    };
    render(Inspector, { props: { event: approvalEvent } });
    expect(screen.getByText(/approved · src\/billing\.ts · receipt apr_01J/)).toBeInTheDocument();
    expect(screen.getAllByText('apr_01J').length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole('tab', { name: /Data/ }));
    expect(screen.getByText('single mutation')).toBeInTheDocument();
    expect(screen.getByText('src/billing.ts')).toBeInTheDocument();
  });

  it('navigates parent and linked evidence through the optional callback', async () => {
    const onnavigate = vi.fn();
    const parent = { ...event, event_id: 'parent-1', sequence: 1, kind: 'agent.turn' };
    const evidence = { ...event, event_id: 'evidence-1', sequence: 3, kind: 'tool.execution' };
    render(Inspector, {
      props: {
        event: { ...event, parent_event_id: 'parent-1', links: ['evidence-1'] },
        events: [parent, event, evidence],
        onnavigate
      }
    });
    await userEvent.click(screen.getByRole('tab', { name: /Relations/ }));
    await userEvent.click(screen.getByRole('button', { name: /parent-1/ }));
    await userEvent.click(screen.getByRole('button', { name: /evidence-1/ }));
    expect(onnavigate).toHaveBeenNthCalledWith(1, 'parent-1');
    expect(onnavigate).toHaveBeenNthCalledWith(2, 'evidence-1');
  });

  it('supports arrow-key navigation across evidence tabs', async () => {
    render(Inspector, { props: { event } });
    const overview = screen.getByRole('tab', { name: 'Overview' });
    overview.focus();
    await userEvent.keyboard('{ArrowRight}');
    expect(screen.getByRole('tab', { name: /Data/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: /Data/ })).toHaveFocus();
    await userEvent.keyboard('{End}');
    expect(screen.getByRole('tab', { name: 'Raw' })).toHaveFocus();
  });

  it('copies a stable deep link and the captured event JSON', async () => {
    window.history.replaceState({}, '', '/?actor=reviewer&kind=error&from=1&to=2&view=map');
    render(Inspector, { props: { event } });
    await userEvent.click(screen.getByRole('button', { name: 'Copy event link' }));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('trace=trace-1'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('event_id=event-1'));
    expect(navigator.clipboard.writeText).not.toHaveBeenCalledWith(expect.stringContaining('event=2'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('view=map'));
    // Investigation scope must survive inspector copy so shared links reopen the same filter window.
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('actor=reviewer'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('kind=error'));
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(expect.stringContaining('from=1'));

    await userEvent.click(screen.getByRole('button', { name: 'Copy event JSON' }));
    expect(navigator.clipboard.writeText).toHaveBeenLastCalledWith(expect.stringContaining('"event_id": "event-1"'));
  });

  it('uses complementary semantics on desktop and deterministic close actions', async () => {
    const onclose = vi.fn();
    render(Inspector, { props: { event, onclose } });
    expect(screen.getByRole('complementary', { name: 'Event inspector' })).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(onclose).toHaveBeenCalledOnce();
    await userEvent.click(screen.getByRole('button', { name: 'Close inspector' }));
    expect(onclose).toHaveBeenCalledTimes(2);
  });

  it('uses modal semantics when the inspector becomes a responsive overlay', () => {
    const addEventListener = vi.fn();
    const removeEventListener = vi.fn();
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: vi.fn().mockReturnValue({ matches: true, addEventListener, removeEventListener })
    });
    render(Inspector, { props: { event, onclose: vi.fn() } });
    expect(screen.getByRole('dialog', { name: 'Event inspector' })).toHaveAttribute('aria-modal', 'true');
  });

  it('provides useful inspector navigation in the compact desktop rail', async () => {
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      value: vi.fn().mockReturnValue({ matches: false, addEventListener: vi.fn(), removeEventListener: vi.fn() })
    });
    const onrestore = vi.fn();
    render(Inspector, { props: { event, compact: true, onrestore } });
    expect(screen.getByLabelText('Compact event inspector')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Open Data' }));
    expect(onrestore).toHaveBeenCalledOnce();
  });

  it('separates failure status from event family and treats zero timing as unknown', () => {
    render(Inspector, { props: { event: { ...event, kind: 'tool.error', status: 'error', duration_ms: 0 } } });
    expect(screen.getByText('tool')).toBeInTheDocument();
    expect(screen.getByText('Not captured')).toBeInTheDocument();
  });

  it('makes long evidence explicitly expandable and preserves the complete value', async () => {
    const longValue = `start-${'evidence '.repeat(110)}-finish`;
    render(Inspector, { props: { event: { ...event, payload_json: JSON.stringify({ text: longValue }) } } });
    const toggle = screen.getByRole('button', { name: /Show complete value/ });
    expect(toggle).toHaveTextContent(longValue.length.toLocaleString());
    expect(screen.queryByText(longValue)).not.toBeInTheDocument();
    await userEvent.click(toggle);
    expect(screen.getByText(longValue)).toBeInTheDocument();
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
  });
});
