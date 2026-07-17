import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import LocalAssistant from './LocalAssistant.svelte';
import type { TraceEvent } from './types';

const mocks = vi.hoisted(() => ({ assistants: vi.fn(), askAssistant: vi.fn() }));
vi.mock('./api', () => ({ api: mocks }));

const selectedEvent: TraceEvent = {
  event_id: 'event-9', trace_id: 'trace-1', sequence: 9, timestamp: '2026-07-13T20:51:39Z',
  kind: 'tool.error', source: 'test', payload_json: '{"detail":"failed"}', actor_id: 'worker',
  actor_type: 'subagent', parent_event_id: '', span_id: '', parent_span_id: '', correlation_id: '',
  status: 'error', duration_ms: 18, links: []
};

const providers = [
  { provider: 'claude', label: 'Claude', installed: true, available: true },
  { provider: 'codex', label: 'Codex', installed: true, available: true },
  { provider: 'opencode', label: 'OpenCode', installed: true, available: false, reason: 'No verified tool-deny mode.' }
];

describe('LocalAssistant', () => {
  beforeEach(() => {
    mocks.assistants.mockReset().mockResolvedValue(providers);
    mocks.askAssistant.mockReset().mockResolvedValue({ provider: 'claude', answer: 'The compiler failed in worker.', elapsed_ms: 125 });
  });

  it('discovers safe providers and keeps unavailable providers visible with a reason', async () => {
    render(LocalAssistant, { props: { traceId: 'trace-1' } });

    expect(screen.getByText('Discovering installed CLIs…')).toBeInTheDocument();
    const provider = await screen.findByRole('button', { name: 'Local provider' });
    await userEvent.click(provider);
    expect(screen.getByRole('option', { name: /Claude/ })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: /Codex/ })).toBeInTheDocument();
    await userEvent.click(screen.getByText('1 unavailable provider'));
    expect(screen.getByText('OpenCode')).toBeInTheDocument();
    expect(screen.getByText('No verified tool-deny mode.')).toBeInTheDocument();
  });

  it('uses starters to fill the composer without submitting', async () => {
    const user = userEvent.setup();
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Local provider' });

    await user.click(screen.getByRole('button', { name: /Summarize the run/ }));
    expect(screen.getByLabelText('Question for your local AI')).toHaveValue('Summarize the run and identify the highest-impact issue.');
    expect(mocks.askAssistant).not.toHaveBeenCalled();
  });

  it('sends real history and selected-event scope and renders the measured answer', async () => {
    const user = userEvent.setup();
    render(LocalAssistant, { props: { traceId: 'trace-1', selectedEvent } });
    await user.click(await screen.findByRole('button', { name: 'Local provider' }));
    await user.click(screen.getByRole('option', { name: /Codex/ }));
    await user.click(screen.getByRole('radio', { name: /Selected event/ }));
    await user.type(screen.getByLabelText('Question for your local AI'), 'Why did this fail?');
    mocks.askAssistant.mockResolvedValueOnce({ provider: 'codex', answer: 'Event 9 contains the compiler failure.', elapsed_ms: 240 });
    await user.click(screen.getByRole('button', { name: 'Ask Codex' }));

    await screen.findByText('Event 9 contains the compiler failure.');
    expect(mocks.askAssistant).toHaveBeenCalledWith('trace-1', {
      provider: 'codex', prompt: 'Why did this fail?', history: [], selected_event_id: 'event-9'
    });
    expect(screen.getByText('240 ms')).toBeInTheDocument();

    await user.type(screen.getByLabelText('Question for your local AI'), 'What next?');
    await user.click(screen.getByRole('button', { name: 'Ask Codex' }));
    await waitFor(() => expect(mocks.askAssistant).toHaveBeenCalledTimes(2));
    expect(mocks.askAssistant.mock.calls[1][1].history).toEqual([
      { role: 'user', content: 'Why did this fail?' },
      { role: 'assistant', content: 'Event 9 contains the compiler failure.' }
    ]);
  });

  it('renders provider Markdown as semantic, readable trace analysis', async () => {
    const user = userEvent.setup();
    mocks.askAssistant.mockResolvedValueOnce({
      provider: 'claude',
      answer: '## Highest-impact issue\n\n**Missing evidence:**\n\n- No model call\n- No tool execution\n\n`correlation_id` is empty.',
      elapsed_ms: 25_400
    });
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Local provider' });
    await user.type(screen.getByLabelText('Question for your local AI'), 'Review the run');
    await user.click(screen.getByRole('button', { name: 'Ask Claude' }));

    expect(await screen.findByRole('heading', { level: 2, name: 'Highest-impact issue' })).toBeInTheDocument();
    expect(screen.getByText('Missing evidence:').tagName).toBe('STRONG');
    expect(screen.getByText('No model call').closest('ul')).toHaveTextContent('No model call No tool execution');
    expect(screen.getByText('correlation_id').tagName).toBe('CODE');
    expect(screen.getByText('25.4 s')).toBeInTheDocument();
  });

  it('preserves a failed question and exposes the real backend error', async () => {
    const user = userEvent.setup();
    mocks.askAssistant.mockRejectedValueOnce(new Error('Claude exited with status 1: login required'));
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Local provider' });
    const input = screen.getByLabelText('Question for your local AI');
    await user.type(input, 'Diagnose this');
    await user.click(screen.getByRole('button', { name: 'Ask Claude' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Claude exited with status 1: login required');
    expect(input).toHaveValue('Diagnose this');
  });

  it('shows a truthful waiting state while the provider is running', async () => {
    const user = userEvent.setup();
    let resolveAnswer!: (value: { provider: string; answer: string; elapsed_ms: number }) => void;
    mocks.askAssistant.mockReturnValueOnce(new Promise((resolve) => { resolveAnswer = resolve; }));
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Local provider' });
    await user.type(screen.getByLabelText('Question for your local AI'), 'Inspect latency');
    await user.click(screen.getByRole('button', { name: 'Ask Claude' }));

    expect(screen.getByRole('status')).toHaveTextContent('Claude is analyzing the trace');
    expect(screen.getByRole('button', { name: 'Waiting' })).toBeDisabled();
    resolveAnswer({ provider: 'claude', answer: 'Latency is concentrated in tools.', elapsed_ms: 80 });
    expect(await screen.findByText('Latency is concentrated in tools.')).toBeInTheDocument();
  });

  it('bounds the visible transcript and reports hidden earlier messages', async () => {
    const user = userEvent.setup();
    mocks.askAssistant.mockImplementation(async (_traceId: string, body: { prompt: string }) => ({
      provider: 'claude', answer: `Answer to ${body.prompt}`, elapsed_ms: 10
    }));
    render(LocalAssistant, { props: { traceId: 'trace-1' } });
    await screen.findByRole('button', { name: 'Local provider' });
    const input = screen.getByLabelText('Question for your local AI');
    for (let index = 1; index <= 7; index += 1) {
      await user.type(input, `Question ${index}`);
      await user.click(screen.getByRole('button', { name: 'Ask Claude' }));
      await screen.findByText(`Answer to Question ${index}`);
    }
    expect(screen.getByText('2 earlier messages hidden')).toBeInTheDocument();
    expect(screen.queryByText('Question 1')).not.toBeInTheDocument();
    expect(screen.getByText('Question 7')).toBeInTheDocument();
  });

  it('shows the no-provider state without enabling fake interaction', async () => {
    mocks.assistants.mockResolvedValueOnce([
      { provider: 'opencode', label: 'OpenCode', installed: true, available: false, reason: 'No safe invocation.' }
    ]);
    render(LocalAssistant, { props: { traceId: 'trace-1' } });

    const provider = await screen.findByRole('button', { name: 'Local provider' });
    expect(provider).toHaveTextContent('No safe provider available');
    expect(provider).toBeDisabled();
    expect(screen.getByLabelText('Question for your local AI')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Ask assistant' })).toBeDisabled();
  });
});
