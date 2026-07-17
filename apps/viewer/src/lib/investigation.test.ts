import { describe, expect, it } from 'vitest';
import { buildInvestigationSummary } from './investigation';
import type { TraceEvent, TraceManifest } from './types';

const trace = (overrides: Partial<TraceManifest> = {}): TraceManifest => ({
  format_version: 1,
  trace_id: 'trace-a',
  command: ['codex'],
  started_at: '2026-07-15T12:00:00.000Z',
  ended_at: '2026-07-15T12:00:04.000Z',
  exit_code: 1,
  journal: null,
  ...overrides
});

const event = (sequence: number, kind: string, overrides: Partial<TraceEvent> = {}): TraceEvent => ({
  event_id: `event-${sequence}`,
  trace_id: 'trace-a',
  sequence,
  timestamp: `2026-07-15T12:00:0${sequence}.000Z`,
  kind,
  source: 'sdk',
  payload_json: '{}',
  actor_id: 'coordinator',
  actor_type: 'agent',
  parent_event_id: '',
  span_id: `span-${sequence}`,
  parent_span_id: '',
  correlation_id: 'run-1',
  status: 'ok',
  duration_ms: 0,
  links: [],
  ...overrides
});

describe('buildInvestigationSummary', () => {
  it('identifies the earliest causal failure and builds an evidence-linked chain', () => {
    const events = [
      event(1, 'agent.turn', { span_id: 'root-span', correlation_id: 'work' }),
      event(2, 'tool.execution', { parent_event_id: 'event-1', parent_span_id: 'root-span', span_id: 'tool-span', correlation_id: 'work', duration_ms: 3800, payload_json: '{"tool":"deploy"}' }),
      event(3, 'tool.error', { parent_event_id: 'event-2', parent_span_id: 'tool-span', correlation_id: 'work', status: 'error', payload_json: '{"tool":"deploy","error":"permission denied"}' }),
      event(4, 'agent.result', { parent_event_id: 'event-3', status: 'failed', correlation_id: 'work', payload_json: '{"result":"deployment failed"}' })
    ];

    const result = buildInvestigationSummary(trace(), events);

    expect(result.cause.event?.event_id).toBe('event-3');
    expect(result.cause.title).toContain('tool.error');
    expect(result.cause.detail).toContain('permission denied');
    expect(result.failureChain.map((item) => item.event.event_id)).toEqual(['event-1', 'event-2', 'event-3', 'event-4']);
    expect(result.recommendedEvent?.event.event_id).toBe('event-3');
    expect(result.hotspots[0]).toMatchObject({ event: { event_id: 'event-2' }, durationMs: 3800 });
  });

  it('ranks expensive model calls and reports specific missing usage evidence', () => {
    const events = [
      event(1, 'model.response', { duration_ms: 120, payload_json: '{"model":"gpt-fast","usage":{"total_tokens":80},"cost_usd":0.01}' }),
      event(2, 'model.response', { duration_ms: 900, payload_json: '{"model":"gpt-big","usage":{"total_tokens":9000},"cost_usd":1.25}' }),
      event(3, 'model.response', { duration_ms: 200, payload_json: '{"model":"mystery"}' })
    ];

    const result = buildInvestigationSummary(trace({ exit_code: 0 }), events);

    expect(result.hotspots[0]).toMatchObject({ event: { event_id: 'event-2' }, costUsd: 1.25, totalTokens: 9000 });
    expect(result.gaps.map((gap) => gap.id)).toEqual(expect.arrayContaining(['model-cost', 'model-tokens']));
    expect(result.recommendedEvent?.event.event_id).toBe('event-2');
  });

  it('uses the highest-impact causal branch as the critical chain on a passing run', () => {
    const events = [
      event(1, 'agent.turn', { span_id: 'root-span' }),
      event(2, 'tool.execution', { parent_event_id: 'event-1', parent_span_id: 'root-span', duration_ms: 2400, payload_json: '{"tool":"build"}' }),
      event(3, 'process.exit', { actor_id: 'root', actor_type: 'process', payload_json: '{"exit_code":0}' })
    ];
    const result = buildInvestigationSummary(trace({ exit_code: 0 }), events);
    expect(result.chainKind).toBe('critical');
    expect(result.failureChain.map((item) => item.event.event_id)).toEqual(['event-1', 'event-2']);
  });

  it('explains a non-zero exit without a recorded failure as missing causal evidence', () => {
    const events = [event(1, 'process.exit', { actor_id: 'root', actor_type: 'process', payload_json: '{"exit_code":2}' })];
    const result = buildInvestigationSummary(trace({ exit_code: 2 }), events);

    expect(result.cause.title).toBe('Process exited with status 2');
    expect(result.cause.confidence).toBe('low');
    expect(result.gaps[0].id).toBe('exit-cause');
    expect(result.recommendedEvent?.event.event_id).toBe('event-1');
  });

  it('explains recovered interruptions without misreporting a missing exit cause', () => {
    const events = [event(1, 'session.interrupted', { actor_id: 'root', actor_type: 'process' })];
    const result = buildInvestigationSummary(trace({ exit_code: 130, termination: { kind: 'interrupted', exit_code: 130 } }), events);
    expect(result.cause.title).toBe('Recorder interruption recovered');
    expect(result.gaps.map((gap) => gap.id)).not.toContain('exit-cause');
  });

  it('names the terminating signal when structured termination evidence exists', () => {
    const events = [event(1, 'process.exit', { actor_id: 'root', actor_type: 'process' })];
    const result = buildInvestigationSummary(trace({ exit_code: 143, termination: { kind: 'signal', signal: 15, signal_name: 'SIGTERM' } }), events);
    expect(result.cause.title).toBe('Process terminated by SIGTERM');
    expect(result.gaps.map((gap) => gap.id)).not.toContain('exit-cause');
  });

  it('handles an active empty trace without inventing a cause or next event', () => {
    const result = buildInvestigationSummary(trace({ ended_at: null, exit_code: null, integrity: 'live' }), []);
    expect(result.cause).toMatchObject({ title: 'Waiting for evidence', confidence: 'low', event: null });
    expect(result.gaps.map((gap) => gap.id)).toContain('no-events');
    expect(result.recommendedEvent).toBeNull();
  });

  it('flags broken causal references and incomplete terminal evidence', () => {
    const events = [event(1, 'agent.result', { parent_event_id: 'missing-event', parent_span_id: 'missing-span' })];
    const result = buildInvestigationSummary(trace({ exit_code: 0 }), events);
    expect(result.gaps.map((gap) => gap.id)).toEqual(expect.arrayContaining(['causal-links', 'completion-event']));
  });

  it('surfaces recorder semantic diagnostics as missing-evidence findings', () => {
    const result = buildInvestigationSummary(trace({
      diagnostics: [{ severity: 'warning', code: 'missing_lifecycle_result', message: 'agent.spawn has no matching agent.result', event_id: 'event-1', sequence: 1 }]
    }), [event(1, 'agent.spawn')]);
    expect(result.gaps).toContainEqual(expect.objectContaining({
      id: 'diagnostic-missing_lifecycle_result',
      label: 'Recorded lifecycle evidence is incomplete'
    }));
  });
});
