import { describe, expect, it } from 'vitest';
import { activitySegments, inferArchitecture, orchestratorRank } from './architectureInference';
import type { TraceEvent } from './types';

function event(sequence: number, actor: string, kind = 'agent.turn', overrides: Partial<TraceEvent> = {}): TraceEvent {
  return {
    event_id: `event-${sequence}`,
    trace_id: 'trace-1',
    sequence,
    timestamp: `2026-07-13T12:00:0${sequence}.000Z`,
    kind,
    source: 'test',
    payload_json: '{}',
    actor_id: actor,
    actor_type: actor === 'coordinator' ? 'agent' : 'subagent',
    parent_event_id: '',
    span_id: `span-${sequence}`,
    parent_span_id: '',
    correlation_id: '',
    status: 'ok',
    duration_ms: 0,
    links: [],
    ...overrides
  };
}

describe('architecture inference', () => {
  it('infers actor evidence, windows, kinds, issues, and exact parent-event connections', () => {
    const parent = event(1, 'coordinator', 'agent.delegation', { duration_ms: 4_000 });
    const child = event(2, 'researcher', 'tool.error', { parent_event_id: parent.event_id, status: 'error', duration_ms: 2_000 });
    const result = inferArchitecture([parent, child]);

    expect(result.actors[0]).toMatchObject({ id: 'coordinator', role: 'agent', eventCount: 1, eventKinds: { 'agent.delegation': 1 }, confidence: 'recorded' });
    expect(result.actors[1]).toMatchObject({ id: 'researcher', issueCount: 1, window: { durationMs: 2_000 } });
    expect(result.connections).toEqual([expect.objectContaining({
      sourceActorId: 'coordinator', targetActorId: 'researcher', eventCount: 1,
      issueCount: 1, sources: ['parent-event'], confidence: 'recorded', parentEvidenceInScope: true
    })]);
    expect(result.concurrency.some((sample) => sample.activeActorCount === 2)).toBe(true);
  });

  it('accepts an unambiguous parent span but refuses an ambiguous span', () => {
    const parent = event(1, 'coordinator', 'agent.delegation', { span_id: 'delegation' });
    const child = event(2, 'researcher', 'agent.spawn', { parent_span_id: 'delegation' });
    const accepted = inferArchitecture([parent, child]);
    expect(accepted.connections[0]).toMatchObject({ sources: ['parent-span'], confidence: 'high' });

    const secondOwner = event(3, 'reviewer', 'agent.turn', { span_id: 'delegation' });
    const ambiguous = inferArchitecture([parent, secondOwner, child]);
    expect(ambiguous.connections).toHaveLength(0);
    expect(ambiguous.unresolvedParents).toContainEqual(expect.objectContaining({ eventId: child.event_id, reason: 'ambiguous-span' }));
  });

  it('keeps co-presence observational and reports actors without explicit links', () => {
    const left = event(1, 'researcher', 'model.response', { duration_ms: 3_000 });
    const right = event(2, 'reviewer', 'tool.execution', { duration_ms: 1_000 });
    const result = inferArchitecture([left, right]);

    expect(result.connections).toHaveLength(0);
    expect(result.unlinkedActorIds).toEqual(['researcher', 'reviewer']);
    expect(result.coPresence).toEqual([expect.objectContaining({
      actorIds: ['researcher', 'reviewer'], explicitlyConnected: false,
      confidence: 'observation-only', source: 'temporal-overlap', isRelationship: false
    })]);
  });

  it('records missing parent evidence instead of inventing nodes or edges', () => {
    const orphan = event(1, 'researcher', 'agent.spawn', { parent_event_id: 'not-recorded' });
    const result = inferArchitecture([orphan]);
    expect(result.actors.map((actor) => actor.id)).toEqual(['researcher']);
    expect(result.connections).toHaveLength(0);
    expect(result.unresolvedParents).toEqual([expect.objectContaining({ reference: 'not-recorded', reason: 'missing' })]);
  });

  it('handles single actors, zero-duration events, invalid timestamps, and empty input', () => {
    const zero = event(1, 'solo');
    const invalid = event(2, 'solo', 'tool.execution', { timestamp: 'unknown' });
    const result = inferArchitecture([zero, invalid]);
    expect(result.actors[0]).toMatchObject({ id: 'solo', eventCount: 2, window: { durationMs: 0 } });
    expect(result.concurrency).toEqual([expect.objectContaining({ activeActorIds: ['solo'], activeEventCount: 1 })]);
    expect(result.scope.temporalEventCount).toBe(1);
    expect(inferArchitecture([])).toMatchObject({ actors: [], connections: [], concurrency: [], scope: { startMs: null, endMs: null } });
  });

  it('applies viewer filters and does not surface a filtered-out source actor', () => {
    const parent = event(1, 'coordinator', 'agent.delegation');
    const child = event(2, 'researcher', 'tool.execution', { parent_event_id: parent.event_id });
    const result = inferArchitecture([parent, child], {
      filters: { search: '', category: 'tool', actorId: null, errorsOnly: false, correlationId: null }
    });

    expect(result.scope).toMatchObject({ inputEventCount: 2, eventCount: 1, filtered: true });
    expect(result.actors.map((actor) => actor.id)).toEqual(['researcher']);
    expect(result.connections).toHaveLength(0);
    expect(result.unresolvedParents).toContainEqual(expect.objectContaining({ reason: 'source-outside-scope' }));
  });

  it('preserves explicit edges when both actors remain in scope while labeling hidden parent evidence', () => {
    const parent = event(1, 'coordinator', 'agent.delegation');
    const visibleCoordinator = event(2, 'coordinator', 'tool.execution');
    const child = event(3, 'researcher', 'tool.execution', { parent_event_id: parent.event_id });
    const result = inferArchitecture([parent, visibleCoordinator, child], {
      filters: { search: '', category: 'tool', actorId: null, errorsOnly: false, correlationId: null }
    });
    expect(result.connections[0]).toMatchObject({ sourceActorId: 'coordinator', targetActorId: 'researcher', parentEvidenceInScope: false });
  });

  it('places late-starting actors after the orchestrator plane with accurate windows', () => {
    const coordinator = event(1, 'coordinator', 'session.start', {
      timestamp: '2026-07-13T12:00:00.000Z',
      duration_ms: 0
    });
    const researcher = event(2, 'researcher', 'agent.spawn', {
      timestamp: '2026-07-13T12:00:05.000Z',
      duration_ms: 500,
      parent_event_id: coordinator.event_id
    });
    const reviewer = event(3, 'reviewer', 'agent.spawn', {
      timestamp: '2026-07-13T12:00:20.000Z',
      duration_ms: 800
    });
    const result = inferArchitecture([researcher, reviewer, coordinator]);
    expect(result.actors.map((actor) => actor.id)).toEqual(['coordinator', 'researcher', 'reviewer']);
    expect(result.actors[0].window?.startMs).toBe(Date.parse('2026-07-13T12:00:00.000Z'));
    expect(result.actors[1].window?.startMs).toBe(Date.parse('2026-07-13T12:00:05.000Z'));
    expect(result.actors[2].window?.startMs).toBe(Date.parse('2026-07-13T12:00:20.000Z'));
  });

  it('splits intermittent actor activity into separate segments instead of one continuous bar', () => {
    const early = event(1, 'coder', 'tool.execution', {
      timestamp: '2026-07-13T12:00:00.000Z',
      duration_ms: 200
    });
    const late = event(2, 'coder', 'tool.execution', {
      timestamp: '2026-07-13T12:00:10.000Z',
      duration_ms: 300
    });
    const result = inferArchitecture([early, late]);
    expect(result.actors[0].segments).toHaveLength(2);
    expect(result.actors[0].window?.durationMs).toBeGreaterThan(result.actors[0].segments[0].durationMs);
  });

  it('ranks orchestrator names ahead of generic agents', () => {
    expect(orchestratorRank({ id: 'coordinator', role: 'agent' })).toBeLessThan(
      orchestratorRank({ id: 'worker', role: 'agent' })
    );
    expect(orchestratorRank({ id: 'worker', role: 'agent' })).toBeLessThan(
      orchestratorRank({ id: 'helper', role: 'subagent' })
    );
  });

  it('merges near-adjacent intervals and splits true idle gaps', () => {
    const segments = activitySegments([
      { startMs: 0, endMs: 100, durationMs: 100 },
      { startMs: 150, endMs: 200, durationMs: 50 },
      { startMs: 5_000, endMs: 5_100, durationMs: 100 }
    ], 400);
    expect(segments).toHaveLength(2);
    expect(segments[0]).toMatchObject({ startMs: 0, endMs: 200 });
    expect(segments[1]).toMatchObject({ startMs: 5_000, endMs: 5_100 });
  });
});
