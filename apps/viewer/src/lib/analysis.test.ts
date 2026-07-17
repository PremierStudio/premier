import { describe, expect, it } from 'vitest';
import { actorInventory, eventSummary, filterEvents, isIssue, runHealth, summarizeAgents, timelineLayout } from './analysis';
import type { TraceEvent, TraceManifest } from './types';

function event(sequence: number, actor: string, kind: string, status = 'ok'): TraceEvent {
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-1', sequence,
    timestamp: '2026-07-13T12:00:01Z', kind, source: 'sdk', payload_json: '{}',
    actor_id: actor, actor_type: actor === 'root' ? 'agent' : 'subagent', parent_event_id: '',
    span_id: `span-${sequence}`, parent_span_id: actor === 'root' ? '' : 'root-span',
    correlation_id: '', status, duration_ms: 0, links: []
  };
}

const events = [
  event(1, 'root', 'agent.delegation'),
  event(2, 'researcher', 'model.response'),
  event(3, 'coder', 'tool.execution'),
  event(4, 'reviewer', 'tool.error', 'error')
];

describe('agent trace analysis', () => {
  it('summarizes independent agent lanes and failures', () => {
    const agents = summarizeAgents(events);
    expect(agents.map((agent) => agent.id)).toEqual(['root', 'researcher', 'coder', 'reviewer']);
    expect(agents.at(-1)).toMatchObject({ errors: 1, status: 'error' });
  });

  it('combines actor, category, search, and error filters', () => {
    expect(filterEvents(events, { search: '', category: 'tool', actorId: 'coder', errorsOnly: false, correlationId: null })).toHaveLength(1);
    expect(filterEvents(events, { search: 'reviewer', category: 'all', actorId: null, errorsOnly: true, correlationId: null })[0].kind).toBe('tool.error');
  });

  it('filters by correlation id', () => {
    const correlated = [
      { ...event(1, 'coder', 'approval.request'), correlation_id: 'apr-1' },
      { ...event(2, 'brad', 'approval.decision'), correlation_id: 'apr-1' },
      { ...event(3, 'coder', 'tool.execution'), correlation_id: 'other' }
    ];
    expect(filterEvents(correlated, {
      search: '', category: 'all', actorId: null, errorsOnly: false, correlationId: 'apr-1'
    })).toHaveLength(2);
  });

  it('keeps failed tool events in both their recorded family and the issue facet', () => {
    const failedTool = event(5, 'coder', 'tool.execution_failed', 'blocked');
    expect(isIssue(failedTool)).toBe(true);
    expect(filterEvents([failedTool], { search: '', category: 'tool', actorId: null, errorsOnly: false, correlationId: null })).toEqual([failedTool]);
    expect(filterEvents([failedTool], { search: '', category: 'error', actorId: null, errorsOnly: false, correlationId: null })).toEqual([failedTool]);
  });

  it('separates runtime processes, coordinating agents, subagents, and humans', () => {
    const mixed = [
      { ...event(1, 'root', 'process.stdout'), actor_type: 'process' },
      { ...event(2, 'coordinator', 'agent.turn'), actor_type: 'agent' },
      { ...event(3, 'researcher', 'agent.spawn'), actor_type: 'subagent' },
      { ...event(4, 'brad', 'approval.decision'), actor_type: 'human' }
    ];
    expect(actorInventory(mixed)).toEqual({ processes: 1, agents: 1, subagents: 1, humans: 1, systems: 0 });
  });

  it('reports recorded errors even when the process exits cleanly', () => {
    const trace: TraceManifest = {
      format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: '', exit_code: 0, journal: null
    };
    expect(runHealth(trace, [event(1, 'reviewer', 'tool.error', 'error')])).toMatchObject({ label: 'Needs attention', tone: 'warning' });
    expect(runHealth({ ...trace, exit_code: 7 }, [])).toMatchObject({ label: 'Failed', detail: 'Exit 7' });
    expect(runHealth({ ...trace, exit_code: 143, termination: { kind: 'signal', signal: 15, signal_name: 'SIGTERM' } }, [])).toMatchObject({ label: 'Failed', detail: 'Terminated by SIGTERM' });
    expect(runHealth({ ...trace, exit_code: 130, termination: { kind: 'interrupted', exit_code: 130 } }, [])).toMatchObject({ label: 'Interrupted', detail: 'Recovered after recorder interruption' });
  });

  it('never presents integrity-invalid journals as passed', () => {
    const trace: TraceManifest = {
      format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: '2026-01-01',
      exit_code: 0, journal: null, integrity: 'invalid', integrity_detail: 'journal digest mismatch'
    };
    expect(runHealth(trace, [])).toMatchObject({
      label: 'Unverified',
      tone: 'error',
      detail: 'journal digest mismatch'
    });
    expect(runHealth({ ...trace, integrity_detail: null }, [])).toMatchObject({
      detail: 'Journal failed integrity verification'
    });
  });

  it('reports verified passed, live, blocked, and pending health states', () => {
    const base: TraceManifest = {
      format_version: 1, trace_id: 'trace-1', command: ['test'], started_at: '', ended_at: '2026-01-01',
      exit_code: 0, journal: null, integrity: 'verified'
    };
    expect(runHealth(base, [])).toMatchObject({ label: 'Passed', detail: expect.stringContaining('integrity verified') });
    expect(runHealth({ ...base, ended_at: null, integrity: 'live' }, [])).toMatchObject({ label: 'Running' });
    expect(runHealth(base, [event(1, 'policy', 'approval.decision', 'denied')])).toMatchObject({ label: 'Blocked' });
    expect(runHealth(base, [event(1, 'policy', 'approval.request', 'pending')])).toMatchObject({ label: 'Awaiting approval' });
  });

  it('survives null and array payloads in event summaries', () => {
    expect(eventSummary({ ...event(1, 'root', 'agent.turn'), payload_json: 'null' })).toBe('null payload');
    expect(eventSummary({ ...event(2, 'root', 'agent.turn'), payload_json: '["a","b"]' })).toContain('a');
    expect(eventSummary({ ...event(3, 'root', 'agent.turn'), payload_json: '42' })).toBe('42');
  });


  it('extracts category-specific evidence instead of displaying the source', () => {
    const model = { ...event(1, 'researcher', 'model.response'), payload_json: JSON.stringify({ model: 'frontier-mini', summary: 'Found the divergence', tokens: 42 }) };
    const tool = { ...event(2, 'coder', 'tool.execution'), payload_json: JSON.stringify({ tool: 'rg', query: 'reconcileInvoice' }) };
    expect(eventSummary(model)).toBe('frontier-mini · Found the divergence · 42 tokens');
    expect(eventSummary(tool)).toBe('rg · query: reconcileInvoice');
  });

  it('summarizes shell wrappers and agent coordination without leaking command payloads', () => {
    const session = { ...event(1, 'root', 'session.start'), payload_json: JSON.stringify({ command: ['sh', '-c', 'post a very long collector harness'] }) };
    const delegation = { ...event(2, 'coordinator', 'agent.delegation'), payload_json: JSON.stringify({ delegates: ['auditor', 'reviewer'], execution: 'parallel' }) };
    const joined = { ...event(3, 'coordinator', 'agent.join'), payload_json: JSON.stringify({ joined: ['auditor', 'reviewer'], outcome: 'review complete' }) };
    expect(eventSummary(session)).toBe('Shell trace recording started');
    expect(eventSummary(delegation)).toBe('Delegated to auditor, reviewer');
    expect(eventSummary(joined)).toBe('Joined auditor, reviewer · review complete');
  });

  it('maps cross-actor parentage into causal lanes', () => {
    const parent = { ...event(1, 'coordinator', 'agent.delegation'), event_id: 'parent', span_id: 'delegate' };
    const child = { ...event(2, 'researcher', 'agent.spawn'), parent_event_id: 'parent', parent_span_id: 'delegate' };
    const layout = timelineLayout([parent, child]);
    expect(layout.lanes).toEqual(['coordinator', 'researcher']);
    expect(layout.events[1]).toMatchObject({ lane: 1, parentLane: 0, depth: 1, elapsedMs: 0 });
  });
});
