import { describe, expect, it } from 'vitest';
import { modelCallUsage, modelUsage } from './modelUsage';
import type { TraceEvent } from './types';

function event(sequence: number, actor = 'researcher', payload: Record<string, unknown> = {}): TraceEvent {
  return {
    event_id: `event-${sequence}`, trace_id: 'trace-usage', sequence,
    timestamp: new Date(Date.parse('2026-07-14T12:00:00Z') + sequence * 1000).toISOString(),
    kind: 'model.response', source: 'test', payload_json: JSON.stringify(payload), actor_id: actor,
    actor_type: 'subagent', parent_event_id: '', span_id: `span-${sequence}`, parent_span_id: '',
    correlation_id: '', status: 'ok', duration_ms: 100, links: []
  };
}

describe('model usage evidence', () => {
  it('attributes exact usage and captured context without double-counting totals', () => {
    const call = modelCallUsage(event(1, 'researcher', {
      provider: 'openai', model: 'gpt-test',
      system_prompt: 'System contract', developer_prompt: 'Developer instruction',
      messages: [{ role: 'user', content: 'User request' }],
      tools: [{ name: 'search', input_schema: { type: 'object' } }],
      usage: {
        input_tokens: 100, output_tokens: 40, total_tokens: 140,
        input_tokens_details: { cached_tokens: 25 },
        output_tokens_details: { reasoning_tokens: 12 },
        input_tokens_by_role: { system: 20, developer: 30, user: 10, tool: 40 },
        cost_usd: 0.003
      },
      response: 'Answer'
    }));

    expect(call?.tokens).toEqual({ input: 100, output: 40, cacheRead: 25, cacheWrite: null, reasoning: 12, total: 140 });
    expect(call?.prompts.map((prompt) => [prompt.role, prompt.tokens])).toEqual([
      ['system', 20], ['developer', 30], ['user', 10], ['tool', 40]
    ]);
    expect(call?.toolSchemaCount).toBe(1);
    expect(call?.response).toBe('Answer');
  });

  it('rolls calls up by model and actor while preserving missing dimensions', () => {
    const usage = modelUsage([
      event(1, 'researcher', { model: 'gpt-test', usage: { input_tokens: 100, output_tokens: 20 } }),
      event(2, 'researcher', { model: 'gpt-test', tokens: 75 }),
      event(3, 'reviewer', { model: 'gpt-test', usage: { input_tokens: 50, output_tokens: 10 }, cost_usd: 0.001 })
    ]);

    expect(usage.calls).toHaveLength(3);
    expect(usage.rollups).toHaveLength(2);
    const researcher = usage.rollups.find((row) => row.actor === 'researcher')!;
    expect(researcher).toMatchObject({ calls: 2, input: 100, output: 20, total: 195, hasInput: true, hasCost: false });
  });

  it('does not invent prompt roles or token breakdowns from a legacy total', () => {
    const call = modelCallUsage(event(1, 'researcher', { model: 'legacy', tokens: 1842, summary: 'finding' }));
    expect(call?.tokens.total).toBe(1842);
    expect(call?.tokens.input).toBeNull();
    expect(call?.prompts).toEqual([]);
  });

  it('does not mistake run metadata that names a model for a model call', () => {
    const metadata = { ...event(0, 'coordinator', { model: 'frontier-large', goal: 'Run the trace' }), kind: 'session.start' };
    expect(modelCallUsage(metadata)).toBeNull();
  });
});
