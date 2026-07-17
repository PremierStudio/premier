import { actorId } from './analysis';
import { eventPayload, type TraceEvent } from './types';

export type PromptRole = 'system' | 'developer' | 'user' | 'tool' | 'assistant';

export interface PromptEvidence {
  role: PromptRole;
  text: string;
  source: string;
  characters: number;
  tokens: number | null;
}

export interface TokenUsage {
  input: number | null;
  output: number | null;
  cacheRead: number | null;
  cacheWrite: number | null;
  reasoning: number | null;
  total: number | null;
}

export interface ModelCallUsage {
  event: TraceEvent;
  actor: string;
  provider: string | null;
  model: string;
  tokens: TokenUsage;
  costUsd: number | null;
  prompts: PromptEvidence[];
  response: string | null;
  toolSchemaCount: number;
}

export interface ModelUsageRollup {
  key: string;
  actor: string;
  provider: string | null;
  model: string;
  calls: number;
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
  reasoning: number;
  total: number;
  costUsd: number;
  hasInput: boolean;
  hasOutput: boolean;
  hasCacheRead: boolean;
  hasCacheWrite: boolean;
  hasReasoning: boolean;
  hasTotal: boolean;
  hasCost: boolean;
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function finite(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.max(0, value);
  if (typeof value === 'string' && value.trim() && Number.isFinite(Number(value))) return Math.max(0, Number(value));
  return null;
}

function numberFrom(sources: Array<Record<string, unknown> | null>, keys: string[]): number | null {
  for (const source of sources) {
    if (!source) continue;
    for (const key of keys) {
      const value = finite(source[key]);
      if (value !== null) return value;
    }
  }
  return null;
}

function stringFrom(source: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function textOf(value: unknown): string | null {
  if (typeof value === 'string') return value.trim() || null;
  if (Array.isArray(value)) {
    const joined = value.map((item) => {
      const itemRecord = record(item);
      return itemRecord ? textOf(itemRecord.text ?? itemRecord.content ?? itemRecord.input_text ?? itemRecord.output_text) : textOf(item);
    }).filter(Boolean).join('\n');
    return joined || null;
  }
  const valueRecord = record(value);
  if (!valueRecord) return null;
  return textOf(valueRecord.text ?? valueRecord.content ?? valueRecord.input_text ?? valueRecord.output_text);
}

function normalizedRole(value: unknown): PromptRole | null {
  const role = typeof value === 'string' ? value.toLowerCase() : '';
  if (role === 'system' || role === 'developer' || role === 'user' || role === 'tool' || role === 'assistant') return role;
  return null;
}

function roleTokenMap(payload: Record<string, unknown>, usage: Record<string, unknown> | null): Record<string, number> {
  const candidates = [usage?.input_tokens_by_role, usage?.prompt_tokens_by_role, payload.input_tokens_by_role, payload.prompt_tokens_by_role];
  for (const candidate of candidates) {
    const candidateRecord = record(candidate);
    if (!candidateRecord) continue;
    return Object.fromEntries(Object.entries(candidateRecord).flatMap(([key, value]) => {
      const numeric = finite(value);
      return numeric === null ? [] : [[key.toLowerCase(), numeric]];
    }));
  }
  return {};
}

function promptEvidence(payload: Record<string, unknown>, usage: Record<string, unknown> | null): { prompts: PromptEvidence[]; toolSchemaCount: number } {
  const roleTokens = roleTokenMap(payload, usage);
  const prompts: PromptEvidence[] = [];
  const seen = new Set<string>();
  const add = (role: PromptRole, value: unknown, source: string) => {
    const text = textOf(value);
    if (!text) return;
    const signature = `${role}\u0000${text}`;
    if (seen.has(signature)) return;
    seen.add(signature);
    prompts.push({ role, text, source, characters: text.length, tokens: roleTokens[role] ?? null });
  };

  for (const [role, keys] of Object.entries({
    system: ['system_prompt', 'system', 'system_instruction'],
    developer: ['developer_prompt', 'developer', 'instructions'],
    user: ['user_prompt', 'prompt'],
    assistant: ['assistant_prompt']
  }) as Array<[PromptRole, string[]]>) {
    for (const key of keys) if (payload[key] !== undefined) add(role, payload[key], key);
  }

  const messages = Array.isArray(payload.messages) ? payload.messages : Array.isArray(payload.input) ? payload.input : [];
  for (const [index, message] of messages.entries()) {
    const messageRecord = record(message);
    if (!messageRecord) {
      add('user', message, `input[${index}]`);
      continue;
    }
    const role = normalizedRole(messageRecord.role) ?? 'user';
    add(role, messageRecord.content ?? messageRecord.text ?? messageRecord.input_text, `messages[${index}]`);
  }

  const tools = Array.isArray(payload.tools) ? payload.tools : Array.isArray(payload.tool_definitions) ? payload.tool_definitions : [];
  for (const [index, tool] of tools.entries()) {
    const toolRecord = record(tool);
    const name = toolRecord && typeof toolRecord.name === 'string' ? toolRecord.name : `tool ${index + 1}`;
    add('tool', typeof tool === 'string' ? tool : `${name}\n${JSON.stringify(tool, null, 2)}`, `tools[${index}]`);
  }
  return { prompts, toolSchemaCount: tools.length };
}

export function modelCallUsage(event: TraceEvent): ModelCallUsage | null {
  const payload = eventPayload(event);
  const usage = record(payload.usage);
  const isModelEvent = event.kind.startsWith('model.') || event.kind.startsWith('llm.');
  const hasDirectUsage = ['input_tokens', 'prompt_tokens', 'output_tokens', 'completion_tokens', 'total_tokens', 'tokens', 'cost_usd', 'total_cost_usd']
    .some((key) => finite(payload[key]) !== null);
  if (!isModelEvent && !usage && !hasDirectUsage) return null;
  const inputDetails = record(usage?.input_tokens_details ?? payload.input_tokens_details);
  const outputDetails = record(usage?.output_tokens_details ?? payload.output_tokens_details);
  const model = stringFrom(payload, ['model', 'model_id', 'deployment']) ?? (isModelEvent ? 'Unknown model' : null);

  const input = numberFrom([usage, payload], ['input_tokens', 'prompt_tokens']);
  const output = numberFrom([usage, payload], ['output_tokens', 'completion_tokens']);
  const cacheRead = numberFrom([inputDetails, usage, payload], ['cached_tokens', 'cache_read_tokens', 'cache_read_input_tokens', 'cached_input_tokens']);
  const cacheWrite = numberFrom([inputDetails, usage, payload], ['cache_creation_tokens', 'cache_write_tokens', 'cache_creation_input_tokens']);
  const reasoning = numberFrom([outputDetails, usage, payload], ['reasoning_tokens']);
  const explicitTotal = numberFrom([usage, payload], ['total_tokens', 'tokens']);
  const total = explicitTotal ?? (input !== null || output !== null ? (input ?? 0) + (output ?? 0) : null);
  const { prompts, toolSchemaCount } = promptEvidence(payload, usage);
  return {
    event,
    actor: actorId(event),
    provider: stringFrom(payload, ['provider', 'vendor']),
    model: model ?? 'Unknown model',
    tokens: { input, output, cacheRead, cacheWrite, reasoning, total },
    costUsd: numberFrom([usage, payload], ['cost_usd', 'total_cost_usd', 'cost']),
    prompts,
    response: textOf(payload.response ?? payload.output ?? payload.content ?? payload.text ?? payload.summary),
    toolSchemaCount
  };
}

export function modelUsage(events: TraceEvent[]): { calls: ModelCallUsage[]; rollups: ModelUsageRollup[] } {
  const calls = events.map(modelCallUsage).filter((call): call is ModelCallUsage => call !== null);
  const groups = new Map<string, ModelUsageRollup>();
  for (const call of calls) {
    const key = `${call.provider ?? ''}\u0000${call.model}\u0000${call.actor}`;
    const current = groups.get(key) ?? {
      key, actor: call.actor, provider: call.provider, model: call.model, calls: 0,
      input: 0, output: 0, cacheRead: 0, cacheWrite: 0, reasoning: 0, total: 0, costUsd: 0,
      hasInput: false, hasOutput: false, hasCacheRead: false, hasCacheWrite: false, hasReasoning: false, hasTotal: false, hasCost: false
    };
    current.calls += 1;
    for (const key of ['input', 'output', 'cacheRead', 'cacheWrite', 'reasoning', 'total'] as const) {
      const value = call.tokens[key];
      if (value !== null) {
        current[key] += value;
        current[`has${key[0].toUpperCase()}${key.slice(1)}` as 'hasInput'] = true;
      }
    }
    if (call.costUsd !== null) { current.costUsd += call.costUsd; current.hasCost = true; }
    groups.set(key, current);
  }
  return { calls, rollups: [...groups.values()].sort((a, b) => b.total - a.total || b.calls - a.calls) };
}
