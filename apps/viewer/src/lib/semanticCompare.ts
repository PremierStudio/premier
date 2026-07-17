import { modelCallUsage } from './modelUsage';
import { eventPayload, type TraceEvent } from './types';

export type ComparisonStatus = 'added' | 'removed' | 'changed' | 'unchanged';

export interface FieldChange {
  field: string;
  before: unknown;
  after: unknown;
}

export interface NumericDelta {
  before: number;
  after: number;
  delta: number;
}

export interface ComparisonItem {
  key: string;
  status: ComparisonStatus;
  baseline: TraceEvent | null;
  current: TraceEvent | null;
  changes: FieldChange[];
  deltas: {
    durationMs: NumericDelta | null;
    totalTokens: NumericDelta | null;
    costUsd: NumericDelta | null;
  };
}

export interface TraceComparison {
  items: ComparisonItem[];
  counts: Record<ComparisonStatus, number>;
}

function clean(value: string): string {
  return value.trim().toLowerCase().replace(/\s+/g, ' ');
}

function payloadIdentity(event: TraceEvent): string {
  const payload = eventPayload(event);
  if (event.kind.startsWith('tool.')) {
    const tool = payload.tool ?? payload.name ?? payload.command;
    return tool === undefined ? '' : `:${clean(typeof tool === 'string' ? tool : JSON.stringify(tool))}`;
  }
  if (event.kind.startsWith('approval.')) {
    const operation = payload.operation ?? payload.action;
    return operation === undefined ? '' : `:${clean(String(operation))}`;
  }
  return '';
}

/** A cross-run identity: intentionally excludes generated event/span/correlation ids. */
export function semanticEventKey(event: TraceEvent): string {
  return `${clean(event.kind)}:${clean(event.actor_id || 'root')}${payloadIdentity(event)}`;
}

function comparablePayload(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(comparablePayload);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .filter(([key]) => !['event_id', 'trace_id', 'span_id', 'parent_span_id', 'correlation_id', 'timestamp', 'created_at'].includes(key))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, item]) => [key, comparablePayload(item)]));
}

function flatten(value: unknown, prefix: string, output = new Map<string, unknown>()): Map<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const entries = Object.entries(value as Record<string, unknown>);
    if (!entries.length) output.set(prefix, {});
    else for (const [key, item] of entries) flatten(item, prefix ? `${prefix}.${key}` : key, output);
  } else {
    output.set(prefix, value);
  }
  return output;
}

function equal(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function round(value: number): number {
  return Math.round(value * 1_000_000) / 1_000_000;
}

function delta(before: number | null, after: number | null): NumericDelta | null {
  if (before === null || after === null || before === after) return null;
  return { before, after, delta: round(after - before) };
}

function comparePair(key: string, baseline: TraceEvent, current: TraceEvent): ComparisonItem {
  const beforePayload = comparablePayload(eventPayload(baseline));
  const afterPayload = comparablePayload(eventPayload(current));
  const before = flatten(beforePayload, 'payload');
  const after = flatten(afterPayload, 'payload');
  const fields = new Set([...before.keys(), ...after.keys()]);
  const changes: FieldChange[] = [];
  if (baseline.status !== current.status) changes.push({ field: 'status', before: baseline.status, after: current.status });
  if (baseline.source !== current.source) changes.push({ field: 'source', before: baseline.source, after: current.source });
  if (baseline.actor_type !== current.actor_type) changes.push({ field: 'actor_type', before: baseline.actor_type, after: current.actor_type });
  for (const field of [...fields].sort()) {
    if (!equal(before.get(field), after.get(field))) changes.push({ field, before: before.get(field), after: after.get(field) });
  }
  const beforeModel = modelCallUsage(baseline);
  const afterModel = modelCallUsage(current);
  const deltas = {
    durationMs: delta(baseline.duration_ms, current.duration_ms),
    totalTokens: delta(beforeModel?.tokens.total ?? null, afterModel?.tokens.total ?? null),
    costUsd: delta(beforeModel?.costUsd ?? null, afterModel?.costUsd ?? null)
  };
  const changed = changes.length > 0 || Object.values(deltas).some(Boolean);
  return { key, status: changed ? 'changed' : 'unchanged', baseline, current, changes, deltas };
}

function oneSided(key: string, status: 'added' | 'removed', event: TraceEvent): ComparisonItem {
  return {
    key,
    status,
    baseline: status === 'removed' ? event : null,
    current: status === 'added' ? event : null,
    changes: [],
    deltas: { durationMs: null, totalTokens: null, costUsd: null }
  };
}

export function compareTraces(baselineInput: TraceEvent[], currentInput: TraceEvent[]): TraceComparison {
  const baseline = [...baselineInput].sort((a, b) => a.sequence - b.sequence);
  const current = [...currentInput].sort((a, b) => a.sequence - b.sequence);
  const currentGroups = new Map<string, TraceEvent[]>();
  for (const event of current) {
    const key = semanticEventKey(event);
    currentGroups.set(key, [...(currentGroups.get(key) ?? []), event]);
  }
  const usedCurrent = new Set<string>();
  const occurrences = new Map<string, number>();
  const items: ComparisonItem[] = [];
  for (const event of baseline) {
    const key = semanticEventKey(event);
    const occurrence = occurrences.get(key) ?? 0;
    occurrences.set(key, occurrence + 1);
    const match = currentGroups.get(key)?.[occurrence];
    if (match) {
      usedCurrent.add(match.event_id);
      items.push(comparePair(`${key}#${occurrence + 1}`, event, match));
    } else {
      items.push(oneSided(`${key}#${occurrence + 1}`, 'removed', event));
    }
  }
  const addedOccurrences = new Map<string, number>();
  for (const event of current) {
    if (usedCurrent.has(event.event_id)) continue;
    const key = semanticEventKey(event);
    const index = (addedOccurrences.get(key) ?? (occurrences.get(key) ?? 0)) + 1;
    addedOccurrences.set(key, index);
    items.push(oneSided(`${key}#${index}`, 'added', event));
  }
  const counts: Record<ComparisonStatus, number> = { added: 0, removed: 0, changed: 0, unchanged: 0 };
  for (const item of items) counts[item.status] += 1;
  return { items, counts };
}
