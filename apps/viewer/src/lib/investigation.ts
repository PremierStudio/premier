import { actorId, eventSummary, isIssue, runHealth } from './analysis';
import { modelCallUsage } from './modelUsage';
import type { TraceEvent, TraceManifest } from './types';

export type EvidenceConfidence = 'high' | 'medium' | 'low';
export type GapSeverity = 'high' | 'medium' | 'low';

export interface InvestigationCause {
  title: string;
  detail: string;
  confidence: EvidenceConfidence;
  event: TraceEvent | null;
}

export interface ChainEvidence {
  rank: number;
  relation: 'context' | 'cause' | 'effect' | 'correlated';
  event: TraceEvent;
  summary: string;
}

export interface InvestigationHotspot {
  rank: number;
  event: TraceEvent;
  label: string;
  durationMs: number | null;
  costUsd: number | null;
  totalTokens: number | null;
  score: number;
}

export interface EvidenceGap {
  id: string;
  severity: GapSeverity;
  label: string;
  detail: string;
}

export interface RecommendedEvidence {
  event: TraceEvent;
  reason: string;
}

export interface InvestigationSummary {
  outcome: ReturnType<typeof runHealth>;
  cause: InvestigationCause;
  chainKind: 'failure' | 'critical';
  failureChain: ChainEvidence[];
  hotspots: InvestigationHotspot[];
  gaps: EvidenceGap[];
  recommendedEvent: RecommendedEvidence | null;
}

function sorted(events: TraceEvent[]): TraceEvent[] {
  return [...events].sort((a, b) => a.sequence - b.sequence || a.event_id.localeCompare(b.event_id));
}

function exitEvent(events: TraceEvent[]): TraceEvent | null {
  return [...events].reverse().find((event) => ['process.exit', 'session.end', 'session.interrupted'].includes(event.kind)) ?? null;
}

function primaryIssue(events: TraceEvent[]): TraceEvent | null {
  // The first explicit failure is normally the causal divergence. Later failures are
  // commonly propagation, cleanup, or the final process result.
  return events.find(isIssue) ?? null;
}

function causeFor(trace: TraceManifest, events: TraceEvent[]): InvestigationCause {
  if (!events.length) {
    return {
      title: trace.ended_at === null ? 'Waiting for evidence' : 'No evidence captured',
      detail: trace.ended_at === null ? 'The run is active but has not emitted an event yet.' : 'The recorder produced no events for this run.',
      confidence: 'low',
      event: null
    };
  }
  if (trace.integrity === 'invalid') {
    return {
      title: 'Trace integrity failed',
      detail: trace.integrity_detail?.trim() || 'The journal does not match the recorded manifest digest.',
      confidence: 'high',
      event: null
    };
  }
  const issue = primaryIssue(events);
  if (issue) {
    return {
      title: `${issue.kind} in ${actorId(issue)}`,
      detail: eventSummary(issue),
      confidence: issue.status || issue.kind.includes('error') || issue.kind.includes('fail') ? 'high' : 'medium',
      event: issue
    };
  }
  if (trace.termination?.kind === 'interrupted') {
    return {
      title: 'Recorder interruption recovered',
      detail: 'The journal was salvaged and finalized after the recorder stopped before normal publication.',
      confidence: 'high',
      event: exitEvent(events)
    };
  }
  if (trace.termination?.kind === 'signal') {
    const signal = trace.termination.signal_name?.trim() || (trace.termination.signal ? `signal ${trace.termination.signal}` : 'a signal');
    return {
      title: `Process terminated by ${signal}`,
      detail: 'Structured termination metadata identifies how the process stopped.',
      confidence: 'high',
      event: exitEvent(events)
    };
  }
  if (trace.exit_code !== null && trace.exit_code !== 0) {
    const terminal = exitEvent(events);
    return {
      title: `Process exited with status ${trace.exit_code}`,
      detail: 'No explicit failed, blocked, or error event explains the non-zero exit.',
      confidence: 'low',
      event: terminal
    };
  }
  if (trace.ended_at === null || trace.integrity === 'live') {
    const latest = events.at(-1) ?? null;
    return {
      title: 'Run is still active',
      detail: latest ? `Latest evidence: ${eventSummary(latest)}` : 'Waiting for the first recorded event.',
      confidence: 'medium',
      event: latest
    };
  }
  const terminal = exitEvent(events) ?? events.at(-1)!;
  return {
    title: 'No recorded failure',
    detail: 'The run completed cleanly with no explicit error, denial, or blocked operation.',
    confidence: 'high',
    event: terminal
  };
}

function chainFor(events: TraceEvent[], cause: TraceEvent | null, includeCorrelated = true): ChainEvidence[] {
  if (!cause) return [];
  const byId = new Map(events.map((event) => [event.event_id, event]));
  const bySpan = new Map<string, TraceEvent>();
  for (const event of events) if (event.span_id && !bySpan.has(event.span_id)) bySpan.set(event.span_id, event);
  const included = new Map<string, { event: TraceEvent; relation: ChainEvidence['relation'] }>();
  const ancestors: TraceEvent[] = [];
  const seen = new Set<string>([cause.event_id]);
  let cursor = cause;
  while (ancestors.length < 4) {
    const parent = byId.get(cursor.parent_event_id) ?? bySpan.get(cursor.parent_span_id);
    if (!parent || seen.has(parent.event_id)) break;
    seen.add(parent.event_id);
    ancestors.unshift(parent);
    cursor = parent;
  }
  for (const event of ancestors) included.set(event.event_id, { event, relation: 'context' });
  included.set(cause.event_id, { event: cause, relation: 'cause' });

  let frontier = [cause.event_id];
  for (let depth = 0; depth < 3 && frontier.length; depth += 1) {
    const next = events.filter((event) => frontier.includes(event.parent_event_id) && !included.has(event.event_id));
    for (const event of next) included.set(event.event_id, { event, relation: 'effect' });
    frontier = next.map((event) => event.event_id);
  }
  if (includeCorrelated && cause.correlation_id) {
    for (const event of events) {
      if (included.size >= 8) break;
      if (event.correlation_id === cause.correlation_id && !included.has(event.event_id) && Math.abs(event.sequence - cause.sequence) <= 3) {
        included.set(event.event_id, { event, relation: event.sequence < cause.sequence ? 'context' : 'correlated' });
      }
    }
  }
  return [...included.values()]
    .sort((a, b) => a.event.sequence - b.event.sequence)
    .slice(0, 8)
    .map((item, index) => ({ ...item, rank: index + 1, summary: eventSummary(item.event) }));
}

function hotspotsFor(events: TraceEvent[]): InvestigationHotspot[] {
  return events.flatMap((event) => {
    const model = modelCallUsage(event);
    const durationMs = event.duration_ms > 0 ? event.duration_ms : null;
    const costUsd = model?.costUsd ?? null;
    const totalTokens = model?.tokens.total ?? null;
    if (durationMs === null && costUsd === null && totalTokens === null) return [];
    // Cost is the strongest operational signal, then latency and token volume.
    const score = (costUsd ?? 0) * 1_000_000 + (durationMs ?? 0) * 10 + (totalTokens ?? 0);
    return [{ rank: 0, event, label: eventSummary(event), durationMs, costUsd, totalTokens, score }];
  }).sort((a, b) => b.score - a.score || a.event.sequence - b.event.sequence)
    .slice(0, 5)
    .map((item, index) => ({ ...item, rank: index + 1 }));
}

function gapsFor(trace: TraceManifest, events: TraceEvent[]): EvidenceGap[] {
  const gaps: EvidenceGap[] = [];
  const add = (gap: EvidenceGap) => { if (!gaps.some((existing) => existing.id === gap.id)) gaps.push(gap); };
  for (const diagnostic of trace.diagnostics ?? []) {
    const lifecycle = diagnostic.code.includes('lifecycle') || diagnostic.code.includes('pair');
    add({
      id: `diagnostic-${diagnostic.code}`,
      severity: 'medium',
      label: lifecycle ? 'Recorded lifecycle evidence is incomplete' : 'Recorded evidence needs review',
      detail: diagnostic.message
    });
  }
  if (!events.length) add({ id: 'no-events', severity: 'high', label: 'No events captured', detail: 'Instrument the run before relying on its outcome or architecture.' });
  if (trace.exit_code !== null && trace.exit_code !== 0 && !trace.termination && !events.some(isIssue)) {
    add({ id: 'exit-cause', severity: 'high', label: 'Exit cause is missing', detail: 'A non-zero exit was recorded without a failed, blocked, denied, or error event.' });
  }
  const ids = new Set(events.map((event) => event.event_id));
  const spans = new Set(events.map((event) => event.span_id).filter(Boolean));
  const brokenParents = events.filter((event) => event.parent_event_id && !ids.has(event.parent_event_id) && (!event.parent_span_id || !spans.has(event.parent_span_id)));
  if (brokenParents.length) add({ id: 'causal-links', severity: 'medium', label: 'Causal links are incomplete', detail: `${brokenParents.length} event${brokenParents.length === 1 ? '' : 's'} reference a parent that is not present.` });
  if (trace.ended_at !== null && events.length && !events.some((event) => ['process.exit', 'session.end', 'session.interrupted', 'trace.complete'].includes(event.kind))) {
    add({ id: 'completion-event', severity: 'medium', label: 'Terminal event is missing', detail: 'The manifest says the run ended, but the journal contains no process exit or completion event.' });
  }
  const models = events.map(modelCallUsage).filter((call): call is NonNullable<ReturnType<typeof modelCallUsage>> => call !== null);
  if (models.some((call) => call.costUsd === null)) add({ id: 'model-cost', severity: 'low', label: 'Some model costs are unknown', detail: 'Capture provider pricing or explicit cost data to rank expensive calls reliably.' });
  if (models.some((call) => call.tokens.total === null)) add({ id: 'model-tokens', severity: 'low', label: 'Some token usage is unknown', detail: 'Capture input and output usage to explain context growth and model spend.' });
  const tools = events.filter((event) => event.kind.startsWith('tool.'));
  if (tools.length && tools.every((event) => event.duration_ms <= 0)) add({ id: 'tool-duration', severity: 'low', label: 'Tool latency is unavailable', detail: 'Record tool durations to identify slow external dependencies and blocked agents.' });
  const severity = { high: 0, medium: 1, low: 2 } as const;
  return gaps.sort((a, b) => severity[a.severity] - severity[b.severity] || a.id.localeCompare(b.id));
}

export function buildInvestigationSummary(trace: TraceManifest, inputEvents: TraceEvent[]): InvestigationSummary {
  const events = sorted(inputEvents);
  const cause = causeFor(trace, events);
  const gaps = gapsFor(trace, events);
  const hotspots = hotspotsFor(events);
  const issue = primaryIssue(events);
  const chainKind = issue ? 'failure' : 'critical';
  const chainAnchor = issue ?? hotspots[0]?.event ?? cause.event;
  const recommended = issue
    ? { event: issue, reason: 'Inspect the first explicit failure and its causal parents.' }
    : trace.exit_code !== null && trace.exit_code !== 0 && exitEvent(events)
      ? { event: exitEvent(events)!, reason: 'Start at the terminal event because no explicit cause was captured.' }
      : hotspots[0]
        ? { event: hotspots[0].event, reason: 'Inspect the run’s highest-impact latency or cost hotspot.' }
        : cause.event
          ? { event: cause.event, reason: trace.ended_at === null ? 'Inspect the latest evidence while the run is active.' : 'Inspect the terminal evidence for outcome context.' }
          : null;
  return {
    outcome: runHealth(trace, events),
    cause,
    chainKind,
    failureChain: chainFor(events, chainAnchor, Boolean(issue)),
    hotspots,
    gaps,
    recommendedEvent: recommended
  };
}
