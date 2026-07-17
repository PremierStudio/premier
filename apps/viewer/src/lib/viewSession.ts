import type { TraceEvent, TraceManifest } from './types';

const sessionKey = 'premier.viewer.session.v1';
const maxAgeMs = 30 * 60 * 1000;
/** Cap cached events so large journals don't blow sessionStorage. */
const maxCachedEvents = 2_500;

export interface ViewSessionSnapshot {
  version: 1;
  savedAt: number;
  traces: TraceManifest[];
  selectedTrace: TraceManifest;
  events: TraceEvent[];
  selectedSequence: number | null;
}

function canUseStorage(): boolean {
  return typeof sessionStorage !== 'undefined';
}

export function readViewSession(traceId?: string | null): ViewSessionSnapshot | null {
  if (!canUseStorage()) return null;
  try {
    const raw = sessionStorage.getItem(sessionKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as ViewSessionSnapshot;
    if (!parsed || parsed.version !== 1 || !parsed.selectedTrace || !Array.isArray(parsed.events)) return null;
    if (!Number.isFinite(parsed.savedAt) || Date.now() - parsed.savedAt > maxAgeMs) return null;
    if (traceId && parsed.selectedTrace.trace_id !== traceId) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function writeViewSession(input: {
  traces: TraceManifest[];
  selectedTrace: TraceManifest;
  events: TraceEvent[];
  selectedSequence: number | null;
}): void {
  if (!canUseStorage()) return;
  try {
    const snapshot: ViewSessionSnapshot = {
      version: 1,
      savedAt: Date.now(),
      traces: input.traces.slice(0, 80),
      selectedTrace: input.selectedTrace,
      events: input.events.slice(0, maxCachedEvents),
      selectedSequence: input.selectedSequence
    };
    sessionStorage.setItem(sessionKey, JSON.stringify(snapshot));
  } catch {
    // Quota or private mode — paint still works without cache.
  }
}

export function clearViewSession(): void {
  if (!canUseStorage()) return;
  try {
    sessionStorage.removeItem(sessionKey);
  } catch {
    // ignore
  }
}
