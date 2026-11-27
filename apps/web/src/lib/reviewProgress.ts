import type { ConcernGroup } from "./reviewConcerns.ts";

export type ReviewViewMode = "guided" | "all";

export interface ReviewProgressStats {
  reviewed: number;
  total: number;
  percent: number;
}

export type ReviewKeyAction =
  | "next"
  | "prev"
  | "toggle_reviewed"
  | "open_comment"
  | "close_composer"
  | null;

const STORAGE_PREFIX = "premier:review:reviewed:";

function getSafeStorage(): Storage | null {
  try {
    if (typeof window !== "undefined" && window.localStorage) {
      return window.localStorage;
    }
    if (typeof localStorage !== "undefined") {
      return localStorage;
    }
    return null;
  } catch {
    return null;
  }
}

export function loadReviewedSet(scopeKey: string): Set<string> {
  const storage = getSafeStorage();
  if (!storage) return new Set<string>();
  try {
    const raw = storage.getItem(`${STORAGE_PREFIX}${scopeKey}`);
    if (!raw) return new Set<string>();
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return new Set<string>();
    return new Set(parsed.filter((entry): entry is string => typeof entry === "string"));
  } catch {
    return new Set<string>();
  }
}

export function saveReviewedSet(scopeKey: string, ids: ReadonlySet<string>): void {
  const storage = getSafeStorage();
  if (!storage) return;
  try {
    storage.setItem(`${STORAGE_PREFIX}${scopeKey}`, JSON.stringify(Array.from(ids)));
  } catch {
    // Ignore storage quota or security errors in restricted browser contexts.
  }
}

export function toggleReviewedId(reviewed: ReadonlySet<string>, id: string): Set<string> {
  const next = new Set(reviewed);
  if (next.has(id)) {
    next.delete(id);
  } else {
    next.add(id);
  }
  return next;
}

export function computeProgress(
  ids: readonly string[],
  reviewed: ReadonlySet<string>,
): ReviewProgressStats {
  const uniqueIds = new Set(ids);
  const total = uniqueIds.size;
  if (total === 0) {
    return { reviewed: 0, total: 0, percent: 0 };
  }
  let count = 0;
  for (const id of uniqueIds) {
    if (reviewed.has(id)) count += 1;
  }
  return {
    reviewed: count,
    total,
    percent: Math.round((count / total) * 100),
  };
}

export function flattenOrderedIds<T>(
  groups: readonly ConcernGroup<T>[],
  allIds: readonly string[],
  viewMode: ReviewViewMode,
): string[] {
  if (viewMode === "all") {
    return [...allIds];
  }
  const ordered: string[] = [];
  for (const group of groups) {
    for (const entry of group.items) {
      ordered.push(entry.id);
    }
  }
  return ordered;
}

export function stepNavigationId(
  orderedIds: readonly string[],
  currentId: string | null,
  direction: "next" | "prev",
): string | null {
  if (orderedIds.length === 0) return null;
  const idx = currentId !== null ? orderedIds.indexOf(currentId) : -1;
  if (idx === -1) {
    return direction === "next" ? orderedIds[0] : orderedIds[orderedIds.length - 1];
  }
  if (direction === "next") {
    return orderedIds[Math.min(orderedIds.length - 1, idx + 1)];
  }
  return orderedIds[Math.max(0, idx - 1)];
}

export function resolveReviewKeyAction(
  key: string,
  ctx: {
    mode: "commits" | "rounds";
    isEditable: boolean;
    hasModifiers: boolean;
    shiftKey: boolean;
    withinGChord: boolean;
    composerOpen: boolean;
  },
): ReviewKeyAction {
  if (key === "Escape") {
    return ctx.composerOpen ? "close_composer" : null;
  }
  if (ctx.isEditable || ctx.hasModifiers || ctx.withinGChord || ctx.shiftKey) {
    return null;
  }
  if (key === "j") return "next";
  if (key === "k") return "prev";
  if (key === "v") return "toggle_reviewed";
  if (key === "c" && ctx.mode === "rounds") return "open_comment";
  return null;
}
