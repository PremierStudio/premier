import type { ConflictHunk, LaneConflict } from "../api";

export const MARKER_LINE_RE = /^(<{7}|={7}|>{7})(\s|$)/m;

const WHOLE_FILE_CONFLICT_KINDS = new Set(["add_add", "modify_delete", "delete_modify"]);
const UNSUPPORTED_CUSTOM_EDIT_KINDS = new Set([
  "binary_conflict",
  "mode_conflict",
  "path_type_collision",
]);

export type CustomEditEligibility =
  | { ok: true; mode: "whole_file" | "splice" }
  | { ok: false; reason: string };

export function canCustomEditConflict(conflict: LaneConflict): CustomEditEligibility {
  if (!conflict.allowed) {
    return {
      ok: false,
      reason: "This conflict is withheld by server policy and cannot be edited here.",
    };
  }
  if (UNSUPPORTED_CUSTOM_EDIT_KINDS.has(conflict.kind)) {
    return {
      ok: false,
      reason: `Inline text editing is disabled for ${conflict.kind.replace(/_/g, " ")} conflicts. Choose Use Target, Use Agent, or Delete file.`,
    };
  }
  if (WHOLE_FILE_CONFLICT_KINDS.has(conflict.kind)) {
    if (conflict.hunks.length === 1) {
      return { ok: true, mode: "whole_file" };
    }
    return {
      ok: false,
      reason:
        "This conflict does not contain textual file content. Choose Use Target, Use Agent, or Delete file.",
    };
  }
  if (conflict.hunks.length === 0) {
    return {
      ok: false,
      reason:
        "No textual conflict hunks are available for inline editing. Choose Use Target, Use Agent, or Delete file.",
    };
  }
  return { ok: true, mode: "splice" };
}

export function buildWholeFileConflictContent(conflict: LaneConflict): {
  content: string;
  lineCount: number;
} {
  const hunk = conflict.hunks[0];
  const raw =
    hunk?.markers ??
    `<<<<<<< target\n${hunk?.ours_lines.join("\n") ?? ""}\n=======\n${hunk?.theirs_lines.join("\n") ?? ""}\n>>>>>>> lane\n`;
  const lines = raw.endsWith("\n") ? raw.slice(0, -1).split("\n") : raw.split("\n");
  return { content: raw, lineCount: lines.length };
}

export type SpliceResult =
  | { ok: true; content: string; lineCount: number }
  | { ok: false; reason: string };

function matchesSlice(lines: readonly string[], start: number, needle: readonly string[]): boolean {
  if (start < 0 || start + needle.length > lines.length) return false;
  for (let i = 0; i < needle.length; i++) {
    if (lines[start + i] !== needle[i]) return false;
  }
  return true;
}

function splitPreservingNewline(text: string): {
  lines: string[];
  eol: "\n" | "\r\n";
  hasTrailingNewline: boolean;
} {
  const eol: "\n" | "\r\n" = text.includes("\r\n") ? "\r\n" : "\n";
  const hasTrailingNewline = text.endsWith("\n");
  if (text.length === 0) {
    return { lines: [], eol, hasTrailingNewline: false };
  }
  const normalized = text.replace(/\r\n/g, "\n");
  const trimmed = hasTrailingNewline ? normalized.slice(0, -1) : normalized;
  return { lines: trimmed.split("\n"), eol, hasTrailingNewline };
}

function markerLinesForHunk(hunk: ConflictHunk): string[] {
  const raw = hunk.markers
    ? hunk.markers.replace(/\r\n/g, "\n")
    : [
        "<<<<<<< target",
        ...hunk.ours_lines,
        ...(hunk.base_lines.length > 0 ? ["||||||| base", ...hunk.base_lines] : []),
        "=======",
        ...hunk.theirs_lines,
        ">>>>>>> lane",
      ].join("\n");
  const trimmed = raw.endsWith("\n") ? raw.slice(0, -1) : raw;
  return trimmed.split("\n");
}

/**
 * Reconstructs the full file with diff3 conflict markers spliced into the target ("ours") file
 * so `strategy: "custom"` (which writes the entire file) never truncates surrounding lines.
 */
export function spliceHunksIntoTargetFile(
  targetContent: string,
  hunks: readonly ConflictHunk[],
): SpliceResult {
  if (hunks.length === 0) {
    return {
      ok: false,
      reason: "No conflict hunks to splice into the target file.",
    };
  }

  const { lines: targetLines, eol, hasTrailingNewline } = splitPreservingNewline(targetContent);
  const outLines: string[] = [];
  let cursor = 0;
  let cumulativeDelta = 0;

  for (const hunk of hunks) {
    const markerLines = markerLinesForHunk(hunk);
    const mergedSpan = Math.max(1, hunk.end_line - hunk.start_line + 1);
    const estimatedIdx = hunk.start_line > 0 ? hunk.start_line - 1 - cumulativeDelta : cursor;
    let matchIdx = -1;

    if (hunk.ours_lines.length === 0) {
      if (estimatedIdx >= cursor && estimatedIdx <= targetLines.length) {
        matchIdx = estimatedIdx;
      } else {
        return {
          ok: false,
          reason:
            "Conflict insertion line no longer aligns with the current target file. Rebase the lane or choose Use Target / Use Agent.",
        };
      }
    } else if (
      estimatedIdx >= cursor &&
      matchesSlice(targetLines, estimatedIdx, hunk.ours_lines)
    ) {
      matchIdx = estimatedIdx;
    } else {
      const candidates: number[] = [];
      const maxStart = targetLines.length - hunk.ours_lines.length;
      for (let i = cursor; i <= maxStart; i++) {
        if (matchesSlice(targetLines, i, hunk.ours_lines)) {
          candidates.push(i);
        }
      }
      if (candidates.length === 0) {
        return {
          ok: false,
          reason:
            "Conflict hunk no longer matches the current target file (the branch may have moved). Rebase the lane or choose Use Target / Use Agent.",
        };
      }
      if (candidates.length === 1) {
        matchIdx = candidates[0];
      } else {
        let best = candidates[0];
        let bestDist = Math.abs(best - estimatedIdx);
        let tied = false;
        for (let i = 1; i < candidates.length; i++) {
          const dist = Math.abs(candidates[i] - estimatedIdx);
          if (dist < bestDist) {
            best = candidates[i];
            bestDist = dist;
            tied = false;
          } else if (dist === bestDist) {
            tied = true;
          }
        }
        if (tied) {
          return {
            ok: false,
            reason:
              "Conflict hunk matches multiple identical regions in the target file and cannot be placed unambiguously. Rebase the lane or choose Use Target / Use Agent.",
          };
        }
        matchIdx = best;
      }
    }

    for (let i = cursor; i < matchIdx; i++) {
      outLines.push(targetLines[i]);
    }
    outLines.push(...markerLines);
    cursor = matchIdx + hunk.ours_lines.length;
    cumulativeDelta += mergedSpan - hunk.ours_lines.length;
  }

  for (let i = cursor; i < targetLines.length; i++) {
    outLines.push(targetLines[i]);
  }

  const joined = outLines.join(eol);
  const content = hasTrailingNewline && outLines.length > 0 ? `${joined}${eol}` : joined;
  return { ok: true, content, lineCount: outLines.length };
}
