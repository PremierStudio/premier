import type { TraceManifest } from './types';

export interface RunIdentityContext {
  goal?: string | null;
  summary?: string | null;
}

export interface RunIdentity {
  title: string;
  source: 'name' | 'goal' | 'summary' | 'command' | 'fallback';
}

type IdentityManifest = Pick<TraceManifest, 'name' | 'command'>;

const GENERIC_LABELS = new Set([
  'agent run',
  'command run',
  'recorded run',
  'run',
  'shell agent run',
  'shell command',
  'shell run',
]);

const INLINE_CODE_FLAGS: Record<string, Set<string>> = {
  bash: new Set(['-c']),
  cmd: new Set(['/c']),
  dash: new Set(['-c']),
  fish: new Set(['-c']),
  ksh: new Set(['-c']),
  node: new Set(['-e', '--eval']),
  perl: new Set(['-e']),
  powershell: new Set(['-c', '-command']),
  pwsh: new Set(['-c', '-command']),
  python: new Set(['-c']),
  python3: new Set(['-c']),
  ruby: new Set(['-e']),
  sh: new Set(['-c']),
  zsh: new Set(['-c']),
};

function executableName(value: string): string {
  return value.split(/[\\/]/).pop()?.toLowerCase() ?? '';
}

function normalizeSemanticLabel(value: string | null | undefined): string | null {
  if (!value) return null;

  const normalized = value.trim().replace(/\s+/g, ' ');
  if (!normalized || GENERIC_LABELS.has(normalized.toLowerCase())) return null;

  // Semantic metadata occasionally inherits an invocation verbatim. Keep scripts in
  // the command disclosure rather than turning them into navigation labels.
  if (
    value.includes('\n') ||
    /^#!\s*\//.test(normalized) ||
    /(?:^|\s)(?:curl|wget)\s.+(?:--data|-d)\b/i.test(normalized) ||
    /(?:^|\s)(?:function\s+\w+|\w+\s*\(\)\s*\{)/.test(normalized) ||
    /(?:&&|\|\||;\s*(?:curl|post|printf|echo)\b)/i.test(normalized)
  ) return null;

  return normalized;
}

function isInlineCodeInvocation(command: string[]): boolean {
  if (command.length < 2) return false;
  const executable = executableName(command[0]);
  return INLINE_CODE_FLAGS[executable]?.has(command[1].toLowerCase()) ?? false;
}

function commandTitle(command: string[]): string | null {
  if (command.length === 0 || isInlineCodeInvocation(command)) return null;

  const safeArguments = command
    .slice(1, 4)
    .filter((argument) => argument && !argument.includes('\n'));
  if (safeArguments.length === 0) return command[0] || null;

  return [command[0], ...safeArguments].join(' ');
}

/**
 * Derives the stable, human-facing identity of a recorded run.
 *
 * Explicit semantic metadata wins. Inline source passed to a shell or interpreter
 * is never returned; callers can still present the complete invocation separately.
 */
export function deriveRunIdentity(
  manifest: IdentityManifest,
  context: RunIdentityContext = {},
): RunIdentity {
  const candidates: Array<[RunIdentity['source'], string | null | undefined]> = [
    ['name', manifest.name],
    ['goal', context.goal],
    ['summary', context.summary],
  ];

  for (const [source, candidate] of candidates) {
    const title = normalizeSemanticLabel(candidate);
    if (title) return { title, source };
  }

  const title = commandTitle(manifest.command);
  if (title) return { title, source: 'command' };

  return {
    title: isInlineCodeInvocation(manifest.command) ? 'Recorded inline workflow' : 'Recorded run',
    source: 'fallback',
  };
}
