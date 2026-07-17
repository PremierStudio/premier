import { describe, expect, it } from 'vitest';
import { deriveRunIdentity } from './runIdentity';

const manifest = (name: string | null | undefined, command: string[]) => ({ name, command });

describe('deriveRunIdentity', () => {
  it('uses an explicit run name as the strongest identity', () => {
    expect(deriveRunIdentity(
      manifest('Multi-agent failure investigation', ['premier', 'demo']),
      { goal: 'Audit agent authority' },
    )).toEqual({ title: 'Multi-agent failure investigation', source: 'name' });
  });

  it('uses a goal for an unnamed inline shell workflow', () => {
    expect(deriveRunIdentity(
      manifest(null, ['sh', '-c', 'curl --data "$payload" "$url"']),
      { goal: 'Establish the takeover baseline' },
    )).toEqual({ title: 'Establish the takeover baseline', source: 'goal' });
  });

  it('uses a summary when no meaningful name or goal exists', () => {
    expect(deriveRunIdentity(
      manifest(undefined, ['bash', '-c', 'private script body']),
      { summary: 'Auditor and verifier completed in parallel' },
    )).toEqual({ title: 'Auditor and verifier completed in parallel', source: 'summary' });
  });

  it('rejects legacy generic labels in favor of semantic context', () => {
    expect(deriveRunIdentity(
      manifest('Shell agent run', ['sh', '-c', 'private script body']),
      { goal: 'Map PRD requirements to code' },
    )).toEqual({ title: 'Map PRD requirements to code', source: 'goal' });
  });

  it('never exposes a shell body when semantic context is unavailable', () => {
    const body = 'post() { curl "$URL"; }; post secret-payload';
    const identity = deriveRunIdentity(manifest(null, ['sh', '-c', body]));

    expect(identity).toEqual({ title: 'Recorded inline workflow', source: 'fallback' });
    expect(identity.title).not.toContain(body);
  });

  it.each([
    ['node', '-e'],
    ['python3', '-c'],
    ['pwsh', '-Command'],
    ['cmd', '/c'],
  ])('does not expose inline source passed through %s %s', (executable, flag) => {
    expect(deriveRunIdentity(manifest(null, [executable, flag, 'sensitive source']))).toEqual({
      title: 'Recorded inline workflow',
      source: 'fallback',
    });
  });

  it('preserves a concise ordinary command as a truthful identity', () => {
    expect(deriveRunIdentity(manifest(null, ['npm', 'run', 'test:all', '--', '--watch']))).toEqual({
      title: 'npm run test:all --',
      source: 'command',
    });
  });

  it('uses a standalone executable rather than a generic fallback', () => {
    expect(deriveRunIdentity(manifest(null, ['premier']))).toEqual({
      title: 'premier',
      source: 'command',
    });
  });

  it('rejects script-shaped semantic metadata', () => {
    expect(deriveRunIdentity(
      manifest('post() { curl "$URL"; }\npost "$payload"', ['sh', '-c', 'same script']),
    )).toEqual({ title: 'Recorded inline workflow', source: 'fallback' });
  });

  it('normalizes whitespace without truncating meaningful labels', () => {
    const full = 'Investigate authority boundaries across coordinator and delegated agents';
    expect(deriveRunIdentity(manifest(`  ${full}  `, ['premier']))).toEqual({
      title: full,
      source: 'name',
    });
  });
});
