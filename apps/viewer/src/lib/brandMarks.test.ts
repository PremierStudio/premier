import { describe, expect, it } from 'vitest';
import { resolveProviderBrand } from './brandMarks';

describe('resolveProviderBrand', () => {
  it('maps anthropic / claude family', () => {
    expect(resolveProviderBrand('anthropic', 'claude-sonnet').brand).toBe('anthropic');
    expect(resolveProviderBrand(null, 'claude-3-opus').brand).toBe('anthropic');
  });

  it('maps openai / codex family', () => {
    expect(resolveProviderBrand('openai', 'gpt-5').brand).toBe('openai');
    expect(resolveProviderBrand(null, 'codex-mini').brand).toBe('openai');
  });

  it('maps xai / grok family', () => {
    expect(resolveProviderBrand('xai', 'grok-3').brand).toBe('xai');
    expect(resolveProviderBrand(null, 'grok-beta').brand).toBe('xai');
  });

  it('maps google / gemini family', () => {
    expect(resolveProviderBrand('google', 'gemini-2.0-flash').brand).toBe('google');
  });

  it('falls back to unknown', () => {
    expect(resolveProviderBrand('acme', 'custom-7b').brand).toBe('unknown');
  });
});
