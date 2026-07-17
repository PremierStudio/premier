/** Resolve model/provider brand identity for badges and icons. */

export type ProviderBrand =
  | 'anthropic'
  | 'openai'
  | 'xai'
  | 'google'
  | 'meta'
  | 'mistral'
  | 'amazon'
  | 'cohere'
  | 'unknown';

export interface BrandIdentity {
  brand: ProviderBrand;
  label: string;
  /** CSS color for monochrome fills on dark UI */
  color: string;
}

const BRANDS: Record<ProviderBrand, Omit<BrandIdentity, 'brand'>> = {
  anthropic: { label: 'Anthropic', color: '#D4A27F' },
  openai: { label: 'OpenAI', color: '#10A37F' },
  xai: { label: 'xAI', color: '#E8E8E8' },
  google: { label: 'Google', color: '#8AB4F8' },
  meta: { label: 'Meta', color: '#66B2FF' },
  mistral: { label: 'Mistral', color: '#FF7000' },
  amazon: { label: 'Amazon', color: '#FF9900' },
  cohere: { label: 'Cohere', color: '#39594D' },
  unknown: { label: 'Model', color: '#8BA4FF' }
};

export function resolveProviderBrand(
  provider?: string | null,
  model?: string | null
): BrandIdentity {
  const haystack = `${provider ?? ''} ${model ?? ''}`.toLowerCase();

  if (/anthropic|claude|sonnet|opus|haiku/.test(haystack)) {
    return { brand: 'anthropic', ...BRANDS.anthropic };
  }
  if (/openai|gpt|o1|o3|o4|codex|chatgpt|davinci|whisper/.test(haystack)) {
    return { brand: 'openai', ...BRANDS.openai };
  }
  if (/\bxai\b|grok|spacexai/.test(haystack)) {
    return { brand: 'xai', ...BRANDS.xai };
  }
  if (/google|gemini|bard|palm|vertex/.test(haystack)) {
    return { brand: 'google', ...BRANDS.google };
  }
  if (/meta|llama|llama-?3|facebook/.test(haystack)) {
    return { brand: 'meta', ...BRANDS.meta };
  }
  if (/mistral|mixtral|codestral/.test(haystack)) {
    return { brand: 'mistral', ...BRANDS.mistral };
  }
  if (/amazon|bedrock|titan|nova/.test(haystack)) {
    return { brand: 'amazon', ...BRANDS.amazon };
  }
  if (/cohere|command-?r/.test(haystack)) {
    return { brand: 'cohere', ...BRANDS.cohere };
  }
  return { brand: 'unknown', ...BRANDS.unknown };
}
