<script lang="ts">
  import { PROVIDER_MARKS, type ProviderMarkId } from '@premier/brand';
  import { resolveProviderBrand, type ProviderBrand } from './brandMarks';

  let {
    provider = null,
    model = null,
    brand: brandOverride = null,
    size = 14,
    title = ''
  }: {
    provider?: string | null;
    model?: string | null;
    brand?: ProviderBrand | null;
    size?: number;
    title?: string;
  } = $props();

  const identity = $derived(
    brandOverride
      ? { ...resolveProviderBrand(brandOverride), brand: brandOverride }
      : resolveProviderBrand(provider, model)
  );
  const label = $derived(title || identity.label);
  const sharedMark = $derived(
    ({ anthropic: 'anthropic', openai: 'openai', google: 'google', xai: 'xai' } as Partial<Record<ProviderBrand, ProviderMarkId>>)[identity.brand]
  );
</script>

<span class="brand-icon" data-brand={identity.brand} style={`--brand:${identity.color};--size:${size}px`} title={label} aria-hidden="true">
  {#if sharedMark}
    <svg viewBox={PROVIDER_MARKS[sharedMark].viewBox} fill="currentColor" aria-hidden="true">
      <path d={PROVIDER_MARKS[sharedMark].path}/>
    </svg>
  {:else if identity.brand === 'meta'}
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 5.5c-1.9 0-3.4 2.4-4.1 5.7C7.1 8.4 5.8 6.8 4.4 6.8 2.3 6.8.8 9.7.8 14.2S2.3 21.6 4.4 21.6c1.6 0 3.1-1.9 4-5.1.5 3.1 2 5.1 3.6 5.1s3.1-2 3.6-5.1c.9 3.2 2.4 5.1 4 5.1 2.1 0 3.6-2.9 3.6-7.4S21.7 6.8 19.6 6.8c-1.4 0-2.7 1.6-3.5 4.4C15.4 7.9 13.9 5.5 12 5.5z"/>
    </svg>
  {:else if identity.brand === 'mistral'}
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M3 4h5v5H3V4zm6.5 0h5v5h-5V4zM16 4h5v5h-5V4zM3 10.5h5v5H3v-5zm13 0h5v5h-5v-5zM3 17h5v3H3v-3zm6.5 0h5v3h-5v-3zM16 17h5v3h-5v-3z"/>
    </svg>
  {:else if identity.brand === 'amazon'}
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M15.9 17.1c-2.3 1.7-5.6 2.6-8.5 2.6-4 0-7.6-1.5-10.3-4 .4.2.8.3 1.2.4 3.4 1.4 7.1 1.1 10.2-.6 1.5-.8 3.1-2.1 4.2-3.6.1-.2.4-.1.3.1-.7 2.1-2.3 3.9-4.1 5.1h.1zm5.4-2.4c-.3-.4-1.8-.2-2.5-.1-.2 0-.3-.1-.1-.3.7-.9 1.9-1.1 2.1-1.2.1 0 .9-.2 1.4.3.1.1.2.5.1 1-.1.4-.6.8-1 .9z"/>
      <path d="M14.1 4.3c0-.5.1-1.1.3-1.5.1-.2.2-.3.2-.4 0-.1-.1-.2-.2-.1-.9.4-1.5 1.3-1.5 2.4 0 1.1.7 1.8 1.5 1.6.1 0 .2-.1.2-.2 0 0-.1-.1-.2-.2-.4-.4-.5-1-.3-1.6z"/>
    </svg>
  {:else}
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true">
      <path d="M12 3l2.1 4.3 4.7.7-3.4 3.3.8 4.7L12 13.8 7.8 16l.8-4.7L5.2 8l4.7-.7L12 3z"/>
    </svg>
  {/if}
</span>

<style>
  .brand-icon {
    display: inline-grid;
    place-items: center;
    width: var(--size);
    height: var(--size);
    min-width: var(--size);
    min-height: var(--size);
    flex: 0 0 auto;
    color: var(--brand);
    line-height: 0;
    overflow: hidden;
  }
  .brand-icon :global(svg) {
    display: block;
    width: 100%;
    height: 100%;
  }
</style>
