<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { Check, ChevronDown } from '@lucide/svelte';
  import { portal } from './interactions';

  export type PremierSelectOption = { value: string; label: string; description?: string; disabled?: boolean };

  let { value, options, label, disabled = false, placeholder = 'Select…', onchange }: {
    value: string;
    options: PremierSelectOption[];
    label: string;
    disabled?: boolean;
    placeholder?: string;
    onchange: (value: string) => void;
  } = $props();

  let open = $state(false);
  let activeIndex = $state(0);
  let root = $state<HTMLDivElement>();
  let trigger = $state<HTMLButtonElement>();
  let menu = $state<HTMLDivElement>();
  let menuStyle = $state('');
  let typeahead = '';
  let typeaheadTimer: number | null = null;
  const selected = $derived(options.find((option) => option.value === value) ?? null);

  function enabledIndex(from: number, direction = 1): number {
    if (!options.length) return -1;
    for (let step = 0; step < options.length; step += 1) {
      const index = (from + step * direction + options.length) % options.length;
      if (!options[index]?.disabled) return index;
    }
    return -1;
  }

  function positionMenu(): void {
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const spaceBelow = innerHeight - rect.bottom - 10;
    const spaceAbove = rect.top - 10;
    const openAbove = spaceBelow < 210 && spaceAbove > spaceBelow;
    const maxHeight = Math.max(120, Math.min(320, openAbove ? spaceAbove : spaceBelow));
    const width = Math.min(Math.max(rect.width, 220), Math.max(220, innerWidth - 20));
    const left = Math.max(10, Math.min(rect.left, innerWidth - width - 10));
    menuStyle = `--menu-left:${left}px;--menu-top:${openAbove ? rect.top : rect.bottom}px;--menu-width:${width}px;--menu-height:${maxHeight}px;--menu-transform:${openAbove ? 'translateY(calc(-100% - 6px))' : 'translateY(6px)'}`;
  }

  async function showMenu(): Promise<void> {
    if (disabled || !options.length) return;
    const selectedIndex = options.findIndex((option) => option.value === value && !option.disabled);
    activeIndex = selectedIndex >= 0 ? selectedIndex : enabledIndex(0);
    open = true;
    await tick();
    positionMenu();
    menu?.querySelector<HTMLElement>(`[data-index="${activeIndex}"]`)?.focus();
  }

  function closeMenu(focusTrigger = false): void {
    open = false;
    if (focusTrigger) void tick().then(() => trigger?.focus());
  }

  function choose(option: PremierSelectOption): void {
    if (option.disabled) return;
    onchange(option.value);
    closeMenu(true);
  }

  function triggerKeydown(event: KeyboardEvent): void {
    if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(event.key)) {
      event.preventDefault();
      void showMenu();
    }
  }

  function optionKeydown(event: KeyboardEvent): void {
    if (event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      return closeMenu(true);
    }
    if (event.key === 'Tab') return closeMenu();
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      const option = options[activeIndex];
      if (option) return choose(option);
      return;
    }
    if (event.key.length === 1 && !event.metaKey && !event.ctrlKey && !event.altKey) {
      typeahead += event.key.toLocaleLowerCase();
      if (typeaheadTimer) window.clearTimeout(typeaheadTimer);
      typeaheadTimer = window.setTimeout(() => { typeahead = ''; typeaheadTimer = null; }, 650);
      const match = options.findIndex((option) => !option.disabled && option.label.toLocaleLowerCase().startsWith(typeahead));
      if (match >= 0) {
        activeIndex = match;
        menu?.querySelector<HTMLElement>(`[data-index="${activeIndex}"]`)?.focus();
      }
      return;
    }
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    if (event.key === 'Home') activeIndex = enabledIndex(0);
    else if (event.key === 'End') activeIndex = enabledIndex(options.length - 1, -1);
    else activeIndex = enabledIndex(activeIndex + (event.key === 'ArrowDown' ? 1 : -1), event.key === 'ArrowDown' ? 1 : -1);
    menu?.querySelector<HTMLElement>(`[data-index="${activeIndex}"]`)?.focus();
  }

  onMount(() => {
    const outside = (event: PointerEvent) => {
      const target = event.target as Node;
      if (open && !root?.contains(target) && !menu?.contains(target)) closeMenu();
    };
    const reposition = () => { if (open) positionMenu(); };
    document.addEventListener('pointerdown', outside, true);
    window.addEventListener('resize', reposition);
    window.addEventListener('scroll', reposition, true);
    return () => {
      document.removeEventListener('pointerdown', outside, true);
      window.removeEventListener('resize', reposition);
      window.removeEventListener('scroll', reposition, true);
      if (typeaheadTimer) window.clearTimeout(typeaheadTimer);
    };
  });
</script>

<div class="premier-select" bind:this={root}>
  <button bind:this={trigger} type="button" class="select-trigger" aria-label={label} aria-haspopup="listbox" aria-expanded={open} {disabled} onclick={() => open ? closeMenu() : showMenu()} onkeydown={triggerKeydown}>
    <span><strong>{selected?.label ?? placeholder}</strong>{#if selected?.description}<small>{selected.description}</small>{/if}</span>
    <ChevronDown size={16} strokeWidth={1.8} aria-hidden="true" />
  </button>
  {#if open}
    <div use:portal bind:this={menu} class="select-menu" style={menuStyle} role="listbox" tabindex="-1" aria-label={`${label} options`} onkeydown={optionKeydown}>
      {#each options as option, index (option.value)}
        <button type="button" role="option" aria-selected={option.value === value} disabled={option.disabled} data-index={index} tabindex={index === activeIndex ? 0 : -1} onclick={() => choose(option)} onpointerenter={() => { if (!option.disabled) activeIndex = index; }}>
          <span><strong>{option.label}</strong>{#if option.description}<small>{option.description}</small>{/if}</span>
          {#if option.value === value}<Check size={16} strokeWidth={2.2} aria-hidden="true" />{/if}
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .premier-select { min-width: 0; }
  .select-trigger { width: 100%; min-width: 0; min-height: 42px; display: grid; grid-template-columns: minmax(0,1fr) auto; align-items: center; gap: 10px; padding: 7px 10px 7px 12px; border: 1px solid #344156; border-radius: 7px; color: #e9eef5; background: linear-gradient(180deg,#121925,#0e141e); box-shadow: inset 0 1px rgba(255,255,255,.035); text-align: left; cursor: pointer; }
  .select-trigger:hover:not(:disabled), .select-trigger[aria-expanded='true'] { border-color: #5a77c1; background: linear-gradient(180deg,#182235,#111926); }
  .select-trigger[aria-expanded='true'] { box-shadow: 0 0 0 3px rgba(111,123,247,.12), inset 0 1px rgba(255,255,255,.05); }
  .select-trigger:disabled { opacity: .45; cursor: not-allowed; }
  .select-trigger > span, .select-menu button > span { min-width: 0; }
  .select-trigger strong, .select-trigger small, .select-menu strong, .select-menu small { display: block; min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
  .select-trigger strong { font-size: 12px; font-weight: 700; }
  .select-trigger small { margin-top: 2px; color: #8290a4; font-size: 9px; }
  .select-trigger :global(svg) { color: #8496b2; transition: transform .14s ease; }
  .select-trigger[aria-expanded='true'] :global(svg) { color: #9bb4ff; transform: rotate(180deg); }
  .select-menu { position: fixed; z-index: 100; left: var(--menu-left); top: var(--menu-top); width: var(--menu-width); max-height: var(--menu-height); padding: 5px; overflow-y: auto; transform: var(--menu-transform); border: 1px solid #40506a; border-radius: 9px; background: rgba(10,14,21,.985); box-shadow: 0 22px 70px rgba(0,0,0,.68), inset 0 1px rgba(255,255,255,.045); backdrop-filter: blur(18px); }
  .select-menu button { width: 100%; min-width: 0; min-height: 42px; display: grid; grid-template-columns: minmax(0,1fr) 18px; align-items: center; gap: 10px; padding: 7px 9px; border: 0; border-radius: 5px; color: #cbd5e2; background: transparent; text-align: left; cursor: pointer; }
  .select-menu button:hover:not(:disabled), .select-menu button:focus-visible { color: white; background: rgba(111,123,247,.15); outline: 1px solid rgba(158,170,255,.28); }
  .select-menu button[aria-selected='true'] { color: #f4f7fb; background: rgba(111,123,247,.19); }
  .select-menu button:disabled { opacity: .4; cursor: not-allowed; }
  .select-menu strong { font-size: 12px; font-weight: 700; }
  .select-menu small { margin-top: 2px; color: #7f8da2; font-size: 9px; }
  .select-menu :global(svg) { justify-self: end; color: #83a1ff; }
</style>
