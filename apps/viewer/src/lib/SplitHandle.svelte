<script lang="ts">
  import { onDestroy } from 'svelte';
  import { PanelLeftClose, PanelRightClose } from '@lucide/svelte';

  let {
    side,
    label,
    value,
    min,
    max,
    collapsed = false,
    onresize,
    oncollapse
  }: {
    side: 'left' | 'right';
    label: string;
    value: number;
    min: number;
    max: number;
    collapsed?: boolean;
    onresize: (value: number) => void;
    oncollapse: () => void;
  } = $props();

  let dragging = $state(false);
  let startX = 0;
  let startValue = 0;

  function clamp(next: number) {
    return Math.min(max, Math.max(min, next));
  }

  function beginDrag(event: PointerEvent) {
    if (collapsed || event.button !== 0) return;
    event.preventDefault();
    dragging = true;
    startX = event.clientX;
    startValue = value;
    window.addEventListener('pointermove', drag);
    window.addEventListener('pointerup', endDrag, { once: true });
  }

  function drag(event: PointerEvent) {
    const delta = (event.clientX - startX) * (side === 'left' ? 1 : -1);
    onresize(clamp(startValue + delta));
  }

  function endDrag() {
    dragging = false;
    window.removeEventListener('pointermove', drag);
  }

  function handleKeydown(event: KeyboardEvent) {
    if (collapsed) return;
    const step = event.shiftKey ? 32 : 12;
    let next = value;
    if (event.key === 'Home') next = min;
    else if (event.key === 'End') next = max;
    else if (event.key === 'ArrowLeft') next += side === 'left' ? -step : step;
    else if (event.key === 'ArrowRight') next += side === 'left' ? step : -step;
    else return;
    event.preventDefault();
    onresize(clamp(next));
  }

  onDestroy(() => {
    window.removeEventListener('pointermove', drag);
    window.removeEventListener('pointerup', endDrag);
  });
</script>

<div class="split-handle" class:dragging class:collapsed data-side={side}>
  <!-- A focusable separator is an interactive ARIA widget even though it uses a div. -->
  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <div
    class="split-target"
    role="separator"
    aria-label={`Resize ${label}`}
    aria-orientation="vertical"
    aria-valuemin={min}
    aria-valuemax={max}
    aria-valuenow={collapsed ? 0 : Math.round(value)}
    aria-valuetext={collapsed ? `${label} collapsed` : `${Math.round(value)} pixels`}
    title={`Drag to resize ${label}; double-click to reset`}
    tabindex={collapsed ? -1 : 0}
    onpointerdown={beginDrag}
    onkeydown={handleKeydown}
    ondblclick={() => onresize(side === 'left' ? 260 : 420)}
  ></div>
  <button
    class="split-toggle"
    type="button"
    aria-label={`${collapsed ? 'Restore' : 'Collapse'} ${label}`}
    title={`${collapsed ? 'Restore' : 'Collapse'} ${label}`}
    onclick={oncollapse}
  >{#if side === 'left'}<PanelLeftClose size={15} strokeWidth={1.8} aria-hidden="true" />{:else}<PanelRightClose size={15} strokeWidth={1.8} aria-hidden="true" />{/if}</button>
</div>
