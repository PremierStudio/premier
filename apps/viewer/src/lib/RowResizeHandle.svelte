<script lang="ts">
  import { onDestroy } from 'svelte';
  let { label, value, min, max, defaultValue, onresize }: { label:string;value:number;min:number;max:number;defaultValue:number;onresize:(value:number)=>void } = $props();
  let dragging = $state(false);
  let startY = 0;
  let startValue = 0;
  const clamp = (next:number) => Math.min(max, Math.max(min, next));
  function beginDrag(event:PointerEvent) { if(event.button!==0)return;event.preventDefault();dragging=true;startY=event.clientY;startValue=value;window.addEventListener('pointermove',drag);window.addEventListener('pointerup',endDrag,{once:true}); }
  function drag(event:PointerEvent) { onresize(clamp(startValue+event.clientY-startY)); }
  function endDrag() { dragging=false;window.removeEventListener('pointermove',drag); }
  function handleKeydown(event:KeyboardEvent) { const step=event.shiftKey?32:12;let next=value;if(event.key==='Home')next=min;else if(event.key==='End')next=max;else if(event.key==='ArrowUp')next-=step;else if(event.key==='ArrowDown')next+=step;else return;event.preventDefault();onresize(clamp(next)); }
  onDestroy(()=>{window.removeEventListener('pointermove',drag);window.removeEventListener('pointerup',endDrag);});
</script>
<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
<!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
<div class="row-resize-handle" class:dragging role="separator" aria-label={`Resize ${label}`} aria-orientation="horizontal" aria-valuemin={min} aria-valuemax={max} aria-valuenow={Math.round(value)} aria-valuetext={`${Math.round(value)} pixels high`} title={`Drag to resize ${label}; double-click to reset`} tabindex="0" onpointerdown={beginDrag} onkeydown={handleKeydown} ondblclick={()=>onresize(defaultValue)}><span aria-hidden="true"></span></div>
<style>
  .row-resize-handle{position:absolute;z-index:8;right:0;bottom:0;left:0;height:10px;cursor:row-resize;touch-action:none;outline-offset:-2px}.row-resize-handle::before{position:absolute;right:0;bottom:0;left:0;height:1px;background:rgba(255,255,255,.1);content:''}.row-resize-handle span{position:absolute;bottom:2px;left:50%;width:38px;height:4px;transform:translateX(-50%);border:1px solid rgba(126,163,255,.4);border-radius:999px;background:#1a2946;box-shadow:0 2px 8px rgba(0,0,0,.48);transition:width .12s ease,border-color .12s ease,background .12s ease}.row-resize-handle:hover span,.row-resize-handle:focus-visible span,.row-resize-handle.dragging span{width:54px;border-color:#91adff;background:#3152a0}
</style>
