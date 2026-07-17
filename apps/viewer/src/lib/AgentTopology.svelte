<script lang="ts">
  import { onMount } from 'svelte';
  import type { TraceEvent } from './types';
  import { actorId, categoryOf, type ActorRole } from './analysis';
  import { inferArchitecture } from './architectureInference';
  import { fitTopology } from './topologyViewport';

  type Point = { x: number; y: number };
  type TopologyActor = {
    id: string;
    type: ActorRole;
    events: number;
    errors: number;
    firstSequence: number;
    status: string;
  } & Point;
  type TopologyEdge = {
    id: string;
    source: string;
    target: string;
    count: number;
    issues: number;
    event: TraceEvent;
    events: TraceEvent[];
  };

  let {
    events,
    focusEvents = null,
    selectedActor = null,
    onactor,
    onselect = () => undefined
  }: {
    events: TraceEvent[];
    focusEvents?: TraceEvent[] | null;
    selectedActor?: string | null;
    onactor: (actorId: string | null) => void;
    onselect?: (event: TraceEvent) => void;
  } = $props();

  const roleOrder: ActorRole[] = ['process', 'system', 'agent', 'subagent', 'human'];
  const roleX: Record<ActorRole, number> = { process: 105, system: 285, agent: 500, subagent: 720, human: 915 };
  let stageElement = $state<HTMLDivElement>();
  let zoom = $state(1);
  let panX = $state(0);
  let panY = $state(0);
  let panPointer = $state<number | null>(null);
  let panOrigin = { x: 0, y: 0, panX: 0, panY: 0 };

  function fitView() {
    const width = stageElement?.clientWidth ?? 0;
    const height = stageElement?.clientHeight ?? 0;
    const fit = fitTopology({ width, height }, topology.actors);
    zoom = fit.zoom;
    panX = fit.panX;
    panY = fit.panY;
  }

  function changeZoom(next: number) {
    const clamped = Math.max(.35, Math.min(2, next));
    if (!stageElement || zoom === clamped) {
      zoom = clamped;
      return;
    }
    const centerX = stageElement.clientWidth / 2;
    const centerY = stageElement.clientHeight / 2;
    const ratio = clamped / zoom;
    panX = centerX - (centerX - panX) * ratio;
    panY = centerY - (centerY - panY) * ratio;
    zoom = clamped;
  }

  function pan(direction: 'left' | 'right' | 'up' | 'down') {
    if (direction === 'left') panX += 80;
    if (direction === 'right') panX -= 80;
    if (direction === 'up') panY += 60;
    if (direction === 'down') panY -= 60;
  }

  function startPan(event: PointerEvent) {
    if ((event.target as HTMLElement).closest('button, [role="button"]')) return;
    panPointer = event.pointerId;
    panOrigin = { x: event.clientX, y: event.clientY, panX, panY };
    (event.currentTarget as HTMLElement).setPointerCapture?.(event.pointerId);
  }

  function movePan(event: PointerEvent) {
    if (panPointer !== event.pointerId) return;
    panX = panOrigin.panX + event.clientX - panOrigin.x;
    panY = panOrigin.panY + event.clientY - panOrigin.y;
  }

  function stopPan(event: PointerEvent) {
    if (panPointer !== event.pointerId) return;
    panPointer = null;
    (event.currentTarget as HTMLElement).releasePointerCapture?.(event.pointerId);
  }

  function roleLabel(role: ActorRole): string {
    if (role === 'agent') return 'Coordinator';
    if (role === 'subagent') return 'Delegated agent';
    if (role === 'process') return 'Runtime process';
    if (role === 'human') return 'Human reviewer';
    return 'System service';
  }

  function actorLabel(actor: TopologyActor): string {
    const issueText = actor.errors ? `${actor.errors} issue${actor.errors === 1 ? '' : 's'}` : 'no issues';
    return `${actor.id}, ${roleLabel(actor.type)}, ${actor.events} event${actor.events === 1 ? '' : 's'}, ${issueText}`;
  }

  function layoutActors(input: TraceEvent[]): { actors: TopologyActor[]; height: number } {
    const summaries = inferArchitecture(input).actors.map((actor) => ({
      id: actor.id,
      type: actor.role,
      events: actor.eventCount,
      errors: actor.issueCount,
      firstSequence: actor.firstSequence,
      status: actor.issueCount ? 'error' : 'ok'
    }));
    const maxInColumn = Math.max(1, ...roleOrder.map((role) => summaries.filter((actor) => actor.type === role).length));
    const height = Math.max(330, maxInColumn * 138 + 72);
    const actors = summaries.map((actor) => {
      const peers = summaries.filter((candidate) => candidate.type === actor.type);
      const index = peers.findIndex((candidate) => candidate.id === actor.id);
      return { ...actor, x: roleX[actor.type], y: ((index + 1) * height) / (peers.length + 1) };
    });
    return { actors, height };
  }

  function causalEdges(input: TraceEvent[]): TopologyEdge[] {
    const byEvent = new Map(input.map((event) => [event.event_id, event]));
    return inferArchitecture(input).connections.flatMap((connection) => {
      const linked = connection.eventIds.map((id) => byEvent.get(id)).filter((event): event is TraceEvent => Boolean(event));
      const representative = linked.find((event) => categoryOf(event) === 'error') ?? linked[0];
      if (!representative) return [];
      return [{
        id: connection.id,
        source: connection.sourceActorId,
        target: connection.targetActorId,
        count: connection.eventCount,
        issues: connection.issueCount,
        event: representative,
        events: linked
      }];
    });
  }

  function edgeKinds(edge: TopologyEdge): string {
    const kinds = [...new Set(edge.events.map((event) => event.kind))];
    if (kinds.length <= 2) return kinds.join(' · ');
    return `${kinds.slice(0, 2).join(' · ')} +${kinds.length - 2} more`;
  }

  function eventStatus(event: TraceEvent): string {
    return event.status && event.status !== 'ok' ? event.status : 'recorded';
  }

  function curve(source: Point, target: Point): string {
    const nodeHalfWidth = 98;
    const startX = source.x + (target.x >= source.x ? nodeHalfWidth : -nodeHalfWidth);
    const endX = target.x + (target.x >= source.x ? -nodeHalfWidth : nodeHalfWidth);
    const control = (startX + endX) / 2;
    return `M ${startX} ${source.y} C ${control} ${source.y}, ${control} ${target.y}, ${endX} ${target.y}`;
  }

  function activateEdge(keyEvent: KeyboardEvent, edge: TopologyEdge) {
    if (keyEvent.key !== 'Enter' && keyEvent.key !== ' ') return;
    keyEvent.preventDefault();
    onselect(edge.event);
  }

  let topology = $derived(layoutActors(events));
  let edges = $derived(causalEdges(events));
  let byActor = $derived(new Map(topology.actors.map((actor) => [actor.id, actor])));
  let focusActive = $derived(focusEvents !== null && focusEvents.length !== events.length);
  let focusedEventIds = $derived(new Set((focusEvents ?? events).map((event) => event.event_id)));
  let focusedActorIds = $derived(new Set((focusEvents ?? events).map(actorId)));
  let fittedTopologyKey = '';

  $effect(() => {
    const key = topology.actors.map((actor) => `${actor.id}:${actor.x}:${actor.y}`).join('|');
    if (key === fittedTopologyKey) return;
    fittedTopologyKey = key;
    if (stageElement && stageElement.clientWidth > 0 && stageElement.clientHeight > 0) fitView();
  });

  onMount(() => {
    if (!stageElement || typeof ResizeObserver === 'undefined') {
      fitView();
      return;
    }
    const observer = new ResizeObserver(() => fitView());
    observer.observe(stageElement);
    fitView();
    return () => observer.disconnect();
  });
</script>

<section class="topology" aria-labelledby="agent-topology-title">
  <header>
    <div>
      <p>Execution map</p>
      <h2 id="agent-topology-title">Agent topology</h2>
    </div>
    <div class="topology-actions"><span class="summary">{topology.actors.length} actor{topology.actors.length === 1 ? '' : 's'} · {edges.length} causal connection{edges.length === 1 ? '' : 's'}</span><div class="canvas-controls" aria-label="Map controls"><div class="pan-controls"><button onclick={() => pan('left')} aria-label="Pan left">←</button><button onclick={() => pan('up')} aria-label="Pan up">↑</button><button onclick={() => pan('down')} aria-label="Pan down">↓</button><button onclick={() => pan('right')} aria-label="Pan right">→</button></div><div class="zoom-controls" aria-label="Map zoom"><button onclick={() => changeZoom(zoom - .25)} disabled={zoom <= .35} aria-label="Zoom out">−</button><button onclick={fitView} aria-label="Reset map view">Fit</button><button onclick={() => changeZoom(zoom + .25)} disabled={zoom >= 2} aria-label="Zoom in">+</button></div></div></div>
  </header>

  <div class="map-scope" aria-label="Map scope">
    <strong>Scope</strong>
    <span>{events.length} supplied event{events.length === 1 ? '' : 's'}</span>
    <p>This map reflects the evidence currently supplied by the viewer. Connections require a recorded parent event or parent span.</p>
  </div>

  {#if topology.actors.length === 0}
    <div class="empty" role="status">
      <strong>No actors recorded</strong>
      <span>Agent relationships appear when this trace captures actor events and their parent links.</span>
    </div>
  {:else}
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <div
      class="stage"
      bind:this={stageElement}
      class:panning={panPointer !== null}
      aria-label="Architecture canvas"
      role="group"
      data-zoom={zoom}
      data-pan-x={panX}
      data-pan-y={panY}
      onpointerdown={startPan}
      onpointermove={movePan}
      onpointerup={stopPan}
      onpointercancel={stopPan}
    >
      <div class="graph" style={`--graph-height:${topology.height}px;transform:translate(${panX}px, ${panY}px) scale(${zoom})`}>
        <svg viewBox={`0 0 1020 ${topology.height}`} preserveAspectRatio="none" aria-label="Causal connections between actors">
          <defs>
            <marker id="topology-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto" markerUnits="strokeWidth">
              <path d="M0,0 L7,3.5 L0,7 Z" class="arrow-head" />
            </marker>
          </defs>
          {#each edges as edge (edge.id)}
            {@const source = byActor.get(edge.source)}
            {@const target = byActor.get(edge.target)}
            {#if source && target}
              {@const path = curve({ x: source.x, y: source.y }, { x: target.x, y: target.y })}
              <path d={path} class:error={edge.issues > 0} class:muted={focusActive && !edge.events.some((event) => focusedEventIds.has(event.event_id))} class="edge-line" marker-end="url(#topology-arrow)" />
              <path
                d={path}
                class="edge-hit"
                class:muted={focusActive && !edge.events.some((event) => focusedEventIds.has(event.event_id))}
                role="button"
                tabindex="0"
                aria-label={`${edge.source} to ${edge.target}: ${edge.count} linked event${edge.count === 1 ? '' : 's'}, ${edgeKinds(edge)}${edge.issues ? `, ${edge.issues} issue${edge.issues === 1 ? '' : 's'}` : ''}. Select representative event ${edge.event.kind}, sequence ${edge.event.sequence}`}
                onclick={() => onselect(edge.event)}
                onkeydown={(event) => activateEdge(event, edge)}
              ><title>{edge.source} → {edge.target} · {edgeKinds(edge)} · select {edge.event.kind} #{edge.event.sequence}</title></path>
            {/if}
          {/each}
        </svg>

        {#each topology.actors as actor (actor.id)}
          <button
            type="button"
            class="actor"
            class:selected={selectedActor === actor.id}
            class:muted={focusActive && !focusedActorIds.has(actor.id)}
            class:has-issues={actor.errors > 0}
            data-role={actor.type}
            style={`--actor-x:${actor.x}px;--actor-y:${actor.y}px`}
            aria-label={actorLabel(actor)}
            aria-pressed={selectedActor === actor.id}
            onclick={() => onactor(selectedActor === actor.id ? null : actor.id)}
          >
            <span class="identity">
              <span class="monogram" aria-hidden="true">{actor.id.slice(0, 1).toUpperCase()}</span>
              <span class="name"><strong>{actor.id}</strong><small>{roleLabel(actor.type)}</small></span>
              <span class="health" data-tone={actor.errors ? 'issue' : 'healthy'}>{actor.errors ? 'Needs review' : 'Healthy'}</span>
            </span>
            <span class="metrics">
              <span><strong>{actor.events}</strong> event{actor.events === 1 ? '' : 's'}</span>
              <span class:error={actor.errors > 0}><strong>{actor.errors}</strong> issue{actor.errors === 1 ? '' : 's'}</span>
            </span>
          </button>
        {/each}
      </div>

      <div class="minimap" aria-label="Architecture minimap" role="img">
        {#each topology.actors as actor (actor.id)}
          <i class:issue={actor.errors > 0} style={`left:${actor.x / 10.2}%;top:${actor.y / topology.height * 100}%`} title={actor.id}></i>
        {/each}
        <span style={`transform:translate(${-panX / Math.max(1, zoom) / 12}px, ${-panY / Math.max(1, zoom) / 12}px) scale(${1 / zoom})`}></span>
      </div>

    </div>

      {#if edges.length}
        <div class="handoff-evidence" aria-label="Exact handoff evidence">
          <div class="handoff-heading">
            <div><span>Connection ledger</span><strong>Exact handoff evidence</strong></div>
            <p>Expand a route to inspect every recorded cross-actor event behind its line.</p>
          </div>
          {#each edges as edge (edge.id)}
            <details class:has-issues={edge.issues > 0}>
              <summary>
                <span class="route"><strong>{edge.source}</strong><i aria-hidden="true">→</i><strong>{edge.target}</strong></span>
                <span class="route-kinds">{edgeKinds(edge)}</span>
                <small>{edge.count} event{edge.count === 1 ? '' : 's'}{edge.issues ? ` · ${edge.issues} issue${edge.issues === 1 ? '' : 's'}` : ''}</small>
              </summary>
              <div class="handoff-events">
                {#each edge.events as linkedEvent (linkedEvent.event_id)}
                  <button type="button" onclick={() => onselect(linkedEvent)} aria-label={`Inspect handoff event ${linkedEvent.kind}, sequence ${linkedEvent.sequence}, ${edge.source} to ${edge.target}`}>
                    <span class="event-sequence">#{linkedEvent.sequence}</span>
                    <strong>{linkedEvent.kind}</strong>
                    <span class="event-status" class:issue={categoryOf(linkedEvent) === 'error'}>{eventStatus(linkedEvent)}</span>
                  </button>
                {/each}
              </div>
            </details>
          {/each}
        </div>
      {:else if topology.actors.length === 1}
        <p class="single-note">This run has one actor, so there are no cross-actor causal links.</p>
      {/if}
  {/if}

  <div class="legend" aria-label="Topology legend">
    <strong>How to read this map</strong>
    <span><i class="sample solid" aria-hidden="true"></i>Solid node: coordinator, runtime, system, or human</span>
    <span><i class="sample dashed" aria-hidden="true"></i>Dashed node: delegated agent</span>
    <span><i class="sample flow" aria-hidden="true"></i>Blue arrow: parent-to-child event flow</span>
    <span><i class="sample issue" aria-hidden="true"></i>Red status: actor or link has recorded issues</span>
    <span class="hint">Select a node to filter by actor. Select a line for its representative event, or expand Exact handoff evidence for every event behind the connection.</span>
  </div>
</section>

<style>
  .topology { min-width: 0; overflow: hidden; container-type: inline-size; border: 1px solid rgba(255,255,255,.075); border-radius: 14px; background: linear-gradient(145deg, rgba(17,21,28,.94), rgba(5,7,10,.97)); box-shadow: 0 20px 55px rgba(0,0,0,.28), inset 0 1px rgba(255,255,255,.035); color: var(--text, #e8edf5); }
  header { display: flex; min-width: 0; align-items: end; justify-content: space-between; gap: 18px; padding: 17px 20px 15px; border-bottom: 1px solid rgba(255,255,255,.065); background: rgba(255,255,255,.018); }
  header div { min-width: 0; }
  p, h2 { margin: 0; }
  header p { margin-bottom: 3px; color: var(--blue-strong, #8da9ff); font: 700 10px 'IBM Plex Mono', monospace; letter-spacing: .12em; text-transform: uppercase; }
  h2 { font: 650 17px/1.2 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; letter-spacing: -.01em; }
  .topology-actions { display: flex; min-width: 0; align-items: center; gap: 12px; }
  .canvas-controls { display: flex; align-items: center; gap: 6px; }
  .pan-controls { display: inline-flex; overflow: hidden; border: 1px solid rgba(255,255,255,.12); border-radius: 6px; }
  .pan-controls button { min-width: 28px; min-height: 30px; padding: 0; border: 0; border-right: 1px solid rgba(255,255,255,.1); color: #9eacc1; background: #0d131c; cursor: pointer; }
  .pan-controls button:last-child { border-right: 0; }
  .pan-controls button:hover { color: white; background: rgba(111,123,247,.18); }
  .summary { min-width: 0; color: var(--muted, #8a9ab0); font-size: 11px; text-align: right; overflow-wrap: anywhere; }
  .zoom-controls { flex: 0 0 auto; display: inline-flex; overflow: hidden; border: 1px solid rgba(255,255,255,.12); border-radius: 6px; }
  .zoom-controls button { min-width: 32px; min-height: 30px; padding: 0 8px; border: 0; border-right: 1px solid rgba(255,255,255,.1); color: #b9c6d8; background: #111722; font-size: 10px; cursor: pointer; }
  .zoom-controls button:last-child { border-right: 0; }
  .zoom-controls button:hover:not(:disabled) { color: white; background: rgba(111,123,247,.18); }
  .zoom-controls button:disabled { opacity: .35; cursor: not-allowed; }
  .map-scope { min-width: 0; display: flex; align-items: center; gap: 8px; padding: 8px 20px; border-bottom: 1px solid rgba(255,255,255,.055); color: #7f8da1; background: rgba(3,5,8,.34); font-size: 10px; }
  .map-scope strong { color: #aebbd0; font-size: 9px; letter-spacing: .1em; text-transform: uppercase; }
  .map-scope span { flex: 0 0 auto; padding: 2px 6px; border: 1px solid rgba(158,170,255,.24); border-radius: 999px; color: #aebfff; background: rgba(111,123,247,.08); font: 9px 'IBM Plex Mono', monospace; }
  .map-scope p { min-width: 0; overflow: hidden; color: #718096; font-size: 10px; white-space: nowrap; text-overflow: ellipsis; }
  .stage { position: relative; min-width: 0; height: clamp(240px, calc(100dvh - 520px), 560px); overflow: hidden; overscroll-behavior: contain; cursor: grab; touch-action: none; background-color: #070a0f; background-image: linear-gradient(rgba(122,145,184,.075) 1px, transparent 1px), linear-gradient(90deg, rgba(122,145,184,.075) 1px, transparent 1px), linear-gradient(rgba(122,145,184,.025) 1px, transparent 1px), linear-gradient(90deg, rgba(122,145,184,.025) 1px, transparent 1px); background-position: center; background-size: 112px 112px, 112px 112px, 28px 28px, 28px 28px; box-shadow: inset 0 0 60px rgba(0,0,0,.3); }
  .stage.panning { cursor: grabbing; }
  .graph { position: relative; width: 1020px; min-width: 0; height: var(--graph-height); transform-origin: top left; }
  .stage.panning .graph { transition: none; }
  .minimap { position: sticky; z-index: 4; display: block; width: 118px; height: 72px; right: 10px; bottom: 10px; margin: -82px 10px 10px auto; overflow: hidden; pointer-events: none; border: 1px solid rgba(141,169,255,.28); border-radius: 7px; background: rgba(5,8,13,.88); box-shadow: 0 8px 22px rgba(0,0,0,.32); }
  .minimap i { position: absolute; width: 5px; height: 5px; transform: translate(-50%,-50%); border-radius: 50%; background: #7f9fff; }
  .minimap i.issue { background: #ff716d; }
  .minimap span { position: absolute; inset: 5px; transform-origin: center; border: 1px solid rgba(255,255,255,.36); border-radius: 3px; }
  svg { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; }
  .edge-line { fill: none; stroke: #9eaaff; stroke-width: 1.7; vector-effect: non-scaling-stroke; opacity: .8; }
  .edge-line.muted { opacity: .14; }
  .edge-line.error { stroke: #ff716d; }
  .arrow-head { fill: #9eaaff; }
  .edge-hit { fill: none; stroke: transparent; stroke-width: 14; vector-effect: non-scaling-stroke; cursor: pointer; pointer-events: stroke; }
  .edge-hit.muted { pointer-events: none; }
  .edge-hit:focus { outline: none; stroke: rgba(141,169,255,.28); }
  .actor { position: absolute; left: var(--actor-x); top: var(--actor-y); z-index: 1; width: 196px; min-width: 0; padding: 12px; transform: translate(-50%, -50%); border: 1px solid rgba(255,255,255,.13); border-radius: 10px; color: inherit; background: linear-gradient(145deg, rgba(23,29,39,.97), rgba(12,15,21,.98)); box-shadow: 0 12px 28px rgba(0,0,0,.3), inset 0 1px rgba(255,255,255,.045); text-align: left; cursor: pointer; }
  .actor.muted { opacity: .34; filter: saturate(.45); }
  .actor[data-role='subagent'] { border-style: dashed; }
  .actor:hover { border-color: rgba(141,169,255,.58); transform: translate(-50%, -50%) translateY(-2px); }
  .actor:focus-visible { outline: 2px solid var(--focus, #8da9ff); outline-offset: 3px; }
  .actor.selected { border-color: var(--blue, #9eaaff); box-shadow: 0 0 0 1px rgba(96,135,255,.25), 0 16px 35px rgba(0,0,0,.38), inset 0 1px rgba(255,255,255,.06); }
  .actor.has-issues { border-color: rgba(255,113,109,.45); }
  .identity { display: grid; grid-template-columns: 30px minmax(0,1fr); gap: 3px 9px; align-items: center; }
  .monogram { grid-row: 1 / 3; display: grid; width: 30px; height: 30px; place-items: center; border: 1px solid rgba(141,169,255,.38); border-radius: 7px; color: #b8c8ff; background: rgba(96,135,255,.11); font: 700 13px 'IBM Plex Sans Variable', sans-serif; }
  .actor[data-role='human'] .monogram { border-radius: 50%; border-color: rgba(99,215,210,.5); color: #8de4df; background: rgba(99,215,210,.09); }
  .actor[data-role='process'] .monogram { border-color: rgba(95,214,160,.45); color: #8de3bc; background: rgba(95,214,160,.08); }
  .name { display: block; min-width: 0; }
  .name strong, .name small { display: block; min-width: 0; overflow-wrap: anywhere; }
  .name strong { color: #f2f5fa; font: 650 12px/1.2 'IBM Plex Sans Variable', 'IBM Plex Sans', sans-serif; }
  .name small { margin-top: 2px; color: #8d9bad; font-size: 10px; }
  .health { grid-column: 2; width: max-content; max-width: 100%; margin-top: 4px; padding: 2px 6px; border-radius: 999px; color: #8de3bc; background: rgba(95,214,160,.09); font: 700 9px/1.3 'IBM Plex Sans Variable', sans-serif; letter-spacing: .03em; }
  .health[data-tone='issue'] { color: #ff9b97; background: rgba(255,113,109,.1); }
  .metrics { display: flex; justify-content: space-between; gap: 8px; margin-top: 11px; padding-top: 9px; border-top: 1px solid rgba(255,255,255,.065); color: #8795a8; font-size: 10px; }
  .metrics strong { color: #dfe6f2; }
  .metrics .error, .metrics .error strong { color: #ff918d; }
  .empty { display: grid; min-height: 210px; place-content: center; gap: 7px; padding: 24px; text-align: center; }
  .empty strong { font-size: 14px; }
  .empty span, .single-note { max-width: 480px; color: var(--muted, #8a9ab0); font-size: 11px; line-height: 1.5; }
  .single-note { max-width: none; padding: 0 20px 17px; text-align: center; }
  .handoff-evidence { display: grid; gap: 7px; padding: 13px 14px 15px; border-top: 1px solid rgba(255,255,255,.065); background: rgba(4,6,9,.68); }
  .handoff-heading { min-width: 0; display: flex; align-items: end; justify-content: space-between; gap: 16px; padding: 1px 2px 4px; }
  .handoff-heading div { display: grid; gap: 2px; }
  .handoff-heading span { color: #718096; font: 700 9px 'IBM Plex Mono', monospace; letter-spacing: .1em; text-transform: uppercase; }
  .handoff-heading strong { color: #d5deea; font-size: 12px; }
  .handoff-heading p { color: #718096; font-size: 10px; text-align: right; }
  .handoff-evidence details { min-width: 0; overflow: hidden; border: 1px solid rgba(255,255,255,.075); border-radius: 7px; background: rgba(255,255,255,.02); }
  .handoff-evidence details.has-issues { border-color: rgba(255,113,109,.22); }
  .handoff-evidence summary { min-width: 0; display: grid; grid-template-columns: minmax(150px,.75fr) minmax(150px,1fr) auto; gap: 12px; align-items: center; padding: 9px 11px; color: #cfd8e5; cursor: pointer; list-style-position: inside; }
  .handoff-evidence summary:hover { background: rgba(111,123,247,.06); }
  .route { display: inline-flex; min-width: 0; align-items: center; gap: 6px; overflow-wrap: anywhere; }
  .route i { color: #7e9eff; font-style: normal; }
  .route-kinds { min-width: 0; overflow: hidden; color: #9cabc0; font: 10px 'IBM Plex Mono', monospace; white-space: nowrap; text-overflow: ellipsis; }
  .handoff-evidence summary small { color: #8290a4; font-size: 9px; text-align: right; }
  .handoff-events { display: grid; padding: 0 7px 7px 27px; }
  .handoff-events button { min-width: 0; display: grid; grid-template-columns: 38px minmax(0,1fr) auto; gap: 9px; align-items: center; padding: 8px 9px; border: 0; border-top: 1px solid rgba(255,255,255,.055); color: #cfd8e5; background: transparent; text-align: left; cursor: pointer; }
  .handoff-events button:hover { color: white; background: rgba(111,123,247,.08); }
  .event-sequence { color: #718096; font: 9px 'IBM Plex Mono', monospace; }
  .handoff-events strong { min-width: 0; overflow-wrap: anywhere; font: 600 11px 'IBM Plex Sans Variable', sans-serif; }
  .event-status { color: #7fcbab; font-size: 9px; text-transform: uppercase; }
  .event-status.issue { color: #ff918d; }
  .legend { display: flex; min-width: 0; flex-wrap: wrap; align-items: center; gap: 9px 16px; padding: 12px 20px; border-top: 1px solid rgba(255,255,255,.065); color: #8d9bad; background: rgba(2,3,5,.46); font-size: 10px; line-height: 1.4; }
  .legend > strong { color: #cdd6e3; font-size: 10px; }
  .legend span { display: inline-flex; min-width: 0; align-items: center; gap: 7px; }
  .legend .hint { flex: 1 1 100%; color: #748297; }
  .sample { display: inline-block; flex: 0 0 auto; width: 17px; height: 10px; border: 1px solid #7d8ba0; border-radius: 3px; }
  .sample.dashed { border-style: dashed; }
  .sample.flow { position: relative; width: 20px; height: 0; border: 0; border-top: 2px solid #9eaaff; border-radius: 0; }
  .sample.flow::after { position: absolute; top: -4px; right: -1px; width: 5px; height: 5px; border-top: 2px solid #9eaaff; border-right: 2px solid #9eaaff; content: ''; transform: rotate(45deg); }
  .sample.issue { width: 8px; height: 8px; border: 0; border-radius: 50%; background: #ff716d; box-shadow: 0 0 0 3px rgba(255,113,109,.12); }

  @container (max-width: 820px) {
    .actor { padding: 10px; }
    .identity { grid-template-columns: 27px minmax(0,1fr); column-gap: 7px; }
    .monogram { width: 27px; height: 27px; }
    .metrics { gap: 5px; font-size: 9px; }
  }

  @container (max-width: 540px) {
    header { align-items: start; padding-inline: 15px; }
    .topology-actions { align-items: flex-end; flex-direction: column; gap: 6px; }
    .zoom-controls { display: none; }
    .summary { max-width: 45%; }
    .stage { height: auto; min-height: 0; overflow: visible; background-size: 96px 96px, 96px 96px, 24px 24px, 24px 24px; }
    .graph { display: grid; width: 100%; min-width: 0; height: auto; padding: 14px 14px 8px; gap: 9px; transform: none !important; }
    .graph svg { display: none; }
    .actor { position: static; width: 100%; transform: none; }
    .actor:hover { transform: translateY(-1px); }
    .map-scope { align-items: start; flex-wrap: wrap; padding-inline: 15px; }
    .map-scope p { flex: 1 1 100%; white-space: normal; }
    .handoff-heading { align-items: start; flex-direction: column; gap: 4px; }
    .handoff-heading p { text-align: left; }
    .handoff-evidence summary { grid-template-columns: minmax(0,1fr) auto; gap: 5px 10px; }
    .route-kinds { grid-column: 1 / -1; grid-row: 2; padding-left: 18px; }
    .handoff-events { padding-left: 7px; }
    .legend { padding-inline: 15px; }
  }

  @media (prefers-reduced-motion: no-preference) {
    .actor { transition: border-color 140ms ease, box-shadow 140ms ease, transform 140ms ease; }
  }
</style>
