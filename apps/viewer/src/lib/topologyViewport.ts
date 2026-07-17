export interface TopologyPoint { x: number; y: number }
export interface TopologyViewport { width: number; height: number }
export interface TopologyFit { zoom: number; panX: number; panY: number }

const padding = 24;
const nodeHalfWidth = 108;
const nodeHalfHeight = 62;

/** Fit the occupied node bounds—not the unused logical canvas—into the stage. */
export function fitTopology(viewport: TopologyViewport, actors: TopologyPoint[]): TopologyFit {
  if (!actors.length || viewport.width <= 0 || viewport.height <= 0) return { zoom: 1, panX: 0, panY: 0 };

  const minX = Math.min(...actors.map((actor) => actor.x)) - nodeHalfWidth;
  const maxX = Math.max(...actors.map((actor) => actor.x)) + nodeHalfWidth;
  const minY = Math.min(...actors.map((actor) => actor.y)) - nodeHalfHeight;
  const maxY = Math.max(...actors.map((actor) => actor.y)) + nodeHalfHeight;
  const contentWidth = Math.max(1, maxX - minX);
  const contentHeight = Math.max(1, maxY - minY);
  const availableWidth = Math.max(1, viewport.width - padding * 2);
  const availableHeight = Math.max(1, viewport.height - padding * 2);
  const zoom = Math.max(.35, Math.min(1.25, availableWidth / contentWidth, availableHeight / contentHeight));
  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;

  return {
    zoom: Math.round(zoom * 1000) / 1000,
    panX: Math.round((viewport.width / 2 - centerX * zoom) * 10) / 10,
    panY: Math.round((viewport.height / 2 - centerY * zoom) * 10) / 10
  };
}
