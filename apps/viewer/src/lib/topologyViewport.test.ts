import { describe, expect, it } from 'vitest';
import { fitTopology } from './topologyViewport';

describe('fitTopology', () => {
  it('centers the occupied actor bounds inside the available stage', () => {
    const fit = fitTopology(
      { width: 620, height: 260 },
      [{ x: 105, y: 165 }, { x: 500, y: 165 }, { x: 720, y: 165 }]
    );

    expect(fit.zoom).toBeCloseTo(0.68, 1);
    expect(105 * fit.zoom + fit.panX).toBeGreaterThanOrEqual(24);
    expect(720 * fit.zoom + fit.panX).toBeLessThanOrEqual(596);
    expect(165 * fit.zoom + fit.panY).toBeCloseTo(130, 0);
  });

  it('fits tall actor columns without allowing nodes outside the stage', () => {
    const fit = fitTopology(
      { width: 760, height: 300 },
      [{ x: 500, y: 82 }, { x: 500, y: 246 }, { x: 720, y: 164 }]
    );

    expect(fit.zoom).toBeLessThanOrEqual(1.25);
    expect(82 * fit.zoom + fit.panY).toBeGreaterThanOrEqual(24);
    expect(246 * fit.zoom + fit.panY).toBeLessThanOrEqual(276);
  });
});
