import { fireEvent, render, screen } from '@testing-library/svelte';
import { expect, it, vi } from 'vitest';
import SplitHandle from './SplitHandle.svelte';

it('exposes separator values and supports keyboard resizing', async () => {
  const onresize = vi.fn();
  render(SplitHandle, { side: 'left', label: 'trace list', value: 260, min: 180, max: 420, onresize, oncollapse: vi.fn() });
  const separator = screen.getByRole('separator', { name: 'Resize trace list' });
  expect(separator).toHaveAttribute('aria-valuenow', '260');
  await fireEvent.keyDown(separator, { key: 'ArrowRight' });
  expect(onresize).toHaveBeenLastCalledWith(272);
  await fireEvent.keyDown(separator, { key: 'Home' });
  expect(onresize).toHaveBeenLastCalledWith(180);
  await fireEvent.keyDown(separator, { key: 'End' });
  expect(onresize).toHaveBeenLastCalledWith(420);
});

it('inverts keyboard direction for the right pane and resets on double click', async () => {
  const onresize = vi.fn();
  render(SplitHandle, { side: 'right', label: 'event inspector', value: 420, min: 360, max: 640, onresize, oncollapse: vi.fn() });
  const separator = screen.getByRole('separator', { name: 'Resize event inspector' });
  await fireEvent.keyDown(separator, { key: 'ArrowLeft', shiftKey: true });
  expect(onresize).toHaveBeenLastCalledWith(452);
  await fireEvent.doubleClick(separator);
  expect(onresize).toHaveBeenLastCalledWith(420);
});

it('offers an accessible collapse and restore control', async () => {
  const oncollapse = vi.fn();
  const { rerender } = render(SplitHandle, { side: 'left', label: 'trace list', value: 260, min: 180, max: 420, onresize: vi.fn(), oncollapse });
  await fireEvent.click(screen.getByRole('button', { name: 'Collapse trace list' }));
  expect(oncollapse).toHaveBeenCalledOnce();
  await rerender({ side: 'left', label: 'trace list', value: 260, min: 180, max: 420, collapsed: true, onresize: vi.fn(), oncollapse });
  expect(screen.getByRole('button', { name: 'Restore trace list' })).toBeInTheDocument();
});

it('resizes continuously during pointer dragging', async () => {
  const onresize = vi.fn();
  render(SplitHandle, { side: 'left', label: 'trace list', value: 260, min: 180, max: 420, onresize, oncollapse: vi.fn() });
  const separator = screen.getByRole('separator', { name: 'Resize trace list' });
  await fireEvent.pointerDown(separator, { button: 0, clientX: 100 });
  await fireEvent.pointerMove(window, { clientX: 140 });
  await fireEvent.pointerUp(window);
  expect(onresize).toHaveBeenLastCalledWith(300);
});
