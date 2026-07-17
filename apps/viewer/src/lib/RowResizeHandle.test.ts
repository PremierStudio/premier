import { fireEvent, render, screen } from '@testing-library/svelte';
import { expect, it, vi } from 'vitest';
import RowResizeHandle from './RowResizeHandle.svelte';

it('exposes a horizontal separator and supports keyboard resizing', async () => {
  const onresize = vi.fn();
  render(RowResizeHandle, { label: 'run activity', value: 184, min: 148, max: 420, defaultValue: 184, onresize });
  const separator = screen.getByRole('separator', { name: 'Resize run activity' });
  expect(separator).toHaveAttribute('aria-orientation', 'horizontal');
  expect(separator).toHaveAttribute('aria-valuenow', '184');
  await fireEvent.keyDown(separator, { key: 'ArrowDown' });
  expect(onresize).toHaveBeenLastCalledWith(196);
  await fireEvent.keyDown(separator, { key: 'Home' });
  expect(onresize).toHaveBeenLastCalledWith(148);
  await fireEvent.keyDown(separator, { key: 'End' });
  expect(onresize).toHaveBeenLastCalledWith(420);
});

it('resizes with vertical pointer movement and resets on double click', async () => {
  const onresize = vi.fn();
  render(RowResizeHandle, { label: 'run activity', value: 184, min: 148, max: 420, defaultValue: 184, onresize });
  const separator = screen.getByRole('separator', { name: 'Resize run activity' });
  await fireEvent.pointerDown(separator, { button: 0, clientY: 200 });
  await fireEvent.pointerMove(window, { clientY: 248 });
  await fireEvent.pointerUp(window);
  expect(onresize).toHaveBeenLastCalledWith(232);
  await fireEvent.doubleClick(separator);
  expect(onresize).toHaveBeenLastCalledWith(184);
});
