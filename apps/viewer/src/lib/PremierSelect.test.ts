import { fireEvent, render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import PremierSelect from './PremierSelect.svelte';

const options = [
  { value: 'claude', label: 'Claude', description: 'Verified local CLI' },
  { value: 'codex', label: 'Codex', description: 'Verified local CLI' },
  { value: 'unsafe', label: 'Unsafe provider', disabled: true }
];

it('renders a custom listbox and selects an option', async () => {
  const onchange = vi.fn();
  const user = userEvent.setup();
  render(PremierSelect, { props: { value: 'claude', options, label: 'Local provider', onchange } });
  await user.click(screen.getByRole('button', { name: 'Local provider' }));
  expect(screen.getByRole('listbox', { name: 'Local provider options' })).toBeInTheDocument();
  await user.click(screen.getByRole('option', { name: /Codex/ }));
  expect(onchange).toHaveBeenCalledWith('codex');
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
});

it('supports keyboard navigation and escape close', async () => {
  const onchange = vi.fn();
  render(PremierSelect, { props: { value: 'claude', options, label: 'Local provider', onchange } });
  const trigger = screen.getByRole('button', { name: 'Local provider' });
  await fireEvent.keyDown(trigger, { key: 'ArrowDown' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Claude/ }), { key: 'ArrowDown' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Codex/ }), { key: 'Enter' });
  expect(onchange).toHaveBeenCalledWith('codex');
  await fireEvent.keyDown(trigger, { key: 'Enter' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Claude/ }), { key: 'Escape' });
  expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
});

it('supports label typeahead while skipping disabled options', async () => {
  const onchange = vi.fn();
  render(PremierSelect, { props: { value: 'claude', options, label: 'Local provider', onchange } });
  const trigger = screen.getByRole('button', { name: 'Local provider' });
  await fireEvent.keyDown(trigger, { key: 'Enter' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Claude/ }), { key: 'c' });
  await fireEvent.keyDown(screen.getByRole('option', { name: /Claude/ }), { key: 'o' });
  expect(screen.getByRole('option', { name: /Codex/ })).toHaveFocus();
  await fireEvent.keyDown(screen.getByRole('option', { name: /Codex/ }), { key: 'Enter' });
  expect(onchange).toHaveBeenCalledWith('codex');
});
