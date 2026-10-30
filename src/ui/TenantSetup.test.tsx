import { fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { expect, test } from 'vitest';
import { DEFAULT_TENANT, type TenantProfile } from '../model/types';
import { TenantSetup } from './TenantSetup';

function Harness() {
  const [tenant, setTenant] = useState<TenantProfile>(DEFAULT_TENANT);
  return <TenantSetup tenant={tenant} onChange={setTenant} />;
}

test('two new friendly-name rows can hold different ids', () => {
  render(<Harness />);
  fireEvent.click(screen.getByRole('button', { name: 'Add name' }));
  fireEvent.click(screen.getByRole('button', { name: 'Add name' }));
  const ids = screen.getAllByLabelText('Object ID');
  fireEvent.change(ids[0], { target: { value: 'aaa' } });
  fireEvent.change(ids[1], { target: { value: 'bbb' } });
  expect(screen.getAllByLabelText('Object ID')).toHaveLength(2);
  expect((screen.getAllByLabelText('Object ID')[0] as HTMLInputElement).value).toBe('aaa');
  expect((screen.getAllByLabelText('Object ID')[1] as HTMLInputElement).value).toBe('bbb');
});

test('a friendly-name row can be removed', () => {
  render(<Harness />);
  fireEvent.click(screen.getByRole('button', { name: 'Add name' }));
  fireEvent.click(screen.getByRole('button', { name: 'Remove name' }));
  expect(screen.queryByLabelText('Object ID')).toBeNull();
});

test('Entra ID P2 explains what it changes', () => {
  render(<Harness />);
  expect(screen.getByText('Sign-in risk and user risk. Insider risk also needs Purview.')).toBeTruthy();
});
