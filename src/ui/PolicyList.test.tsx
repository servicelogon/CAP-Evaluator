import { fireEvent, render, screen } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { goodTenant } from '../samples/goodTenant';
import { PolicyList } from './PolicyList';

test('import paste adds a policy card', () => {
  const onPolicies = vi.fn();
  render(
    <PolicyList
      policies={[]}
      onPolicies={onPolicies}
      onTenant={() => undefined}
      onEdit={() => undefined}
    />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Import a JSON file' }));
  fireEvent.click(screen.getByText('Or paste JSON'));
  fireEvent.change(screen.getByLabelText('Policy JSON'), {
    target: { value: JSON.stringify({ displayName: 'Block legacy', state: 'enabled', conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] } } }) },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Import pasted JSON' }));
  expect(onPolicies).toHaveBeenCalled();
  expect(onPolicies.mock.calls[0][0][0].displayName).toBe('Block legacy');
});

test('load known-good replaces the list', () => {
  const onPolicies = vi.fn();
  render(
    <PolicyList
      policies={[]}
      onPolicies={onPolicies}
      onTenant={() => undefined}
      onEdit={() => undefined}
    />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Load sample: known-good' }));
  expect(onPolicies.mock.calls[0][0]).toHaveLength(goodTenant.policies.length);
});
