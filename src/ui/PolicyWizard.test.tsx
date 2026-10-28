import { fireEvent, render, screen } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { AUTH_STRENGTH } from '../catalog/authStrengths';
import { USER_ACTION } from '../catalog/apps';
import { blankPolicy } from '../model/newPolicy';
import { PolicyWizard } from './PolicyWizard';

test('saving phishing-resistant strength and security-info action', () => {
  const onSave = vi.fn();
  render(<PolicyWizard policy={blankPolicy()} onSave={onSave} onCancel={() => undefined} />);
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Admin phishing-resistant' } });
  fireEvent.click(screen.getByRole('button', { name: 'Grant' }));
  fireEvent.change(screen.getByLabelText('Authentication strength'), { target: { value: AUTH_STRENGTH.phishingResistant } });
  fireEvent.click(screen.getByRole('button', { name: 'Target resources' }));
  fireEvent.click(screen.getByLabelText('User actions'));
  fireEvent.click(screen.getByLabelText('User action: Register security information'));
  fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));
  const saved = onSave.mock.calls[0][0];
  expect(saved.displayName).toBe('Admin phishing-resistant');
  expect(saved.grantControls?.authenticationStrength?.id).toBe(AUTH_STRENGTH.phishingResistant);
  expect(saved.conditions.applications.includeUserActions).toContain(USER_ACTION.registerSecurityInfo);
});

test('can exclude a country from the network condition', () => {
  const onSave = vi.fn();
  render(<PolicyWizard policy={blankPolicy()} onSave={onSave} onCancel={() => undefined} />);
  fireEvent.click(screen.getByRole('button', { name: 'Network' }));
  fireEvent.click(screen.getByLabelText('Yes'));
  fireEvent.click(screen.getByLabelText('Exclude country: United States'));
  fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));
  const saved = onSave.mock.calls[0][0];
  expect(saved.conditions.locations?.includeLocations).toEqual(['All']);
  expect(saved.conditions.locations?.excludeLocations).toContain('US');
});

test('builder uses Entra assignment headings', () => {
  render(<PolicyWizard policy={blankPolicy()} onSave={() => undefined} onCancel={() => undefined} />);
  expect(screen.getByRole('heading', { name: /Conditional Access policy/ })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Users' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Target resources' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Network' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Conditions' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Grant' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Session' })).toBeTruthy();
});
