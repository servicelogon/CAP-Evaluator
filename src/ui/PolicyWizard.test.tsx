import { fireEvent, render, screen, within } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { AUTH_STRENGTH } from '../catalog/authStrengths';
import { APP, USER_ACTION } from '../catalog/apps';
import { blankPolicy } from '../model/newPolicy';
import { normalizePolicy } from '../model/normalize';
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

test('Azure CLI does not claim that only All resources covers Graph', () => {
  render(<PolicyWizard policy={blankPolicy()} onSave={() => undefined} onCancel={() => undefined} />);
  fireEvent.click(screen.getByRole('button', { name: 'Target resources' }));
  fireEvent.click(screen.getByLabelText('Select resources'));
  fireEvent.change(screen.getByLabelText('Search resources'), { target: { value: 'Azure CLI' } });
  const includePick = document.querySelectorAll('.app-pick')[0];
  expect(includePick).toBeTruthy();
  const scope = within(includePick as HTMLElement);
  expect(scope.getByText('This is a client app and cannot be targeted.')).toBeTruthy();
  expect(scope.queryByText('Microsoft Graph can only be covered via All resources.')).toBeNull();
});

test('excluding Office 365 writes the keyword', () => {
  const onSave = vi.fn();
  render(<PolicyWizard policy={blankPolicy()} onSave={onSave} onCancel={() => undefined} />);
  fireEvent.click(screen.getByRole('button', { name: 'Target resources' }));
  fireEvent.click(screen.getByLabelText('All resources'));
  fireEvent.click(screen.getByLabelText('Exclude Office 365'));
  fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));
  expect(onSave.mock.calls[0][0].conditions.applications.excludeApplications).toContain('Office365');
});

test('non-catalog excluded app id is listed and can be removed', () => {
  const customId = '11111111-1111-1111-1111-111111111111';
  const policy = blankPolicy();
  policy.conditions.applications.includeApplications = ['All'];
  policy.conditions.applications.excludeApplications = [customId];
  const onSave = vi.fn();
  render(<PolicyWizard policy={policy} onSave={onSave} onCancel={() => undefined} />);
  fireEvent.click(screen.getByRole('button', { name: 'Target resources' }));
  expect(screen.getByText(/Unknown app \(11111111-1111-1111-1111-111111111111\)/)).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: `Remove excluded resource ${customId}` }));
  fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));
  expect(onSave.mock.calls[0][0].conditions.applications.excludeApplications).not.toContain(customId);
});

test('exclude catalog checkbox matches stored id regardless of case', () => {
  const graphId = APP.microsoftGraph.toUpperCase();
  const policy = normalizePolicy({
    displayName: 'Case test',
    state: 'enabled',
    conditions: {
      users: { includeUsers: ['All'] },
      applications: { includeApplications: ['All'], excludeApplications: [graphId] },
    },
    grantControls: { operator: 'OR', builtInControls: ['mfa'] },
  }, 0).policy;
  const onSave = vi.fn();
  render(<PolicyWizard policy={policy} onSave={onSave} onCancel={() => undefined} />);
  fireEvent.click(screen.getByRole('button', { name: 'Target resources' }));
  fireEvent.change(screen.getByLabelText('Search resources to exclude'), { target: { value: 'Microsoft Graph' } });
  const excludePick = document.querySelectorAll('.app-pick')[0];
  const graphLabel = within(excludePick as HTMLElement).getByText(/^Microsoft Graph$/);
  const graphCheckbox = graphLabel.closest('label')!.querySelector('input[type="checkbox"]') as HTMLInputElement;
  expect(graphCheckbox.checked).toBe(true);
  fireEvent.click(graphCheckbox);
  fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));
  const saved = onSave.mock.calls[0][0].conditions.applications.excludeApplications;
  expect(saved.filter((id: string) => id.toLowerCase() === APP.microsoftGraph.toLowerCase())).toHaveLength(0);
});
