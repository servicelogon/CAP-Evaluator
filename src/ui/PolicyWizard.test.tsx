import { fireEvent, render, screen } from '@testing-library/react';
import { expect, test, vi } from 'vitest';
import { AUTH_STRENGTH } from '../catalog/authStrengths';
import { USER_ACTION } from '../catalog/apps';
import { blankPolicy } from '../model/newPolicy';
import { PolicyWizard } from './PolicyWizard';

test('saving phishing-resistant strength and security-info action', () => {
  const onSave = vi.fn();
  render(<PolicyWizard policy={blankPolicy()} onSave={onSave} onCancel={() => undefined} />);
  fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'Admin phishing-resistant' } });
  fireEvent.click(screen.getByRole('button', { name: 'Grant' }));
  fireEvent.change(screen.getByLabelText('Authentication strength'), { target: { value: AUTH_STRENGTH.phishingResistant } });
  fireEvent.click(screen.getByRole('button', { name: 'Target resources' }));
  fireEvent.click(screen.getByLabelText('User action: Register security information'));
  fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));
  const saved = onSave.mock.calls[0][0];
  expect(saved.displayName).toBe('Admin phishing-resistant');
  expect(saved.grantControls?.authenticationStrength?.id).toBe(AUTH_STRENGTH.phishingResistant);
  expect(saved.conditions.applications.includeUserActions).toContain(USER_ACTION.registerSecurityInfo);
});
