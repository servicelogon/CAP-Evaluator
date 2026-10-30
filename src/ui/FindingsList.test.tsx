import { fireEvent, render, screen } from '@testing-library/react';
import { expect, test } from 'vitest';
import type { Finding } from '../model/types';
import { FindingsList } from './FindingsList';

const finding: Finding = {
  ruleId: 'ADM-01',
  title: 'Privileged roles need phishing-resistant MFA',
  family: 'admin',
  severity: 'critical',
  status: 'gap',
  policyIds: [],
  explanation: 'No enforced policy requires a phishing-resistant strength.',
  remediation: 'Create a policy from the admin template.',
  references: ['https://example.test/learn'],
};

test('a finding hides its explanation and remediation until the row is opened', () => {
  render(<FindingsList findings={[finding]} policies={[]} />);
  expect(screen.getByText('ADM-01').className).toContain('rule-id');
  expect(screen.getByText('ADM-01').className).toContain('critical');
  expect(screen.queryByText(finding.explanation)).toBeNull();
  expect(screen.queryByText(finding.remediation)).toBeNull();
  fireEvent.click(screen.getByText(finding.title));
  expect(screen.getByText(finding.explanation)).toBeTruthy();
  expect(screen.getByText(finding.remediation)).toBeTruthy();
  expect(screen.getByRole('link', { name: 'Learn' }).getAttribute('href')).toBe('https://example.test/learn');
});
