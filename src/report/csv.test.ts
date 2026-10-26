import { expect, test } from 'vitest';
import type { CAPolicy, Finding } from '../model/types';
import { findingsToCsv } from './csv';

const finding = (over: Partial<Finding> = {}): Finding => ({
  ruleId: 'BAS-01',
  title: 't',
  family: 'baseline',
  severity: 'critical',
  status: 'gap',
  policyIds: ['p1'],
  explanation: '',
  remediation: 'Do this, then that',
  references: ['https://learn.microsoft.com/x'],
  ...over,
});

test('escapes commas in remediation and policy names', () => {
  const csv = findingsToCsv(
    [finding()],
    [{ id: 'p1', displayName: 'Block, legacy' } as CAPolicy],
  );
  expect(csv).toContain('"Do this, then that"');
  expect(csv).toContain('"Block, legacy"');
  expect(csv.startsWith('ruleId,severity,status,title,policies,remediation,requiredLicense,reference')).toBe(true);
});

test('joins multiple policy names with semicolons', () => {
  const csv = findingsToCsv(
    [finding({ policyIds: ['a', 'b'] })],
    [
      { id: 'a', displayName: 'One' } as CAPolicy,
      { id: 'b', displayName: 'Two' } as CAPolicy,
    ],
  );
  expect(csv).toContain('One; Two');
});
