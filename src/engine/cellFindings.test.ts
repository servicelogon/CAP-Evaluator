import { describe, expect, test } from 'vitest';
import type { Finding, MatrixCell } from '../model/types';
import { findingsForCell } from './cellFindings';

function finding(ruleId: string): Finding {
  return {
    ruleId, title: ruleId, family: 'baseline', severity: 'high', status: 'gap',
    policyIds: [], explanation: '', remediation: '', references: [],
  };
}

function cell(surface: string, control: string): MatrixCell {
  return { surface, control, state: 'gap', policyIds: [], reasons: [] };
}

describe('findingsForCell', () => {
  const findings = ['BAS-01', 'BAS-03', 'APP-06', 'APP-07', 'BAS-09', 'RSK-01', 'HYG-02'].map(finding);

  test('MFA on Graph includes the MFA rules and the Graph rule, once each', () => {
    expect(findingsForCell(cell('graph', 'mfa'), findings).map((f) => f.ruleId)).toEqual(['BAS-03', 'APP-06', 'APP-07']);
  });

  test('device registration ignores MFA-only rules and keeps BAS-09', () => {
    expect(findingsForCell(cell('registerDevice', 'mfa'), findings).map((f) => f.ruleId)).toEqual(['BAS-03', 'BAS-09']);
  });

  test('legacy auth does not include the MFA finding', () => {
    expect(findingsForCell(cell('allResources', 'legacyBlocked'), findings).map((f) => f.ruleId)).toEqual(['BAS-01']);
  });

  test('unknown control returns no findings', () => {
    expect(findingsForCell(cell('allResources', 'not-a-control'), findings)).toEqual([]);
  });
});
