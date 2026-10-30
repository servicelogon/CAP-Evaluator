import { fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { expect, test } from 'vitest';
import type { CoverageMatrix, Finding, MatrixCell, Population } from '../model/types';
import { blankPolicy } from '../model/newPolicy';
import { HeatMap } from './HeatMap';

const cell: MatrixCell = {
  surface: 'graph', control: 'mfa', state: 'partial',
  policyIds: ['pol-1'], reasons: ['grant is MFA or a compliant device'],
};

const matrices: Record<Population, CoverageMatrix> = {
  allUsers: { population: 'allUsers', cells: [cell] },
  admins: { population: 'admins', cells: [] },
  guests: { population: 'guests', cells: [] },
};

const finding: Finding = {
  ruleId: 'BAS-03', title: 'No MFA baseline', family: 'baseline', severity: 'critical', status: 'gap',
  policyIds: ['pol-1'], explanation: 'No enforced MFA policy covers all users.', remediation: 'Require MFA.', references: [],
};

function Harness() {
  const [selected, setSelected] = useState<MatrixCell | null>(null);
  const policy = blankPolicy();
  policy.id = 'pol-1';
  policy.displayName = 'MFA or compliant device';
  return (
    <HeatMap
      matrices={matrices}
      population="allUsers"
      onPopulation={() => undefined}
      selected={selected}
      onSelect={setSelected}
      policies={[policy]}
      findings={[finding]}
    />
  );
}

test('a cell names the policy and lists the related finding', () => {
  render(<Harness />);
  fireEvent.click(screen.getByRole('button', { name: /Microsoft Graph & Graph PowerShell, MFA/ }));
  expect(screen.getByText('MFA or compliant device')).toBeTruthy();
  expect(screen.queryByText('pol-1')).toBeNull();
  expect(screen.getByText('No MFA baseline')).toBeTruthy();
  expect(screen.getByText('grant is MFA or a compliant device')).toBeTruthy();
});
