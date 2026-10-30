import type { PolicyState, Population } from '../model/types';
import type { CellState } from '../model/types';

export const STATE_LABEL: Record<PolicyState, string> = {
  enabled: 'On',
  enabledForReportingButNotEnforced: 'Report-only',
  disabled: 'Off',
};

export const STATE_CLASS: Record<PolicyState, string> = {
  enabled: 'on',
  enabledForReportingButNotEnforced: 'report',
  disabled: 'off',
};

export const POP_LABEL: Record<Population, string> = {
  allUsers: 'All users',
  admins: 'Admins',
  guests: 'Guests',
};

export const CELL_LABEL: Record<CellState, string> = {
  covered: 'Covered',
  partial: 'Partial',
  gap: 'Gap',
  requiresLicense: 'License',
  na: 'n/a',
};

export const LICENSE_FIELDS = [
  {
    key: 'entraP1' as const,
    label: 'Entra ID P1',
    hint: 'Conditional Access itself. Token protection is also gated on P1.',
  },
  {
    key: 'entraP2' as const,
    label: 'Entra ID P2',
    hint: 'Sign-in risk and user risk. Insider risk also needs Purview.',
  },
  {
    key: 'intune' as const,
    label: 'Intune',
    hint: 'Managed-device findings and the managed-device column.',
  },
  {
    key: 'workloadIdPremium' as const,
    label: 'Workload Identities Premium',
    hint: 'Workload identity policies.',
  },
  {
    key: 'defenderForCloudApps' as const,
    label: 'Defender for Cloud Apps',
    hint: 'Stored on the profile. No current rule reads this license.',
  },
  {
    key: 'purviewInsiderRisk' as const,
    label: 'Purview Insider Risk',
    hint: 'Insider risk, together with Entra ID P2.',
  },
];

export const ALL_GUEST_TYPES = [
  'internalGuest',
  'b2bCollaborationGuest',
  'b2bCollaborationMember',
  'b2bDirectConnectUser',
  'otherExternalUser',
  'serviceProvider',
];

export function linesOf(value: string): string[] {
  return value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
}
