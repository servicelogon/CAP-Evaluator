import type { CellState, FindingStatus, PolicyState, Population, RuleFamily, Severity } from '../model/types';

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

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  gap: 'Gap',
  partial: 'Partial',
  requiresLicense: 'Needs license',
  unverified: 'Unverified',
};

export const FAMILY_LABEL: Record<RuleFamily, string> = {
  baseline: 'Baseline',
  admin: 'Admin',
  apps: 'Apps',
  weakening: 'Weakening',
  risk: 'Risk',
  hygiene: 'Hygiene',
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

/** Short names for narrow screens. Full names stay in aria-labels and titles. */
export const SURFACE_SHORT: Record<string, string> = {
  allResources: 'All resources',
  office365: 'Office 365',
  adminPortals: 'Admin portals',
  azureManagement: 'Azure management',
  graph: 'Microsoft Graph',
  intuneApi: 'Intune APIs',
  azureDevOps: 'Azure DevOps',
  thirdParty: 'Third-party apps',
  registerSecurityInfo: 'Register security info',
  registerDevice: 'Register or join devices',
};

export const CONTROL_SHORT: Record<string, string> = {
  legacyBlocked: 'Legacy auth',
  mfa: 'MFA',
  phishResistant: 'Phish-resistant',
  managedDevice: 'Managed device',
  deviceCodeBlocked: 'Device code',
  signInRisk: 'Sign-in risk',
  userRisk: 'User risk',
  session: 'Session',
};

/** A shape for each cell state so the map does not rely on color alone. */
export const CELL_GLYPH: Record<CellState, string> = {
  covered: '✓',
  partial: '~',
  gap: '✕',
  requiresLicense: '',
  na: '–',
};
