import { normalizePolicy } from '../model/normalize';
import type { CAPolicy, TenantProfile } from '../model/types';

const EMPLOYEES = '9c2e4a6b-1d3f-4b5a-8c7e-0f2a4b6c8d01';
const SCAN_TO_EMAIL = '9c2e4a6b-1d3f-4b5a-8c7e-0f2a4b6c8d02';

const users = (o: { includeUsers?: string[]; excludeUsers?: string[]; includeGroups?: string[]; includeRoles?: string[] }) => ({
  includeUsers: [], excludeUsers: [], includeGroups: [], excludeGroups: [], includeRoles: [], excludeRoles: [],
  includeGuestsOrExternalUsers: null, excludeGuestsOrExternalUsers: null, ...o,
});
const apps = (includeApplications: string[], excludeApplications: string[] = []) => ({
  includeApplications, excludeApplications, includeUserActions: [], includeAuthenticationContextClassReferences: [],
  applicationFilter: null,
});
const grant = (operator: 'AND' | 'OR', builtInControls: string[]) => ({
  operator, builtInControls, customAuthenticationFactors: [], termsOfUse: [], authenticationStrength: null,
});

/** Microsoft Graph beta conditionalAccessPolicy objects, as returned by GET /identity/conditionalAccess/policies. */
export const weakTenantRaw: unknown[] = [
  {
    id: '6d4b2f80-7a1c-4e3d-b5f9-1a2b3c4d5e01',
    displayName: 'CA01 - Require MFA - Employees - Outside trusted locations',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: users({ includeGroups: [EMPLOYEES] }),
      applications: apps(['All']),
      clientAppTypes: ['all'],
      locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] },
    },
    grantControls: grant('OR', ['mfa']),
    sessionControls: null,
  },
  {
    id: '6d4b2f80-7a1c-4e3d-b5f9-1a2b3c4d5e02',
    displayName: 'CA02 - Require MFA or compliant device - Admins - Admin portals',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: users({
        includeRoles: [
          '62e90394-69f5-4237-9190-012177145e10', // Global Administrator
          '29232cdf-9323-42fd-ade2-1d097af3e4de', // Exchange Administrator
          'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', // SharePoint Administrator
          'fe930be7-5e62-47db-91af-98c3a49a38b1', // User Administrator
          '194ae4cb-b126-40b2-bd5b-6091b380977d', // Security Administrator
        ],
      }),
      applications: apps(['MicrosoftAdminPortals']),
      clientAppTypes: ['all'],
    },
    grantControls: grant('OR', ['mfa', 'compliantDevice']),
    sessionControls: null,
  },
  {
    id: '6d4b2f80-7a1c-4e3d-b5f9-1a2b3c4d5e03',
    displayName: 'CA03 - Block legacy authentication - All users',
    state: 'enabledForReportingButNotEnforced',
    templateId: null,
    conditions: {
      users: users({ includeUsers: ['All'], excludeUsers: [SCAN_TO_EMAIL] }),
      applications: apps(['All']),
      clientAppTypes: ['other'],
    },
    grantControls: grant('OR', ['block']),
    sessionControls: null,
  },
  {
    id: '6d4b2f80-7a1c-4e3d-b5f9-1a2b3c4d5e04',
    displayName: 'CA04 - Require compliant device - Employees - All resources except Office 365',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: users({ includeGroups: [EMPLOYEES] }),
      applications: apps(['All'], ['Office365']),
      clientAppTypes: ['all'],
    },
    grantControls: grant('OR', ['compliantDevice']),
    sessionControls: null,
  },
  {
    id: '6d4b2f80-7a1c-4e3d-b5f9-1a2b3c4d5e05',
    displayName: 'CA05 - Keep users signed in - All users - Office 365',
    state: 'enabled',
    templateId: null,
    conditions: { users: users({ includeUsers: ['All'] }), applications: apps(['Office365']), clientAppTypes: ['all'] },
    grantControls: null,
    sessionControls: { persistentBrowser: { isEnabled: true, mode: 'always' } },
  },
  {
    id: '6d4b2f80-7a1c-4e3d-b5f9-1a2b3c4d5e06',
    displayName: 'CA06 - Require approved client app - Employees - iOS and Android',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: users({ includeGroups: [EMPLOYEES] }),
      applications: apps(['Office365']),
      clientAppTypes: ['all'],
      platforms: { includePlatforms: ['android', 'iOS'], excludePlatforms: [] },
    },
    grantControls: grant('OR', ['approvedApplication']),
    sessionControls: null,
  },
  {
    id: '6d4b2f80-7a1c-4e3d-b5f9-1a2b3c4d5e07',
    displayName: 'Microsoft-managed: Block device code flow',
    state: 'disabled',
    templateId: null,
    conditions: {
      users: users({ includeUsers: ['All'] }),
      applications: apps(['All']),
      clientAppTypes: ['all'],
      authenticationFlows: { transferMethods: 'deviceCodeFlow' },
    },
    grantControls: grant('OR', ['block']),
    sessionControls: null,
  },
  {
    id: '6d4b2f80-7a1c-4e3d-b5f9-1a2b3c4d5e08',
    displayName: 'CA08 - Require MFA - All users - Graph PowerShell',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: users({ includeUsers: ['All'] }),
      applications: apps(['14d82eec-204b-4c2f-b7e8-296a70dab67e']), // Microsoft Graph Command Line Tools
      clientAppTypes: ['all'],
    },
    grantControls: grant('OR', ['mfa']),
    sessionControls: null,
  },
];

export const weakTenant: { policies: CAPolicy[]; tenant: TenantProfile } = {
  policies: weakTenantRaw.map((raw, i) => normalizePolicy(raw, i).policy),
  tenant: {
    licenses: { entraP1: true, entraP2: false, intune: false, workloadIdPremium: false, defenderForCloudApps: false, purviewInsiderRisk: false },
    breakGlass: [],
    displayNames: {
      [EMPLOYEES]: 'Employees',
      [SCAN_TO_EMAIL]: 'Scan-to-email service account',
    },
  },
};
