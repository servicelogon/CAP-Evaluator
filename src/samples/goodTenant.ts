import { normalizePolicy } from '../model/normalize';
import type { CAPolicy, TenantProfile } from '../model/types';

const EMERGENCY_01 = '3f8e2a71-5c4d-4b9e-a0f6-7d1c9e2b4a01';
const EMERGENCY_02 = '3f8e2a71-5c4d-4b9e-a0f6-7d1c9e2b4a02';
const PIM_ADMINS = '4f1c2b9a-7d3e-4e21-8b0a-9e6f5d4c3b2a';
const BREAK_GLASS = [EMERGENCY_01, EMERGENCY_02];

const ADMIN_ROLES = [
  '62e90394-69f5-4237-9190-012177145e10', // Global Administrator
  '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', // Application Administrator
  'c4e39bd9-1100-46d3-8c65-fb160da0071f', // Authentication Administrator
  'b0f54661-2d74-4c50-afa3-1ec803f12efe', // Billing Administrator
  '158c047a-c907-4556-b7ef-446551a6b5f7', // Cloud Application Administrator
  'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', // Conditional Access Administrator
  '29232cdf-9323-42fd-ade2-1d097af3e4de', // Exchange Administrator
  '729827e3-9c14-49f7-bb1b-9608f156bbb8', // Helpdesk Administrator
  '966707d0-3269-4727-9be2-8c3a10f19b9d', // Password Administrator
  '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', // Privileged Authentication Administrator
  'e8611ab8-c189-46e8-94e1-60213ab1f814', // Privileged Role Administrator
  '194ae4cb-b126-40b2-bd5b-6091b380977d', // Security Administrator
  'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', // SharePoint Administrator
  'fe930be7-5e62-47db-91af-98c3a49a38b1', // User Administrator
];

const ALL_GUEST_TYPES = 'internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider';

const allUsers = {
  includeUsers: ['All'], excludeUsers: BREAK_GLASS, includeGroups: [], excludeGroups: [], includeRoles: [], excludeRoles: [],
  includeGuestsOrExternalUsers: null, excludeGuestsOrExternalUsers: null,
};
const admins = { ...allUsers, includeUsers: [], includeGroups: [PIM_ADMINS], includeRoles: ADMIN_ROLES };
const allResources = {
  includeApplications: ['All'], excludeApplications: [], includeUserActions: [], includeAuthenticationContextClassReferences: [],
  applicationFilter: null,
};
const userAction = (action: string) => ({ ...allResources, includeApplications: [], includeUserActions: [action] });
const grant = (operator: 'AND' | 'OR', builtInControls: string[], authenticationStrength: unknown = null) => ({
  operator, builtInControls, customAuthenticationFactors: [], termsOfUse: [], authenticationStrength,
});
const block = grant('OR', ['block']);
const mfa = grant('OR', ['mfa']);
const everyTime = {
  isEnabled: true, type: null, value: null, frequencyInterval: 'everyTime', authenticationType: 'primaryAndSecondaryAuthentication',
};
const PHISHING_RESISTANT = {
  id: '00000000-0000-0000-0000-000000000004',
  displayName: 'Phishing-resistant MFA',
  policyType: 'builtIn',
  requirementsSatisfied: 'mfa',
  allowedCombinations: ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor'],
};

/** Microsoft Graph beta conditionalAccessPolicy objects, as returned by GET /identity/conditionalAccess/policies. */
export const goodTenantRaw: unknown[] = [
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a01',
    displayName: 'CA001 - Block legacy authentication - All users',
    state: 'enabled',
    templateId: null,
    conditions: { users: allUsers, applications: allResources, clientAppTypes: ['exchangeActiveSync', 'other'] },
    grantControls: block,
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a02',
    displayName: 'CA002 - Require MFA - All users - All resources',
    state: 'enabled',
    templateId: null,
    conditions: { users: allUsers, applications: allResources, clientAppTypes: ['all'] },
    grantControls: mfa,
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a03',
    displayName: 'CA003 - Require MFA - Guests and external users',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: {
        ...allUsers,
        includeUsers: [],
        includeGuestsOrExternalUsers: {
          guestOrExternalUserTypes: ALL_GUEST_TYPES,
          externalTenants: { '@odata.type': '#microsoft.graph.conditionalAccessAllExternalTenants', membershipKind: 'all' },
        },
      },
      applications: allResources,
      clientAppTypes: ['all'],
    },
    grantControls: mfa,
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a04',
    displayName: 'CA004 - Block device code flow - All users',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: allUsers, applications: allResources, clientAppTypes: ['all'],
      authenticationFlows: { transferMethods: 'deviceCodeFlow' },
    },
    grantControls: block,
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a05',
    displayName: 'CA005 - Block authentication transfer - All users',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: allUsers, applications: allResources, clientAppTypes: ['all'],
      authenticationFlows: { transferMethods: 'authenticationTransfer' },
    },
    grantControls: block,
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a06',
    displayName: 'CA006 - Block unknown or unsupported device platforms - All users',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: allUsers, applications: allResources, clientAppTypes: ['all'],
      platforms: { includePlatforms: ['all'], excludePlatforms: ['android', 'iOS', 'windows', 'macOS'] },
    },
    grantControls: block,
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a07',
    displayName: 'CA007 - Require MFA to register security information - All users',
    state: 'enabled',
    templateId: null,
    conditions: { users: allUsers, applications: userAction('urn:user:registersecurityinfo'), clientAppTypes: ['all'] },
    grantControls: mfa,
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a08',
    displayName: 'CA008 - Require MFA to register or join devices - All users',
    state: 'enabled',
    templateId: null,
    conditions: { users: allUsers, applications: userAction('urn:user:registerdevice'), clientAppTypes: ['all'] },
    grantControls: mfa,
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a09',
    displayName: 'CA009 - Require compliant or hybrid joined device - All users',
    state: 'enabled',
    templateId: null,
    conditions: { users: allUsers, applications: allResources, clientAppTypes: ['all'] },
    grantControls: grant('OR', ['compliantDevice', 'domainJoinedDevice']),
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a10',
    displayName: 'CA010 - Require reauthentication and no persistent browser on unmanaged devices - All users',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: allUsers, applications: allResources, clientAppTypes: ['all'],
      devices: { deviceFilter: { mode: 'exclude', rule: 'device.isCompliant -eq True -or device.trustType -eq "ServerAD"' } },
    },
    grantControls: null,
    sessionControls: {
      signInFrequency: { isEnabled: true, type: 'hours', value: 1, frequencyInterval: 'timeBased', authenticationType: 'primaryAndSecondaryAuthentication' },
      persistentBrowser: { isEnabled: true, mode: 'never' },
    },
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a11',
    displayName: 'CA011 - Require MFA and reauthentication for risky sign-ins - All users',
    state: 'enabled',
    templateId: null,
    conditions: { users: allUsers, applications: allResources, clientAppTypes: ['all'], signInRiskLevels: ['high', 'medium'] },
    grantControls: mfa,
    sessionControls: { signInFrequency: everyTime },
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a12',
    displayName: 'CA012 - Require password change for high-risk users - All users',
    state: 'enabled',
    templateId: null,
    conditions: { users: allUsers, applications: allResources, clientAppTypes: ['all'], userRiskLevels: ['high'] },
    grantControls: grant('AND', ['mfa', 'passwordChange']),
    sessionControls: { signInFrequency: everyTime },
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1a13',
    displayName: 'CA013 - Block access for elevated insider risk - All users',
    state: 'enabled',
    templateId: null,
    conditions: { users: allUsers, applications: allResources, clientAppTypes: ['all'], insiderRiskLevels: 'elevated' },
    grantControls: block,
    sessionControls: null,
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1b01',
    displayName: 'CA101 - Require phishing-resistant MFA and compliant device - Admins - All resources',
    state: 'enabled',
    templateId: null,
    conditions: { users: admins, applications: allResources, clientAppTypes: ['all'] },
    grantControls: grant('AND', ['compliantDevice'], PHISHING_RESISTANT),
    sessionControls: {
      signInFrequency: { isEnabled: true, type: 'hours', value: 4, frequencyInterval: 'timeBased', authenticationType: 'primaryAndSecondaryAuthentication' },
      persistentBrowser: { isEnabled: true, mode: 'never' },
    },
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1b02',
    displayName: 'CA102 - Require token protection - Admins - Windows',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: admins,
      applications: {
        ...allResources,
        includeApplications: [
          '00000002-0000-0ff1-ce00-000000000000', // Office 365 Exchange Online
          '00000003-0000-0ff1-ce00-000000000000', // Office 365 SharePoint Online
          'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe', // Microsoft Teams Services
        ],
      },
      clientAppTypes: ['mobileAppsAndDesktopClients'],
      platforms: { includePlatforms: ['windows'], excludePlatforms: [] },
    },
    grantControls: null,
    sessionControls: { secureSignInSession: { isEnabled: true } },
  },
  {
    id: '0b6a3f1e-2c4d-4e8f-9a1b-3c5d7e9f1c01',
    displayName: 'CA201 - Block workload identities outside trusted locations',
    state: 'enabled',
    templateId: null,
    conditions: {
      users: { ...allUsers, includeUsers: ['None'], excludeUsers: [] },
      applications: allResources,
      clientAppTypes: ['all'],
      clientApplications: { includeServicePrincipals: ['ServicePrincipalsInMyTenant'], excludeServicePrincipals: [] },
      locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] },
    },
    grantControls: block,
    sessionControls: null,
  },
];

export const goodTenant: { policies: CAPolicy[]; tenant: TenantProfile } = {
  policies: goodTenantRaw.map((raw, i) => normalizePolicy(raw, i).policy),
  tenant: {
    licenses: { entraP1: true, entraP2: true, intune: true, workloadIdPremium: true, defenderForCloudApps: false, purviewInsiderRisk: true },
    breakGlass: BREAK_GLASS,
    displayNames: {
      [EMERGENCY_01]: 'Emergency access 01',
      [EMERGENCY_02]: 'Emergency access 02',
      [PIM_ADMINS]: 'PIM-eligible admins',
    },
  },
};
