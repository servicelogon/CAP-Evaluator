export const APP = {
  exchangeOnline: '00000002-0000-0ff1-ce00-000000000000',
  sharePointOnline: '00000003-0000-0ff1-ce00-000000000000',
  teamsServices: 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe',
  teamsClient: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
  microsoftGraph: '00000003-0000-0000-c000-000000000000',
  azureAdGraph: '00000002-0000-0000-c000-000000000000',
  azurePortal: 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c',
  exchangeAdminCenter: '497effe9-df71-4043-a8bb-14cf78c4b63b',
  office365Portal: '00000006-0000-0ff1-ce00-000000000000',
  protectionCenter: '80ccca67-54bd-44ab-8625-4b79c4dc7775',
  azureManagement: '797f4846-ba00-4fd7-ba43-dac1f8f63013',
  azureDevOps: '499b84ac-1321-427f-aa17-267ca6975798',
  intune: '0000000a-0000-0000-c000-000000000000',
  intuneEnrollment: 'd4ebce55-015a-49b5-a083-c84d1797ae8c',
  intuneWebCompanyPortal: '74bcdadc-2fdc-4bb3-8459-76d06952a0e9',
  intuneCompanyPortalClient: '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223',
  deviceRegistrationService: '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9',
  graphPowerShell: '14d82eec-204b-4c2f-b7e8-296a70dab67e',
  graphExplorer: 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',
  azureCli: '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
  azurePowerShell: '1950a258-227b-4e31-a9cf-717495945fc2',
  azureMobileApp: '0c1307d4-29d6-4389-a11c-5cbe7f65d7fa',
  azureAdPowerShell: '1b730954-1685-4b74-9bfd-dac224a7b894',
  powerPlatformAdmin: '065d9450-1e87-434e-ac2f-69af271549ed',
  rightsManagement: '00000012-0000-0000-c000-000000000000',
  storeForBusiness: '45a330b1-b1ec-4cc1-9161-9f03992aa49f',
  authBroker: '29d9ed98-a469-4536-ade2-f981bc1d605e',
  authenticator: '4813382a-8fa7-425e-ab75-3b753aab3abb',
  gsaInternet: '5dc48733-b5df-475c-a49b-fa307ef00853',
} as const;
export const KEYWORD = { all: 'All', none: 'None', office365: 'Office365', adminPortals: 'MicrosoftAdminPortals' } as const;
export const USER_ACTION = { registerSecurityInfo: 'urn:user:registersecurityinfo', registerDevice: 'urn:user:registerdevice' } as const;
export const ADMIN_PORTAL_IDS = [APP.exchangeAdminCenter, APP.azurePortal, APP.office365Portal, APP.protectionCenter];
export const OFFICE365_KEY_IDS = [APP.exchangeOnline, APP.sharePointOnline, APP.teamsServices, APP.office365Portal, APP.protectionCenter];
export type SurfaceId = 'allResources' | 'office365' | 'adminPortals' | 'azureManagement' | 'graph' | 'intuneApi' | 'azureDevOps' | 'thirdParty' | 'registerSecurityInfo' | 'registerDevice';
export interface CatalogApp {
  appId: string; name: string; aliases: string[]; surface: SurfaceId | null;
  groups: ('Office365' | 'MicrosoftAdminPortals')[]; targetable: boolean; highValue: boolean;
  confidence: 'verified' | 'unverified'; notes: string; source: string;
}
export const CATALOG_DATE = '2026-10-26';

const SRC = {
  cloudApps: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps',
  office365Ref: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/reference-office-365-application-contents',
  mandatoryMfa: 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication',
  deviceCompliance: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance',
  authFlows: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows',
  azureDevOps: 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/conditional-access-policies?view=azure-devops',
  intuneMfa: 'https://learn.microsoft.com/en-us/intune/device-enrollment/configure-multifactor-authentication',
  compliantOrMfa: 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-alt-all-users-compliant-hybrid-or-mfa',
  firstParty: 'https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in',
  powerPlatformApps: 'https://learn.microsoft.com/en-us/power-platform/admin/apps-to-allow',
  rms: 'https://learn.microsoft.com/en-us/purview/encryption-azure-ad-configuration',
  graphInternetAccess: 'https://learn.microsoft.com/en-us/graph/tutorial-entra-internet-access',
  devBoxCa: 'https://learn.microsoft.com/en-us/azure/dev-box/how-to-configure-intune-conditional-access-policies',
  brokerQa: 'https://learn.microsoft.com/en-us/answers/questions/5874646/microsoft-authentication-broker-showing-single-fac',
};

type Entry = Omit<CatalogApp, 'appId' | 'groups' | 'aliases'> & { aliases?: string[] };
const ENTRIES: Record<keyof typeof APP, Entry> = {
  exchangeOnline: {
    name: 'Office 365 Exchange Online', surface: 'office365', targetable: true, highValue: true, confidence: 'verified',
    notes: 'Member of the Office 365 group. Microsoft recommends targeting Office 365 instead; Exchange data is also reachable through Search and Teams. Not covered by Microsoft Admin Portals (Exchange Online PowerShell included).',
    source: SRC.powerPlatformApps,
  },
  sharePointOnline: {
    name: 'Office 365 SharePoint Online', surface: 'office365', targetable: true, highValue: true, confidence: 'unverified',
    notes: 'Member of the Office 365 group; also serves the SharePoint admin center. Teams depends on it, so a SharePoint-only policy also affects Teams. App ID is community-sourced.',
    source: SRC.office365Ref,
  },
  teamsServices: {
    name: 'Microsoft Teams Services', surface: 'office365', targetable: true, highValue: true, confidence: 'verified',
    notes: 'Member of the Office 365 group. Teams early-binds to Exchange and SharePoint, so policies on those apps also affect Teams.',
    source: SRC.powerPlatformApps,
  },
  teamsClient: {
    name: 'Microsoft Teams (client)', aliases: ['Microsoft Teams'], surface: null, targetable: false, highValue: false, confidence: 'verified',
    notes: 'Client app; cannot be targeted. Conditional Access evaluates the resources it calls (Teams Services, Exchange, SharePoint).',
    source: SRC.powerPlatformApps,
  },
  microsoftGraph: {
    name: 'Microsoft Graph', surface: 'graph', targetable: false, highValue: false, confidence: 'verified',
    notes: 'Covered only by All resources. Umbrella resource that cannot be selected in a policy; Graph PowerShell, Graph Explorer and admin-center API calls go here.',
    source: SRC.cloudApps,
  },
  azureAdGraph: {
    name: 'Windows Azure Active Directory (Azure AD Graph)', aliases: ['Windows Azure Active Directory', 'Azure AD Graph'],
    surface: 'graph', targetable: false, highValue: false, confidence: 'verified',
    notes: 'Covered only by All resources (or a custom security attribute app filter). Not in the picker. Since 2026 it is the evaluation audience for baseline-scope (OIDC/User.Read) sign-ins.',
    source: SRC.cloudApps,
  },
  azurePortal: {
    name: 'Azure portal', surface: 'adminPortals', targetable: true, highValue: true, confidence: 'verified',
    notes: 'Also the sign-in app for the Microsoft Entra and Intune admin centers. Backend APIs those portals call (Microsoft Graph, Intune, ARM) are separate resources.',
    source: SRC.cloudApps,
  },
  exchangeAdminCenter: {
    name: 'Exchange Admin Center', surface: 'adminPortals', targetable: true, highValue: true, confidence: 'verified',
    notes: 'Member of Microsoft Admin Portals. Covers the portal front end only; Exchange Online and Exchange Online PowerShell are separate resources.',
    source: SRC.cloudApps,
  },
  office365Portal: {
    name: 'Microsoft Office 365 Portal', surface: 'office365', targetable: true, highValue: false, confidence: 'verified',
    notes: 'In both the Office 365 and Microsoft Admin Portals groups. Sign-in app for the Microsoft 365 admin center; M365 Admin Services, Graph and ARM calls are separate resources.',
    source: SRC.cloudApps,
  },
  protectionCenter: {
    name: 'Microsoft 365 Security and Compliance Center (Protection Center)', aliases: ['Protection Center'],
    surface: 'office365', targetable: true, highValue: false, confidence: 'verified',
    notes: 'In both the Office 365 and Microsoft Admin Portals groups. Likely the sign-in app for the Purview portal; Defender portal mapping is unverified.',
    source: SRC.cloudApps,
  },
  azureManagement: {
    name: 'Windows Azure Service Management API', aliases: ['Microsoft Azure Management', 'Azure Resource Manager'],
    surface: 'azureManagement', targetable: true, highValue: true, confidence: 'verified',
    notes: 'Covers ARM, Azure portal, Azure CLI/PowerShell. Does not cover Microsoft Graph or Azure DevOps (removed Sep 2025). Display name has changed several times; match by app ID.',
    source: SRC.devBoxCa,
  },
  azureDevOps: {
    name: 'Azure DevOps', surface: 'azureDevOps', targetable: true, highValue: false, confidence: 'verified',
    notes: 'Must be targeted directly or via All resources. No longer covered by Windows Azure Service Management API since Sep 2025.',
    source: SRC.azureDevOps,
  },
  intune: {
    name: 'Microsoft Intune', surface: 'intuneApi', targetable: true, highValue: true, confidence: 'unverified',
    notes: 'Intune API called by the Intune admin center after sign-in; not covered by Microsoft Admin Portals. Compliant-device policies need no exclusion for it. App ID is community-sourced.',
    source: SRC.intuneMfa,
  },
  intuneEnrollment: {
    name: 'Microsoft Intune Enrollment', surface: null, targetable: true, highValue: false, confidence: 'verified',
    notes: 'Not created automatically in new tenants; a policy targeting it protects nothing until the service principal exists. Use for MFA at enrollment. Must be excluded from per-device Terms of Use policies.',
    source: SRC.intuneMfa,
  },
  intuneWebCompanyPortal: {
    name: 'Microsoft Intune Web Company Portal', surface: null, targetable: true, highValue: false, confidence: 'unverified',
    notes: 'Built-in carve-out: Require compliant device does not block it, so excluding it is unnecessary and only weakens coverage. App ID is community-sourced.',
    source: SRC.compliantOrMfa,
  },
  intuneCompanyPortalClient: {
    name: 'Microsoft Intune Company Portal (client)', aliases: ['Intune Company Portal'], surface: null, targetable: false, highValue: false, confidence: 'verified',
    notes: 'Client app; cannot be targeted. Conditional Access evaluates the resources it calls.',
    source: SRC.powerPlatformApps,
  },
  deviceRegistrationService: {
    name: 'Device Registration Service', surface: null, targetable: true, highValue: true, confidence: 'verified',
    notes: 'Governed by the Register or join devices user action (MFA or auth strength only). Authentication-flow policies on All resources apply to it since Sep 2024. Location conditions are not enforced for device registration.',
    source: SRC.authFlows,
  },
  graphPowerShell: {
    name: 'Microsoft Graph Command Line Tools', aliases: ['Microsoft Graph PowerShell', 'Graph PowerShell'],
    surface: null, targetable: false, highValue: false, confidence: 'verified',
    notes: 'Client app; cannot be targeted. Its calls go to Microsoft Graph, which is only covered by All resources.',
    source: SRC.firstParty,
  },
  graphExplorer: {
    name: 'Graph Explorer', surface: 'graph', targetable: true, highValue: false, confidence: 'verified',
    notes: 'Web app that calls Microsoft Graph. Community reports say it can be targeted, but its Graph calls are only covered by All resources.',
    source: SRC.firstParty,
  },
  azureCli: {
    name: 'Azure CLI', aliases: ['Microsoft Azure CLI'], surface: null, targetable: false, highValue: false, confidence: 'verified',
    notes: 'Client app; cannot be targeted. ARM calls are covered by Windows Azure Service Management API; Graph calls (az ad) are only covered by All resources.',
    source: SRC.mandatoryMfa,
  },
  azurePowerShell: {
    name: 'Azure PowerShell', aliases: ['Microsoft Azure PowerShell'], surface: null, targetable: false, highValue: false, confidence: 'verified',
    notes: 'Client app; cannot be targeted. ARM calls are covered by Windows Azure Service Management API; Get-AzAD* calls go to Graph, only covered by All resources.',
    source: SRC.mandatoryMfa,
  },
  azureMobileApp: {
    name: 'Azure mobile app', surface: null, targetable: false, highValue: false, confidence: 'verified',
    notes: 'Client app; cannot be targeted. Calls ARM, so it is covered by Windows Azure Service Management API.',
    source: SRC.mandatoryMfa,
  },
  azureAdPowerShell: {
    name: 'Azure Active Directory PowerShell (retired)', aliases: ['Azure Active Directory PowerShell', 'MSOnline', 'AzureAD PowerShell'],
    surface: null, targetable: false, highValue: false, confidence: 'verified',
    notes: 'Client app; cannot be targeted. Retired (MSOnline Apr–May 2025, AzureAD mid-Oct to mid-Nov 2025); references in policies are stale.',
    source: SRC.powerPlatformApps,
  },
  powerPlatformAdmin: {
    name: 'Power Platform admin center', surface: null, targetable: true, highValue: false, confidence: 'verified',
    notes: 'Not documented as a Microsoft Admin Portals member and not in the Office 365 group; target it directly or via All resources.',
    source: SRC.powerPlatformApps,
  },
  rightsManagement: {
    name: 'Microsoft Rights Management Services', surface: null, targetable: true, highValue: true, confidence: 'verified',
    notes: 'Often excluded so external users can open encrypted content; prefer MFA trust or excluding external users instead of excluding the app.',
    source: SRC.rms,
  },
  storeForBusiness: {
    name: 'Windows Store for Business (Universal Store Service APIs)', aliases: ['Windows Store for Business', 'Universal Store Service APIs'], surface: null,
    targetable: true, highValue: false, confidence: 'verified',
    notes: 'Microsoft recommends excluding it from device-compliance policies when using Windows Subscription Activation.',
    source: SRC.deviceCompliance,
  },
  authBroker: {
    name: 'Microsoft Authentication Broker', surface: null, targetable: false, highValue: false, confidence: 'unverified',
    notes: 'Client/broker, not a resource; broker sign-ins show "Not applied" by design. Evaluate the target resource instead. App ID is community-sourced.',
    source: SRC.brokerQa,
  },
  authenticator: {
    name: 'Microsoft Authenticator App', aliases: ['Microsoft Authenticator'], surface: null, targetable: true, highValue: false, confidence: 'verified',
    notes: 'Require compliant device does not block its UserAuthenticationMethod.Read scope (ReadWrite is enforced); no exclusion needed.',
    source: SRC.powerPlatformApps,
  },
  gsaInternet: {
    name: 'All internet resources with Global Secure Access', surface: null, targetable: true, highValue: false, confidence: 'verified',
    notes: 'Internet Access traffic forwarding profile. Without a policy on this app or All resources, tunnelled internet traffic has no Conditional Access.',
    source: SRC.graphInternetAccess,
  },
};

export const APP_CATALOG: CatalogApp[] = (Object.keys(APP) as (keyof typeof APP)[]).map(key => {
  const { aliases = [], ...rest } = ENTRIES[key];
  const appId: string = APP[key];
  const groups: CatalogApp['groups'] = [];
  if ((OFFICE365_KEY_IDS as string[]).includes(appId)) groups.push('Office365');
  if ((ADMIN_PORTAL_IDS as string[]).includes(appId)) groups.push('MicrosoftAdminPortals');
  return { appId, aliases, groups, ...rest };
});

const BY_ID = new Map(APP_CATALOG.map(a => [a.appId.toLowerCase(), a]));

export function lookupApp(appId: string): CatalogApp | undefined {
  return BY_ID.get(appId.toLowerCase());
}

const SPECIAL_LABELS = new Map<string, string>([
  [KEYWORD.all.toLowerCase(), 'All resources'],
  [KEYWORD.none.toLowerCase(), 'None'],
  [KEYWORD.office365.toLowerCase(), 'Office 365 (app group)'],
  [KEYWORD.adminPortals.toLowerCase(), 'Microsoft Admin Portals (app group)'],
  [USER_ACTION.registerSecurityInfo, 'User action: Register security information'],
  [USER_ACTION.registerDevice, 'User action: Register or join devices'],
]);

export function appLabel(idOrKeyword: string): string {
  return SPECIAL_LABELS.get(idOrKeyword.toLowerCase()) ?? lookupApp(idOrKeyword)?.name ?? `Unknown app (${idOrKeyword})`;
}
