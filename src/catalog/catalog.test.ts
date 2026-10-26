import { APP, APP_CATALOG, ADMIN_PORTAL_IDS, OFFICE365_KEY_IDS, lookupApp, appLabel } from './apps';
import { PRIVILEGED_ROLES, EXTENDED_ROLES, GLOBAL_ADMIN, HYBRID_IDENTITY_ADMIN, isPrivilegedRole, roleName } from './roles';
import { AUTH_STRENGTH, isPhishResistant } from './authStrengths';
import { SURFACES, CONTROLS, isNA } from './surfaces';

test('every APP id has a catalog entry', () => { for (const id of Object.values(APP)) expect(lookupApp(id)).toBeDefined(); });
test('admin portals group = 4 ids', () => expect(ADMIN_PORTAL_IDS).toHaveLength(4));
test('graph powershell is not targetable', () => expect(lookupApp(APP.graphPowerShell)!.targetable).toBe(false));
test('appLabel unknown', () => expect(appLabel('11111111-1111-1111-1111-111111111111')).toMatch(/^Unknown app/));
test('14 privileged roles incl. GA', () => { expect(PRIVILEGED_ROLES).toHaveLength(14); expect(isPrivilegedRole(GLOBAL_ADMIN)).toBe(true); });
test('phish resistant', () => {
  expect(isPhishResistant({ id: AUTH_STRENGTH.phishingResistant })).toBe(true);
  expect(isPhishResistant({ id: 'custom', allowedCombinations: ['fido2'] })).toBe(true);
  expect(isPhishResistant({ id: AUTH_STRENGTH.mfa })).toBe(false);
});
test('NA cells', () => { expect(isNA('registerDevice', 'managedDevice')).toBe(true); expect(isNA('registerDevice', 'mfa')).toBe(false); });

test('privileged role IDs match research section 6 exactly', () => {
  expect(PRIVILEGED_ROLES.map(r => r.id).sort()).toEqual([
    '62e90394-69f5-4237-9190-012177145e10', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', 'c4e39bd9-1100-46d3-8c65-fb160da0071f',
    'b0f54661-2d74-4c50-afa3-1ec803f12efe', '158c047a-c907-4556-b7ef-446551a6b5f7', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9',
    '29232cdf-9323-42fd-ade2-1d097af3e4de', '729827e3-9c14-49f7-bb1b-9608f156bbb8', '966707d0-3269-4727-9be2-8c3a10f19b9d',
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'e8611ab8-c189-46e8-94e1-60213ab1f814', '194ae4cb-b126-40b2-bd5b-6091b380977d',
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', 'fe930be7-5e62-47db-91af-98c3a49a38b1',
  ].sort());
});
test('extended roles include Hybrid Identity Admin and none of the 14', () => {
  expect(EXTENDED_ROLES.map(r => r.id)).toContain(HYBRID_IDENTITY_ADMIN);
  expect(EXTENDED_ROLES).toHaveLength(24);
  for (const r of EXTENDED_ROLES) expect(isPrivilegedRole(r.id)).toBe(false);
  expect(roleName(HYBRID_IDENTITY_ADMIN)).toBe('Hybrid Identity Administrator');
  expect(roleName(GLOBAL_ADMIN.toUpperCase())).toBe('Global Administrator');
  expect(roleName('nope')).toBeUndefined();
});

test('every catalog entry has a non-empty https source URL and notes', () => {
  expect(APP_CATALOG).toHaveLength(Object.keys(APP).length);
  for (const a of APP_CATALOG) {
    expect(a.source).toMatch(/^https:\/\/\S+$/);
    expect(a.notes.length).toBeGreaterThan(0);
  }
});
test('catalog flags follow the brief', () => {
  const nonTargetable = ['graphPowerShell', 'azureCli', 'azurePowerShell', 'azureMobileApp', 'teamsClient', 'authBroker',
    'intuneCompanyPortalClient', 'azureAdPowerShell', 'microsoftGraph', 'azureAdGraph'] as const;
  const highValue = ['exchangeOnline', 'sharePointOnline', 'teamsServices', 'azurePortal', 'azureManagement', 'intune',
    'deviceRegistrationService', 'rightsManagement', 'exchangeAdminCenter'] as const;
  const unverified = ['sharePointOnline', 'intune', 'intuneWebCompanyPortal', 'authBroker'] as const;
  for (const [key, id] of Object.entries(APP)) {
    const a = lookupApp(id)!;
    expect(a.targetable, key).toBe(!(nonTargetable as readonly string[]).includes(key));
    expect(a.highValue, key).toBe((highValue as readonly string[]).includes(key));
    expect(a.confidence, key).toBe((unverified as readonly string[]).includes(key) ? 'unverified' : 'verified');
  }
  expect(lookupApp(APP.microsoftGraph)!.notes).toMatch(/Covered only by All resources/);
  expect(lookupApp(APP.azureAdGraph)!.notes).toMatch(/Covered only by All resources/);
});
test('surfaces and groups follow the brief', () => {
  const s = (k: keyof typeof APP) => lookupApp(APP[k])!.surface;
  for (const k of ['exchangeOnline', 'sharePointOnline', 'teamsServices', 'office365Portal', 'protectionCenter'] as const) expect(s(k)).toBe('office365');
  expect(s('azurePortal')).toBe('adminPortals');
  expect(s('exchangeAdminCenter')).toBe('adminPortals');
  expect(s('azureManagement')).toBe('azureManagement');
  for (const k of ['microsoftGraph', 'graphExplorer', 'azureAdGraph'] as const) expect(s(k)).toBe('graph');
  expect(s('intune')).toBe('intuneApi');
  expect(s('azureDevOps')).toBe('azureDevOps');
  expect(s('graphPowerShell')).toBeNull();
  for (const a of APP_CATALOG) {
    expect(a.groups.includes('Office365')).toBe(OFFICE365_KEY_IDS.includes(a.appId as never));
    expect(a.groups.includes('MicrosoftAdminPortals')).toBe(ADMIN_PORTAL_IDS.includes(a.appId as never));
  }
  expect(lookupApp(APP.office365Portal)!.groups).toEqual(['Office365', 'MicrosoftAdminPortals']);
});
test('lookupApp and appLabel are case-insensitive and handle keywords', () => {
  expect(lookupApp(APP.azurePortal.toUpperCase())?.appId).toBe(APP.azurePortal);
  expect(appLabel('All')).toBe('All resources');
  expect(appLabel('none')).toBe('None');
  expect(appLabel('Office365')).toBe('Office 365 (app group)');
  expect(appLabel('microsoftadminportals')).toBe('Microsoft Admin Portals (app group)');
  expect(appLabel('urn:user:registersecurityinfo')).toBe('User action: Register security information');
  expect(appLabel('urn:user:registerdevice')).toBe('User action: Register or join devices');
  expect(appLabel(APP.azureDevOps)).toBe('Azure DevOps');
  expect(appLabel('11111111-1111-1111-1111-111111111111')).toBe('Unknown app (11111111-1111-1111-1111-111111111111)');
});
test('phish resistant edge cases', () => {
  expect(isPhishResistant(null)).toBe(false);
  expect(isPhishResistant({ id: 'custom', allowedCombinations: [] })).toBe(false);
  expect(isPhishResistant({ id: 'custom', allowedCombinations: ['fido2', 'password,microsoftAuthenticatorPush'] })).toBe(false);
  expect(isPhishResistant({ id: 'custom', allowedCombinations: ['windowsHelloForBusiness', 'x509CertificateMultiFactor'] })).toBe(true);
  expect(isPhishResistant({ id: AUTH_STRENGTH.passwordless })).toBe(false);
});
test('surface and control ordering, licenses', () => {
  expect(SURFACES.map(s => s.id)).toEqual(['allResources', 'office365', 'adminPortals', 'azureManagement', 'graph', 'intuneApi',
    'azureDevOps', 'thirdParty', 'registerSecurityInfo', 'registerDevice']);
  for (const s of SURFACES) expect(s.description.length).toBeGreaterThan(0);
  expect(CONTROLS.map(c => c.id)).toEqual(['legacyBlocked', 'mfa', 'phishResistant', 'managedDevice', 'deviceCodeBlocked',
    'signInRisk', 'userRisk', 'session']);
  const byId = Object.fromEntries(CONTROLS.map(c => [c.id, c]));
  expect(byId.managedDevice.license).toBe('intune');
  expect(byId.signInRisk.license).toBe('entraP2');
  expect(byId.userRisk.license).toBe('entraP2');
  expect(byId.mfa.license).toBeUndefined();
});
test('isNA matrix', () => {
  const all = CONTROLS.map(c => c.id);
  expect(all.filter(c => !isNA('registerDevice', c))).toEqual(['mfa', 'phishResistant']);
  expect(all.filter(c => !isNA('registerSecurityInfo', c))).toEqual(['mfa', 'phishResistant', 'managedDevice']);
  for (const s of SURFACES.filter(s => !s.id.startsWith('register'))) for (const c of all) expect(isNA(s.id, c)).toBe(false);
});
