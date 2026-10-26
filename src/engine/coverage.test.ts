import { APP, ADMIN_PORTAL_IDS, USER_ACTION } from '../catalog/apps';
import { AUTH_STRENGTH } from '../catalog/authStrengths';
import { GLOBAL_ADMIN, PRIVILEGED_ROLES } from '../catalog/roles';
import { pol, tenant } from './testUtils';
import {
  coversLegacyClients, coversModernClients, grantAlternatives, isRiskOrFlowScoped, managedDeviceStrength, mfaStrength,
  narrowingReasons, phishStrength,
} from './predicates';
import {
  bestCoverage, controlCoverage, policyContribution, populationCoverage, surfaceCoverage, unexpectedExclusions,
} from './coverage';

const ALL_GUEST_TYPES = ['internalGuest', 'b2bCollaborationGuest', 'b2bCollaborationMember', 'b2bDirectConnectUser', 'otherExternalUser', 'serviceProvider'];
const PHISH = { id: AUTH_STRENGTH.phishingResistant, displayName: 'Phishing-resistant MFA' };

// Brief cases (verbatim)
const t = tenant({ breakGlass: ['bg-1'] });
test('All users with only break-glass exclusion is full', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeUsers: ['bg-1'] } } }), 'allUsers', t).level).toBe('full'));
test('All users excluding a group is partial', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeGroups: ['g1'] } } }), 'allUsers', t).level).toBe('partial'));
test('5 privileged roles is partial for admins', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeRoles: PRIVILEGED_ROLES.slice(0,5).map(r=>r.id) } } }), 'admins', t).level).toBe('partial'));
test('All 14 roles is full for admins', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeRoles: PRIVILEGED_ROLES.map(r=>r.id) } } }), 'admins', t).level).toBe('full'));
test('guest exclusion removes guests', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeUsers: ['GuestsOrExternalUsers'] } } }), 'guests', t).level).toBe('none'));
test('Admin portals policy does not cover graph', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['MicrosoftAdminPortals'] } } }), 'graph').level).toBe('none'));
test('Admin portals policy covers admin portals', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['MicrosoftAdminPortals'] } } }), 'adminPortals').level).toBe('full'));
test('Azure mgmt does not cover DevOps', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: [APP.azureManagement] } } }), 'azureDevOps').level).toBe('none'));
test('All resources does not cover user actions', () => expect(surfaceCoverage(pol({}), 'registerSecurityInfo').level).toBe('none'));
test('All with exclusions makes graph partial', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['All'], excludeApplications: [APP.storeForBusiness] } } }), 'graph').level).toBe('partial'));
test('MFA OR compliant is partial mfa', () => expect(controlCoverage(pol({ grantControls: { operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] } }), 'mfa').level).toBe('partial'));
test('MFA AND compliant is full for both', () => { const p = pol({ grantControls: { operator: 'AND', builtInControls: ['mfa', 'compliantDevice'] } }); expect(controlCoverage(p, 'mfa').level).toBe('full'); expect(controlCoverage(p, 'managedDevice').level).toBe('full'); });
test('risk-scoped MFA is not baseline mfa', () => expect(controlCoverage(pol({ conditions: { signInRiskLevels: ['high'] }, grantControls: { builtInControls: ['mfa'] } }), 'mfa').level).toBe('none'));
test('MFA excluding trusted locations is partial', () => expect(controlCoverage(pol({ conditions: { locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } }, grantControls: { builtInControls: ['mfa'] } }), 'mfa').level).toBe('partial'));
test('legacy block covers legacy', () => expect(controlCoverage(pol({ conditions: { clientAppTypes: ['exchangeActiveSync', 'other'] }, grantControls: { builtInControls: ['block'] } }), 'legacyBlocked').level).toBe('full'));
test('legacy block without EAS is partial', () => expect(controlCoverage(pol({ conditions: { clientAppTypes: ['other'] }, grantControls: { builtInControls: ['block'] } }), 'legacyBlocked').level).toBe('partial'));
test('legacy block does not count as mfa', () => expect(controlCoverage(pol({ conditions: { clientAppTypes: ['exchangeActiveSync', 'other'] }, grantControls: { builtInControls: ['block'] } }), 'mfa').level).toBe('none'));
test('report-only downgrades', () => expect(policyContribution(pol({ state: 'enabledForReportingButNotEnforced', grantControls: { builtInControls: ['mfa'] } }), 'allUsers', 'allResources', 'mfa', t).level).toBe('reportOnly'));
test('best picks full over partial', () => { const ps = [pol({ id: 'a', grantControls: { operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] } }), pol({ id: 'b', grantControls: { builtInControls: ['mfa'] } })]; const r = bestCoverage(ps, 'allUsers', 'allResources', 'mfa', t); expect([r.level, r.policyIds]).toEqual(['full', ['b']]); });

describe('test utils', () => {
  test('pol assigns distinct auto ids and replaces arrays', () => {
    const a = pol({}), b = pol({ conditions: { clientAppTypes: ['other'] } });
    expect([a.id === b.id, b.conditions.clientAppTypes]).toEqual([false, ['other']]);
  });
  test('tenant merges licenses onto defaults', () => expect(tenant({ licenses: { entraP2: true } }).licenses).toMatchObject({ entraP1: true, entraP2: true }));
});

describe('predicates', () => {
  test('coversLegacyClients: all / both / one / none', () => expect([
    coversLegacyClients(pol({})),
    coversLegacyClients(pol({ conditions: { clientAppTypes: ['exchangeActiveSync', 'other'] } })),
    coversLegacyClients(pol({ conditions: { clientAppTypes: ['exchangeActiveSync'] } })),
    coversLegacyClients(pol({ conditions: { clientAppTypes: ['browser', 'mobileAppsAndDesktopClients'] } })),
  ]).toEqual(['full', 'full', 'partial', 'none']));
  test('coversModernClients needs browser and mobile/desktop', () => expect([
    coversModernClients(pol({})),
    coversModernClients(pol({ conditions: { clientAppTypes: ['browser', 'mobileAppsAndDesktopClients'] } })),
    coversModernClients(pol({ conditions: { clientAppTypes: ['browser'] } })),
  ]).toEqual([true, true, false]));
  test('grantAlternatives AND groups everything, OR splits', () => expect([
    grantAlternatives(pol({ grantControls: { operator: 'AND', builtInControls: ['mfa', 'compliantDevice'], termsOfUse: ['tou'] } })),
    grantAlternatives(pol({ grantControls: { operator: 'OR', builtInControls: ['compliantDevice'], authenticationStrength: PHISH } })),
    grantAlternatives(pol({})),
  ]).toEqual([[['mfa', 'compliantDevice', 'termsOfUse']], [['compliantDevice'], ['authStrength']], []]));
  test('auth strength satisfies mfa and phish strength', () => {
    const p = pol({ grantControls: { authenticationStrength: PHISH } });
    expect([mfaStrength(p), phishStrength(p)]).toEqual(['full', 'full']);
  });
  test('MFA auth strength is not phishing resistant', () => expect(phishStrength(pol({ grantControls: { authenticationStrength: { id: AUTH_STRENGTH.mfa } } }))).toBe('none'));
  test('compliant OR hybrid is full managed device', () => expect(managedDeviceStrength(pol({ grantControls: { builtInControls: ['compliantDevice', 'domainJoinedDevice'] } }))).toBe('full'));
  test('strengths are none without controls', () => expect([mfaStrength(pol({})), phishStrength(pol({})), managedDeviceStrength(pol({}))]).toEqual(['none', 'none', 'none']));
  test('device code flow and SP targeting are risk/flow scoped', () => expect([
    isRiskOrFlowScoped(pol({ conditions: { authenticationFlows: { transferMethods: ['deviceCodeFlow'] } } })),
    isRiskOrFlowScoped(pol({ conditions: { clientApplications: { includeServicePrincipals: ['ServicePrincipalsInMyTenant'] } } })),
    isRiskOrFlowScoped(pol({ conditions: { insiderRiskLevels: ['elevated'] } })),
    isRiskOrFlowScoped(pol({})),
  ]).toEqual([true, true, true, false]));
  test('narrowingReasons are readable', () => expect(narrowingReasons(pol({ conditions: {
    locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] },
    platforms: { includePlatforms: ['android', 'iOS'] },
    devices: { deviceFilter: { mode: 'exclude', rule: 'device.isCompliant -eq True' } },
  } }))).toEqual([
    'excludes locations: All trusted locations', 'only includes platforms: android, iOS', 'device filter (exclude: device.isCompliant -eq True)',
  ]));
  test('include all platforms with exclusions is narrowing', () => expect(narrowingReasons(pol({ conditions: { platforms: { includePlatforms: ['all'], excludePlatforms: ['windows'] } } }))).toEqual(['excludes platforms: windows']));
});

describe('populationCoverage', () => {
  test('excluded group reason uses display name', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeGroups: ['g1'] } } }), 'allUsers', tenant({ displayNames: { g1: 'Contractors' } })).reasons).toEqual(['excludes Contractors']));
  test('break-glass match is case-insensitive', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeUsers: ['BG-1'] } } }), 'allUsers', t).level).toBe('full'));
  test('group-scoped policy is partial for all users', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeGroups: ['g1'] } } }), 'allUsers', t)).toEqual({ level: 'partial', reasons: ['scoped to specific groups/users/roles, not All users'] }));
  test('includeUsers None covers nobody', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['None'] } } }), 'allUsers', t).level).toBe('none'));
  test('All users excluding Global Admin is partial for admins', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeRoles: [GLOBAL_ADMIN] } } }), 'admins', t)).toEqual({ level: 'partial', reasons: ['excludes privileged roles: Global Administrator'] }));
  test('14 roles minus an excluded privileged role is partial', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeRoles: PRIVILEGED_ROLES.map(r => r.id), excludeRoles: [GLOBAL_ADMIN] } } }), 'admins', t).level).toBe('partial'));
  test('5 roles reason counts roles', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeRoles: PRIVILEGED_ROLES.slice(0, 5).map(r => r.id) } } }), 'admins', t).reasons).toEqual(['covers 5 of 14 privileged roles']));
  test('admin group is partial for admins', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeGroups: ['admins'] } } }), 'admins', t).reasons).toEqual(['scoped by group; cannot verify it contains all admins']));
  test('specific users only is none for admins', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['u1'] } } }), 'admins', t).level).toBe('none'));
  test('All users covers guests fully', () => expect(populationCoverage(pol({}), 'guests', t).level).toBe('full'));
  test('GuestsOrExternalUsers include is full for guests', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['GuestsOrExternalUsers'] } } }), 'guests', t).level).toBe('full'));
  test('all six guest types in all tenants is full', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeGuestsOrExternalUsers: { guestOrExternalUserTypes: ALL_GUEST_TYPES, externalTenants: { membershipKind: 'all' } } } } }), 'guests', t).level).toBe('full'));
  test('guest type subset is partial', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeGuestsOrExternalUsers: { guestOrExternalUserTypes: ['b2bCollaborationGuest'], externalTenants: { membershipKind: 'all' } } } } }), 'guests', t).level).toBe('partial'));
  test('enumerated tenants is partial', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeGuestsOrExternalUsers: { guestOrExternalUserTypes: ALL_GUEST_TYPES, externalTenants: { membershipKind: 'enumerated', members: ['t1'] } } } } }), 'guests', t).level).toBe('partial'));
  test('excluding a guest subset leaves guests partial', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeGuestsOrExternalUsers: { guestOrExternalUserTypes: ['serviceProvider'], externalTenants: { membershipKind: 'all' } } } } }), 'guests', t).level).toBe('partial'));
  test('excluding all six guest types removes guests', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeGuestsOrExternalUsers: { guestOrExternalUserTypes: ALL_GUEST_TYPES, externalTenants: { membershipKind: 'all' } } } } }), 'guests', t).level).toBe('none'));
  test('employee group does not cover guests', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeGroups: ['employees'] } } }), 'guests', t).level).toBe('none'));
});

describe('unexpectedExclusions', () => {
  test('renders users, groups, roles and guests; skips break-glass', () => expect(unexpectedExclusions(pol({ conditions: { users: {
    includeUsers: ['All'], excludeUsers: ['bg-1', 'u2'], excludeGroups: ['g1'], excludeRoles: [GLOBAL_ADMIN],
    excludeGuestsOrExternalUsers: { guestOrExternalUserTypes: ['serviceProvider', 'otherExternalUser'], externalTenants: { membershipKind: 'all' } },
  } } }), tenant({ breakGlass: ['bg-1'], displayNames: { u2: 'Svc account' } }))).toEqual([
    'Svc account', 'g1', 'Global Administrator', 'Guests or external users (serviceProvider, otherExternalUser)',
  ]));
  test('GuestsOrExternalUsers in excludeUsers renders once without types', () => expect(unexpectedExclusions(pol({ conditions: { users: { includeUsers: ['All'], excludeUsers: ['GuestsOrExternalUsers'] } } }), t)).toEqual(['Guests or external users']));
});

describe('surfaceCoverage', () => {
  test('user action policy covers its action only', () => {
    const p = pol({ conditions: { applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerSecurityInfo] } } });
    expect([surfaceCoverage(p, 'registerSecurityInfo').level, surfaceCoverage(p, 'registerDevice').level, surfaceCoverage(p, 'allResources').level]).toEqual(['full', 'none', 'none']);
  });
  test('auth-context-only policy covers no surface', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: [], includeAuthenticationContextClassReferences: ['c1'] } } }), 'allResources').level).toBe('none'));
  test('All resources with exclusions is partial', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['All'], excludeApplications: [APP.storeForBusiness] } } }), 'allResources')).toEqual({ level: 'partial', reasons: ['excludes 1 app'] }));
  test('selected apps do not cover All resources', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['Office365'] } } }), 'allResources').level).toBe('none'));
  test('Office365 group is full for office365', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['Office365'] } } }), 'office365').level).toBe('full'));
  test('Exchange alone is partial for office365', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: [APP.exchangeOnline] } } }), 'office365')).toEqual({ level: 'partial', reasons: ['targets individual workloads, not the Office 365 group'] }));
  test('All excluding SharePoint is partial for office365', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['All'], excludeApplications: [APP.sharePointOnline] } } }), 'office365').level).toBe('partial'));
  test('All excluding Office365 is none for office365', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['All'], excludeApplications: ['Office365'] } } }), 'office365').level).toBe('none'));
  test('all four portal IDs is full for admin portals', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ADMIN_PORTAL_IDS } } }), 'adminPortals').level).toBe('full'));
  test('Azure portal alone is partial for admin portals', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: [APP.azurePortal] } } }), 'adminPortals')).toEqual({ level: 'partial', reasons: ['covers 1 of 4 admin portals'] }));
  test('All excluding MicrosoftAdminPortals is none for admin portals', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['All'], excludeApplications: ['MicrosoftAdminPortals'] } } }), 'adminPortals').level).toBe('none'));
  test('All excluding Azure management is none for it', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['All'], excludeApplications: [APP.azureManagement] } } }), 'azureManagement').level).toBe('none'));
  test('Azure management app is full for azureManagement', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: [APP.azureManagement] } } }), 'azureManagement').level).toBe('full'));
  test('Graph Explorer alone is partial for graph', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: [APP.graphExplorer] } } }), 'graph').level).toBe('partial'));
  test('Intune app is full for intuneApi; admin portals is not', () => expect([
    surfaceCoverage(pol({ conditions: { applications: { includeApplications: [APP.intune] } } }), 'intuneApi').level,
    surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['MicrosoftAdminPortals'] } } }), 'intuneApi').level,
  ]).toEqual(['full', 'none']));
  test('unknown app is partial third-party; Microsoft app is none', () => expect([
    surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['11111111-2222-3333-4444-555555555555'] } } }), 'thirdParty').level,
    surfaceCoverage(pol({ conditions: { applications: { includeApplications: [APP.exchangeOnline] } } }), 'thirdParty').level,
  ]).toEqual(['partial', 'none']));
  test('non-GUID app names do not count as third-party coverage', () => expect([
    surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['Salesforce'] } } }), 'thirdParty').level,
    surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['All'], excludeApplications: ['Salesforce'] } } }), 'thirdParty').level,
  ]).toEqual(['none', 'full']));
  test('All excluding a third-party app is partial third-party', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['All'], excludeApplications: ['11111111-2222-3333-4444-555555555555'] } } }), 'thirdParty').level).toBe('partial'));
});

describe('controlCoverage', () => {
  test('OR reason lists the alternatives', () => expect(controlCoverage(pol({ grantControls: { operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] } }), 'mfa').reasons).toEqual(['Require one of: MFA OR compliant device']));
  test('block on modern clients is full mfa', () => expect(controlCoverage(pol({ grantControls: { builtInControls: ['block'] } }), 'mfa').level).toBe('full'));
  test('MFA policy on browser only is none', () => expect(controlCoverage(pol({ conditions: { clientAppTypes: ['browser'] }, grantControls: { builtInControls: ['mfa'] } }), 'mfa').level).toBe('none'));
  test('phish-resistant strength is full phishResistant; plain MFA is none', () => expect([
    controlCoverage(pol({ grantControls: { authenticationStrength: PHISH } }), 'phishResistant').level,
    controlCoverage(pol({ grantControls: { builtInControls: ['mfa'] } }), 'phishResistant').level,
  ]).toEqual(['full', 'none']));
  test('MFA policy also blocks legacy (grant on all clients)', () => expect(controlCoverage(pol({ grantControls: { builtInControls: ['mfa'] } }), 'legacyBlocked').level).toBe('full'));
  test('modern-only MFA does not block legacy', () => expect(controlCoverage(pol({ conditions: { clientAppTypes: ['browser', 'mobileAppsAndDesktopClients'] }, grantControls: { builtInControls: ['mfa'] } }), 'legacyBlocked').level).toBe('none'));
  test('legacy block narrowed by location is partial', () => expect(controlCoverage(pol({ conditions: { clientAppTypes: ['exchangeActiveSync', 'other'], locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } }, grantControls: { builtInControls: ['block'] } }), 'legacyBlocked').level).toBe('partial'));
  test('session-only policy does not block legacy', () => expect(controlCoverage(pol({ sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 4 } } }), 'legacyBlocked').level).toBe('none'));
  test('device code block is full deviceCodeBlocked', () => expect(controlCoverage(pol({ conditions: { authenticationFlows: { transferMethods: ['deviceCodeFlow'] } }, grantControls: { builtInControls: ['block'] } }), 'deviceCodeBlocked').level).toBe('full'));
  test('authentication transfer block is not deviceCodeBlocked', () => expect(controlCoverage(pol({ conditions: { authenticationFlows: { transferMethods: ['authenticationTransfer'] } }, grantControls: { builtInControls: ['block'] } }), 'deviceCodeBlocked').level).toBe('none'));
  test('high sign-in risk MFA is full signInRisk', () => expect(controlCoverage(pol({ conditions: { signInRiskLevels: ['high', 'medium'] }, grantControls: { builtInControls: ['mfa'] } }), 'signInRisk').level).toBe('full'));
  test('medium-only sign-in risk is partial', () => expect(controlCoverage(pol({ conditions: { signInRiskLevels: ['medium'] }, grantControls: { builtInControls: ['mfa'] } }), 'signInRisk').level).toBe('partial'));
  test('sign-in risk with no grant is none', () => expect(controlCoverage(pol({ conditions: { signInRiskLevels: ['high'] } }), 'signInRisk').level).toBe('none'));
  test('high user risk with password change AND mfa is full', () => expect(controlCoverage(pol({ conditions: { userRiskLevels: ['high'] }, grantControls: { operator: 'AND', builtInControls: ['mfa', 'passwordChange'] } }), 'userRisk').level).toBe('full'));
  test('high user risk with risk remediation AND auth strength is full', () => expect(controlCoverage(pol({ conditions: { userRiskLevels: ['high'] }, grantControls: { operator: 'AND', builtInControls: ['riskRemediation'], authenticationStrength: { id: AUTH_STRENGTH.mfa } } }), 'userRisk').level).toBe('full'));
  test('high user risk with MFA only is none', () => expect(controlCoverage(pol({ conditions: { userRiskLevels: ['high'] }, grantControls: { builtInControls: ['mfa'] } }), 'userRisk').level).toBe('none'));
  test('high user risk with block and mfa is full (block wins)', () => expect(controlCoverage(pol({ conditions: { userRiskLevels: ['high'] }, grantControls: { operator: 'OR', builtInControls: ['block', 'mfa'] } }), 'userRisk').level).toBe('full'));
  test('high user risk block is full', () => expect(controlCoverage(pol({ conditions: { userRiskLevels: ['high'] }, grantControls: { builtInControls: ['block'] } }), 'userRisk').level).toBe('full'));
  test('SIF + never persistent is full session', () => expect(controlCoverage(pol({ sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 1 }, persistentBrowser: { isEnabled: true, mode: 'never' } } }), 'session').level).toBe('full'));
  test('SIF alone is partial session', () => expect(controlCoverage(pol({ sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 1 } } }), 'session').level).toBe('partial'));
  test('persistent browser always is none', () => expect(controlCoverage(pol({ sessionControls: { persistentBrowser: { isEnabled: true, mode: 'always' } } }), 'session').level).toBe('none'));
  test('session scoped by device filter is partial', () => expect(controlCoverage(pol({ conditions: { devices: { deviceFilter: { mode: 'exclude', rule: 'device.isCompliant -eq True' } } }, sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 1 }, persistentBrowser: { isEnabled: true, mode: 'never' } } }), 'session').level).toBe('partial'));
});

describe('policyContribution and bestCoverage', () => {
  test('disabled policy contributes none', () => expect(policyContribution(pol({ state: 'disabled', grantControls: { builtInControls: ['mfa'] } }), 'allUsers', 'allResources', 'mfa', t).level).toBe('none'));
  test('takes the minimum of population, surface and control with merged reasons', () => expect(policyContribution(pol({ conditions: { users: { includeUsers: [], includeGroups: ['g1'] } }, grantControls: { builtInControls: ['mfa', 'compliantDevice'] } }), 'allUsers', 'allResources', 'mfa', t)).toEqual({
    level: 'partial', reasons: ['scoped to specific groups/users/roles, not All users', 'Require one of: MFA OR compliant device'],
  }));
  test('report-only adds a reason', () => expect(policyContribution(pol({ state: 'enabledForReportingButNotEnforced', grantControls: { builtInControls: ['mfa'] } }), 'allUsers', 'allResources', 'mfa', t).reasons).toEqual(['report-only (not enforced)']));
  test('report-only partial stays reportOnly, not partial', () => expect(policyContribution(pol({ state: 'enabledForReportingButNotEnforced', grantControls: { builtInControls: ['mfa', 'compliantDevice'] } }), 'allUsers', 'allResources', 'mfa', t).level).toBe('reportOnly'));
  test('partial beats reportOnly', () => expect(bestCoverage([pol({ id: 'ro', state: 'enabledForReportingButNotEnforced', grantControls: { builtInControls: ['mfa'] } }), pol({ id: 'pa', grantControls: { builtInControls: ['mfa', 'compliantDevice'] } })], 'allUsers', 'allResources', 'mfa', t).policyIds).toEqual(['pa']));
  test('returns all policies tied at the best level', () => expect(bestCoverage([pol({ id: 'x', grantControls: { builtInControls: ['mfa'] } }), pol({ id: 'y', grantControls: { builtInControls: ['mfa'] } })], 'allUsers', 'allResources', 'mfa', t).policyIds).toEqual(['x', 'y']));
  test('no coverage gives none with empty ids and reasons', () => expect(bestCoverage([pol({ grantControls: { builtInControls: ['compliantDevice'] } })], 'allUsers', 'allResources', 'mfa', t)).toEqual({ level: 'none', reasons: [], policyIds: [] }));
  test('partial reasons from tied policies are de-duplicated', () => expect(bestCoverage([pol({ grantControls: { builtInControls: ['mfa', 'compliantDevice'] } }), pol({ grantControls: { builtInControls: ['mfa', 'compliantDevice'] } })], 'allUsers', 'allResources', 'mfa', t).reasons).toEqual(['Require one of: MFA OR compliant device']));
});
