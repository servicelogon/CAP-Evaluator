import { APP, KEYWORD } from '../../catalog/apps';
import { PRIVILEGED_ROLES } from '../../catalog/roles';
import type { CAPolicy, TenantProfile } from '../../model/types';
import { pol, tenant } from '../testUtils';
import { appRules } from './apps';

const T = tenant();
const REPORT_ONLY = 'enabledForReportingButNotEnforced' as const;
const ROLES = PRIVILEGED_ROLES.map(r => r.id);

function rule(id: string) {
  const r = appRules.find(x => x.id === id);
  if (!r) throw new Error(`missing rule ${id}`);
  return r;
}
const run = (id: string, policies: CAPolicy[], t: TenantProfile = T) => rule(id).run({ policies, tenant: t });

function single(id: string, policies: CAPolicy[], t: TenantProfile = T) {
  const fs = run(id, policies, t);
  expect(fs).toHaveLength(1);
  expect(fs[0].ruleId).toBe(id);
  return fs[0];
}

type Grant = NonNullable<Parameters<typeof pol>[0]['grantControls']>;
const MFA: Grant = { builtInControls: ['mfa'] };
const COMPLIANT: Grant = { builtInControls: ['compliantDevice'] };

const appsPolicy = (o: {
  include?: string[]; exclude?: string[]; grant?: Grant | null; state?: CAPolicy['state']; flows?: string[];
} = {}) => pol({
  state: o.state ?? 'enabled',
  conditions: {
    applications: { includeApplications: o.include ?? ['All'], excludeApplications: o.exclude ?? [] },
    ...(o.flows ? { authenticationFlows: { transferMethods: o.flows } } : {}),
  },
  grantControls: o.grant === undefined ? MFA : o.grant,
});
const rolePolicy = (apps: string[], grant: Grant = MFA) => pol({
  conditions: { users: { includeUsers: [], includeRoles: ROLES }, applications: { includeApplications: apps } },
  grantControls: grant,
});

test('exports eight app rules in order', () => {
  expect(appRules.map(r => r.id)).toEqual(['APP-01', 'APP-02', 'APP-03', 'APP-04', 'APP-05', 'APP-06', 'APP-07', 'APP-08']);
  expect(appRules.every(r => r.family === 'apps')).toBe(true);
});

describe('APP-01 All resources with app exclusions', () => {
  test('fires on All excluding Windows Store for Business, listing the app and the baseline-scopes note', () => {
    const p = appsPolicy({ exclude: [APP.storeForBusiness], grant: COMPLIANT });
    const f = single('APP-01', [p]);
    expect([f.severity, f.status, f.policyIds]).toEqual(['medium', 'gap', [p.id]]);
    expect(f.explanation).toContain('Windows Store for Business');
    expect(f.explanation).toContain('aka.ms/BaselineScopesSettingsUX');
    expect(f.explanation).toContain('User.Read');
  });

  test('one finding per policy, including report-only policies', () => {
    const a = appsPolicy({ exclude: [APP.storeForBusiness] });
    const b = appsPolicy({ exclude: [APP.rightsManagement], state: REPORT_ONLY });
    expect(run('APP-01', [a, b]).map(f => f.policyIds)).toEqual([[a.id], [b.id]]);
  });

  test('silent on All with no exclusions', () => expect(run('APP-01', [appsPolicy()])).toEqual([]));
  test('ignores disabled policies', () =>
    expect(run('APP-01', [appsPolicy({ exclude: [APP.storeForBusiness], state: 'disabled' })])).toEqual([]));
  test('ignores exclusions on selected-app policies', () =>
    expect(run('APP-01', [appsPolicy({ include: [KEYWORD.office365], exclude: [APP.sharePointOnline] })])).toEqual([]));
});

describe('APP-02 high-value app excluded', () => {
  test('fires on excluding Office365', () => {
    const p = appsPolicy({ exclude: [KEYWORD.office365] });
    const f = single('APP-02', [p]);
    expect([f.severity, f.status, f.policyIds]).toEqual(['high', 'gap', [p.id]]);
    expect(f.explanation).toContain('Office 365 (app group)');
  });

  test('lists every high-value exclusion and ignores low-value ones', () => {
    const f = single('APP-02', [appsPolicy({ exclude: [KEYWORD.adminPortals, APP.azureManagement, APP.storeForBusiness] })]);
    expect(f.explanation).toContain('Microsoft Admin Portals (app group)');
    expect(f.explanation).toContain('Windows Azure Service Management API');
    expect(f.explanation).not.toContain('Windows Store for Business');
  });

  test('accepts Device Registration Service excluded from a device code flow policy', () =>
    expect(run('APP-02', [appsPolicy({
      exclude: [APP.deviceRegistrationService], flows: ['deviceCodeFlow'], grant: { builtInControls: ['block'] },
    })])).toEqual([]));

  test('fires on Device Registration Service excluded from a policy without authentication flows', () =>
    expect(single('APP-02', [appsPolicy({ exclude: [APP.deviceRegistrationService] })]).explanation).toContain('Device Registration Service'));

  test('explains the Rights Management Services exclusion and recommends cross-tenant MFA trust', () => {
    const f = single('APP-02', [appsPolicy({ exclude: [APP.rightsManagement] })]);
    expect(f.explanation).toContain('encrypted');
    expect(f.explanation).toContain('MFA trust');
  });

  test('flags community-sourced app IDs in the label', () =>
    expect(single('APP-02', [appsPolicy({ exclude: [APP.sharePointOnline] })]).explanation)
      .toContain('Office 365 SharePoint Online (app ID from community sources)'));

  test('silent when only low-value apps are excluded', () =>
    expect(run('APP-02', [appsPolicy({ exclude: [APP.storeForBusiness] })])).toEqual([]));
});

describe('APP-03 unnecessary Intune exclusions on compliant-device policies', () => {
  test('fires on a compliant-device policy excluding Intune Enrollment', () => {
    const p = appsPolicy({ exclude: [APP.intuneEnrollment], grant: COMPLIANT });
    const f = single('APP-03', [p]);
    expect([f.severity, f.status, f.policyIds]).toEqual(['low', 'gap', [p.id]]);
    expect(f.explanation).toContain('Microsoft Intune Enrollment');
  });

  test('silent when the policy also requires terms of use', () =>
    expect(run('APP-03', [appsPolicy({
      exclude: [APP.intuneEnrollment], grant: { builtInControls: ['compliantDevice'], termsOfUse: ['tou-1'] },
    })])).toEqual([]));

  test('terms of use does not excuse a Web Company Portal exclusion', () => {
    const f = single('APP-03', [appsPolicy({
      exclude: [APP.intuneEnrollment, APP.intuneWebCompanyPortal], grant: { builtInControls: ['compliantDevice'], termsOfUse: ['tou-1'] },
    })]);
    expect(f.explanation).toContain('Microsoft Intune Web Company Portal');
    expect(f.explanation).not.toContain('Microsoft Intune Enrollment');
  });

  test('silent on an MFA policy excluding Intune', () =>
    expect(run('APP-03', [appsPolicy({ exclude: [APP.intune] })])).toEqual([]));
});

describe('APP-04 single Microsoft 365 workload targeted', () => {
  test('fires on a SharePoint-only policy', () => {
    const p = appsPolicy({ include: [APP.sharePointOnline] });
    const f = single('APP-04', [p]);
    expect([f.severity, f.status, f.policyIds]).toEqual(['low', 'gap', [p.id]]);
    expect(f.explanation).toContain('Office 365 SharePoint Online');
    expect(f.explanation).toContain('Teams');
  });

  test('silent when the policy also targets Office365', () =>
    expect(run('APP-04', [appsPolicy({ include: [KEYWORD.office365, APP.sharePointOnline] })])).toEqual([]));
  test('silent on All resources', () => expect(run('APP-04', [appsPolicy()])).toEqual([]));
  test('silent on a token protection policy, which Microsoft requires to target the workloads individually', () => {
    const p = pol({
      conditions: { applications: { includeApplications: [APP.exchangeOnline, APP.sharePointOnline, APP.teamsServices] } },
      sessionControls: { secureSignInSession: { isEnabled: true } },
    });
    expect(run('APP-04', [p])).toEqual([]);
  });
  test('still fires on a token protection policy that also targets other individual apps', () => {
    const p = pol({
      conditions: { applications: { includeApplications: [APP.exchangeOnline, APP.sharePointOnline, APP.azureDevOps] } },
      sessionControls: { secureSignInSession: { isEnabled: true } },
    });
    expect(single('APP-04', [p]).policyIds).toEqual([p.id]);
  });
  test('still fires when token protection is present but disabled', () => {
    const p = pol({
      conditions: { applications: { includeApplications: [APP.sharePointOnline] } },
      sessionControls: { secureSignInSession: { isEnabled: false } },
    });
    expect(single('APP-04', [p]).policyIds).toEqual([p.id]);
  });
});

describe('APP-05 non-targetable client app in a policy', () => {
  test('fires on a policy including Graph PowerShell, with the catalog note', () => {
    const p = appsPolicy({ include: [APP.graphPowerShell] });
    const f = single('APP-05', [p]);
    expect([f.severity, f.status, f.policyIds]).toEqual(['medium', 'gap', [p.id]]);
    expect(f.explanation).toContain('Microsoft Graph Command Line Tools');
    expect(f.explanation).toContain('only covered by All resources');
  });

  test('fires on excluded client apps too', () =>
    expect(single('APP-05', [appsPolicy({ exclude: [APP.azureCli, APP.teamsClient] })]).explanation).toContain('Azure CLI'));

  test('status unverified when every flagged app is community-sourced', () => {
    const f = single('APP-05', [appsPolicy({ include: [APP.authBroker] })]);
    expect(f.status).toBe('unverified');
    expect(f.explanation).toContain('Microsoft Authentication Broker (app ID from community sources)');
  });

  test('status stays gap when verified and unverified apps are mixed', () =>
    expect(single('APP-05', [appsPolicy({ include: [APP.authBroker, APP.graphPowerShell] })]).status).toBe('gap'));

  test('fires on disabled policies too', () =>
    expect(run('APP-05', [appsPolicy({ include: [APP.azurePowerShell], state: 'disabled' })])).toHaveLength(1));

  test('silent on targetable apps', () =>
    expect(run('APP-05', [appsPolicy({ include: [APP.azureManagement], exclude: [] })])).toEqual([]));
});

describe('APP-06 Microsoft Graph unprotected', () => {
  test('gap when only a Microsoft Admin Portals MFA policy exists', () => {
    const f = single('APP-06', [rolePolicy([KEYWORD.adminPortals])]);
    expect([f.severity, f.status]).toEqual(['high', 'gap']);
    expect(f.explanation).toContain('all users');
    expect(f.explanation).toContain('administrators');
  });

  test('silent with an All users / All resources MFA policy', () => expect(run('APP-06', [appsPolicy()])).toEqual([]));

  test('partial when the All resources policy has exclusions', () => {
    const p = appsPolicy({ exclude: [APP.storeForBusiness] });
    const f = single('APP-06', [p]);
    expect([f.status, f.policyIds]).toEqual(['partial', [p.id]]);
  });

  test('names only the population that is not fully covered', () => {
    const f = single('APP-06', [rolePolicy(['All'])]);
    expect(f.status).toBe('partial');
    expect(f.explanation).toContain('all users: only partly covered');
    expect(f.explanation).not.toContain('administrators:');
  });
});

describe('APP-07 Azure management and Azure DevOps', () => {
  test('gap with no policies', () => {
    const f = single('APP-07', []);
    expect([f.severity, f.status]).toEqual(['high', 'gap']);
  });

  test('Azure DevOps sub-finding when only Azure management is targeted', () => {
    const f = single('APP-07', [appsPolicy({ include: [APP.azureManagement] })]);
    expect([f.severity, f.status]).toEqual(['medium', 'gap']);
    expect(f.explanation).toContain('Azure DevOps');
    expect(f.explanation).toContain('September 2025');
  });

  test('Azure DevOps sub-finding says Azure management is only partially protected', () => {
    const p = pol({
      conditions: { applications: { includeApplications: [APP.azureManagement] }, locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } },
      grantControls: MFA,
    });
    const devOps = run('APP-07', [p]).find(f => f.severity === 'medium');
    expect(devOps?.explanation).toContain('Azure management is only partially protected');
    expect(devOps?.explanation).not.toContain('Azure management is protected');
  });

  test('Azure DevOps sub-finding says Azure management is report-only', () => {
    const devOps = run('APP-07', [appsPolicy({ include: [APP.azureManagement], state: REPORT_ONLY })]).find(f => f.severity === 'medium');
    expect(devOps?.explanation).toContain('Azure management is only covered by report-only MFA policies');
  });

  test('primary finding is partial when Azure management MFA has a location exclusion', () => {
    const p = pol({
      conditions: { locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } }, grantControls: MFA,
    });
    const f = single('APP-07', [p]);
    expect([f.severity, f.status, f.policyIds]).toEqual(['high', 'partial', [p.id]]);
  });

  test('primary finding is partial when Azure management MFA is report-only', () => {
    const fs = run('APP-07', [appsPolicy({ state: REPORT_ONLY })]);
    expect(fs.map(f => [f.severity, f.status])).toEqual([['high', 'partial']]);
  });

  test('silent with an All users / All resources MFA policy', () => expect(run('APP-07', [appsPolicy()])).toEqual([]));

  test('silent when Azure management and Azure DevOps are both targeted', () =>
    expect(run('APP-07', [appsPolicy({ include: [APP.azureManagement, APP.azureDevOps] })])).toEqual([]));
});

describe('APP-08 Office365 assumed to cover admin surfaces', () => {
  test('fires on a 14-role Office365 MFA policy', () => {
    const p = rolePolicy([KEYWORD.office365]);
    const f = single('APP-08', [p]);
    expect([f.severity, f.policyIds]).toEqual(['info', [p.id]]);
    expect(f.explanation).toContain('Azure portal');
    expect(f.explanation).toContain('Exchange admin center');
    expect(f.explanation).toContain('Microsoft Graph');
  });

  test('silent on an All users Office365 policy', () => expect(run('APP-08', [appsPolicy({ include: [KEYWORD.office365] })])).toEqual([]));
  test('silent on an admin policy on All resources', () => expect(run('APP-08', [rolePolicy(['All'])])).toEqual([]));
});
