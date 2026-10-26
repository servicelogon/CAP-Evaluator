import { APP, KEYWORD } from '../../catalog/apps';
import { AUTH_STRENGTH } from '../../catalog/authStrengths';
import { GLOBAL_ADMIN, PRIVILEGED_ROLES } from '../../catalog/roles';
import type { CAPolicy, TenantProfile } from '../../model/types';
import { pol, tenant } from '../testUtils';
import { weakeningRules } from './weakening';

const T = tenant();
const BG = tenant({ breakGlass: ['bg-1'] });
const REPORT_ONLY = 'enabledForReportingButNotEnforced' as const;
const ROLES = PRIVILEGED_ROLES.map(r => r.id);

function rule(id: string) {
  const r = weakeningRules.find(x => x.id === id);
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
const BLOCK: Grant = { builtInControls: ['block'] };
const COMPLIANT: Grant = { builtInControls: ['compliantDevice'] };
const PHISH: Grant = { builtInControls: [], authenticationStrength: { id: AUTH_STRENGTH.phishingResistant } };

const withGrant = (grantControls: Grant | null, o: Parameters<typeof pol>[0] = {}) => pol({ ...o, grantControls });

test('exports twelve weakening rules in order', () => {
  expect(weakeningRules.map(r => r.id)).toEqual([
    'WEK-01', 'WEK-02', 'WEK-03', 'WEK-04', 'WEK-05', 'WEK-06', 'WEK-07', 'WEK-08', 'WEK-09', 'WEK-10', 'WEK-11', 'WEK-12',
  ]);
  expect(weakeningRules.every(r => r.family === 'weakening')).toBe(true);
});

describe('WEK-01 exclusions beyond break-glass on baseline policies', () => {
  test('critical for an All users / All resources MFA policy excluding a group, listing it', () => {
    const p = withGrant(MFA, { conditions: { users: { excludeGroups: ['g1'] } } });
    const f = single('WEK-01', [p], tenant({ displayNames: { g1: 'Contractors' } }));
    expect([f.severity, f.status, f.policyIds]).toEqual(['critical', 'gap', [p.id]]);
    expect(f.explanation).toContain('Contractors');
  });

  test('critical for a legacy-auth block and for a phishing-resistant admin policy', () => {
    const legacy = withGrant(BLOCK, { conditions: { clientAppTypes: ['exchangeActiveSync', 'other'], users: { excludeUsers: ['u1'] } } });
    const admins = withGrant(PHISH, { conditions: { users: { includeUsers: [], includeRoles: ROLES, excludeGroups: ['g1'] } } });
    expect(run('WEK-01', [legacy, admins]).map(f => f.severity)).toEqual(['critical', 'critical']);
  });

  test('high for other baseline policies, such as compliant device or admin portals MFA, including report-only', () => {
    const device = withGrant(COMPLIANT, { conditions: { users: { excludeGroups: ['g1'] } } });
    const portals = withGrant(MFA, {
      state: REPORT_ONLY,
      conditions: { users: { includeUsers: [], includeRoles: ROLES, excludeRoles: [GLOBAL_ADMIN] }, applications: { includeApplications: [KEYWORD.adminPortals] } },
    });
    const fs = run('WEK-01', [device, portals]);
    expect(fs.map(f => [f.severity, f.policyIds[0]])).toEqual([['high', device.id], ['high', portals.id]]);
    expect(fs[1].explanation).toContain('Global Administrator');
  });

  test('flags excluded guests', () => {
    const p = withGrant(MFA, { conditions: { users: { excludeUsers: ['GuestsOrExternalUsers'] } } });
    expect(single('WEK-01', [p]).explanation).toContain('Guests or external users');
  });

  test('does not fire when only break-glass is excluded, for disabled policies, or for non-baseline policies', () => {
    const bgOnly = withGrant(MFA, { conditions: { users: { excludeUsers: ['bg-1'] } } });
    const disabled = withGrant(MFA, { state: 'disabled', conditions: { users: { excludeGroups: ['g1'] } } });
    const groupScoped = withGrant(MFA, { conditions: { users: { includeUsers: [], includeGroups: ['staff'], excludeGroups: ['g1'] } } });
    const sessionOnly = pol({ conditions: { users: { excludeGroups: ['g1'] } }, sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 4 } } });
    const sharepoint = withGrant(MFA, { conditions: { users: { excludeGroups: ['g1'] }, applications: { includeApplications: [APP.sharePointOnline] } } });
    expect(run('WEK-01', [bgOnly, disabled, groupScoped, sessionOnly, sharepoint], BG)).toEqual([]);
  });
});

describe('WEK-02 break-glass not excluded', () => {
  test('fires for an All users MFA policy that does not exclude the break-glass account', () => {
    const p = withGrant(MFA);
    const f = single('WEK-02', [p], tenant({ breakGlass: ['bg-1'], displayNames: { 'bg-1': 'Emergency 1' } }));
    expect([f.severity, f.status, f.policyIds]).toEqual(['medium', 'gap', [p.id]]);
    expect(f.explanation).toContain('Emergency 1');
  });

  test('fires for a block policy covering all privileged roles and lists only the missing accounts', () => {
    const p = withGrant(BLOCK, { conditions: { users: { includeUsers: [], includeRoles: ROLES, excludeUsers: ['BG-1'] } } });
    const f = single('WEK-02', [p], tenant({ breakGlass: ['bg-1', 'bg-2'] }));
    expect(f.explanation).toContain('bg-2');
    expect(f.explanation).not.toContain('bg-1');
  });

  test('does not fire when excluded by user or group, or for report-only, risk-scoped, flow-scoped or legacy-only policies', () => {
    const t = tenant({ breakGlass: ['bg-1', 'bg-grp'] });
    const excluded = withGrant(MFA, { conditions: { users: { excludeUsers: ['BG-1'], excludeGroups: ['bg-grp'] } } });
    const reportOnly = withGrant(MFA, { state: REPORT_ONLY });
    const risk = withGrant(MFA, { conditions: { signInRiskLevels: ['high'] } });
    const flow = withGrant(BLOCK, { conditions: { authenticationFlows: { transferMethods: ['deviceCodeFlow'] } } });
    const legacy = withGrant(BLOCK, { conditions: { clientAppTypes: ['exchangeActiveSync', 'other'] } });
    const sessionOnly = pol({ sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 4 } } });
    const groupScoped = withGrant(MFA, { conditions: { users: { includeUsers: [], includeGroups: ['staff'] } } });
    expect(run('WEK-02', [excluded, reportOnly, risk, flow, legacy, sessionOnly, groupScoped], t)).toEqual([]);
  });

  test('single info finding when no break-glass accounts are configured', () => {
    const f = single('WEK-02', [withGrant(MFA)]);
    expect([f.severity, f.status]).toEqual(['info', 'gap']);
    expect(f.title).toBe('No break-glass accounts configured in tenant setup');
    expect(f.explanation).toMatch(/cannot tell/);
  });
});

describe('WEK-03 privileged roles excluded', () => {
  test('fires for a policy excluding Global Administrator', () => {
    const p = withGrant(MFA, { conditions: { users: { excludeRoles: [GLOBAL_ADMIN] } } });
    const f = single('WEK-03', [p]);
    expect([f.severity, f.policyIds]).toEqual(['high', [p.id]]);
    expect(f.explanation).toContain('Global Administrator');
  });

  test('does not fire for block policies, non-privileged roles or disabled policies', () => {
    const block = withGrant(BLOCK, { conditions: { users: { excludeRoles: [GLOBAL_ADMIN] } } });
    const other = withGrant(MFA, { conditions: { users: { excludeRoles: ['88d8e3e3-8f55-4a1e-953a-9b9898b8876b'] } } });
    const disabled = withGrant(MFA, { state: 'disabled', conditions: { users: { excludeRoles: [GLOBAL_ADMIN] } } });
    expect(run('WEK-03', [block, other, disabled])).toEqual([]);
  });
});

describe('WEK-04 trusted location bypasses MFA', () => {
  test('fires for MFA excluding All trusted locations, mentioning MFA trusted IPs', () => {
    const p = withGrant(MFA, { conditions: { locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } } });
    const f = single('WEK-04', [p]);
    expect([f.severity, f.policyIds]).toEqual(['high', [p.id]]);
    expect(f.explanation).toContain('All trusted locations');
    expect(f.explanation).toMatch(/trusted IPs/);
  });

  test('fires for phishing-resistant MFA that only includes a named location', () => {
    const p = withGrant(PHISH, { conditions: { locations: { includeLocations: ['loc-1'], excludeLocations: [] } } });
    expect(single('WEK-04', [p], tenant({ displayNames: { 'loc-1': 'Outside EU' } })).explanation).toContain('Outside EU');
  });

  test('does not fire for block policies, all locations, or non-MFA grants', () => {
    const block = withGrant(BLOCK, { conditions: { locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } } });
    const all = withGrant(MFA, { conditions: { locations: { includeLocations: ['All'], excludeLocations: [] } } });
    const device = withGrant(COMPLIANT, { conditions: { locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } } });
    expect(run('WEK-04', [block, all, device, withGrant(MFA)])).toEqual([]);
  });
});

describe('WEK-05 OR grant mixes MFA with weaker controls', () => {
  test('high for All users / All resources mfa OR compliant device, naming the weakest option', () => {
    const p = withGrant({ operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] });
    const f = single('WEK-05', [p]);
    expect([f.severity, f.policyIds]).toEqual(['high', [p.id]]);
    expect(f.explanation).toContain('MFA OR compliant device');
    expect(f.explanation).toMatch(/weakest.*compliant device/);
  });

  test('high when the policy may cover admins on selected apps; medium for specific non-admin users, also when risk-scoped', () => {
    const grant: Grant = { operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] };
    const apps = { includeApplications: [APP.azureManagement] };
    const allUsers = withGrant(grant, { conditions: { applications: apps } });
    const admins = withGrant(grant, { conditions: { users: { includeUsers: [], includeRoles: [GLOBAL_ADMIN] }, applications: apps } });
    const group = withGrant(grant, { conditions: { users: { includeUsers: [], includeGroups: ['g1'] }, applications: apps } });
    const users = withGrant(grant, { conditions: { users: { includeUsers: ['u1', 'u2'] }, applications: apps } });
    const risk = withGrant(grant, { conditions: { users: { includeUsers: ['u1'] }, applications: apps, signInRiskLevels: ['high'] } });
    expect(run('WEK-05', [allUsers, admins, group, users, risk]).map(f => f.severity))
      .toEqual(['high', 'high', 'high', 'medium', 'medium']);
  });

  test('does not fire for OR of device controls, AND of mfa and device, or a single control', () => {
    const devices = withGrant({ operator: 'OR', builtInControls: ['compliantDevice', 'domainJoinedDevice'] });
    const and = withGrant({ operator: 'AND', builtInControls: ['mfa', 'compliantDevice'] });
    const single1 = withGrant({ operator: 'OR', builtInControls: ['mfa'] });
    expect(run('WEK-05', [devices, and, single1])).toEqual([]);
  });
});

describe('WEK-06 platform condition relaxes MFA or device requirement', () => {
  test('fires for MFA excluding a platform and for compliant device including only some platforms', () => {
    const ex = withGrant(MFA, { conditions: { platforms: { includePlatforms: ['all'], excludePlatforms: ['linux'] } } });
    const inc = withGrant(COMPLIANT, { conditions: { platforms: { includePlatforms: ['windows', 'macOS'], excludePlatforms: [] } } });
    const fs = run('WEK-06', [ex, inc]);
    expect(fs.map(f => [f.severity, f.policyIds[0]])).toEqual([['medium', ex.id], ['medium', inc.id]]);
    expect(fs[0].explanation).toContain('linux');
    expect(fs[0].explanation).toMatch(/user agent/);
  });

  test('does not fire for block policies or all platforms', () => {
    const block = withGrant(BLOCK, { conditions: { platforms: { includePlatforms: ['all'], excludePlatforms: ['windows', 'iOS'] } } });
    const all = withGrant(MFA, { conditions: { platforms: { includePlatforms: ['all'], excludePlatforms: [] } } });
    expect(run('WEK-06', [block, all])).toEqual([]);
  });
});

describe('WEK-07 include device filter with positive operators', () => {
  test('fires for include + device.isCompliant -eq True on an MFA policy', () => {
    const p = withGrant(MFA, { conditions: { devices: { deviceFilter: { mode: 'include', rule: 'device.isCompliant -eq True' } } } });
    const f = single('WEK-07', [p]);
    expect([f.severity, f.policyIds]).toEqual(['medium', [p.id]]);
    expect(f.explanation).toMatch(/unregistered/i);
  });

  test('matches operators case-insensitively and with several positive clauses', () => {
    const p = withGrant(MFA, { conditions: { devices: { deviceFilter: { mode: 'include', rule: 'device.trustType -EQ "AzureAD" -or device.model -startsWith "Surface"' } } } });
    expect(run('WEK-07', [p])).toHaveLength(1);
  });

  test('does not fire for exclude + -eq, include + negative operator, block policies or no grant', () => {
    const exclude = withGrant(MFA, { conditions: { devices: { deviceFilter: { mode: 'exclude', rule: 'device.isCompliant -eq True' } } } });
    const negative = withGrant(MFA, { conditions: { devices: { deviceFilter: { mode: 'include', rule: 'device.trustType -ne "ServerAD" -and device.model -eq "x"' } } } });
    const block = withGrant(BLOCK, { conditions: { devices: { deviceFilter: { mode: 'include', rule: 'device.isCompliant -eq True' } } } });
    const session = pol({ conditions: { devices: { deviceFilter: { mode: 'include', rule: 'device.isCompliant -eq True' } } }, sessionControls: { signInFrequency: { isEnabled: true } } });
    expect(run('WEK-07', [exclude, negative, block, session])).toEqual([]);
  });
});

describe('WEK-08 persistent browser', () => {
  const always = { persistentBrowser: { isEnabled: true, mode: 'always' as const } };

  test('fires for persistent browser always with no device restriction', () => {
    const p = pol({ sessionControls: always });
    const f = single('WEK-08', [p]);
    expect([f.severity, f.policyIds]).toEqual(['medium', [p.id]]);
    expect(f.explanation).toMatch(/unmanaged/);
  });

  test('fires for persistent browser never on a policy without All resources', () => {
    const p = pol({ conditions: { applications: { includeApplications: [KEYWORD.office365] } }, sessionControls: { persistentBrowser: { isEnabled: true, mode: 'never' } } });
    expect(single('WEK-08', [p]).explanation).toMatch(/All resources/);
  });

  test('does not fire when restricted to managed devices or for never on All resources', () => {
    const filter = pol({ conditions: { devices: { deviceFilter: { mode: 'include', rule: 'device.isCompliant -eq True' } } }, sessionControls: always });
    const compliant = withGrant(COMPLIANT, { sessionControls: always });
    const never = pol({ sessionControls: { persistentBrowser: { isEnabled: true, mode: 'never' } } });
    expect(run('WEK-08', [filter, compliant, never])).toEqual([]);
  });

  test('still fires when the device filter also matches unregistered devices', () => {
    const p = pol({ conditions: { devices: { deviceFilter: { mode: 'exclude', rule: 'device.isCompliant -eq True' } } }, sessionControls: always });
    expect(run('WEK-08', [p])).toHaveLength(1);
  });
});

describe('WEK-09 approved client app', () => {
  test('high when it is the only control, explaining the retirement discrepancy', () => {
    const p = withGrant({ builtInControls: ['approvedApplication'] });
    const f = single('WEK-09', [p]);
    expect([f.severity, f.status, f.policyIds]).toEqual(['high', 'gap', [p.id]]);
    expect(f.explanation).toContain('June 30, 2026');
    expect(f.explanation).toContain('MC1220751');
    expect(f.explanation).toMatch(/read-only/);
    expect(f.remediation).toMatch(/app protection policy/);
  });

  test('medium when combined with another control', () => {
    const p = withGrant({ operator: 'OR', builtInControls: ['approvedApplication', 'compliantApplication'] });
    expect(single('WEK-09', [p]).severity).toBe('medium');
  });

  test('does not fire without approvedApplication', () => {
    expect(run('WEK-09', [withGrant({ builtInControls: ['compliantApplication'] })])).toEqual([]);
  });
});

describe('WEK-10 custom controls', () => {
  test('fires when custom controls are used', () => {
    const p = withGrant({ builtInControls: [], customAuthenticationFactors: ['duo'] });
    const f = single('WEK-10', [p]);
    expect([f.severity, f.policyIds]).toEqual(['medium', [p.id]]);
    expect(f.explanation).toMatch(/do not satisfy/);
  });

  test('does not fire without custom controls', () => {
    expect(run('WEK-10', [withGrant(MFA)])).toEqual([]);
  });
});

describe('WEK-11 resilience defaults disabled broadly', () => {
  test('fires for an All users policy', () => {
    const p = withGrant(MFA, { conditions: { applications: { includeApplications: [APP.sharePointOnline] } }, sessionControls: { disableResilienceDefaults: true } });
    const f = single('WEK-11', [p]);
    expect([f.severity, f.policyIds]).toEqual(['low', [p.id]]);
  });

  test('does not fire for a narrow policy or when not disabled', () => {
    const narrow = withGrant(MFA, {
      conditions: { users: { includeUsers: [], includeGroups: ['g1'] }, applications: { includeApplications: [APP.sharePointOnline] } },
      sessionControls: { disableResilienceDefaults: true },
    });
    const off = withGrant(MFA, { sessionControls: { disableResilienceDefaults: false } });
    expect(run('WEK-11', [narrow, off])).toEqual([]);
  });
});

describe('WEK-12 continuous access evaluation disabled', () => {
  test('fires when CAE is disabled', () => {
    const p = pol({ sessionControls: { continuousAccessEvaluation: { mode: 'disabled' } } });
    const f = single('WEK-12', [p]);
    expect([f.severity, f.policyIds]).toEqual(['low', [p.id]]);
  });

  test('does not fire for strict enforcement', () => {
    expect(run('WEK-12', [pol({ sessionControls: { continuousAccessEvaluation: { mode: 'strictEnforcement' } } })])).toEqual([]);
  });
});
