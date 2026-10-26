import { APP, USER_ACTION } from '../catalog/apps';
import type { CAPolicy, Finding } from '../model/types';
import { buildManualChecks } from './manualChecks';
import { pol, tenant } from './testUtils';

const T = tenant();
type Grant = NonNullable<Parameters<typeof pol>[0]['grantControls']>;
const MFA: Grant = { builtInControls: ['mfa'] };

const finding = (ruleId: string): Finding => ({
  ruleId, title: ruleId, family: 'admin', severity: 'high', status: 'gap', policyIds: [], explanation: '', remediation: '', references: [],
});
const ids = (policies: CAPolicy[], findings: Finding[] = []) => buildManualChecks({ policies, tenant: T }, findings).map(c => c.id);

test('a plain policy set only gets the always-on checks: security defaults and Azure Government', () => {
  expect(ids([pol({ grantControls: MFA })])).toEqual(['MC-08', 'MC-10']);
  expect(ids([])).toEqual(['MC-08', 'MC-10']);
});

test('all ten checks, in spec order, have a title, why, where and related rules', () => {
  const p = pol({
    conditions: {
      users: { includeGroups: ['g1'] },
      applications: { includeApplications: [APP.exchangeOnline], includeAuthenticationContextClassReferences: ['c1'] },
      locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] },
    },
    grantControls: MFA,
  });
  const device = pol({ conditions: { applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerDevice] } }, grantControls: MFA });
  const checks = buildManualChecks({ policies: [p, device], tenant: T }, [finding('ADM-05'), finding('APP-01')]);
  expect(checks.map(c => c.id)).toEqual(['MC-01', 'MC-02', 'MC-03', 'MC-04', 'MC-05', 'MC-06', 'MC-07', 'MC-08', 'MC-09', 'MC-10']);
  for (const c of checks) {
    expect(c.title.length).toBeGreaterThan(0);
    expect(c.why.length).toBeGreaterThan(20);
    expect(c.where.length).toBeGreaterThan(10);
    expect(Array.isArray(c.relatedRuleIds)).toBe(true);
  }
  expect(checks.find(c => c.id === 'MC-05')?.where).toContain('https://aka.ms/BaselineScopesSettingsUX');
});

describe('device registration MFA setting (MC-06)', () => {
  const registerDevice = (state: CAPolicy['state'] = 'enabled') => pol({
    state, conditions: { applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerDevice] } }, grantControls: MFA,
  });

  test('present when an active policy protects device registration, with the device settings path', () => {
    const c = buildManualChecks({ policies: [registerDevice()], tenant: T }, []).find(x => x.id === 'MC-06');
    expect(c?.where).toContain('Device settings');
    expect(c?.where).toContain('Require Multifactor Authentication to register or join devices');
    expect(c?.relatedRuleIds).toContain('BAS-09');
  });

  test('absent without a register-device policy or when that policy is disabled', () => {
    expect(ids([pol({ grantControls: MFA })])).not.toContain('MC-06');
    expect(ids([registerDevice('disabled')])).not.toContain('MC-06');
  });
});

test('group checks follow include and exclude groups', () => {
  expect(ids([pol({ conditions: { users: { excludeGroups: ['g1'] } }, grantControls: MFA })])).toEqual(['MC-01', 'MC-08', 'MC-10']);
  expect(ids([pol({ conditions: { users: { includeGroups: ['g1'] } }, grantControls: MFA })])).toEqual(['MC-01', 'MC-04', 'MC-08', 'MC-10']);
});

test('PIM and baseline scopes checks follow ADM-05 and APP-01 findings', () => {
  expect(ids([], [finding('ADM-05')])).toEqual(['MC-02', 'MC-08', 'MC-10']);
  expect(ids([], [finding('APP-01')])).toEqual(['MC-05', 'MC-08', 'MC-10']);
});

test('service principal existence check follows specific app IDs, not keywords', () => {
  expect(ids([pol({ conditions: { applications: { includeApplications: ['Office365'] } }, grantControls: MFA })])).not.toContain('MC-03');
  expect(ids([pol({ conditions: { applications: { excludeApplications: [APP.intuneEnrollment] } }, grantControls: MFA })])).toContain('MC-03');
});

test('trusted IPs check follows All trusted locations; auth contexts check follows authentication context targets', () => {
  expect(ids([pol({ conditions: { locations: { includeLocations: ['AllTrusted'] } }, grantControls: MFA })])).toContain('MC-07');
  expect(ids([pol({ conditions: { locations: { includeLocations: ['All'], excludeLocations: ['loc1'] } }, grantControls: MFA })])).not.toContain('MC-07');
  expect(ids([pol({
    conditions: { applications: { includeApplications: [], includeAuthenticationContextClassReferences: ['c2'] } }, grantControls: MFA,
  })])).toContain('MC-09');
});
