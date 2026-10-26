import { USER_ACTION } from '../../catalog/apps';
import { AUTH_STRENGTH } from '../../catalog/authStrengths';
import type { CAPolicy, TenantProfile } from '../../model/types';
import { pol, tenant } from '../testUtils';
import { baselineRules } from './baseline';
import { LICENSE_LABEL, coverageRule, makeFinding, type RuleMeta } from './types';

const T = tenant();
const REPORT_ONLY = 'enabledForReportingButNotEnforced' as const;

function rule(id: string) {
  const r = baselineRules.find(x => x.id === id);
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

const legacyBlock = (o: Partial<CAPolicy> = {}) =>
  pol({ ...o, conditions: { clientAppTypes: ['exchangeActiveSync', 'other'] }, grantControls: { builtInControls: ['block'] } });
const mfaAll = () => pol({ grantControls: { builtInControls: ['mfa'] } });
const userAction = (action: string, grant: { builtInControls?: string[] } = { builtInControls: ['mfa'] }) =>
  pol({ conditions: { applications: { includeApplications: [], includeUserActions: [action] } }, grantControls: grant });
const sifPolicy = (state: CAPolicy['state'] = 'enabled') => pol({
  state,
  conditions: { devices: { deviceFilter: { mode: 'include', rule: 'device.isCompliant -ne True -or device.trustType -ne "ServerAD"' } } },
  sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 1 }, persistentBrowser: { isEnabled: true, mode: 'never' } },
});
const platformBlock = (state: CAPolicy['state'] = 'enabled') => pol({
  state,
  conditions: { platforms: { includePlatforms: ['all'], excludePlatforms: ['windows', 'iOS', 'android', 'macOS'] } },
  grantControls: { builtInControls: ['block'] },
});

describe('rule framework', () => {
  const meta: RuleMeta = {
    id: 'TST-01', title: 'Test rule', family: 'baseline', severity: 'high',
    remediation: 'Do the thing.', references: ['https://example.test'], requiredLicense: 'entraP2',
  };

  test('LICENSE_LABEL names every license', () => {
    expect(LICENSE_LABEL).toEqual({
      entraP1: 'Microsoft Entra ID P1', entraP2: 'Microsoft Entra ID P2', intune: 'Microsoft Intune',
      workloadIdPremium: 'Microsoft Entra Workload ID Premium', defenderForCloudApps: 'Microsoft Defender for Cloud Apps',
      purviewInsiderRisk: 'Microsoft Purview Insider Risk Management (Adaptive Protection)',
    });
  });

  test('makeFinding defaults to gap and copies meta', () => {
    const f = makeFinding(meta, { policies: [], tenant: tenant({ licenses: { entraP2: true } }) }, { explanation: 'x' });
    expect(f).toEqual({
      ruleId: 'TST-01', title: 'Test rule', family: 'baseline', severity: 'high', status: 'gap', policyIds: [],
      explanation: 'x', remediation: 'Do the thing.', references: ['https://example.test'], requiredLicense: 'Microsoft Entra ID P2',
    });
  });

  test('makeFinding marks requiresLicense when the license is missing', () => {
    const f = makeFinding(meta, { policies: [], tenant: T }, { explanation: 'x', status: 'partial', severity: 'low', policyIds: ['a'] });
    expect([f.status, f.severity, f.policyIds, f.requiredLicense]).toEqual(['requiresLicense', 'low', ['a'], 'Microsoft Entra ID P2']);
  });

  test('makeFinding without requiredLicense omits the label', () => {
    const { requiredLicense: _, ...noLicense } = meta;
    expect(makeFinding(noLicense, { policies: [], tenant: T }, { explanation: 'x' }).requiredLicense).toBeUndefined();
  });

  test('coverageRule maps levels to findings', () => {
    const r = coverageRule({ ...meta, requiredLicense: undefined }, 'allUsers', 'allResources', 'mfa', c => `level ${c.level}.`);
    expect(r.id).toBe('TST-01');
    expect(r.family).toBe('baseline');
    expect(r.run({ policies: [mfaAll()], tenant: T })).toEqual([]);
    const none = r.run({ policies: [], tenant: T });
    expect([none[0].status, none[0].explanation]).toEqual(['gap', 'level none.']);
    const p = pol({ displayName: 'MFA minus g1', conditions: { users: { excludeGroups: ['g1'] } }, grantControls: { builtInControls: ['mfa'] } });
    const part = r.run({ policies: [p], tenant: T })[0];
    expect(part.status).toBe('partial');
    expect(part.policyIds).toEqual([p.id]);
    expect(part.explanation).toContain('MFA minus g1');
    expect(part.explanation).toContain('excludes g1');
    const ro = pol({ displayName: 'RO MFA', state: REPORT_ONLY, grantControls: { builtInControls: ['mfa'] } });
    const rof = r.run({ policies: [ro], tenant: T })[0];
    expect(rof.status).toBe('partial');
    expect(rof.explanation).toContain('report-only');
    expect(rof.explanation).toContain('RO MFA');
  });
});

describe('baseline rules', () => {
  test('exports BAS-01..11 in order, all baseline family', () => {
    expect(baselineRules.map(r => r.id)).toEqual(Array.from({ length: 11 }, (_, i) => `BAS-${String(i + 1).padStart(2, '0')}`));
    expect(baselineRules.every(r => r.family === 'baseline')).toBe(true);
  });

  test('every finding has title, remediation, Learn references and a severity', () => {
    for (const r of baselineRules) {
      for (const f of r.run({ policies: [], tenant: T })) {
        expect(f.title.length).toBeGreaterThan(10);
        expect(f.remediation.length).toBeGreaterThan(20);
        expect(f.references.length).toBeGreaterThan(0);
        expect(f.references.every(u => u.startsWith('https://learn.microsoft.com/'))).toBe(true);
      }
    }
  });

  describe('BAS-01 legacy authentication', () => {
    test('fails with no policies', () => {
      const f = single('BAS-01', []);
      expect([f.status, f.severity]).toEqual(['gap', 'critical']);
      expect(f.explanation).toContain('Legacy protocols cannot perform MFA');
    });
    test('passes with an enforced legacy block', () => expect(run('BAS-01', [legacyBlock()])).toEqual([]));
    test('report-only block is partial', () => {
      const p = legacyBlock({ state: REPORT_ONLY, displayName: 'Block legacy auth' });
      const f = single('BAS-01', [p]);
      expect(f.status).toBe('partial');
      expect(f.explanation).toContain('report-only');
      expect(f.explanation).toContain('Block legacy auth');
      expect(f.policyIds).toEqual([p.id]);
    });
    test('block of other only is partial', () => {
      const f = single('BAS-01', [pol({ conditions: { clientAppTypes: ['other'] }, grantControls: { builtInControls: ['block'] } })]);
      expect(f.status).toBe('partial');
      expect(f.explanation).toContain('Exchange ActiveSync');
    });
  });

  describe('BAS-02 Exchange ActiveSync omitted', () => {
    test('fails when the block covers other only', () => {
      const p = pol({ displayName: 'Legacy block', conditions: { clientAppTypes: ['other'] }, grantControls: { builtInControls: ['block'] } });
      const f = single('BAS-02', [p]);
      expect([f.status, f.severity, f.policyIds]).toEqual(['gap', 'high', [p.id]]);
      expect(f.explanation).toContain('Legacy block');
    });
    test('passes when EAS is included', () => expect(run('BAS-02', [legacyBlock()])).toEqual([]));
    test('ignores disabled policies', () =>
      expect(run('BAS-02', [pol({ state: 'disabled', conditions: { clientAppTypes: ['other'] }, grantControls: { builtInControls: ['block'] } })])).toEqual([]));
  });

  describe('BAS-03 MFA baseline', () => {
    test('fails with no policies', () => expect([single('BAS-03', []).status, single('BAS-03', []).severity]).toEqual(['gap', 'critical']));
    test('passes with All users MFA', () => expect(run('BAS-03', [mfaAll()])).toEqual([]));
    test('group exclusion is partial', () => {
      const f = single('BAS-03', [pol({ conditions: { users: { excludeGroups: ['g1'] } }, grantControls: { builtInControls: ['mfa'] } })]);
      expect(f.status).toBe('partial');
      expect(f.explanation).toContain('g1');
    });
  });

  describe('BAS-04 device code flow', () => {
    test('fails with no policies', () => expect([single('BAS-04', []).status, single('BAS-04', []).severity]).toEqual(['gap', 'high']));
    test('passes with a device code block', () => expect(run('BAS-04', [pol({
      conditions: { authenticationFlows: { transferMethods: ['deviceCodeFlow'] } }, grantControls: { builtInControls: ['block'] },
    })])).toEqual([]));
  });

  describe('BAS-05 authentication transfer', () => {
    const transferBlock = (state: CAPolicy['state'] = 'enabled') => pol({
      state, conditions: { authenticationFlows: { transferMethods: ['authenticationTransfer'] } }, grantControls: { builtInControls: ['block'] },
    });
    test('fails with no policies', () => expect([single('BAS-05', []).status, single('BAS-05', []).severity]).toEqual(['gap', 'low']));
    test('passes with an authentication transfer block', () => expect(run('BAS-05', [transferBlock()])).toEqual([]));
    test('report-only only is partial', () => {
      const f = single('BAS-05', [transferBlock(REPORT_ONLY)]);
      expect(f.status).toBe('partial');
      expect(f.explanation).toContain('report-only');
    });
  });

  describe('BAS-06 unknown platforms', () => {
    test('fails with no policies', () => expect([single('BAS-06', []).status, single('BAS-06', []).severity]).toEqual(['gap', 'medium']));
    test('passes with an all-minus-supported platform block', () => expect(run('BAS-06', [platformBlock()])).toEqual([]));
    test('report-only only is partial', () => {
      const p = platformBlock(REPORT_ONLY);
      const f = single('BAS-06', [p]);
      expect([f.status, f.policyIds]).toEqual(['partial', [p.id]]);
      expect(f.explanation).toContain('report-only');
    });
    test('block without platform exclusions does not count', () =>
      expect(run('BAS-06', [pol({ conditions: { platforms: { includePlatforms: ['all'] } }, grantControls: { builtInControls: ['block'] } })])).toHaveLength(1));
  });

  describe('BAS-07 guests MFA', () => {
    test('fails when the MFA baseline excludes guests', () => {
      const f = single('BAS-07', [pol({ conditions: { users: { excludeUsers: ['GuestsOrExternalUsers'] } }, grantControls: { builtInControls: ['mfa'] } })]);
      expect([f.status, f.severity]).toEqual(['gap', 'high']);
    });
    test('passes with All users MFA', () => expect(run('BAS-07', [mfaAll()])).toEqual([]));
  });

  describe('BAS-08 security info registration', () => {
    test('fails with no policies and mentions Windows Hello / Platform SSO', () => {
      const f = single('BAS-08', []);
      expect([f.status, f.severity]).toEqual(['gap', 'high']);
      expect(f.explanation).toContain('July 6, 2026');
      expect(f.explanation).toContain('Windows Hello for Business');
      expect(f.explanation).toContain('Platform SSO');
    });
    test('passes with MFA on the user action', () => expect(run('BAS-08', [userAction(USER_ACTION.registerSecurityInfo)])).toEqual([]));
    test('passes with a managed device on the user action', () =>
      expect(run('BAS-08', [userAction(USER_ACTION.registerSecurityInfo, { builtInControls: ['compliantDevice'] })])).toEqual([]));
    test('passes with an MFA authentication strength', () =>
      expect(run('BAS-08', [pol({
        conditions: { applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerSecurityInfo] } },
        grantControls: { authenticationStrength: { id: AUTH_STRENGTH.mfa } },
      })])).toEqual([]));
    test('All resources MFA does not cover registration', () => expect(run('BAS-08', [mfaAll()])).toHaveLength(1));
    test('report-only is partial', () => {
      const p = pol({ state: REPORT_ONLY, conditions: { applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerSecurityInfo] } }, grantControls: { builtInControls: ['mfa'] } });
      const f = single('BAS-08', [p]);
      expect([f.status, f.policyIds]).toEqual(['partial', [p.id]]);
      expect(f.explanation).toContain('report-only');
    });
    test('excluded group is partial', () => {
      const f = single('BAS-08', [pol({
        conditions: { users: { excludeGroups: ['g1'] }, applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerSecurityInfo] } },
        grantControls: { builtInControls: ['mfa'] },
      })]);
      expect(f.status).toBe('partial');
      expect(f.explanation).toContain('g1');
    });
  });

  describe('BAS-09 device registration', () => {
    test('fails with no policies', () => expect([single('BAS-09', []).status, single('BAS-09', []).severity]).toEqual(['gap', 'medium']));
    test('passes with MFA on the user action', () => expect(run('BAS-09', [userAction(USER_ACTION.registerDevice)])).toEqual([]));
    test('compliant device grant is flagged unsupported', () => {
      const p = userAction(USER_ACTION.registerDevice, { builtInControls: ['compliantDevice'] });
      const unsupported = run('BAS-09', [p]).filter(f => f.explanation.includes('unsupported'));
      expect(unsupported).toHaveLength(1);
      expect(unsupported[0].policyIds).toEqual([p.id]);
      expect(unsupported[0].ruleId).toBe('BAS-09');
    });
    test('location condition is flagged as not enforced', () => {
      const p = pol({
        conditions: { applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerDevice] }, locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } },
        grantControls: { builtInControls: ['mfa'] },
      });
      const unsupported = run('BAS-09', [p]).filter(f => f.explanation.includes('unsupported'));
      expect(unsupported).toHaveLength(1);
      expect(unsupported[0].explanation).toMatch(/location conditions are not enforced/i);
    });
    test('client app types other than all are flagged', () => {
      const p = pol({
        conditions: { clientAppTypes: ['browser'], applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerDevice] } },
        grantControls: { builtInControls: ['mfa'] },
      });
      expect(run('BAS-09', [p]).filter(f => f.explanation.includes('unsupported'))).toHaveLength(1);
    });
    test('device filter is flagged', () => {
      const p = pol({
        conditions: { devices: { deviceFilter: { mode: 'exclude', rule: 'device.isCompliant -eq True' } }, applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerDevice] } },
        grantControls: { builtInControls: ['mfa'] },
      });
      expect(run('BAS-09', [p]).filter(f => f.explanation.includes('unsupported'))).toHaveLength(1);
    });
  });

  describe('BAS-10 managed device', () => {
    test('requires Intune when unlicensed', () => {
      const f = single('BAS-10', [], tenant({ licenses: { intune: false } }));
      expect([f.status, f.severity, f.requiredLicense]).toEqual(['requiresLicense', 'medium', 'Microsoft Intune']);
    });
    test('is a gap when Intune is licensed', () => expect(single('BAS-10', [], tenant({ licenses: { intune: true } })).status).toBe('gap'));
    test('passes with a compliant device requirement', () =>
      expect(run('BAS-10', [pol({ grantControls: { builtInControls: ['compliantDevice'] } })], tenant({ licenses: { intune: true } }))).toEqual([]));
  });

  describe('BAS-11 sign-in frequency for unmanaged devices', () => {
    test('fails with no policies', () => expect([single('BAS-11', []).status, single('BAS-11', []).severity]).toEqual(['gap', 'medium']));
    test('passes with SIF + never persistent on a device filter', () => expect(run('BAS-11', [sifPolicy()])).toEqual([]));
    test('report-only only is partial', () => {
      const f = single('BAS-11', [sifPolicy(REPORT_ONLY)]);
      expect(f.status).toBe('partial');
      expect(f.explanation).toContain('report-only');
    });
    test('SIF without a device filter does not count', () =>
      expect(run('BAS-11', [pol({ sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 1 }, persistentBrowser: { isEnabled: true, mode: 'never' } } })])).toHaveLength(1));
  });
});
