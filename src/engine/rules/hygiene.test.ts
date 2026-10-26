import { USER_ACTION } from '../../catalog/apps';
import type { CAPolicy, TenantProfile } from '../../model/types';
import { pol, tenant } from '../testUtils';
import { hygieneRules } from './hygiene';
import { ALL_RULES } from './index';
import { reportOnlySummary } from './reportOnly';
import type { Rule, RuleContext } from './types';

const T = tenant();
const REPORT_ONLY = 'enabledForReportingButNotEnforced' as const;

function rule(id: string) {
  const r = hygieneRules.find(x => x.id === id);
  if (!r) throw new Error(`missing rule ${id}`);
  return r;
}
const run = (id: string, policies: CAPolicy[], t: TenantProfile = T) => rule(id).run({ policies, tenant: t });

type Grant = NonNullable<Parameters<typeof pol>[0]['grantControls']>;
const MFA: Grant = { builtInControls: ['mfa'] };
const BLOCK: Grant = { builtInControls: ['block'] };

test('exports HYG-02 and HYG-03; HYG-01 is not a rule', () => {
  expect(hygieneRules.map(r => r.id)).toEqual(['HYG-02', 'HYG-03']);
  expect(hygieneRules.every(r => r.family === 'hygiene')).toBe(true);
});

describe('ALL_RULES', () => {
  test('ids are unique', () => {
    const ids = ALL_RULES.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test('contains every family in order and no HYG-01', () => {
    expect([...new Set(ALL_RULES.map(r => r.family))]).toEqual(['baseline', 'admin', 'apps', 'weakening', 'risk', 'hygiene']);
    expect(ALL_RULES.map(r => r.id)).not.toContain('HYG-01');
    expect(ALL_RULES).toHaveLength(11 + 8 + 8 + 12 + 6 + 2);
  });
});

describe('HYG-02 disabled policies', () => {
  test('medium for a disabled Microsoft-managed policy, low for other disabled policies', () => {
    const managed = pol({ state: 'disabled', displayName: 'Microsoft-managed: Block legacy authentication', grantControls: BLOCK });
    const other = pol({ state: 'disabled', displayName: 'Old MFA', grantControls: MFA });
    const fs = run('HYG-02', [managed, other]);
    expect(fs.map(f => [f.ruleId, f.severity, f.status, f.policyIds])).toEqual([
      ['HYG-02', 'medium', 'gap', [managed.id]],
      ['HYG-02', 'low', 'gap', [other.id]],
    ]);
    expect(fs[0].explanation).toContain('Microsoft-managed: Block legacy authentication');
  });

  test('no finding for enabled or report-only policies', () => {
    expect(run('HYG-02', [pol({ grantControls: MFA }), pol({ state: REPORT_ONLY, grantControls: MFA })])).toEqual([]);
  });
});

describe('HYG-03 policies with no effect', () => {
  test('fires on an active policy with no grant or session controls', () => {
    const p = pol({ displayName: 'Empty' });
    const fs = run('HYG-03', [p]);
    expect(fs.map(f => [f.ruleId, f.severity, f.policyIds])).toEqual([['HYG-03', 'low', [p.id]]]);
    expect(fs[0].explanation).toMatch(/no grant or session controls/);
  });

  test('fires when users are None with nothing else, or resources are None or empty with no user actions', () => {
    const noUsers = pol({ conditions: { users: { includeUsers: ['None'] } }, grantControls: MFA });
    const noApps = pol({ conditions: { applications: { includeApplications: ['None'] } }, grantControls: MFA });
    const emptyApps = pol({ conditions: { applications: { includeApplications: [] } }, grantControls: MFA });
    expect(run('HYG-03', [noUsers, noApps, emptyApps]).map(f => f.policyIds[0])).toEqual([noUsers.id, noApps.id, emptyApps.id]);
  });

  test('no finding for a normal MFA policy, a session-only policy, a user-action policy or a workload identity policy', () => {
    const session = pol({ sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 4 } } });
    const userAction = pol({
      conditions: { applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerSecurityInfo] } }, grantControls: MFA,
    });
    const authContext = pol({
      conditions: { applications: { includeApplications: [], includeAuthenticationContextClassReferences: ['c1'] } }, grantControls: MFA,
    });
    const workload = pol({
      conditions: { users: { includeUsers: ['None'] }, clientApplications: { includeServicePrincipals: ['ServicePrincipalsInMyTenant'] } },
      grantControls: BLOCK,
    });
    const roles = pol({ conditions: { users: { includeUsers: ['None'], includeRoles: ['r1'] } }, grantControls: MFA });
    expect(run('HYG-03', [pol({ grantControls: MFA }), session, userAction, authContext, workload, roles])).toEqual([]);
  });

  test('ignores disabled policies', () => {
    expect(run('HYG-03', [pol({ state: 'disabled' })])).toEqual([]);
  });
});

describe('HYG-01 report-only summary', () => {
  const analyze = (policies: CAPolicy[], t: TenantProfile = T) => {
    const ctx: RuleContext = { policies, tenant: t };
    return { ctx, findings: ALL_RULES.flatMap(r => r.run(ctx)) };
  };

  test('one high finding naming report-only policies that would close critical/high gaps and the rules they improve', () => {
    const mfa = pol({ state: REPORT_ONLY, displayName: 'MFA for everyone', grantControls: MFA });
    const harmless = pol({
      state: REPORT_ONLY, displayName: 'SIF for one user', conditions: { users: { includeUsers: ['u1'] } },
      sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 4 } },
    });
    const { ctx, findings } = analyze([mfa, harmless]);
    const fs = reportOnlySummary(ctx, findings);
    expect(fs).toHaveLength(1);
    const f = fs[0];
    expect([f.ruleId, f.family, f.severity, f.policyIds]).toEqual(['HYG-01', 'hygiene', 'high', [mfa.id]]);
    expect(f.explanation).toContain('MFA for everyone');
    expect(f.explanation).toContain('BAS-03');
    expect(f.explanation).not.toContain('SIF for one user');
    expect(f.explanation).toMatch(/user action/i);
  });

  test('no finding without report-only policies, or when enabling them closes nothing', () => {
    const enforced = analyze([pol({ grantControls: MFA })]);
    expect(reportOnlySummary(enforced.ctx, enforced.findings)).toEqual([]);
    const harmless = analyze([pol({
      state: REPORT_ONLY, conditions: { users: { includeUsers: ['u1'] } },
      sessionControls: { signInFrequency: { isEnabled: true, type: 'hours', value: 4 } },
    })]);
    expect(reportOnlySummary(harmless.ctx, harmless.findings)).toEqual([]);
  });

  test('uses the given rules and only counts critical/high gap or partial findings', () => {
    const p = pol({ state: REPORT_ONLY, grantControls: MFA });
    const mk = (id: string, severity: 'critical' | 'medium', status: 'partial' | 'requiresLicense'): Rule => ({
      id, family: 'baseline',
      run: ctx => (ctx.policies.some(x => x.state === 'enabled') ? [] : [{
        ruleId: id, title: id, family: 'baseline', severity, status, policyIds: [], explanation: '', remediation: '', references: [],
      }]),
    });
    const ctx: RuleContext = { policies: [p], tenant: T };
    const counted = [mk('A', 'critical', 'partial')];
    expect(reportOnlySummary(ctx, counted.flatMap(r => r.run(ctx)), counted)[0].explanation).toContain(`"${p.displayName}" (A)`);
    const ignored = [mk('B', 'medium', 'partial'), mk('C', 'critical', 'requiresLicense')];
    expect(reportOnlySummary(ctx, ignored.flatMap(r => r.run(ctx)), ignored)).toEqual([]);
  });
});
