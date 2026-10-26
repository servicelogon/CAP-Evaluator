import { PRIVILEGED_ROLES } from '../../catalog/roles';
import type { CAPolicy, TenantProfile } from '../../model/types';
import { pol, tenant } from '../testUtils';
import { riskRules } from './risk';
import { makeFinding, type RuleMeta } from './types';

const T = tenant();
const P2 = tenant({ licenses: { entraP2: true } });
const REPORT_ONLY = 'enabledForReportingButNotEnforced' as const;
const ROLES = PRIVILEGED_ROLES.map(r => r.id);

function rule(id: string) {
  const r = riskRules.find(x => x.id === id);
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

test('exports six risk rules in order', () => {
  expect(riskRules.map(r => r.id)).toEqual(['RSK-01', 'RSK-02', 'RSK-03', 'RSK-04', 'RSK-05', 'RSK-06']);
  expect(riskRules.every(r => r.family === 'risk')).toBe(true);
});

describe('makeFinding with several required licenses', () => {
  const meta: RuleMeta = {
    id: 'X', title: 'x', family: 'risk', severity: 'low', remediation: 'r', references: [], requiredLicense: ['entraP2', 'purviewInsiderRisk'],
  };
  test('requiresLicense when any one is missing, with labels joined by " + "', () => {
    for (const t of [T, P2, tenant({ licenses: { purviewInsiderRisk: true } })]) {
      const f = makeFinding(meta, { policies: [], tenant: t }, { explanation: 'x' });
      expect(f.status).toBe('requiresLicense');
      expect(f.requiredLicense).toBe('Microsoft Entra ID P2 + Microsoft Purview Insider Risk Management (Adaptive Protection)');
    }
  });
  test('own status when all are owned', () => {
    const t = tenant({ licenses: { entraP2: true, purviewInsiderRisk: true } });
    expect(makeFinding(meta, { policies: [], tenant: t }, { explanation: 'x', status: 'partial' }).status).toBe('partial');
  });
});

describe('RSK-01 sign-in risk', () => {
  test('requiresLicense without P2', () => {
    const f = single('RSK-01', []);
    expect([f.status, f.severity, f.requiredLicense]).toEqual(['requiresLicense', 'high', 'Microsoft Entra ID P2']);
  });

  test('gap with P2 and no sign-in risk policy', () => {
    expect(single('RSK-01', [pol({ grantControls: MFA })], P2).status).toBe('gap');
  });

  test('no finding with P2 and an All users / All resources MFA policy on high and medium sign-in risk', () => {
    expect(run('RSK-01', [pol({ conditions: { signInRiskLevels: ['high', 'medium'] }, grantControls: MFA })], P2)).toEqual([]);
  });

  test('partial when only medium risk is covered', () => {
    expect(single('RSK-01', [pol({ conditions: { signInRiskLevels: ['medium'] }, grantControls: MFA })], P2).status).toBe('partial');
  });
});

describe('RSK-02 user risk', () => {
  test('gap with P2 when a high user risk policy only requires MFA', () => {
    const f = single('RSK-02', [pol({ conditions: { userRiskLevels: ['high'] }, grantControls: MFA })], P2);
    expect([f.status, f.severity]).toEqual(['gap', 'high']);
  });

  test('no finding for high user risk with MFA AND password change', () => {
    const p = pol({ conditions: { userRiskLevels: ['high'] }, grantControls: { operator: 'AND', builtInControls: ['mfa', 'passwordChange'] } });
    expect(run('RSK-02', [p], P2)).toEqual([]);
  });

  test('requiresLicense without P2', () => {
    expect(single('RSK-02', []).status).toBe('requiresLicense');
  });
});

describe('RSK-03 workload identities', () => {
  const WID = tenant({ licenses: { workloadIdPremium: true } });
  const spPolicy = (state: CAPolicy['state'] = 'enabled', grant: Grant = BLOCK) => pol({
    state,
    conditions: {
      users: { includeUsers: ['None'] },
      clientApplications: { includeServicePrincipals: ['ServicePrincipalsInMyTenant'] },
      locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] },
    },
    grantControls: grant,
  });

  test('gap with explanation about single-tenant service principals and Block only', () => {
    const f = single('RSK-03', [pol({ grantControls: MFA })], WID);
    expect([f.status, f.severity, f.requiredLicense]).toEqual(['gap', 'medium', 'Microsoft Entra Workload ID Premium']);
    expect(f.explanation).toMatch(/single-tenant/);
    expect(f.explanation).toMatch(/managed identities/);
    expect(f.explanation).toMatch(/Block/);
  });

  test('no finding with a block policy on ServicePrincipalsInMyTenant', () => {
    expect(run('RSK-03', [spPolicy()], WID)).toEqual([]);
  });

  test('partial when the block policy is report-only; requiresLicense without the license', () => {
    expect(single('RSK-03', [spPolicy(REPORT_ONLY)], WID).status).toBe('partial');
    expect(single('RSK-03', []).status).toBe('requiresLicense');
  });
});

describe('RSK-04 insider risk', () => {
  const BOTH = tenant({ licenses: { entraP2: true, purviewInsiderRisk: true } });
  const insider = (level: string, grant: Grant = BLOCK) => pol({ conditions: { insiderRiskLevels: [level] }, grantControls: grant });

  test('gap with both licenses and no insider risk block; requiresLicense when either is missing', () => {
    const f = single('RSK-04', [], BOTH);
    expect([f.status, f.severity]).toEqual(['gap', 'low']);
    expect(single('RSK-04', [], P2).status).toBe('requiresLicense');
    expect(single('RSK-04', [], tenant({ licenses: { purviewInsiderRisk: true } })).status).toBe('requiresLicense');
  });

  test('no finding with a block policy on elevated insider risk', () => {
    expect(run('RSK-04', [insider('elevated')], BOTH)).toEqual([]);
  });

  test('still a gap when only moderate risk is blocked or elevated only requires MFA', () => {
    expect(single('RSK-04', [insider('moderate'), insider('elevated', MFA)], BOTH).status).toBe('gap');
  });
});

describe('RSK-05 token protection for admins', () => {
  const tokenProtection = (users: Parameters<typeof pol>[0]['conditions'] = {}, state: CAPolicy['state'] = 'enabled') => pol({
    state,
    conditions: { ...users, platforms: { includePlatforms: ['windows'] }, clientAppTypes: ['mobileAppsAndDesktopClients'] },
    sessionControls: { secureSignInSession: { isEnabled: true } },
  });

  test('gap without any token protection policy', () => {
    const f = single('RSK-05', [pol({ grantControls: MFA })]);
    expect([f.status, f.severity, f.requiredLicense]).toEqual(['gap', 'low', 'Microsoft Entra ID P1']);
  });

  test('no finding with token protection on a policy for privileged roles or All users', () => {
    expect(run('RSK-05', [tokenProtection({ users: { includeUsers: [], includeRoles: ROLES } })])).toEqual([]);
    expect(run('RSK-05', [tokenProtection()])).toEqual([]);
  });

  test('gap when token protection only covers non-admin users; partial when report-only', () => {
    expect(single('RSK-05', [tokenProtection({ users: { includeUsers: ['u1'] } })]).status).toBe('gap');
    expect(single('RSK-05', [tokenProtection({}, REPORT_ONLY)]).status).toBe('partial');
  });
});

describe('RSK-06 agent identities', () => {
  test('one unverified info finding by default', () => {
    const f = single('RSK-06', [pol({ grantControls: MFA })]);
    expect([f.status, f.severity, f.requiredLicense]).toEqual(['unverified', 'info', undefined]);
    expect(f.explanation).toMatch(/All users/);
  });

  test('suppressed by a policy for AllAgentIdUsers or agent identity service principals', () => {
    expect(run('RSK-06', [pol({ conditions: { users: { includeUsers: ['AllAgentIdUsers'] } }, grantControls: BLOCK })])).toEqual([]);
    const agents = pol({
      conditions: { users: { includeUsers: ['None'] }, clientApplications: { includeAgentIdServicePrincipals: ['All'] } }, grantControls: BLOCK,
    });
    expect(run('RSK-06', [agents])).toEqual([]);
  });

  test('a disabled agent policy does not suppress it', () => {
    const p = pol({ state: 'disabled', conditions: { users: { includeUsers: ['AllAgentIdUsers'] } }, grantControls: BLOCK });
    expect(run('RSK-06', [p])).toHaveLength(1);
  });
});
