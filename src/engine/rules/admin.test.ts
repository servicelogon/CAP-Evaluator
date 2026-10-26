import { ADMIN_PORTAL_IDS, APP, KEYWORD } from '../../catalog/apps';
import { AUTH_STRENGTH } from '../../catalog/authStrengths';
import { GLOBAL_ADMIN, PRIVILEGED_ROLES } from '../../catalog/roles';
import type { CAPolicy, TenantProfile } from '../../model/types';
import { pol, tenant } from '../testUtils';
import { adminRules } from './admin';

const T = tenant();
const REPORT_ONLY = 'enabledForReportingButNotEnforced' as const;
const ROLES = PRIVILEGED_ROLES.map(r => r.id);

function rule(id: string) {
  const r = adminRules.find(x => x.id === id);
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
const PHISH: Grant = { authenticationStrength: { id: AUTH_STRENGTH.phishingResistant } };
const MFA: Grant = { builtInControls: ['mfa'] };

const rolePolicy = (o: {
  roles?: string[]; apps?: string[]; grant?: Grant | null; state?: CAPolicy['state']; groups?: string[];
  excludeRoles?: string[]; session?: Parameters<typeof pol>[0]['sessionControls'];
} = {}) => pol({
  state: o.state ?? 'enabled',
  conditions: {
    users: { includeUsers: [], includeRoles: o.roles ?? ROLES, includeGroups: o.groups ?? [], excludeRoles: o.excludeRoles ?? [] },
    applications: { includeApplications: o.apps ?? ['All'] },
  },
  grantControls: o.grant === undefined ? PHISH : o.grant,
  ...(o.session ? { sessionControls: o.session } : {}),
});
const mfaAll = (state: CAPolicy['state'] = 'enabled') => pol({ state, grantControls: MFA });

test('exports eight admin rules in order', () => {
  expect(adminRules.map(r => r.id)).toEqual(['ADM-01', 'ADM-02', 'ADM-03', 'ADM-04', 'ADM-05', 'ADM-06', 'ADM-07', 'ADM-08']);
  expect(adminRules.every(r => r.family === 'admin')).toBe(true);
});

describe('ADM-01 phishing-resistant MFA for privileged roles', () => {
  test('passes with an enforced 14-role phishing-resistant policy on all resources', () => {
    expect(run('ADM-01', [rolePolicy()])).toEqual([]);
  });

  test('passes with an All users phishing-resistant policy', () => {
    expect(run('ADM-01', [pol({ grantControls: PHISH })])).toEqual([]);
  });

  test('lists missing roles when Global Administrator is not included', () => {
    const p = rolePolicy({ roles: ROLES.filter(r => r !== GLOBAL_ADMIN) });
    const f = single('ADM-01', [p]);
    expect(f.status).toBe('gap');
    expect(f.severity).toBe('critical');
    expect(f.explanation).toContain('Global Administrator');
    expect(f.explanation).not.toContain('Security Administrator');
    expect(f.explanation).toMatch(/FIDO2/);
    expect(f.remediation).toContain('Require phishing-resistant multifactor authentication for administrators');
    expect(f.requiredLicense).toBe('Microsoft Entra ID P1');
  });

  test('treats an excluded role as missing', () => {
    const f = single('ADM-01', [pol({ conditions: { users: { excludeRoles: [GLOBAL_ADMIN] } }, grantControls: PHISH })]);
    expect(f.explanation).toContain('Global Administrator');
  });

  test('does not count plain MFA, targeted resources or disabled policies', () => {
    const fs = run('ADM-01', [
      rolePolicy({ grant: MFA }),
      rolePolicy({ apps: [KEYWORD.adminPortals] }),
      rolePolicy({ state: 'disabled' }),
    ]);
    expect(fs).toHaveLength(1);
    expect(fs[0].status).toBe('gap');
    expect(fs[0].explanation).toContain('Global Administrator');
  });

  test('combines role-specific policies', () => {
    const ga = rolePolicy({ roles: [GLOBAL_ADMIN] });
    const rest = rolePolicy({ roles: ROLES.filter(r => r !== GLOBAL_ADMIN) });
    expect(run('ADM-01', [ga, rest])).toEqual([]);
  });

  test('partial when some roles are covered only by report-only policies', () => {
    const ga = rolePolicy({ roles: [GLOBAL_ADMIN], state: REPORT_ONLY });
    const rest = rolePolicy({ roles: ROLES.filter(r => r !== GLOBAL_ADMIN) });
    const f = single('ADM-01', [ga, rest]);
    expect(f.status).toBe('partial');
    expect(f.policyIds).toEqual([ga.id]);
    expect(f.explanation).toContain('Global Administrator');
    expect(f.explanation).toMatch(/report-only/i);
  });

  test('requiresLicense without Entra ID P1', () => {
    expect(single('ADM-01', [], tenant({ licenses: { entraP1: false } })).status).toBe('requiresLicense');
  });
});

describe('ADM-02 MFA fallback for privileged roles', () => {
  test('fires when nothing covers admins', () => {
    const f = single('ADM-02', []);
    expect(f.status).toBe('gap');
    expect(f.severity).toBe('critical');
  });

  test('does not fire when an All users MFA policy exists, while ADM-01 still fires', () => {
    expect(run('ADM-02', [mfaAll()])).toEqual([]);
    expect(run('ADM-01', [mfaAll()])).toHaveLength(1);
  });

  test('partial when the MFA policy is report-only', () => {
    expect(single('ADM-02', [mfaAll(REPORT_ONLY)]).status).toBe('partial');
  });

  test('suppressed when ADM-01 is fully satisfied', () => {
    const ga = rolePolicy({ roles: [GLOBAL_ADMIN] });
    const rest = rolePolicy({ roles: ROLES.filter(r => r !== GLOBAL_ADMIN) });
    expect(run('ADM-02', [ga, rest])).toEqual([]);
  });
});

describe('ADM-03 admin policy targets only Microsoft Admin Portals', () => {
  test('fires for a 14-role Admin Portals MFA policy and names the uncovered APIs', () => {
    const p = rolePolicy({ apps: [KEYWORD.adminPortals], grant: MFA });
    const f = single('ADM-03', [p]);
    expect(f.policyIds).toEqual([p.id]);
    expect(f.severity).toBe('high');
    expect(f.explanation).toContain('Intune');
    expect(f.explanation).toContain('Microsoft Graph');
    expect(f.explanation).toContain('Azure Resource Manager');
    expect(f.explanation).toContain('Exchange Online PowerShell');
    expect(f.explanation).toMatch(/Microsoft Entra and Intune admin centers/);
    expect(f.remediation).toMatch(/All resources/);
  });

  test('fires when the policy lists the portal app IDs individually', () => {
    expect(single('ADM-03', [rolePolicy({ apps: [...ADMIN_PORTAL_IDS], grant: MFA })]).status).toBe('gap');
  });

  test('one finding per offending policy', () => {
    const a = rolePolicy({ apps: [KEYWORD.adminPortals], grant: MFA });
    const b = rolePolicy({ apps: [APP.azurePortal], grant: MFA });
    expect(run('ADM-03', [a, b]).map(f => f.policyIds)).toEqual([[a.id], [b.id]]);
  });

  test('not fired when an All-resources admin MFA policy exists', () => {
    expect(run('ADM-03', [rolePolicy({ apps: [KEYWORD.adminPortals], grant: MFA }), mfaAll()])).toEqual([]);
  });

  test('partial when the All-resources admin MFA policy is report-only', () => {
    expect(single('ADM-03', [rolePolicy({ apps: [KEYWORD.adminPortals], grant: MFA }), mfaAll(REPORT_ONLY)]).status).toBe('partial');
  });

  test('ignores policies that do not cover admins or are disabled', () => {
    const nobody = pol({ conditions: { users: { includeUsers: ['None'] }, applications: { includeApplications: [KEYWORD.adminPortals] } }, grantControls: MFA });
    expect(run('ADM-03', [nobody, rolePolicy({ apps: [KEYWORD.adminPortals], state: 'disabled' })])).toEqual([]);
  });
});

describe('ADM-04 admin policy targets only Azure management', () => {
  test('fires for a policy targeting only Windows Azure Service Management API', () => {
    const p = rolePolicy({ apps: [APP.azureManagement], grant: MFA });
    const f = single('ADM-04', [p]);
    expect(f.policyIds).toEqual([p.id]);
    expect(f.explanation).toContain('Azure DevOps');
    expect(f.explanation).toContain('Microsoft Graph');
  });

  test('does not fire for All resources or mixed targets, or with an All-resources admin MFA policy', () => {
    expect(run('ADM-04', [rolePolicy({ grant: MFA }), rolePolicy({ apps: [APP.azureManagement, APP.azureDevOps], grant: MFA })])).toEqual([]);
    expect(run('ADM-04', [rolePolicy({ apps: [APP.azureManagement], grant: MFA }), mfaAll()])).toEqual([]);
  });
});

describe('ADM-05 admin policies scoped only by directory roles', () => {
  test('fires for a role-only MFA policy and mentions PIM and Exchange role groups', () => {
    const p = rolePolicy();
    const f = single('ADM-05', [p]);
    expect(f.policyIds).toEqual([p.id]);
    expect(f.explanation).toMatch(/PIM/);
    expect(f.explanation).toMatch(/Exchange/);
    expect(f.explanation).toMatch(/administrative unit/);
  });

  test('lists all offending policies in one finding', () => {
    const a = rolePolicy();
    const b = rolePolicy({ grant: { builtInControls: ['compliantDevice'] } });
    expect(single('ADM-05', [a, b]).policyIds).toEqual([a.id, b.id]);
  });

  test('does not fire when the policy also includes a group, or for All users policies', () => {
    expect(run('ADM-05', [rolePolicy({ groups: ['admins-group'] }), mfaAll()])).toEqual([]);
  });

  test('ignores role-only policies without an MFA or device control', () => {
    expect(run('ADM-05', [rolePolicy({ grant: null, session: { signInFrequency: { isEnabled: true, type: 'hours', value: 4 } } })])).toEqual([]);
  });
});

describe('ADM-06 managed device for admins', () => {
  test('requiresLicense without Intune', () => {
    const f = single('ADM-06', []);
    expect(f.status).toBe('requiresLicense');
    expect(f.requiredLicense).toBe('Microsoft Intune');
  });

  test('gap with Intune and no device policy', () => {
    expect(single('ADM-06', [rolePolicy()], tenant({ licenses: { intune: true } })).status).toBe('gap');
  });

  test('passes with Intune and a compliant-device 14-role policy', () => {
    expect(run('ADM-06', [rolePolicy({ grant: { builtInControls: ['compliantDevice'] } })], tenant({ licenses: { intune: true } }))).toEqual([]);
  });
});

describe('ADM-07 sign-in frequency for admins', () => {
  const sif = { signInFrequency: { isEnabled: true, type: 'hours' as const, value: 4 } };

  test('fires without sign-in frequency', () => {
    const f = single('ADM-07', [rolePolicy()]);
    expect(f.severity).toBe('low');
    expect(f.status).toBe('gap');
  });

  test('passes with sign-in frequency on a 14-role policy', () => {
    expect(run('ADM-07', [rolePolicy({ session: sif })])).toEqual([]);
  });

  test('partial when only report-only', () => {
    expect(single('ADM-07', [rolePolicy({ session: sif, state: REPORT_ONLY })]).status).toBe('partial');
  });
});

describe('ADM-08 reliance on Microsoft Admin Portals', () => {
  test('unverified info finding listing admin policies that use Admin Portals', () => {
    const a = rolePolicy({ apps: [KEYWORD.adminPortals], grant: MFA });
    const b = rolePolicy({ apps: [KEYWORD.adminPortals, APP.azureManagement], grant: MFA });
    const f = single('ADM-08', [a, b, mfaAll()]);
    expect(f.status).toBe('unverified');
    expect(f.severity).toBe('info');
    expect(f.policyIds).toEqual([a.id, b.id]);
    expect(f.explanation).toContain('Defender');
    expect(f.explanation).toContain('Power Platform');
    expect(f.requiredLicense).toBeUndefined();
  });

  test('silent when no policy uses Admin Portals', () => {
    expect(run('ADM-08', [rolePolicy(), mfaAll()])).toEqual([]);
  });
});
