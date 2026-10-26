import { analyze } from '../engine/analyze';
import { normalizePolicy } from '../model/normalize';
import { goodTenant, goodTenantRaw } from './goodTenant';
import { weakTenant, weakTenantRaw } from './weakTenant';

const serious = (sev: string) => sev === 'critical' || sev === 'high';
const open = (status: string) => status === 'gap' || status === 'partial';

describe('good tenant sample', () => {
  const result = analyze(goodTenant.policies, goodTenant.tenant);

  test('has no open critical or high findings', () => {
    const bad = result.findings.filter(f => serious(f.severity) && open(f.status));
    expect(bad.map(f => `${f.ruleId}: ${f.explanation}`)).toEqual([]);
  });

  test('scores at least 90', () => expect(result.score).toBeGreaterThanOrEqual(90));

  test('only finding is the informational agent identity check', () => {
    // RSK-06 is an unverified info prompt that fires whenever no policy targets Agent ID; the sample does not use Agent ID.
    expect(result.findings.map(f => `${f.ruleId} ${f.severity} ${f.status}`)).toEqual(['RSK-06 info unverified']);
    expect(result.score).toBe(100);
  });

  test('all-users matrix has no gaps except controls not applicable to user-action surfaces by design', () => {
    // Accepted gaps on the user-action surfaces:
    // - Phishing-resistant MFA on "Register security information" and "Register or join devices": Microsoft's baseline requires
    //   phishing-resistant MFA only for administrators. Requiring it for all users here would make first-time registration
    //   impossible (a Temporary Access Pass does not satisfy the built-in Phishing-resistant MFA strength, and Windows Hello for
    //   Business is provisioned only after the device is joined).
    // - Managed device on "Register security information": the Microsoft template requires MFA here; requiring a compliant device
    //   would block onboarding on new devices. MFA on this action is covered (BAS-08).
    const accepted = new Set(['registerSecurityInfo/phishResistant', 'registerSecurityInfo/managedDevice', 'registerDevice/phishResistant']);
    const gaps = result.matrices.allUsers.cells.filter(c => c.state === 'gap').map(c => `${c.surface}/${c.control}`);
    expect(gaps.filter(g => !accepted.has(g))).toEqual([]);
  });

  test('excludes the break-glass accounts from every policy that targets users', () => {
    for (const p of goodTenant.policies) {
      const u = p.conditions.users;
      const targetsUsers = u.includeUsers.some(x => x !== 'None') || u.includeGroups.length > 0 || u.includeRoles.length > 0
        || u.includeGuestsOrExternalUsers !== null;
      if (targetsUsers) expect(u.excludeUsers).toEqual(expect.arrayContaining(goodTenant.tenant.breakGlass));
    }
  });
});

describe('weak tenant sample', () => {
  const result = analyze(weakTenant.policies, weakTenant.tenant);
  const ids = new Set(result.findings.map(f => f.ruleId));

  test('produces the expected findings', () => {
    const expected = ['BAS-01', 'BAS-02', 'BAS-03', 'ADM-01', 'ADM-03', 'APP-02', 'APP-05', 'APP-06', 'WEK-04', 'WEK-05', 'WEK-08',
      'WEK-09', 'HYG-02'];
    expect(expected.filter(id => !ids.has(id))).toEqual([]);
  });

  test('scores below 40', () => expect(result.score).toBeLessThan(40));
});

describe('samples double as import fixtures', () => {
  test.each([
    ['good', goodTenantRaw, goodTenant.policies],
    ['weak', weakTenantRaw, weakTenant.policies],
  ])('%s tenant raw policies normalize without notes and have unique GUID ids', (_name, raw, policies) => {
    const normalized = raw.map((r, i) => normalizePolicy(r, i));
    expect(normalized.flatMap(n => n.notes)).toEqual([]);
    expect(normalized.map(n => n.policy)).toEqual(policies);
    const ids = policies.map(p => p.id);
    expect(new Set(ids).size).toBe(ids.length);
    ids.forEach(id => expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/));
  });
});
