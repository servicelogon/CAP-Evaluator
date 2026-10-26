import { CATALOG_DATE, KEYWORD } from '../catalog/apps';
import { PRIVILEGED_ROLES } from '../catalog/roles';
import { CONTROLS, SURFACES } from '../catalog/surfaces';
import type { CoverageMatrix, Finding } from '../model/types';
import { analyze } from './analyze';
import { buildMatrix } from './matrix';
import { pol, tenant } from './testUtils';

const T = tenant();
const cell = (m: CoverageMatrix, surface: string, control: string) => {
  const c = m.cells.find(x => x.surface === surface && x.control === control);
  if (!c) throw new Error(`missing cell ${surface} × ${control}`);
  return c;
};

describe('buildMatrix', () => {
  test('has one cell per surface and control, in catalog order', () => {
    const m = buildMatrix([], T, 'allUsers');
    expect(m.population).toBe('allUsers');
    expect(m.cells).toHaveLength(SURFACES.length * CONTROLS.length);
    expect(m.cells.slice(0, 2).map(c => [c.surface, c.control])).toEqual([['allResources', 'legacyBlocked'], ['allResources', 'mfa']]);
  });

  test('empty policies: gaps, na and requiresLicense', () => {
    const m = buildMatrix([], T, 'allUsers');
    const mfa = cell(m, 'allResources', 'mfa');
    expect(mfa.state).toBe('gap');
    expect(mfa.policyIds).toEqual([]);
    expect(mfa.reasons).toEqual(['No policy provides this control for this population and resource']);
    expect(cell(m, 'registerDevice', 'managedDevice').state).toBe('na');
    expect(cell(m, 'registerDevice', 'managedDevice').reasons).toEqual([]);
    const risk = cell(m, 'allResources', 'signInRisk');
    expect(risk.state).toBe('requiresLicense');
    expect(risk.reasons).toEqual(['Requires Microsoft Entra ID P2']);
    expect(cell(m, 'allResources', 'managedDevice').reasons).toEqual(['Requires Microsoft Intune']);
  });

  test('licensed controls without a policy are gaps', () => {
    const m = buildMatrix([], tenant({ licenses: { entraP2: true } }), 'allUsers');
    expect(cell(m, 'allResources', 'signInRisk').state).toBe('gap');
  });

  test('admin-portals-only 14-role MFA policy covers admin portals but not Graph for admins', () => {
    const p = pol({
      conditions: {
        users: { includeUsers: [], includeRoles: PRIVILEGED_ROLES.map(r => r.id) },
        applications: { includeApplications: [KEYWORD.adminPortals] },
      },
      grantControls: { builtInControls: ['mfa'] },
    });
    const m = buildMatrix([p], T, 'admins');
    expect(m.population).toBe('admins');
    const portals = cell(m, 'adminPortals', 'mfa');
    expect(portals.state).toBe('covered');
    expect(portals.policyIds).toEqual([p.id]);
    expect(cell(m, 'graph', 'mfa').state).toBe('gap');
    expect(cell(buildMatrix([p], T, 'allUsers'), 'adminPortals', 'mfa').state).toBe('partial');
  });

  test('partial and report-only coverage are partial with reasons and policy IDs', () => {
    const ro = pol({ state: 'enabledForReportingButNotEnforced', grantControls: { builtInControls: ['mfa'] } });
    const c = cell(buildMatrix([ro], T, 'allUsers'), 'allResources', 'mfa');
    expect(c.state).toBe('partial');
    expect(c.policyIds).toEqual([ro.id]);
    expect(c.reasons).toContain('report-only (not enforced)');

    const ex = pol({ conditions: { users: { excludeUsers: ['someone'] } }, grantControls: { builtInControls: ['mfa'] } });
    const e = cell(buildMatrix([ex], T, 'allUsers'), 'allResources', 'mfa');
    expect(e.state).toBe('partial');
    expect(e.reasons).toEqual(['excludes someone']);
  });

  test('unlicensed control with partial coverage stays partial', () => {
    const p = pol({ conditions: { signInRiskLevels: ['medium'] }, grantControls: { builtInControls: ['mfa'] } });
    expect(cell(buildMatrix([p], T, 'allUsers'), 'allResources', 'signInRisk').state).toBe('partial');
  });
});

describe('analyze', () => {
  test('returns three matrices, score, findings, manual checks and metadata', () => {
    const r = analyze([], T);
    expect(Object.keys(r.matrices).sort()).toEqual(['admins', 'allUsers', 'guests']);
    expect(r.matrices.guests.population).toBe('guests');
    expect(r.catalogDate).toBe(CATALOG_DATE);
    expect(new Date(r.generatedAt).toISOString()).toBe(r.generatedAt);
    expect(r.findings.length).toBeGreaterThan(0);
    expect(r.manualChecks.map(c => c.id)).toContain('MC-08');
    expect(r.score).toBe(0);
  });

  test('sorts findings by severity then rule ID', () => {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const { findings } = analyze([], T);
    const key = (f: Finding) => [order.indexOf(f.severity), f.ruleId] as const;
    for (let i = 1; i < findings.length; i++) {
      const [a, ar] = key(findings[i - 1]);
      const [b, br] = key(findings[i]);
      expect(a < b || (a === b && ar <= br)).toBe(true);
    }
  });

  test('appends the HYG-01 report-only summary', () => {
    const ro = pol({ state: 'enabledForReportingButNotEnforced', grantControls: { builtInControls: ['block'] } });
    const r = analyze([ro], T);
    const hyg = r.findings.filter(f => f.ruleId === 'HYG-01');
    expect(hyg).toHaveLength(1);
    expect(hyg[0].policyIds).toEqual([ro.id]);
  });

  test('does not mutate its inputs', () => {
    const ro = pol({ state: 'enabledForReportingButNotEnforced', grantControls: { builtInControls: ['mfa'] } });
    const policies = [ro];
    const t = tenant();
    const before = JSON.stringify({ policies, t });
    analyze(policies, t);
    expect(JSON.stringify({ policies, t })).toBe(before);
  });
});
