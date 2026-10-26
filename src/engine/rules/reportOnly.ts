import type { Finding } from '../../model/types';
import { isReportOnly } from '../predicates';
import { ALL_RULES } from './index';
import { makeFinding, type Rule, type RuleContext, type RuleMeta } from './types';

const HYG01: RuleMeta = {
  id: 'HYG-01', title: 'Requirement met only by report-only policies', family: 'hygiene', severity: 'high',
  remediation: 'Review each listed policy\'s report-only results in the sign-in logs or the Conditional Access insights and reporting '
    + 'workbook, fix any unexpected impact, then switch the policy to On.',
  references: ['https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only'],
};

/** Per rule ID, the number of critical/high findings that are gaps or partial. */
function seriousCounts(findings: Finding[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const f of findings) {
    if ((f.severity === 'critical' || f.severity === 'high') && (f.status === 'gap' || f.status === 'partial')) {
      counts.set(f.ruleId, (counts.get(f.ruleId) ?? 0) + 1);
    }
  }
  return counts;
}

const total = (counts: Map<string, number>) => [...counts.values()].reduce((a, b) => a + b, 0);

/**
 * HYG-01: re-runs `rules` with each report-only policy switched to enabled. Policies whose enabling reduces the number of
 * critical/high gap or partial findings compared with `findings` are listed in one finding, with the rule IDs that improve.
 */
export function reportOnlySummary(ctx: RuleContext, findings: Finding[], rules: Rule[] = ALL_RULES): Finding[] {
  const before = seriousCounts(findings);
  const closing = ctx.policies.filter(isReportOnly).flatMap(p => {
    const policies = ctx.policies.map(x => (x.id === p.id ? { ...x, state: 'enabled' as const } : x));
    const after = seriousCounts(rules.flatMap(r => r.run({ ...ctx, policies })));
    if (total(after) >= total(before)) return [];
    const improved = [...before.keys()].filter(id => (after.get(id) ?? 0) < (before.get(id) ?? 0));
    return [{ p, improved }];
  });
  if (!closing.length) return [];
  const list = closing.map(({ p, improved }) => `"${p.displayName}" (${improved.join(', ')})`).join('; ');
  return [makeFinding(HYG01, ctx, {
    status: 'partial',
    policyIds: closing.map(c => c.p.id),
    explanation: `These report-only policies would close critical or high findings if they were turned on, shown with the rules that `
      + `would improve: ${list}. Report-only policies are evaluated and logged but never enforced, so these protections are configured `
      + 'but not in effect. Policies on the "Register security information" or "Register or join devices" user actions produce no '
      + 'report-only results, so their impact cannot be reviewed in the sign-in logs before turning them on.',
  })];
}
