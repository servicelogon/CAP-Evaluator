import type { ControlId } from '../../catalog/surfaces';
import type { SurfaceId } from '../../catalog/apps';
import type {
  CAPolicy, Finding, FindingStatus, Licenses, Population, RuleFamily, Severity, TenantProfile,
} from '../../model/types';
import { bestCoverage, type Contribution } from '../coverage';
import { isActive, isEnforced } from '../predicates';

export interface RuleContext { policies: CAPolicy[]; tenant: TenantProfile }
export interface Rule { id: string; family: RuleFamily; run(ctx: RuleContext): Finding[] }
export interface RuleMeta {
  id: string; title: string; family: RuleFamily; severity: Severity;
  remediation: string; references: string[]; requiredLicense?: keyof Licenses;
}

export const LICENSE_LABEL: Record<keyof Licenses, string> = {
  entraP1: 'Microsoft Entra ID P1',
  entraP2: 'Microsoft Entra ID P2',
  intune: 'Microsoft Intune',
  workloadIdPremium: 'Microsoft Entra Workload ID Premium',
  defenderForCloudApps: 'Microsoft Defender for Cloud Apps',
  purviewInsiderRisk: 'Microsoft Purview Insider Risk Management (Adaptive Protection)',
};

/** Builds a finding; sets status 'requiresLicense' when meta.requiredLicense is not owned, and severity override optional. */
export function makeFinding(
  meta: RuleMeta, ctx: RuleContext,
  f: { explanation: string; policyIds?: string[]; status?: FindingStatus; severity?: Severity },
): Finding {
  const license = meta.requiredLicense;
  const unlicensed = license !== undefined && !ctx.tenant.licenses[license];
  return {
    ruleId: meta.id,
    title: meta.title,
    family: meta.family,
    severity: f.severity ?? meta.severity,
    status: unlicensed ? 'requiresLicense' : f.status ?? 'gap',
    policyIds: f.policyIds ?? [],
    explanation: f.explanation,
    remediation: meta.remediation,
    references: meta.references,
    ...(license !== undefined ? { requiredLicense: LICENSE_LABEL[license] } : {}),
  };
}

/**
 * One finding per policy in `scope` (default: active) for which `offending` returns a non-empty list (IDs or labels).
 * `status` and `severity` may depend on the list and the policy.
 */
export function perPolicyRule(
  meta: RuleMeta, offending: (p: CAPolicy, ctx: RuleContext) => string[], explain: (ctx: RuleContext, p: CAPolicy, ids: string[]) => string,
  opts: {
    scope?: (p: CAPolicy) => boolean;
    status?: (ids: string[]) => FindingStatus;
    severity?: (p: CAPolicy, ids: string[], ctx: RuleContext) => Severity;
  } = {},
): Rule {
  const { scope = isActive, status = () => 'gap', severity = () => meta.severity } = opts;
  return {
    id: meta.id,
    family: meta.family,
    run: ctx => ctx.policies.filter(scope).flatMap(p => {
      const ids = offending(p, ctx);
      return ids.length
        ? [makeFinding(meta, ctx, {
          policyIds: [p.id], status: status(ids), severity: severity(p, ids, ctx), explanation: explain(ctx, p, ids),
        })]
        : [];
    }),
  };
}

/** Quoted display names of the given policies, e.g. `"Block legacy auth", "MFA"`. */
export function policyNames(ctx: RuleContext, ids: string[]): string {
  return ids.map(id => `"${ctx.policies.find(p => p.id === id)?.displayName ?? id}"`).join(', ');
}

/**
 * Explanation for a coverage result: `describe(c)` plus, for partial, the best policies and their limitations,
 * and for reportOnly, the report-only policies that would otherwise satisfy the rule.
 */
export function coverageExplanation(ctx: RuleContext, c: Contribution & { policyIds: string[] }, describe: (c: Contribution) => string): string {
  const base = describe(c);
  const names = policyNames(ctx, c.policyIds);
  if (c.level === 'partial') {
    return `${base} Closest matching policies: ${names}. Limitations: ${c.reasons.join('; ')}.`;
  }
  if (c.level === 'reportOnly') {
    const other = c.reasons.filter(r => !r.startsWith('report-only'));
    return `${base} Only report-only policies meet this requirement: ${names}. Report-only policies log what would happen but do not enforce anything.`
      + (other.length ? ` They also have limitations: ${other.join('; ')}.` : '');
  }
  return base;
}

/** Turns a coverage result into findings: none → gap, partial/reportOnly → partial, full → []. */
export function coverageFindings(
  meta: RuleMeta, ctx: RuleContext, c: Contribution & { policyIds: string[] }, describe: (c: Contribution) => string,
): Finding[] {
  if (c.level === 'full') return [];
  return [makeFinding(meta, ctx, {
    explanation: coverageExplanation(ctx, c, describe),
    policyIds: c.policyIds,
    status: c.level === 'none' ? 'gap' : 'partial',
  })];
}

/**
 * Rule satisfied by any enforced policy matching `matches`: none → gap with `missing`, only report-only matches →
 * partial naming them, an enforced match → []. Disabled policies never count.
 */
export function policyMatchRule(meta: RuleMeta, matches: (p: CAPolicy) => boolean, missing: string): Rule {
  return {
    id: meta.id,
    family: meta.family,
    run: ctx => {
      const hits = ctx.policies.filter(p => isActive(p) && matches(p));
      if (hits.some(isEnforced)) return [];
      if (!hits.length) return [makeFinding(meta, ctx, { explanation: missing })];
      const ids = hits.map(p => p.id);
      return [makeFinding(meta, ctx, {
        status: 'partial',
        policyIds: ids,
        explanation: `${missing} Only report-only policies meet this requirement: ${policyNames(ctx, ids)}. `
          + 'Report-only policies log what would happen but do not enforce anything.',
      })];
    },
  };
}

/** Common pattern: evaluate bestCoverage; none → gap finding, partial/reportOnly → partial finding (reportOnly explanation says "only report-only policies"), full → []. */
export function coverageRule(
  meta: RuleMeta, pop: Population, surface: SurfaceId, control: ControlId, describe: (c: Contribution) => string,
): Rule {
  return {
    id: meta.id,
    family: meta.family,
    run: ctx => coverageFindings(meta, ctx, bestCoverage(ctx.policies, pop, surface, control, ctx.tenant), describe),
  };
}
