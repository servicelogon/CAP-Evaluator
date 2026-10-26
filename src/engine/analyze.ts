import { CATALOG_DATE } from '../catalog/apps';
import type { AnalysisResult, CAPolicy, Finding, Severity, TenantProfile } from '../model/types';
import { buildManualChecks } from './manualChecks';
import { buildMatrix } from './matrix';
import { ALL_RULES } from './rules';
import { reportOnlySummary } from './rules/reportOnly';
import type { RuleContext } from './rules/types';
import { computeScore } from './score';

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const byPriority = (a: Finding, b: Finding) =>
  SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0);

/** Runs every rule, the report-only summary, the three coverage matrices, manual checks and the score. */
export function analyze(policies: CAPolicy[], tenant: TenantProfile): AnalysisResult {
  const ctx: RuleContext = { policies, tenant };
  const ruleFindings = ALL_RULES.flatMap(r => r.run(ctx));
  const findings = [...ruleFindings, ...reportOnlySummary(ctx, ruleFindings)].sort(byPriority);
  return {
    findings,
    manualChecks: buildManualChecks(ctx, findings),
    matrices: {
      allUsers: buildMatrix(policies, tenant, 'allUsers'),
      admins: buildMatrix(policies, tenant, 'admins'),
      guests: buildMatrix(policies, tenant, 'guests'),
    },
    score: computeScore(findings),
    generatedAt: new Date().toISOString(),
    catalogDate: CATALOG_DATE,
  };
}
