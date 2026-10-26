import type { Finding, Severity } from '../model/types';

const WEIGHT: Record<Severity, number> = { critical: 15, high: 8, medium: 4, low: 1, info: 0 };
/** HYG-01 summarizes findings that other rules already score. */
const UNSCORED_RULES = new Set(['HYG-01']);

/** 100 minus severity weights of gap (full) and partial (half) findings, rounded, floored at 0. */
export function computeScore(findings: Finding[]): number {
  const deduction = findings.reduce((sum, f) => {
    if (UNSCORED_RULES.has(f.ruleId)) return sum;
    if (f.status === 'gap') return sum + WEIGHT[f.severity];
    if (f.status === 'partial') return sum + WEIGHT[f.severity] / 2;
    return sum;
  }, 0);
  return Math.max(0, Math.round(100 - deduction));
}
