import type { Finding, Severity } from '../model/types';

const WEIGHT: Record<Severity, number> = { critical: 15, high: 8, medium: 4, low: 1, info: 0 };
/** HYG-01 summarizes findings that other rules already score. */
const UNSCORED_RULES = new Set(['HYG-01']);

export interface ScoreDeduction {
  ruleId: string;
  title: string;
  severity: Severity;
  status: 'gap' | 'partial';
  points: number;
}

/** Gap uses the severity weight. Partial uses half. License, unverified, info, and HYG-01 contribute 0. */
export function pointsFor(finding: Finding): number {
  if (UNSCORED_RULES.has(finding.ruleId)) return 0;
  if (finding.status === 'gap') return WEIGHT[finding.severity];
  if (finding.status === 'partial') return WEIGHT[finding.severity] / 2;
  return 0;
}

/** 100 minus severity weights of gap (full) and partial (half) findings, rounded down so any finding lowers it, min 0. */
export function computeScore(findings: Finding[]): number {
  const deduction = findings.reduce((sum, finding) => sum + pointsFor(finding), 0);
  return Math.max(0, Math.floor(100 - deduction));
}

/** Scored findings only, highest deduction first, then rule id. */
export function scoreDeductions(findings: Finding[]): ScoreDeduction[] {
  return findings
    .flatMap((finding) => {
      const points = pointsFor(finding);
      if (points === 0 || (finding.status !== 'gap' && finding.status !== 'partial')) return [];
      return [{
        ruleId: finding.ruleId,
        title: finding.title,
        severity: finding.severity,
        status: finding.status,
        points,
      }];
    })
    .sort((a, b) => b.points - a.points || (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0));
}
