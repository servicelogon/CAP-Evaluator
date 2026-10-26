import type { Finding, FindingStatus, Severity } from '../model/types';
import { computeScore } from './score';

const f = (severity: Severity, status: FindingStatus, ruleId = 'BAS-01'): Finding => ({
  ruleId, title: 't', family: 'baseline', severity, status, policyIds: [], explanation: '', remediation: '', references: [],
});

describe('computeScore', () => {
  test('no findings scores 100', () => {
    expect(computeScore([])).toBe(100);
  });

  test('critical gap and high partial: 100 - 15 - 4 = 81', () => {
    expect(computeScore([f('critical', 'gap'), f('high', 'partial')])).toBe(81);
  });

  test('weights per severity', () => {
    expect(computeScore([f('critical', 'gap')])).toBe(85);
    expect(computeScore([f('high', 'gap')])).toBe(92);
    expect(computeScore([f('medium', 'gap')])).toBe(96);
    expect(computeScore([f('low', 'gap')])).toBe(99);
    expect(computeScore([f('info', 'gap')])).toBe(100);
  });

  test('requiresLicense and unverified are ignored', () => {
    expect(computeScore([f('critical', 'requiresLicense'), f('critical', 'unverified'), f('high', 'gap')])).toBe(92);
  });

  test('HYG-01 is not counted because it summarizes other findings', () => {
    expect(computeScore([f('high', 'partial', 'HYG-01'), f('medium', 'gap')])).toBe(96);
  });

  test('floors to an integer after summing, so any scored finding lowers the score', () => {
    expect(computeScore([f('low', 'partial')])).toBe(99); // 100 - 0.5 = 99.5 → 99
    expect(computeScore([f('medium', 'partial'), f('low', 'partial')])).toBe(97); // 97.5 → 97
    expect(computeScore([f('low', 'partial'), f('low', 'partial'), f('low', 'partial')])).toBe(98); // 98.5 → 98
  });

  test('never below 0', () => {
    expect(computeScore(Array.from({ length: 10 }, () => f('critical', 'gap')))).toBe(0);
  });
});
