import type { CAPolicy, Finding } from '../model/types';

function csvField(value: string): string {
  if (/[",\n\r]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

export function findingsToCsv(findings: Finding[], policies: CAPolicy[]): string {
  const names = new Map(policies.map((p) => [p.id, p.displayName]));
  const header = 'ruleId,severity,status,title,policies,remediation,requiredLicense,reference';
  const rows = findings.map((f) => {
    const policyNames = f.policyIds.map((id) => names.get(id) ?? id).join('; ');
    return [
      f.ruleId,
      f.severity,
      f.status,
      f.title,
      policyNames,
      f.remediation,
      f.requiredLicense ?? '',
      f.references[0] ?? '',
    ].map(csvField).join(',');
  });
  return [header, ...rows].join('\n');
}
