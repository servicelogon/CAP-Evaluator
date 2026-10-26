import { CONTROLS, SURFACES } from '../catalog/surfaces';
import type { AnalysisResult, CAPolicy, CellState, CoverageMatrix, TenantProfile } from '../model/types';
import { LICENSE_LABEL } from '../engine/rules/types';

const CELL_COLOR: Record<CellState, string> = {
  covered: '#107c10',
  partial: '#c47b00',
  gap: '#d13438',
  requiresLicense: '#9aa0a6',
  na: '#f3f2f1',
};

const CELL_LABEL: Record<CellState, string> = {
  covered: 'Covered',
  partial: 'Partial',
  gap: 'Gap',
  requiresLicense: 'Needs license',
  na: 'n/a',
};

function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function heatMapTable(matrix: CoverageMatrix): string {
  const header = CONTROLS.map((c) => `<th>${esc(c.label)}</th>`).join('');
  const rows = SURFACES.map((s) => {
    const cells = CONTROLS.map((c) => {
      const cell = matrix.cells.find((x) => x.surface === s.id && x.control === c.id);
      const state = cell?.state ?? 'gap';
      const color = CELL_COLOR[state];
      const fg = state === 'na' || state === 'requiresLicense' ? '#323130' : '#fff';
      return `<td style="background:${color};color:${fg};text-align:center;padding:6px;font-size:11px">${esc(CELL_LABEL[state])}</td>`;
    }).join('');
    return `<tr><th style="text-align:left;padding:6px 10px;background:#f3f2f1">${esc(s.label)}</th>${cells}</tr>`;
  }).join('');
  return `<table style="border-collapse:collapse;width:100%;font-size:12px"><thead><tr><th></th>${header}</tr></thead><tbody>${rows}</tbody></table>`;
}

function licenseSummary(tenant: TenantProfile): string {
  return (Object.keys(LICENSE_LABEL) as (keyof typeof LICENSE_LABEL)[])
    .map((k) => `<li>${esc(LICENSE_LABEL[k])}: ${tenant.licenses[k] ? 'yes' : 'no'}</li>`)
    .join('');
}

export function buildHtmlReport(input: {
  tenant: TenantProfile;
  policies: CAPolicy[];
  result: AnalysisResult;
}): string {
  const { tenant, policies, result } = input;
  const names = new Map(policies.map((p) => [p.id, p.displayName]));
  const findings = result.findings.map((f) => {
    const policyNames = f.policyIds.map((id) => names.get(id) ?? id).join('; ') || '—';
    const ref = f.references[0] ? `<a href="${esc(f.references[0])}">Learn</a>` : '';
    return `<tr>
      <td>${esc(f.ruleId)}</td>
      <td>${esc(f.severity)}</td>
      <td>${esc(f.status)}</td>
      <td>${esc(f.title)}</td>
      <td>${esc(policyNames)}</td>
      <td>${esc(f.remediation)}</td>
      <td>${ref}</td>
    </tr>`;
  }).join('');
  const checks = result.manualChecks.map((c) =>
    `<li><strong>${esc(c.title)}</strong> — ${esc(c.why)} <em>Where:</em> ${esc(c.where)}</li>`
  ).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <title>CA Gap Evaluator report</title>
  <style>
    body { font-family: "Segoe UI", ui-sans-serif, system-ui, sans-serif; color: #242424; margin: 24px; }
    h1, h2 { color: #0b2e4a; }
    table { border-collapse: collapse; width: 100%; margin: 12px 0 24px; }
    th, td { border: 1px solid #e1dfdd; padding: 6px 8px; text-align: left; vertical-align: top; font-size: 13px; }
    th { background: #f3f2f1; }
    .score { font-size: 28px; font-weight: 600; }
    @media print {
      a { color: inherit; text-decoration: none; }
      body { margin: 12px; }
    }
  </style>
</head>
<body>
  <h1>CA Gap Evaluator report</h1>
  <p>Catalog date: ${esc(result.catalogDate)} · Generated: ${esc(result.generatedAt)} · Policies: ${policies.length}</p>
  <p class="score">Score: ${result.score}</p>
  <h2>Licenses</h2>
  <ul>${licenseSummary(tenant)}</ul>
  <h2>Coverage heat map (all users)</h2>
  ${heatMapTable(result.matrices.allUsers)}
  <h2>Findings</h2>
  <table>
    <thead><tr><th>ID</th><th>Severity</th><th>Status</th><th>Title</th><th>Policies</th><th>Remediation</th><th>Reference</th></tr></thead>
    <tbody>${findings || '<tr><td colspan="7">No findings.</td></tr>'}</tbody>
  </table>
  <h2>Verify manually</h2>
  <ol>${checks}</ol>
</body>
</html>`;
}
