import { useMemo } from 'react';
import { analyze } from '../engine/analyze';
import { findingsToCsv } from '../report/csv';
import { downloadFile } from '../report/download';
import { buildHtmlReport } from '../report/html';
import { policiesToJson } from '../report/json';
import type { CAPolicy, TenantProfile } from '../model/types';

interface Props {
  policies: CAPolicy[];
  tenant: TenantProfile;
}

export function ExportView({ policies, tenant }: Props) {
  const result = useMemo(() => analyze(policies, tenant), [policies, tenant]);

  return (
    <section>
      <p className="kicker">Step 4</p>
      <h2>Export</h2>
      <p className="lede">
        Download a printable HTML report, a findings CSV for tracking, and policy JSON you can reload later.
      </p>
      <div className="score-row">
        <p className="score score-compact" aria-label={`Score ${result.score}`}>
          {result.score}<span className="score-of">/100</span>
        </p>
        <p className="muted">{result.findings.length} findings · {policies.length} {policies.length === 1 ? 'policy' : 'policies'}</p>
      </div>
      <div className="card">
        <div className="export-row">
          <div>
            <h3>HTML report</h3>
            <p className="muted">Printable report. Open it and use Print → Save as PDF.</p>
          </div>
          <button
            type="button"
            className="btn"
            onClick={() => downloadFile(
              'ca-gap-report.html',
              'text/html;charset=utf-8',
              buildHtmlReport({ tenant, policies, result }),
            )}
          >
            Download HTML report
          </button>
        </div>
        <div className="export-row">
          <div>
            <h3>Findings CSV</h3>
            <p className="muted">A spreadsheet of findings for tracking.</p>
          </div>
          <button
            type="button"
            className="btn secondary"
            onClick={() => downloadFile(
              'ca-gap-findings.csv',
              'text/csv;charset=utf-8',
              findingsToCsv(result.findings, policies),
            )}
          >
            Download findings CSV
          </button>
        </div>
        <div className="export-row">
          <div>
            <h3>Policy JSON</h3>
            <p className="muted">Policy JSON you can reload later.</p>
          </div>
          <button
            type="button"
            className="btn secondary"
            onClick={() => downloadFile(
              'ca-gap-policies.json',
              'application/json;charset=utf-8',
              policiesToJson(policies, tenant),
            )}
          >
            Download policy JSON
          </button>
        </div>
      </div>
    </section>
  );
}
