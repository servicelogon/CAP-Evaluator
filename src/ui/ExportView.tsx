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
        Download a printable HTML report (open it and use Print → Save as PDF), a findings CSV for tracking,
        and policy JSON you can reload later.
      </p>
      <p className="muted">Current score: {result.score} · {result.findings.length} findings · {policies.length} policies</p>
      <div className="actions">
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
    </section>
  );
}
