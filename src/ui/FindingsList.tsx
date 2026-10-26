import { useMemo, useState } from 'react';
import type { CAPolicy, Finding, RuleFamily, Severity } from '../model/types';

interface Props {
  findings: Finding[];
  policies: CAPolicy[];
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const FAMILIES: RuleFamily[] = ['baseline', 'admin', 'apps', 'weakening', 'risk', 'hygiene'];

export function FindingsList({ findings, policies }: Props) {
  const [severity, setSeverity] = useState<string>('all');
  const [family, setFamily] = useState<string>('all');
  const [policyId, setPolicyId] = useState<string>('all');
  const names = useMemo(() => new Map(policies.map((p) => [p.id, p.displayName])), [policies]);

  const rows = findings.filter((f) =>
    (severity === 'all' || f.severity === severity)
    && (family === 'all' || f.family === family)
    && (policyId === 'all' || f.policyIds.includes(policyId)),
  );

  return (
    <div>
      <h3>Findings ({rows.length})</h3>
      <div className="filters">
        <select aria-label="Filter by severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="all">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select aria-label="Filter by family" value={family} onChange={(e) => setFamily(e.target.value)}>
          <option value="all">All families</option>
          {FAMILIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select aria-label="Filter by policy" value={policyId} onChange={(e) => setPolicyId(e.target.value)}>
          <option value="all">All policies</option>
          {policies.map((p) => <option key={p.id} value={p.id}>{p.displayName}</option>)}
        </select>
      </div>
      {rows.length === 0 && <p className="muted">No findings match the filters.</p>}
      <table className="findings">
        <thead>
          <tr>
            <th>Severity</th>
            <th>ID</th>
            <th>Title</th>
            <th>Status</th>
            <th>Policies</th>
            <th>Remediation</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f, i) => (
            <tr key={`${f.ruleId}-${f.status}-${i}`}>
              <td><span className={`badge ${f.severity}`}>{f.severity}</span></td>
              <td>{f.ruleId}</td>
              <td>
                <strong>{f.title}</strong>
                <div className="muted">{f.explanation}</div>
              </td>
              <td><span className={`badge ${f.status}`}>{f.status}</span></td>
              <td>{f.policyIds.map((id) => names.get(id) ?? id).join('; ') || '—'}</td>
              <td>
                {f.remediation}
                {f.references[0] && (
                  <>
                    {' '}
                    <a href={f.references[0]} target="_blank" rel="noreferrer">Learn</a>
                  </>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
