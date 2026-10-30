import { useMemo, useState } from 'react';
import type { CAPolicy, Finding, RuleFamily, Severity } from '../model/types';
import { FAMILY_LABEL, FINDING_STATUS_LABEL, SEVERITY_LABEL } from './labels';

interface Props {
  findings: Finding[];
  policies: CAPolicy[];
  pinnedRuleIds?: string[];
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const FAMILIES: RuleFamily[] = ['baseline', 'admin', 'apps', 'weakening', 'risk', 'hygiene'];

export function FindingsList({ findings, policies, pinnedRuleIds }: Props) {
  const [severity, setSeverity] = useState<string>('all');
  const [family, setFamily] = useState<string>('all');
  const [policyId, setPolicyId] = useState<string>('all');
  const names = useMemo(() => new Map(policies.map((p) => [p.id, p.displayName])), [policies]);

  const pinned = pinnedRuleIds && pinnedRuleIds.length > 0 ? new Set(pinnedRuleIds) : null;
  const relatedCount = pinned ? findings.filter((f) => pinned.has(f.ruleId)).length : 0;
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
          {SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
        </select>
        <select aria-label="Filter by family" value={family} onChange={(e) => setFamily(e.target.value)}>
          <option value="all">All families</option>
          {FAMILIES.map((s) => <option key={s} value={s}>{FAMILY_LABEL[s]}</option>)}
        </select>
        <select aria-label="Filter by policy" value={policyId} onChange={(e) => setPolicyId(e.target.value)}>
          <option value="all">All policies</option>
          {policies.map((p) => <option key={p.id} value={p.id}>{p.displayName}</option>)}
        </select>
      </div>
      {pinned && (
        <p className="muted related-note">
          {relatedCount} {relatedCount === 1 ? 'finding relates' : 'findings relate'} to the selected cell.
        </p>
      )}
      {rows.length === 0 && <p className="muted">No findings match the filters.</p>}
      <div className="findings-scroll">
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
            <tr key={`${f.ruleId}-${f.status}-${i}`} className={pinned?.has(f.ruleId) ? 'related-row' : undefined}>
              <td><span className={`badge ${f.severity}`}>{SEVERITY_LABEL[f.severity]}</span></td>
              <td>{f.ruleId}</td>
              <td>
                <strong>{f.title}</strong>
                <div className="muted">{f.explanation}</div>
              </td>
              <td><span className={`badge ${f.status}`}>{FINDING_STATUS_LABEL[f.status]}</span></td>
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
    </div>
  );
}
