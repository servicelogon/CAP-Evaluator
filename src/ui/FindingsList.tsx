import { Fragment, useMemo, useState } from 'react';
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
  const [open, setOpen] = useState<Set<string>>(new Set());
  const names = useMemo(() => new Map(policies.map((p) => [p.id, p.displayName])), [policies]);

  function toggle(key: string) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  const pinned = pinnedRuleIds && pinnedRuleIds.length > 0 ? new Set(pinnedRuleIds) : null;
  const relatedCount = pinned ? findings.filter((f) => pinned.has(f.ruleId)).length : 0;
  const rows = findings.filter((f) =>
    (severity === 'all' || f.severity === severity)
    && (family === 'all' || f.family === family)
    && (policyId === 'all' || f.policyIds.includes(policyId)),
  );

  return (
    <div className="findings-block">
      <h3 className="findings-heading">Findings ({rows.length})</h3>
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
          </tr>
        </thead>
        <tbody>
          {rows.map((f, i) => {
            const key = `${f.ruleId}-${f.status}-${i}`;
            const isOpen = open.has(key);
            return (
              <Fragment key={key}>
                <tr
                  className={`finding-row${pinned?.has(f.ruleId) ? ' related-row' : ''}${isOpen ? ' open' : ''}`}
                  onClick={() => toggle(key)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      toggle(key);
                    }
                  }}
                  tabIndex={0}
                  aria-expanded={isOpen}
                >
                  <td><span className={`badge ${f.severity}`}>{SEVERITY_LABEL[f.severity]}</span></td>
                  <td className={`rule-id ${f.severity}`}>{f.ruleId}</td>
                  <td><strong>{f.title}</strong></td>
                  <td><span className={`badge ${f.status}`}>{FINDING_STATUS_LABEL[f.status]}</span></td>
                  <td>{f.policyIds.map((id) => names.get(id) ?? id).join('; ') || '—'}</td>
                </tr>
                {isOpen && (
                  <tr className="finding-detail">
                    <td colSpan={5}>
                      <p className="subhead">What this means</p>
                      <p className="muted">{f.explanation}</p>
                      <p className="subhead">Remediation</p>
                      <p>{f.remediation}</p>
                      {f.references[0] && (
                        <a href={f.references[0]} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>Learn</a>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
      </div>
    </div>
  );
}
