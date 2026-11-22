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
  const filtered = severity !== 'all' || family !== 'all' || policyId !== 'all';

  return (
    <div className="block findings-block">
      <div className="findings-head">
        <h3 className="block-title findings-heading">
          Findings <span className="count">{rows.length}{filtered ? ` of ${findings.length}` : ''}</span>
        </h3>
        {filtered && (
          <button type="button" className="text-btn" onClick={() => { setSeverity('all'); setFamily('all'); setPolicyId('all'); }}>
            Reset filters
          </button>
        )}
      </div>
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
        <p className="related-note">
          <span className="related-dot" aria-hidden="true" />
          {relatedCount} {relatedCount === 1 ? 'finding relates' : 'findings relate'} to the selected cell.
        </p>
      )}
      {rows.length === 0 && <p className="muted empty-note">No findings match the filters.</p>}
      {rows.length > 0 && (
        <>
          <div className="findings-columns" aria-hidden="true">
            <span>Severity</span>
            <span>ID</span>
            <span>Finding</span>
            <span>Status</span>
            <span>Policies</span>
          </div>
          <ul className="findings">
            {rows.map((f, i) => {
              const key = `${f.ruleId}-${f.status}-${i}`;
              const isOpen = open.has(key);
              const policyNames = f.policyIds.map((id) => names.get(id) ?? id);
              const detailId = `finding-${i}`;
              return (
                <li key={key} className={`finding${pinned?.has(f.ruleId) ? ' related-row' : ''}${isOpen ? ' open' : ''}`}>
                  <button
                    type="button"
                    className="finding-row"
                    aria-expanded={isOpen}
                    aria-controls={isOpen ? detailId : undefined}
                    onClick={() => toggle(key)}
                  >
                    <span className="f-sev"><span className={`badge ${f.severity}`}>{SEVERITY_LABEL[f.severity]}</span></span>
                    <span className={`rule-id ${f.severity}`}>{f.ruleId}</span>
                    <span className="f-title">{f.title}</span>
                    <span className="f-status"><span className={`badge ${f.status}`}>{FINDING_STATUS_LABEL[f.status]}</span></span>
                    <span className={`f-policies${policyNames.length ? '' : ' empty'}`}>{policyNames.length ? policyNames.join('; ') : '—'}</span>
                    <span className="chevron" aria-hidden="true" />
                  </button>
                  {isOpen && (
                    <div className="finding-detail" id={detailId}>
                      <p className="subhead">What this means</p>
                      <p className="muted">{f.explanation}</p>
                      <p className="subhead">Remediation</p>
                      <p>{f.remediation}</p>
                      {f.references[0] && (
                        <a className="ext-link" href={f.references[0]} target="_blank" rel="noreferrer">
                          Learn more<span className="arrow-icon" aria-hidden="true" />
                        </a>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </>
      )}
    </div>
  );
}
