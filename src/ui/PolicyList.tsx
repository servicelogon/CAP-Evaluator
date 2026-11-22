import { useState } from 'react';
import { blankPolicy } from '../model/newPolicy';
import { goodTenant } from '../samples/goodTenant';
import { weakTenant } from '../samples/weakTenant';
import type { CAPolicy, TenantProfile } from '../model/types';
import { STATE_CLASS, STATE_LABEL } from './labels';
import { PolicyImport } from './PolicyImport';
import { policyCardSummary } from './policySummary';

interface Props {
  policies: CAPolicy[];
  onPolicies: (policies: CAPolicy[]) => void;
  onTenant: (tenant: TenantProfile) => void;
  onEdit: (policy: CAPolicy) => void;
}

export function PolicyList({ policies, onPolicies, onTenant, onEdit }: Props) {
  const [showImport, setShowImport] = useState(false);

  function loadSample(sample: { tenant: TenantProfile; policies: CAPolicy[] }) {
    if (policies.length > 0 && !window.confirm('Replace the policies and tenant setup in this browser with the sample?')) return;
    onTenant(sample.tenant);
    onPolicies(sample.policies);
  }

  return (
    <section>
      <header className="step-head">
        <p className="kicker">Step 2 of 4</p>
        <h2>Policies</h2>
        <p className="lede">
          Build each policy with the same Assignments, Conditions, and Access controls as the Entra admin center. Import JSON only if you already exported policies from Graph.
        </p>
      </header>
      <div className="actions">
        <button type="button" className="btn" onClick={() => onEdit(blankPolicy())}>
          <span className="plus-icon" aria-hidden="true" />Create new policy
        </button>
        <button type="button" className="btn secondary" aria-expanded={showImport} onClick={() => setShowImport((v) => !v)}>
          Import a JSON file
        </button>
      </div>
      <div className="examples">
        <span className="examples-label">Try a sample</span>
        <button type="button" className="btn quiet" onClick={() => loadSample(goodTenant)}>
          Load sample: known-good
        </button>
        <button type="button" className="btn quiet" onClick={() => loadSample(weakTenant)}>
          Load sample: weak
        </button>
      </div>

      {showImport && (
        <PolicyImport
          onImport={(incoming, { tenant, replace }) => {
            if (tenant) onTenant(tenant);
            onPolicies(replace ? incoming : [...policies, ...incoming]);
          }}
        />
      )}

      <div className="block policy-block">
        <h3 className="block-title">
          Your policies <span className="count">{policies.length}</span>
        </h3>
        {policies.length === 0 && (
          <p className="muted empty-note">No policies yet. Create a policy, import a JSON file, or load a sample to see how the evaluator works.</p>
        )}
        {policies.map((p) => {
          const summary = policyCardSummary(p);
          return (
            <article className="policy-card" key={p.id}>
              <div className="policy-main">
                <div className="policy-title">
                  <h4>{p.displayName}</h4>
                  <span className={`badge ${STATE_CLASS[p.state]}`}>{STATE_LABEL[p.state]}</span>
                </div>
                <div className="policy-id">{p.id}</div>
                <dl className="policy-facts">
                  <div>
                    <dt>Who</dt>
                    <dd>{summary.who}</dd>
                  </div>
                  <div>
                    <dt>Resources</dt>
                    <dd>{summary.resources}</dd>
                  </div>
                  <div>
                    <dt>Access</dt>
                    <dd>{summary.access}</dd>
                  </div>
                </dl>
              </div>
              <div className="policy-actions">
                <button type="button" className="btn secondary" aria-label={`Edit ${p.displayName}`} onClick={() => onEdit(p)}>Edit</button>
                <button type="button" className="btn danger" aria-label={`Delete ${p.displayName}`} onClick={() => {
                  if (window.confirm(`Delete “${p.displayName}”?`)) onPolicies(policies.filter((x) => x.id !== p.id));
                }}>
                  Delete
                </button>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
