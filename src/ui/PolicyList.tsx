import { useState } from 'react';
import { blankPolicy } from '../model/newPolicy';
import { goodTenant } from '../samples/goodTenant';
import { weakTenant } from '../samples/weakTenant';
import type { CAPolicy, TenantProfile } from '../model/types';
import { STATE_CLASS, STATE_LABEL } from './labels';
import { PolicyImport } from './PolicyImport';

interface Props {
  policies: CAPolicy[];
  onPolicies: (policies: CAPolicy[]) => void;
  onTenant: (tenant: TenantProfile) => void;
  onEdit: (policy: CAPolicy) => void;
}

export function PolicyList({ policies, onPolicies, onTenant, onEdit }: Props) {
  const [showImport, setShowImport] = useState(false);
  return (
    <section>
      <p className="kicker">Step 2</p>
      <h2>Policies</h2>
      <p className="lede">
        Build each policy with the same Assignments, Conditions, and Access controls as the Entra admin center. Import JSON only if you already exported policies from Graph.
      </p>
      <div className="actions">
        <button type="button" className="btn" onClick={() => onEdit(blankPolicy())}>Create new policy</button>
        <button type="button" className="btn secondary" onClick={() => setShowImport((v) => !v)}>Import a JSON file</button>
        <button
          type="button"
          className="btn secondary"
          onClick={() => {
            onTenant(goodTenant.tenant);
            onPolicies(goodTenant.policies);
          }}
        >
          Load sample: known-good
        </button>
        <button
          type="button"
          className="btn secondary"
          onClick={() => {
            onTenant(weakTenant.tenant);
            onPolicies(weakTenant.policies);
          }}
        >
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

      {policies.length === 0 && <p className="muted">No policies yet. Create a policy, or import a JSON file.</p>}
      {policies.map((p) => (
        <article className="card policy-card" key={p.id}>
          <div>
            <h3>{p.displayName}</h3>
            <div className="meta">{p.id}</div>
          </div>
          <div className="actions" style={{ margin: 0 }}>
            <span className={`badge ${STATE_CLASS[p.state]}`}>{STATE_LABEL[p.state]}</span>
            <button type="button" className="btn secondary" onClick={() => onEdit(p)}>Edit</button>
            <button type="button" className="btn danger" onClick={() => onPolicies(policies.filter((x) => x.id !== p.id))}>
              Delete
            </button>
          </div>
        </article>
      ))}
    </section>
  );
}
