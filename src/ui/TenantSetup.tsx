import type { TenantProfile } from '../model/types';
import { LICENSE_FIELDS, linesOf } from './labels';

interface Props {
  tenant: TenantProfile;
  onChange: (tenant: TenantProfile) => void;
}

export function TenantSetup({ tenant, onChange }: Props) {
  const names = Object.entries(tenant.displayNames);

  return (
    <section>
      <p className="kicker">Step 1</p>
      <h2>Tenant setup</h2>
      <p className="lede">
        Tell the evaluator which licenses you have and which accounts are break-glass.
        Findings that need a license you do not have are marked “requires upgrade” instead of a gap.
      </p>

      <div className="card">
        <h3>Licenses</h3>
        {LICENSE_FIELDS.map((f) => (
          <label className="check" key={f.key}>
            <input
              type="checkbox"
              checked={tenant.licenses[f.key]}
              onChange={(e) =>
                onChange({ ...tenant, licenses: { ...tenant.licenses, [f.key]: e.target.checked } })
              }
            />
            {f.label}
          </label>
        ))}
      </div>

      <div className="card">
        <label className="field">
          Break-glass account IDs or UPNs
          <textarea
            rows={4}
            value={tenant.breakGlass.join('\n')}
            onChange={(e) => onChange({ ...tenant, breakGlass: linesOf(e.target.value) })}
            placeholder="One object ID or UPN per line"
          />
        </label>
        <p className="muted">These identities are treated as the only acceptable exclusions on baseline policies.</p>
      </div>

      <div className="card">
        <h3>Friendly names (optional)</h3>
        <p className="muted">Map group, user, or role GUIDs to names so the report is readable.</p>
        {names.map(([id, name], i) => (
          <div className="grid-2" key={`${id}-${i}`}>
            <label className="field">
              Object ID
              <input
                value={id}
                onChange={(e) => {
                  const next = { ...tenant.displayNames };
                  delete next[id];
                  next[e.target.value] = name;
                  onChange({ ...tenant, displayNames: next });
                }}
              />
            </label>
            <label className="field">
              Display name
              <input
                value={name}
                onChange={(e) => onChange({ ...tenant, displayNames: { ...tenant.displayNames, [id]: e.target.value } })}
              />
            </label>
          </div>
        ))}
        <button
          type="button"
          className="btn secondary"
          onClick={() => onChange({ ...tenant, displayNames: { ...tenant.displayNames, '': '' } })}
        >
          Add name
        </button>
      </div>
    </section>
  );
}
