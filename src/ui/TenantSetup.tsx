import { useState } from 'react';
import type { TenantProfile } from '../model/types';
import { newId } from '../model/normalize';
import { LICENSE_FIELDS, linesOf } from './labels';

interface Props {
  tenant: TenantProfile;
  onChange: (tenant: TenantProfile) => void;
}

export function TenantSetup({ tenant, onChange }: Props) {
  const [rows, setRows] = useState<{ key: string; id: string; name: string }[]>(() =>
    Object.entries(tenant.displayNames).map(([id, name]) => ({ key: id || newId(), id, name })),
  );

  function publish(next: { key: string; id: string; name: string }[]) {
    setRows(next);
    const displayNames: Record<string, string> = {};
    for (const row of next) {
      if (row.id.trim()) displayNames[row.id.trim()] = row.name;
    }
    onChange({ ...tenant, displayNames });
  }

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
          <div key={f.key}>
            <label className="check">
              <input
                type="checkbox"
                checked={tenant.licenses[f.key]}
                onChange={(e) =>
                  onChange({ ...tenant, licenses: { ...tenant.licenses, [f.key]: e.target.checked } })
                }
              />
              {f.label}
            </label>
            <p className="muted">{f.hint}</p>
          </div>
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
        {rows.map((item) => (
          <div className="grid-2" key={item.key}>
            <label className="field">
              Object ID
              <input
                value={item.id}
                onChange={(e) =>
                  publish(rows.map((row) => (row.key === item.key ? { ...row, id: e.target.value } : row)))
                }
              />
            </label>
            <label className="field">
              Display name
              <input
                value={item.name}
                onChange={(e) =>
                  publish(rows.map((row) => (row.key === item.key ? { ...row, name: e.target.value } : row)))
                }
              />
            </label>
            <button
              type="button"
              className="btn secondary"
              aria-label="Remove name"
              onClick={() => publish(rows.filter((row) => row.key !== item.key))}
            >
              Remove
            </button>
          </div>
        ))}
        <button
          type="button"
          className="btn secondary"
          onClick={() => publish([...rows, { key: newId(), id: '', name: '' }])}
        >
          Add name
        </button>
      </div>
    </section>
  );
}
