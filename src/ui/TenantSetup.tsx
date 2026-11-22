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
      <header className="step-head">
        <p className="kicker">Step 1 of 4</p>
        <h2>Tenant setup</h2>
        <p className="lede">
          Tell the evaluator which licenses you have and which accounts are break-glass.
          Findings that need a license you do not have are marked “needs license” instead of a gap.
        </p>
      </header>

      <div className="block">
        <h3 className="block-title">Licenses</h3>
        <div className="license-list">
        {LICENSE_FIELDS.map((f) => (
          <div className="license" key={f.key}>
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
            <p className="hint">{f.hint}</p>
          </div>
        ))}
        </div>
      </div>

      <div className="block">
        <h3 className="block-title">Break-glass accounts</h3>
        <label className="field">
          Account IDs or UPNs
          <textarea
            rows={4}
            value={tenant.breakGlass.join('\n')}
            onChange={(e) => onChange({ ...tenant, breakGlass: linesOf(e.target.value) })}
            placeholder="One object ID or UPN per line"
          />
        </label>
        <p className="muted field-note">These identities are treated as the only acceptable exclusions on baseline policies.</p>
      </div>

      <div className="block">
        <h3 className="block-title">Friendly names <span className="optional">Optional</span></h3>
        <p className="muted block-note">Map group, user, or role GUIDs to names so the report is readable.</p>
        {rows.map((item) => (
          <div className="name-row" key={item.key}>
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
              className="btn danger"
              aria-label="Remove name"
              onClick={() => publish(rows.filter((row) => row.key !== item.key))}
            >
              Remove
            </button>
          </div>
        ))}
        <button
          type="button"
          className="btn"
          onClick={() => publish([...rows, { key: newId(), id: '', name: '' }])}
        >
          <span className="plus-icon" aria-hidden="true" />Add name
        </button>
      </div>
    </section>
  );
}
