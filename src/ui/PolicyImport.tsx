import { useState } from 'react';
import { parseImport } from '../model/importPolicies';
import type { CAPolicy, TenantProfile } from '../model/types';

interface Props {
  onImport: (policies: CAPolicy[], options: { tenant?: TenantProfile; replace: boolean }) => void;
}

export function PolicyImport({ onImport }: Props) {
  const [text, setText] = useState('');
  const [replace, setReplace] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [notes, setNotes] = useState<string[]>([]);
  const [ok, setOk] = useState('');

  function apply(raw: string) {
    let tenant: TenantProfile | undefined;
    try {
      const parsed = JSON.parse(raw) as { tenant?: TenantProfile };
      if (parsed && typeof parsed === 'object' && parsed.tenant) tenant = parsed.tenant;
    } catch {
      /* parseImport reports JSON errors */
    }
    const result = parseImport(raw);
    setErrors(result.errors);
    setNotes(result.notes);
    if (result.policies.length === 0) {
      setOk('');
      return;
    }
    onImport(result.policies, { tenant, replace });
    setOk(
      `${replace ? 'Replaced with' : 'Added'} ${result.policies.length} ${result.policies.length === 1 ? 'policy' : 'policies'}.`,
    );
  }

  return (
    <div className="card">
      <h3>Import a JSON file</h3>
      <p className="muted">
        Choose a file exported from this app, or a Graph response from <code>GET /identity/conditionalAccess/policies</code>.
      </p>
      <label className="btn" style={{ cursor: 'pointer', display: 'inline-block' }}>
        Choose JSON file
        <input
          type="file"
          accept="application/json,.json"
          hidden
          aria-label="Policy JSON file"
          onChange={async (e) => {
            const file = e.target.files?.[0];
            if (!file) return;
            const raw = await file.text();
            setText(raw);
            apply(raw);
            e.target.value = '';
          }}
        />
      </label>
      <details className="import-paste">
        <summary>Or paste JSON</summary>
      <textarea
        className="search"
        rows={8}
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="{ }"
        aria-label="Policy JSON"
      />
      <label className="check">
        <input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} />
        Replace existing policies
      </label>
      <div className="actions">
        <button type="button" className="btn secondary" onClick={() => apply(text)} disabled={!text.trim()}>
          Import pasted JSON
        </button>
      </div>
      </details>
      {ok && <p className="ok">{ok}</p>}
      {errors.map((err) => <p className="error" key={err}>{err}</p>)}
      {notes.map((n) => <p className="warn" key={n}>{n}</p>)}
    </div>
  );
}
