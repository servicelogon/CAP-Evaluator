import { useMemo, useState } from 'react';
import { COUNTRIES, isCountryCode, locationDisplayName } from '../catalog/locations';

interface Props {
  selected: string[];
  onChange: (ids: string[]) => void;
  kind: 'Include' | 'Exclude';
}

export function LocationPicker({ selected, onChange, kind }: Props) {
  const [query, setQuery] = useState('');
  const [namedId, setNamedId] = useState('');

  const custom = selected.filter((id) => id !== 'All' && id !== 'AllTrusted');
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matches = COUNTRIES.filter(
      (c) => !q || c.name.toLowerCase().includes(q) || c.code.toLowerCase().startsWith(q),
    );
    if (q) return matches;
    const suggested = ['US', 'GB', 'CA', 'AU', 'DE', 'FR', 'NL', 'IE', 'IN', 'JP', 'SG', 'BR', 'MX'];
    const suggestedSet = new Set(suggested);
    const byCode = new Map(matches.map((c) => [c.code, c]));
    return [
      ...suggested.map((code) => byCode.get(code)).filter((c): c is (typeof COUNTRIES)[number] => !!c),
      ...matches.filter((c) => !suggestedSet.has(c.code)),
    ];
  }, [query]);

  function toggleCountry(code: string, on: boolean) {
    const without = selected.filter((id) => id.toUpperCase() !== code);
    onChange(on ? [...without, code] : without);
  }

  function addNamed() {
    const id = namedId.trim();
    if (!id || selected.includes(id)) {
      setNamedId('');
      return;
    }
    onChange([...selected, id]);
    setNamedId('');
  }

  return (
    <div className="location-picker">
      {custom.length > 0 && (
        <div className="chips">
          {custom.map((id) => (
            <span className="chip" key={id}>
              {locationDisplayName(id)}
              <button
                type="button"
                aria-label={`Remove ${kind.toLowerCase()} ${locationDisplayName(id)}`}
                onClick={() => onChange(selected.filter((x) => x !== id))}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
      <input
        className="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search countries or regions"
        aria-label={`${kind} search countries or regions`}
      />
      <div className="app-pick location-list">
        {filtered.map((c) => (
          <label className="check" key={c.code}>
            <input
              type="checkbox"
              aria-label={`${kind} country: ${c.name}`}
              checked={selected.some((id) => id.toUpperCase() === c.code)}
              onChange={(e) => toggleCountry(c.code, e.target.checked)}
            />
            {c.name}
          </label>
        ))}
        {filtered.length === 0 && <p className="muted">No countries match that search.</p>}
      </div>
      <label className="field">
        Named location ID
        <span className="named-row">
          <input
            aria-label={`${kind} named location ID`}
            value={namedId}
            onChange={(e) => setNamedId(e.target.value)}
            placeholder="Paste a Graph named location GUID"
          />
          <button type="button" className="btn secondary" onClick={addNamed}>
            Add
          </button>
        </span>
      </label>
      {custom.some((id) => !isCountryCode(id)) && (
        <p className="muted">Named location IDs are stored as Graph object IDs.</p>
      )}
    </div>
  );
}
