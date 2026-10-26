import { CONTROLS, SURFACES } from '../catalog/surfaces';
import type { CoverageMatrix, MatrixCell, Population } from '../model/types';
import { CELL_LABEL, POP_LABEL } from './labels';

interface Props {
  matrices: Record<Population, CoverageMatrix>;
  population: Population;
  onPopulation: (p: Population) => void;
  selected: MatrixCell | null;
  onSelect: (cell: MatrixCell | null) => void;
}

export function HeatMap({ matrices, population, onPopulation, selected, onSelect }: Props) {
  const matrix = matrices[population];

  return (
    <div>
      <div className="tabs" role="tablist" aria-label="Population">
        {(Object.keys(POP_LABEL) as Population[]).map((p) => (
          <button
            type="button"
            key={p}
            role="tab"
            aria-selected={p === population}
            className={p === population ? 'current' : ''}
            onClick={() => onPopulation(p)}
          >
            {POP_LABEL[p]}
          </button>
        ))}
      </div>
      <div className="legend">
        <span><i className="swatch covered" /> Covered</span>
        <span><i className="swatch partial" /> Partial</span>
        <span><i className="swatch gap" /> Gap</span>
        <span><i className="swatch requiresLicense" /> Needs license</span>
        <span><i className="swatch na" /> Not applicable</span>
      </div>
      <div className="heat-wrap">
        <table className="heat">
          <thead>
            <tr>
              <th>Resource</th>
              {CONTROLS.map((c) => <th key={c.id}>{c.label}</th>)}
            </tr>
          </thead>
          <tbody>
            {SURFACES.map((s) => (
              <tr key={s.id}>
                <th scope="row" title={s.description}>{s.label}</th>
                {CONTROLS.map((c) => {
                  const cell = matrix.cells.find((x) => x.surface === s.id && x.control === c.id);
                  const state = cell?.state ?? 'gap';
                  return (
                    <td key={c.id}>
                      <button
                        type="button"
                        className={state}
                        data-state={state}
                        disabled={state === 'na'}
                        aria-label={`${s.label}, ${c.label}: ${CELL_LABEL[state]}`}
                        onClick={() => cell && onSelect(cell)}
                      >
                        {CELL_LABEL[state]}
                      </button>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selected && (
        <div className="cell-detail">
          <strong>{SURFACES.find((s) => s.id === selected.surface)?.label} · {CONTROLS.find((c) => c.id === selected.control)?.label}</strong>
          <p>{CELL_LABEL[selected.state]}</p>
          {selected.reasons.map((r) => <p className="muted" key={r}>{r}</p>)}
          {selected.policyIds.length > 0 && (
            <p className="muted">Policies: {selected.policyIds.join(', ')}</p>
          )}
          <button type="button" className="btn secondary" onClick={() => onSelect(null)}>Close</button>
        </div>
      )}
    </div>
  );
}
