import { Fragment, useEffect, useRef } from 'react';
import { CONTROLS, SURFACES } from '../catalog/surfaces';
import { findingsForCell } from '../engine/cellFindings';
import type { CAPolicy, CellState, CoverageMatrix, Finding, MatrixCell, Population } from '../model/types';
import { CELL_GLYPH, CELL_LABEL, CONTROL_SHORT, POP_LABEL, SEVERITY_LABEL, SURFACE_SHORT } from './labels';

interface Props {
  matrices: Record<Population, CoverageMatrix>;
  population: Population;
  onPopulation: (p: Population) => void;
  selected: MatrixCell | null;
  onSelect: (cell: MatrixCell | null) => void;
  policies: CAPolicy[];
  findings: Finding[];
}

const LEGEND: CellState[] = ['covered', 'partial', 'gap', 'requiresLicense', 'na'];
const LEGEND_LABEL: Record<CellState, string> = {
  covered: 'Covered',
  partial: 'Partial',
  gap: 'Gap',
  requiresLicense: 'Needs license',
  na: 'Not applicable',
};

export function HeatMap({ matrices, population, onPopulation, selected, onSelect, policies, findings }: Props) {
  const matrix = matrices[population];
  const related = selected ? findingsForCell(selected, findings) : [];
  const detailRef = useRef<HTMLDivElement>(null);

  // On a phone the detail can open below the fold. Bring it into view.
  useEffect(() => {
    const el = detailRef.current;
    if (!el || typeof el.scrollIntoView !== 'function') return;
    const box = el.getBoundingClientRect();
    if (box.bottom > window.innerHeight) el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [selected]);

  const isSelected = (surface: string, control: string) =>
    !!selected && selected.surface === surface && selected.control === control;

  return (
    <div className="heatmap">
      <div className="heat-toolbar">
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
        <ul className="legend" aria-label="Legend">
          {LEGEND.map((s) => (
            <li key={s}><i className={`swatch ${s}`} aria-hidden="true">{CELL_GLYPH[s]}</i>{LEGEND_LABEL[s]}</li>
          ))}
        </ul>
      </div>
      <table className={`heat${selected ? ' has-detail' : ''}`}>
        <caption className="visually-hidden">Coverage for {POP_LABEL[population]}. Rows are resources, columns are controls.</caption>
        <thead>
          <tr>
            <th scope="col" className="heat-corner">Resource</th>
            {CONTROLS.map((c) => (
              <th scope="col" key={c.id} title={c.label}>
                <span className="full">{c.label}</span>
                <span className="short" aria-hidden="true">{CONTROL_SHORT[c.id]}</span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {SURFACES.map((s) => {
            const rowOpen = selected?.surface === s.id;
            return (
              <Fragment key={s.id}>
                <tr className={rowOpen ? 'row-open' : undefined}>
                  <th scope="row" title={s.description}>
                    <span className="full">{s.label}</span>
                    <span className="short" aria-hidden="true">{SURFACE_SHORT[s.id]}</span>
                  </th>
                  {CONTROLS.map((c) => {
                    const cell = matrix.cells.find((x) => x.surface === s.id && x.control === c.id);
                    const state = cell?.state ?? 'gap';
                    const on = isSelected(s.id, c.id);
                    return (
                      <td key={c.id}>
                        <button
                          type="button"
                          className={`cell ${state}${on ? ' selected' : ''}`}
                          data-state={state}
                          disabled={state === 'na'}
                          aria-pressed={state === 'na' ? undefined : on}
                          aria-label={`${s.label}, ${c.label}: ${CELL_LABEL[state]}`}
                          onClick={() => cell && onSelect(on ? null : cell)}
                        >
                          <span className="cell-text" aria-hidden="true">{CELL_LABEL[state]}</span>
                          <span className="cell-glyph" aria-hidden="true">{CELL_GLYPH[state]}</span>
                        </button>
                      </td>
                    );
                  })}
                </tr>
                {rowOpen && selected && (
                  <tr className="cell-detail-row">
                    <td colSpan={CONTROLS.length + 1}>
                      <div className="cell-detail" ref={detailRef} role="region" aria-label="Cell detail">
                        <div className="cell-detail-head">
                          <p className="kicker">{s.label}</p>
                          <button type="button" className="text-btn" onClick={() => onSelect(null)}>Close</button>
                        </div>
                        <h4>
                          {CONTROLS.find((c) => c.id === selected.control)?.label}
                          <span className={`badge ${selected.state}`}>{CELL_LABEL[selected.state]}</span>
                        </h4>
                        {selected.reasons.length > 0 && (
                          <ul className="reasons">
                            {selected.reasons.map((r) => <li key={r}>{r}</li>)}
                          </ul>
                        )}
                        {selected.policyIds.length > 0 && (
                          <>
                            <p className="subhead">Policies</p>
                            <ul className="cell-policies">
                              {selected.policyIds.map((id) => (
                                <li key={id}>{policies.find((p) => p.id === id)?.displayName ?? id}</li>
                              ))}
                            </ul>
                          </>
                        )}
                        {related.length > 0 && (
                          <>
                            <p className="subhead">Related findings</p>
                            <ul className="related">
                              {related.map((finding) => (
                                <li key={finding.ruleId}>
                                  <span className={`rule-id ${finding.severity}`} title={SEVERITY_LABEL[finding.severity]}>{finding.ruleId}</span>
                                  <span>{finding.title}</span>
                                </li>
                              ))}
                            </ul>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
