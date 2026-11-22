import { useMemo, useState } from 'react';
import { analyze } from '../engine/analyze';
import { findingsForCell } from '../engine/cellFindings';
import { scoreDeductions } from '../engine/score';
import type { CAPolicy, MatrixCell, Population, TenantProfile } from '../model/types';
import { FindingsList } from './FindingsList';
import { HeatMap } from './HeatMap';
import { SEVERITY_LABEL } from './labels';

interface Props {
  policies: CAPolicy[];
  tenant: TenantProfile;
}

export function AnalysisView({ policies, tenant }: Props) {
  const result = useMemo(() => analyze(policies, tenant), [policies, tenant]);
  const deductions = useMemo(() => scoreDeductions(result.findings), [result.findings]);
  const hiddenDeductions = deductions.slice(8);
  const [population, setPopulation] = useState<Population>('allUsers');
  const [selected, setSelected] = useState<MatrixCell | null>(null);
  const counts = useMemo(() => {
    const open = result.findings.filter((f) => f.status === 'gap' || f.status === 'partial');
    return {
      critical: open.filter((f) => f.severity === 'critical').length,
      high: open.filter((f) => f.severity === 'high').length,
    };
  }, [result.findings]);

  return (
    <section>
      <header className="step-head">
        <p className="kicker">Step 3 of 4</p>
        <h2>Analysis</h2>
        <p className="lede">
          Coverage is scored per population. Green is enforced, amber is partial (report-only or weakened),
          red is a gap. Select a cell for the policies and reasons behind it.
        </p>
      </header>

      {policies.length === 0 && (
        <p className="warn">No policies loaded. Import JSON or load a sample on the Policies step, then come back.</p>
      )}

      <div className="score-panel">
        <div className="score-block">
          <p className="kicker">Coverage score</p>
          <p className="score" aria-label={`Score ${result.score}`}>
            {result.score}<span className="score-of">/100</span>
          </p>
          <div className="score-meter" aria-hidden="true"><span style={{ width: `${result.score}%` }} /></div>
          <dl className="score-facts">
            <div><dt>Policies</dt><dd>{policies.length}</dd></div>
            <div><dt>{SEVERITY_LABEL.critical}</dt><dd className="critical">{counts.critical}</dd></div>
            <div><dt>{SEVERITY_LABEL.high}</dt><dd className="high">{counts.high}</dd></div>
            <div><dt>Catalog</dt><dd>{result.catalogDate}</dd></div>
          </dl>
        </div>
        {deductions.length > 0 && (
          <div className="deductions-block">
            <h3>What lowered the score</h3>
            <ul className="deductions">
              {deductions.slice(0, 8).map((row) => (
                <li key={`${row.ruleId}-${row.status}`}>
                  <span className={`rule-id ${row.severity}`} title={SEVERITY_LABEL[row.severity]}>{row.ruleId}</span>
                  <span className="deduction-title">{row.title}</span>
                  <span className="points">−{row.points}</span>
                </li>
              ))}
            </ul>
            {hiddenDeductions.length > 0 && (
              <p className="deductions-remainder muted">
                {hiddenDeductions.length} more, −{hiddenDeductions.reduce((sum, row) => sum + row.points, 0)} in total. Every one is in the findings below.
              </p>
            )}
          </div>
        )}
      </div>

      <div className="block">
        <h3 className="block-title">Coverage map</h3>
        <HeatMap
          matrices={result.matrices}
          population={population}
          onPopulation={(p) => { setPopulation(p); setSelected(null); }}
          selected={selected}
          onSelect={setSelected}
          policies={policies}
          findings={result.findings}
        />
      </div>

      <FindingsList
        findings={result.findings}
        policies={policies}
        pinnedRuleIds={selected ? findingsForCell(selected, result.findings).map((f) => f.ruleId) : undefined}
      />

      <div className="block manual-checks">
        <h3 className="block-title">Verify manually</h3>
        <p className="muted">These checks need directory data that is not in the policy JSON.</p>
        <ol className="check-list">
          {result.manualChecks.map((c) => (
            <li key={c.id}>
              <strong>{c.title}</strong>
              <p>{c.why}</p>
              <p className="muted">Where: {c.where}</p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
