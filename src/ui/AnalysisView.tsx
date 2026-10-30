import { useMemo, useState } from 'react';
import { analyze } from '../engine/analyze';
import { findingsForCell } from '../engine/cellFindings';
import { scoreDeductions } from '../engine/score';
import type { CAPolicy, MatrixCell, Population, TenantProfile } from '../model/types';
import { FindingsList } from './FindingsList';
import { HeatMap } from './HeatMap';

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

  return (
    <section>
      <p className="kicker">Step 3</p>
      <h2>Analysis</h2>
      <p className="lede">
        Coverage is scored per population. Green is enforced coverage, amber is partial (report-only or weakened),
        red is a gap. Click a cell for the policies and reasons behind it.
      </p>
      <div className="score-row">
        <div className="score-block">
          <p className="kicker">Coverage score</p>
          <p className="score" aria-label={`Score ${result.score}`}>
            {result.score}<span className="score-of">/100</span>
          </p>
        </div>
        <p className="muted">{policies.length} {policies.length === 1 ? 'policy' : 'policies'} · catalog {result.catalogDate}</p>
      </div>
      {deductions.length > 0 && (
        <div className="card">
          <h3>What lowered the score</h3>
          <ul className="deductions">
            {deductions.slice(0, 8).map((row) => (
              <li key={`${row.ruleId}-${row.status}`}>
                <span className={`badge ${row.severity}`}>{row.ruleId}</span>
                <span>{row.title}</span>
                <span className="muted">−{row.points}</span>
              </li>
            ))}
          </ul>
          {hiddenDeductions.length > 0 && (
            <p className="deductions-remainder muted">
              {hiddenDeductions.length} more, −{hiddenDeductions.reduce((sum, row) => sum + row.points, 0)}
            </p>
          )}
        </div>
      )}
      {policies.length === 0 && (
        <p className="warn">No policies loaded. Import JSON or load a sample on the Policies step, then come back.</p>
      )}
      <HeatMap
        matrices={result.matrices}
        population={population}
        onPopulation={setPopulation}
        selected={selected}
        onSelect={setSelected}
        policies={policies}
        findings={result.findings}
      />
      <FindingsList
        findings={result.findings}
        policies={policies}
        pinnedRuleIds={selected ? findingsForCell(selected, result.findings).map((f) => f.ruleId) : undefined}
      />
      <div className="card manual-checks">
        <h3>Verify manually</h3>
        <p className="muted">These checks need directory data that is not in the policy JSON.</p>
        <ol>
          {result.manualChecks.map((c) => (
            <li key={c.id}>
              <strong>{c.title}</strong>
              <div className="muted">{c.why}</div>
              <div className="muted">Where: {c.where}</div>
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
