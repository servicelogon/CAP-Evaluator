import { useMemo, useState } from 'react';
import { analyze } from '../engine/analyze';
import type { CAPolicy, MatrixCell, Population, TenantProfile } from '../model/types';
import { FindingsList } from './FindingsList';
import { HeatMap } from './HeatMap';

interface Props {
  policies: CAPolicy[];
  tenant: TenantProfile;
}

export function AnalysisView({ policies, tenant }: Props) {
  const result = useMemo(() => analyze(policies, tenant), [policies, tenant]);
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
        <p className="score" aria-label={`Score ${result.score}`}>{result.score}</p>
        <p className="muted">{policies.length} {policies.length === 1 ? 'policy' : 'policies'} · catalog {result.catalogDate}</p>
      </div>
      {policies.length === 0 && (
        <p className="warn">No policies loaded. Import JSON or load a sample on the Policies step, then come back.</p>
      )}
      <HeatMap
        matrices={result.matrices}
        population={population}
        onPopulation={setPopulation}
        selected={selected}
        onSelect={setSelected}
      />
      <FindingsList findings={result.findings} policies={policies} />
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
    </section>
  );
}
