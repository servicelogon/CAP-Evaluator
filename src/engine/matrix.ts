import { CONTROLS, SURFACES, isNA } from '../catalog/surfaces';
import type { CAPolicy, CellState, CoverageMatrix, MatrixCell, Population, TenantProfile } from '../model/types';
import { bestCoverage } from './coverage';

const NO_POLICY_REASON = 'No policy provides this control for this population and resource';

/** Heat-map cells for one population: every surface × control, in catalog order. */
export function buildMatrix(policies: CAPolicy[], tenant: TenantProfile, pop: Population): CoverageMatrix {
  const cells = SURFACES.flatMap(s => CONTROLS.map((c): MatrixCell => {
    if (isNA(s.id, c.id)) return { surface: s.id, control: c.id, state: 'na', policyIds: [], reasons: [] };
    const best = bestCoverage(policies, pop, s.id, c.id, tenant);
    if (best.level !== 'none') {
      const state: CellState = best.level === 'full' ? 'covered' : 'partial';
      return { surface: s.id, control: c.id, state, policyIds: best.policyIds, reasons: best.reasons };
    }
    const unlicensed = c.license !== undefined && !tenant.licenses[c.license];
    return unlicensed
      ? { surface: s.id, control: c.id, state: 'requiresLicense', policyIds: [], reasons: [`Requires ${c.licenseLabel ?? c.license}`] }
      : { surface: s.id, control: c.id, state: 'gap', policyIds: [], reasons: [NO_POLICY_REASON] };
  }));
  return { population: pop, cells };
}
