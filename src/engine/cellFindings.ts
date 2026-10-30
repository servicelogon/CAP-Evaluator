import type { SurfaceId } from '../catalog/apps';
import type { ControlId } from '../catalog/surfaces';
import type { Finding, MatrixCell } from '../model/types';

const CONTROL_RULES: Record<ControlId, readonly string[]> = {
  legacyBlocked: ['BAS-01', 'BAS-02'],
  mfa: ['BAS-03', 'BAS-07', 'ADM-02', 'APP-07', 'WEK-04', 'WEK-05'],
  phishResistant: ['ADM-01', 'WEK-05'],
  managedDevice: ['BAS-10', 'ADM-06', 'WEK-05', 'WEK-06'],
  deviceCodeBlocked: ['BAS-04'],
  signInRisk: ['RSK-01'],
  userRisk: ['RSK-02'],
  session: ['BAS-11', 'ADM-07', 'WEK-08'],
};

const SURFACE_RULES: Partial<Record<SurfaceId, readonly string[]>> = {
  graph: ['APP-06'],
  adminPortals: ['ADM-03', 'ADM-08'],
  azureManagement: ['ADM-04'],
  azureDevOps: ['APP-07'],
  office365: ['APP-02', 'APP-04'],
  registerSecurityInfo: ['BAS-08'],
  registerDevice: ['BAS-09'],
};

const USER_ACTION_SURFACES = new Set<SurfaceId>(['registerDevice', 'registerSecurityInfo']);

/** MFA control rules on user-action surfaces are limited to the baseline MFA finding. */
function controlRuleIds(cell: MatrixCell): readonly string[] {
  const control = cell.control as ControlId;
  const rules = CONTROL_RULES[control] ?? [];
  if (control === 'mfa' && USER_ACTION_SURFACES.has(cell.surface as SurfaceId)) {
    return rules.filter((id) => id === 'BAS-03');
  }
  return rules;
}

/** Findings whose rule id is mapped to this cell's control or surface, in input order. */
export function findingsForCell(cell: MatrixCell, findings: Finding[]): Finding[] {
  const ids = new Set<string>([
    ...controlRuleIds(cell),
    ...(SURFACE_RULES[cell.surface as SurfaceId] ?? []),
  ]);
  return findings.filter((finding) => ids.has(finding.ruleId));
}
