import type { CAPolicy } from '../model/types';
import { isPhishResistant } from '../catalog/authStrengths';

export type Strength = 'full' | 'partial' | 'none';

export const isEnforced = (p: CAPolicy) => p.state === 'enabled';
export const isReportOnly = (p: CAPolicy) => p.state === 'enabledForReportingButNotEnforced';
export const isActive = (p: CAPolicy) => isEnforced(p) || isReportOnly(p);
export const hasControl = (p: CAPolicy, c: string) => !!p.grantControls?.builtInControls.includes(c);
export const isBlock = (p: CAPolicy) => hasControl(p, 'block');
export const includesAllUsers = (p: CAPolicy) => p.conditions.users.includeUsers.includes('All');
export const includesAllApps = (p: CAPolicy) => p.conditions.applications.includeApplications.includes('All');

const clientTypes = (p: CAPolicy) => p.conditions.clientAppTypes;

export function coversLegacyClients(p: CAPolicy): Strength {
  const types = clientTypes(p);
  if (types.includes('all')) return 'full';
  const eas = types.includes('exchangeActiveSync') || types.includes('easSupported');
  const other = types.includes('other');
  if (eas && other) return 'full';
  return eas || other ? 'partial' : 'none';
}

export function coversModernClients(p: CAPolicy): boolean {
  const types = clientTypes(p);
  return types.includes('all') || (types.includes('browser') && types.includes('mobileAppsAndDesktopClients'));
}

/** Grant alternatives as a list: AND → [controls], OR → each control alone. Auth strength counts as one control 'authStrength'. */
export function grantAlternatives(p: CAPolicy): string[][] {
  const g = p.grantControls;
  if (!g) return [];
  const controls = [...g.builtInControls];
  if (g.authenticationStrength) controls.push('authStrength');
  if (g.termsOfUse.length) controls.push('termsOfUse');
  if (g.customAuthenticationFactors.length) controls.push('customControl');
  if (!controls.length) return [];
  return g.operator === 'AND' ? [controls] : controls.map(c => [c]);
}

function strength(p: CAPolicy, satisfies: (control: string) => boolean): Strength {
  const alts = grantAlternatives(p);
  const hits = alts.filter(alt => alt.some(satisfies)).length;
  if (!alts.length || hits === 0) return 'none';
  return hits === alts.length ? 'full' : 'partial';
}

/** A custom strength that reports a non-MFA requirement is not treated as MFA. */
const strengthIsMfa = (p: CAPolicy) => {
  const req = p.grantControls?.authenticationStrength?.requirementsSatisfied;
  return req === undefined || req.toLowerCase() === 'mfa';
};

export function mfaStrength(p: CAPolicy): Strength {
  return strength(p, c => c === 'mfa' || (c === 'authStrength' && strengthIsMfa(p)));
}

export function phishStrength(p: CAPolicy): Strength {
  return strength(p, c => c === 'authStrength' && isPhishResistant(p.grantControls?.authenticationStrength ?? null));
}

export function managedDeviceStrength(p: CAPolicy): Strength {
  return strength(p, c => c === 'compliantDevice' || c === 'domainJoinedDevice');
}

/** Conditions that remove the policy from being a baseline: risk, insider risk, auth flows, SP-only. */
export function isRiskOrFlowScoped(p: CAPolicy): boolean {
  const c = p.conditions;
  const sp = c.clientApplications;
  return c.signInRiskLevels.length > 0
    || c.userRiskLevels.length > 0
    || c.servicePrincipalRiskLevels.length > 0
    || c.insiderRiskLevels.length > 0
    || (c.authenticationFlows?.transferMethods.length ?? 0) > 0
    || (sp?.includeServicePrincipals.length ?? 0) > 0
    || (sp?.includeAgentIdServicePrincipals?.length ?? 0) > 0;
}

export const CLIENT_TYPES_REASON = 'does not cover browser and modern clients';

const LOCATION_LABELS: Record<string, string> = { All: 'All locations', AllTrusted: 'All trusted locations' };
const locationLabel = (id: string) => LOCATION_LABELS[id] ?? id;

/** Narrowing conditions that make coverage partial; returns human-readable reasons. */
export function narrowingReasons(p: CAPolicy): string[] {
  const { locations, platforms, devices } = p.conditions;
  const reasons: string[] = [];
  if (locations) {
    const inc = locations.includeLocations;
    if (inc.length && !inc.includes('All')) reasons.push(`only includes locations: ${inc.map(locationLabel).join(', ')}`);
    if (locations.excludeLocations.length) reasons.push(`excludes locations: ${locations.excludeLocations.map(locationLabel).join(', ')}`);
  }
  if (platforms) {
    const inc = platforms.includePlatforms;
    if (inc.length && !inc.includes('all')) reasons.push(`only includes platforms: ${inc.join(', ')}`);
    if (platforms.excludePlatforms.length) reasons.push(`excludes platforms: ${platforms.excludePlatforms.join(', ')}`);
  }
  if (!coversModernClients(p)) reasons.push(CLIENT_TYPES_REASON);
  const filter = devices?.deviceFilter;
  if (filter) reasons.push(`device filter (${filter.mode}: ${filter.rule})`);
  return reasons;
}
