import type { CAPolicy, Population, TenantProfile } from '../model/types';
import type { ControlId } from '../catalog/surfaces';
import { APP, ADMIN_PORTAL_IDS, OFFICE365_KEY_IDS, USER_ACTION, appLabel, lookupApp, type SurfaceId } from '../catalog/apps';
import { PRIVILEGED_ROLES, isPrivilegedRole, roleName } from '../catalog/roles';
import {
  CLIENT_TYPES_REASON, coversLegacyClients, coversModernClients, grantAlternatives, isBlock, isReportOnly,
  isRiskOrFlowScoped, managedDeviceStrength, mfaStrength, narrowingReasons, phishStrength, type Strength,
} from './predicates';

export interface Contribution { level: 'full' | 'partial' | 'reportOnly' | 'none'; reasons: string[] }

const NONE: Contribution = { level: 'none', reasons: [] };
const FULL: Contribution = { level: 'full', reasons: [] };
const partial = (...reasons: string[]): Contribution => ({ level: 'partial', reasons });
const RANK: Record<Contribution['level'], number> = { none: 0, reportOnly: 1, partial: 2, full: 3 };
const uniq = (xs: string[]) => [...new Set(xs)];
const lower = (xs: string[]) => new Set(xs.map(x => x.toLowerCase()));

// ---------- Population ----------

const GUEST_TYPES = ['internalGuest', 'b2bCollaborationGuest', 'b2bCollaborationMember', 'b2bDirectConnectUser', 'otherExternalUser', 'serviceProvider'];
const GUESTS_KEYWORD = 'guestsorexternalusers';
const GUESTS_LABEL = 'Guests or external users';
const SCOPED_REASON = 'scoped to specific groups/users/roles, not All users';
const ADMIN_GROUP_REASON = 'scoped by group; cannot verify it contains all admins';

function displayName(t: TenantProfile, id: string): string {
  const exact = t.displayNames[id];
  if (exact !== undefined) return exact;
  const key = Object.keys(t.displayNames).find(k => k.toLowerCase() === id.toLowerCase());
  return key === undefined ? id : t.displayNames[key];
}

const roleLabel = (id: string) => roleName(id) ?? id;

interface GuestExclusion { full: boolean; label: string }

function guestExclusion(p: CAPolicy): GuestExclusion | null {
  const u = p.conditions.users;
  if (u.excludeUsers.some(x => x.toLowerCase() === GUESTS_KEYWORD)) return { full: true, label: GUESTS_LABEL };
  const ex = u.excludeGuestsOrExternalUsers;
  if (!ex || !ex.guestOrExternalUserTypes.length) return null;
  const allTypes = GUEST_TYPES.every(g => ex.guestOrExternalUserTypes.includes(g));
  const allTenants = !ex.externalTenants || ex.externalTenants.membershipKind !== 'enumerated';
  if (!allTypes) return { full: false, label: `${GUESTS_LABEL} (${ex.guestOrExternalUserTypes.join(', ')})` };
  if (!allTenants) return { full: false, label: `${GUESTS_LABEL} (specific external tenants)` };
  return { full: true, label: GUESTS_LABEL };
}

interface Exclusions { people: string[]; roleIds: string[]; guest: GuestExclusion | null }

function exclusions(p: CAPolicy, t: TenantProfile): Exclusions {
  const u = p.conditions.users;
  const breakGlass = lower(t.breakGlass);
  const tolerated = (id: string) => !breakGlass.has(id.toLowerCase());
  const people = [
    ...u.excludeUsers.filter(id => id.toLowerCase() !== GUESTS_KEYWORD && tolerated(id)),
    ...u.excludeGroups.filter(tolerated),
  ].map(id => displayName(t, id));
  return { people, roleIds: u.excludeRoles, guest: guestExclusion(p) };
}

export function unexpectedExclusions(p: CAPolicy, t: TenantProfile): string[] {
  const ex = exclusions(p, t);
  return [...ex.people, ...ex.roleIds.map(roleLabel), ...(ex.guest ? [ex.guest.label] : [])];
}

const excludesReason = (labels: string[]) => `excludes ${labels.join(', ')}`;

function allUsersCoverage(p: CAPolicy, t: TenantProfile): Contribution {
  const u = p.conditions.users;
  if (u.includeUsers.includes('All')) {
    const labels = unexpectedExclusions(p, t);
    return labels.length ? partial(excludesReason(labels)) : FULL;
  }
  const scoped = u.includeUsers.some(x => x !== 'None') || u.includeGroups.length > 0 || u.includeRoles.length > 0
    || u.includeGuestsOrExternalUsers !== null;
  return scoped ? partial(SCOPED_REASON) : NONE;
}

function adminsCoverage(p: CAPolicy, t: TenantProfile): Contribution {
  const u = p.conditions.users;
  const ex = exclusions(p, t);
  const privExcluded = ex.roleIds.filter(isPrivilegedRole);
  const otherExcluded = [
    ...ex.people, ...ex.roleIds.filter(id => !isPrivilegedRole(id)).map(roleLabel), ...(ex.guest ? [ex.guest.label] : []),
  ];
  const exclusionReasons = [
    ...(privExcluded.length ? [`excludes privileged roles: ${privExcluded.map(roleLabel).join(', ')}`] : []),
    ...(otherExcluded.length ? [excludesReason(otherExcluded)] : []),
  ];
  const fullUnlessExcluded = () => (exclusionReasons.length ? partial(...exclusionReasons) : FULL);
  if (u.includeUsers.includes('All')) return fullUnlessExcluded();

  const included = lower(u.includeRoles);
  const privIncluded = PRIVILEGED_ROLES.filter(r => included.has(r.id.toLowerCase())).length;
  if (privIncluded === PRIVILEGED_ROLES.length) return fullUnlessExcluded();
  const scopeReasons = [
    ...(privIncluded ? [`covers ${privIncluded} of ${PRIVILEGED_ROLES.length} privileged roles`] : []),
    ...(u.includeGroups.length ? [ADMIN_GROUP_REASON] : []),
  ];
  return scopeReasons.length ? partial(...scopeReasons, ...exclusionReasons) : NONE;
}

function guestsCoverage(p: CAPolicy, t: TenantProfile): Contribution {
  const u = p.conditions.users;
  const ex = exclusions(p, t);
  if (ex.guest?.full) return NONE;

  let base: Contribution = NONE;
  if (u.includeUsers.includes('All') || u.includeUsers.some(x => x.toLowerCase() === GUESTS_KEYWORD)) base = FULL;
  else if (u.includeGuestsOrExternalUsers) {
    const inc = u.includeGuestsOrExternalUsers;
    const allTypes = GUEST_TYPES.every(g => inc.guestOrExternalUserTypes.includes(g));
    base = allTypes && inc.externalTenants?.membershipKind === 'all'
      ? FULL
      : partial('covers only some guest or external user types or tenants');
  }
  if (base.level === 'none') return NONE;

  const otherLabels = [...ex.people, ...ex.roleIds.map(roleLabel), ...(ex.guest ? [ex.guest.label] : [])];
  const reasons = [...base.reasons, ...(otherLabels.length ? [excludesReason(otherLabels)] : [])];
  return reasons.length ? partial(...reasons) : FULL;
}

export function populationCoverage(p: CAPolicy, pop: Population, t: TenantProfile): Contribution {
  switch (pop) {
    case 'allUsers': return allUsersCoverage(p, t);
    case 'admins': return adminsCoverage(p, t);
    case 'guests': return guestsCoverage(p, t);
  }
}

// ---------- Surface ----------

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isThirdParty = (id: string) => GUID.test(id) && !lookupApp(id);
const CORE_O365 = [APP.exchangeOnline, APP.sharePointOnline, APP.teamsServices];
const O365_IN_PORTALS = [APP.office365Portal, APP.protectionCenter];
const GRAPH_EXCLUSION_REASON = 'All resources with exclusions — verify baseline-scopes enforcement setting';
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;

export function surfaceCoverage(p: CAPolicy, s: SurfaceId): Contribution {
  const a = p.conditions.applications;
  if (s === 'registerSecurityInfo' || s === 'registerDevice') {
    return lower(a.includeUserActions).has(USER_ACTION[s]) ? FULL : NONE;
  }
  if (a.includeUserActions.length) return NONE;

  const inc = lower(a.includeApplications);
  const exc = lower(a.excludeApplications);
  const all = inc.has('all');
  const filterExcludes = a.applicationFilter?.mode === 'exclude';
  const exclusionReasons = [
    ...(exc.size ? [`excludes ${plural(exc.size, 'app')}`] : []),
    ...(filterExcludes ? ['excludes apps matching an application filter'] : []),
  ];
  const excluded = new Set(exc);
  if (exc.has('office365')) OFFICE365_KEY_IDS.forEach(id => excluded.add(id));
  if (exc.has('microsoftadminportals')) ADMIN_PORTAL_IDS.forEach(id => excluded.add(id));
  const covers = (id: string) => (all || inc.has(id)) && !excluded.has(id);

  switch (s) {
    case 'allResources':
      if (!all) return NONE;
      return exclusionReasons.length ? partial(...exclusionReasons) : FULL;

    case 'office365': {
      if (exc.has('office365')) return NONE;
      const excludedKeys = OFFICE365_KEY_IDS.filter(id => exc.has(id));
      if (all || inc.has('office365')) {
        if (CORE_O365.every(id => exc.has(id))) return NONE;
        return excludedKeys.length ? partial(`excludes Office 365 apps: ${excludedKeys.map(appLabel).join(', ')}`) : FULL;
      }
      return CORE_O365.some(id => inc.has(id) && !exc.has(id)) ? partial('targets individual workloads, not the Office 365 group') : NONE;
    }

    case 'adminPortals': {
      const included = new Set<string>(ADMIN_PORTAL_IDS.filter(id => inc.has(id)));
      if (all || inc.has('microsoftadminportals')) ADMIN_PORTAL_IDS.forEach(id => included.add(id));
      if (inc.has('office365')) O365_IN_PORTALS.forEach(id => included.add(id));
      const n = [...included].filter(id => !excluded.has(id)).length;
      if (n === ADMIN_PORTAL_IDS.length) return FULL;
      return n ? partial(`covers ${n} of ${ADMIN_PORTAL_IDS.length} admin portals`) : NONE;
    }

    case 'azureManagement': return covers(APP.azureManagement) ? FULL : NONE;
    case 'intuneApi': return covers(APP.intune) ? FULL : NONE;
    case 'azureDevOps': return covers(APP.azureDevOps) ? FULL : NONE;

    case 'graph':
      if (all) return exclusionReasons.length ? partial(GRAPH_EXCLUSION_REASON) : FULL;
      return inc.has(APP.graphExplorer) && !exc.has(APP.graphExplorer)
        ? partial('targets Graph Explorer only; other Microsoft Graph clients are covered only by All resources')
        : NONE;

    case 'thirdParty': {
      if (all) {
        const excludedApps = [...exc].filter(isThirdParty).length;
        const reasons = [
          ...(excludedApps ? [`excludes ${plural(excludedApps, 'third-party app')}`] : []),
          ...(filterExcludes ? ['excludes apps matching an application filter'] : []),
        ];
        return reasons.length ? partial(...reasons) : FULL;
      }
      const selected = [...inc].some(id => isThirdParty(id) && !exc.has(id)) || a.applicationFilter?.mode === 'include';
      return selected ? partial('covers only selected apps') : NONE;
    }
  }
}

// ---------- Control ----------

const CONTROL_LABELS: Record<string, string> = {
  block: 'block', mfa: 'MFA', compliantDevice: 'compliant device', domainJoinedDevice: 'hybrid joined device',
  approvedApplication: 'approved client app', compliantApplication: 'app protection policy', passwordChange: 'password change',
  riskRemediation: 'risk remediation', termsOfUse: 'terms of use', customControl: 'custom control',
};

function controlLabel(p: CAPolicy, c: string): string {
  if (c === 'authStrength') {
    const name = p.grantControls?.authenticationStrength?.displayName;
    return name ? `authentication strength (${name})` : 'authentication strength';
  }
  return CONTROL_LABELS[c] ?? c;
}

function alternativesReason(p: CAPolicy): string {
  const alts = grantAlternatives(p).map(alt => alt.map(c => controlLabel(p, c)).join(' AND '));
  return `Require one of: ${alts.join(' OR ')}`;
}

/** Applies narrowing reasons: full becomes partial; partial keeps its reasons plus the narrowing ones. */
function narrowed(level: Strength, reasons: string[], narrowing: string[]): Contribution {
  if (level === 'none') return NONE;
  const all = [...reasons, ...narrowing];
  return level === 'full' && !all.length ? FULL : partial(...all);
}

function otherConditionReasons(p: CAPolicy, own: 'signIn' | 'user' | 'flow'): string[] {
  const c = p.conditions;
  const reasons: string[] = [];
  if (own !== 'signIn' && c.signInRiskLevels.length) reasons.push(`only applies at sign-in risk: ${c.signInRiskLevels.join(', ')}`);
  if (own !== 'user' && c.userRiskLevels.length) reasons.push(`only applies at user risk: ${c.userRiskLevels.join(', ')}`);
  if (c.insiderRiskLevels.length) reasons.push(`only applies at insider risk: ${c.insiderRiskLevels.join(', ')}`);
  if (own !== 'flow' && c.authenticationFlows?.transferMethods.length) {
    reasons.push(`only applies to authentication flows: ${c.authenticationFlows.transferMethods.join(', ')}`);
  }
  return reasons;
}

function riskLevel(levels: string[], kind: string): { level: Strength; reasons: string[] } {
  if (levels.includes('high')) return { level: 'full', reasons: [] };
  const lesser = levels.filter(l => l === 'medium' || l === 'low');
  return lesser.length
    ? { level: 'partial', reasons: [`only applies to ${lesser.join('/')} ${kind} risk, not high`] }
    : { level: 'none', reasons: [] };
}

export function controlCoverage(p: CAPolicy, c: ControlId): Contribution {
  const narrowing = narrowingReasons(p);
  const g = p.grantControls;

  switch (c) {
    case 'legacyBlocked': {
      const legacy = coversLegacyClients(p);
      const anyGrant = !!g && (g.builtInControls.length > 0 || g.authenticationStrength !== null);
      if (legacy === 'none' || !anyGrant || isRiskOrFlowScoped(p)) return NONE;
      const types = p.conditions.clientAppTypes;
      const missing = legacy === 'partial'
        ? [types.includes('other') ? 'does not cover Exchange ActiveSync' : 'does not cover other legacy clients (IMAP, POP, SMTP, …)']
        : [];
      return narrowed(legacy, missing, narrowing.filter(r => r !== CLIENT_TYPES_REASON));
    }

    case 'deviceCodeBlocked': {
      const dcf = p.conditions.authenticationFlows?.transferMethods.includes('deviceCodeFlow');
      if (!isBlock(p) || !dcf) return NONE;
      return narrowed('full', otherConditionReasons(p, 'flow'), narrowing);
    }

    case 'signInRisk': {
      if (!isBlock(p) && mfaStrength(p) === 'none') return NONE;
      const r = riskLevel(p.conditions.signInRiskLevels, 'sign-in');
      return narrowed(r.level, [...r.reasons, ...otherConditionReasons(p, 'signIn')], narrowing);
    }

    case 'userRisk': {
      const alts = grantAlternatives(p);
      const remediates = isBlock(p) || alts.length > 0 && alts.every(alt =>
        (alt.includes('passwordChange') && alt.includes('mfa'))
        || (alt.includes('riskRemediation') && alt.includes('authStrength')));
      if (!remediates) return NONE;
      const r = riskLevel(p.conditions.userRiskLevels, 'user');
      return narrowed(r.level, [...r.reasons, ...otherConditionReasons(p, 'user')], narrowing);
    }

    case 'mfa':
    case 'phishResistant':
    case 'managedDevice': {
      if (isRiskOrFlowScoped(p) || !coversModernClients(p)) return NONE;
      if (isBlock(p)) return narrowed('full', [], narrowing);
      const fn = c === 'mfa' ? mfaStrength : c === 'phishResistant' ? phishStrength : managedDeviceStrength;
      const level = fn(p);
      return narrowed(level, level === 'partial' ? [alternativesReason(p)] : [], narrowing);
    }

    case 'session': {
      if (isRiskOrFlowScoped(p)) return NONE;
      const sc = p.sessionControls;
      const sif = !!sc?.signInFrequency?.isEnabled;
      const never = !!sc?.persistentBrowser?.isEnabled && sc.persistentBrowser.mode === 'never';
      if (sif && never) return narrowed('full', [], narrowing);
      if (sif) return narrowed('partial', ['sign-in frequency without persistent browser set to never'], narrowing);
      if (never) return narrowed('partial', ['persistent browser set to never without sign-in frequency'], narrowing);
      return NONE;
    }
  }
}

// ---------- Composition ----------

/** min of the three, then: disabled → none; report-only → full/partial downgraded to 'reportOnly'. */
export function policyContribution(p: CAPolicy, pop: Population, s: SurfaceId, c: ControlId, t: TenantProfile): Contribution {
  if (p.state === 'disabled') return NONE;
  const parts = [populationCoverage(p, pop, t), surfaceCoverage(p, s), controlCoverage(p, c)];
  const level = parts.reduce((min, x) => (RANK[x.level] < RANK[min] ? x.level : min), parts[0].level);
  if (level === 'none') return NONE;
  const reasons = uniq(parts.flatMap(x => x.reasons));
  return isReportOnly(p) ? { level: 'reportOnly', reasons: [...reasons, 'report-only (not enforced)'] } : { level, reasons };
}

/** Best contribution across policies (full > partial > reportOnly > none) with contributing policy IDs. */
export function bestCoverage(
  ps: CAPolicy[], pop: Population, s: SurfaceId, c: ControlId, t: TenantProfile,
): Contribution & { policyIds: string[] } {
  const scored = ps.map(p => ({ p, r: policyContribution(p, pop, s, c, t) }));
  const best = scored.reduce<Contribution['level']>((b, x) => (RANK[x.r.level] > RANK[b] ? x.r.level : b), 'none');
  if (best === 'none') return { level: 'none', reasons: [], policyIds: [] };
  const top = scored.filter(x => x.r.level === best);
  return { level: best, reasons: uniq(top.flatMap(x => x.r.reasons)), policyIds: top.map(x => x.p.id) };
}
