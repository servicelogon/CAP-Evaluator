import type {
  AuthStrengthRef, CAApplications, CAClientApplications, CAConditions, CAGrantControls, CAPolicy,
  CASessionControls, CAUsers, GuestsOrExternalUsers, PolicyState,
} from './types';

type Obj = Record<string, unknown>;

export class PolicyValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PolicyValidationError';
  }
}

const POLICY_STATES: readonly PolicyState[] = ['enabled', 'disabled', 'enabledForReportingButNotEnforced'];
const KNOWN_KEYS = new Set([
  'id', 'displayName', 'state', 'templateId', 'conditions', 'grantControls', 'sessionControls',
  'createdDateTime', 'modifiedDateTime', 'deletedDateTime', 'partialEnablementStrategy', 'description',
]);
const GUID = /^[0-9a-f-]{36}$/i;

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const asObj = (v: unknown): Obj | null => (isObj(v) ? v : null);
const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const bool = (v: unknown): boolean => v === true;

function strArr(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string');
  if (typeof v === 'string' && v !== '') return [v];
  return [];
}

const lowerGuid = (s: string): string => (GUID.test(s) ? s.toLowerCase() : s);
const ids = (v: unknown): string[] => strArr(v).map(lowerGuid);

/** Graph flag enums may arrive as comma-separated strings; `none` means no value. */
export function splitFlags(v: unknown): string[] {
  const parts = typeof v === 'string' ? v.split(',') : strArr(v);
  return parts.map((s) => s.trim()).filter((s) => s !== '' && s !== 'none');
}

function includeExcludeFilter(v: unknown): { mode: 'include' | 'exclude'; rule: string } | null {
  const o = asObj(v);
  if (!o) return null;
  const rule = str(o.rule);
  if (rule === undefined) return null;
  return { mode: o.mode === 'exclude' ? 'exclude' : 'include', rule };
}

function guests(v: unknown): GuestsOrExternalUsers | null {
  const o = asObj(v);
  if (!o) return null;
  const t = asObj(o.externalTenants);
  let externalTenants: GuestsOrExternalUsers['externalTenants'] = null;
  if (t) {
    const kind = t.membershipKind;
    const membershipKind = kind === 'all' || kind === 'enumerated' || kind === 'unknownFutureValue'
      ? kind
      : Array.isArray(t.members) ? 'enumerated' : 'all';
    externalTenants = Array.isArray(t.members) ? { membershipKind, members: ids(t.members) } : { membershipKind };
  }
  return { guestOrExternalUserTypes: splitFlags(o.guestOrExternalUserTypes), externalTenants };
}

function users(o: Obj): CAUsers {
  return {
    includeUsers: ids(o.includeUsers), excludeUsers: ids(o.excludeUsers),
    includeGroups: ids(o.includeGroups), excludeGroups: ids(o.excludeGroups),
    includeRoles: ids(o.includeRoles), excludeRoles: ids(o.excludeRoles),
    includeGuestsOrExternalUsers: guests(o.includeGuestsOrExternalUsers),
    excludeGuestsOrExternalUsers: guests(o.excludeGuestsOrExternalUsers),
  };
}

function applications(o: Obj): CAApplications {
  return {
    includeApplications: ids(o.includeApplications), excludeApplications: ids(o.excludeApplications),
    includeUserActions: strArr(o.includeUserActions),
    includeAuthenticationContextClassReferences: strArr(o.includeAuthenticationContextClassReferences),
    applicationFilter: includeExcludeFilter(o.applicationFilter),
  };
}

function clientApplications(v: unknown): CAClientApplications | null {
  const o = asObj(v);
  if (!o) return null;
  const f = asObj(o.servicePrincipalFilter);
  const rule = f ? str(f.rule) : undefined;
  const out: CAClientApplications = {
    includeServicePrincipals: ids(o.includeServicePrincipals),
    excludeServicePrincipals: ids(o.excludeServicePrincipals),
    servicePrincipalFilter: f && rule !== undefined ? { mode: str(f.mode) ?? 'include', rule } : null,
  };
  if (o.includeAgentIdServicePrincipals !== undefined) out.includeAgentIdServicePrincipals = ids(o.includeAgentIdServicePrincipals);
  return out;
}

function conditions(c: Obj, u: Obj, a: Obj): CAConditions {
  const platforms = asObj(c.platforms);
  const locations = asObj(c.locations);
  const devices = asObj(c.devices);
  const flows = asObj(c.authenticationFlows);
  const clientAppTypes = strArr(c.clientAppTypes);
  return {
    users: users(u),
    applications: applications(a),
    clientApplications: clientApplications(c.clientApplications),
    clientAppTypes: clientAppTypes.length ? clientAppTypes : ['all'],
    platforms: platforms ? { includePlatforms: strArr(platforms.includePlatforms), excludePlatforms: strArr(platforms.excludePlatforms) } : null,
    locations: locations ? { includeLocations: ids(locations.includeLocations), excludeLocations: ids(locations.excludeLocations) } : null,
    devices: devices ? { deviceFilter: includeExcludeFilter(devices.deviceFilter) } : null,
    signInRiskLevels: strArr(c.signInRiskLevels),
    userRiskLevels: strArr(c.userRiskLevels),
    servicePrincipalRiskLevels: strArr(c.servicePrincipalRiskLevels),
    insiderRiskLevels: splitFlags(c.insiderRiskLevels),
    authenticationFlows: flows ? { transferMethods: splitFlags(flows.transferMethods) } : null,
  };
}

function authStrength(v: unknown): AuthStrengthRef | null {
  const o = asObj(v);
  if (!o) return null;
  const out: AuthStrengthRef = { id: lowerGuid(str(o.id) ?? '') };
  const displayName = str(o.displayName);
  if (displayName !== undefined) out.displayName = displayName;
  if (Array.isArray(o.allowedCombinations)) out.allowedCombinations = strArr(o.allowedCombinations);
  const req = str(o.requirementsSatisfied);
  if (req !== undefined) out.requirementsSatisfied = req;
  return out;
}

function grantControls(v: unknown): CAGrantControls | null {
  const o = asObj(v);
  if (!o) return null;
  return {
    operator: str(o.operator)?.toUpperCase() === 'AND' ? 'AND' : 'OR',
    builtInControls: strArr(o.builtInControls),
    customAuthenticationFactors: strArr(o.customAuthenticationFactors),
    termsOfUse: ids(o.termsOfUse),
    authenticationStrength: authStrength(o.authenticationStrength),
  };
}

function signInFrequency(v: unknown): CASessionControls['signInFrequency'] {
  const o = asObj(v);
  if (!o) return null;
  const out: NonNullable<CASessionControls['signInFrequency']> = { isEnabled: bool(o.isEnabled) };
  if (o.type === 'days' || o.type === 'hours' || o.type === null) out.type = o.type;
  if (typeof o.value === 'number' || o.value === null) out.value = o.value;
  if (o.frequencyInterval === 'timeBased' || o.frequencyInterval === 'everyTime') out.frequencyInterval = o.frequencyInterval;
  const authType = str(o.authenticationType);
  if (authType !== undefined) out.authenticationType = authType;
  return out;
}

function sessionControls(v: unknown): CASessionControls | null {
  const o = asObj(v);
  if (!o) return null;
  const enabledOnly = (x: unknown) => { const s = asObj(x); return s ? { isEnabled: bool(s.isEnabled) } : null; };
  const mcas = asObj(o.cloudAppSecurity);
  const cloudAppSecurityType = mcas ? str(mcas.cloudAppSecurityType) : undefined;
  const browser = asObj(o.persistentBrowser);
  const cae = asObj(o.continuousAccessEvaluation);
  return {
    applicationEnforcedRestrictions: enabledOnly(o.applicationEnforcedRestrictions),
    cloudAppSecurity: mcas
      ? { isEnabled: bool(mcas.isEnabled), ...(cloudAppSecurityType !== undefined && { cloudAppSecurityType }) }
      : null,
    signInFrequency: signInFrequency(o.signInFrequency),
    persistentBrowser: browser ? { isEnabled: bool(browser.isEnabled), mode: browser.mode === 'always' ? 'always' : 'never' } : null,
    continuousAccessEvaluation: cae && typeof cae.mode === 'string' ? { mode: cae.mode } : null,
    secureSignInSession: enabledOnly(o.secureSignInSession),
    disableResilienceDefaults: typeof o.disableResilienceDefaults === 'boolean' ? o.disableResilienceDefaults : null,
  };
}

export function normalizePolicy(raw: unknown, index: number): { policy: CAPolicy; notes: string[] } {
  if (!isObj(raw)) throw new PolicyValidationError(`Policy ${index + 1}: expected a JSON object`);
  const displayName = str(raw.displayName) || `Policy ${index + 1}`;
  const c = asObj(raw.conditions);
  const u = c && asObj(c.users);
  const a = c && asObj(c.applications);
  if (!c || !u) throw new PolicyValidationError(`${displayName}: missing conditions.users`);
  if (!a) throw new PolicyValidationError(`${displayName}: missing conditions.applications`);

  const notes: string[] = [];
  let state: PolicyState = 'disabled';
  if (POLICY_STATES.includes(raw.state as PolicyState)) state = raw.state as PolicyState;
  else notes.push(`Invalid state ${JSON.stringify(raw.state ?? null)}; treated as disabled`);

  const extra: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (!KNOWN_KEYS.has(k) && !k.startsWith('@odata')) extra[k] = v;
  }
  const extraKeys = Object.keys(extra);
  if (extraKeys.length) notes.push(`Unknown properties preserved: ${extraKeys.join(', ')}`);

  const policy: CAPolicy = {
    id: str(raw.id) || crypto.randomUUID(),
    displayName,
    state,
    conditions: conditions(c, u, a),
    grantControls: grantControls(raw.grantControls),
    sessionControls: sessionControls(raw.sessionControls),
  };
  if (typeof raw.templateId === 'string' || raw.templateId === null) policy.templateId = raw.templateId;
  if (extraKeys.length) policy.extra = extra;
  return { policy, notes };
}
