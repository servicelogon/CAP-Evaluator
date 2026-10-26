import { PRIVILEGED_ROLES, isPrivilegedRole, roleName } from '../../catalog/roles';
import type { CAPolicy } from '../../model/types';
import { controlLabel, displayName, populationCoverage, surfaceCoverage, unexpectedExclusions } from '../coverage';
import {
  coversLegacyClients, coversModernClients, grantAlternatives, hasControl, includesAllApps, includesAllUsers, isBlock,
  isEnforced, isMfaControl, isRiskOrFlowScoped, locationLabel, managedDeviceStrength, mfaStrength, phishStrength,
} from '../predicates';
import { makeFinding, perPolicyRule, policyNames, type Rule, type RuleContext, type RuleMeta } from './types';

const LEARN = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access';
const REF = {
  usersGroups: `${LEARN}/concept-conditional-access-users-groups`,
  phishAdmins: `${LEARN}/policy-admin-phish-resistant-mfa`,
  network: `${LEARN}/concept-assignment-network`,
  policies: `${LEARN}/concept-conditional-access-policies`,
  grant: `${LEARN}/concept-conditional-access-grant`,
  compliantOrMfa: `${LEARN}/policy-alt-all-users-compliant-hybrid-or-mfa`,
  conditions: `${LEARN}/concept-conditional-access-conditions`,
  unknownPlatforms: `${LEARN}/policy-all-users-device-unknown-unsupported`,
  deviceFilters: `${LEARN}/concept-condition-filters-for-devices`,
  persistentBrowser: 'https://learn.microsoft.com/en-us/graph/api/resources/persistentbrowsersessioncontrol?view=graph-rest-1.0',
  persistentBrowserPolicy: `${LEARN}/policy-all-users-persistent-browser`,
  session: `${LEARN}/concept-conditional-access-session`,
  migrateApprovedApp: `${LEARN}/migrate-approved-client-app`,
  mc1220751: 'https://mc.merill.net/message/MC1220751',
  managedPolicies: `${LEARN}/managed-policies`,
  cae: 'https://learn.microsoft.com/en-us/graph/api/resources/continuousaccessevaluationsessioncontrol?view=graph-rest-beta',
};

const lowerSet = (xs: string[]) => new Set(xs.map(x => x.toLowerCase()));
const targetsAdminRoles = (p: CAPolicy) => p.conditions.users.includeRoles.some(isPrivilegedRole);
const coversAdmins = (p: CAPolicy) => includesAllUsers(p) || targetsAdminRoles(p);
const coversAllAdminRoles = (p: CAPolicy) => {
  const roles = lowerSet(p.conditions.users.includeRoles);
  return PRIVILEGED_ROLES.every(r => roles.has(r.id.toLowerCase()));
};
const quoted = (ctx: RuleContext, p: CAPolicy) => policyNames(ctx, [p.id]);

// ---------- Device filter operators ----------

const POSITIVE_OPS = new Set(['eq', 'startswith', 'endswith', 'contains', 'in']);
const NEGATIVE_OPS = new Set(['ne', 'notin', 'notcontains', 'notstartswith', 'notendswith']);

function filterOperators(rule: string): { positive: boolean; negative: boolean } {
  const ops = [...rule.matchAll(/(?:^|[\s(])-([a-z]+)\b/gi)].map(m => m[1].toLowerCase());
  return { positive: ops.some(o => POSITIVE_OPS.has(o)), negative: ops.some(o => NEGATIVE_OPS.has(o)) };
}
const onlyPositive = (rule: string) => { const o = filterOperators(rule); return o.positive && !o.negative; };
const onlyNegative = (rule: string) => { const o = filterOperators(rule); return o.negative && !o.positive; };

// ---------- WEK-01 ----------

const WEK01: RuleMeta = {
  id: 'WEK-01', title: 'Baseline policy excludes more than break-glass accounts', family: 'weakening', severity: 'high',
  remediation: 'Reduce the exclusions to your break-glass (emergency access) accounts and record them in tenant setup. Replace service-account '
    + 'exclusions with workload identities or managed identities, cover guests instead of excluding them (for example with a guest MFA '
    + 'policy), and, where a group genuinely cannot meet the control, give it a separate policy with an alternative control rather than '
    + 'an exclusion.',
  references: [REF.usersGroups, REF.phishAdmins],
};

const protectiveGrant = (p: CAPolicy) => isBlock(p) || hasControl(p, 'mfa') || !!p.grantControls?.authenticationStrength
  || hasControl(p, 'compliantDevice') || hasControl(p, 'domainJoinedDevice');
const adminSurface = (p: CAPolicy) => surfaceCoverage(p, 'adminPortals').level !== 'none' || surfaceCoverage(p, 'azureManagement').level !== 'none';
const isBaseline = (p: CAPolicy) => coversAdmins(p) && (includesAllApps(p) || adminSurface(p)) && protectiveGrant(p);

/** The kind of policy BAS-01 (legacy block), BAS-03 (MFA for all users) or ADM-01 (phishing-resistant admins) relies on, ignoring exclusions. */
const isCoreBaseline = (p: CAPolicy) => !isRiskOrFlowScoped(p) && includesAllApps(p) && (
  (includesAllUsers(p) && ((isBlock(p) && coversLegacyClients(p) !== 'none') || (coversModernClients(p) && mfaStrength(p) === 'full')))
  || (coversAdmins(p) && coversModernClients(p) && phishStrength(p) === 'full'));

const wek01 = perPolicyRule(WEK01,
  (p, ctx) => (isBaseline(p) ? unexpectedExclusions(p, ctx.tenant) : []),
  (ctx, p, labels) => `${quoted(ctx, p)} is a baseline policy for ${includesAllUsers(p) ? 'all users' : 'administrators'} but excludes `
    + `more than break-glass accounts: ${labels.join(', ')}. Every sign-in by an excluded user, group member, role holder or guest skips `
    + 'the policy entirely, and attackers look for exactly these accounts because they are never challenged.'
    + (isCoreBaseline(p)
      ? ' This is one of the tenant\'s core protections (blocking legacy authentication, MFA for all users, or phishing-resistant MFA '
        + 'for administrators), so these exclusions are critical.'
      : ''),
  { severity: p => (isCoreBaseline(p) ? 'critical' : 'high') });

// ---------- WEK-02 ----------

const WEK02: RuleMeta = {
  id: 'WEK-02', title: 'Break-glass accounts not excluded from a policy that applies to everyone', family: 'weakening', severity: 'medium',
  remediation: 'Exclude every break-glass (emergency access) account from this policy, preferably through a dedicated group used for all '
    + 'policies, and monitor and alert on their sign-ins. Protect the accounts themselves with strong credentials such as FIDO2 security keys.',
  references: [REF.phishAdmins, REF.usersGroups],
};

const WEK02_NONE: RuleMeta = {
  ...WEK02, title: 'No break-glass accounts configured in tenant setup', severity: 'info',
  remediation: 'Enter the object IDs of your break-glass (emergency access) accounts, or of the group that holds them, in tenant setup and '
    + 'run the analysis again. If you have no break-glass accounts, create at least two cloud-only emergency access accounts and exclude '
    + 'them from your Conditional Access policies.',
};

const appliesToEveryone = (p: CAPolicy) => (includesAllUsers(p) || coversAllAdminRoles(p))
  && (isBlock(p) || grantAlternatives(p).length > 0) && !isRiskOrFlowScoped(p) && coversModernClients(p);

const wek02Policies = perPolicyRule(WEK02,
  (p, ctx) => {
    if (!appliesToEveryone(p)) return [];
    const excluded = lowerSet([...p.conditions.users.excludeUsers, ...p.conditions.users.excludeGroups]);
    return ctx.tenant.breakGlass.filter(id => !excluded.has(id.toLowerCase())).map(id => displayName(ctx.tenant, id));
  },
  (ctx, p, labels) => `${quoted(ctx, p)} ${isBlock(p) ? 'blocks' : 'requires controls for'} `
    + `${includesAllUsers(p) ? 'all users' : 'all privileged administrator roles'} but does not exclude these break-glass accounts: `
    + `${labels.join(', ')}. If the policy cannot be satisfied, for example during an MFA or federation outage or after a `
    + 'misconfiguration, the emergency accounts are locked out along with everyone else, and they are the way back in.',
  { scope: isEnforced });

const wek02: Rule = {
  id: WEK02.id,
  family: WEK02.family,
  run: ctx => (ctx.tenant.breakGlass.length
    ? wek02Policies.run(ctx)
    : [makeFinding(WEK02_NONE, ctx, {
      explanation: 'No break-glass (emergency access) accounts are configured in tenant setup, so the tool cannot tell emergency-access '
        + 'exclusions from risky ones: every user or group exclusion is reported as unexpected, and it cannot check that your emergency '
        + 'accounts are excluded from policies that could lock everyone out.',
    })]),
};

// ---------- WEK-03 ----------

const WEK03: RuleMeta = {
  id: 'WEK-03', title: 'Policy excludes privileged roles', family: 'weakening', severity: 'high',
  remediation: 'Remove the role exclusions. If emergency access is the reason, exclude the specific break-glass accounts instead of the role.',
  references: [REF.usersGroups, REF.phishAdmins],
};

const wek03 = perPolicyRule(WEK03,
  p => (isBlock(p) ? [] : p.conditions.users.excludeRoles.filter(isPrivilegedRole).map(id => roleName(id) ?? id)),
  (ctx, p, names) => `${quoted(ctx, p)} excludes privileged roles: ${names.join(', ')}. Every active holder of these roles, usually the `
    + 'most valuable accounts in the tenant, skips this policy, so an attacker who compromises one of them is not challenged by it.');

// ---------- WEK-04 ----------

const WEK04: RuleMeta = {
  id: 'WEK-04', title: 'Trusted location exclusion bypasses MFA', family: 'weakening', severity: 'high',
  remediation: 'Remove the location condition so MFA applies on every network. If prompts on the corporate network are the concern, rely on '
    + 'a compliant or hybrid joined device, Windows Hello for Business or token protection instead of IP-based trust. Use locations to '
    + 'block access from unwanted places, not to skip MFA.',
  references: [REF.network],
};

const ALL_TRUSTED = 'alltrusted';

const wek04 = perPolicyRule(WEK04,
  (p, ctx) => {
    const loc = p.conditions.locations;
    if (!loc || isBlock(p) || (mfaStrength(p) === 'none' && phishStrength(p) === 'none')) return [];
    const label = (id: string) => (locationLabel(id) === id ? displayName(ctx.tenant, id) : locationLabel(id));
    const inc = loc.includeLocations;
    return [
      ...(inc.length && !inc.includes('All') ? [`only applies in: ${inc.map(label).join(', ')}`] : []),
      ...(loc.excludeLocations.length ? [`excludes: ${loc.excludeLocations.map(label).join(', ')}`] : []),
    ];
  },
  (ctx, p, reasons) => {
    const loc = p.conditions.locations;
    const allTrusted = !!loc && [...loc.includeLocations, ...loc.excludeLocations].some(id => id.toLowerCase() === ALL_TRUSTED);
    return `${quoted(ctx, p)} requires MFA but its network condition ${reasons.join('; ')}. Anyone signing in from a trusted network, `
      + 'including from a compromised device or as a malicious insider, skips MFA, and trusted IP ranges are often broader than intended.'
      + (allTrusted
        ? ' All trusted locations also includes the legacy MFA service trusted IPs, which are configured outside Conditional Access and '
          + 'easy to overlook.'
        : '');
  });

// ---------- WEK-05 ----------

const WEK05: RuleMeta = {
  id: 'WEK-05', title: 'OR grant lets a weaker control replace MFA', family: 'weakening', severity: 'medium',
  remediation: 'Change the grant to "Require all the selected controls", or split the policy into separate policies (each one is then '
    + 'required). The Microsoft template "compliant OR hybrid joined OR MFA" is intended for regular users only; administrators should '
    + 'always be required to use (phishing-resistant) MFA.',
  references: [REF.policies, REF.grant, REF.compliantOrMfa],
};

const wek05 = perPolicyRule(WEK05,
  p => {
    const alts = grantAlternatives(p);
    if (isBlock(p) || p.grantControls?.operator !== 'OR' || alts.length < 2 || mfaStrength(p) !== 'partial') return [];
    return alts.map(alt => alt[0]);
  },
  (ctx, p, controls) => {
    const weakest = controls.find(c => !isMfaControl(p, c)) ?? controls[0];
    return `${quoted(ctx, p)} grants access when any one of these is met: ${controls.map(c => controlLabel(p, c)).join(' OR ')}. A policy `
      + `with OR is only as strong as its weakest option; here the weakest is ${controlLabel(p, weakest)}, so a sign-in that meets it `
      + 'is never asked for MFA by this policy.';
  },
  {
    severity: (p, _ids, ctx) => (populationCoverage(p, 'admins', ctx.tenant).level !== 'none' || (includesAllUsers(p) && includesAllApps(p))
      ? 'high' : 'medium'),
  });

// ---------- WEK-06 ----------

const WEK06: RuleMeta = {
  id: 'WEK-06', title: 'Platform condition relaxes an MFA or device requirement', family: 'weakening', severity: 'medium',
  remediation: 'Apply the requirement to all platforms. Use the platform condition only to scope block policies or device and app '
    + 'protection policies, and block unknown or unsupported platforms with a separate policy that includes "Any device" and excludes '
    + 'the platforms you support.',
  references: [REF.conditions, REF.unknownPlatforms],
};

const wek06 = perPolicyRule(WEK06,
  p => {
    const pl = p.conditions.platforms;
    if (!pl || isBlock(p) || (mfaStrength(p) === 'none' && managedDeviceStrength(p) === 'none')) return [];
    const inc = pl.includePlatforms;
    return [
      ...(inc.length && !inc.includes('all') ? [`only includes platforms: ${inc.join(', ')}`] : []),
      ...(pl.excludePlatforms.length ? [`excludes platforms: ${pl.excludePlatforms.join(', ')}`] : []),
    ];
  },
  (ctx, p, reasons) => {
    const what = [mfaStrength(p) !== 'none' ? 'MFA' : '', managedDeviceStrength(p) !== 'none' ? 'a managed device' : ''].filter(Boolean);
    return `${quoted(ctx, p)} requires ${what.join(' or ')} but ${reasons.join(' and ')}. The device platform is read from the user agent, `
      + 'which the client sends and can change, so an attacker can claim to be on an excluded or untargeted platform and skip this requirement.';
  });

// ---------- WEK-07 ----------

const WEK07: RuleMeta = {
  id: 'WEK-07', title: 'Include-mode device filter misses unregistered devices', family: 'weakening', severity: 'medium',
  remediation: 'Invert the filter so unregistered devices stay in scope: use "Exclude filtered devices" with the positive rule (exclude the '
    + 'devices you trust), or keep "Include filtered devices" with negative operators such as -ne or -notIn.',
  references: [REF.deviceFilters],
};

const wek07 = perPolicyRule(WEK07,
  p => {
    const f = p.conditions.devices?.deviceFilter;
    return f && f.mode === 'include' && !isBlock(p) && grantAlternatives(p).length && onlyPositive(f.rule) ? [f.rule] : [];
  },
  (ctx, p, [rule]) => `${quoted(ctx, p)} applies only to devices matching the include filter "${rule}", which uses only positive `
    + 'operators. Unregistered devices, such as an attacker\'s own computer, have no device properties, so positive operators never match '
    + 'them and the policy does not apply to them at all.');

// ---------- WEK-08 ----------

const WEK08: RuleMeta = {
  id: 'WEK-08', title: 'Persistent browser session misconfigured', family: 'weakening', severity: 'medium',
  remediation: 'Set persistent browser session to "Never persistent" for devices that are not compliant or hybrid joined (as in the '
    + 'Microsoft template, which targets All resources). Allow "Always persistent" only in a policy restricted to managed devices, and '
    + 'target All resources in any policy that uses this control.',
  references: [REF.persistentBrowser, REF.persistentBrowserPolicy, REF.session],
};

const restrictedToManaged = (p: CAPolicy) => {
  const f = p.conditions.devices?.deviceFilter;
  return managedDeviceStrength(p) === 'full' || (!!f && (f.mode === 'include' ? onlyPositive(f.rule) : onlyNegative(f.rule)));
};

const wek08 = perPolicyRule(WEK08,
  p => {
    const pb = p.sessionControls?.persistentBrowser;
    if (!pb?.isEnabled) return [];
    return [
      ...(pb.mode === 'always' && !restrictedToManaged(p)
        ? ['it is set to "Always persistent" without restricting the policy to managed devices, so on an unmanaged, shared or attacker-'
          + 'controlled computer the browser stays signed in after it is closed and a stolen session cookie stays usable']
        : []),
      ...(!includesAllApps(p) ? ['the policy does not target All resources, which Microsoft requires for this control to work correctly'] : []),
    ];
  },
  (ctx, p, reasons) => `${quoted(ctx, p)} uses the persistent browser session control, but ${reasons.join('; and ')}.`);

// ---------- WEK-09 ----------

const WEK09: RuleMeta = {
  id: 'WEK-09', title: 'Retired "Require approved client app" control in use', family: 'weakening', severity: 'medium',
  remediation: 'Create a replacement policy with Grant = "Require app protection policy" (compliantApplication) backed by Intune app '
    + 'protection policies, test it in report-only, enable it, then disable or delete the old policy.',
  references: [REF.migrateApprovedApp, REF.mc1220751, REF.grant],
};

const onlyApprovedApp = (p: CAPolicy) => grantAlternatives(p).flat().every(c => c === 'approvedApplication');

const wek09 = perPolicyRule(WEK09,
  p => (hasControl(p, 'approvedApplication') ? ['approvedApplication'] : []),
  (ctx, p) => `${quoted(ctx, p)} uses "Require approved client app", which Microsoft retired on June 30, 2026. Microsoft's sources `
    + 'disagree on what happens to existing policies: the Learn migration article says they become read-only (they can be disabled or '
    + 'deleted but not edited) and keep enforcing, while Message Center MC1220751 says the control is no longer enforced, "as if this '
    + 'grant is not selected".'
    + (onlyApprovedApp(p)
      ? ' It is the only control in this policy, so under the Message Center reading the policy no longer requires anything.'
      : ' Either way the policy can no longer be changed and should be replaced.'),
  { severity: p => (onlyApprovedApp(p) ? 'high' : 'medium') });

// ---------- WEK-10 ----------

const WEK10: RuleMeta = {
  id: 'WEK-10', title: 'Custom controls used instead of MFA', family: 'weakening', severity: 'medium',
  remediation: 'Migrate the third-party provider to external authentication methods and use Require multifactor authentication in this '
    + 'policy, then remove the custom control.',
  references: [REF.managedPolicies, REF.grant],
};

const wek10 = perPolicyRule(WEK10,
  p => p.grantControls?.customAuthenticationFactors ?? [],
  (ctx, p, ids) => `${quoted(ctx, p)} uses custom controls (${ids.join(', ')}). Custom controls are a legacy preview feature and do not `
    + 'satisfy multifactor authentication: a user who completes one has not done MFA as far as Microsoft Entra is concerned, so the '
    + 'control cannot stand in for Require multifactor authentication.');

// ---------- WEK-11 ----------

const WEK11: RuleMeta = {
  id: 'WEK-11', title: 'Resilience defaults disabled on a broad policy', family: 'weakening', severity: 'low',
  remediation: 'Turn resilience defaults back on for this policy. If some highly sensitive apps or users must not have sessions extended '
    + 'during an outage, disable them only in a separate policy scoped to those apps or users.',
  references: [REF.session],
};

const wek11 = perPolicyRule(WEK11,
  p => (p.sessionControls?.disableResilienceDefaults === true && (includesAllUsers(p) || includesAllApps(p)) ? ['disabled'] : []),
  (ctx, p) => `${quoted(ctx, p)} disables resilience defaults and applies to ${includesAllUsers(p) ? 'all users' : 'all resources'}. `
    + 'During a Microsoft Entra outage, existing sessions covered by this policy are not extended, so a large part of the organization '
    + 'can lose access until the service recovers.');

// ---------- WEK-12 ----------

const WEK12: RuleMeta = {
  id: 'WEK-12', title: 'Continuous access evaluation disabled', family: 'weakening', severity: 'low',
  remediation: 'Remove the continuous access evaluation customization from this policy so the default applies, or consider strict '
    + 'location enforcement instead.',
  references: [REF.cae, REF.session],
};

const wek12 = perPolicyRule(WEK12,
  p => (p.sessionControls?.continuousAccessEvaluation?.mode === 'disabled' ? ['disabled'] : []),
  (ctx, p) => `${quoted(ctx, p)} disables continuous access evaluation. Without it, services cannot revoke access in near real time when `
    + 'a user is disabled, their password is changed or their sessions are revoked, so a stolen or revoked session keeps working until '
    + 'its access token expires.');

export const weakeningRules: Rule[] = [wek01, wek02, wek03, wek04, wek05, wek06, wek07, wek08, wek09, wek10, wek11, wek12];
