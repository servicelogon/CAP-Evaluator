import { ADMIN_PORTAL_IDS, APP, KEYWORD, type SurfaceId } from '../../catalog/apps';
import { PRIVILEGED_ROLES } from '../../catalog/roles';
import type { CAPolicy } from '../../model/types';
import { controlCoverage, populationCoverage, surfaceCoverage, type Contribution } from '../coverage';
import { includesAllApps, includesAllUsers, isActive, isEnforced, isReportOnly } from '../predicates';
import {
  coverageRule, makeFinding, policyMatchRule, policyNames, type Rule, type RuleContext, type RuleMeta,
} from './types';

const LEARN = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access';
const REF = {
  phishAdmins: `${LEARN}/policy-admin-phish-resistant-mfa`,
  managedPolicies: `${LEARN}/managed-policies`,
  cloudApps: `${LEARN}/concept-conditional-access-cloud-apps`,
  mfaAdminPortals: `${LEARN}/how-to-policy-mfa-admin-portals`,
  azureManagement: `${LEARN}/policy-old-require-mfa-azure-mgmt`,
  azureDevOps: 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/conditional-access-policies?view=azure-devops',
  troubleshoot: `${LEARN}/troubleshoot-conditional-access`,
  usersGroups: `${LEARN}/concept-conditional-access-users-groups`,
  pimSettings: 'https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings',
  deviceCompliance: `${LEARN}/policy-all-users-device-compliance`,
  session: `${LEARN}/concept-conditional-access-session`,
};

const BREAK_GLASS = 'exclude only your break-glass (emergency access) accounts';
const REVIEW_THEN_ENABLE = 'Start in report-only, review the sign-in logs for impact, then switch the policy to On.';
const ADMIN_USERS = 'Users = Directory roles with at least the 14 privileged roles from the Microsoft template, plus a group that '
  + `contains all administrators including PIM-eligible ones (${BREAK_GLASS})`;
const ADMIN_ALL_RESOURCES = `Create or extend an administrator policy that targets All resources: ${ADMIN_USERS}, Target resources = `
  + 'All resources with no exclusions, Grant = Require authentication strength "Phishing-resistant MFA" (or at least Require '
  + `multifactor authentication). ${REVIEW_THEN_ENABLE}`;

const coversAdmins = (p: CAPolicy, ctx: RuleContext) => populationCoverage(p, 'admins', ctx.tenant).level !== 'none';
const full = (c: Contribution) => c.level === 'full';
const lowerIncludes = (xs: string[], id: string) => xs.some(x => x.toLowerCase() === id.toLowerCase());

// ---------- ADM-01 ----------

const ADM01: RuleMeta = {
  id: 'ADM-01', title: 'Privileged roles not required to use phishing-resistant MFA on all resources', family: 'admin', severity: 'critical',
  requiredLicense: 'entraP1',
  remediation: 'Create a policy from the "Require phishing-resistant multifactor authentication for administrators" template: Users = '
    + `Directory roles with all 14 privileged roles the template selects (${BREAK_GLASS}), Target resources = All resources with no `
    + 'exclusions, no other conditions, Grant = Require authentication strength "Phishing-resistant MFA". Make sure every administrator '
    + `has registered Windows Hello for Business, a FIDO2 security key or passkey, or certificate-based authentication first. ${REVIEW_THEN_ENABLE}`,
  references: [REF.phishAdmins, REF.managedPolicies],
};

const PHISH_WHY = 'Ordinary MFA can be phished: adversary-in-the-middle kits relay the password, one-time code or push approval and steal '
  + 'the session cookie. Phishing-resistant methods (Windows Hello for Business, FIDO2 security keys and passkeys, and certificate-based '
  + 'authentication) are bound to the genuine sign-in site and cannot be relayed. The policy must target All resources because admin '
  + 'tools such as Microsoft Graph PowerShell call resources that cannot be selected individually.';

/** Role is covered by p: All users or role included, role not excluded, All resources and phishing-resistant strength without narrowing. */
const coversRolePhish = (p: CAPolicy, roleId: string) => {
  const u = p.conditions.users;
  return isActive(p) && (includesAllUsers(p) || lowerIncludes(u.includeRoles, roleId)) && !lowerIncludes(u.excludeRoles, roleId)
    && full(surfaceCoverage(p, 'allResources')) && full(controlCoverage(p, 'phishResistant'));
};

interface RoleCoverage { missing: string[]; reportOnly: string[]; reportOnlyPolicyIds: string[] }

function roleCoverage(policies: CAPolicy[]): RoleCoverage {
  const out: RoleCoverage = { missing: [], reportOnly: [], reportOnlyPolicyIds: [] };
  for (const role of PRIVILEGED_ROLES) {
    const hits = policies.filter(p => coversRolePhish(p, role.id));
    if (hits.some(isEnforced)) continue;
    if (!hits.length) { out.missing.push(role.name); continue; }
    out.reportOnly.push(role.name);
    hits.filter(isReportOnly).forEach(p => { if (!out.reportOnlyPolicyIds.includes(p.id)) out.reportOnlyPolicyIds.push(p.id); });
  }
  return out;
}

const adm01FullyCovered = (policies: CAPolicy[]) => {
  const c = roleCoverage(policies);
  return !c.missing.length && !c.reportOnly.length;
};

const adm01: Rule = {
  id: ADM01.id,
  family: ADM01.family,
  run: ctx => {
    const c = roleCoverage(ctx.policies);
    if (!c.missing.length && !c.reportOnly.length) return [];
    const reportOnly = c.reportOnly.length
      ? ` These roles are covered only by report-only policies (${policyNames(ctx, c.reportOnlyPolicyIds)}), which log what would happen `
        + `but do not enforce anything: ${c.reportOnly.join(', ')}.`
      : '';
    const lead = c.missing.length
      ? 'No enforced or report-only policy requires a phishing-resistant authentication strength on all resources for these privileged '
        + `roles: ${c.missing.join(', ')}.`
      : `All ${PRIVILEGED_ROLES.length} privileged roles are covered by a phishing-resistant policy on all resources, but not all by an enforced one.`;
    return [makeFinding(ADM01, ctx, {
      status: c.missing.length ? 'gap' : 'partial',
      policyIds: c.reportOnlyPolicyIds,
      explanation: `${lead}${reportOnly} ${PHISH_WHY}`,
    })];
  },
};

// ---------- ADM-02 ----------

const ADM02: RuleMeta = {
  id: 'ADM-02', title: 'Privileged roles not required to use MFA on all resources', family: 'admin', severity: 'critical',
  requiredLicense: 'entraP1',
  remediation: `Create a policy: ${ADMIN_USERS}, Target resources = All resources with no exclusions, Grant = Require multifactor `
    + 'authentication, or better, Require authentication strength "Phishing-resistant MFA". The Microsoft-managed policy for admins only '
    + `covers the Microsoft Admin Portals and is not a substitute. ${REVIEW_THEN_ENABLE}`,
  references: [REF.phishAdmins, REF.managedPolicies],
};

const adm02Coverage = coverageRule(ADM02, 'admins', 'allResources', 'mfa', c => `${c.level === 'none'
  ? 'No enforced policy requires MFA for privileged administrators on all resources.'
  : 'MFA is not required for all privileged administrators on all resources without exceptions.'} `
  + 'An administrator whose password is phished, sprayed or reused can then sign in with the password alone wherever no other MFA policy '
  + 'applies, including Microsoft Graph PowerShell and Azure Resource Manager, and take over the tenant.');

const adm02: Rule = {
  id: ADM02.id,
  family: ADM02.family,
  run: ctx => (adm01FullyCovered(ctx.policies) ? [] : adm02Coverage.run(ctx)),
};

// ---------- ADM-03 / ADM-04 shared ----------

type AllResourcesMfa = 'enforced' | 'reportOnly' | 'none';

/** Strongest active admin policy on All resources with full MFA, full admin population and no narrowing. */
function allResourcesAdminMfa(ctx: RuleContext): { level: AllResourcesMfa; policyIds: string[] } {
  const hits = ctx.policies.filter(p => isActive(p) && full(populationCoverage(p, 'admins', ctx.tenant))
    && full(surfaceCoverage(p, 'allResources')) && full(controlCoverage(p, 'mfa')));
  if (hits.some(isEnforced)) return { level: 'enforced', policyIds: hits.filter(isEnforced).map(p => p.id) };
  return hits.length ? { level: 'reportOnly', policyIds: hits.map(p => p.id) } : { level: 'none', policyIds: [] };
}

/** One finding per offending policy, suppressed by an enforced All-resources admin MFA policy, partial if only report-only. */
function targetedAdminRule(meta: RuleMeta, offends: (p: CAPolicy) => boolean, explain: (ctx: RuleContext, p: CAPolicy) => string): Rule {
  return {
    id: meta.id,
    family: meta.family,
    run: ctx => {
      const backstop = allResourcesAdminMfa(ctx);
      if (backstop.level === 'enforced') return [];
      const suffix = backstop.level === 'reportOnly'
        ? ` An All resources policy for administrators exists (${policyNames(ctx, backstop.policyIds)}) but is report-only, so it does `
          + 'not enforce anything.'
        : ' No enforced policy requires MFA for all administrators on All resources to cover these.';
      return ctx.policies.filter(p => isActive(p) && coversAdmins(p, ctx) && offends(p)).map(p => makeFinding(meta, ctx, {
        status: backstop.level === 'reportOnly' ? 'partial' : 'gap',
        policyIds: [p.id],
        explanation: `${explain(ctx, p)}${suffix}`,
      }));
    },
  };
}

const ADMIN_PORTALS_KEY = KEYWORD.adminPortals.toLowerCase();
const PORTAL_IDS = new Set(ADMIN_PORTAL_IDS.map(id => id.toLowerCase()));
const includeApps = (p: CAPolicy) => p.conditions.applications.includeApplications.map(x => x.toLowerCase());
const usesAdminPortals = (p: CAPolicy) => includeApps(p).includes(ADMIN_PORTALS_KEY);

// ---------- ADM-03 ----------

const ADM03: RuleMeta = {
  id: 'ADM-03', title: 'Admin policy targets only Microsoft Admin Portals', family: 'admin', severity: 'high',
  requiredLicense: 'entraP1',
  remediation: `${ADMIN_ALL_RESOURCES} Keep the Admin Portals policy if you like, but do not rely on it alone. Use the sign-in logs' `
    + 'audience reporting to see which resources your admin portals actually call.',
  references: [REF.cloudApps, REF.mfaAdminPortals, REF.troubleshoot],
};

const BACKEND_APIS: { surface: SurfaceId; label: string }[] = [
  { surface: 'graph', label: 'Microsoft Graph (Graph PowerShell, Graph Explorer and the data behind the Microsoft Entra admin center)' },
  { surface: 'intuneApi', label: 'the Microsoft Intune API' },
  { surface: 'azureManagement', label: 'Azure Resource Manager (Azure CLI, Azure PowerShell and infrastructure-as-code tools)' },
  { surface: 'office365', label: 'Exchange Online PowerShell and the Teams and SharePoint admin APIs' },
];

const adm03 = targetedAdminRule(ADM03,
  p => !includesAllApps(p) && (usesAdminPortals(p) || (includeApps(p).length > 0 && includeApps(p).every(id => PORTAL_IDS.has(id)))),
  (ctx, p) => {
    const uncovered = BACKEND_APIS.filter(b => !full(surfaceCoverage(p, b.surface))).map(b => b.label);
    return `${policyNames(ctx, [p.id])} protects administrators only on the Microsoft Admin Portals. That app group covers sign-in to the `
      + 'Azure portal (also used by the Microsoft Entra and Intune admin centers), the Exchange admin center, the Microsoft 365 admin '
      + 'center and the Purview/Protection Center, but not the backend APIs those portals call. Intune admin center sign-in is therefore '
      + 'covered, but the Intune and Graph API calls it makes are not.'
      + (uncovered.length ? ` This policy does not cover: ${uncovered.join('; ')}.` : '')
      + ' An attacker with an administrator\'s password can call these APIs directly, for example with Graph PowerShell, without meeting '
      + 'this policy.';
  });

// ---------- ADM-04 ----------

const ADM04: RuleMeta = {
  id: 'ADM-04', title: 'Admin policy targets only Azure management', family: 'admin', severity: 'high',
  requiredLicense: 'entraP1',
  remediation: `${ADMIN_ALL_RESOURCES} If you must keep targeted policies, also target Azure DevOps (499b84ac-1321-427f-aa17-267ca6975798) `
    + 'and the Microsoft Admin Portals; Microsoft Graph can only be covered by All resources.',
  references: [REF.azureManagement, REF.cloudApps, REF.azureDevOps],
};

const adm04 = targetedAdminRule(ADM04,
  p => { const apps = includeApps(p); return apps.length === 1 && apps[0] === APP.azureManagement; },
  (ctx, p) => `${policyNames(ctx, [p.id])} protects administrators only on Windows Azure Service Management API (Azure Resource Manager, `
    + 'the Azure portal, Azure CLI and Azure PowerShell). It does not cover Microsoft Graph, so Graph PowerShell, Graph Explorer, the '
    + 'Microsoft Entra admin center\'s data and Graph commands in Azure CLI and PowerShell (az ad, Get-AzAD*) are unprotected; nor the '
    + 'Microsoft 365 admin center and Exchange admin center; nor Azure DevOps, which has not been covered by this app since September 2025.');

// ---------- ADM-05 ----------

const ADM05: RuleMeta = {
  id: 'ADM-05', title: 'Admin policies scoped only by directory roles', family: 'admin', severity: 'high',
  requiredLicense: 'entraP1',
  remediation: 'In each listed policy, also include a group that contains all administrators, both active and PIM-eligible (or target '
    + 'All users), so that coverage does not depend on an active role assignment. In Privileged Identity Management, set "On activation, '
    + 'require Microsoft Entra Conditional Access authentication context" and target that authentication context with a policy scoped to '
    + 'users, not roles.',
  references: [REF.pimSettings, REF.usersGroups],
};

const roleOnly = (p: CAPolicy) => {
  const u = p.conditions.users;
  return !includesAllUsers(p) && !u.includeGroups.length && u.includeRoles.length > 0;
};
const protectsAdmins = (p: CAPolicy) => (['mfa', 'phishResistant', 'managedDevice'] as const).some(c => controlCoverage(p, c).level !== 'none');

const adm05: Rule = {
  id: ADM05.id,
  family: ADM05.family,
  run: ctx => {
    const ids = ctx.policies.filter(p => isActive(p) && coversAdmins(p, ctx) && roleOnly(p) && protectsAdmins(p)).map(p => p.id);
    if (!ids.length) return [];
    return [makeFinding(ADM05, ctx, {
      policyIds: ids,
      explanation: `${policyNames(ctx, ids)} target administrators only through directory roles. Conditional Access applies role-scoped `
        + 'policies only to active assignments of built-in, tenant-wide roles: administrators who are PIM-eligible are not covered until '
        + 'they activate the role, and custom roles and roles scoped to an administrative unit are ignored. Exchange RBAC role groups such '
        + 'as Organization Management are not directory roles either, so their members are not covered. Check in Privileged Identity '
        + 'Management whether these roles have eligible assignments.',
    })];
  },
};

// ---------- ADM-06 ----------

const ADM06: RuleMeta = {
  id: 'ADM-06', title: 'Admins not required to use a managed device', family: 'admin', severity: 'high',
  requiredLicense: 'intune',
  remediation: 'Enroll administrator workstations in Microsoft Intune with compliance policies, then create a policy from the "Require '
    + `compliant or hybrid joined device for administrators" template: ${ADMIN_USERS}, Target resources = All resources, Grant = Require `
    + `device to be marked as compliant OR Require Microsoft Entra hybrid joined device. ${REVIEW_THEN_ENABLE}`,
  references: [REF.deviceCompliance, REF.phishAdmins],
};

const adm06 = coverageRule(ADM06, 'admins', 'allResources', 'managedDevice', c => `${c.level === 'none'
  ? 'No enforced policy requires a compliant or hybrid joined device for privileged administrators on all resources.'
  : 'A compliant or hybrid joined device is not required for all privileged administrators on all resources in every case.'} `
  + 'Without it, an attacker who steals an administrator\'s credentials or session token can use them from any computer they control.');

// ---------- ADM-07 ----------

const ADM07: RuleMeta = {
  id: 'ADM-07', title: 'Admins lack sign-in frequency', family: 'admin', severity: 'low',
  requiredLicense: 'entraP1',
  remediation: `Add a sign-in frequency session control (for example 4 to 12 hours) to a policy for administrators: ${ADMIN_USERS}, `
    + 'Target resources = All resources, Session = Sign-in frequency. Alternatively rely on reauthentication at PIM role activation.',
  references: [REF.session],
};

const ADM07_MISSING = 'No enforced policy sets a sign-in frequency for administrators. Without one, an administrator\'s session and '
  + 'refresh tokens stay usable for a long time, so a stolen token gives an attacker long-lived privileged access.';

const adm07: Rule = {
  id: ADM07.id,
  family: ADM07.family,
  run: ctx => policyMatchRule(ADM07, p => coversAdmins(p, ctx) && !!p.sessionControls?.signInFrequency?.isEnabled, ADM07_MISSING).run(ctx),
};

// ---------- ADM-08 ----------

const ADM08: RuleMeta = {
  id: 'ADM-08', title: 'Admin portals relied on for Defender, Purview, Teams, SharePoint or Power Platform admin', family: 'admin',
  severity: 'info',
  remediation: 'Do not rely on Microsoft Admin Portals for these admin centers. Target All resources for administrators, or add explicit '
    + 'targets such as Power Platform admin center (065d9450-1e87-434e-ac2f-69af271549ed) and Office 365 SharePoint Online. Confirm '
    + 'the resources each portal requests with the sign-in logs\' audience reporting.',
  references: [REF.cloudApps, REF.troubleshoot],
};

const adm08: Rule = {
  id: ADM08.id,
  family: ADM08.family,
  run: ctx => {
    const ids = ctx.policies.filter(p => isActive(p) && coversAdmins(p, ctx) && usesAdminPortals(p)).map(p => p.id);
    if (!ids.length) return [];
    return [makeFinding(ADM08, ctx, {
      status: 'unverified',
      policyIds: ids,
      explanation: `${policyNames(ctx, ids)} use the Microsoft Admin Portals app group. Microsoft documents its members only as the Exchange `
        + 'admin center, Azure portal, Microsoft Office 365 Portal and Protection Center app IDs. Which app the Microsoft Defender portal, '
        + 'Purview portal, Teams admin center, SharePoint admin center and Power Platform admin center sign in to is not documented, so '
        + 'these admin centers may not be covered by this group.',
    })];
  },
};

export const adminRules: Rule[] = [adm01, adm02, adm03, adm04, adm05, adm06, adm07, adm08];
