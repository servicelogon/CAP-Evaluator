import {
  APP, APP_CATALOG, KEYWORD, appLabel, lookupApp, type SurfaceId,
} from '../../catalog/apps';
import { isPrivilegedRole } from '../../catalog/roles';
import type { CAPolicy, Finding, Population } from '../../model/types';
import { bestCoverage, type Contribution } from '../coverage';
import { hasControl, includesAllApps, includesAllUsers, isActive } from '../predicates';
import { makeFinding, policyNames, type Rule, type RuleContext, type RuleMeta } from './types';

const LEARN = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access';
const REF = {
  cloudApps: `${LEARN}/concept-conditional-access-cloud-apps`,
  baselineScopes: `${LEARN}/concept-enforcement-resource-exclusions`,
  office365Ref: `${LEARN}/reference-office-365-application-contents`,
  serviceDependencies: `${LEARN}/service-dependencies`,
  authFlows: `${LEARN}/concept-authentication-flows`,
  rms: 'https://learn.microsoft.com/en-us/purview/encryption-azure-ad-configuration',
  compliantOrMfa: `${LEARN}/policy-alt-all-users-compliant-hybrid-or-mfa`,
  zeroTrust: 'https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-identity-device-access-policies-common',
  termsOfUse: `${LEARN}/terms-of-use`,
  firstParty: 'https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in',
  troubleshoot: `${LEARN}/troubleshoot-conditional-access`,
  azureManagement: `${LEARN}/policy-old-require-mfa-azure-mgmt`,
  azureDevOps: 'https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/conditional-access-policies?view=azure-devops',
  commonPolicies: `${LEARN}/concept-conditional-access-policy-common`,
};

const BREAK_GLASS = 'exclude only your break-glass (emergency access) accounts';
const REVIEW_THEN_ENABLE = 'Start in report-only, review the sign-in logs for impact, then switch the policy to On.';

const lower = (xs: string[]) => xs.map(x => x.toLowerCase());
const included = (p: CAPolicy) => lower(p.conditions.applications.includeApplications);
const excluded = (p: CAPolicy) => lower(p.conditions.applications.excludeApplications);
const labels = (ids: string[]) => ids.map(appLabel).join(', ');

/** One finding per active policy for which `offending` returns a non-empty list of app IDs. */
function perPolicyRule(
  meta: RuleMeta, offending: (p: CAPolicy) => string[], explain: (ctx: RuleContext, p: CAPolicy, ids: string[]) => string,
  scope: (p: CAPolicy) => boolean = isActive,
): Rule {
  return {
    id: meta.id,
    family: meta.family,
    run: ctx => ctx.policies.filter(scope).flatMap(p => {
      const ids = offending(p);
      return ids.length ? [makeFinding(meta, ctx, { policyIds: [p.id], explanation: explain(ctx, p, ids) })] : [];
    }),
  };
}

// ---------- APP-01 ----------

const APP01: RuleMeta = {
  id: 'APP-01', title: 'All resources policy has app exclusions', family: 'apps', severity: 'medium',
  remediation: 'Remove the resource exclusions so the policy covers All resources with no exceptions. Where an exception is genuinely '
    + 'needed, create a separate, narrowly scoped policy for it instead of excluding the app from the baseline. Then check the Baseline '
    + 'scopes enforcement setting at https://aka.ms/BaselineScopesSettingsUX and keep it on "Enable enforcement".',
  references: [REF.baselineScopes, REF.cloudApps],
};

const BASELINE_SCOPES_NOTE = 'Until 2026, an All resources policy with any resource exclusion silently skipped sign-ins that requested '
  + 'only low-privilege baseline scopes (openid, profile, email, offline_access, User.Read, People.Read), so apps such as Azure CLI and '
  + 'VS Code could sign in without meeting it. Microsoft has rolled out baseline-scope enforcement (its documentation gives both March 2026 '
  + 'and June 15, 2026 as the start): these sign-ins are now evaluated as access to Windows Azure Active Directory (Azure AD Graph), unless '
  + 'the tenant opted out with "Customize behavior" or "Disable enforcement". The policy data does not show which applies, so verify the '
  + 'setting at https://aka.ms/BaselineScopesSettingsUX.';

const app01 = perPolicyRule(APP01,
  p => (includesAllApps(p) ? p.conditions.applications.excludeApplications : []),
  (ctx, p, ids) => `${policyNames(ctx, [p.id])} targets All resources but excludes: ${labels(ids)}. Sign-ins to the excluded apps `
    + `are not covered by this policy. ${BASELINE_SCOPES_NOTE}`);

// ---------- APP-02 ----------

const APP02: RuleMeta = {
  id: 'APP-02', title: 'High-value app excluded from an All resources policy', family: 'apps', severity: 'high',
  remediation: 'Remove the listed exclusions. If some users genuinely cannot meet the policy for one of these apps, exclude those users '
    + '(not the app) or create a separate policy with a different control for them. For Microsoft Rights Management Services, exclude '
    + 'external users from the policy or configure cross-tenant access settings to trust MFA from partner tenants instead of excluding the '
    + 'app. Device Registration Service should only be excluded from authentication-flow (device code) policies.',
  references: [REF.cloudApps, REF.authFlows, REF.rms],
};

const HIGH_VALUE = new Set(lower([
  KEYWORD.office365, KEYWORD.adminPortals, ...APP_CATALOG.filter(a => a.highValue).map(a => a.appId),
]));
const DRS = APP.deviceRegistrationService.toLowerCase();
const RMS = APP.rightsManagement.toLowerCase();
const hasAuthFlows = (p: CAPolicy) => (p.conditions.authenticationFlows?.transferMethods.length ?? 0) > 0;

const app02 = perPolicyRule(APP02,
  p => (includesAllApps(p) ? excluded(p).filter(id => HIGH_VALUE.has(id) && !(id === DRS && hasAuthFlows(p))) : []),
  (ctx, p, ids) => `${policyNames(ctx, [p.id])} targets All resources but excludes high-value apps: ${labels(ids)}. Every sign-in to `
    + 'these apps skips the policy, so an attacker who only needs mail, files, administration or device registration is not challenged.'
    + (ids.includes(RMS)
      ? ' Microsoft Rights Management Services is commonly excluded so that external users can open encrypted content; excluding it '
        + 'removes the policy from encrypted content for everyone. Exclude external users or use cross-tenant MFA trust instead.'
      : ''));

// ---------- APP-03 ----------

const APP03: RuleMeta = {
  id: 'APP-03', title: 'Unnecessary Intune exclusions on compliant-device policies', family: 'apps', severity: 'low',
  remediation: 'Remove the listed Intune exclusions from the compliant-device policy. Require device to be marked as compliant already '
    + 'lets users enroll and reach the Company Portal. Keep the Microsoft Intune Enrollment exclusion only on policies that require Terms '
    + 'of use.',
  references: [REF.compliantOrMfa, REF.zeroTrust, REF.termsOfUse],
};

const INTUNE_APPS = lower([APP.intune, APP.intuneEnrollment, APP.intuneWebCompanyPortal]);
const ENROLLMENT = APP.intuneEnrollment.toLowerCase();

const app03 = perPolicyRule(APP03,
  p => (hasControl(p, 'compliantDevice')
    ? excluded(p).filter(id => INTUNE_APPS.includes(id) && !(id === ENROLLMENT && !!p.grantControls?.termsOfUse.length))
    : []),
  (ctx, p, ids) => `${policyNames(ctx, [p.id])} requires a compliant device but excludes ${labels(ids)}. Microsoft documents that `
    + 'Require compliant device does not block Intune enrollment or the Intune Web Company Portal, so these exclusions are unnecessary. '
    + 'Each one widens the policy (and adds a resource exclusion, which also matters for baseline-scope enforcement).');

// ---------- APP-04 ----------

const APP04: RuleMeta = {
  id: 'APP-04', title: 'Single Microsoft 365 workload targeted instead of Office 365', family: 'apps', severity: 'low',
  remediation: 'Target the Office 365 app group instead of individual Exchange Online, SharePoint Online or Teams apps, so the policy '
    + 'applies consistently across the services that share data with each other.',
  references: [REF.office365Ref, REF.serviceDependencies, REF.cloudApps],
};

const WORKLOADS = lower([APP.exchangeOnline, APP.sharePointOnline, APP.teamsServices]);
const O365_KEY = KEYWORD.office365.toLowerCase();

const app04 = perPolicyRule(APP04,
  p => (includesAllApps(p) || included(p).includes(O365_KEY) ? [] : included(p).filter(id => WORKLOADS.includes(id))),
  (ctx, p, ids) => `${policyNames(ctx, [p.id])} targets ${labels(ids)} individually rather than the Office 365 app group. Microsoft 365 `
    + 'services depend on each other: Exchange data is also reachable through Search and Teams, and Teams depends on SharePoint and '
    + 'Exchange, so a SharePoint-only policy also affects Teams. Targeting individual workloads leads to inconsistent prompts and data '
    + 'reachable through the services the policy does not target.');

// ---------- APP-05 ----------

const APP05: RuleMeta = {
  id: 'APP-05', title: 'Policy targets a client app that cannot be targeted', family: 'apps', severity: 'medium',
  remediation: 'Remove the listed client apps from the policy. Conditional Access applies to the resource being accessed, so target the '
    + 'resources these clients call instead; for Microsoft Graph (Graph PowerShell, Graph Explorer) that means a policy on All resources '
    + 'with no exclusions.',
  references: [REF.cloudApps, REF.firstParty],
};

const nonTargetable = (ids: string[]) => ids.filter(id => lookupApp(id)?.targetable === false);

const app05 = perPolicyRule(APP05,
  p => nonTargetable([...p.conditions.applications.includeApplications, ...p.conditions.applications.excludeApplications]),
  (ctx, p, ids) => `${policyNames(ctx, [p.id])} includes or excludes apps that Conditional Access cannot target, so these entries have `
    + `no effect: ${ids.map(id => `${appLabel(id)} (${lookupApp(id)?.notes ?? ''})`).join('; ')}.`,
  () => true);

// ---------- APP-06 / APP-07 shared ----------

const POPULATIONS: { pop: Population; label: string }[] = [
  { pop: 'allUsers', label: 'all users' },
  { pop: 'admins', label: 'administrators' },
];

type Result = Contribution & { policyIds: string[] };
const LEVEL_TEXT: Record<Contribution['level'], string> = {
  none: 'not covered', partial: 'only partly covered', reportOnly: 'covered only by report-only policies', full: 'covered',
};

/** One finding for the populations not fully covered on `surface`/mfa: gap if any is none, otherwise partial. */
function populationsFinding(meta: RuleMeta, ctx: RuleContext, surface: SurfaceId, lead: string, why: string): Finding[] {
  const results = POPULATIONS.map(x => ({ ...x, r: bestCoverage(ctx.policies, x.pop, surface, 'mfa', ctx.tenant) }))
    .filter(x => x.r.level !== 'full');
  if (!results.length) return [];
  const detail = results.map(({ label, r }) => `${label}: ${LEVEL_TEXT[r.level]}`
    + (r.policyIds.length ? ` (closest: ${policyNames(ctx, r.policyIds)}${r.reasons.length ? `; ${r.reasons.join('; ')}` : ''})` : ''));
  return [makeFinding(meta, ctx, {
    status: results.some(x => x.r.level === 'none') ? 'gap' : 'partial',
    policyIds: [...new Set(results.flatMap(x => x.r.policyIds))],
    explanation: `${lead} ${detail.join('. ')}. ${why}`,
  })];
}

// ---------- APP-06 ----------

const APP06: RuleMeta = {
  id: 'APP-06', title: 'Microsoft Graph not protected by MFA', family: 'apps', severity: 'high',
  requiredLicense: 'entraP1',
  remediation: `Create or fix a policy: Users = All users (${BREAK_GLASS}), Target resources = All resources with no resource `
    + 'exclusions, Grant = Require multifactor authentication or an authentication strength. Do the same for administrators with '
    + `phishing-resistant MFA. ${REVIEW_THEN_ENABLE}`,
  references: [REF.cloudApps, REF.commonPolicies, REF.troubleshoot],
};

const app06: Rule = {
  id: APP06.id,
  family: APP06.family,
  run: ctx => populationsFinding(APP06, ctx, 'graph',
    'MFA is not fully required for sign-ins to Microsoft Graph.',
    'Microsoft Graph cannot be selected as a target resource. Graph PowerShell, Graph Explorer and every API call the admin centers make '
      + 'reach Graph, so only an All resources policy without exclusions covers it. An attacker with a password can read and change '
      + 'directory, mail and file data through Graph directly.'),
};

// ---------- APP-07 ----------

const APP07: RuleMeta = {
  id: 'APP-07', title: 'Azure management not protected with MFA', family: 'apps', severity: 'high',
  requiredLicense: 'entraP1',
  remediation: 'Create a policy from the "Require multifactor authentication for Azure management" template (Users = All users, '
    + `${BREAK_GLASS}; Target resources = Windows Azure Service Management API, app ID 797f4846-ba00-4fd7-ba43-dac1f8f63013; Grant = Require `
    + 'multifactor authentication), or rely on an All resources MFA policy without exclusions. Also target Azure DevOps '
    + `(499b84ac-1321-427f-aa17-267ca6975798). ${REVIEW_THEN_ENABLE}`,
  references: [REF.azureManagement, REF.cloudApps, REF.azureDevOps],
};

const covered = (r: Result) => r.level === 'full' || r.level === 'partial';

const app07: Rule = {
  id: APP07.id,
  family: APP07.family,
  run: ctx => {
    const main = populationsFinding(APP07, ctx, 'azureManagement',
      'MFA is not fully required for Azure management (Windows Azure Service Management API).',
      'This app covers Azure Resource Manager, the Azure portal, Azure CLI, Azure PowerShell and infrastructure-as-code tools. Without '
        + 'MFA, a stolen password gives an attacker control of your Azure subscriptions. Microsoft\'s mandatory Azure MFA covers some of '
        + 'these sign-ins at the platform level, but it is not a replacement for Conditional Access.');
    const mgmt = bestCoverage(ctx.policies, 'admins', 'azureManagement', 'mfa', ctx.tenant);
    const devOps = bestCoverage(ctx.policies, 'admins', 'azureDevOps', 'mfa', ctx.tenant);
    const devOpsGap = covered(mgmt) && devOps.level === 'none'
      ? [makeFinding(APP07, ctx, {
        severity: 'medium',
        policyIds: mgmt.policyIds,
        explanation: `Azure management is protected with MFA for administrators by ${policyNames(ctx, mgmt.policyIds)}, but Azure DevOps `
          + 'is not. Azure DevOps was removed from Windows Azure Service Management API coverage in September 2025, so it must be targeted '
          + 'directly (499b84ac-1321-427f-aa17-267ca6975798) or through All resources. Without it, pipelines, repositories and service '
          + 'connections that deploy to Azure can be reached with a password alone.',
      })]
      : [];
    return [...main, ...devOpsGap];
  },
};

// ---------- APP-08 ----------

const APP08: RuleMeta = {
  id: 'APP-08', title: 'Office 365 targeting assumed to cover admin surfaces', family: 'apps', severity: 'info',
  remediation: 'Do not rely on the Office 365 app group to protect administrators. Target All resources for administrators (or at least '
    + 'add the Microsoft Admin Portals and Windows Azure Service Management API); Microsoft Graph can only be covered by All resources.',
  references: [REF.office365Ref, REF.cloudApps],
};

const targetsPrivilegedRoles = (p: CAPolicy) => !includesAllUsers(p) && p.conditions.users.includeRoles.some(isPrivilegedRole);
const onlyOffice365 = (p: CAPolicy) => { const apps = included(p); return apps.length === 1 && apps[0] === O365_KEY; };

const app08: Rule = {
  id: APP08.id,
  family: APP08.family,
  run: ctx => {
    const ids = ctx.policies.filter(p => isActive(p) && targetsPrivilegedRoles(p) && onlyOffice365(p)).map(p => p.id);
    if (!ids.length) return [];
    return [makeFinding(APP08, ctx, {
      policyIds: ids,
      explanation: `${policyNames(ctx, ids)} protect administrators only on the Office 365 app group. Office 365 includes the Microsoft `
        + '365 admin center sign-in, M365 Admin Services, the Protection Center and the Skype and Teams Tenant Admin API, but not the '
        + 'Azure portal (and so the Microsoft Entra and Intune admin centers), the Exchange admin center or Microsoft Graph. These '
        + 'policies do not protect those admin surfaces.',
    })];
  },
};

export const appRules: Rule[] = [app01, app02, app03, app04, app05, app06, app07, app08];
