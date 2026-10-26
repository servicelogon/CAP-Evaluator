import type { CAPolicy } from '../../model/types';
import { populationCoverage } from '../coverage';
import { isActive, isBlock } from '../predicates';
import { coverageRule, makeFinding, policyMatchRule, type Rule, type RuleMeta } from './types';

const LEARN = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access';
const REF = {
  managedPolicies: `${LEARN}/managed-policies`,
  grant: `${LEARN}/concept-conditional-access-grant`,
  workloadIdentity: `${LEARN}/workload-identity`,
  insiderRisk: `${LEARN}/how-to-policy-insider-risk`,
  insiderRiskRecommendation: 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/recommendation-insider-risk-condition',
  tokenProtection: `${LEARN}/concept-token-protection`,
  tokenProtectionWindows: `${LEARN}/deployment-guide-token-protection-windows`,
  secureSignInSession: 'https://learn.microsoft.com/en-us/graph/api/resources/securesigninsessioncontrol?view=graph-rest-beta',
  agentId: `${LEARN}/agent-id`,
};

const BREAK_GLASS = 'exclude only your break-glass (emergency access) accounts';
const REVIEW_THEN_ENABLE = 'Start in report-only, review the sign-in logs for impact, then switch the policy to On.';
const GUESTS_MAY_BE_EXCLUDED = 'Guests and external users may also be excluded, as in the Microsoft-managed policy, because risk '
  + 'remediation is not supported for them';
const GUESTS_NOTE = ' Excluding guests and external users is accepted for this rule.';

const GUESTS_KEYWORD = 'guestsorexternalusers';

/** Copy of p without guest exclusions, so that only other exclusions count against risk policies. */
function withoutGuestExclusions(p: CAPolicy): CAPolicy {
  const u = p.conditions.users;
  return {
    ...p,
    conditions: {
      ...p.conditions,
      users: { ...u, excludeUsers: u.excludeUsers.filter(x => x.toLowerCase() !== GUESTS_KEYWORD), excludeGuestsOrExternalUsers: null },
    },
  };
}

/** Evaluates `rule` as if no policy excluded guests. */
const toleratingGuests = (rule: Rule): Rule => ({
  ...rule,
  run: ctx => rule.run({ ...ctx, policies: ctx.policies.map(withoutGuestExclusions) }),
});

// ---------- RSK-01 ----------

const RSK01: RuleMeta = {
  id: 'RSK-01', title: 'No sign-in risk policy', family: 'risk', severity: 'high',
  requiredLicense: 'entraP2',
  remediation: 'Turn on the Microsoft-managed policy "Multifactor authentication and reauthentication for risky sign-ins", or create a '
    + `policy: Users = All users (${BREAK_GLASS}; ${GUESTS_MAY_BE_EXCLUDED}), Target resources = All resources, Conditions > `
    + 'Sign-in risk = High and Medium, Grant = Require multifactor authentication or an authentication strength (or Block access for High), Session = Sign-in frequency Every '
    + `time. Make sure users have registered MFA before they become risky. ${REVIEW_THEN_ENABLE}`,
  references: [REF.managedPolicies, REF.grant],
};

const rsk01 = toleratingGuests(coverageRule(RSK01, 'allUsers', 'allResources', 'signInRisk', c => `${c.level === 'none'
  ? 'No enforced policy requires MFA or blocks access for high-risk sign-ins for all users on all resources.'
  : 'High-risk sign-ins are not fully challenged or blocked for all users on all resources.'} `
  + 'Microsoft Entra ID Protection flags sign-ins that look like an attacker (anonymous IP addresses, impossible travel, password '
  + 'spray, token replay); without a policy acting on that risk, a sign-in with a stolen password is allowed if no other policy stops it.'
  + GUESTS_NOTE));

// ---------- RSK-02 ----------

const RSK02: RuleMeta = {
  id: 'RSK-02', title: 'High-risk users not blocked or remediated', family: 'risk', severity: 'high',
  requiredLicense: 'entraP2',
  remediation: 'Turn on the Microsoft-managed policy "Require remediation for high-risk users" or "Block access for high-risk users", or '
    + `create a policy: Users = All users (${BREAK_GLASS}; ${GUESTS_MAY_BE_EXCLUDED}), Target resources = All resources with no `
    + 'exclusions, Conditions > User risk = High, Grant = Require all of: Require multifactor authentication AND Require password change (or Require risk remediation AND an '
    + `authentication strength), or Block access. ${REVIEW_THEN_ENABLE}`,
  references: [REF.managedPolicies, REF.grant],
};

const rsk02 = toleratingGuests(coverageRule(RSK02, 'allUsers', 'allResources', 'userRisk', c => `${c.level === 'none'
  ? 'No enforced policy blocks high-risk users or requires them to remediate (MFA and password change, or risk remediation with an '
    + 'authentication strength) for all users on all resources.'
  : 'High-risk users are not fully blocked or required to remediate for all users on all resources.'} `
  + 'High user risk means Microsoft Entra ID Protection believes the account is compromised, for example because its credentials were '
  + 'leaked; MFA alone does not remove the attacker\'s knowledge of the password.' + GUESTS_NOTE));

// ---------- RSK-03 ----------

const RSK03: RuleMeta = {
  id: 'RSK-03', title: 'Workload identities unprotected', family: 'risk', severity: 'medium',
  requiredLicense: 'workloadIdPremium',
  remediation: 'Create a policy: Workload identities = Service principals in my tenant (ServicePrincipalsInMyTenant) or specific '
    + 'service principal object IDs, Target resources = All resources, Conditions > Network = Any network excluding the locations '
    + 'your service principals run from (or Service principal risk = High), Grant = Block access. Use the enterprise application '
    + `(service principal) object ID, not the app registration object ID. ${REVIEW_THEN_ENABLE}`,
  references: [REF.workloadIdentity],
};

const rsk03 = policyMatchRule(RSK03,
  p => isBlock(p) && (p.conditions.clientApplications?.includeServicePrincipals.length ?? 0) > 0,
  'No enforced policy blocks workload identities (service principals). Service principals are not covered by policies scoped to users, '
    + 'so their client secrets and certificates work from anywhere if stolen. Workload identity policies apply only to single-tenant '
    + 'service principals registered in your tenant, not to managed identities or to multitenant and SaaS apps, and they support only '
    + 'Block access, typically outside known locations or at high service principal risk.');

// ---------- RSK-04 ----------

const RSK04: RuleMeta = {
  id: 'RSK-04', title: 'Insider risk not used', family: 'risk', severity: 'low',
  requiredLicense: ['entraP2', 'purviewInsiderRisk'],
  remediation: 'Turn on Adaptive Protection in Microsoft Purview Insider Risk Management, then create a policy from the "Block access for '
    + `users with insider risk" template: Users = All users (${BREAK_GLASS}; the template also excludes B2B direct connect users, `
    + 'service providers and other external users), Target resources = All resources, Conditions > Insider risk = Elevated, Grant = '
    + `Block access. ${REVIEW_THEN_ENABLE}`,
  references: [REF.insiderRisk, REF.insiderRiskRecommendation],
};

const rsk04 = policyMatchRule(RSK04,
  p => isBlock(p) && p.conditions.insiderRiskLevels.includes('elevated'),
  'No enforced policy blocks users with elevated insider risk. Microsoft Purview Adaptive Protection can raise a user\'s insider risk '
    + 'level when they show data-theft or sabotage behaviour, but without a Conditional Access policy that level does not restrict '
    + 'their access.');

// ---------- RSK-05 ----------

const RSK05: RuleMeta = {
  id: 'RSK-05', title: 'No token protection for admins', family: 'risk', severity: 'low',
  requiredLicense: 'entraP1',
  remediation: 'Pilot token protection for administrators: create a policy for your privileged roles (or a group of administrators, '
    + `${BREAK_GLASS}), Target resources = Office 365 Exchange Online, Office 365 SharePoint Online and Microsoft Teams Services, `
    + 'Conditions > Device platforms = Windows, macOS and iOS, Client apps = Mobile apps and desktop clients, Session = Require token '
    + `protection for sign-in sessions. ${REVIEW_THEN_ENABLE}`,
  references: [REF.tokenProtection, REF.tokenProtectionWindows, REF.secureSignInSession],
};

const RSK05_MISSING = 'No enforced policy requires token protection for administrators. Token protection binds sign-in session '
  + 'tokens to the device they were issued to, so a token stolen from an administrator\'s device by malware cannot be replayed from '
  + 'another one. The setting (secureSignInSession) is only returned by the Microsoft Graph beta endpoint, so policies exported from '
  + 'v1.0 never show it.';

const rsk05: Rule = {
  id: RSK05.id,
  family: RSK05.family,
  run: ctx => policyMatchRule(RSK05,
    p => populationCoverage(p, 'admins', ctx.tenant).level !== 'none' && !!p.sessionControls?.secureSignInSession?.isEnabled,
    RSK05_MISSING).run(ctx),
};

// ---------- RSK-06 ----------

const RSK06: RuleMeta = {
  id: 'RSK-06', title: 'Agent identities and agent users not covered', family: 'risk', severity: 'info',
  remediation: 'If Microsoft Entra Agent ID is in use, turn on the Microsoft-managed policy "Block high risk agents" and create policies '
    + 'under Assignments > Agents: target All agent identities (block high agent risk, or allow only approved agents with an attribute '
    + 'filter) and All agent users (block, or require a compliant device).',
  references: [REF.agentId],
};

const AGENT_USERS = 'allagentidusers';
const targetsAgents = (p: CAPolicy) => p.conditions.users.includeUsers.some(x => x.toLowerCase() === AGENT_USERS)
  || (p.conditions.clientApplications?.includeAgentIdServicePrincipals?.length ?? 0) > 0;

const rsk06: Rule = {
  id: RSK06.id,
  family: RSK06.family,
  run: ctx => (ctx.policies.some(p => isActive(p) && targetsAgents(p)) ? [] : [makeFinding(RSK06, ctx, {
    status: 'unverified',
    explanation: 'No policy targets agent identities or agent users. Policies assigned to "All users", groups, roles or guests do not '
      + 'apply to agent user accounts, and user policies do not apply to agent identities, so agents created with Microsoft Entra Agent '
      + 'ID (preview) are not covered by any of your policies. Check Assignments > Agents if Agent ID is in use; this needs Agent 365 '
      + 'with Microsoft Entra ID P1 or Microsoft 365 E3, or Microsoft 365 E7.',
  })]),
};

export const riskRules: Rule[] = [rsk01, rsk02, rsk03, rsk04, rsk05, rsk06];
