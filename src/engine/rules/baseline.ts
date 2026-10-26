import { USER_ACTION } from '../../catalog/apps';
import type { CAPolicy } from '../../model/types';
import { bestCoverage, type Contribution } from '../coverage';
import { includesAllApps, includesAllUsers, isActive, isBlock } from '../predicates';
import {
  coverageFindings, coverageRule, makeFinding, policyMatchRule, policyNames, type Rule, type RuleContext, type RuleMeta,
} from './types';

const LEARN = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access';
const REF = {
  managedPolicies: `${LEARN}/managed-policies`,
  conditions: `${LEARN}/concept-conditional-access-conditions`,
  cloudApps: `${LEARN}/concept-conditional-access-cloud-apps`,
  authFlows: `${LEARN}/concept-authentication-flows`,
  blockAuthFlows: `${LEARN}/policy-block-authentication-flows`,
  authTransfer: `${LEARN}/concept-authentication-transfer`,
  unknownPlatforms: `${LEARN}/policy-all-users-device-unknown-unsupported`,
  commonPolicies: `${LEARN}/concept-conditional-access-policy-common`,
  securityInfo: `${LEARN}/policy-all-users-security-info-registration`,
  deviceCompliance: `${LEARN}/policy-all-users-device-compliance`,
  compliantHybridOrMfa: `${LEARN}/policy-alt-all-users-compliant-hybrid-or-mfa`,
  persistentBrowser: `${LEARN}/policy-all-users-persistent-browser`,
  deviceFilters: `${LEARN}/concept-condition-filters-for-devices`,
};

const BREAK_GLASS = 'exclude only your break-glass (emergency access) accounts';
const REVIEW_THEN_ENABLE = 'Start in report-only, review the sign-in logs for impact, then switch the policy to On.';

/** Picks the gap sentence for no coverage, otherwise the "not fully" sentence; both end with the shared risk text. */
const byLevel = (none: string, weak: string, risk: string) => (c: Contribution) => `${c.level === 'none' ? none : weak} ${risk}`;

// ---------- BAS-01 ----------

const BAS01: RuleMeta = {
  id: 'BAS-01', title: 'Legacy authentication not blocked for all users on all resources', family: 'baseline', severity: 'critical',
  requiredLicense: 'entraP1',
  remediation: 'Turn on the Microsoft-managed policy "Block legacy authentication", or create a policy from the "Block legacy authentication" '
    + `template: Users = All users (${BREAK_GLASS}), Target resources = All resources, Conditions > Client apps = Exchange ActiveSync clients `
    + 'and Other clients, Grant = Block access. Before enforcing, filter the sign-in logs by legacy client apps to find mailboxes, devices '
    + 'and scripts that still use them and move them to modern authentication.',
  references: [REF.managedPolicies, REF.conditions],
};

const bas01 = coverageRule(BAS01, 'allUsers', 'allResources', 'legacyBlocked', byLevel(
  'No enforced policy blocks legacy authentication (Exchange ActiveSync and other legacy clients) for all users on all resources.',
  'Legacy authentication (Exchange ActiveSync and other legacy clients) is not fully blocked for all users on all resources.',
  'Legacy protocols cannot perform MFA, so passwords alone grant access; most password-spray attacks use them.',
));

// ---------- BAS-02 ----------

const BAS02: RuleMeta = {
  id: 'BAS-02', title: 'Legacy authentication block omits Exchange ActiveSync', family: 'baseline', severity: 'high',
  requiredLicense: 'entraP1',
  remediation: 'Edit the policy and under Conditions > Client apps also select "Exchange ActiveSync clients" '
    + '(clientAppTypes exchangeActiveSync), so that it blocks both Exchange ActiveSync and Other clients.',
  references: [REF.conditions],
};

const omitsEas = (p: CAPolicy) => {
  const types = p.conditions.clientAppTypes;
  return types.includes('other') && !types.includes('all') && !types.includes('exchangeActiveSync') && !types.includes('easSupported');
};

const bas02: Rule = {
  id: BAS02.id,
  family: BAS02.family,
  run: ctx => ctx.policies.filter(p => isActive(p) && isBlock(p) && omitsEas(p)).map(p => makeFinding(BAS02, ctx, {
    policyIds: [p.id],
    explanation: `${policyNames(ctx, [p.id])} blocks "Other clients" (IMAP, POP, SMTP and other legacy protocols) but not Exchange ActiveSync. `
      + 'Mail apps that sync over Exchange ActiveSync use basic authentication, cannot perform MFA, and can still sign in with only a password.',
  })),
};

// ---------- BAS-03 ----------

const BAS03: RuleMeta = {
  id: 'BAS-03', title: 'No MFA baseline for all users on all resources', family: 'baseline', severity: 'critical',
  requiredLicense: 'entraP1',
  remediation: 'Create a policy from the "Require multifactor authentication for all users" template: Users = All users '
    + `(${BREAK_GLASS}), Target resources = All resources with no resource exclusions, Client apps = all, no location, platform or `
    + 'device filter conditions, Grant = Require multifactor authentication or an authentication strength. Handle exceptions with '
    + `separate, narrowly scoped policies rather than exclusions. ${REVIEW_THEN_ENABLE}`,
  references: [REF.cloudApps, REF.managedPolicies],
};

const bas03 = coverageRule(BAS03, 'allUsers', 'allResources', 'mfa', byLevel(
  'No enforced policy requires MFA for all users on all resources.',
  'MFA is not required for all users on all resources without exceptions.',
  'Any account whose password is phished, sprayed or reused can sign in without a second factor wherever no other MFA policy applies, '
    + 'including Microsoft Graph and apps without a policy of their own; each excluded user, app, client type or condition is such a path.',
));

// ---------- BAS-04 ----------

const BAS04: RuleMeta = {
  id: 'BAS-04', title: 'Device code flow not blocked', family: 'baseline', severity: 'high',
  requiredLicense: 'entraP1',
  remediation: 'Turn on the Microsoft-managed policy "Block device code flow", or create a policy: Users = All users '
    + `(${BREAK_GLASS} and accounts that genuinely need the flow, such as Microsoft Teams Rooms devices), Target resources = All resources, `
    + 'Conditions > Authentication flows = Device code flow, Grant = Block access. If devices are registered using device code, exclude '
    + 'Device Registration Service (01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9).',
  references: [REF.blockAuthFlows, REF.authFlows, REF.managedPolicies],
};

const bas04 = coverageRule(BAS04, 'allUsers', 'allResources', 'deviceCodeBlocked', byLevel(
  'No enforced policy blocks the device code flow for all users on all resources.',
  'The device code flow is not fully blocked for all users on all resources.',
  'In device code phishing an attacker sends the user a code to enter on the genuine Microsoft sign-in page; the user completes MFA '
    + 'and the attacker receives the tokens. Most organizations only need this flow on a few shared or input-constrained devices.',
));

// ---------- BAS-05 ----------

const BAS05: RuleMeta = {
  id: 'BAS-05', title: 'Authentication transfer not controlled', family: 'baseline', severity: 'low',
  requiredLicense: 'entraP1',
  remediation: 'Create a policy: Users = the users who may not use personal devices (or All users, '
    + `${BREAK_GLASS}), Target resources = All resources, Conditions > Authentication flows = Authentication transfer, `
    + `Grant = Block access. ${REVIEW_THEN_ENABLE}`,
  references: [REF.authTransfer, REF.blockAuthFlows],
};

const bas05 = policyMatchRule(BAS05,
  p => isBlock(p) && !!p.conditions.authenticationFlows?.transferMethods.includes('authenticationTransfer'),
  'No enforced policy blocks authentication transfer. Authentication transfer lets a user move a signed-in session from a computer to a '
    + 'Microsoft mobile app such as Outlook by scanning a QR code, which can carry corporate sessions onto personal phones that no device '
    + 'policy has checked. This matters where personal devices are not allowed.');

// ---------- BAS-06 ----------

const BAS06: RuleMeta = {
  id: 'BAS-06', title: 'Unknown or unsupported device platforms not blocked', family: 'baseline', severity: 'medium',
  requiredLicense: 'entraP1',
  remediation: 'Create a policy from the "Block access for unknown or unsupported device platform" template: Users = All users '
    + `(${BREAK_GLASS}), Target resources = All resources, Conditions > Device platforms = Any device, excluding the platforms you `
    + `support (for example Android, iOS, Windows and macOS), Grant = Block access. ${REVIEW_THEN_ENABLE}`,
  references: [REF.unknownPlatforms, REF.conditions],
};

const bas06 = policyMatchRule(BAS06,
  p => isBlock(p) && includesAllUsers(p) && includesAllApps(p)
    && !!p.conditions.platforms?.includePlatforms.includes('all') && (p.conditions.platforms?.excludePlatforms.length ?? 0) > 0,
  'No enforced policy blocks unknown or unsupported device platforms for all users on all resources. The device platform is read from '
    + 'the user agent, which an attacker can blank or spoof (for example as ChromeOS or Linux) so that policies scoped to known '
    + 'platforms such as Windows or iOS do not apply to them.');

// ---------- BAS-07 ----------

const BAS07: RuleMeta = {
  id: 'BAS-07', title: 'Guests and external users not required to use MFA', family: 'baseline', severity: 'high',
  requiredLicense: 'entraP1',
  remediation: 'Create a policy from the "Require multifactor authentication for guest access" template (Users = Guest or external users, '
    + 'all types and all external tenants; Target resources = All resources; Grant = Require multifactor authentication), or remove the '
    + 'guest exclusion from your all-users MFA policy. Configure cross-tenant access settings to trust MFA from partner tenants to avoid '
    + 'double prompts.',
  references: [REF.commonPolicies],
};

const bas07 = coverageRule(BAS07, 'guests', 'allResources', 'mfa', byLevel(
  'No enforced policy requires MFA for guests and external users on all resources.',
  'Guests and external users are not fully required to use MFA on all resources.',
  'Their accounts and passwords are managed outside your organization, so a compromised guest credential gives direct access to the '
    + 'files, Teams and apps shared with them.',
));

// ---------- BAS-08 ----------

const BAS08: RuleMeta = {
  id: 'BAS-08', title: 'Security info registration not protected', family: 'baseline', severity: 'high',
  requiredLicense: 'entraP1',
  remediation: 'Create a policy from the "Securing security info registration" template: Users = All users '
    + `(${BREAK_GLASS}), Target resources = User actions > Register security information, Grant = Require multifactor authentication `
    + 'or an authentication strength (a compliant or hybrid joined device also works). Issue a Temporary Access Pass to new users who '
    + 'have no method yet so they can satisfy the policy when they first register.',
  references: [REF.securityInfo, REF.cloudApps],
};

const describeBas08 = byLevel(
  'No enforced policy requires MFA or a managed device for all users on the "Register security information" user action.',
  'The "Register security information" user action is not fully protected for all users.',
  'An attacker who knows only a user\'s password can register their own authenticator app, phone number or passkey and pass MFA from '
    + 'then on. Since July 6, 2026 this user action also governs Windows Hello for Business and macOS Platform SSO credential registration.',
);

const RANK: Record<Contribution['level'], number> = { none: 0, reportOnly: 1, partial: 2, full: 3 };

const bas08: Rule = {
  id: BAS08.id,
  family: BAS08.family,
  run: ctx => {
    const byMfa = bestCoverage(ctx.policies, 'allUsers', 'registerSecurityInfo', 'mfa', ctx.tenant);
    const byDevice = bestCoverage(ctx.policies, 'allUsers', 'registerSecurityInfo', 'managedDevice', ctx.tenant);
    const best = RANK[byMfa.level] === RANK[byDevice.level]
      ? {
        level: byMfa.level,
        reasons: [...new Set([...byMfa.reasons, ...byDevice.reasons])],
        policyIds: [...new Set([...byMfa.policyIds, ...byDevice.policyIds])],
      }
      : RANK[byMfa.level] > RANK[byDevice.level] ? byMfa : byDevice;
    return coverageFindings(BAS08, ctx, best, describeBas08);
  },
};

// ---------- BAS-09 ----------

const BAS09: RuleMeta = {
  id: 'BAS-09', title: 'Device registration or join not protected, or uses unsupported configuration', family: 'baseline', severity: 'medium',
  requiredLicense: 'entraP1',
  remediation: `Create a policy: Users = All users (${BREAK_GLASS}), Target resources = User actions > Register or join devices, `
    + 'Grant = Require multifactor authentication or an authentication strength. Then set Devices > Device settings > "Require '
    + 'Multifactor Authentication to register or join devices with Microsoft Entra" to No; otherwise the Conditional Access policy is '
    + 'not properly enforced.',
  references: [REF.cloudApps],
};

const BAS09_UNSUPPORTED: RuleMeta = {
  ...BAS09,
  remediation: 'Edit the policy so that its only grant is Require multifactor authentication or Require authentication strength, and '
    + 'remove location, client app and filter for devices conditions. Do not rely on locations to restrict who can register devices; '
    + 'require MFA or an authentication strength instead.',
  references: [REF.cloudApps, REF.deviceFilters],
};

const bas09Coverage = coverageRule(BAS09, 'allUsers', 'registerDevice', 'mfa', byLevel(
  'No enforced policy requires MFA or an authentication strength for all users on the "Register or join devices" user action.',
  'The "Register or join devices" user action is not fully protected with MFA for all users.',
  'An attacker with only a password can register or join a device of their own, obtain a Primary Refresh Token and then satisfy '
    + 'policies that trust registered devices.',
));

const CONTROL_NAMES: Record<string, string> = {
  block: 'block access', compliantDevice: 'compliant device', domainJoinedDevice: 'hybrid joined device',
  approvedApplication: 'approved client app', compliantApplication: 'app protection policy', passwordChange: 'password change',
  riskRemediation: 'risk remediation',
};

function unsupportedRegisterDevice(p: CAPolicy): string[] {
  const c = p.conditions;
  const g = p.grantControls;
  const grants = [
    ...(g?.builtInControls.filter(x => x !== 'mfa').map(x => CONTROL_NAMES[x] ?? x) ?? []),
    ...(g?.termsOfUse.length ? ['terms of use'] : []),
    ...(g?.customAuthenticationFactors.length ? ['custom controls'] : []),
  ];
  const loc = c.locations;
  const problems: string[] = [];
  if (grants.length) problems.push(`grant controls other than MFA or authentication strength (${grants.join(', ')}) are not available for this user action`);
  if (loc && (loc.excludeLocations.length > 0 || loc.includeLocations.some(x => x !== 'All'))) {
    problems.push('it uses a location condition, but location conditions are not enforced for device registration');
  }
  if (c.devices?.deviceFilter) problems.push('it uses a filter for devices, which is not available for this user action');
  if (!c.clientAppTypes.includes('all')) problems.push(`it limits client apps (${c.clientAppTypes.join(', ')}), which is not available for this user action`);
  return problems;
}

const targetsRegisterDevice = (p: CAPolicy) => p.conditions.applications.includeUserActions.some(a => a.toLowerCase() === USER_ACTION.registerDevice);

const bas09: Rule = {
  id: BAS09.id,
  family: BAS09.family,
  run: (ctx: RuleContext) => [
    ...bas09Coverage.run(ctx),
    ...ctx.policies.filter(p => isActive(p) && targetsRegisterDevice(p)).flatMap(p => {
      const problems = unsupportedRegisterDevice(p);
      return problems.length ? [makeFinding(BAS09_UNSUPPORTED, ctx, {
        policyIds: [p.id],
        explanation: `${policyNames(ctx, [p.id])} targets the "Register or join devices" user action with an unsupported configuration: `
          + `${problems.join('; ')}. Unsupported settings are ignored or break enforcement, so device registration is less protected `
          + 'than the policy suggests.',
      })] : [];
    }),
  ],
};

// ---------- BAS-10 ----------

const BAS10: RuleMeta = {
  id: 'BAS-10', title: 'No managed-device requirement for users', family: 'baseline', severity: 'medium',
  requiredLicense: 'intune',
  remediation: 'Enroll devices in Microsoft Intune and assign compliance policies, then create a policy from the "Require a compliant '
    + `device" template: Users = All users (${BREAK_GLASS}), Target resources = All resources, Grant = Require device to be marked as `
    + 'compliant OR Require Microsoft Entra hybrid joined device. The "Require compliant or hybrid joined device or multifactor '
    + 'authentication for all users" template is a weaker first step. At minimum enforce a managed device for administrators.',
  references: [REF.deviceCompliance, REF.compliantHybridOrMfa],
};

const bas10 = coverageRule(BAS10, 'allUsers', 'allResources', 'managedDevice', byLevel(
  'No enforced policy requires a compliant or hybrid joined device for all users on all resources.',
  'A compliant or hybrid joined device is not required for all users on all resources in every case.',
  'Without it, an attacker with a user\'s credentials and session can sign in from any computer they control, and corporate data can '
    + 'be downloaded to unmanaged devices.',
));

// ---------- BAS-11 ----------

const BAS11: RuleMeta = {
  id: 'BAS-11', title: 'No sign-in frequency or persistent browser control for unmanaged devices', family: 'baseline', severity: 'medium',
  requiredLicense: 'entraP1',
  remediation: 'Create a policy from the "Require reauthentication and disable browser persistence" guidance: Users = All users '
    + `(${BREAK_GLASS}), Target resources = All resources, Conditions > Filter for devices include `
    + '`device.isCompliant -ne True -or device.trustType -ne "ServerAD"` (matches unmanaged and unregistered devices), Session = '
    + 'Sign-in frequency 1 hour and Persistent browser session Never persistent.',
  references: [REF.persistentBrowser, REF.deviceFilters],
};

const bas11 = policyMatchRule(BAS11,
  p => includesAllUsers(p) && includesAllApps(p) && !!p.conditions.devices?.deviceFilter
    && !!p.sessionControls?.signInFrequency?.isEnabled
    && !!p.sessionControls.persistentBrowser?.isEnabled && p.sessionControls.persistentBrowser.mode === 'never',
  'No enforced policy requires periodic reauthentication and disables persistent browser sessions on unmanaged devices for all users '
    + 'on all resources. On a shared, personal or attacker-controlled computer a browser session that is left signed in stays usable '
    + 'long after the user walks away.');

export const baselineRules: Rule[] = [bas01, bas02, bas03, bas04, bas05, bas06, bas07, bas08, bas09, bas10, bas11];
