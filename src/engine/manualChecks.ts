import { USER_ACTION } from '../catalog/apps';
import type { CAPolicy, Finding, ManualCheck } from '../model/types';
import { isActive } from './predicates';
import type { RuleContext } from './rules/types';

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CA = 'Entra admin center > Entra ID > Conditional Access';

const CHECKS: ManualCheck[] = [
  {
    id: 'MC-01', title: 'Check membership of included and excluded groups',
    why: 'Policy JSON only contains group IDs, not who is in them. An empty include group makes a policy apply to nobody, and an '
      + 'oversized or nested exclusion group can quietly remove many users from a baseline.',
    where: 'Entra admin center > Groups > All groups > (group) > Members. Check transitive (nested) members, include groups that are '
      + 'empty and exclude groups that hold more than your break-glass accounts.',
    relatedRuleIds: ['WEK-01', 'WEK-02', 'ADM-05'],
  },
  {
    id: 'MC-02', title: 'Check PIM eligible assignments for targeted roles',
    why: 'Role-scoped policies only apply to active role assignments. Administrators who are only eligible in Privileged Identity '
      + 'Management are not covered until they activate the role.',
    where: 'Entra admin center > ID Governance > Privileged Identity Management > Microsoft Entra roles > Assignments > Eligible assignments.',
    relatedRuleIds: ['ADM-05', 'ADM-01', 'ADM-02'],
  },
  {
    id: 'MC-03', title: 'Confirm targeted app IDs exist as service principals',
    why: 'A policy can name an application ID that has no service principal in your tenant, so the include or exclude does nothing. '
      + 'Some Microsoft apps, such as Microsoft Intune Enrollment, are not created automatically in new tenants.',
    where: 'Entra admin center > Enterprise apps > All applications, set Application type to Microsoft Applications and search by '
      + 'application ID.',
    relatedRuleIds: ['APP-02', 'APP-03'],
  },
  {
    id: 'MC-04', title: 'Check whether included groups contain service principals',
    why: 'Conditional Access is not enforced on service principals through group membership, so a service principal in an included '
      + 'group is not protected by that policy.',
    where: 'Entra admin center > Groups > All groups > (group) > Members; look for members of type Service principal. Target them with '
      + 'a workload identity policy instead.',
    relatedRuleIds: ['RSK-03'],
  },
  {
    id: 'MC-05', title: 'Check the baseline scopes enforcement setting',
    why: 'All resources policies with app exclusions used to skip low-privilege scopes such as User.Read. Tenants that opted out of '
      + 'the new enforcement still have that hole, and the setting is not part of the policy JSON.',
    where: 'https://aka.ms/BaselineScopesSettingsUX',
    relatedRuleIds: ['APP-01', 'APP-06'],
  },
  {
    id: 'MC-06', title: 'Check the device registration MFA setting',
    why: 'When a Conditional Access policy protects device registration, the tenant-wide device setting must be off; otherwise the '
      + 'policy is not properly enforced. The setting is not part of the policy JSON.',
    where: 'Entra admin center > Entra ID > Devices > Device settings > "Require Multifactor Authentication to register or join devices '
      + 'with Microsoft Entra" must be No.',
    relatedRuleIds: ['BAS-09'],
  },
  {
    id: 'MC-07', title: 'Review legacy MFA trusted IPs',
    why: '"All trusted locations" also includes the trusted IPs from the legacy per-user MFA service settings, which are configured '
      + 'outside Conditional Access and do not appear in the policy JSON.',
    where: `${CA} > Named locations > Configure MFA trusted IPs (legacy per-user MFA service settings).`,
    relatedRuleIds: ['WEK-04'],
  },
  {
    id: 'MC-08', title: 'Check the security defaults state',
    why: 'Security defaults and Conditional Access are alternatives: if security defaults are off and your policies leave gaps, '
      + 'nothing else enforces MFA. The setting is not part of the policy JSON.',
    where: 'Entra admin center > Entra ID > Overview > Properties > Manage security defaults.',
    relatedRuleIds: ['BAS-03'],
  },
  {
    id: 'MC-09', title: 'Check that targeted authentication contexts are published and used',
    why: 'A policy on an authentication context only applies when something requests that context. If the context is unpublished or '
      + 'nothing uses it, the policy never runs.',
    where: `${CA} > Authentication contexts. Confirm each targeted context is published and used by SharePoint sensitivity labels, `
      + 'PIM role settings or Microsoft Defender for Cloud Apps.',
    relatedRuleIds: [],
  },
  {
    id: 'MC-10', title: 'Azure Government tenants use a different management app',
    why: 'This tool assumes the commercial cloud. In Azure Government, Azure management is protected through a different app, so '
      + 'policies on Windows Azure Service Management API may not cover it.',
    where: 'In government cloud tenants, target "Azure Government Cloud Management API" instead of Windows Azure Service Management API '
      + `(${CA} > (policy) > Target resources).`,
    relatedRuleIds: ['APP-07', 'ADM-04'],
  },
];

const lowerIncludes = (xs: string[], value: string) => xs.some(x => x.toLowerCase() === value.toLowerCase());

/** The manual checks from the spec's checklist that apply to these policies and findings, in checklist order. */
export function buildManualChecks(ctx: RuleContext, findings: Finding[]): ManualCheck[] {
  const active = ctx.policies.filter(isActive);
  const any = (pred: (p: CAPolicy) => boolean) => active.some(pred);
  const fired = (ruleId: string) => findings.some(f => f.ruleId === ruleId);
  const users = (p: CAPolicy) => p.conditions.users;
  const apps = (p: CAPolicy) => p.conditions.applications;

  const applies: Record<string, boolean> = {
    'MC-01': any(p => users(p).includeGroups.length > 0 || users(p).excludeGroups.length > 0),
    'MC-02': fired('ADM-05'),
    'MC-03': any(p => [...apps(p).includeApplications, ...apps(p).excludeApplications].some(id => GUID.test(id))),
    'MC-04': any(p => users(p).includeGroups.length > 0),
    'MC-05': fired('APP-01'),
    'MC-06': any(p => lowerIncludes(apps(p).includeUserActions, USER_ACTION.registerDevice)),
    'MC-07': any(p => !!p.conditions.locations
      && lowerIncludes([...p.conditions.locations.includeLocations, ...p.conditions.locations.excludeLocations], 'AllTrusted')),
    'MC-08': true,
    'MC-09': any(p => apps(p).includeAuthenticationContextClassReferences.length > 0),
    'MC-10': true,
  };
  return CHECKS.filter(c => applies[c.id]);
}
