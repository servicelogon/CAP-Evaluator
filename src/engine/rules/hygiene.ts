import type { CAPolicy } from '../../model/types';
import { grantAlternatives, isEnforced } from '../predicates';
import { perPolicyRule, policyNames, type Rule, type RuleMeta } from './types';

const LEARN = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access';
const REF = {
  managedPolicies: `${LEARN}/managed-policies`,
  policies: `${LEARN}/concept-conditional-access-policies`,
};

// ---------- HYG-02 ----------

const HYG02: RuleMeta = {
  id: 'HYG-02', title: 'Disabled policy', family: 'hygiene', severity: 'low',
  remediation: 'Delete policies you no longer need, or review their impact in report-only and turn them back on. Microsoft-managed '
    + 'policies cannot be deleted: turn them back on, or record why your organization opted out.',
  references: [REF.managedPolicies, REF.policies],
};

const MANAGED_PREFIX = 'microsoft-managed:';
const isManaged = (p: CAPolicy) => p.displayName.trim().toLowerCase().startsWith(MANAGED_PREFIX);

const hyg02 = perPolicyRule(HYG02,
  () => ['disabled'],
  (ctx, p) => (isManaged(p)
    ? `${policyNames(ctx, [p.id])} is a Microsoft-managed policy that has been turned off. Microsoft deploys these policies as a security `
      + 'baseline and enables them automatically unless an administrator opts out, so turning one off removes a protection Microsoft '
      + 'considers essential.'
    : `${policyNames(ctx, [p.id])} is disabled and has no effect. Stale disabled policies clutter the policy list and can be turned on `
      + 'by mistake, or hide that a protection everyone assumes is in place was switched off.'),
  { scope: p => p.state === 'disabled', severity: p => (isManaged(p) ? 'medium' : 'low') });

// ---------- HYG-03 ----------

const HYG03: RuleMeta = {
  id: 'HYG-03', title: 'Policy has no effective controls or no assignees', family: 'hygiene', severity: 'low',
  remediation: 'Configure the users, target resources and grant or session controls the policy is meant to have, or delete it.',
  references: [REF.policies],
};

function hasSessionControl(p: CAPolicy): boolean {
  const s = p.sessionControls;
  if (!s) return false;
  return !!s.applicationEnforcedRestrictions?.isEnabled || !!s.cloudAppSecurity?.isEnabled || !!s.signInFrequency?.isEnabled
    || !!s.persistentBrowser?.isEnabled || !!s.secureSignInSession?.isEnabled || s.continuousAccessEvaluation !== null
    || s.disableResilienceDefaults === true;
}

const onlyNone = (xs: string[]) => xs.every(x => x.toLowerCase() === 'none');

function noAssignees(p: CAPolicy): boolean {
  const u = p.conditions.users;
  const sp = p.conditions.clientApplications;
  return onlyNone(u.includeUsers) && !u.includeGroups.length && !u.includeRoles.length && u.includeGuestsOrExternalUsers === null
    && !sp?.includeServicePrincipals.length && !sp?.includeAgentIdServicePrincipals?.length;
}

function noResources(p: CAPolicy): boolean {
  const a = p.conditions.applications;
  return onlyNone(a.includeApplications) && !a.includeUserActions.length && !a.includeAuthenticationContextClassReferences.length
    && a.applicationFilter?.mode !== 'include';
}

const hyg03 = perPolicyRule(HYG03,
  p => [
    ...(!grantAlternatives(p).length && !hasSessionControl(p) ? ['it has no grant or session controls, so it requires nothing'] : []),
    ...(noAssignees(p) ? ['it is assigned to no users, groups, roles, guests or workload identities'] : []),
    ...(noResources(p) ? ['it targets no resources, user actions or authentication contexts'] : []),
  ],
  (ctx, p, reasons) => `${policyNames(ctx, [p.id])} is ${isEnforced(p) ? 'turned on' : 'in report-only mode'} but has no effect: `
    + `${reasons.join('; ')}. A policy like this looks like `
    + 'protection in the policy list while enforcing nothing.');

export const hygieneRules: Rule[] = [hyg02, hyg03];
