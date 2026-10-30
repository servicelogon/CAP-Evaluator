import { KEYWORD, appLabel } from '../catalog/apps';
import type { CAPolicy } from '../model/types';

export interface PolicyCardSummary {
  who: string;
  resources: string;
  access: string;
}

export function policyCardSummary(policy: CAPolicy): PolicyCardSummary {
  const users = policy.conditions.users;
  const apps = policy.conditions.applications;
  let who = 'Not configured';
  if (users.includeUsers.includes('All')) who = 'All users';
  else if (
    users.includeUsers.length === 1 && users.includeUsers[0] === 'None'
    && users.includeGroups.length === 0 && users.includeRoles.length === 0 && !users.includeGuestsOrExternalUsers
  ) who = 'None';
  else {
    const parts: string[] = [];
    if (users.includeUsers.some((id) => id !== 'All' && id !== 'None') || users.includeGroups.length) parts.push('Select users and groups');
    if (users.includeRoles.length) parts.push(`${users.includeRoles.length} roles`);
    if (users.includeGuestsOrExternalUsers) parts.push('Guests');
    if (parts.length) who = parts.join(', ');
  }

  let resources = 'Not configured';
  if (apps.includeUserActions.length) resources = 'User actions';
  else if (apps.includeAuthenticationContextClassReferences.length && apps.includeApplications.length === 0) resources = 'Authentication context';
  else if (apps.includeApplications.includes(KEYWORD.all)) resources = 'All resources';
  else if (apps.includeApplications.length === 1 && apps.includeApplications[0] === KEYWORD.office365) resources = 'Office 365';
  else if (apps.includeApplications.length === 1 && apps.includeApplications[0] === KEYWORD.adminPortals) resources = 'Microsoft Admin Portals';
  else if (apps.includeApplications.length) resources = apps.includeApplications.map(appLabel).slice(0, 2).join(', ');

  const grant = policy.grantControls;
  let access = 'Not configured';
  if (grant?.builtInControls.includes('block')) access = 'Block access';
  else if (grant) {
    const names = grant.builtInControls.filter((control) => control !== 'block');
    if (grant.authenticationStrength?.displayName) names.push(grant.authenticationStrength.displayName);
    if (names.length) access = `${grant.operator === 'AND' ? 'Require all' : 'Require one'}: ${names.join(', ')}`;
  }

  return { who, resources, access };
}
