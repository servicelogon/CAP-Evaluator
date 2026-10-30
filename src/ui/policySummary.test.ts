import { describe, expect, test } from 'vitest';
import { KEYWORD } from '../catalog/apps';
import { blankPolicy } from '../model/newPolicy';
import { policyCardSummary } from './policySummary';

describe('policyCardSummary', () => {
  test('blank policy has no users, resources, or grant selected', () => {
    expect(policyCardSummary(blankPolicy())).toEqual({
      who: 'Not configured',
      resources: 'Not configured',
      access: 'Not configured',
    });
  });

  test('all users, all resources, block', () => {
    const policy = blankPolicy();
    policy.conditions.users.includeUsers = ['All'];
    policy.conditions.applications.includeApplications = [KEYWORD.all];
    policy.grantControls = {
      operator: 'OR', builtInControls: ['block'], customAuthenticationFactors: [], termsOfUse: [], authenticationStrength: null,
    };
    expect(policyCardSummary(policy)).toEqual({
      who: 'All users',
      resources: 'All resources',
      access: 'Block access',
    });
  });

  test('report-only is not part of the access line; the badge already says it', () => {
    const policy = blankPolicy();
    policy.state = 'enabledForReportingButNotEnforced';
    policy.conditions.users.includeUsers = ['All'];
    policy.grantControls = {
      operator: 'OR',
      builtInControls: ['mfa'],
      customAuthenticationFactors: [],
      termsOfUse: [],
      authenticationStrength: null,
    };
    expect(policyCardSummary(policy).access).toBe('Require one: mfa');
  });
});
