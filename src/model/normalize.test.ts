import { normalizePolicy } from './normalize';
const base = { displayName: 'P', state: 'enabled', conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] } } };
test('defaults clientAppTypes to all and fills arrays', () => {
  const { policy } = normalizePolicy(base, 0);
  expect(policy.conditions.clientAppTypes).toEqual(['all']);
  expect(policy.conditions.users.excludeUsers).toEqual([]);
  expect(policy.grantControls).toBeNull();
});
test('splits comma-separated flags', () => {
  const { policy } = normalizePolicy({ ...base, conditions: { ...base.conditions,
    authenticationFlows: { transferMethods: 'deviceCodeFlow,authenticationTransfer' }, insiderRiskLevels: 'elevated',
    users: { includeGuestsOrExternalUsers: { guestOrExternalUserTypes: 'internalGuest,b2bCollaborationGuest', externalTenants: { membershipKind: 'all' } } } } }, 0);
  expect(policy.conditions.authenticationFlows?.transferMethods).toEqual(['deviceCodeFlow', 'authenticationTransfer']);
  expect(policy.conditions.insiderRiskLevels).toEqual(['elevated']);
  expect(policy.conditions.users.includeGuestsOrExternalUsers?.guestOrExternalUserTypes).toEqual(['internalGuest', 'b2bCollaborationGuest']);
});
test('lower-cases GUIDs, keeps keywords', () => {
  const { policy } = normalizePolicy({ ...base, conditions: { ...base.conditions, applications: { includeApplications: ['Office365', '797F4846-BA00-4FD7-BA43-DAC1F8F63013'] } } }, 0);
  expect(policy.conditions.applications.includeApplications).toEqual(['Office365', '797f4846-ba00-4fd7-ba43-dac1f8f63013']);
});
test('upper-cases operator', () => {
  const { policy } = normalizePolicy({ ...base, grantControls: { operator: 'and', builtInControls: ['mfa'] } }, 0);
  expect(policy.grantControls?.operator).toBe('AND');
});
test('throws on missing users', () => {
  expect(() => normalizePolicy({ displayName: 'X', conditions: { applications: {} } }, 3)).toThrow(/X/);
});
test('preserves unknown props with a note', () => {
  const r = normalizePolicy({ ...base, fancyNewThing: 1 }, 0);
  expect(r.policy.extra).toEqual({ fancyNewThing: 1 });
  expect(r.notes[0]).toMatch(/fancyNewThing/);
});
test('throws PolicyValidationError with index when unnamed and not an object', async () => {
  const { PolicyValidationError } = await import('./normalize');
  expect(() => normalizePolicy(42, 1)).toThrow(PolicyValidationError);
  expect(() => normalizePolicy({ conditions: { users: {} } }, 1)).toThrow(/Policy 2/);
});
test('defaults id, displayName, invalid state; ignores metadata keys', () => {
  const r = normalizePolicy({ ...base, displayName: undefined, state: 'bogus', '@odata.context': 'x', createdDateTime: 't', description: 'd' }, 4);
  expect(r.policy.id).toMatch(/^[0-9a-f-]{36}$/);
  expect(r.policy.displayName).toBe('Policy 5');
  expect(r.policy.state).toBe('disabled');
  expect(r.policy.extra).toBeUndefined();
  expect(r.notes.some((n) => /state/.test(n))).toBe(true);
});
test('drops none from flags and fills grant/session defaults', () => {
  const { policy } = normalizePolicy({ ...base, conditions: { ...base.conditions, insiderRiskLevels: 'none' },
    grantControls: { authenticationStrength: { id: '00000000-0000-0000-0000-00000000000A' } },
    sessionControls: { signInFrequency: { isEnabled: true, frequencyInterval: 'everyTime' } } }, 0);
  expect(policy.conditions.insiderRiskLevels).toEqual([]);
  expect(policy.grantControls).toEqual({ operator: 'OR', builtInControls: [], customAuthenticationFactors: [], termsOfUse: [],
    authenticationStrength: { id: '00000000-0000-0000-0000-00000000000a' } });
  expect(policy.sessionControls?.persistentBrowser).toBeNull();
  expect(policy.sessionControls?.signInFrequency?.frequencyInterval).toBe('everyTime');
  expect(policy.sessionControls?.disableResilienceDefaults).toBeNull();
});
