import { expect, test, vi } from 'vitest';
import { parseImport } from './importPolicies';
import { blankPolicy } from './newPolicy';

const mk = (name: string) => ({ displayName: name, state: 'enabled', conditions: { users: { includeUsers: ['All'] }, applications: { includeApplications: ['All'] } } });

test('single object yields one policy', () => {
  const r = parseImport(JSON.stringify(mk('A')));
  expect(r.policies).toHaveLength(1);
  expect(r.errors).toEqual([]);
});
test('array of two yields two policies', () => {
  expect(parseImport(JSON.stringify([mk('A'), mk('B')])).policies).toHaveLength(2);
});
test('Graph { value: [...] } envelope yields two policies', () => {
  expect(parseImport(JSON.stringify({ value: [mk('A'), mk('B')] })).policies).toHaveLength(2);
});
test('invalid JSON reports an error', () => {
  const r = parseImport('{bad');
  expect(r.policies).toEqual([]);
  expect(r.errors[0]).toMatch(/^Invalid JSON/);
});
test('one valid and one empty object yields one policy and one error', () => {
  const r = parseImport(JSON.stringify([mk('A'), {}]));
  expect(r.policies).toHaveLength(1);
  expect(r.errors).toHaveLength(1);
});
test('notes are prefixed with the policy name', () => {
  const r = parseImport(JSON.stringify([{ ...mk('A'), surprise: true }]));
  expect(r.notes[0]).toMatch(/^A: .*surprise/);
});
test('blankPolicy has report-only defaults', () => {
  const p = blankPolicy();
  expect(p.state).toBe('enabledForReportingButNotEnforced');
  expect(p.conditions.users.includeUsers).toEqual([]);
  expect(p.conditions.applications.includeApplications).toEqual([]);
  expect(p.conditions.clientAppTypes).toEqual(['all']);
  expect(p.grantControls?.operator).toBe('OR');
  expect(p.grantControls?.builtInControls).toEqual([]);
});
test('blankPolicy still gets an id when randomUUID is unavailable', () => {
  const real = globalThis.crypto;
  vi.stubGlobal('crypto', { getRandomValues: real.getRandomValues.bind(real) });
  try {
    const p = blankPolicy();
    expect(p.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  } finally {
    vi.unstubAllGlobals();
  }
});
