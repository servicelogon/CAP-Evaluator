import { afterEach, describe, expect, test } from 'vitest';
import { DEFAULT_TENANT } from '../model/types';
import { blankPolicy } from '../model/newPolicy';
import { clearState, INITIAL_STATE, loadState, saveState, STORAGE_KEY } from './state';

describe('persistence', () => {
  afterEach(() => {
    localStorage.clear();
  });

  test('loadState returns initial state when empty', () => {
    expect(loadState()).toEqual(INITIAL_STATE);
  });

  test('round-trips policies and tenant', () => {
    const policy = blankPolicy();
    const state = {
      step: 'policies' as const,
      tenant: { ...DEFAULT_TENANT, breakGlass: ['bg-1'], licenses: { ...DEFAULT_TENANT.licenses, entraP2: true } },
      policies: [policy],
    };
    saveState(state);
    const loaded = loadState();
    expect(loaded.step).toBe('policies');
    expect(loaded.tenant.breakGlass).toEqual(['bg-1']);
    expect(loaded.tenant.licenses.entraP2).toBe(true);
    expect(loaded.policies).toHaveLength(1);
    expect(loaded.policies[0]?.displayName).toBe(policy.displayName);
  });

  test('corrupt JSON falls back to initial state', () => {
    localStorage.setItem(STORAGE_KEY, '{not json');
    expect(loadState()).toEqual(INITIAL_STATE);
  });

  test('clearState removes the key', () => {
    saveState(INITIAL_STATE);
    clearState();
    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });
});
