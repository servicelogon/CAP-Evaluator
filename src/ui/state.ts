import { DEFAULT_TENANT, type CAPolicy, type TenantProfile } from '../model/types';

export type Step = 'tenant' | 'policies' | 'analysis' | 'export';

export interface AppState {
  step: Step;
  tenant: TenantProfile;
  policies: CAPolicy[];
}

export const STORAGE_KEY = 'ca-gap-evaluator:v1';

export const STEPS: { id: Step; label: string; index: number }[] = [
  { id: 'tenant', label: 'Tenant setup', index: 0 },
  { id: 'policies', label: 'Policies', index: 1 },
  { id: 'analysis', label: 'Analysis', index: 2 },
  { id: 'export', label: 'Export', index: 3 },
];

export const INITIAL_STATE: AppState = {
  step: 'tenant',
  tenant: structuredClone(DEFAULT_TENANT),
  policies: [],
};

function isTenant(value: unknown): value is TenantProfile {
  if (!value || typeof value !== 'object') return false;
  const t = value as TenantProfile;
  return !!t.licenses && Array.isArray(t.breakGlass) && typeof t.displayNames === 'object';
}

export function loadState(): AppState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return structuredClone(INITIAL_STATE);
    const parsed = JSON.parse(raw) as Partial<AppState>;
    if (!isTenant(parsed.tenant) || !Array.isArray(parsed.policies)) return structuredClone(INITIAL_STATE);
    const step = STEPS.some((s) => s.id === parsed.step) ? parsed.step! : 'tenant';
    return { step, tenant: parsed.tenant, policies: parsed.policies };
  } catch {
    return structuredClone(INITIAL_STATE);
  }
}

export function saveState(state: AppState): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

export function clearState(): void {
  localStorage.removeItem(STORAGE_KEY);
}

export function stepIndex(step: Step): number {
  return STEPS.find((s) => s.id === step)?.index ?? 0;
}

export function stepByIndex(index: number): Step {
  return STEPS[Math.max(0, Math.min(STEPS.length - 1, index))]!.id;
}
