import type { CAPolicy, Licenses, TenantProfile } from '../model/types';
import { DEFAULT_TENANT } from '../model/types';
import { normalizePolicy } from '../model/normalize';

export type DeepPartial<T> = T extends (infer U)[]
  ? DeepPartial<U>[]
  : T extends object ? { [K in keyof T]?: DeepPartial<T[K]> } : T;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Objects merge recursively; arrays, primitives and null replace. */
function deepMerge(base: unknown, over: unknown): unknown {
  if (over === undefined) return base;
  if (!isObj(base) || !isObj(over)) return over;
  const out: Obj = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = deepMerge(base[k], v);
  return out;
}

let seq = 0;

/** Normalized policy built from a default enabled All users / All resources / all clients policy. */
export function pol(overrides: DeepPartial<CAPolicy> & { displayName?: string }): CAPolicy {
  seq += 1;
  const base: Obj = {
    id: `p${seq}`,
    displayName: 'Test policy',
    state: 'enabled',
    conditions: {
      users: { includeUsers: ['All'] },
      applications: { includeApplications: ['All'] },
      clientAppTypes: ['all'],
    },
    grantControls: null,
    sessionControls: null,
  };
  const { grantControls, ...rest } = overrides;
  const merged = deepMerge(base, rest) as Obj;
  if (grantControls !== undefined) {
    merged.grantControls = grantControls === null ? null : deepMerge({ operator: 'OR', builtInControls: [] }, grantControls);
  }
  return normalizePolicy(merged, 0).policy;
}

export function tenant(o: Omit<Partial<TenantProfile>, 'licenses'> & { licenses?: Partial<Licenses> } = {}): TenantProfile {
  return { ...DEFAULT_TENANT, ...o, licenses: { ...DEFAULT_TENANT.licenses, ...o.licenses } };
}
