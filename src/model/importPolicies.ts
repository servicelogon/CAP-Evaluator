import { normalizePolicy, PolicyValidationError } from './normalize';
import type { CAPolicy } from './types';

export function parseImport(text: string): { policies: CAPolicy[]; errors: string[]; notes: string[] } {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (e) {
    return { policies: [], errors: [`Invalid JSON: ${e instanceof Error ? e.message : String(e)}`], notes: [] };
  }

  let items: unknown[];
  if (Array.isArray(data)) items = data;
  else if (typeof data === 'object' && data !== null && Array.isArray((data as { value?: unknown }).value)) items = (data as { value: unknown[] }).value;
  else if (typeof data === 'object' && data !== null) items = [data];
  else return { policies: [], errors: ['Expected a policy object, an array of policies, or { "value": [...] }'], notes: [] };

  const policies: CAPolicy[] = [];
  const errors: string[] = [];
  const notes: string[] = [];
  items.forEach((item, i) => {
    try {
      const { policy, notes: policyNotes } = normalizePolicy(item, i);
      policies.push(policy);
      notes.push(...policyNotes.map((n) => `${policy.displayName}: ${n}`));
    } catch (e) {
      if (!(e instanceof PolicyValidationError)) throw e;
      errors.push(e.message);
    }
  });
  return { policies, errors, notes };
}
