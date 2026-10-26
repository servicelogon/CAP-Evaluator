import { normalizePolicy } from './normalize';
import type { CAPolicy } from './types';

export function blankPolicy(): CAPolicy {
  return normalizePolicy({
    displayName: 'New policy',
    state: 'enabledForReportingButNotEnforced',
    conditions: { users: {}, applications: {} },
    grantControls: { operator: 'OR' },
  }, 0).policy;
}
