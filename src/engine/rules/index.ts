import { adminRules } from './admin';
import { appRules } from './apps';
import { baselineRules } from './baseline';
import { hygieneRules } from './hygiene';
import { riskRules } from './risk';
import type { Rule } from './types';
import { weakeningRules } from './weakening';

export const ALL_RULES: Rule[] = [...baselineRules, ...adminRules, ...appRules, ...weakeningRules, ...riskRules, ...hygieneRules];
