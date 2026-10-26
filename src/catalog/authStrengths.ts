import type { AuthStrengthRef } from '../model/types';

export const AUTH_STRENGTH = {
  mfa: '00000000-0000-0000-0000-000000000002',
  passwordless: '00000000-0000-0000-0000-000000000003',
  phishingResistant: '00000000-0000-0000-0000-000000000004',
};
export const PHISH_RESISTANT_METHODS = ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor'];

export function isPhishResistant(s: AuthStrengthRef | null): boolean {
  if (!s) return false;
  if (s.id === AUTH_STRENGTH.phishingResistant) return true;
  const combos = s.allowedCombinations ?? [];
  return combos.length > 0 && combos.every(c => PHISH_RESISTANT_METHODS.includes(c));
}
