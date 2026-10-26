export type PolicyState = 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced';
export interface GuestsOrExternalUsers {
  guestOrExternalUserTypes: string[];            // normalized from comma string
  externalTenants: { membershipKind: 'all' | 'enumerated' | 'unknownFutureValue'; members?: string[] } | null;
}
export interface CAUsers {
  includeUsers: string[]; excludeUsers: string[];
  includeGroups: string[]; excludeGroups: string[];
  includeRoles: string[]; excludeRoles: string[];
  includeGuestsOrExternalUsers: GuestsOrExternalUsers | null;
  excludeGuestsOrExternalUsers: GuestsOrExternalUsers | null;
}
export interface CAApplications {
  includeApplications: string[]; excludeApplications: string[];
  includeUserActions: string[]; includeAuthenticationContextClassReferences: string[];
  applicationFilter: { mode: 'include' | 'exclude'; rule: string } | null;
}
export interface CAClientApplications {
  includeServicePrincipals: string[]; excludeServicePrincipals: string[];
  servicePrincipalFilter: { mode: string; rule: string } | null;
  includeAgentIdServicePrincipals?: string[];
}
export interface CAConditions {
  users: CAUsers;
  applications: CAApplications;
  clientApplications: CAClientApplications | null;
  clientAppTypes: string[];                       // default ['all']
  platforms: { includePlatforms: string[]; excludePlatforms: string[] } | null;
  locations: { includeLocations: string[]; excludeLocations: string[] } | null;
  devices: { deviceFilter: { mode: 'include' | 'exclude'; rule: string } | null } | null;
  signInRiskLevels: string[]; userRiskLevels: string[]; servicePrincipalRiskLevels: string[];
  insiderRiskLevels: string[];                    // normalized from comma string
  authenticationFlows: { transferMethods: string[] } | null; // normalized
}
export interface AuthStrengthRef { id: string; displayName?: string; allowedCombinations?: string[]; requirementsSatisfied?: string }
export interface CAGrantControls {
  operator: 'AND' | 'OR';
  builtInControls: string[];
  customAuthenticationFactors: string[];
  termsOfUse: string[];
  authenticationStrength: AuthStrengthRef | null;
}
export interface CASessionControls {
  applicationEnforcedRestrictions: { isEnabled: boolean } | null;
  cloudAppSecurity: { isEnabled: boolean; cloudAppSecurityType?: string } | null;
  signInFrequency: { isEnabled: boolean; type?: 'days' | 'hours' | null; value?: number | null; frequencyInterval?: 'timeBased' | 'everyTime'; authenticationType?: string } | null;
  persistentBrowser: { isEnabled: boolean; mode: 'always' | 'never' } | null;
  continuousAccessEvaluation: { mode: string } | null;
  secureSignInSession: { isEnabled: boolean } | null;
  disableResilienceDefaults: boolean | null;
}
export interface CAPolicy {
  id: string; displayName: string; state: PolicyState; templateId?: string | null;
  conditions: CAConditions;
  grantControls: CAGrantControls | null;
  sessionControls: CASessionControls | null;
  extra?: Record<string, unknown>;                // unknown top-level props preserved
}
export interface Licenses { entraP1: boolean; entraP2: boolean; intune: boolean; workloadIdPremium: boolean; defenderForCloudApps: boolean; purviewInsiderRisk: boolean }
export interface TenantProfile { licenses: Licenses; breakGlass: string[]; displayNames: Record<string, string> }
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingStatus = 'gap' | 'partial' | 'requiresLicense' | 'unverified';
export type RuleFamily = 'baseline' | 'admin' | 'apps' | 'weakening' | 'risk' | 'hygiene';
export interface Finding {
  ruleId: string; title: string; family: RuleFamily; severity: Severity; status: FindingStatus;
  policyIds: string[]; explanation: string; remediation: string; references: string[]; requiredLicense?: string;
}
export interface ManualCheck { id: string; title: string; why: string; where: string; relatedRuleIds: string[] }
export type Population = 'allUsers' | 'admins' | 'guests';
export type CellState = 'covered' | 'partial' | 'gap' | 'requiresLicense' | 'na';
export interface MatrixCell { surface: string; control: string; state: CellState; policyIds: string[]; reasons: string[] }
export interface CoverageMatrix { population: Population; cells: MatrixCell[] }
export interface AnalysisResult {
  findings: Finding[]; manualChecks: ManualCheck[];
  matrices: Record<Population, CoverageMatrix>; score: number; generatedAt: string; catalogDate: string;
}
export const DEFAULT_TENANT: TenantProfile = {
  licenses: { entraP1: true, entraP2: false, intune: false, workloadIdPremium: false, defenderForCloudApps: false, purviewInsiderRisk: false },
  breakGlass: [], displayNames: {},
};
