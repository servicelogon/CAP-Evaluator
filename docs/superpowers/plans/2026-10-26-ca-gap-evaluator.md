# CA Gap Evaluator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a browser-only web app that analyzes Entra ID Conditional Access policies (entered manually or imported as Graph JSON) for coverage gaps, shows a heat map, and exports HTML/CSV/JSON reports.

**Architecture:** React + TypeScript SPA built with Vite. A pure TypeScript engine (`src/engine`) consumes Graph-shaped policies plus a tenant profile and returns findings, a coverage matrix, manual checks and a score. UI and report builders only consume `AnalysisResult`.

**Tech Stack:** Node 26, Vite, React 19, TypeScript (strict), Vitest, @testing-library/react (UI smoke tests only). No CSS framework, no runtime network calls.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-10-26-ca-gap-evaluator-design.md`. Research: `docs/research/*.md`.
- Apps are always matched by **app ID** (lower-cased GUID) or Graph keyword (`All`, `None`, `Office365`, `MicrosoftAdminPortals`), never display name.
- No network calls at runtime; all data in `localStorage` under key `ca-gap-evaluator:v1`.
- Rule IDs and severities exactly as in spec §4.3.
- Findings from UNVERIFIED research get `status: 'unverified'` and are excluded from the score.
- Score: `100 − Σ(weight)`, weights critical 15, high 8, medium 4, low 1, info 0; `partial` status = half weight; floor 0; `requiresLicense` and `unverified` excluded.
- Every rule has a triggering and a non-triggering test.
- Commit after each task.

---

## File Structure

```
package.json, tsconfig.json, vite.config.ts, index.html
src/
  main.tsx, App.tsx, styles.css
  model/
    types.ts            Graph-shaped CAPolicy + TenantProfile + result types
    normalize.ts        normalizePolicy(raw) -> CAPolicy (arrays, defaults, lower-case IDs)
    importPolicies.ts   parseImport(text) -> { policies, errors, notes }
    newPolicy.ts        blankPolicy() for the wizard
  catalog/
    apps.ts             APP_CATALOG, app IDs constants, lookupApp()
    roles.ts            PRIVILEGED_ROLES (14), EXTENDED_ROLES, roleName()
    authStrengths.ts    built-in auth strength IDs, isPhishResistant()
    surfaces.ts         SURFACES (heat-map rows) + CONTROLS (columns) + NA cells
  engine/
    predicates.ts       state, grant classification, condition narrowing
    coverage.ts         populationCoverage, surfaceCoverage, controlCoverage, bestCoverage
    rules/
      types.ts          Rule, RuleContext, helpers makeFinding()
      baseline.ts       BAS-01..11
      admin.ts          ADM-01..08
      apps.ts           APP-01..08
      weakening.ts      WEK-01..12
      risk.ts           RSK-01..06
      hygiene.ts        HYG-01..03
      index.ts          ALL_RULES
    manualChecks.ts     buildManualChecks()
    matrix.ts           buildMatrix()
    score.ts            computeScore()
    analyze.ts          analyze()
  report/
    csv.ts, json.ts, html.ts, download.ts
  samples/
    goodTenant.ts, weakTenant.ts
  state/
    store.tsx           React context + reducer + localStorage persistence
  ui/
    Stepper.tsx
    tenant/TenantSetup.tsx
    policies/PolicyList.tsx, ImportDialog.tsx, PolicyWizard.tsx,
    policies/sections/{Basics,Users,Resources,Network,Conditions,Grant,Session,Json}Section.tsx
    policies/AppPicker.tsx, IdListInput.tsx
    analysis/AnalysisView.tsx, HeatMap.tsx, CellDetail.tsx, FindingsList.tsx, ManualChecklist.tsx
    export/ExportView.tsx
tests/ (co-located as *.test.ts next to sources)
```

---

### Task 1: Scaffold project

**Files:** Create `package.json`, `tsconfig.json`, `vite.config.ts`, `index.html`, `src/main.tsx`, `src/App.tsx`, `src/styles.css`, `.gitignore`, `src/smoke.test.ts`.

- [ ] **Step 1:** `npm create vite@latest . -- --template react-ts` (non-interactive; if the directory is non-empty, scaffold into `/tmp/scaffold` and copy files over keeping `docs/`).
- [ ] **Step 2:** `npm i && npm i -D vitest @testing-library/react @testing-library/jest-dom jsdom`.
- [ ] **Step 3:** Add to `vite.config.ts`:

```ts
/// <reference types="vitest/config" />
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({
  plugins: [react()],
  base: './',
  test: { environment: 'jsdom', globals: true },
});
```

Add scripts: `"test": "vitest run"`, `"test:watch": "vitest"`.

- [ ] **Step 4:** Smoke test `src/smoke.test.ts`: `expect(1 + 1).toBe(2)`. Run `npm test` → PASS. Run `npm run build` → success.
- [ ] **Step 5:** Commit `chore: scaffold Vite React TS app with Vitest`.

---

### Task 2: Policy model, normalization, import

**Files:** Create `src/model/types.ts`, `src/model/normalize.ts`, `src/model/importPolicies.ts`, `src/model/newPolicy.ts`, tests `src/model/normalize.test.ts`, `src/model/importPolicies.test.ts`.

**Interfaces — Produces:**

```ts
// src/model/types.ts
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
```

`normalize.ts` exports `normalizePolicy(raw: unknown, index: number): { policy: CAPolicy; notes: string[] }` and throws `PolicyValidationError` (message includes policy index/name) when `raw` is not an object or `conditions.users`/`conditions.applications` are missing.

Normalization rules:
- `splitFlags(v)`: string → split on `,`, trim, drop empty and `none`; array → as-is; null → `[]`.
- All ID arrays: default `[]`; GUIDs lower-cased (`/^[0-9a-f-]{36}$/i`), keywords kept verbatim.
- `clientAppTypes`: empty/null → `['all']`.
- `grantControls.operator`: upper-case; default `'OR'`.
- `id` missing → `crypto.randomUUID()`; `displayName` missing → `Policy ${index+1}`; `state` invalid → `'disabled'` plus note.
- Unknown top-level keys (other than known + `@odata.*`, `createdDateTime`, `modifiedDateTime`, `deletedDateTime`, `partialEnablementStrategy`, `description`) → `extra`, with a note.

`importPolicies.ts` exports `parseImport(text: string): { policies: CAPolicy[]; errors: string[]; notes: string[] }` accepting a single object, an array, or `{ value: [...] }`; JSON syntax errors return `errors: ['Invalid JSON: <message>']`.

`newPolicy.ts` exports `blankPolicy(): CAPolicy` (state `enabledForReportingButNotEnforced`, includeUsers `[]`, includeApplications `[]`, clientAppTypes `['all']`, grantControls `{operator:'OR', builtInControls:[], ...}`).

- [ ] **Step 1: Write failing tests** (`normalize.test.ts`):

```ts
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
```

`importPolicies.test.ts`: single object → 1 policy; array of 2 → 2; `{value:[a,b]}` → 2; `'{bad'` → errors[0] starts `Invalid JSON`; array with one valid and one `{}` → 1 policy, 1 error.

- [ ] **Step 2:** `npm test` → FAIL (modules missing).
- [ ] **Step 3:** Implement the four files per the interfaces above.
- [ ] **Step 4:** `npm test` → PASS.
- [ ] **Step 5:** Commit `feat(model): Graph-shaped policy model, normalization and import`.

---

### Task 3: Catalog — apps, roles, auth strengths, surfaces

**Files:** Create `src/catalog/apps.ts`, `roles.ts`, `authStrengths.ts`, `surfaces.ts`, test `src/catalog/catalog.test.ts`.

**Produces:**

```ts
// apps.ts
export const APP = {
  exchangeOnline: '00000002-0000-0ff1-ce00-000000000000',
  sharePointOnline: '00000003-0000-0ff1-ce00-000000000000',
  teamsServices: 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe',
  teamsClient: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
  microsoftGraph: '00000003-0000-0000-c000-000000000000',
  azureAdGraph: '00000002-0000-0000-c000-000000000000',
  azurePortal: 'c44b4083-3bb0-49c1-b47d-974e53cbdf3c',
  exchangeAdminCenter: '497effe9-df71-4043-a8bb-14cf78c4b63b',
  office365Portal: '00000006-0000-0ff1-ce00-000000000000',
  protectionCenter: '80ccca67-54bd-44ab-8625-4b79c4dc7775',
  azureManagement: '797f4846-ba00-4fd7-ba43-dac1f8f63013',
  azureDevOps: '499b84ac-1321-427f-aa17-267ca6975798',
  intune: '0000000a-0000-0000-c000-000000000000',
  intuneEnrollment: 'd4ebce55-015a-49b5-a083-c84d1797ae8c',
  intuneWebCompanyPortal: '74bcdadc-2fdc-4bb3-8459-76d06952a0e9',
  intuneCompanyPortalClient: '9ba1a5c7-f17a-4de9-a1f1-6178c8d51223',
  deviceRegistrationService: '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9',
  graphPowerShell: '14d82eec-204b-4c2f-b7e8-296a70dab67e',
  graphExplorer: 'de8bc8b5-d9f9-48b1-a8ad-b748da725064',
  azureCli: '04b07795-8ddb-461a-bbee-02f9e1bf7b46',
  azurePowerShell: '1950a258-227b-4e31-a9cf-717495945fc2',
  azureMobileApp: '0c1307d4-29d6-4389-a11c-5cbe7f65d7fa',
  azureAdPowerShell: '1b730954-1685-4b74-9bfd-dac224a7b894',
  powerPlatformAdmin: '065d9450-1e87-434e-ac2f-69af271549ed',
  rightsManagement: '00000012-0000-0000-c000-000000000000',
  storeForBusiness: '45a330b1-b1ec-4cc1-9161-9f03992aa49f',
  authBroker: '29d9ed98-a469-4536-ade2-f981bc1d605e',
  authenticator: '4813382a-8fa7-425e-ab75-3b753aab3abb',
  gsaInternet: '5dc48733-b5df-475c-a49b-fa307ef00853',
} as const;
export const KEYWORD = { all: 'All', none: 'None', office365: 'Office365', adminPortals: 'MicrosoftAdminPortals' } as const;
export const USER_ACTION = { registerSecurityInfo: 'urn:user:registersecurityinfo', registerDevice: 'urn:user:registerdevice' } as const;
export const ADMIN_PORTAL_IDS = [APP.exchangeAdminCenter, APP.azurePortal, APP.office365Portal, APP.protectionCenter];
export const OFFICE365_KEY_IDS = [APP.exchangeOnline, APP.sharePointOnline, APP.teamsServices, APP.office365Portal, APP.protectionCenter];
export type SurfaceId = 'allResources' | 'office365' | 'adminPortals' | 'azureManagement' | 'graph' | 'intuneApi' | 'azureDevOps' | 'thirdParty' | 'registerSecurityInfo' | 'registerDevice';
export interface CatalogApp {
  appId: string; name: string; aliases: string[]; surface: SurfaceId | null;
  groups: ('Office365' | 'MicrosoftAdminPortals')[]; targetable: boolean; highValue: boolean;
  confidence: 'verified' | 'unverified'; notes: string; source: string;
}
export const APP_CATALOG: CatalogApp[];        // one entry per APP id, data from research §9
export function lookupApp(appId: string): CatalogApp | undefined;
export function appLabel(idOrKeyword: string): string; // "Office 365 (group)", catalog name, or "Unknown app (<guid>)"
export const CATALOG_DATE = '2026-10-26';
```

Catalog entries (`targetable:false` for client apps): graphPowerShell, azureCli, azurePowerShell, azureMobileApp, teamsClient, authBroker, intuneCompanyPortalClient, azureAdPowerShell (retired). `microsoftGraph` and `azureAdGraph` are `targetable:false` with notes "Covered only by All resources". `highValue:true`: exchangeOnline, sharePointOnline, teamsServices, azurePortal, azureManagement, intune, deviceRegistrationService, rightsManagement, exchangeAdminCenter. `unverified`: sharePointOnline, intune, intuneWebCompanyPortal, authBroker (community-sourced IDs). Surfaces: exchange/sharepoint/teams/office365Portal/protectionCenter → `office365` (portal IDs also listed under adminPortals via `groups`), azurePortal/exchangeAdminCenter → `adminPortals`, azureManagement → `azureManagement`, microsoftGraph/graphExplorer/azureAdGraph → `graph`, intune → `intuneApi`, azureDevOps → `azureDevOps`; everything else `null`.

```ts
// roles.ts
export const PRIVILEGED_ROLES: { id: string; name: string }[]; // the 14 template IDs from research §6
export const HYBRID_IDENTITY_ADMIN = '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2';
export const EXTENDED_ROLES: { id: string; name: string }[];   // research §6 "other commonly targeted"
export const GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10';
export function roleName(id: string): string | undefined;
export function isPrivilegedRole(id: string): boolean;          // in PRIVILEGED_ROLES
// authStrengths.ts
export const AUTH_STRENGTH = { mfa: '00000000-0000-0000-0000-000000000002', passwordless: '00000000-0000-0000-0000-000000000003', phishingResistant: '00000000-0000-0000-0000-000000000004' };
export const PHISH_RESISTANT_METHODS = ['windowsHelloForBusiness', 'fido2', 'x509CertificateMultiFactor'];
export function isPhishResistant(s: AuthStrengthRef | null): boolean; // id === …0004 OR allowedCombinations non-empty and ⊆ PHISH_RESISTANT_METHODS
// surfaces.ts
export type ControlId = 'legacyBlocked' | 'mfa' | 'phishResistant' | 'managedDevice' | 'deviceCodeBlocked' | 'signInRisk' | 'userRisk' | 'session';
export const SURFACES: { id: SurfaceId; label: string; description: string }[]; // order as spec §5
export const CONTROLS: { id: ControlId; label: string; license?: keyof Licenses; licenseLabel?: string }[];
// signInRisk & userRisk: license 'entraP2'; managedDevice: license 'intune'
export function isNA(surface: SurfaceId, control: ControlId): boolean;
// registerDevice: only mfa & phishResistant applicable. registerSecurityInfo: mfa, phishResistant, managedDevice applicable.
```

- [ ] **Step 1: Failing tests:**

```ts
test('every APP id has a catalog entry', () => { for (const id of Object.values(APP)) expect(lookupApp(id)).toBeDefined(); });
test('admin portals group = 4 ids', () => expect(ADMIN_PORTAL_IDS).toHaveLength(4));
test('graph powershell is not targetable', () => expect(lookupApp(APP.graphPowerShell)!.targetable).toBe(false));
test('appLabel unknown', () => expect(appLabel('11111111-1111-1111-1111-111111111111')).toMatch(/^Unknown app/));
test('14 privileged roles incl. GA', () => { expect(PRIVILEGED_ROLES).toHaveLength(14); expect(isPrivilegedRole(GLOBAL_ADMIN)).toBe(true); });
test('phish resistant', () => {
  expect(isPhishResistant({ id: AUTH_STRENGTH.phishingResistant })).toBe(true);
  expect(isPhishResistant({ id: 'custom', allowedCombinations: ['fido2'] })).toBe(true);
  expect(isPhishResistant({ id: AUTH_STRENGTH.mfa })).toBe(false);
});
test('NA cells', () => { expect(isNA('registerDevice', 'managedDevice')).toBe(true); expect(isNA('registerDevice', 'mfa')).toBe(false); });
```

- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** run → PASS.
- [ ] **Step 5:** Commit `feat(catalog): Microsoft app, role, auth strength and surface catalogs`.

---

### Task 4: Predicates and coverage primitives

**Files:** Create `src/engine/predicates.ts`, `src/engine/coverage.ts`, tests `src/engine/coverage.test.ts`, plus `src/engine/testUtils.ts` (fixture builder).

**Produces:**

```ts
// testUtils.ts — used by every engine test
export function pol(overrides: DeepPartial<CAPolicy> & { displayName?: string }): CAPolicy; // normalizePolicy over a default enabled All/All policy
export const tenant = (o?: Partial<TenantProfile>): TenantProfile;  // DEFAULT_TENANT + overrides, licenses merged
// predicates.ts
export const isEnforced = (p: CAPolicy) => p.state === 'enabled';
export const isReportOnly = (p: CAPolicy) => p.state === 'enabledForReportingButNotEnforced';
export const isActive = (p: CAPolicy) => isEnforced(p) || isReportOnly(p);
export const hasControl = (p: CAPolicy, c: string) => !!p.grantControls?.builtInControls.includes(c);
export const isBlock = (p: CAPolicy) => hasControl(p, 'block');
export const includesAllUsers = (p: CAPolicy) => p.conditions.users.includeUsers.includes('All');
export const includesAllApps = (p: CAPolicy) => p.conditions.applications.includeApplications.includes('All');
export function coversLegacyClients(p: CAPolicy): 'full' | 'partial' | 'none'; // all or {eas,other}=full; one of them=partial
export function coversModernClients(p: CAPolicy): boolean; // all, or browser+mobileAppsAndDesktopClients
/** Grant alternatives as a list: AND → [controls], OR → each control alone. Auth strength counts as one control 'authStrength'. */
export function grantAlternatives(p: CAPolicy): string[][];
export type Strength = 'full' | 'partial' | 'none';
export function mfaStrength(p: CAPolicy): Strength;          // every alternative contains mfa|authStrength → full; some → partial; none → none
export function phishStrength(p: CAPolicy): Strength;        // every alternative contains phish-resistant authStrength → full; some → partial
export function managedDeviceStrength(p: CAPolicy): Strength;// every alternative contains compliantDevice|domainJoinedDevice → full; some → partial
/** Conditions that remove the policy from being a baseline: risk, insider risk, auth flows, SP-only. */
export function isRiskOrFlowScoped(p: CAPolicy): boolean;
/** Narrowing conditions that make coverage partial; returns human-readable reasons. */
export function narrowingReasons(p: CAPolicy): string[];
// reasons: "excludes locations (…)", "only includes locations (…)", "only includes platforms (…)",
// "excludes platforms (…)", "does not cover browser and modern clients", "device filter (include|exclude: rule)"
```

```ts
// coverage.ts
export interface Contribution { level: 'full' | 'partial' | 'reportOnly' | 'none'; reasons: string[] }
export function populationCoverage(p: CAPolicy, pop: Population, t: TenantProfile): Contribution;
export function surfaceCoverage(p: CAPolicy, s: SurfaceId): Contribution;
export function controlCoverage(p: CAPolicy, c: ControlId): Contribution;
/** min of the three, then: disabled → none; report-only → full/partial downgraded to 'reportOnly'. */
export function policyContribution(p: CAPolicy, pop: Population, s: SurfaceId, c: ControlId, t: TenantProfile): Contribution;
/** Best contribution across policies (full > partial > reportOnly > none) with contributing policy IDs. */
export function bestCoverage(ps: CAPolicy[], pop: Population, s: SurfaceId, c: ControlId, t: TenantProfile): Contribution & { policyIds: string[] };
export function unexpectedExclusions(p: CAPolicy, t: TenantProfile): string[]; // excludeUsers+excludeGroups not in breakGlass, plus every excludeRoles and guest exclusion, rendered via displayNames/roleName
```

Exact semantics:

- **populationCoverage**
  - `allUsers`: `includeUsers` has `All` → full if `unexpectedExclusions` empty else partial (reason "excludes …"). Only groups/users/roles/guests included → partial ("scoped to specific groups/users/roles, not All users"). Nothing → none.
  - `admins`: `All` → full/partial as above, but `excludeRoles ∩ PRIVILEGED` → partial with reason. Else `includeRoles ⊇ PRIVILEGED` → full (partial if any privileged role excluded); `includeRoles` ∩ PRIVILEGED non-empty → partial ("covers N of 14 privileged roles"); `includeGroups` non-empty → partial ("scoped by group; cannot verify it contains all admins"). Else none.
  - `guests`: guest exclusion (`excludeGuestsOrExternalUsers` non-null or `excludeUsers` has `GuestsOrExternalUsers`) → none if it covers all six types, else partial. `All` → full (subject to other unexpected exclusions → partial). `includeUsers` has `GuestsOrExternalUsers` → full. `includeGuestsOrExternalUsers` with all six types and `membershipKind: 'all'` → full; otherwise partial. Else none.
- **surfaceCoverage**
  - user-action surfaces: `includeUserActions` contains the URN → full, else none.
  - otherwise if `includeUserActions` non-empty or include is only auth contexts → none.
  - `allResources`: `All` → full (partial "excludes N apps" when `excludeApplications` non-empty).
  - `office365`: `All` and not excluding `Office365`/key IDs → full (partial if any OFFICE365_KEY_IDS excluded); `Office365` → full; any of exchange/sharepoint/teams → partial ("targets individual workloads").
  - `adminPortals`: `All` not excluding `MicrosoftAdminPortals`/portal IDs → full; `MicrosoftAdminPortals` → full; all 4 portal IDs → full; some → partial.
  - `azureManagement`: `All` (not excluding it) or the app ID → full.
  - `graph`: `All` → full (partial when `excludeApplications` non-empty: reason "All resources with exclusions — verify baseline-scopes enforcement setting"); otherwise none (Graph is not targetable). `graphExplorer` included alone → partial.
  - `intuneApi`: `All` (not excluding) or `APP.intune` → full.
  - `azureDevOps`: `All` (not excluding) or `APP.azureDevOps` → full.
  - `thirdParty`: `All` → full (partial if excludes non-Microsoft app IDs); any included GUID not in catalog → partial ("covers only selected apps").
- **controlCoverage** (block policies are handled first):
  - `legacyBlocked`: requires `coversLegacyClients(p) !== 'none'` and (`isBlock` or any grant control) and not `isRiskOrFlowScoped`; level = coversLegacyClients result, then partial if `narrowingReasons` other than client-types.
  - `deviceCodeBlocked`: `isBlock` and transferMethods includes `deviceCodeFlow` → full (partial if narrowing reasons).
  - `signInRisk`: `signInRiskLevels` includes `high` and (`isBlock` or `mfaStrength !== 'none'`) → full; includes only medium/low → partial.
  - `userRisk`: `userRiskLevels` includes `high` and (`isBlock` or (`passwordChange` and `mfa`) or (`riskRemediation` and authStrength)) → full.
  - `mfa` / `phishResistant` / `managedDevice`: if `isRiskOrFlowScoped` or `coversModernClients` false → none. `isBlock` → full. Else the matching `*Strength`; then if `narrowingReasons` non-empty, full → partial.
  - `session`: not risk/flow scoped; `signInFrequency.isEnabled && persistentBrowser?.mode === 'never'` → full; either → partial; `persistentBrowser.mode === 'always'` contributes none.
  - Reasons always describe why partial (e.g. "Require one of: MFA OR compliant device").

- [ ] **Step 1: Failing tests** (`coverage.test.ts`), each a single `expect`:

```ts
const t = tenant({ breakGlass: ['bg-1'] });
test('All users with only break-glass exclusion is full', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeUsers: ['bg-1'] } } }), 'allUsers', t).level).toBe('full'));
test('All users excluding a group is partial', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeGroups: ['g1'] } } }), 'allUsers', t).level).toBe('partial'));
test('5 privileged roles is partial for admins', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeRoles: PRIVILEGED_ROLES.slice(0,5).map(r=>r.id) } } }), 'admins', t).level).toBe('partial'));
test('All 14 roles is full for admins', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: [], includeRoles: PRIVILEGED_ROLES.map(r=>r.id) } } }), 'admins', t).level).toBe('full'));
test('guest exclusion removes guests', () => expect(populationCoverage(pol({ conditions: { users: { includeUsers: ['All'], excludeUsers: ['GuestsOrExternalUsers'] } } }), 'guests', t).level).toBe('none'));
test('Admin portals policy does not cover graph', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['MicrosoftAdminPortals'] } } }), 'graph').level).toBe('none'));
test('Admin portals policy covers admin portals', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['MicrosoftAdminPortals'] } } }), 'adminPortals').level).toBe('full'));
test('Azure mgmt does not cover DevOps', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: [APP.azureManagement] } } }), 'azureDevOps').level).toBe('none'));
test('All resources does not cover user actions', () => expect(surfaceCoverage(pol({}), 'registerSecurityInfo').level).toBe('none'));
test('All with exclusions makes graph partial', () => expect(surfaceCoverage(pol({ conditions: { applications: { includeApplications: ['All'], excludeApplications: [APP.storeForBusiness] } } }), 'graph').level).toBe('partial'));
test('MFA OR compliant is partial mfa', () => expect(controlCoverage(pol({ grantControls: { operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] } }), 'mfa').level).toBe('partial'));
test('MFA AND compliant is full for both', () => { const p = pol({ grantControls: { operator: 'AND', builtInControls: ['mfa', 'compliantDevice'] } }); expect(controlCoverage(p, 'mfa').level).toBe('full'); expect(controlCoverage(p, 'managedDevice').level).toBe('full'); });
test('risk-scoped MFA is not baseline mfa', () => expect(controlCoverage(pol({ conditions: { signInRiskLevels: ['high'] }, grantControls: { builtInControls: ['mfa'] } }), 'mfa').level).toBe('none'));
test('MFA excluding trusted locations is partial', () => expect(controlCoverage(pol({ conditions: { locations: { includeLocations: ['All'], excludeLocations: ['AllTrusted'] } }, grantControls: { builtInControls: ['mfa'] } }), 'mfa').level).toBe('partial'));
test('legacy block covers legacy', () => expect(controlCoverage(pol({ conditions: { clientAppTypes: ['exchangeActiveSync', 'other'] }, grantControls: { builtInControls: ['block'] } }), 'legacyBlocked').level).toBe('full'));
test('legacy block without EAS is partial', () => expect(controlCoverage(pol({ conditions: { clientAppTypes: ['other'] }, grantControls: { builtInControls: ['block'] } }), 'legacyBlocked').level).toBe('partial'));
test('legacy block does not count as mfa', () => expect(controlCoverage(pol({ conditions: { clientAppTypes: ['exchangeActiveSync', 'other'] }, grantControls: { builtInControls: ['block'] } }), 'mfa').level).toBe('none'));
test('report-only downgrades', () => expect(policyContribution(pol({ state: 'enabledForReportingButNotEnforced', grantControls: { builtInControls: ['mfa'] } }), 'allUsers', 'allResources', 'mfa', t).level).toBe('reportOnly'));
test('best picks full over partial', () => { const ps = [pol({ id: 'a', grantControls: { operator: 'OR', builtInControls: ['mfa', 'compliantDevice'] } }), pol({ id: 'b', grantControls: { builtInControls: ['mfa'] } })]; const r = bestCoverage(ps, 'allUsers', 'allResources', 'mfa', t); expect([r.level, r.policyIds]).toEqual(['full', ['b']]); });
```

- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** run → PASS.
- [ ] **Step 5:** Commit `feat(engine): coverage primitives for population, surface and control`.

---

### Task 5: Rule framework + baseline rules (BAS-01..11)

**Files:** Create `src/engine/rules/types.ts`, `src/engine/rules/baseline.ts`, test `src/engine/rules/baseline.test.ts`.

**Produces:**

```ts
// rules/types.ts
export interface RuleContext { policies: CAPolicy[]; tenant: TenantProfile }
export interface Rule { id: string; family: RuleFamily; run(ctx: RuleContext): Finding[] }
export interface RuleMeta { id: string; title: string; family: RuleFamily; severity: Severity; remediation: string; references: string[]; requiredLicense?: keyof Licenses }
export const LICENSE_LABEL: Record<keyof Licenses, string>; // 'Microsoft Entra ID P2', ...
/** Builds a finding; sets status 'requiresLicense' when meta.requiredLicense is not owned, and severity override optional. */
export function makeFinding(meta: RuleMeta, ctx: RuleContext, f: { explanation: string; policyIds?: string[]; status?: FindingStatus; severity?: Severity }): Finding;
/** Common pattern: evaluate bestCoverage; none → gap finding, partial/reportOnly → partial finding (reportOnly explanation says "only report-only policies"), full → []. */
export function coverageRule(meta: RuleMeta, pop: Population, surface: SurfaceId, control: ControlId, describe: (c: Contribution) => string): Rule;
```

Baseline rules (all use `coverageRule` unless noted; references from research catalog):

| ID | Pop / surface / control or logic | Severity | License |
|---|---|---|---|
| BAS-01 | allUsers / allResources / legacyBlocked; partial → status partial | critical | entraP1 |
| BAS-02 | custom: any active policy with block + `other` in clientAppTypes but neither `exchangeActiveSync` nor `all` | high | entraP1 |
| BAS-03 | allUsers / allResources / mfa | critical | entraP1 |
| BAS-04 | allUsers / allResources / deviceCodeBlocked | high | entraP1 |
| BAS-05 | custom: no active block policy with `authenticationTransfer` | low | entraP1 |
| BAS-06 | custom: no enforced block policy with includeAllUsers, `includePlatforms` contains `all` and non-empty `excludePlatforms` (report-only → partial) | medium | entraP1 |
| BAS-07 | guests / allResources / mfa | high | entraP1 |
| BAS-08 | allUsers / registerSecurityInfo / mfa — but also satisfied by managedDevice full; custom wrapper | high | entraP1 |
| BAS-09 | allUsers / registerDevice / mfa; plus custom: policies on registerDevice using grants other than mfa/authStrength, or locations/devices/clientAppTypes≠all → separate finding "unsupported configuration" | medium | entraP1 |
| BAS-10 | allUsers / allResources / managedDevice | medium | intune |
| BAS-11 | custom: no active policy with includeAllUsers, includeAllApps, `devices.deviceFilter` present, signInFrequency enabled and persistentBrowser never | medium | entraP1 |

- [ ] **Step 1: Failing tests:** for each rule, `run({policies, tenant})` on (a) `[]` or a weak fixture → expect one finding with the rule ID and expected status, (b) a fixture that satisfies it → expect `[]`. Concrete fixtures:
  - BAS-01 pass: `pol({ conditions: { clientAppTypes: ['exchangeActiveSync','other'] }, grantControls: { builtInControls: ['block'] } })`. Fail: `[]` → status `gap`. Partial: same policy but report-only → status `partial`, explanation contains "report-only".
  - BAS-02 fail: block with `clientAppTypes:['other']`. Pass: `['exchangeActiveSync','other']`.
  - BAS-03 pass: `pol({ grantControls: { builtInControls: ['mfa'] } })`; partial: same + `excludeGroups:['g1']`.
  - BAS-04 pass: `pol({ conditions: { authenticationFlows: { transferMethods: 'deviceCodeFlow' } }, grantControls: { builtInControls: ['block'] } })`.
  - BAS-05 pass: transferMethods `'authenticationTransfer'` block.
  - BAS-06 pass: `pol({ conditions: { platforms: { includePlatforms: ['all'], excludePlatforms: ['windows','iOS','android','macOS'] } }, grantControls: { builtInControls: ['block'] } })`.
  - BAS-07 fail: MFA policy with `excludeUsers:['GuestsOrExternalUsers']`; pass: All users MFA.
  - BAS-08 pass: `pol({ conditions: { applications: { includeApplications: [], includeUserActions: [USER_ACTION.registerSecurityInfo] } }, grantControls: { builtInControls: ['mfa'] } })`.
  - BAS-09 pass: same with registerDevice; misconfig fail: registerDevice + `compliantDevice` → finding with "unsupported".
  - BAS-10 with `tenant({ licenses: { intune: false } })` and no policy → status `requiresLicense`; with intune true → `gap`.
  - BAS-11 pass: All/All, `devices.deviceFilter {mode:'include', rule:'device.isCompliant -ne True -or device.trustType -ne "ServerAD"'}`, SIF 1h, persistentBrowser never.
- [ ] **Step 2:** run → FAIL. **Step 3:** implement. **Step 4:** PASS.
- [ ] **Step 5:** Commit `feat(rules): rule framework and baseline coverage rules`.

---

### Task 6: Admin rules (ADM-01..08)

**Files:** Create `src/engine/rules/admin.ts`, test `admin.test.ts`.

| ID | Logic | Severity | License |
|---|---|---|---|
| ADM-01 | For each of 14 roles, is there an active policy whose population includes the role (All users, or role in includeRoles, not in excludeRoles), surface allResources full, control phishResistant full? List missing role names. Enforced for all → none. Missing any → gap (or partial if only report-only satisfies). | critical | entraP1 |
| ADM-02 | admins / allResources / mfa via `coverageRule`, but only emitted if ADM-01 coverage for admins is not full. | critical | entraP1 |
| ADM-03 | Active policies that cover admins (population ≠ none) with `includeApplications` containing `MicrosoftAdminPortals` (or only portal IDs) and no other active admin policy with includeAllApps + mfaStrength full. Explanation lists uncovered: Microsoft Graph (Graph PowerShell, Graph Explorer, Entra admin center data), Intune API, Azure Resource Manager, Exchange/Teams/SharePoint admin APIs; note Intune and Entra admin center sign-in is covered via Azure portal ID. | high | entraP1 |
| ADM-04 | Same pattern with include = only `APP.azureManagement`: lists Graph tooling, M365 admin, Azure DevOps. | high | entraP1 |
| ADM-05 | Any active admin policy with MFA/phish/managed control whose users are only `includeRoles` (no All, no groups). Explanation: PIM-eligible admins not covered until activation; custom and AU-scoped roles ignored. Emits manual check reference. | high | entraP1 |
| ADM-06 | admins / allResources / managedDevice | high | intune |
| ADM-07 | No active admin-covering policy with `signInFrequency.isEnabled` | low | entraP1 |
| ADM-08 | Any active admin policy relying on `MicrosoftAdminPortals` → info, status `unverified`: Defender, Purview, Teams, SharePoint admin and Power Platform admin center mapping not documented. | info | — |

- [ ] **Step 1: Failing tests:**
  - ADM-01 pass: `pol({ conditions: { users: { includeUsers: [], includeRoles: PRIVILEGED_ROLES.map(r=>r.id) } }, grantControls: { authenticationStrength: { id: AUTH_STRENGTH.phishingResistant } } })`. Fail with roles minus GA → explanation contains "Global Administrator".
  - ADM-02 fires with `[]`; does not fire when an All users MFA policy exists (ADM-01 still fires).
  - ADM-03 fires for 14-role policy targeting `MicrosoftAdminPortals` with MFA; explanation contains "Intune". Not fired when an additional All-resources admin MFA policy exists.
  - ADM-04 fires for `[APP.azureManagement]`; explanation contains "Azure DevOps".
  - ADM-05 fires for role-only policy; not for policy with `includeGroups:['admins-group']` plus roles.
  - ADM-06 requiresLicense without intune; pass with intune + `compliantDevice` 14-role policy.
  - ADM-07 pass with SIF on 14-role policy.
  - ADM-08 status `unverified` when Admin Portals used.
- [ ] **Steps 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(rules): admin protection rules`.

---

### Task 7: App coverage rules (APP-01..08)

**Files:** Create `src/engine/rules/apps.ts`, test `apps.test.ts`.

| ID | Logic | Severity |
|---|---|---|
| APP-01 | Each active policy with `All` and non-empty `excludeApplications`: list `appLabel` of exclusions; explanation includes baseline-scopes enforcement note (June 2026) and "verify setting at aka.ms/BaselineScopesSettingsUX". | medium |
| APP-02 | Each active policy with `All` excluding `Office365`, `MicrosoftAdminPortals`, or a `highValue` app — except DRS excluded on a policy with `authenticationFlows` (acceptable). One finding per policy listing apps. | high |
| APP-03 | Policies requiring `compliantDevice` that exclude intune/intuneEnrollment/intuneWebCompanyPortal — exception: intuneEnrollment exclusion on a policy with `termsOfUse` non-empty. | low |
| APP-04 | Active policy including exchange/sharepoint/teams individually without `Office365`/`All`. Explanation: dependency leakage, SharePoint policy affects Teams. | low |
| APP-05 | Any policy including or excluding an app with `targetable:false`. Explanation per app (e.g. Graph PowerShell → "client app; protect Microsoft Graph via All resources"). | medium |
| APP-06 | For each population (allUsers, admins): bestCoverage(graph, mfa) none → gap; partial → partial. One finding listing affected populations. | high |
| APP-07 | allUsers-or-admins / azureManagement / mfa none → gap. Separate sub-finding (same rule ID, severity medium) when azureManagement is covered but azureDevOps is not. | high |
| APP-08 | Admin policy targeting only `Office365` → info explaining it does not cover Azure portal, Exchange Admin Center or Graph. | info |

- [ ] **Step 1: Failing tests:** APP-01 fires on All excluding `APP.storeForBusiness`, none on All with no exclusions. APP-02 fires on excluding `Office365`; not on DRS exclusion in a device-code policy. APP-03 fires on compliant policy excluding `APP.intuneEnrollment`; not when termsOfUse set. APP-04 fires on `[APP.sharePointOnline]`. APP-05 fires on `[APP.graphPowerShell]`. APP-06 fires when only a MicrosoftAdminPortals MFA policy exists; not when All users/All resources MFA exists. APP-07 fires with `[]`; sub-finding when only `[APP.azureManagement]` MFA. APP-08 fires on 14-role `Office365` MFA policy.
- [ ] **Steps 2–4.** **Step 5:** Commit `feat(rules): Microsoft app coverage rules`.

---

### Task 8: Weakening rules (WEK-01..12)

**Files:** Create `src/engine/rules/weakening.ts`, test `weakening.test.ts`.

"Baseline policy" = active, includeAllUsers or covers admins, includeAllApps or adminPortals/azureManagement, with block/mfa/authStrength/device grant.

| ID | Logic | Severity |
|---|---|---|
| WEK-01 | Baseline policy with `unexpectedExclusions` non-empty. Severity critical if the policy is the best contributor for BAS-01, BAS-03 or ADM-01 checks (legacy block, MFA all users, phish admins); else high. | high/critical |
| WEK-02 | `breakGlass` non-empty and an enforced policy with includeAllUsers (or admins full) that is block or requires grants (not risk-scoped, not legacy-only) does not exclude every break-glass ID (by excludeUsers or excludeGroups). `breakGlass` empty → single info finding "No break-glass accounts configured in tenant setup". | medium |
| WEK-03 | Any active policy with `excludeRoles ∩ PRIVILEGED` non-empty and grant not block. | high |
| WEK-04 | Active non-block policy with mfa/phish strength ≠ none whose locations exclude anything or include ≠ `All`. | high |
| WEK-05 | `operator OR`, >1 alternative, alternatives mix MFA-equivalent and non-MFA. High if admins covered, or All users+All resources; else medium. Explanation lists the weakest option. | high/medium |
| WEK-06 | Non-block active policy with mfa/managed strength ≠ none and `excludePlatforms` non-empty or `includePlatforms` not containing `all`. | medium |
| WEK-07 | Non-block active policy with grants and deviceFilter `mode:'include'` whose rule uses only positive operators (`-eq`, `-startsWith`, `-endsWith`, `-contains`, `-in`) and no `-ne`/`-notIn`/`-notContains`/`-notStartsWith`/`-notEndsWith`. | medium |
| WEK-08 | `persistentBrowser.mode === 'always'` and no device filter restricting to managed devices; or persistentBrowser set on a policy without `All` apps. | medium |
| WEK-09 | `approvedApplication` in builtInControls. High if it is the only control, else medium. Explanation notes the June 30 2026 retirement and the Learn vs MC1220751 discrepancy. | medium/high |
| WEK-10 | `customAuthenticationFactors` non-empty. | medium |
| WEK-11 | `disableResilienceDefaults === true` on includeAllUsers or includeAllApps policy. | low |
| WEK-12 | `continuousAccessEvaluation.mode === 'disabled'`. | low |

- [ ] **Step 1: Failing tests** — one fire + one non-fire per rule, e.g. WEK-01 fires for All/All MFA excluding group `g1` with severity critical; does not fire when excluding only `bg-1` with `breakGlass:['bg-1']`. WEK-02 fires when breakGlass `['bg-1']` and All-users MFA without exclusion; not when excluded. WEK-05 fires for `OR [mfa, compliantDevice]`; not for `OR [compliantDevice, domainJoinedDevice]` or `AND [mfa, compliantDevice]`. WEK-07 fires for include + `device.isCompliant -eq True`; not for exclude + `-eq`.
- [ ] **Steps 2–4.** **Step 5:** Commit `feat(rules): weakening pattern rules`.

---

### Task 9: Risk, hygiene rules, manual checks, rule index

**Files:** Create `src/engine/rules/risk.ts`, `hygiene.ts`, `index.ts`, `src/engine/manualChecks.ts`, tests `risk.test.ts`, `hygiene.test.ts`, `manualChecks.test.ts`.

| ID | Logic | Severity | License |
|---|---|---|---|
| RSK-01 | allUsers / allResources / signInRisk | high | entraP2 |
| RSK-02 | allUsers / allResources / userRisk | high | entraP2 |
| RSK-03 | No active policy with `clientApplications.includeServicePrincipals` non-empty and block | medium | workloadIdPremium |
| RSK-04 | No active policy with `insiderRiskLevels` containing `elevated` and block | low | purviewInsiderRisk |
| RSK-05 | No active admin-covering policy with `secureSignInSession.isEnabled` | low | entraP1 |
| RSK-06 | Always emit one info finding, status `unverified`: "All users" policies do not cover agent users; check Agents assignments if Entra Agent ID is in use. Suppressed if any policy contains `AllAgentIdUsers` or `includeAgentIdServicePrincipals`. | info | — |
| HYG-01 | Summarizes rules that are `partial` only because of report-only: one finding listing report-only policies that would satisfy a critical/high rule if enabled. | high |
| HYG-02 | Each disabled policy; medium if `displayName` starts with `Microsoft-managed:`, else low. | low/medium |
| HYG-03 | Active policy with no grant controls and no enabled session controls; or includeUsers `['None']` with no groups/roles/guests/SPs; or includeApplications `['None']`/empty with no user actions/auth contexts. | low |

HYG-01 implementation: run in `analyze()` after other rules — it is defined in `hygiene.ts` as `reportOnlySummary(findings, policies)`, not in `ALL_RULES`.

`manualChecks.ts` exports `buildManualChecks(ctx: RuleContext, findings: Finding[]): ManualCheck[]` returning the 10 checks in spec §4.4. Always include: group membership (when any include/exclude groups exist), service principal existence (when specific app IDs are targeted), security defaults, legacy MFA trusted IPs (when `AllTrusted` used anywhere), baseline scopes setting (when APP-01 fired), device registration MFA setting (when any registerDevice policy exists), PIM eligible (when ADM-05 fired), groups with service principals (when any includeGroups), auth contexts (when any `includeAuthenticationContextClassReferences`), Azure Government (always, low key). Each has `where` text with the exact Entra admin center path, e.g. "Entra admin center → Identity → Devices → Device settings → Require Multifactor Authentication to register or join devices".

`index.ts`: `export const ALL_RULES: Rule[] = [...baselineRules, ...adminRules, ...appRules, ...weakeningRules, ...riskRules, ...hygieneRules]`.

- [ ] **Step 1: Failing tests:** RSK-01 without P2 → `requiresLicense`; with P2 and `signInRiskLevels:['high','medium']` + mfa → none. RSK-02 pass with `userRiskLevels:['high']` + AND `[mfa, passwordChange]`. RSK-03 pass with `includeServicePrincipals:['ServicePrincipalsInMyTenant']` block. HYG-02 medium for `Microsoft-managed: Block legacy authentication` disabled. HYG-03 fires on policy with no controls. Manual checks: device registration check present iff registerDevice policy exists. `ALL_RULES` ids are unique.
- [ ] **Steps 2–4.** **Step 5:** Commit `feat(rules): risk and hygiene rules, manual checks`.

---

### Task 10: Matrix, score, analyze()

**Files:** Create `src/engine/matrix.ts`, `score.ts`, `analyze.ts`, tests `matrix.test.ts`, `score.test.ts`.

```ts
export function buildMatrix(policies: CAPolicy[], tenant: TenantProfile, pop: Population): CoverageMatrix;
// for each SURFACES × CONTROLS: isNA → 'na'; else bestCoverage → full:'covered', partial|reportOnly:'partial', none: (control.license && !tenant.licenses[control.license]) ? 'requiresLicense' : 'gap'
export function computeScore(findings: Finding[]): number;
export function analyze(policies: CAPolicy[], tenant: TenantProfile): AnalysisResult;
// runs ALL_RULES, appends reportOnlySummary, sorts findings by severity then ruleId, builds 3 matrices, manual checks, score, generatedAt ISO, catalogDate
```

- [ ] **Step 1: Failing tests:** empty policies → `allResources × mfa` is `gap`, `registerDevice × managedDevice` is `na`, `allResources × signInRisk` is `requiresLicense` without P2. Admin-portals-only 14-role MFA policy → admins matrix `adminPortals × mfa` covered, `graph × mfa` gap. Score: `[critical gap, high partial]` → `100-15-4 = 81`; `requiresLicense` ignored; never below 0.
- [ ] **Steps 2–4.** **Step 5:** Commit `feat(engine): coverage matrix, score and analyze()`.

---

### Task 11: Sample tenants + integration tests

**Files:** Create `src/samples/goodTenant.ts`, `src/samples/weakTenant.ts`, test `src/samples/samples.test.ts`.

- `goodTenant`: `{ policies, tenant }` with P2 + Intune + Workload ID, breakGlass `['bg-1']`, policies (all enforced, excluding `bg-1`): block legacy (EAS+other); All users All resources MFA; 14 roles All resources phishing-resistant + compliant device AND + SIF 4h + token protection; guests MFA (All users already covers — keep explicit guest policy); block device code flow; block authentication transfer; block unknown platforms; security info registration MFA; device registration MFA; sign-in risk high → MFA + SIF everyTime; user risk high → AND mfa+passwordChange; All users All resources compliant OR hybrid (AND-free device policy); unmanaged-device SIF + never persistent browser; workload identities block outside trusted; insider risk elevated block (licenses purviewInsiderRisk true); admins also via group `admins-pim` to avoid ADM-05.
- `weakTenant`: P1 only, no break-glass configured; MFA for group `employees` excluding `AllTrusted`; admins: 5 roles, `MicrosoftAdminPortals`, OR [mfa, compliantDevice]; legacy block report-only with `other` only; All resources policy excluding `Office365` with compliant device; persistent browser always; `approvedApplication` policy; disabled `Microsoft-managed: Block device code flow`; policy including `APP.graphPowerShell`.
- [ ] **Step 1: Failing tests:** good → `analyze()` has no findings with severity critical/high and status gap/partial; score ≥ 90. Weak → finding IDs include `BAS-01, BAS-02, BAS-03, ADM-01, ADM-03, APP-02, APP-05, APP-06, WEK-04, WEK-05, WEK-08, WEK-09, HYG-02`; score < 40.
- [ ] **Step 2:** run → FAIL. **Step 3:** write samples; fix engine bugs surfaced (document any rule tweak in the commit message). **Step 4:** PASS.
- [ ] **Step 5:** Commit `test: sample tenants and end-to-end engine tests`.

---

### Task 12: Exports

**Files:** Create `src/report/csv.ts`, `json.ts`, `html.ts`, `download.ts`, test `src/report/report.test.ts`.

```ts
export function findingsToCsv(findings: Finding[], policies: CAPolicy[]): string;
// header: ruleId,severity,status,family,title,policies,explanation,remediation,requiredLicense,references
// RFC 4180 escaping: wrap in quotes, double internal quotes; policies = displayNames joined by '; '
export function policiesToJson(policies: CAPolicy[]): string; // {"value":[...]} pretty, extra merged back
export function buildHtmlReport(result: AnalysisResult, policies: CAPolicy[], tenant: TenantProfile): string;
// self-contained: inline <style>, no <script src>, no external CSS; sections: summary (score, counts by severity, licenses), heat maps for 3 populations (HTML tables, cell classes), findings grouped by severity, manual checklist, policy inventory, methodology & catalog date; @media print styles; all text HTML-escaped
export function downloadText(filename: string, mime: string, text: string): void; // Blob + anchor click
```

- [ ] **Step 1: Failing tests:** CSV escapes `He said "hi", ok` → `"He said ""hi"", ok"`; header row exact. JSON round-trips through `parseImport` to equal policies. HTML contains `<table`, contains finding title, contains no `<script` and no `<link`, escapes `<b>` in a policy name.
- [ ] **Steps 2–4.** **Step 5:** Commit `feat(report): HTML, CSV and JSON exports`.

---

### Task 13: App state, shell, tenant setup

**Files:** Create `src/state/store.tsx`, `src/ui/Stepper.tsx`, `src/ui/tenant/TenantSetup.tsx`; modify `src/App.tsx`, `src/styles.css`; test `src/state/store.test.ts`.

```ts
interface AppState { step: 0 | 1 | 2 | 3; tenant: TenantProfile; policies: CAPolicy[] }
type Action =
 | { type: 'setStep'; step: AppState['step'] } | { type: 'setTenant'; tenant: TenantProfile }
 | { type: 'upsertPolicy'; policy: CAPolicy } | { type: 'deletePolicy'; id: string }
 | { type: 'replacePolicies'; policies: CAPolicy[] } | { type: 'addPolicies'; policies: CAPolicy[] }
 | { type: 'loadSample'; which: 'good' | 'weak' } | { type: 'clearAll' };
export function reducer(s: AppState, a: Action): AppState;
export function StoreProvider(props: { children: ReactNode }): JSX.Element; // persists to localStorage key 'ca-gap-evaluator:v1'; loads on init, falls back to defaults on parse error
export function useStore(): { state: AppState; dispatch: Dispatch<Action> };
```

TenantSetup: license checkboxes with one-line explanation each (P1 implied for CA; P2 → risk conditions; Intune → compliant device/app protection; Workload ID Premium; Defender for Cloud Apps; Purview Insider Risk), break-glass textarea (one ID/UPN per line), friendly-names textarea (`<guid> = Name` per line), "Clear all data" with `confirm()`.

Stepper: 4 buttons "1 Tenant · 2 Policies · 3 Analysis · 4 Export"; Analysis/Export disabled when no policies.

Styling (`styles.css`): neutral light theme, CSS variables `--covered:#2e9d5b; --partial:#e0a800; --gap:#d64545; --license:#9aa0a6`, hatched background for requiresLicense via `repeating-linear-gradient`.

- [ ] **Step 1: Failing tests:** reducer upsert adds then replaces by id; deletePolicy removes; clearAll resets to defaults; loadSample good sets policies length > 10.
- [ ] **Steps 2–4.** Then `npm run dev` and manually confirm the tenant step renders and persists across reload.
- [ ] **Step 5:** Commit `feat(ui): app shell, persistent store and tenant setup`.

---

### Task 14: Policies list, import, wizard

**Files:** Create `src/ui/policies/PolicyList.tsx`, `ImportDialog.tsx`, `PolicyWizard.tsx`, `AppPicker.tsx`, `IdListInput.tsx`, `sections/*.tsx`; test `src/ui/policies/PolicyWizard.test.tsx`.

- PolicyList: cards with name, state badge (On / Report-only / Off), summary line ("All users · All resources · Block"), Edit / Duplicate / Delete. Toolbar: Add policy, Import JSON, Load sample (good/weak), Export JSON.
- ImportDialog: file input + textarea; calls `parseImport`; shows count, errors, notes; buttons "Add to existing" / "Replace all".
- PolicyWizard: modal with section tabs Basics · Users · Target resources · Network · Conditions · Grant · Session · JSON. Edits a local draft `CAPolicy`; Save dispatches `upsertPolicy`. JSON tab: textarea of the draft; "Apply JSON" runs `normalizePolicy` and shows errors.
  - Users: include radio None / All users / Select (users IDs, groups IDs, roles multi-select from PRIVILEGED_ROLES + EXTENDED_ROLES, guest types checkboxes); exclude: users, groups, roles, guest types; quick button "Add break-glass accounts to exclusions".
  - Target resources: radio Resources / User actions / Authentication context. Resources: All / Select / None; `AppPicker` for include and exclude. User actions checkboxes. Auth context: text list `c1..`.
  - AppPicker: search over APP_CATALOG + group keywords (Office 365, Microsoft Admin Portals) + free GUID entry; shows group badges and inline warnings: not targetable → "Client app — cannot be targeted; Conditional Access applies to the resource"; Microsoft Graph → "Graph can only be covered through All resources"; MicrosoftAdminPortals → "Covers portal sign-in only (Azure portal incl. Entra & Intune admin centers, Exchange admin center, M365 admin center, Purview/Protection Center). Backend APIs (Graph, Intune, ARM) are not included."; unverified → "App ID from community sources".
  - Network: include All / AllTrusted / selected IDs; exclude list.
  - Conditions: user risk, sign-in risk (checkbox high/medium/low/none), insider risk, platforms include/exclude, client app types (all or checkboxes), device filter mode + rule, auth flows (device code, authentication transfer), workload identities (include SPs list).
  - Grant: Block vs Grant; checkboxes mfa, compliantDevice, domainJoinedDevice, compliantApplication, approvedApplication (labeled "retired"), passwordChange, riskRemediation; auth strength select (none / MFA / Passwordless / Phishing-resistant / custom ID); operator AND/OR; terms of use IDs; enforce "auth strength and MFA can't both be selected" by disabling the other.
  - Session: app enforced restrictions, MDCA type, SIF (value + unit / every time), persistent browser (always/never), CAE mode, disable resilience defaults, token protection.
- [ ] **Step 1: Failing test** (`@testing-library/react`): render wizard with `blankPolicy()`, set name "Test", choose All users, All resources, Grant → MFA, click Save → `onSave` called with policy where `includeUsers` = `['All']`, `includeApplications` = `['All']`, `builtInControls` = `['mfa']`.
- [ ] **Steps 2–4.** Manual: import `docs/research` example JSON via paste; edit; confirm persistence.
- [ ] **Step 5:** Commit `feat(ui): policy list, JSON import and policy wizard`.

---

### Task 15: Analysis view

**Files:** Create `src/ui/analysis/AnalysisView.tsx`, `HeatMap.tsx`, `CellDetail.tsx`, `FindingsList.tsx`, `ManualChecklist.tsx`; test `src/ui/analysis/HeatMap.test.tsx`.

- AnalysisView: `useMemo(() => analyze(policies, tenant))`; header with score gauge (color by band ≥80 green, ≥50 amber, else red) and counts per severity; population segmented control (All users / Admins / Guests); HeatMap; CellDetail panel; FindingsList; ManualChecklist.
- HeatMap: `<table>`, rows SURFACES (label + description tooltip), columns CONTROLS (license label on hover), cell classes `cell-covered|partial|gap|requiresLicense|na`, text symbol for accessibility (✓, ◐, ✕, $, —), `aria-label` "Admins, Microsoft Graph, MFA: gap". Legend below.
- CellDetail: selected cell → state, reasons, contributing policy names, related findings (match by surface/control keywords: map table in `CellDetail.tsx` from control → rule IDs, e.g. mfa → BAS-03, ADM-02, APP-06, WEK-04, WEK-05).
- FindingsList: filters severity (multi), family, policy; each item expandable showing explanation, affected policies, remediation, references (links `target="_blank" rel="noreferrer"`), license badge, status badge.
- [ ] **Step 1: Failing test:** render HeatMap with matrix from `buildMatrix([], DEFAULT_TENANT, 'allUsers')` → has 10 rows × 8 data cells; cell for All resources × MFA has `aria-label` containing "gap".
- [ ] **Steps 2–4.** Manual: load weak sample, verify heat map and click-through.
- [ ] **Step 5:** Commit `feat(ui): analysis view with heat map and findings`.

---

### Task 16: Export view, README, final verification

**Files:** Create `src/ui/export/ExportView.tsx`, `README.md`.

- ExportView: three cards with buttons: "Download HTML report" (`ca-gap-report-YYYY-MM-DD.html`), "Download findings CSV", "Download policies JSON"; "Open report preview" (opens Blob URL in new tab for print-to-PDF).
- README: what it does, privacy (runs locally), how to get policy JSON (Graph Explorer / `Get-MgIdentityConditionalAccessPolicy | ConvertTo-Json -Depth 10` / beta endpoint with `Prefer: include-unknown-enum-members`), `npm install`, `npm run dev`, `npm test`, `npm run build`, rule catalog summary, limitations (manual checks), research references.
- [ ] **Step 1:** Implement ExportView and README.
- [ ] **Step 2:** `npm test` → all PASS; `npx tsc --noEmit` → no errors; `npm run build` → success.
- [ ] **Step 3:** Browser check via `npm run dev`: load weak sample → analysis → export all three files; open HTML report and confirm heat map and findings render.
- [ ] **Step 4:** Commit `feat(ui): export view and README`.

---

## Self-Review

- Spec coverage: input both modes (Tasks 2, 14), app catalog (3), engine semantics (4), all rule families (5–9), manual checklist (9), heat map with population selector (10, 15), licensing gating (5, 10), score (10), exports (12, 16), autosave & clear (13), tests incl. sample tenants (11). ✔
- Names consistent: `bestCoverage`, `coverageRule`, `makeFinding`, `analyze`, `buildMatrix`, `computeScore`, `parseImport`, `normalizePolicy`, `ALL_RULES`, `reportOnlySummary`. ✔
