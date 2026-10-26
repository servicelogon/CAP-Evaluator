# CA Gap Evaluator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a browser-only React + TypeScript app that imports or captures Entra ID Conditional Access policies, evaluates a documented gap-rule catalog, renders a coverage heat map, and exports HTML/CSV/JSON reports.

**Architecture:** The Graph `conditionalAccessPolicy` JSON shape is the source of truth. A pure TypeScript engine (`analyze`) consumes normalized policies plus a tenant profile and returns findings, a coverage matrix, a manual-verification checklist, and a score. The UI is a four-step wizard with no network calls; state lives in `localStorage`.

**Tech Stack:** React 19, TypeScript 5.9, Vite 7, Vitest 3, Testing Library, Tailwind CSS 4. No backend, no Graph SDK, no router.

## Global Constraints

- Browser-only: no Microsoft Graph sign-in, no server, no network calls at runtime.
- Internal policy type **is** the Graph beta `conditionalAccessPolicy` shape; match apps and roles by ID, never display name.
- Rule IDs, severities, and license gates are those in `docs/superpowers/specs/2026-10-26-ca-gap-evaluator-design.md`.
- UNVERIFIED / DISCREPANCY research items must emit `status: "unverified"` or a `ManualCheck`, never a confirmed gap.
- Engine code in `src/engine`, `src/model`, `src/catalog` must not import from `src/ui`.
- Tests first (Vitest). Every rule has a fixture that fires and a fixture that does not.
- Score: `max(0, 100 - Σ weights)` where gap weights are critical 15, high 8, medium 4, low 1; `partial` is half; `requiresLicense` and `unverified` and `info` do not deduct.
- Catalog date shown on the report: `2026-10-26`.

## File map

```
index.html
package.json
vite.config.ts
vitest.config.ts
tsconfig.json
tsconfig.app.json
tsconfig.node.json
src/main.tsx
src/App.tsx
src/index.css
src/vite-env.d.ts
src/model/types.ts
src/model/normalize.ts
src/model/importPolicies.ts
src/model/ids.ts
src/catalog/apps.ts
src/catalog/roles.ts
src/catalog/authStrengths.ts
src/engine/predicates.ts
src/engine/findings.ts
src/engine/rules/baseline.ts
src/engine/rules/admin.ts
src/engine/rules/apps.ts
src/engine/rules/weakening.ts
src/engine/rules/risk.ts
src/engine/rules/hygiene.ts
src/engine/matrix.ts
src/engine/manualChecks.ts
src/engine/analyze.ts
src/engine/index.ts
src/samples/knownGood.ts
src/samples/weak.ts
src/report/csv.ts
src/report/json.ts
src/report/html.ts
src/ui/state.ts
src/ui/AppShell.tsx
src/ui/TenantSetup.tsx
src/ui/PolicyList.tsx
src/ui/PolicyImport.tsx
src/ui/PolicyWizard.tsx
src/ui/AnalysisView.tsx
src/ui/HeatMap.tsx
src/ui/FindingsList.tsx
src/ui/ExportView.tsx
src/test/fixtures.ts
```

Tests live next to the module they cover: `src/model/normalize.test.ts`, `src/engine/rules/baseline.test.ts`, and so on.

---

### Task 1: Scaffold the Vite + React + TypeScript + Vitest app

**Files:**
- Create: `package.json`, `vite.config.ts`, `vitest.config.ts`, `tsconfig.json`, `tsconfig.app.json`, `tsconfig.node.json`, `index.html`, `src/main.tsx`, `src/App.tsx`, `src/index.css`, `src/vite-env.d.ts`, `.gitignore`
- Modify: none (repo currently has only `docs/` and `.git`)

**Interfaces:**
- Consumes: none
- Produces: `npm test` and `npm run dev` work; React app renders a heading "CA Gap Evaluator"

The repo root already contains `docs/`. Do **not** run `npm create vite` (it refuses non-empty directories). Write the files below by hand.

- [ ] **Step 1: Write package.json, configs, and a smoke test**

`package.json`:

```json
{
  "name": "ca-gap-evaluator",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc -b && vite build",
    "preview": "vite preview",
    "test": "vitest run",
    "test:watch": "vitest"
  }
}
```

`.gitignore` (append if `git init` already created one; keep `.git`):

```
node_modules
dist
*.local
.DS_Store
```

`tsconfig.json`:

```json
{
  "files": [],
  "references": [
    { "path": "./tsconfig.app.json" },
    { "path": "./tsconfig.node.json" }
  ]
}
```

`tsconfig.app.json`:

```json
{
  "compilerOptions": {
    "tsBuildInfoFile": "./node_modules/.tmp/tsconfig.app.tsbuildinfo",
    "target": "ES2022",
    "useDefineForClassFields": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "verbatimModuleSyntax": true,
    "moduleDetection": "force",
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "erasableSyntaxOnly": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedSideEffectImports": true
  },
  "include": ["src"]
}
```

`tsconfig.node.json`:

```json
{
  "compilerOptions": {
    "tsBuildInfoFile": "./node_modules/.tmp/tsconfig.node.tsbuildinfo",
    "target": "ES2022",
    "lib": ["ES2023"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "verbatimModuleSyntax": true,
    "moduleDetection": "force",
    "noEmit": true,
    "strict": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "erasableSyntaxOnly": true,
    "noFallthroughCasesInSwitch": true,
    "noUncheckedSideEffectImports": true
  },
  "include": ["vite.config.ts", "vitest.config.ts"]
}
```

`vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
});
```

`vitest.config.ts`:

```ts
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    environmentMatchGlobs: [["src/ui/**", "jsdom"]],
  },
});
```

`index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CA Gap Evaluator</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

`src/vite-env.d.ts`:

```ts
/// <reference types="vite/client" />
```

`src/index.css`:

```css
@import "tailwindcss";

:root {
  color-scheme: light;
  font-family: "Segoe UI", ui-sans-serif, system-ui, sans-serif;
  background: #f4f6f8;
  color: #1b1b1b;
}

body {
  margin: 0;
}
```

`src/main.tsx`:

```ts
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
```

`src/App.tsx`:

```tsx
export default function App() {
  return (
    <main>
      <h1>CA Gap Evaluator</h1>
    </main>
  );
}
```

`src/App.test.tsx`:

```tsx
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import App from "./App";

describe("App", () => {
  it("renders the product name", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "CA Gap Evaluator" })).toBeTruthy();
  });
});
```

- [ ] **Step 2: Install dependencies**

Run:

```bash
npm install react react-dom
npm install -D typescript @types/react @types/react-dom vite @vitejs/plugin-react vitest @testing-library/react @testing-library/dom jsdom tailwindcss @tailwindcss/vite
```

Expected: `package-lock.json` created; `node_modules` present.

- [ ] **Step 3: Run the smoke test**

Run: `npm test`

Expected: FAIL until jsdom is selected for `src/App.test.tsx`. If Vitest reports `document is not defined`, that is the intended first failure for the UI smoke test (engine tests later use `node`). Add this at the top of `src/App.test.tsx`:

```ts
// @vitest-environment jsdom
```

Re-run `npm test`. Expected: PASS (1 test).

- [ ] **Step 4: Commit**

```bash
git add package.json package-lock.json .gitignore index.html vite.config.ts vitest.config.ts tsconfig.json tsconfig.app.json tsconfig.node.json src
git commit -m "$(cat <<'EOF'
chore: scaffold Vite React TypeScript app with Vitest

EOF
)"
```

---

### Task 2: Domain types

**Files:**
- Create: `src/model/types.ts`, `src/model/types.test.ts`, `src/model/ids.ts`

**Interfaces:**
- Consumes: none
- Produces: exported types `CAPolicy`, `TenantProfile`, `Finding`, `AnalysisResult`, `CoverageMatrix`, `ManualCheck`, `EvalContext`, plus ID constants in `ids.ts`

- [ ] **Step 1: Write a compile-time test that a fixture satisfies `CAPolicy`**

`src/model/types.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import type { CAPolicy, TenantProfile } from "./types";
import { AUTH_STRENGTH, PRIVILEGED_ROLE_IDS } from "./ids";

describe("types", () => {
  it("accepts a Graph-shaped policy", () => {
    const policy: CAPolicy = {
      id: "p1",
      displayName: "Block legacy",
      state: "enabled",
      conditions: {
        users: { includeUsers: ["All"], excludeUsers: [], includeGroups: [], excludeGroups: [], includeRoles: [], excludeRoles: [] },
        applications: { includeApplications: ["All"], excludeApplications: [], includeUserActions: [], includeAuthenticationContextClassReferences: [] },
        clientAppTypes: ["exchangeActiveSync", "other"],
      },
      grantControls: { operator: "OR", builtInControls: ["block"] },
    };
    expect(policy.state).toBe("enabled");
  });

  it("exposes the 14 privileged role IDs and built-in auth strengths", () => {
    expect(PRIVILEGED_ROLE_IDS).toHaveLength(14);
    expect(PRIVILEGED_ROLE_IDS[0]).toBe("62e90394-69f5-4237-9190-012177145e10");
    expect(AUTH_STRENGTH.mfa).toBe("00000000-0000-0000-0000-000000000002");
    expect(AUTH_STRENGTH.passwordlessMfa).toBe("00000000-0000-0000-0000-000000000003");
    expect(AUTH_STRENGTH.phishingResistantMfa).toBe("00000000-0000-0000-0000-000000000004");
  });

  it("default tenant profile has P1 on and P2 off", () => {
    const tenant: TenantProfile = {
      licenses: {
        entraP1: true,
        entraP2: false,
        intune: false,
        workloadIdPremium: false,
        defenderForCloudApps: false,
        purviewInsiderRisk: false,
      },
      breakGlass: [],
      displayNames: {},
    };
    expect(tenant.licenses.entraP1).toBe(true);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/model/types.test.ts`

Expected: FAIL — `Cannot find module './types'` / `./ids`.

- [ ] **Step 3: Write types and ID constants**

`src/model/ids.ts`:

```ts
export const AUTH_STRENGTH = {
  mfa: "00000000-0000-0000-0000-000000000002",
  passwordlessMfa: "00000000-0000-0000-0000-000000000003",
  phishingResistantMfa: "00000000-0000-0000-0000-000000000004",
} as const;

export const PRIVILEGED_ROLES: ReadonlyArray<{ id: string; name: string }> = [
  { id: "62e90394-69f5-4237-9190-012177145e10", name: "Global Administrator" },
  { id: "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3", name: "Application Administrator" },
  { id: "c4e39bd9-1100-46d3-8c65-fb160da0071f", name: "Authentication Administrator" },
  { id: "b0f54661-2d74-4c50-afa3-1ec803f12efe", name: "Billing Administrator" },
  { id: "158c047a-c907-4556-b7ef-446551a6b5f7", name: "Cloud Application Administrator" },
  { id: "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", name: "Conditional Access Administrator" },
  { id: "29232cdf-9323-42fd-ade2-1d097af3e4de", name: "Exchange Administrator" },
  { id: "729827e3-9c14-49f7-bb1b-9608f156bbb8", name: "Helpdesk Administrator" },
  { id: "966707d0-3269-4727-9be2-8c3a10f19b9d", name: "Password Administrator" },
  { id: "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", name: "Privileged Authentication Administrator" },
  { id: "e8611ab8-c189-46e8-94e1-60213ab1f814", name: "Privileged Role Administrator" },
  { id: "194ae4cb-b126-40b2-bd5b-6091b380977d", name: "Security Administrator" },
  { id: "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", name: "SharePoint Administrator" },
  { id: "fe930be7-5e62-47db-91af-98c3a49a38b1", name: "User Administrator" },
];

export const PRIVILEGED_ROLE_IDS = PRIVILEGED_ROLES.map((r) => r.id);

export const APP = {
  all: "All",
  none: "None",
  office365: "Office365",
  adminPortals: "MicrosoftAdminPortals",
  exchangeOnline: "00000002-0000-0ff1-ce00-000000000000",
  sharePointOnline: "00000003-0000-0ff1-ce00-000000000000",
  teamsServices: "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",
  teamsClient: "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
  microsoftGraph: "00000003-0000-0000-c000-000000000000",
  azureAdGraph: "00000002-0000-0000-c000-000000000000",
  azurePortal: "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
  exchangeAdminCenter: "497effe9-df71-4043-a8bb-14cf78c4b63b",
  office365Portal: "00000006-0000-0ff1-ce00-000000000000",
  protectionCenter: "80ccca67-54bd-44ab-8625-4b79c4dc7775",
  azureManagement: "797f4846-ba00-4fd7-ba43-dac1f8f63013",
  azureDevOps: "499b84ac-1321-427f-aa17-267ca6975798",
  intune: "0000000a-0000-0000-c000-000000000000",
  intuneEnrollment: "d4ebce55-015a-49b5-a083-c84d1797ae8c",
  intuneWebCompanyPortal: "74bcdadc-2fdc-4bb3-8459-76d06952a0e9",
  intuneCompanyPortalClient: "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",
  deviceRegistrationService: "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9",
  graphPowerShell: "14d82eec-204b-4c2f-b7e8-296a70dab67e",
  graphExplorer: "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
  azureCli: "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
  azurePowerShell: "1950a258-227b-4e31-a9cf-717495945fc2",
  powerPlatformAdmin: "065d9450-1e87-434e-ac2f-69af271549ed",
  rms: "00000012-0000-0000-c000-000000000000",
  authBroker: "29d9ed98-a469-4536-ade2-f981bc1d605e",
} as const;

export const USER_ACTION = {
  registerSecurityInfo: "urn:user:registersecurityinfo",
  registerDevice: "urn:user:registerdevice",
} as const;

export const PHISHING_RESISTANT_COMBINATIONS = [
  "windowsHelloForBusiness",
  "fido2",
  "x509CertificateMultiFactor",
] as const;

export const ALL_GUEST_TYPES = [
  "internalGuest",
  "b2bCollaborationGuest",
  "b2bCollaborationMember",
  "b2bDirectConnectUser",
  "otherExternalUser",
  "serviceProvider",
] as const;

export const CATALOG_DATE = "2026-10-26";
```

`src/model/types.ts` — Graph-shaped, normalized (arrays already split; IDs lower-cased except well-known tokens `All`, `None`, `Office365`, `MicrosoftAdminPortals`, `AllTrusted`, `GuestsOrExternalUsers`, `ServicePrincipalsInMyTenant`, user actions):

```ts
export type PolicyState = "enabled" | "disabled" | "enabledForReportingButNotEnforced";
export type GrantOperator = "AND" | "OR";
export type BuiltInControl =
  | "block"
  | "mfa"
  | "compliantDevice"
  | "domainJoinedDevice"
  | "approvedApplication"
  | "compliantApplication"
  | "passwordChange"
  | "riskRemediation"
  | "unknownFutureValue";
export type ClientAppType =
  | "all"
  | "browser"
  | "mobileAppsAndDesktopClients"
  | "exchangeActiveSync"
  | "easSupported"
  | "other";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "gap" | "partial" | "requiresLicense" | "unverified";
export type FindingFamily = "baseline" | "admin" | "apps" | "weakening" | "risk" | "hygiene";
export type Population = "allUsers" | "admins" | "guests";
export type Surface =
  | "allResources"
  | "office365"
  | "adminPortals"
  | "azureManagement"
  | "microsoftGraph"
  | "intuneApis"
  | "azureDevOps"
  | "thirdParty"
  | "registerSecurityInfo"
  | "registerDevice";
export type Control =
  | "legacyAuthBlocked"
  | "mfa"
  | "phishingResistantMfa"
  | "managedDevice"
  | "deviceCodeBlocked"
  | "signInRisk"
  | "userRisk"
  | "sessionControls";
export type CellState = "covered" | "partial" | "gap" | "requiresLicense" | "na";
export type LicenseKey =
  | "entraP1"
  | "entraP2"
  | "intune"
  | "workloadIdPremium"
  | "defenderForCloudApps"
  | "purviewInsiderRisk";

export interface AuthenticationStrength {
  id: string;
  displayName?: string;
  policyType?: string;
  requirementsSatisfied?: string;
  allowedCombinations?: string[];
}

export interface GrantControls {
  operator: GrantOperator;
  builtInControls: BuiltInControl[];
  customAuthenticationFactors?: string[];
  termsOfUse?: string[];
  authenticationStrength?: AuthenticationStrength | null;
}

export interface SignInFrequency {
  isEnabled: boolean;
  type?: "days" | "hours";
  value?: number;
  authenticationType?: string;
  frequencyInterval?: string;
}

export interface SessionControls {
  applicationEnforcedRestrictions?: { isEnabled: boolean } | null;
  cloudAppSecurity?: { isEnabled: boolean; cloudAppSecurityType?: string } | null;
  disableResilienceDefaults?: boolean | null;
  persistentBrowser?: { isEnabled: boolean; mode: "always" | "never" } | null;
  signInFrequency?: SignInFrequency | null;
  continuousAccessEvaluation?: { mode?: string } | null;
  secureSignInSession?: { isEnabled: boolean } | null;
}

export interface GuestsOrExternalUsers {
  guestOrExternalUserTypes: string[];
  externalTenants?: { membershipKind?: string; members?: string[] };
}

export interface CAUsers {
  includeUsers: string[];
  excludeUsers: string[];
  includeGroups: string[];
  excludeGroups: string[];
  includeRoles: string[];
  excludeRoles: string[];
  includeGuestsOrExternalUsers?: GuestsOrExternalUsers | null;
  excludeGuestsOrExternalUsers?: GuestsOrExternalUsers | null;
}

export interface CAApplications {
  includeApplications: string[];
  excludeApplications: string[];
  includeUserActions: string[];
  includeAuthenticationContextClassReferences: string[];
  applicationFilter?: { mode?: string; rule?: string } | null;
}

export interface CAPolicy {
  id: string;
  displayName: string;
  state: PolicyState;
  createdDateTime?: string | null;
  modifiedDateTime?: string | null;
  templateId?: string | null;
  conditions: {
    users: CAUsers;
    applications: CAApplications;
    clientAppTypes: ClientAppType[];
    platforms?: { includePlatforms: string[]; excludePlatforms: string[] } | null;
    locations?: { includeLocations: string[]; excludeLocations: string[] } | null;
    devices?: { deviceFilter?: { mode?: string; rule?: string } | null } | null;
    signInRiskLevels?: string[];
    userRiskLevels?: string[];
    servicePrincipalRiskLevels?: string[];
    insiderRiskLevels?: string[];
    agentIdRiskLevels?: string[];
    clientApplications?: {
      includeServicePrincipals?: string[];
      excludeServicePrincipals?: string[];
      includeAgentIdServicePrincipals?: string[];
    } | null;
    authenticationFlows?: { transferMethods: string[] } | null;
  };
  grantControls?: GrantControls | null;
  sessionControls?: SessionControls | null;
  extraProperties?: Record<string, unknown>;
}

export interface TenantLicenses {
  entraP1: boolean;
  entraP2: boolean;
  intune: boolean;
  workloadIdPremium: boolean;
  defenderForCloudApps: boolean;
  purviewInsiderRisk: boolean;
}

export interface TenantProfile {
  licenses: TenantLicenses;
  breakGlass: string[];
  displayNames: Record<string, string>;
}

export interface Finding {
  ruleId: string;
  title: string;
  family: FindingFamily;
  severity: Severity;
  status: FindingStatus;
  policyIds: string[];
  explanation: string;
  remediation: string;
  references: string[];
  requiredLicense?: LicenseKey;
}

export interface CoverageCell {
  surface: Surface;
  control: Control;
  state: CellState;
  policyIds: string[];
  findingIds: string[];
}

export interface CoverageMatrix {
  population: Population;
  cells: CoverageCell[];
}

export interface ManualCheck {
  id: string;
  title: string;
  whereToLook: string;
  relatedRuleIds: string[];
}

export interface AnalysisResult {
  findings: Finding[];
  matrices: CoverageMatrix[];
  manualChecks: ManualCheck[];
  score: number;
}

export interface EvalContext {
  policies: CAPolicy[];
  tenant: TenantProfile;
}

export const DEFAULT_TENANT: TenantProfile = {
  licenses: {
    entraP1: true,
    entraP2: false,
    intune: false,
    workloadIdPremium: false,
    defenderForCloudApps: false,
    purviewInsiderRisk: false,
  },
  breakGlass: [],
  displayNames: {},
};
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/model/types.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/model
git commit -m "$(cat <<'EOF'
feat: add Graph-shaped CA policy types and well-known IDs

EOF
)"
```

---

### Task 3: Import and normalize Graph JSON

**Files:**
- Create: `src/model/normalize.ts`, `src/model/importPolicies.ts`, `src/model/normalize.test.ts`, `src/model/importPolicies.test.ts`

**Interfaces:**
- Consumes: `CAPolicy` from `src/model/types.ts`, `APP` tokens from `src/model/ids.ts`
- Produces: `normalizePolicy(raw: unknown): { policy?: CAPolicy; warnings: string[]; error?: string }`, `importPolicies(input: string | unknown): { policies: CAPolicy[]; errors: string[]; warnings: string[] }`

Well-known tokens that must **not** be lowercased: `All`, `None`, `Office365`, `MicrosoftAdminPortals`, `AllTrusted`, `AllAgentIdUsers`, `AllAgentIdResources`, `GuestsOrExternalUsers`, `ServicePrincipalsInMyTenant`, and any value starting with `urn:user:`.

- [ ] **Step 1: Write failing tests**

`src/model/importPolicies.test.ts`:

```ts
import { describe, it, expect } from "vitest";
import { importPolicies } from "./importPolicies";

const blockLegacy = {
  id: "1",
  displayName: "Block legacy",
  state: "enabled",
  conditions: {
    users: { includeUsers: ["All"] },
    applications: { includeApplications: ["All"] },
    clientAppTypes: ["exchangeActiveSync", "other"],
  },
  grantControls: { operator: "OR", builtInControls: ["block"] },
};

describe("importPolicies", () => {
  it("imports a single policy object", () => {
    const result = importPolicies(JSON.stringify(blockLegacy));
    expect(result.policies).toHaveLength(1);
    expect(result.policies[0].displayName).toBe("Block legacy");
    expect(result.errors).toEqual([]);
  });

  it("imports an array of policies", () => {
    const result = importPolicies([blockLegacy, { ...blockLegacy, id: "2" }]);
    expect(result.policies).toHaveLength(2);
  });

  it("imports a Graph { value: [] } wrapper", () => {
    const result = importPolicies({ value: [blockLegacy] });
    expect(result.policies).toHaveLength(1);
  });

  it("keeps valid policies when one entry is malformed", () => {
    const result = importPolicies([blockLegacy, { displayName: "nope" }]);
    expect(result.policies).toHaveLength(1);
    expect(result.errors).toHaveLength(1);
  });

  it("returns an error for invalid JSON text", () => {
    const result = importPolicies("{not json");
    expect(result.policies).toEqual([]);
    expect(result.errors[0]).toMatch(/JSON/i);
  });

  it("splits comma-separated flag enums into arrays", () => {
    const result = importPolicies({
      ...blockLegacy,
      conditions: {
        ...blockLegacy.conditions,
        authenticationFlows: { transferMethods: "deviceCodeFlow,authenticationTransfer" },
        users: {
          includeUsers: [],
          includeGuestsOrExternalUsers: {
            guestOrExternalUserTypes: "internalGuest,b2bCollaborationGuest",
            externalTenants: { membershipKind: "all" },
          },
        },
      },
    });
    expect(result.policies[0].conditions.authenticationFlows?.transferMethods).toEqual([
      "deviceCodeFlow",
      "authenticationTransfer",
    ]);
    expect(
      result.policies[0].conditions.users.includeGuestsOrExternalUsers?.guestOrExternalUserTypes,
    ).toEqual(["internalGuest", "b2bCollaborationGuest"]);
  });

  it("lowercases app IDs but preserves All and MicrosoftAdminPortals", () => {
    const result = importPolicies({
      ...blockLegacy,
      conditions: {
        ...blockLegacy.conditions,
        applications: {
          includeApplications: ["MicrosoftAdminPortals", "797F4846-BA00-4FD7-BA43-DAC1F8F63013"],
        },
      },
    });
    expect(result.policies[0].conditions.applications.includeApplications).toEqual([
      "MicrosoftAdminPortals",
      "797f4846-ba00-4fd7-ba43-dac1f8f63013",
    ]);
  });

  it("synthesizes an id when Graph omitted it", () => {
    const { id: _id, ...rest } = blockLegacy;
    const result = importPolicies(rest);
    expect(result.policies[0].id.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `npx vitest run src/model/importPolicies.test.ts`

Expected: FAIL — module not found.

- [ ] **Step 3: Implement normalize + import**

`src/model/normalize.ts`:

```ts
import type {
  CAPolicy,
  CAUsers,
  CAApplications,
  ClientAppType,
  GrantOperator,
  BuiltInControl,
  PolicyState,
} from "./types";

const PRESERVE_CASE = new Set([
  "All",
  "None",
  "Office365",
  "MicrosoftAdminPortals",
  "AllTrusted",
  "AllAgentIdUsers",
  "AllAgentIdResources",
  "GuestsOrExternalUsers",
  "ServicePrincipalsInMyTenant",
]);

export function normalizeToken(value: string): string {
  if (value.startsWith("urn:user:")) return value;
  if (PRESERVE_CASE.has(value)) return value;
  if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(value)) {
    return value.toLowerCase();
  }
  return value;
}

export function asStringArray(value: unknown): string[] {
  if (value == null) return [];
  if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
  if (typeof value === "string") {
    return value
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean);
  }
  return [];
}

function users(raw: Record<string, unknown> | undefined): CAUsers {
  const u = raw ?? {};
  const guest = (g: unknown): CAUsers["includeGuestsOrExternalUsers"] => {
    if (!g || typeof g !== "object") return null;
    const o = g as Record<string, unknown>;
    const tenants = o.externalTenants as Record<string, unknown> | undefined;
    return {
      guestOrExternalUserTypes: asStringArray(o.guestOrExternalUserTypes),
      externalTenants: tenants
        ? {
            membershipKind: tenants.membershipKind ? String(tenants.membershipKind) : undefined,
            members: asStringArray(tenants.members),
          }
        : undefined,
    };
  };
  return {
    includeUsers: asStringArray(u.includeUsers).map(normalizeToken),
    excludeUsers: asStringArray(u.excludeUsers).map(normalizeToken),
    includeGroups: asStringArray(u.includeGroups).map(normalizeToken),
    excludeGroups: asStringArray(u.excludeGroups).map(normalizeToken),
    includeRoles: asStringArray(u.includeRoles).map(normalizeToken),
    excludeRoles: asStringArray(u.excludeRoles).map(normalizeToken),
    includeGuestsOrExternalUsers: guest(u.includeGuestsOrExternalUsers),
    excludeGuestsOrExternalUsers: guest(u.excludeGuestsOrExternalUsers),
  };
}

function applications(raw: Record<string, unknown> | undefined): CAApplications {
  const a = raw ?? {};
  return {
    includeApplications: asStringArray(a.includeApplications).map(normalizeToken),
    excludeApplications: asStringArray(a.excludeApplications).map(normalizeToken),
    includeUserActions: asStringArray(a.includeUserActions),
    includeAuthenticationContextClassReferences: asStringArray(
      a.includeAuthenticationContextClassReferences,
    ),
    applicationFilter: (a.applicationFilter as CAApplications["applicationFilter"]) ?? null,
  };
}

export function normalizePolicy(raw: unknown): { policy?: CAPolicy; warnings: string[]; error?: string } {
  const warnings: string[] = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { warnings, error: "Policy is not an object" };
  }
  const o = raw as Record<string, unknown>;
  if (!o.conditions || typeof o.conditions !== "object") {
    return { warnings, error: `Policy "${String(o.displayName ?? o.id ?? "?")}" is missing conditions` };
  }
  const conditions = o.conditions as Record<string, unknown>;
  const known = new Set([
    "id",
    "displayName",
    "state",
    "createdDateTime",
    "modifiedDateTime",
    "templateId",
    "conditions",
    "grantControls",
    "sessionControls",
    "description",
    "deletedDateTime",
    "partialEnablementStrategy",
  ]);
  const extra: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (!known.has(k)) extra[k] = v;
  }
  if (Object.keys(extra).length) warnings.push(`Unrecognized fields preserved: ${Object.keys(extra).join(", ")}`);

  const grant = o.grantControls as Record<string, unknown> | null | undefined;
  const session = o.sessionControls as Record<string, unknown> | null | undefined;
  const id = String(o.id ?? crypto.randomUUID());
  const state = (o.state as PolicyState) ?? "enabled";

  const policy: CAPolicy = {
    id,
    displayName: String(o.displayName ?? "(unnamed policy)"),
    state,
    createdDateTime: (o.createdDateTime as string | null) ?? null,
    modifiedDateTime: (o.modifiedDateTime as string | null) ?? null,
    templateId: (o.templateId as string | null) ?? null,
    extraProperties: Object.keys(extra).length ? extra : undefined,
    conditions: {
      users: users(conditions.users as Record<string, unknown> | undefined),
      applications: applications(conditions.applications as Record<string, unknown> | undefined),
      clientAppTypes: (asStringArray(conditions.clientAppTypes) as ClientAppType[]).length
        ? (asStringArray(conditions.clientAppTypes) as ClientAppType[])
        : ["all"],
      platforms: conditions.platforms
        ? {
            includePlatforms: asStringArray((conditions.platforms as Record<string, unknown>).includePlatforms),
            excludePlatforms: asStringArray((conditions.platforms as Record<string, unknown>).excludePlatforms),
          }
        : null,
      locations: conditions.locations
        ? {
            includeLocations: asStringArray((conditions.locations as Record<string, unknown>).includeLocations),
            excludeLocations: asStringArray((conditions.locations as Record<string, unknown>).excludeLocations),
          }
        : null,
      devices: conditions.devices
        ? { deviceFilter: ((conditions.devices as Record<string, unknown>).deviceFilter as { mode?: string; rule?: string }) ?? null }
        : null,
      signInRiskLevels: asStringArray(conditions.signInRiskLevels),
      userRiskLevels: asStringArray(conditions.userRiskLevels),
      servicePrincipalRiskLevels: asStringArray(conditions.servicePrincipalRiskLevels),
      insiderRiskLevels: asStringArray(conditions.insiderRiskLevels),
      agentIdRiskLevels: asStringArray(conditions.agentIdRiskLevels),
      clientApplications: (conditions.clientApplications as CAPolicy["conditions"]["clientApplications"]) ?? null,
      authenticationFlows: conditions.authenticationFlows
        ? {
            transferMethods: asStringArray(
              (conditions.authenticationFlows as Record<string, unknown>).transferMethods,
            ),
          }
        : null,
    },
    grantControls: grant
      ? {
          operator: ((String(grant.operator ?? "AND").toUpperCase() as GrantOperator) === "OR" ? "OR" : "AND"),
          builtInControls: asStringArray(grant.builtInControls) as BuiltInControl[],
          customAuthenticationFactors: asStringArray(grant.customAuthenticationFactors),
          termsOfUse: asStringArray(grant.termsOfUse),
          authenticationStrength: (grant.authenticationStrength as CAPolicy["grantControls"] extends infer G
            ? G extends { authenticationStrength?: infer A }
              ? A
              : never
            : never) ?? null,
        }
      : null,
    sessionControls: (session as CAPolicy["sessionControls"]) ?? null,
  };
  return { policy, warnings };
}
```

If the `authenticationStrength` ternary is too noisy for the compiler, assign `grant.authenticationStrength as CAPolicy["grantControls"]` via a local:

```ts
authenticationStrength: (grant.authenticationStrength as CAPolicy["grantControls"] extends null ? never : NonNullable<CAPolicy["grantControls"]>["authenticationStrength"]) ?? null,
```

Simplest working form:

```ts
authenticationStrength:
  grant.authenticationStrength && typeof grant.authenticationStrength === "object"
    ? (grant.authenticationStrength as NonNullable<CAPolicy["grantControls"]>["authenticationStrength"])
    : null,
```

`src/model/importPolicies.ts`:

```ts
import type { CAPolicy } from "./types";
import { normalizePolicy } from "./normalize";

export function importPolicies(input: string | unknown): {
  policies: CAPolicy[];
  errors: string[];
  warnings: string[];
} {
  const errors: string[] = [];
  const warnings: string[] = [];
  let parsed: unknown = input;
  if (typeof input === "string") {
    try {
      parsed = JSON.parse(input);
    } catch {
      return { policies: [], errors: ["The file is not valid JSON."], warnings };
    }
  }
  const list: unknown[] = Array.isArray(parsed)
    ? parsed
    : parsed && typeof parsed === "object" && Array.isArray((parsed as { value?: unknown }).value)
      ? ((parsed as { value: unknown[] }).value)
      : [parsed];
  const policies: CAPolicy[] = [];
  list.forEach((item, index) => {
    const result = normalizePolicy(item);
    warnings.push(...result.warnings);
    if (result.error) {
      errors.push(`Entry ${index + 1}: ${result.error}`);
      return;
    }
    if (result.policy) policies.push(result.policy);
  });
  return { policies, errors, warnings };
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/model/importPolicies.test.ts src/model/normalize.test.ts`

Expected: PASS. If `normalize.test.ts` was not created, skip it — the import tests cover normalize.

- [ ] **Step 5: Commit**

```bash
git add src/model
git commit -m "$(cat <<'EOF'
feat: import and normalize Graph Conditional Access JSON

EOF
)"
```

---

### Task 4: App catalog

**Files:**
- Create: `src/catalog/apps.ts`, `src/catalog/apps.test.ts`

**Interfaces:**
- Consumes: `APP` from `src/model/ids.ts`, `Surface` from `src/model/types.ts`
- Produces: `AppEntry`, `APP_CATALOG: AppEntry[]`, `getApp(id: string): AppEntry | undefined`, `appsForSurface(surface: Surface): AppEntry[]`, `isTargetable(id: string): boolean`

- [ ] **Step 1: Write failing tests**

```ts
import { describe, it, expect } from "vitest";
import { APP_CATALOG, getApp, isTargetable, appsForSurface } from "./apps";
import { APP } from "../model/ids";

describe("app catalog", () => {
  it("keys Microsoft Admin Portals members by app ID", () => {
    const members = APP_CATALOG.filter((a) => a.groups.includes("MicrosoftAdminPortals"));
    expect(members.map((m) => m.appId).sort()).toEqual(
      [APP.exchangeAdminCenter, APP.azurePortal, APP.office365Portal, APP.protectionCenter].sort(),
    );
  });

  it("marks Graph PowerShell and Azure CLI as not targetable", () => {
    expect(isTargetable(APP.graphPowerShell)).toBe(false);
    expect(isTargetable(APP.azureCli)).toBe(false);
    expect(isTargetable(APP.azureManagement)).toBe(true);
  });

  it("maps Intune API to the intuneApis surface, not adminPortals", () => {
    expect(getApp(APP.intune)?.surface).toBe("intuneApis");
    expect(getApp(APP.azurePortal)?.surface).toBe("adminPortals");
  });

  it("maps Graph to microsoftGraph and Azure DevOps to azureDevOps", () => {
    expect(getApp(APP.microsoftGraph)?.surface).toBe("microsoftGraph");
    expect(getApp(APP.azureDevOps)?.surface).toBe("azureDevOps");
  });

  it("does not treat Graph as coverable except via All (targetable false, surface microsoftGraph)", () => {
    expect(getApp(APP.microsoftGraph)?.targetable).toBe(false);
  });

  it("lists office365 surface apps including Exchange, SharePoint, Teams", () => {
    const ids = appsForSurface("office365").map((a) => a.appId);
    expect(ids).toEqual(expect.arrayContaining([APP.exchangeOnline, APP.sharePointOnline, APP.teamsServices]));
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/catalog/apps.test.ts`

Expected: FAIL — module not found.

- [ ] **Step 3: Implement the catalog**

`src/catalog/apps.ts`:

```ts
import { APP } from "../model/ids";
import type { Surface } from "../model/types";

export interface AppEntry {
  appId: string;
  name: string;
  aliases: string[];
  surface: Surface;
  groups: Array<"Office365" | "MicrosoftAdminPortals">;
  targetable: boolean;
  notes: string;
  confidence: "verified" | "unverified";
  source: string;
}

const L = "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps";

export const APP_CATALOG: AppEntry[] = [
  { appId: APP.exchangeAdminCenter, name: "Exchange Admin Center", aliases: [], surface: "adminPortals", groups: ["MicrosoftAdminPortals"], targetable: true, notes: "Member of Microsoft Admin Portals (Feb 2026).", confidence: "verified", source: L },
  { appId: APP.azurePortal, name: "Azure portal", aliases: ["Microsoft Entra admin center", "Intune admin center (sign-in)"], surface: "adminPortals", groups: ["MicrosoftAdminPortals"], targetable: true, notes: "Entra and Intune admin center front ends sign in with this ID. Backend Graph/Intune/ARM calls are not covered.", confidence: "verified", source: L },
  { appId: APP.office365Portal, name: "Microsoft Office 365 Portal", aliases: ["Microsoft 365 admin center"], surface: "adminPortals", groups: ["Office365", "MicrosoftAdminPortals"], targetable: true, notes: "", confidence: "verified", source: L },
  { appId: APP.protectionCenter, name: "Protection Center", aliases: ["Microsoft 365 Security and Compliance Center", "Purview (unverified mapping)"], surface: "adminPortals", groups: ["Office365", "MicrosoftAdminPortals"], targetable: true, notes: "Purview/Defender portal mapping is unverified after Feb 2026.", confidence: "verified", source: L },
  { appId: APP.exchangeOnline, name: "Office 365 Exchange Online", aliases: [], surface: "office365", groups: ["Office365"], targetable: true, notes: "", confidence: "verified", source: L },
  { appId: APP.sharePointOnline, name: "Office 365 SharePoint Online", aliases: ["SharePoint admin center"], surface: "office365", groups: ["Office365"], targetable: true, notes: "A SharePoint-only policy also affects Teams.", confidence: "unverified", source: L },
  { appId: APP.teamsServices, name: "Microsoft Teams Services", aliases: [], surface: "office365", groups: ["Office365"], targetable: true, notes: "", confidence: "verified", source: L },
  { appId: APP.azureManagement, name: "Windows Azure Service Management API", aliases: ["Microsoft Azure Management", "Azure Resource Manager"], surface: "azureManagement", groups: [], targetable: true, notes: "Match by app ID. Covers ARM, Azure portal, CLI, PowerShell. Does not cover Graph or Azure DevOps (since Sep 2025).", confidence: "verified", source: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-azure-mgmt" },
  { appId: APP.microsoftGraph, name: "Microsoft Graph", aliases: [], surface: "microsoftGraph", groups: [], targetable: false, notes: "Cannot be selected as a target. Only All resources covers it.", confidence: "verified", source: L },
  { appId: APP.azureAdGraph, name: "Azure AD Graph", aliases: ["Windows Azure Active Directory"], surface: "microsoftGraph", groups: [], targetable: false, notes: "Covered by All resources; used for baseline-scope enforcement.", confidence: "verified", source: L },
  { appId: APP.graphPowerShell, name: "Microsoft Graph Command Line Tools", aliases: ["Microsoft Graph PowerShell"], surface: "microsoftGraph", groups: [], targetable: false, notes: "Public client. Targeting this ID has no effect.", confidence: "verified", source: L },
  { appId: APP.graphExplorer, name: "Graph Explorer", aliases: [], surface: "microsoftGraph", groups: [], targetable: false, notes: "Public client.", confidence: "verified", source: L },
  { appId: APP.intune, name: "Microsoft Intune", aliases: ["Microsoft Intune API"], surface: "intuneApis", groups: [], targetable: true, notes: "Not a member of Microsoft Admin Portals.", confidence: "unverified", source: L },
  { appId: APP.intuneEnrollment, name: "Microsoft Intune Enrollment", aliases: [], surface: "intuneApis", groups: [], targetable: true, notes: "Compliant-device grant does not block enrollment; excluding this app is usually unnecessary. May be missing as a service principal in new tenants.", confidence: "verified", source: "https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-policy-compliant-device" },
  { appId: APP.intuneWebCompanyPortal, name: "Microsoft Intune Web Company Portal", aliases: [], surface: "intuneApis", groups: [], targetable: true, notes: "Exclusion usually unnecessary.", confidence: "unverified", source: L },
  { appId: APP.azureDevOps, name: "Azure DevOps", aliases: [], surface: "azureDevOps", groups: [], targetable: true, notes: "No longer covered by Azure management since Sep 2025.", confidence: "verified", source: "https://mc.merill.net/message/MC1123830" },
  { appId: APP.azureCli, name: "Azure CLI", aliases: [], surface: "azureManagement", groups: [], targetable: false, notes: "Client identity; covered via ARM resource.", confidence: "verified", source: L },
  { appId: APP.azurePowerShell, name: "Azure PowerShell", aliases: [], surface: "azureManagement", groups: [], targetable: false, notes: "Client identity; covered via ARM resource.", confidence: "verified", source: L },
  { appId: APP.teamsClient, name: "Microsoft Teams (client)", aliases: [], surface: "office365", groups: [], targetable: false, notes: "Public client.", confidence: "verified", source: L },
  { appId: APP.intuneCompanyPortalClient, name: "Microsoft Intune Company Portal", aliases: [], surface: "intuneApis", groups: [], targetable: false, notes: "Public client.", confidence: "verified", source: L },
  { appId: APP.authBroker, name: "Microsoft Authentication Broker", aliases: [], surface: "thirdParty", groups: [], targetable: false, notes: "Public client.", confidence: "unverified", source: L },
  { appId: APP.deviceRegistrationService, name: "Device Registration Service", aliases: [], surface: "registerDevice", groups: [], targetable: true, notes: "Only targeted via user action Register or join devices.", confidence: "verified", source: L },
  { appId: APP.rms, name: "Microsoft Rights Management Services", aliases: [], surface: "office365", groups: [], targetable: true, notes: "Often excluded for B2B encryption.", confidence: "verified", source: L },
  { appId: APP.powerPlatformAdmin, name: "Power Platform admin center", aliases: [], surface: "thirdParty", groups: [], targetable: true, notes: "Not a confirmed Microsoft Admin Portals member.", confidence: "verified", source: L },
];

export function getApp(id: string): AppEntry | undefined {
  const key = id.toLowerCase();
  return APP_CATALOG.find((a) => a.appId.toLowerCase() === key);
}

export function isTargetable(id: string): boolean {
  const app = getApp(id);
  if (!app) return true;
  return app.targetable;
}

export function appsForSurface(surface: Surface): AppEntry[] {
  return APP_CATALOG.filter((a) => a.surface === surface);
}
```

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/catalog/apps.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/catalog
git commit -m "$(cat <<'EOF'
feat: add Microsoft first-party app catalog keyed by app ID

EOF
)"
```

---

### Task 5: Engine predicates

**Files:**
- Create: `src/engine/predicates.ts`, `src/engine/predicates.test.ts`, `src/test/fixtures.ts`

**Interfaces:**
- Consumes: `CAPolicy`, `TenantProfile`, `APP`, `AUTH_STRENGTH`, `PRIVILEGED_ROLE_IDS`, `PHISHING_RESISTANT_COMBINATIONS`
- Produces: the predicate functions listed below. Later rule tasks must call these names exactly.

```ts
export function isEnforced(p: CAPolicy): boolean
export function isReportOnly(p: CAPolicy): boolean
export function allUsers(p: CAPolicy): boolean
export function includesAnyPrivilegedRole(p: CAPolicy): boolean
export function includesAllPrivilegedRoles(p: CAPolicy): boolean
export function coversGuests(p: CAPolicy): boolean
export function excludesGuests(p: CAPolicy): boolean
export function allResources(p: CAPolicy): boolean
export function noAppExclusions(p: CAPolicy): boolean
export function includesApp(p: CAPolicy, appIdOrToken: string): boolean
export function excludesApp(p: CAPolicy, appIdOrToken: string): boolean
export function coversSurfaceAll(p: CAPolicy): boolean // All with no exclusions that strip the surface
export function coversLegacy(p: CAPolicy): boolean
export function coversAllClients(p: CAPolicy): boolean
export function unconditioned(p: CAPolicy): boolean
export function isBlock(p: CAPolicy): boolean
export function requiresMfa(p: CAPolicy): boolean
export function requiresPhishingResistant(p: CAPolicy): boolean
export function requiresManagedDevice(p: CAPolicy): boolean
export function grantIsOrWeakened(p: CAPolicy): boolean
export function exclusionsOnlyBreakGlass(p: CAPolicy, tenant: TenantProfile): boolean
export function hasUserAction(p: CAPolicy, action: string): boolean
export function hasDeviceCodeFlow(p: CAPolicy): boolean
export function hasAuthenticationTransfer(p: CAPolicy): boolean
```

`requiresMfa`: AND → any control is MFA-equivalent; OR → every alternative is MFA-equivalent (a lone MFA control with operator OR still counts). MFA-equivalent = `builtInControls` contains `mfa` OR `authenticationStrength.requirementsSatisfied === "mfa"` OR strength id is `AUTH_STRENGTH.mfa`, `passwordlessMfa`, or `phishingResistantMfa`.

`requiresPhishingResistant`: strength id is `AUTH_STRENGTH.phishingResistantMfa` OR `allowedCombinations` is a non-empty subset of `PHISHING_RESISTANT_COMBINATIONS`. AND: any such control; OR: every alternative is phishing-resistant.

`unconditioned`: platforms null or include `all` with empty exclude; locations null or include `All` with empty exclude; empty risk arrays; no insider risk; no device filter; no authenticationFlows.

`exclusionsOnlyBreakGlass`: every `excludeUsers` value is in `tenant.breakGlass` (case-insensitive) or is not `GuestsOrExternalUsers`; `excludeGroups` every id is in `tenant.breakGlass`; `excludeRoles` empty; `excludeGuestsOrExternalUsers` null/absent.

- [ ] **Step 1: Write fixtures and failing predicate tests**

`src/test/fixtures.ts`:

```ts
import type { CAPolicy, TenantProfile } from "../model/types";
import { DEFAULT_TENANT } from "../model/types";
import { APP, PRIVILEGED_ROLE_IDS, AUTH_STRENGTH } from "../model/ids";

export const bgTenant = (): TenantProfile => ({
  ...DEFAULT_TENANT,
  breakGlass: ["bg-user-1"],
});

export function policy(overrides: Partial<CAPolicy> & { conditions?: Partial<CAPolicy["conditions"]> } = {}): CAPolicy {
  const base: CAPolicy = {
    id: overrides.id ?? "p",
    displayName: overrides.displayName ?? "policy",
    state: overrides.state ?? "enabled",
    conditions: {
      users: {
        includeUsers: ["All"],
        excludeUsers: ["bg-user-1"],
        includeGroups: [],
        excludeGroups: [],
        includeRoles: [],
        excludeRoles: [],
      },
      applications: {
        includeApplications: ["All"],
        excludeApplications: [],
        includeUserActions: [],
        includeAuthenticationContextClassReferences: [],
      },
      clientAppTypes: ["all"],
    },
  };
  return {
    ...base,
    ...overrides,
    conditions: {
      ...base.conditions,
      ...overrides.conditions,
      users: { ...base.conditions.users, ...overrides.conditions?.users },
      applications: { ...base.conditions.applications, ...overrides.conditions?.applications },
    },
  };
}

export const blockLegacy = (): CAPolicy =>
  policy({
    id: "legacy",
    displayName: "Block legacy",
    conditions: { clientAppTypes: ["exchangeActiveSync", "other"] },
    grantControls: { operator: "OR", builtInControls: ["block"] },
  });

export const mfaAll = (): CAPolicy =>
  policy({
    id: "mfa",
    displayName: "MFA all",
    grantControls: { operator: "OR", builtInControls: ["mfa"] },
  });

export const adminPhish = (): CAPolicy =>
  policy({
    id: "admin-phish",
    displayName: "Admin phishing-resistant",
    conditions: {
      users: {
        includeUsers: [],
        excludeUsers: ["bg-user-1"],
        includeGroups: [],
        excludeGroups: [],
        includeRoles: [...PRIVILEGED_ROLE_IDS],
        excludeRoles: [],
      },
    },
    grantControls: {
      operator: "OR",
      builtInControls: [],
      authenticationStrength: { id: AUTH_STRENGTH.phishingResistantMfa, requirementsSatisfied: "mfa" },
    },
  });
```

`src/engine/predicates.test.ts` — assert:

- `isEnforced` true only for `enabled`
- `coversLegacy(blockLegacy())` true; false if only `other`
- `requiresMfa(mfaAll())` true; `requiresMfa` of OR(`mfa`,`compliantDevice`) false; AND of those true
- `requiresPhishingResistant(adminPhish())` true
- `unconditioned(mfaAll())` true; false when `excludeLocations: ["AllTrusted"]`
- `exclusionsOnlyBreakGlass(mfaAll(), bgTenant())` true; false when `excludeUsers` includes another GUID
- `allResources` / `includesApp` for `MicrosoftAdminPortals` and `APP.azureManagement`

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/engine/predicates.test.ts`

Expected: FAIL — module not found.

- [ ] **Step 3: Implement predicates.ts** with the functions listed in Interfaces, using the semantics above.

- [ ] **Step 4: Run tests**

Run: `npx vitest run src/engine/predicates.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/engine/predicates.ts src/engine/predicates.test.ts src/test/fixtures.ts
git commit -m "$(cat <<'EOF'
feat: add CA policy evaluation predicates

EOF
)"
```

---

### Task 6: Finding helper and rule runner

**Files:**
- Create: `src/engine/findings.ts`, `src/engine/findings.test.ts`, `src/engine/rules/types.ts`

**Interfaces:**
- Consumes: `Finding`, `EvalContext`, `LicenseKey`, predicates
- Produces:

```ts
export interface Rule {
  id: string;
  title: string;
  family: FindingFamily;
  severity: Severity;
  requiredLicense?: LicenseKey;
  extraLicenses?: LicenseKey[];
  references: string[];
  evaluate: (ctx: EvalContext) => Finding[];
}

export function finding(rule: Rule, partial: Omit<Finding, "ruleId" | "title" | "family" | "severity" | "references"> & { title?: string; severity?: Severity }): Finding

export function licenseStatus(ctx: EvalContext, rule: Rule): "ok" | "requiresLicense"

export function matchState(enforced: CAPolicy[], reportOnly: CAPolicy[]): "met" | "partial" | "gap"
```

HYG-01 is **not** a separate rule ID. When a requirement is met only by report-only policies, the originating rule emits `status: "partial"` (this is CA-027). Do not also emit `HYG-01`.

- [ ] **Step 1: Write tests** that `finding()` copies rule metadata, that `licenseStatus` returns `requiresLicense` when `entraP2` is false and `requiredLicense` is `entraP2`, and that `matchState` returns `partial` when only report-only policies are supplied.

- [ ] **Step 2: Run to verify failure**

Run: `npx vitest run src/engine/findings.test.ts`

Expected: FAIL.

- [ ] **Step 3: Implement `src/engine/findings.ts` and `src/engine/rules/types.ts` (`export type { Rule }` from findings or rules/types — pick `src/engine/rules/types.ts` for `Rule` so family files import one path).

- [ ] **Step 4: Run tests — Expected: PASS.**

- [ ] **Step 5: Commit**

```bash
git add src/engine/findings.ts src/engine/findings.test.ts src/engine/rules/types.ts
git commit -m "$(cat <<'EOF'
feat: add finding factory and license gating

EOF
)"
```

---

### Task 7: Baseline rules (BAS-01 … BAS-11)

**Files:**
- Create: `src/engine/rules/baseline.ts`, `src/engine/rules/baseline.test.ts`

**Interfaces:**
- Consumes: `Rule`, `finding`, `licenseStatus`, `matchState`, all Task 5 predicates, `USER_ACTION`, `APP`
- Produces: `export const baselineRules: Rule[]` containing exactly IDs BAS-01 through BAS-11

Rule logic (emit one finding when the requirement is a gap or partial; skip when met by an enforced policy):

| ID | Met when an enforced policy exists such that |
|---|---|
| BAS-01 | `allUsers ∧ allResources ∧ coversLegacy ∧ isBlock ∧ exclusionsOnlyBreakGlass` |
| BAS-02 | Fire only if a legacy block exists that includes `other` but not `exchangeActiveSync` and not `all` |
| BAS-03 | `allUsers ∧ allResources ∧ noAppExclusions ∧ coversAllClients ∧ unconditioned ∧ requiresMfa ∧ exclusionsOnlyBreakGlass`. A location exclusion of `AllTrusted` does **not** count (WEK-04 covers that). |
| BAS-04 | `allUsers ∧ allResources ∧ hasDeviceCodeFlow ∧ isBlock` |
| BAS-05 | `allUsers ∧ allResources ∧ hasAuthenticationTransfer ∧ isBlock` (severity low) |
| BAS-06 | `includePlatforms` contains `all`, `excludePlatforms` non-empty, `allUsers`, `allResources`, `isBlock` |
| BAS-07 | MFA policy covers guests: `allUsers` and not `excludesGuests`, OR `coversGuests` with MFA |
| BAS-08 | `hasUserAction(registerSecurityInfo)` and (`requiresMfa` or `requiresManagedDevice`) |
| BAS-09 | `hasUserAction(registerDevice)` and (`requiresMfa` or `requiresPhishingResistant`). Also fire (same ID, extra finding ok) if such a policy uses unsupported grants (`compliantDevice`, `block`) or location/platform/deviceFilter/clientAppTypes other than all. |
| BAS-10 | `allUsers ∧ allResources` and grant contains `compliantDevice` or `domainJoinedDevice` (AND, or OR among only those two). Microsoft's MFA OR device template is **partial**. Requires Intune: if `!tenant.licenses.intune` emit `requiresLicense`. |
| BAS-11 | `allUsers ∧ allResources` with a device filter targeting unmanaged devices AND `signInFrequency.isEnabled` AND `persistentBrowser.mode === "never"` |

References:

- BAS-01: `https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies`
- BAS-03: `https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps`
- BAS-04: `https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows`
- BAS-08: `https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration`

- [ ] **Step 1: Write failing tests**, one pair per rule ID, using `src/test/fixtures.ts`. Pattern:

```ts
import { describe, it, expect } from "vitest";
import { baselineRules } from "./baseline";
import { blockLegacy, mfaAll, bgTenant, policy } from "../../test/fixtures";

function run(id: string, policies: CAPolicy[], tenant = bgTenant()) {
  const rule = baselineRules.find((r) => r.id === id)!;
  return rule.evaluate({ policies, tenant });
}

it("BAS-01 fires when legacy auth is not blocked", () => {
  expect(run("BAS-01", [mfaAll()]).some((f) => f.status === "gap")).toBe(true);
});
it("BAS-01 is silent when legacy is blocked", () => {
  expect(run("BAS-01", [blockLegacy()])).toEqual([]);
});
it("BAS-01 is partial when the only legacy block is report-only", () => {
  const p = { ...blockLegacy(), state: "enabledForReportingButNotEnforced" as const };
  expect(run("BAS-01", [p])[0].status).toBe("partial");
});
```

Cover BAS-02 through BAS-11 the same way: one gap fixture, one satisfied fixture. For BAS-10 use `tenant.licenses.intune = false` to assert `requiresLicense`.

- [ ] **Step 2: Run to verify failure** — `npx vitest run src/engine/rules/baseline.test.ts` — FAIL.

- [ ] **Step 3: Implement `baseline.ts`.** Export `baselineRules` as an array of 11 `Rule` objects. Each `evaluate` uses `matchState` on the filtered enforced vs report-only lists.

- [ ] **Step 4: Run tests — Expected: PASS.**

- [ ] **Step 5: Commit**

```bash
git add src/engine/rules/baseline.ts src/engine/rules/baseline.test.ts
git commit -m "$(cat <<'EOF'
feat: add baseline Conditional Access gap rules

EOF
)"
```

---

### Task 8: Admin rules (ADM-01 … ADM-08)

**Files:**
- Create: `src/engine/rules/admin.ts`, `src/engine/rules/admin.test.ts`

**Interfaces:**
- Consumes: same as Task 7 plus `PRIVILEGED_ROLES`, `APP`
- Produces: `export const adminRules: Rule[]`

| ID | Detection |
|---|---|
| ADM-01 | For each of the 14 role IDs, there is no enforced policy where (role ∈ `includeRoles` OR `allUsers`) AND `allResources` AND `unconditioned` AND `requiresPhishingResistant`. Finding lists missing role names. |
| ADM-02 | Same population as ADM-01 but `requiresMfa`. Fire only when ADM-01 would fire **and** BAS-03 is also unmet for those users (no all-user MFA baseline). |
| ADM-03 | There exists an enforced admin-scoped (`includesAnyPrivilegedRole` or admin groups — treat includeRoles ∩ privileged set) MFA/phish policy whose include apps are only `MicrosoftAdminPortals` (and/or its four member IDs) and no enforced admin policy uses `All`. |
| ADM-04 | Same, but include apps are only `APP.azureManagement`. Mention Azure DevOps and Graph are uncovered. |
| ADM-05 | Every enforced admin MFA/phish policy scopes users only via `includeRoles` (no `includeGroups`, no `allUsers`). Status `unverified` because PIM eligibility cannot be read. Explanation tells the user to also include a group of eligible admins. |
| ADM-06 | No enforced admin-role policy with `requiresManagedDevice` (AND). License `intune`. |
| ADM-07 | No enforced admin-role policy with `sessionControls.signInFrequency.isEnabled`. Severity low. |
| ADM-08 | Admin policy relies on `MicrosoftAdminPortals` (ADM-03 condition). Status `unverified`, severity `info`. Explains Defender/Purview/Teams/SharePoint/Power Platform admin mappings are not confirmed. |

- [ ] **Step 1: Write failing tests** using `adminPhish()` as the satisfied ADM-01 fixture and a policy targeting only `MicrosoftAdminPortals` for ADM-03.

- [ ] **Step 2: Run — Expected: FAIL.**

- [ ] **Step 3: Implement `admin.ts`.**

- [ ] **Step 4: Run — Expected: PASS.**

- [ ] **Step 5: Commit** `feat: add admin Conditional Access gap rules`

---

### Task 9: App coverage rules (APP-01 … APP-08)

**Files:**
- Create: `src/engine/rules/apps.ts`, `src/engine/rules/apps.test.ts`

**Interfaces:**
- Consumes: predicates, `APP`, `getApp`, `isTargetable`
- Produces: `export const appRules: Rule[]`

| ID | Detection |
|---|---|
| APP-01 | Any enforced policy with `includeApplications` containing `All` and non-empty `excludeApplications`. List excluded IDs/names. Mention Baseline scopes setting `https://aka.ms/BaselineScopesSettingsUX`. |
| APP-02 | Intersection of `excludeApplications` with high-value set: `Office365`, `MicrosoftAdminPortals`, Exchange, SharePoint, Teams Services, Azure management, Azure portal, Intune, RMS, and Device Registration Service **unless** the policy has `hasDeviceCodeFlow`. Severity high. |
| APP-03 | Policy `requiresManagedDevice` and excludes Intune Enrollment, Web Company Portal, or Intune, **unless** `grantControls.termsOfUse` is non-empty (ToU must exclude enrollment). Severity low. |
| APP-04 | `includeApplications` is exactly Exchange, or exactly SharePoint, or exactly Teams Services (not the Office365 group). Severity low. SharePoint-only explanation must mention Teams dependency. |
| APP-05 | include or exclude contains a non-targetable public client (`isTargetable === false` and id is a GUID). |
| APP-06 | No enforced policy for all-users (or for admins, emit per population in explanation) uses `All` without excluding Graph-related apps. Graph cannot be targeted. |
| APP-07 | No enforced `allUsers` policy whose include is `All` (not excluding `APP.azureManagement`) **or** include contains `APP.azureManagement`, requiring MFA. Sub-note if Azure DevOps is not covered by `All` or explicit include. |
| APP-08 | Policy include is only `Office365` and users include privileged roles. Severity info. Office365 is not admin coverage. |

- [ ] **Step 1: Write failing tests** for each ID.

- [ ] **Step 2: Run — Expected: FAIL.**

- [ ] **Step 3: Implement `apps.ts`.**

- [ ] **Step 4: Run — Expected: PASS.**

- [ ] **Step 5: Commit** `feat: add Microsoft app-coverage gap rules`

---

### Task 10: Weakening rules (WEK-01 … WEK-12)

**Files:**
- Create: `src/engine/rules/weakening.ts`, `src/engine/rules/weakening.test.ts`

**Interfaces:**
- Produces: `export const weakeningRules: Rule[]`

| ID | Detection |
|---|---|
| WEK-01 | Enforced policy that would satisfy BAS-01, BAS-03, or ADM-01 except `exclusionsOnlyBreakGlass` is false: extra `excludeUsers`, any `excludeGroups` not in `breakGlass`, any `excludeRoles`, or `excludeGuestsOrExternalUsers`. Severity Critical if the policy is a BAS-01/BAS-03/ADM-01 candidate; otherwise High. |
| WEK-02 | Configured `tenant.breakGlass` IDs are not all present in `excludeUsers ∪ excludeGroups` of every enforced `allUsers` policy that `isBlock` or `requiresMfa`. Skip risk-based and legacy-only policies. |
| WEK-03 | `excludeRoles` intersects `PRIVILEGED_ROLE_IDS`. |
| WEK-04 | MFA baseline candidate has `excludeLocations` containing `AllTrusted` or any named location, or `includeLocations` not `All`/empty. |
| WEK-05 | `operator === "OR"` and alternatives mix MFA-equivalent with `compliantDevice` / `domainJoinedDevice` / `compliantApplication` / `approvedApplication` / `termsOfUse`. High for admin or all-user+all-resource scope; else Medium. Exception: only those three (compliant OR hybrid OR mfa) is Medium even for all users. |
| WEK-06 | Non-block enforced policy with `platforms.excludePlatforms` non-empty that `requiresMfa` or `requiresManagedDevice`. |
| WEK-07 | `deviceFilter.mode === "include"` and `rule` matches `/-eq\|-startsWith\|-in\|-contains/` without a `-ne`/`-notContains` on the same clause. Policy is protective (has grants). |
| WEK-08 | `persistentBrowser.mode === "always"` and (no device filter that restricts to compliant/hybrid, **or** policy does not `allResources`). |
| WEK-09 | `approvedApplication` in `builtInControls`. High if it is the only control; else Medium. Explanation notes the Learn vs Message Center discrepancy (may still enforce or may not after 2026-06-30). |
| WEK-10 | `customAuthenticationFactors` non-empty. |
| WEK-11 | `sessionControls.disableResilienceDefaults === true` on `allUsers ∧ allResources`. |
| WEK-12 | `sessionControls.continuousAccessEvaluation.mode === "disabled"`. |

- [ ] **Step 1: Write failing tests** (gap + clean) for each ID.

- [ ] **Step 2: Run — Expected: FAIL.**

- [ ] **Step 3: Implement `weakening.ts`.**

- [ ] **Step 4: Run — Expected: PASS.**

- [ ] **Step 5: Commit** `feat: add CA policy weakening-pattern rules`

---

### Task 11: Risk and identity rules (RSK-01 … RSK-06)

**Files:**
- Create: `src/engine/rules/risk.ts`, `src/engine/rules/risk.test.ts`

**Interfaces:**
- Produces: `export const riskRules: Rule[]`

Do **not** add an agent-license checkbox (not in `TenantProfile`). RSK-06 always emits an `info` finding reminding that "All users" does not cover agent users.

| ID | License | Detection |
|---|---|---|
| RSK-01 | entraP2 | No enforced `allUsers ∧ allResources` with `signInRiskLevels` containing `high` and (`isBlock` or `requiresMfa`) |
| RSK-02 | entraP2 | No enforced `allUsers ∧ allResources` with `userRiskLevels` containing `high` and (`isBlock` or (`passwordChange` AND `mfa`) or (`riskRemediation` AND authenticationStrength)) |
| RSK-03 | workloadIdPremium | No enforced policy with `clientApplications.includeServicePrincipals` containing `ServicePrincipalsInMyTenant` or any ID, with location-restricted block or `servicePrincipalRiskLevels` containing `high` |
| RSK-04 | entraP2 + purviewInsiderRisk | No enforced policy with `insiderRiskLevels` containing `elevated` and `isBlock` |
| RSK-05 | entraP1 (always present in DEFAULT_TENANT) | No enforced admin policy with `sessionControls.secureSignInSession.isEnabled === true`. Severity low. |
| RSK-06 | none | Always emit info: agent users are not covered by All users; if Agent ID is in use, add policies for `AllAgentIdUsers` / `AllAgentIdResources`. |

When `licenseStatus` is `requiresLicense`, emit the finding with that status and do not deduct score later.

- [ ] **Step 1: Write failing tests**, including P2-off → RSK-01 `requiresLicense`.

- [ ] **Step 2: Run — Expected: FAIL.**

- [ ] **Step 3: Implement `risk.ts`.**

- [ ] **Step 4: Run — Expected: PASS.**

- [ ] **Step 5: Commit** `feat: add risk and workload-identity CA rules`

---

### Task 12: Hygiene rules (HYG-02, HYG-03)

**Files:**
- Create: `src/engine/rules/hygiene.ts`, `src/engine/rules/hygiene.test.ts`

**Interfaces:**
- Produces: `export const hygieneRules: Rule[]` with IDs `HYG-02` and `HYG-03` only (HYG-01 is partial-status on other rules).

| ID | Detection |
|---|---|
| HYG-02 | Any `state === "disabled"`. Severity Medium if `displayName` starts with `Microsoft-managed:` (case-insensitive); else Low. |
| HYG-03 | `grantControls` null/empty-controls AND all session controls null/disabled; OR `includeUsers` is `["None"]` with no groups/roles/guests/SPs; OR `includeApplications` is `["None"]` with no user actions/auth contexts. |

- [ ] **Step 1: Write failing tests.**

- [ ] **Step 2: Run — Expected: FAIL.**

- [ ] **Step 3: Implement `hygiene.ts`.**

- [ ] **Step 4: Run — Expected: PASS.**

- [ ] **Step 5: Commit** `feat: add CA policy hygiene rules`

---

### Task 13: Coverage matrix

**Files:**
- Create: `src/engine/matrix.ts`, `src/engine/matrix.test.ts`

**Interfaces:**
- Consumes: predicates, catalog `appsForSurface` / `getApp`
- Produces:

```ts
export const SURFACES: Surface[]
export const CONTROLS: Control[]
export function buildMatrix(policies: CAPolicy[], tenant: TenantProfile, population: Population): CoverageMatrix
export function buildAllMatrices(policies: CAPolicy[], tenant: TenantProfile): CoverageMatrix[]
```

`SURFACES` order: `allResources`, `office365`, `adminPortals`, `azureManagement`, `microsoftGraph`, `intuneApis`, `azureDevOps`, `thirdParty`, `registerSecurityInfo`, `registerDevice`.

`CONTROLS` order: `legacyAuthBlocked`, `mfa`, `phishingResistantMfa`, `managedDevice`, `deviceCodeBlocked`, `signInRisk`, `userRisk`, `sessionControls`.

Population matching:

- `allUsers`: `allUsers(p)`
- `admins`: `allUsers(p) || includesAnyPrivilegedRole(p)`
- `guests`: `allUsers(p) && !excludesGuests(p) || coversGuests(p)`

Surface matching:

- `allResources`: `allResources(p) && noAppExclusions(p)` (exclusions → do not count as covering the All row; specific rows still covered if their apps were not excluded)
- `office365`: All without excluding `Office365`/Exchange/SharePoint/Teams, **or** include `Office365` or those app IDs
- `adminPortals`: All without excluding `MicrosoftAdminPortals`/its four IDs, **or** include the group or those IDs
- `azureManagement`: All without excluding `APP.azureManagement`, **or** include that ID
- `microsoftGraph`: **only** All (Graph is not targetable). Excluding Azure AD Graph still counts as covering (do not require that)
- `intuneApis`: All without excluding Intune, **or** include `APP.intune`
- `azureDevOps`: All without excluding DevOps, **or** include `APP.azureDevOps` (Azure management include does **not** cover this row)
- `thirdParty`: only All
- `registerSecurityInfo` / `registerDevice`: matching user action

Control matching on a policy that already matches population + surface:

- `legacyAuthBlocked`: `coversLegacy && isBlock`
- `mfa`: `requiresMfa`
- `phishingResistantMfa`: `requiresPhishingResistant`
- `managedDevice`: `requiresManagedDevice`
- `deviceCodeBlocked`: `hasDeviceCodeFlow && isBlock`
- `signInRisk`: `signInRiskLevels` includes `high` and (block or MFA)
- `userRisk`: `userRiskLevels` includes `high` and (block or passwordChange+mfa or riskRemediation)
- `sessionControls`: `signInFrequency.isEnabled` or `persistentBrowser` enabled

Cell state:

- `na` for (`registerDevice` or `registerSecurityInfo`) × (`legacyAuthBlocked`, `managedDevice`, `deviceCodeBlocked`, `signInRisk`, `userRisk`) — user actions only support MFA/auth strength (and security-info also supports managed device: so `registerSecurityInfo` × `managedDevice` is **not** `na`)
- `na` for `registerDevice` × `managedDevice`
- `requiresLicense` for `signInRisk`/`userRisk` when `!entraP2`; for `managedDevice` when `!intune`
- else if any matching enforced policy has the control and is not OR-weakened and is unconditioned → `covered`
- else if only report-only, OR-weakened, or conditioned match → `partial`
- else `gap`

- [ ] **Step 1: Write tests:**

```ts
it("marks Graph MFA covered when an all-users all-resources MFA policy exists", () => {
  const matrix = buildMatrix([mfaAll()], bgTenant(), "allUsers");
  const cell = matrix.cells.find((c) => c.surface === "microsoftGraph" && c.control === "mfa")!;
  expect(cell.state).toBe("covered");
});
it("does not treat Azure management MFA as covering Azure DevOps", () => {
  const p = policy({
    conditions: { applications: { includeApplications: [APP.azureManagement], excludeApplications: [], includeUserActions: [], includeAuthenticationContextClassReferences: [] } },
    grantControls: { operator: "OR", builtInControls: ["mfa"] },
  });
  const matrix = buildMatrix([p], bgTenant(), "allUsers");
  expect(matrix.cells.find((c) => c.surface === "azureDevOps" && c.control === "mfa")!.state).toBe("gap");
  expect(matrix.cells.find((c) => c.surface === "azureManagement" && c.control === "mfa")!.state).toBe("covered");
});
it("marks sign-in risk requiresLicense when P2 is off", () => {
  const matrix = buildMatrix([], bgTenant(), "allUsers");
  expect(matrix.cells.find((c) => c.control === "signInRisk" && c.surface === "allResources")!.state).toBe("requiresLicense");
});
```

- [ ] **Step 2: Run — Expected: FAIL.**

- [ ] **Step 3: Implement `matrix.ts`.**

- [ ] **Step 4: Run — Expected: PASS.**

- [ ] **Step 5: Commit** `feat: build CA coverage heat-map matrix`

---

### Task 14: `analyze()`, scoring, manual checks

**Files:**
- Create: `src/engine/manualChecks.ts`, `src/engine/analyze.ts`, `src/engine/analyze.test.ts`, `src/engine/index.ts`

**Interfaces:**
- Consumes: all `*Rules` arrays, `buildAllMatrices`, `Finding`
- Produces:

```ts
export function analyze(policies: CAPolicy[], tenant: TenantProfile): AnalysisResult
export function scoreFindings(findings: Finding[]): number
export function buildManualChecks(policies: CAPolicy[], tenant: TenantProfile, findings: Finding[]): ManualCheck[]
```

`scoreFindings`: start at 100; for each finding with `status === "gap"` subtract 15/8/4/1 by severity (info = 0); `status === "partial"` subtract half (rounded down); skip `requiresLicense` and `unverified`; floor at 0.

Manual checks always include these IDs (filter related policies when present):

| id | title | whereToLook |
|---|---|---|
| MAN-01 | Confirm included/excluded groups are not empty and exclusion groups are small | Entra admin center → Groups → Members (transitive). Related CA-029. |
| MAN-02 | Confirm PIM-eligible admins are covered | Entra ID → PIM → Roles → Eligible assignments. Related ADM-05. |
| MAN-03 | Confirm targeted app IDs exist as service principals | Entra ID → Enterprise applications. Intune Enrollment is often missing in new tenants. |
| MAN-04 | Confirm groups used in CA do not contain service principals | Group membership; CA does not apply to SPs via groups. |
| MAN-05 | Verify Baseline scopes enforcement is not opted out | `https://aka.ms/BaselineScopesSettingsUX` |
| MAN-06 | Set "Require MFA to register or join devices" to No if using a CA user-action policy | Entra ID → Devices → Device settings |
| MAN-07 | Check legacy MFA trusted IPs are not feeding All trusted locations | Entra ID → Security → MFA → Additional cloud-based MFA settings |
| MAN-08 | Confirm Security defaults are off if using CA | Entra ID → Properties → Manage security defaults |
| MAN-09 | Confirm authentication contexts in policies are published and used | Entra ID → Conditional Access → Authentication context |
| MAN-10 | Azure Government tenants must target Azure Government Cloud Management API | Azure Government documentation |

- [ ] **Step 1: Write tests:** empty policies + default tenant → score < 100, BAS-01 and BAS-03 present as gaps, three matrices, ten manual checks. `scoreFindings` of one critical gap is 85. Known predicates: two critical + one high partial = `100 - 15 - 15 - 4 = 66`.

- [ ] **Step 2: Run — Expected: FAIL.**

- [ ] **Step 3: Implement analyze, scoring, manual checks, and `src/engine/index.ts` re-exports `analyze`, types, catalogs as needed by the UI.

- [ ] **Step 4: Run — Expected: PASS. Also `npx vitest run` for the full engine suite.**

- [ ] **Step 5: Commit** `feat: orchestrate CA gap analysis, scoring, and manual checks`

---

### Task 15: Sample tenants

**Files:**
- Create: `src/samples/knownGood.ts`, `src/samples/weak.ts`, `src/samples/samples.test.ts`

**Interfaces:**
- Consumes: `analyze`, `policy()` helpers, `PRIVILEGED_ROLE_IDS`, `APP`, `AUTH_STRENGTH`, `USER_ACTION`
- Produces: `KNOWN_GOOD_POLICIES: CAPolicy[]`, `KNOWN_GOOD_TENANT: TenantProfile`, `WEAK_POLICIES`, `WEAK_TENANT`

`KNOWN_GOOD_TENANT`: all licenses true; `breakGlass: ["bg-user-1"]`.

`KNOWN_GOOD_POLICIES` (all `enabled`, exclude `bg-user-1` on user-scoped policies):

1. Block legacy — `clientAppTypes: ["exchangeActiveSync","other"]`, block, All/All
2. MFA all users All resources, `builtInControls: ["mfa"]`
3. Block device code flow
4. Block unknown platforms (`includePlatforms: ["all"]`, `excludePlatforms: ["android","iOS","windows","macOS","linux"]` wait — the template excludes nothing from `all` then blocks excluded? Microsoft template: include `all`, exclude the known platforms, block. Use exclude `["android","iOS","windows","windowsPhone","macOS","linux"]`)
5. Guest MFA — `includeGuestsOrExternalUsers` with all six types, `membershipKind: "all"`
6. Register security info — MFA
7. Register device — MFA
8. Compliant device all users All — `operator: "OR"`, `builtInControls: ["compliantDevice","domainJoinedDevice"]` (this is AND-equivalent among only device controls → managed device met, not OR-weakened MFA)
9. Unmanaged SIF: device filter include mode with rule `device.trustType -ne "ServerAD" -or device.isCompliant -ne True`, SIF 1 hour, persistent never
10. Admin phishing-resistant All resources, all 14 roles, SIF 4h, persistent never
11. Admin compliant device
12. Sign-in risk high → MFA
13. User risk high → passwordChange AND mfa
14. Workload identities: `includeServicePrincipals: ["ServicePrincipalsInMyTenant"]`, locations All exclude AllTrusted, block
15. Insider risk elevated → block

`WEAK_POLICIES`:

1. Report-only MFA for a group (not All)
2. Enabled MFA targeting only `MicrosoftAdminPortals` for Global Admin role only
3. Enabled policy targeting Graph PowerShell client ID with MFA
4. Disabled `Microsoft-managed: Block legacy authentication`

`WEAK_TENANT`: P1 only, empty breakGlass.

- [ ] **Step 1: Write tests:**

```ts
it("known-good has no critical or high gap findings", () => {
  const result = analyze(KNOWN_GOOD_POLICIES, KNOWN_GOOD_TENANT);
  const bad = result.findings.filter((f) => f.status === "gap" && (f.severity === "critical" || f.severity === "high"));
  expect(bad).toEqual([]);
});
it("weak tenant produces BAS-01, BAS-03, ADM-01, ADM-03, APP-05, HYG-02", () => {
  const ids = analyze(WEAK_POLICIES, WEAK_TENANT).findings.filter((f) => f.status === "gap" || f.status === "partial").map((f) => f.ruleId);
  expect(ids).toEqual(expect.arrayContaining(["BAS-01", "BAS-03", "ADM-01", "ADM-03", "APP-05", "HYG-02"]));
});
```

If known-good still flags a high/critical rule, **fix the sample policies** until the test passes. Do not weaken the rule.

- [ ] **Step 2: Run — Expected: FAIL.**

- [ ] **Step 3: Implement sample policy objects (full Graph-shaped `CAPolicy` literals, not stubs).**

- [ ] **Step 4: Run — Expected: PASS.**

- [ ] **Step 5: Commit** `feat: add known-good and weak sample tenants`

---

### Task 16: Persistence

**Files:**
- Create: `src/ui/state.ts`, `src/ui/state.test.ts`

**Interfaces:**
- Consumes: `CAPolicy`, `TenantProfile`, `DEFAULT_TENANT`
- Produces:

```ts
export type Step = "tenant" | "policies" | "analysis" | "export";
export interface AppState {
  step: Step;
  tenant: TenantProfile;
  policies: CAPolicy[];
}
export const INITIAL_STATE: AppState
export function loadState(): AppState
export function saveState(state: AppState): void
export function clearState(): void
```

`localStorage` key: `ca-gap-evaluator:v1`. `loadState` returns `INITIAL_STATE` on missing/invalid JSON. `clearState` removes the key.

- [ ] **Step 1: Write tests using a mock:

```ts
const store = new Map<string, string>();
vi.stubGlobal("localStorage", {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => { store.set(k, v); },
  removeItem: (k: string) => { store.delete(k); },
});
```

Assert round-trip of a policy and that corrupt JSON falls back to `INITIAL_STATE`.

- [ ] **Step 2: Run — Expected: FAIL.**

- [ ] **Step 3: Implement `state.ts`.**

- [ ] **Step 4: Run — Expected: PASS.**

- [ ] **Step 5: Commit** `feat: persist evaluator state in localStorage`

---

### Task 17: App shell and stepper

**Files:**
- Create: `src/ui/AppShell.tsx`, `src/ui/AppShell.test.tsx`
- Modify: `src/App.tsx`

**Interfaces:**
- Consumes: `AppState`, `saveState`, `loadState`, `clearState`
- Produces: four-step header (Tenant, Policies, Analysis, Export), Next/Back, Clear all data (confirm via `window.confirm`)

- [ ] **Step 1: Write a jsdom test that Tenant setup is the first heading and Next moves to Policies.

```tsx
// @vitest-environment jsdom
```

Stub child views with simple headings if they do not exist yet: render `AppShell` with slot props:

```tsx
export function AppShell(props: {
  state: AppState;
  onChange: (s: AppState) => void;
  children: React.ReactNode;
})
```

Easier: `App.tsx` holds state and renders step components. For this task, placeholder step panels:

```tsx
{state.step === "tenant" && <section><h2>Tenant setup</h2></section>}
```

- [ ] **Step 2: Run `npx vitest run src/ui/AppShell.test.tsx` — FAIL.**

- [ ] **Step 3: Implement AppShell + wire App.tsx to load/save on change.**

- [ ] **Step 4: Run tests + `npm run build` — Expected: PASS.**

- [ ] **Step 5: Commit** `feat: add four-step app shell`

---

### Task 18: Tenant setup UI

**Files:**
- Create: `src/ui/TenantSetup.tsx`, `src/ui/TenantSetup.test.tsx`
- Modify: `src/App.tsx` to render it on the tenant step

**Interfaces:**
- Consumes: `TenantProfile`
- Produces: checkboxes for each license key with labels "Entra ID P1", "Entra ID P2", "Intune", "Workload Identities Premium", "Defender for Cloud Apps", "Purview Insider Risk"; textarea for break-glass (one ID/UPN per line); optional display-name pairs (GUID, name) as a small list editor

- [ ] **Step 1: jsdom tests — toggling P2 updates `licenses.entraP2`; typing an ID into break-glass and blurring/saving calls `onChange` with that ID.**

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement the form. Use `<label>` + `<input type="checkbox">` so tests can `getByLabelText`.**

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Commit** `feat: add tenant license and break-glass setup`

---

### Task 19: Policy list and JSON import

**Files:**
- Create: `src/ui/PolicyList.tsx`, `src/ui/PolicyImport.tsx`, `src/ui/PolicyList.test.tsx`
- Modify: `src/App.tsx`

**Interfaces:**
- Consumes: `importPolicies`, `KNOWN_GOOD_POLICIES`, `WEAK_POLICIES`, `CAPolicy`
- Produces: card list showing `displayName`, state badge (On / Report-only / Off), delete; buttons "Add policy", "Import JSON", "Load sample: known-good", "Load sample: weak". Import accepts file input **and** a paste `<textarea>`. Failed entries show `errors` inline; successful import appends (does not replace) unless the user checks "Replace existing policies".

- [ ] **Step 1: Tests — render two policies; Import paste of `blockLegacy` JSON adds a card; Load sample known-good replaces the list with `KNOWN_GOOD_POLICIES.length` cards.**

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement list + import. "Add policy" should call `onAdd` with a blank enabled policy:

```ts
{
  id: crypto.randomUUID(),
  displayName: "New policy",
  state: "enabled",
  conditions: {
    users: { includeUsers: ["All"], excludeUsers: [], includeGroups: [], excludeGroups: [], includeRoles: [], excludeRoles: [] },
    applications: { includeApplications: ["All"], excludeApplications: [], includeUserActions: [], includeAuthenticationContextClassReferences: [] },
    clientAppTypes: ["all"],
  },
  grantControls: { operator: "OR", builtInControls: ["mfa"] },
}
```

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Commit** `feat: add policy list, JSON import, and sample tenants`

---

### Task 20: Policy wizard

**Files:**
- Create: `src/ui/PolicyWizard.tsx`, `src/ui/PolicyWizard.test.tsx`
- Modify: `src/ui/PolicyList.tsx` to open the wizard on Add/Edit

**Interfaces:**
- Consumes: `CAPolicy`, `APP_CATALOG`, `PRIVILEGED_ROLES`
- Produces: a modal or full-page editor with sections Users, Target resources, Network, Conditions, Grant, Session. Saving calls `onSave(policy)`.

Users: radio All / None / selected (textarea of IDs); checkboxes for the 14 privileged roles (toggles `includeRoles`); break-glass-style exclude textarea; guest include toggle that sets all six types + `membershipKind: "all"`.

Target resources: radio All / Microsoft Admin Portals / Office 365 / selected apps. Selected apps: searchable list from `APP_CATALOG` showing name, appId, groups, and a warning if `!targetable` ("This is a client app and cannot be targeted") or if appId is Microsoft Graph ("Microsoft Graph can only be covered via All resources"). User actions checkboxes for the two URNs. Exclude apps multi-select.

Network: unset / All locations / All trusted excluded.

Conditions: client app types checkboxes (default all); platforms; sign-in risk / user risk multi-select; authentication flows (device code, authentication transfer); device filter mode + rule text.

Grant: operator AND/OR; built-in control checkboxes; auth strength select (none / MFA / passwordless / phishing-resistant); block exclusive with grants (selecting block clears others).

Session: SIF enabled + hours value; persistent browser never/always/off; disable resilience; CAE disabled checkbox; token protection checkbox.

State: select On / Report-only / Off.

- [ ] **Step 1: Tests — changing display name and selecting phishing-resistant strength, then Save, yields `authenticationStrength.id === AUTH_STRENGTH.phishingResistantMfa`. Checking Register security info adds the URN to `includeUserActions`.**

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement the wizard as controlled inputs writing into a cloned `CAPolicy`.**

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Commit** `feat: add Conditional Access policy editor wizard`

---

### Task 21: Analysis heat map and findings

**Files:**
- Create: `src/ui/AnalysisView.tsx`, `src/ui/HeatMap.tsx`, `src/ui/FindingsList.tsx`, `src/ui/HeatMap.test.tsx`, `src/ui/FindingsList.test.tsx`
- Modify: `src/App.tsx`

**Interfaces:**
- Consumes: `analyze`, `CoverageMatrix`, `Finding`, `ManualCheck`
- Produces: score, population tabs (All users / Admins / Guests), heat map table, filterable findings, manual checklist

Heat map: `<table>` with row headers = human labels (All resources, Office 365, Admin portal sign-ins, Azure management, Microsoft Graph, Intune APIs, Azure DevOps, Third-party & custom, Register security info, Register or join devices). Column headers = Legacy auth blocked, MFA, Phishing-resistant MFA, Managed device, Device code blocked, Sign-in risk, User risk, Session. Cells use `data-state={cell.state}` and background:

- covered: `#0b6a0b`
- partial: `#c47b00`
- gap: `#a4262c`
- requiresLicense: repeating-linear-gradient hatch `#9aa0a6`
- na: `#f4f6f8`

Clicking a cell sets selected cell state and lists contributing `policyIds` (resolved via `displayName`) and `findingIds`.

Findings list: filter by severity, family, policy. Each row: severity badge, ruleId, title, status, affected policies, remediation, Learn link.

Manual checklist below as an ordered list.

- [ ] **Step 1: Tests with `WEAK_POLICIES`:** heat map has a `data-state="gap"` cell; findings list contains `BAS-03`; changing population tab to Admins still renders a table.

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement the three components. Call `analyze` in `AnalysisView` (memoize on policies + tenant).**

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Commit** `feat: add coverage heat map and findings list`

---

### Task 22: Export HTML, CSV, JSON

**Files:**
- Create: `src/report/csv.ts`, `src/report/json.ts`, `src/report/html.ts`, `src/report/csv.test.ts`, `src/report/html.test.ts`, `src/ui/ExportView.tsx`
- Modify: `src/App.tsx`

**Interfaces:**
- Consumes: `AnalysisResult`, `CAPolicy[]`, `TenantProfile`, `CATALOG_DATE`
- Produces:

```ts
export function findingsToCsv(findings: Finding[], policies: CAPolicy[]): string
export function policiesToJson(policies: CAPolicy[]): string
export function buildHtmlReport(input: {
  tenant: TenantProfile;
  policies: CAPolicy[];
  result: AnalysisResult;
}): string
```

CSV header: `ruleId,severity,status,title,policies,remediation,requiredLicense,reference`

Escape fields with quotes when they contain commas/quotes/newlines. `policies` column is display names joined by `; `. `reference` is the first URL.

JSON export: `JSON.stringify({ policies }, null, 2)` where policies are the stored objects (re-importable by `importPolicies`).

HTML report: a complete HTML document with inline CSS (no external stylesheets, no scripts). Sections: title "CA Gap Evaluator report", catalog date, score, license summary, heat map table (All users matrix), findings table, manual checklist. Print CSS via `@media print`. Reference links may be absolute `https://learn.microsoft.com/...` (allowed). No CDN URLs.

`ExportView`: three buttons that download via `Blob` + object URL: `ca-gap-report.html`, `ca-gap-findings.csv`, `ca-gap-policies.json`.

- [ ] **Step 1: Tests:**

```ts
it("escapes commas in remediation", () => {
  const csv = findingsToCsv([{
    ruleId: "BAS-01", title: "t", family: "baseline", severity: "critical", status: "gap",
    policyIds: ["p1"], explanation: "", remediation: "Do this, then that", references: ["https://learn.microsoft.com/x"],
  }], [{ id: "p1", displayName: "Block, legacy", /* minimal CAPolicy */ } as CAPolicy]);
  expect(csv).toContain('"Do this, then that"');
  expect(csv).toContain('"Block, legacy"');
});
it("HTML report is self-contained", () => {
  const html = buildHtmlReport({ tenant: DEFAULT_TENANT, policies: [], result: analyze([], DEFAULT_TENANT) });
  expect(html.startsWith("<!DOCTYPE html>")).toBe(true);
  expect(html).not.toMatch(/https?:\/\/cdn\./);
  expect(html).toContain("CA Gap Evaluator report");
  expect(html).toContain(CATALOG_DATE);
});
```

- [ ] **Step 2: Run — FAIL.**

- [ ] **Step 3: Implement builders and ExportView.**

- [ ] **Step 4: Run — PASS.**

- [ ] **Step 5: Commit** `feat: export HTML report, findings CSV, and policy JSON`

---

### Task 23: README and end-to-end polish

**Files:**
- Create: `README.md`
- Modify: `src/index.css` (spacing, badges, focus rings), `src/App.tsx` if needed

**Interfaces:** none new.

README contents:

- What the app is (offline CA gap evaluator)
- `npm install`, `npm run dev`, `npm test`
- How to import Graph JSON (`GET https://graph.microsoft.com/beta/identity/conditionalAccess/policies`)
- How to read the heat map colors
- Catalog date and pointer to `docs/research/`
- Limitation: no live tenant, manual checklist for directory data

- [ ] **Step 1: Run the full suite** `npm test` — Expected: PASS.

- [ ] **Step 2: Run `npm run build` — Expected: PASS with no TS errors.**

- [ ] **Step 3: Write README.md as specified.**

- [ ] **Step 4: Manual browser check** (`npm run dev`): load weak sample → Analysis shows red cells and BAS-03 → Export downloads three files. Load known-good → no critical/high gaps. Import a pasted Graph `{value:[...]}` policy.

- [ ] **Step 5: Commit** `docs: add README and polish evaluator UI`

---

## Self-review

**Spec coverage**

| Spec section | Task |
|---|---|
| Browser-only React/TS/Vite | 1 |
| Graph-shaped model, import shapes, normalization | 2, 3 |
| Tenant profile + licenses | 2, 18 |
| App catalog by ID, Admin Portals / Graph / Intune / DevOps facts | 4 |
| Evaluation semantics / predicates | 5 |
| Finding shape, license gating, HYG-01 as partial | 6 |
| BAS / ADM / APP / WEK / RSK / HYG rules | 7–12 |
| Manual checklist | 14 |
| Heat map rows/cols/states/population | 13, 21 |
| Score weights | 14 |
| Four-step UI, localStorage, clear | 16–21 |
| HTML + CSV + JSON export | 22 |
| Known-good / weak samples + tests | 15 |
| Vitest per rule | 7–12 |
| README / catalog date on report | 22, 23 |

**Placeholders:** none remaining. Rule evaluate bodies are specified as detection tables the implementer codes against predicates from Task 5.

**Type consistency:** `analyze(policies, tenant): AnalysisResult` with `matrices: CoverageMatrix[]` (one per population). `Finding.status` includes `unverified`. `Rule` lives in `src/engine/rules/types.ts`. IDs `BAS-01`…`HYG-03` match the spec. `HYG-01` is intentionally not a separate finding ID.
