# CA Gap Evaluator — Design Spec

Date: 2026-10-26
Status: Approved design, pending spec review

## 1. Purpose

A browser-only web application that takes a tenant's Microsoft Entra ID Conditional Access (CA) policy configuration (entered manually or imported as JSON), analyzes it for coverage gaps across all Microsoft first-party applications and identity types, visualizes coverage as a heat map, and exports a workable report.

Research backing every rule lives in:

- `docs/research/ca-target-resources.md` — app groups, app IDs, target-resource behavior.
- `docs/research/ca-evaluation-and-gaps.md` — evaluation semantics, Graph schema, licensing, gap rule catalog.

Rules cite those documents and Microsoft Learn. Anything marked UNVERIFIED or DISCREPANCY there is surfaced in the app as lower confidence, never as a confirmed gap.

## 2. Non-goals

- No live Microsoft Graph connection, no sign-in, no backend. (May be added later on top of the same model.)
- No policy deployment or modification of the tenant.
- No sign-in log / What If simulation of individual sign-ins.

## 3. Architecture

Single-page app: **React + TypeScript + Vite**, tests with **Vitest**. All data stays in the browser (`localStorage`); no network calls at runtime.

```
src/
  model/        Graph-shaped types, normalization, validation
  catalog/      Microsoft app catalog, app groups, privileged roles, auth strengths
  engine/       predicates, rules (one file per family), coverage matrix, analyze()
  report/       HTML report, CSV, JSON export builders
  ui/           steps: TenantSetup, Policies (list + wizard + import), Analysis, Export
  samples/      sample tenants (known-good, deliberately weak)
```

The engine has no UI dependencies. Interface:

```ts
analyze(policies: CAPolicy[], tenant: TenantProfile): AnalysisResult
// AnalysisResult = { findings: Finding[]; matrix: CoverageMatrix; manualChecks: ManualCheck[]; score: number }
```

### 3.1 Policy model

Internal representation **is** the Microsoft Graph `conditionalAccessPolicy` shape (beta superset). Import, manual form, and export all operate on it.

- Import accepts: one policy object, an array of policies, or a Graph response wrapper `{ "value": [...] }`.
- Normalization: comma-separated string fields (`guestOrExternalUserTypes`, `authenticationFlows.transferMethods`, `insiderRiskLevels`) become arrays; `null`/missing conditions become explicit "unconfigured" (applies to everything); app IDs lower-cased.
- Unknown properties are preserved and listed as informational notes.
- Per-policy validation errors (malformed or missing `conditions`) are reported for that policy; other policies still import.

### 3.2 Tenant profile

```ts
TenantProfile = {
  licenses: { entraP1, entraP2, intune, workloadIdPremium, defenderForCloudApps, purviewInsiderRisk: boolean }
  breakGlass: string[]               // object IDs or UPNs
  displayNames: Record<string,string> // optional GUID -> friendly name for groups/users/roles
}
```

### 3.3 App catalog

Data file keyed by **app ID** (never display name — names such as Azure management have changed several times). Each entry: `appId`, `name`, aliases, `surface` (heat-map row), group memberships (`Office365`, `MicrosoftAdminPortals`), `targetable` flag (public clients such as Graph PowerShell `14d82eec…`, Azure CLI `04b07795…`, Azure PowerShell `1950a258…` are not targetable), notes, confidence (`verified` / `unverified`), source URL.

Key facts encoded (from research):

- `MicrosoftAdminPortals` = Exchange Admin Center, Azure portal, Office 365 Portal, Protection Center (Feb 2026 definition). Intune admin center and Entra admin center front ends sign in via the Azure portal ID and are covered; their backend APIs (Microsoft Graph, Intune API `0000000a-…`, ARM) are not.
- Azure management `797f4846-ba00-4fd7-ba43-dac1f8f63013` covers ARM, Azure portal, CLI, PowerShell; not Graph; not Azure DevOps (`499b84ac-…`) since Sep 2025.
- Microsoft Graph cannot be targeted directly; only `All` resources covers it.
- Device Registration Service only via user action `urn:user:registerdevice`.

## 4. Rule engine

### 4.1 Evaluation semantics

- All applicable enforced policies must be satisfied; block wins; exclude beats include; assignments are ANDed.
- A requirement is **met** for a population/surface/control if at least one `enabled` policy applies (after subtracting exclusions, tolerating only break-glass) and requires the control.
- Same match from `enabledForReportingButNotEnforced` only → **partial (report-only)**.
- `OR` grants: effective strength is the weakest alternative.
- Conditions that narrow scope (locations, platforms, risk, device filter, client app types not covering all) make a baseline match **partial**, not met.

### 4.2 Finding shape

```ts
Finding = {
  ruleId, title, family, severity: 'critical'|'high'|'medium'|'low'|'info',
  status: 'gap'|'partial'|'requiresLicense'|'unverified',
  policyIds: string[], explanation, remediation, references: string[], requiredLicense?: string
}
```

If a rule's remediation needs a license the tenant lacks, `status = 'requiresLicense'` and severity is shown but not counted in the score.

### 4.3 Rule catalog

IDs map to the research catalogs (CA-xxx from evaluation research; named rules from target-resource research).

**Baseline coverage**

| ID | Rule | Severity |
|---|---|---|
| BAS-01 | Legacy authentication not blocked for all users / all resources (CA-001) | Critical |
| BAS-02 | Legacy block omits Exchange ActiveSync (CA-002) | High |
| BAS-03 | No MFA baseline: all users, all resources, no app exclusions, all client types, unconditioned (CA-003, CA-035) | Critical |
| BAS-04 | Device code flow not blocked (CA-014) | High |
| BAS-05 | Authentication transfer not controlled (CA-015) | Low |
| BAS-06 | Unknown/unsupported device platforms not blocked (CA-019) | Medium |
| BAS-07 | Guests/external users not required to MFA (CA-011) | High |
| BAS-08 | Security info registration not protected (CA-021) | High |
| BAS-09 | Device registration/join not protected, or uses unsupported grants/conditions (CA-022, REGISTERDEVICE-MISCONFIG, DEVICE-REG-LOCATION-ASSUMPTION) | Medium |
| BAS-10 | No managed-device requirement for users (CA-012) | Medium |
| BAS-11 | No sign-in frequency / persistent-browser control for unmanaged devices (CA-024) | Medium |

**Admin protection**

| ID | Rule | Severity |
|---|---|---|
| ADM-01 | Privileged roles lack phishing-resistant auth strength on all resources; lists missing roles (CA-005) | Critical |
| ADM-02 | Privileged roles lack any MFA where no MFA baseline covers them (CA-006) | Critical |
| ADM-03 | Admin policy targets only Microsoft Admin Portals — Graph, Intune API, ARM, Exchange/Teams/SharePoint admin APIs uncovered (ADMIN-PORTALS-ONLY, INTUNE-ADMIN-GAP) | High |
| ADM-04 | Admin policy targets only Azure management — Graph tooling, M365 admin, Azure DevOps uncovered (AZURE-MGMT-ONLY) | High |
| ADM-05 | Admin policies scoped only by directory roles — PIM-eligible, custom, and AU-scoped roles missed (CA-007, ROLE-SCOPE) | High |
| ADM-06 | Admins not required to use a managed device (CA-013) | High |
| ADM-07 | Admins lack sign-in frequency (CA-026) | Low |
| ADM-08 | Admin portals relied on for Defender/Purview/Teams/SharePoint/Power Platform admin (mapping unverified) | Info |

**Microsoft app coverage**

| ID | Rule | Severity |
|---|---|---|
| APP-01 | All-resources policy has app exclusions; per-app risk; verify Baseline scopes setting (CA-004, ALL-WITH-EXCLUSIONS) | Medium |
| APP-02 | High-value app excluded (Office365, MicrosoftAdminPortals, Exchange, SharePoint, Teams, Azure management, Azure portal, Intune, Device Registration Service outside auth-flow policies, RMS) | High |
| APP-03 | Unnecessary Intune exclusions on compliant-device policies (except Intune Enrollment for Terms of Use) | Low |
| APP-04 | Single M365 workload targeted instead of Office365 (dependency leakage, SharePoint affects Teams) | Low |
| APP-05 | Policy targets a non-targetable public client ID (Graph PowerShell, Azure CLI, Azure PowerShell, Teams client, Auth Broker, Company Portal) | Medium |
| APP-06 | Microsoft Graph unprotected for a population (no `All` policy covering it) | High |
| APP-07 | Azure management not protected with MFA; Azure DevOps not covered (CA-023) | High |
| APP-08 | Office365 coverage assumed to cover admin surfaces | Info |

**Weakening patterns**

| ID | Rule | Severity |
|---|---|---|
| WEK-01 | Exclusions broader than break-glass on baseline policies; excluded guests (CA-008) | High (Critical on BAS-01/03, ADM-01 policies) |
| WEK-02 | Break-glass accounts not excluded from blocking/all-user policies — lockout risk (CA-009) | Medium |
| WEK-03 | Privileged roles excluded (CA-010) | High |
| WEK-04 | Trusted location exclusion bypasses MFA (CA-017) | High |
| WEK-05 | OR grant mixes MFA with weaker controls (CA-030) | High for admins/baseline, else Medium |
| WEK-06 | Platform exclusions relax MFA/device requirements — spoofable (CA-020) | Medium |
| WEK-07 | Include-mode device filter with positive operators on protective policy (CA-036) | Medium |
| WEK-08 | Persistent browser "always" on unmanaged scope, or on non-All-resources policy (CA-025) | Medium |
| WEK-09 | Retired "Require approved client app" in use (CA-031, discrepancy noted) | Medium (High if sole control) |
| WEK-10 | Custom controls used as MFA (CA-037) | Medium |
| WEK-11 | Resilience defaults disabled broadly (CA-039) | Low |
| WEK-12 | CAE disabled (CA-040) | Low |

**Risk and identity types** (license-gated)

| ID | Rule | License | Severity |
|---|---|---|---|
| RSK-01 | No sign-in risk policy (CA-016) | P2 | High |
| RSK-02 | High-risk users not blocked or remediated (CA-018) | P2 | High |
| RSK-03 | Workload identities unprotected (CA-032) | Workload ID Premium | Medium |
| RSK-04 | Insider risk not used (CA-038) | P2 + Purview IRM | Low |
| RSK-05 | No token protection for admins (CA-041) | P1 | Low |
| RSK-06 | Agent identities/users not covered; "All users" excludes agent users (CA-034) | Agent licensing | Info (preview) |

**Hygiene**

| ID | Rule | Severity |
|---|---|---|
| HYG-01 | Requirement met only by report-only policies (CA-027) | High |
| HYG-02 | Disabled policies; higher if Microsoft-managed (CA-028) | Low / Medium |
| HYG-03 | Policies with no effective controls or no assignees (CA-042) | Low |

### 4.4 Manual verification checklist

Items requiring directory data the tool cannot see. Emitted as `ManualCheck` with where to look:

- Group membership of included/excluded groups (empty groups, oversized exclusion groups) — CA-029.
- PIM eligible assignments for targeted roles — CA-007.
- Whether targeted app IDs exist as service principals (e.g. Intune Enrollment) — MISSING-SP.
- Groups containing service principals — CA-033.
- Baseline scopes enforcement opt-out setting (aka.ms/BaselineScopesSettingsUX) — APP-01.
- Device setting "Require MFA to register or join devices" must be No — BAS-09.
- Legacy MFA trusted IPs feeding "All trusted locations" — WEK-04.
- Security defaults state — CA-043.
- Unpublished/unused authentication contexts — ORPHAN-AUTH-CONTEXT.
- Azure Government tenants use a different management app.

## 5. Coverage heat map

Rows = resource surfaces, columns = control types, with a population selector (**All users / Admins / Guests**).

- Rows: All resources · Office 365 (Exchange, SharePoint, Teams) · Admin portal sign-ins · Azure management (ARM, CLI, PowerShell) · Microsoft Graph & Graph PowerShell · Intune APIs · Azure DevOps · Third-party & custom apps · Register security info · Register or join devices.
- Columns: Legacy auth blocked · MFA · Phishing-resistant MFA · Managed device · Device code flow blocked · Sign-in risk · User risk · Session controls.
- Cell states: `covered` (green), `partial` (amber — report-only, OR-weakened, broad exclusions, conditioned scope), `gap` (red), `requiresLicense` (grey hatched), `na` (blank, e.g. managed device on device registration).
- A policy covers a row if it includes `All` (and does not exclude the row's apps) or includes an app/group mapped to that row. Graph and third-party rows are coverable only via `All`.
- Clicking a cell shows contributing policies and related findings.

Score: 100 minus weighted gap/partial deductions (critical 15, high 8, medium 4, low 1; partial = half), floored at 0. License-gated and unverified items excluded.

## 6. UI

Four steps in a top stepper; state autosaves to `localStorage`; "Clear all data" control.

1. **Tenant setup** — license checkboxes, break-glass IDs/UPNs, optional friendly names.
2. **Policies** — cards with state badges; Add policy, Import JSON (file or paste), Load sample tenant. Wizard sections mirror the Entra portal: Users · Target resources · Network · Conditions · Grant · Session. Target-resources picker is a searchable catalog showing group membership and inline warnings (e.g. "Microsoft Graph can only be covered via All resources", "This is a client app and cannot be targeted").
3. **Analysis** — heat map with population selector, score, findings list filterable by severity/family/policy, manual checklist.
4. **Export** — self-contained HTML report (executive summary, heat map, findings, manual checklist, print styles for PDF); findings CSV (`ruleId, severity, status, title, policies, remediation, requiredLicense, reference`); policy JSON re-importable.

## 7. Testing

- Vitest unit tests per rule: one fixture that triggers it, one that does not.
- Normalization/import tests: single object, array, `{value: []}`, comma-separated fields, malformed policy.
- Sample tenants: **known-good** must yield zero critical/high findings; **weak** must yield a specified expected finding set.
- Coverage matrix tests against both sample tenants.
- Export builders tested for CSV escaping and HTML self-containment (no external URLs except reference links).

## 8. Risks

- Microsoft changes app groups and enforcement frequently; the catalog records `verified`/`unverified` and source per entry, and the report shows the catalog date.
- Without directory data, some findings are necessarily heuristic; these go to the manual checklist rather than asserted as gaps.
