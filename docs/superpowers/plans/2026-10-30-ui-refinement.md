# UI Refinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing four-step evaluator explain its score, name the policies behind a heat-map cell, and list the related findings, without changing rule logic or the visual theme.

**Architecture:** Two pure helpers sit next to the engine (`pointsFor` / `scoreDeductions` in `src/engine/score.ts`, `findingsForCell` in `src/engine/cellFindings.ts`). The Analysis step renders those results. Policy cards and the app picker get small presentation fixes in `src/ui`. No new dependencies. The engine still must not import from `src/ui`.

**Tech Stack:** React 19, TypeScript 5.9, Vite 8, Vitest 5, Testing Library. No router, no CSS framework beyond the existing `src/styles.css`.

## Global Constraints

- Browser-only: no Microsoft Graph sign-in, no server, no network calls at runtime.
- Do not change rule IDs, severities, license gates, or score weights. Weights stay critical 15, high 8, medium 4, low 1; `partial` is half; `requiresLicense`, `unverified`, and `info` do not deduct; `HYG-01` does not deduct; the score is `max(0, floor(100 - Σ points))`.
- Catalog date shown on the report stays `2026-10-26`.
- Match apps and roles by ID. Display names come from the catalog or `tenant.displayNames`.
- Engine code in `src/engine`, `src/model`, and `src/catalog` must not import from `src/ui`.
- Keep the dark theme, stepper, and Entra-style blades. This plan does not restyle the app.
- Destructive browser actions use `window.confirm`, matching Clear all data in `src/App.tsx`.

## File map

- Modify: `src/engine/score.ts` — export `pointsFor` and `scoreDeductions`. `computeScore` calls `pointsFor`.
- Test: `src/engine/score.test.ts`
- Create: `src/engine/cellFindings.ts` — `findingsForCell(cell, findings)`.
- Test: `src/engine/cellFindings.test.ts`
- Create: `src/ui/policySummary.ts` — `policyCardSummary(policy)`.
- Test: `src/ui/policySummary.test.ts`
- Modify: `src/ui/PolicyWizard.tsx` — fix the non-targetable app warning and replace the exclude-apps textarea with the catalog picker. The wizard keeps its own blade summaries.
- Modify: `src/ui/PolicyWizard.test.tsx`
- Modify: `src/catalog/apps.ts` — `pickerWarning(app)`.
- Test: `src/catalog/catalog.test.ts`
- Modify: `src/ui/HeatMap.tsx` — policy names and related findings in the cell detail.
- Create: `src/ui/HeatMap.test.tsx`
- Modify: `src/ui/AnalysisView.tsx` — score breakdown; pass findings into the heat map; filter the findings list from the selected cell.
- Modify: `src/ui/FindingsList.tsx` — optional `pinnedRuleIds`.
- Modify: `src/ui/PolicyList.tsx` — card summary; confirm delete; confirm sample replace when policies already exist.
- Modify: `src/ui/PolicyList.test.tsx`
- Modify: `src/App.tsx` — confirm before leaving a dirty wizard.
- Modify: `src/App.test.tsx`
- Modify: `src/ui/labels.ts` — license hint strings.
- Modify: `src/ui/TenantSetup.tsx` — license hints; friendly-name rows that can be removed and do not collide.
- Create: `src/ui/TenantSetup.test.tsx`
- Modify: `src/styles.css` — deduction list and findings overflow.
- Modify: `README.md` — one sentence on the score breakdown and cell detail.

---

### Task 1: Score deductions

**Files:**
- Modify: `src/engine/score.ts`
- Test: `src/engine/score.test.ts`

**Interfaces:**
- Consumes: `Finding` from `src/model/types.ts`.
- Produces:
  - `pointsFor(finding: Finding): number`
  - `scoreDeductions(findings: Finding[]): ScoreDeduction[]`
  - `interface ScoreDeduction { ruleId: string; title: string; severity: Severity; status: 'gap' | 'partial'; points: number }`
  - `computeScore` keeps its current signature and results.

- [ ] **Step 1: Write the failing test**

In `src/engine/score.test.ts`, replace `import { computeScore } from './score';` with the import below, and append the two tests. Keep the existing `computeScore` tests.

```ts
import { computeScore, pointsFor, scoreDeductions } from './score';

test('pointsFor matches the score weights', () => {
  expect(pointsFor(f('critical', 'gap'))).toBe(15);
  expect(pointsFor(f('high', 'partial'))).toBe(4);
  expect(pointsFor(f('low', 'partial'))).toBe(0.5);
  expect(pointsFor(f('info', 'gap'))).toBe(0);
  expect(pointsFor(f('critical', 'requiresLicense'))).toBe(0);
  expect(pointsFor(f('high', 'partial', 'HYG-01'))).toBe(0);
});

test('scoreDeductions lists only scored findings, largest points first', () => {
  const rows = scoreDeductions([
    f('low', 'gap', 'BAS-05'),
    f('critical', 'gap', 'BAS-03'),
    f('high', 'partial', 'HYG-01'),
    f('medium', 'requiresLicense', 'RSK-01'),
  ]);
  expect(rows.map((row) => [row.ruleId, row.points])).toEqual([
    ['BAS-03', 15],
    ['BAS-05', 1],
  ]);
  expect(rows[0].status).toBe('gap');
  expect(rows[0].title).toBe('t');
});
```

The helper `f` in that file already accepts `(severity, status, ruleId)`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/engine/score.test.ts`

Expected: FAIL because `pointsFor` and `scoreDeductions` are not exported.

- [ ] **Step 3: Write the implementation**

Replace the body of `src/engine/score.ts` with:

```ts
import type { Finding, Severity } from '../model/types';

const WEIGHT: Record<Severity, number> = { critical: 15, high: 8, medium: 4, low: 1, info: 0 };
/** HYG-01 summarizes findings that other rules already score. */
const UNSCORED_RULES = new Set(['HYG-01']);

export interface ScoreDeduction {
  ruleId: string;
  title: string;
  severity: Severity;
  status: 'gap' | 'partial';
  points: number;
}

/** Gap uses the severity weight. Partial uses half. License, unverified, info, and HYG-01 contribute 0. */
export function pointsFor(finding: Finding): number {
  if (UNSCORED_RULES.has(finding.ruleId)) return 0;
  if (finding.status === 'gap') return WEIGHT[finding.severity];
  if (finding.status === 'partial') return WEIGHT[finding.severity] / 2;
  return 0;
}

/** 100 minus severity weights of gap (full) and partial (half) findings, rounded down so any finding lowers it, min 0. */
export function computeScore(findings: Finding[]): number {
  const deduction = findings.reduce((sum, finding) => sum + pointsFor(finding), 0);
  return Math.max(0, Math.floor(100 - deduction));
}

/** Scored findings only, highest deduction first, then rule id. */
export function scoreDeductions(findings: Finding[]): ScoreDeduction[] {
  return findings
    .flatMap((finding) => {
      const points = pointsFor(finding);
      if (points === 0 || (finding.status !== 'gap' && finding.status !== 'partial')) return [];
      return [{
        ruleId: finding.ruleId,
        title: finding.title,
        severity: finding.severity,
        status: finding.status,
        points,
      }];
    })
    .sort((a, b) => b.points - a.points || (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0));
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/engine/score.test.ts`

Expected: PASS, including the original `computeScore` cases (100, 81, 85, 92, 96, 99, HYG-01 ignored, floor, never below 0).

- [ ] **Step 5: Commit**

```bash
git add src/engine/score.ts src/engine/score.test.ts
git commit -m "feat(engine): list the findings that lower the score"
```

---

### Task 2: Findings related to a heat-map cell

**Files:**
- Create: `src/engine/cellFindings.ts`
- Create: `src/engine/cellFindings.test.ts`

**Interfaces:**
- Consumes: `Finding` and `MatrixCell` from `src/model/types.ts`. `ControlId` from `src/catalog/surfaces.ts`. `SurfaceId` from `src/catalog/apps.ts`.
- Produces: `findingsForCell(cell: MatrixCell, findings: Finding[]): Finding[]`

A finding is related when its `ruleId` is in the control's list or the surface's list. Order follows the input `findings` array (already severity-sorted by `analyze`). Do not filter on `policyIds`: a gap cell often has no contributing policy, and that is when the finding matters.

Control → rule ids:

| Control | Rule ids |
|---|---|
| `legacyBlocked` | BAS-01, BAS-02 |
| `mfa` | BAS-03, BAS-07, ADM-02, APP-07, WEK-04, WEK-05 |
| `phishResistant` | ADM-01, WEK-05 |
| `managedDevice` | BAS-10, ADM-06, WEK-05, WEK-06 |
| `deviceCodeBlocked` | BAS-04 |
| `signInRisk` | RSK-01 |
| `userRisk` | RSK-02 |
| `session` | BAS-11, ADM-07, WEK-08 |

Surface → extra rule ids:

| Surface | Rule ids |
|---|---|
| `graph` | APP-06 |
| `adminPortals` | ADM-03, ADM-08 |
| `azureManagement` | ADM-04 |
| `azureDevOps` | APP-07 |
| `office365` | APP-02, APP-04 |
| `registerSecurityInfo` | BAS-08 |
| `registerDevice` | BAS-09 |

`allResources`, `intuneApi`, and `thirdParty` add no extra ids. APP-07 is on both the MFA control and the Azure DevOps surface, so a DevOps MFA cell includes it once.

- [ ] **Step 1: Write the failing test**

Create `src/engine/cellFindings.test.ts`:

```ts
import { describe, expect, test } from 'vitest';
import type { Finding, MatrixCell } from '../model/types';
import { findingsForCell } from './cellFindings';

function finding(ruleId: string): Finding {
  return {
    ruleId, title: ruleId, family: 'baseline', severity: 'high', status: 'gap',
    policyIds: [], explanation: '', remediation: '', references: [],
  };
}

function cell(surface: string, control: string): MatrixCell {
  return { surface, control, state: 'gap', policyIds: [], reasons: [] };
}

describe('findingsForCell', () => {
  const findings = ['BAS-01', 'BAS-03', 'APP-06', 'APP-07', 'BAS-09', 'RSK-01', 'HYG-02'].map(finding);

  test('MFA on Graph includes the MFA rules and the Graph rule, once each', () => {
    expect(findingsForCell(cell('graph', 'mfa'), findings).map((f) => f.ruleId)).toEqual(['BAS-03', 'APP-06', 'APP-07']);
  });

  test('device registration ignores MFA-only rules and keeps BAS-09', () => {
    expect(findingsForCell(cell('registerDevice', 'mfa'), findings).map((f) => f.ruleId)).toEqual(['BAS-03', 'BAS-09']);
  });

  test('legacy auth does not include the MFA finding', () => {
    expect(findingsForCell(cell('allResources', 'legacyBlocked'), findings).map((f) => f.ruleId)).toEqual(['BAS-01']);
  });

  test('unknown control returns no findings', () => {
    expect(findingsForCell(cell('allResources', 'not-a-control'), findings)).toEqual([]);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/engine/cellFindings.test.ts`

Expected: FAIL because `src/engine/cellFindings.ts` does not exist.

- [ ] **Step 3: Write the implementation**

Create `src/engine/cellFindings.ts`:

```ts
import type { SurfaceId } from '../catalog/apps';
import type { ControlId } from '../catalog/surfaces';
import type { Finding, MatrixCell } from '../model/types';

const CONTROL_RULES: Record<ControlId, readonly string[]> = {
  legacyBlocked: ['BAS-01', 'BAS-02'],
  mfa: ['BAS-03', 'BAS-07', 'ADM-02', 'APP-07', 'WEK-04', 'WEK-05'],
  phishResistant: ['ADM-01', 'WEK-05'],
  managedDevice: ['BAS-10', 'ADM-06', 'WEK-05', 'WEK-06'],
  deviceCodeBlocked: ['BAS-04'],
  signInRisk: ['RSK-01'],
  userRisk: ['RSK-02'],
  session: ['BAS-11', 'ADM-07', 'WEK-08'],
};

const SURFACE_RULES: Partial<Record<SurfaceId, readonly string[]>> = {
  graph: ['APP-06'],
  adminPortals: ['ADM-03', 'ADM-08'],
  azureManagement: ['ADM-04'],
  azureDevOps: ['APP-07'],
  office365: ['APP-02', 'APP-04'],
  registerSecurityInfo: ['BAS-08'],
  registerDevice: ['BAS-09'],
};

/** Findings whose rule id is mapped to this cell's control or surface, in input order. */
export function findingsForCell(cell: MatrixCell, findings: Finding[]): Finding[] {
  const ids = new Set<string>([
    ...(CONTROL_RULES[cell.control as ControlId] ?? []),
    ...(SURFACE_RULES[cell.surface as SurfaceId] ?? []),
  ]);
  return findings.filter((finding) => ids.has(finding.ruleId));
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/engine/cellFindings.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/engine/cellFindings.ts src/engine/cellFindings.test.ts
git commit -m "feat(engine): map heat-map cells to related findings"
```

---

### Task 3: Policy card summary

**Files:**
- Create: `src/ui/policySummary.ts`
- Create: `src/ui/policySummary.test.ts`
- Modify: `src/ui/PolicyList.tsx`

**Interfaces:**
- Consumes: `CAPolicy` from `src/model/types.ts`, `appLabel` from `src/catalog/apps.ts`, `KEYWORD` from `src/catalog/apps.ts`.
- Produces: `policyCardSummary(policy: CAPolicy): { who: string; resources: string; access: string }`

- [ ] **Step 1: Write the failing test**

Create `src/ui/policySummary.test.ts`:

```ts
import { describe, expect, test } from 'vitest';
import { KEYWORD } from '../catalog/apps';
import { blankPolicy } from '../model/newPolicy';
import { policyCardSummary } from './policySummary';

describe('policyCardSummary', () => {
  test('blank policy has no users, resources, or grant selected', () => {
    expect(policyCardSummary(blankPolicy())).toEqual({
      who: 'Not configured',
      resources: 'Not configured',
      access: 'Not configured',
    });
  });

  test('all users, all resources, block', () => {
    const policy = blankPolicy();
    policy.conditions.users.includeUsers = ['All'];
    policy.conditions.applications.includeApplications = [KEYWORD.all];
    policy.grantControls = {
      operator: 'OR', builtInControls: ['block'], customAuthenticationFactors: [], termsOfUse: [], authenticationStrength: null,
    };
    expect(policyCardSummary(policy)).toEqual({
      who: 'All users',
      resources: 'All resources',
      access: 'Block access',
    });
  });

  test('report-only is not part of the access line; the badge already says it', () => {
    const policy = blankPolicy();
    policy.state = 'enabledForReportingButNotEnforced';
    policy.conditions.users.includeUsers = ['All'];
    policy.grantControls = {
      operator: 'OR',
      builtInControls: ['mfa'],
      customAuthenticationFactors: [],
      termsOfUse: [],
      authenticationStrength: null,
    };
    expect(policyCardSummary(policy).access).toBe('Require one: mfa');
  });
});
```

`blankPolicy()` normalizes empty `users` and `applications` to empty arrays, and an operator-only grant to an empty `builtInControls` list. That is why all three lines are `Not configured`, not `None`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/ui/policySummary.test.ts`

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Write the implementation**

Create `src/ui/policySummary.ts`:

```ts
import { KEYWORD, appLabel } from '../catalog/apps';
import type { CAPolicy } from '../model/types';

export interface PolicyCardSummary {
  who: string;
  resources: string;
  access: string;
}

export function policyCardSummary(policy: CAPolicy): PolicyCardSummary {
  const users = policy.conditions.users;
  const apps = policy.conditions.applications;
  let who = 'Not configured';
  if (users.includeUsers.includes('All')) who = 'All users';
  else if (
    users.includeUsers.length === 1 && users.includeUsers[0] === 'None'
    && users.includeGroups.length === 0 && users.includeRoles.length === 0 && !users.includeGuestsOrExternalUsers
  ) who = 'None';
  else {
    const parts: string[] = [];
    if (users.includeUsers.some((id) => id !== 'All' && id !== 'None') || users.includeGroups.length) parts.push('Select users and groups');
    if (users.includeRoles.length) parts.push(`${users.includeRoles.length} roles`);
    if (users.includeGuestsOrExternalUsers) parts.push('Guests');
    if (parts.length) who = parts.join(', ');
  }

  let resources = 'Not configured';
  if (apps.includeUserActions.length) resources = 'User actions';
  else if (apps.includeAuthenticationContextClassReferences.length && apps.includeApplications.length === 0) resources = 'Authentication context';
  else if (apps.includeApplications.includes(KEYWORD.all)) resources = 'All resources';
  else if (apps.includeApplications.length === 1 && apps.includeApplications[0] === KEYWORD.office365) resources = 'Office 365';
  else if (apps.includeApplications.length === 1 && apps.includeApplications[0] === KEYWORD.adminPortals) resources = 'Microsoft Admin Portals';
  else if (apps.includeApplications.length) resources = apps.includeApplications.map(appLabel).slice(0, 2).join(', ');

  const grant = policy.grantControls;
  let access = 'Not configured';
  if (grant?.builtInControls.includes('block')) access = 'Block access';
  else if (grant) {
    const names = grant.builtInControls.filter((control) => control !== 'block');
    if (grant.authenticationStrength?.displayName) names.push(grant.authenticationStrength.displayName);
    if (names.length) access = `${grant.operator === 'AND' ? 'Require all' : 'Require one'}: ${names.join(', ')}`;
  }

  return { who, resources, access };
}
```

In `src/ui/PolicyList.tsx`, import `policyCardSummary` and render it under the policy id:

```tsx
const summary = policyCardSummary(p);
```

Inside the card, after `<div className="meta">{p.id}</div>`:

```tsx
<div className="meta">{summary.who} · {summary.resources} · {summary.access}</div>
```

- [ ] **Step 4: Run the tests**

Run: `npx vitest run src/ui/policySummary.test.ts src/ui/PolicyList.test.tsx`

Expected: PASS. The existing PolicyList tests stay green. They do not render a filled card, so they do not assert the summary line.

- [ ] **Step 5: Commit**

```bash
git add src/ui/policySummary.ts src/ui/policySummary.test.ts src/ui/PolicyList.tsx
git commit -m "feat(ui): summarize assignments on each policy card"
```

---

### Task 4: Confirm delete, sample replace, and leaving a dirty wizard

**Files:**
- Modify: `src/ui/PolicyList.tsx`
- Modify: `src/ui/PolicyList.test.tsx`
- Modify: `src/App.tsx`
- Modify: `src/App.test.tsx`
- Modify: `src/ui/PolicyWizard.tsx` (report dirty state)

**Interfaces:**
- Consumes: existing `PolicyWizard` props `{ policy, onSave, onCancel }`.
- Produces: `PolicyWizard` gains optional `onDirtyChange?: (dirty: boolean) => void`. `App` stores `wizardDirty: boolean`.

`window.confirm` in jsdom returns `false` unless the test stubs it. Only prompt when the action would destroy user-entered policies. Loading a sample onto an empty list must stay a single click, because `src/App.test.tsx` does that.

- [ ] **Step 1: Write the failing tests**

`src/ui/PolicyList.test.tsx` already imports `fireEvent`, `render`, `screen`, `expect`, `test`, and `vi`. Add `blankPolicy` to the imports from `../model/newPolicy`. Append:

```tsx
test('delete asks for confirmation and keeps the policy when declined', () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const onPolicies = vi.fn();
  const policy = blankPolicy();
  policy.displayName = 'Keep me';
  render(
    <PolicyList policies={[policy]} onPolicies={onPolicies} onTenant={() => undefined} onEdit={() => undefined} />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
  expect(confirm).toHaveBeenCalled();
  expect(onPolicies).not.toHaveBeenCalled();
  confirm.mockRestore();
});

test('replacing an existing list with a sample asks first', () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  const onPolicies = vi.fn();
  render(
    <PolicyList policies={[blankPolicy()]} onPolicies={onPolicies} onTenant={() => undefined} onEdit={() => undefined} />,
  );
  fireEvent.click(screen.getByRole('button', { name: 'Load sample: weak' }));
  expect(confirm).toHaveBeenCalled();
  expect(onPolicies).not.toHaveBeenCalled();
  confirm.mockRestore();
});
```

Append to `src/App.test.tsx`, and add `vi` to the existing `vitest` import:

```tsx
test('stepper asks before leaving an edited policy', () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false);
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: 'Next' }));
  fireEvent.click(screen.getByRole('button', { name: 'Create new policy' }));
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'Unsaved MFA' } });
  fireEvent.click(screen.getByRole('button', { name: '3. Analysis' }));
  expect(confirm).toHaveBeenCalled();
  expect(screen.getByRole('heading', { name: /Conditional Access policy/ })).toBeTruthy();
  confirm.mockRestore();
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/ui/PolicyList.test.tsx src/App.test.tsx`

Expected: FAIL. Delete and sample load currently call `onPolicies` without `confirm`. The stepper currently leaves the wizard.

- [ ] **Step 3: Write the implementation**

In `PolicyList`, delete becomes:

```tsx
onClick={() => {
  if (window.confirm(`Delete “${p.displayName}”?`)) onPolicies(policies.filter((x) => x.id !== p.id));
}}
```

Sample buttons call a helper:

```tsx
function loadSample(sample: { tenant: TenantProfile; policies: CAPolicy[] }) {
  if (policies.length > 0 && !window.confirm('Replace the policies and tenant setup in this browser with the sample?')) return;
  onTenant(sample.tenant);
  onPolicies(sample.policies);
}
```

Use curly quotes in the confirm strings exactly as written so the tests do not need to match the message, only that `confirm` was called.

In `PolicyWizard`, add `onDirtyChange?: (dirty: boolean) => void` to `Props`. After the `draft` state:

```tsx
useEffect(() => {
  onDirtyChange?.(JSON.stringify(draft) !== JSON.stringify(policy));
}, [draft, policy, onDirtyChange]);
```

Import `useEffect` from `react`.

In `App.tsx`:

```tsx
const [wizardDirty, setWizardDirty] = useState(false);

function leaveWizard(): boolean {
  if (!editing || !wizardDirty) return true;
  return window.confirm('Discard unsaved policy changes?');
}

function go(step: AppState['step']) {
  if (!leaveWizard()) return;
  setWizardDirty(false);
  setEditing(null);
  setState({ ...state, step });
}
```

Pass `onDirtyChange={setWizardDirty}` to `PolicyWizard`. When `onCancel` runs, clear `wizardDirty` as well:

```tsx
onCancel={() => {
  setWizardDirty(false);
  setEditing(null);
}}
```

Cancel itself stays immediate. The confirm is for the stepper and Back/Next, which call `go`.

- [ ] **Step 4: Run the tests**

Run: `npx vitest run src/ui/PolicyList.test.tsx src/App.test.tsx src/ui/PolicyWizard.test.tsx`

Expected: PASS. The existing App test that loads the weak sample on an empty list still passes without a confirm.

- [ ] **Step 5: Commit**

```bash
git add src/ui/PolicyList.tsx src/ui/PolicyList.test.tsx src/ui/PolicyWizard.tsx src/App.tsx src/App.test.tsx
git commit -m "fix(ui): confirm before deleting policies or discarding edits"
```

---

### Task 5: App picker warnings and exclude catalog

**Files:**
- Modify: `src/catalog/apps.ts`
- Modify: `src/catalog/catalog.test.ts`
- Modify: `src/ui/PolicyWizard.tsx`
- Modify: `src/ui/PolicyWizard.test.tsx`

**Interfaces:**
- Consumes: `CatalogApp` in `src/catalog/apps.ts`. `APP` ids already exported there.
- Produces: `pickerWarning(app: CatalogApp): string | null`

- [ ] **Step 1: Write the failing test**

In `src/catalog/catalog.test.ts`, import `pickerWarning` and `APP` (APP is already in that module). Add:

```ts
test('pickerWarning distinguishes Graph from other clients', () => {
  const graph = lookupApp(APP.microsoftGraph)!;
  const cli = lookupApp(APP.azureCli)!;
  const exchange = lookupApp(APP.exchangeOnline)!;
  expect(pickerWarning(graph)).toBe('Microsoft Graph can only be covered via All resources.');
  expect(pickerWarning(lookupApp(APP.graphPowerShell)!)).toBe('Microsoft Graph can only be covered via All resources.');
  expect(pickerWarning(cli)).toBe('This is a client app and cannot be targeted.');
  expect(pickerWarning(exchange)).toBeNull();
});
```

`src/catalog/catalog.test.ts` already imports `lookupApp` and `APP`. Append the test to that file.

Append to `src/ui/PolicyWizard.test.tsx`:

```tsx
test('Azure CLI does not claim that only All resources covers Graph', () => {
  render(<PolicyWizard policy={blankPolicy()} onSave={() => undefined} onCancel={() => undefined} />);
  fireEvent.click(screen.getByRole('button', { name: 'Target resources' }));
  fireEvent.click(screen.getByLabelText('Select resources'));
  fireEvent.change(screen.getByLabelText('Search resources'), { target: { value: 'Azure CLI' } });
  expect(screen.getByText('This is a client app and cannot be targeted.')).toBeTruthy();
  expect(screen.queryByText('Microsoft Graph can only be covered via All resources.')).toBeNull();
});

test('excluding Office 365 writes the keyword', () => {
  const onSave = vi.fn();
  render(<PolicyWizard policy={blankPolicy()} onSave={onSave} onCancel={() => undefined} />);
  fireEvent.click(screen.getByRole('button', { name: 'Target resources' }));
  fireEvent.click(screen.getByLabelText('All resources'));
  fireEvent.click(screen.getByLabelText('Exclude Office 365'));
  fireEvent.click(screen.getByRole('button', { name: 'Save policy' }));
  expect(onSave.mock.calls[0][0].conditions.applications.excludeApplications).toContain('Office365');
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run src/catalog/catalog.test.ts src/ui/PolicyWizard.test.tsx`

Expected: FAIL. `pickerWarning` is missing. The wizard currently has no "Exclude Office 365" checkbox, and every non-targetable row mentions Graph.

- [ ] **Step 3: Write the implementation**

Add to `src/catalog/apps.ts`, next to `appLabel`:

```ts
const GRAPH_CLIENT_IDS = new Set<string>([APP.microsoftGraph, APP.azureAdGraph, APP.graphPowerShell, APP.graphExplorer]);

/** Short picker warning. Null when the app can be targeted. */
export function pickerWarning(app: CatalogApp): string | null {
  if (app.targetable) return null;
  if (GRAPH_CLIENT_IDS.has(app.appId)) return 'Microsoft Graph can only be covered via All resources.';
  return 'This is a client app and cannot be targeted.';
}
```

In `PolicyWizard.tsx`, import `pickerWarning`. Replace the non-targetable span:

```tsx
{pickerWarning(a) && <span className="app-note">{pickerWarning(a)}</span>}
```

Replace the exclude textarea (the block that starts `<p className="subhead">Exclude</p>` and ends with the `appLabel` muted line) with:

```tsx
<p className="subhead">Exclude</p>
<label className="check">
  <input
    type="checkbox"
    checked={apps.excludeApplications.includes(KEYWORD.office365)}
    onChange={(e) => setApps({
      excludeApplications: e.target.checked
        ? [...apps.excludeApplications, KEYWORD.office365]
        : apps.excludeApplications.filter((id) => id !== KEYWORD.office365),
    })}
  />
  Exclude Office 365
</label>
<label className="check">
  <input
    type="checkbox"
    checked={apps.excludeApplications.includes(KEYWORD.adminPortals)}
    onChange={(e) => setApps({
      excludeApplications: e.target.checked
        ? [...apps.excludeApplications, KEYWORD.adminPortals]
        : apps.excludeApplications.filter((id) => id !== KEYWORD.adminPortals),
    })}
  />
  Exclude Microsoft Admin Portals
</label>
<input className="search" value={excludeQuery} onChange={(e) => setExcludeQuery(e.target.value)} placeholder="Search resources to exclude" aria-label="Search resources to exclude" />
<div className="app-pick">
  {filteredExclude.map((a) => (
    <label className="check" key={`ex-${a.appId}`}>
      <input
        type="checkbox"
        checked={apps.excludeApplications.includes(a.appId)}
        onChange={(e) => setApps({
          excludeApplications: e.target.checked
            ? [...apps.excludeApplications.filter((id) => id !== a.appId), a.appId]
            : apps.excludeApplications.filter((id) => id !== a.appId),
        })}
      />
      <span>
        {a.name}
        {pickerWarning(a) && <span className="app-note">{pickerWarning(a)}</span>}
      </span>
    </label>
  ))}
</div>
```

Add state:

```tsx
const [excludeQuery, setExcludeQuery] = useState('');
const filteredExclude = useMemo(() => {
  const q = excludeQuery.trim().toLowerCase();
  return APP_CATALOG.filter((a) =>
    !q || a.name.toLowerCase().includes(q) || a.appId.includes(q) || a.aliases.some((alias) => alias.toLowerCase().includes(q)),
  );
}, [excludeQuery]);
```

Keep ids already stored in `excludeApplications` that are not in the catalog. Do not wipe them when toggling a catalog app. The filter above only adds or removes the clicked id.

`setApps` merges a partial `CAApplications`. Confirm its implementation replaces `excludeApplications` when that key is passed, and does not require the other application fields. It does: `setApps` calls `patch` with `{ ...apps, ...next }`.

- [ ] **Step 4: Run the tests**

Run: `npx vitest run src/catalog/catalog.test.ts src/ui/PolicyWizard.test.tsx`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/catalog/apps.ts src/catalog/catalog.test.ts src/ui/PolicyWizard.tsx src/ui/PolicyWizard.test.tsx
git commit -m "fix(ui): correct app-picker warnings and exclude from the catalog"
```

---

### Task 6: Heat map detail and score breakdown

**Files:**
- Modify: `src/ui/HeatMap.tsx`
- Create: `src/ui/HeatMap.test.tsx`
- Modify: `src/ui/AnalysisView.tsx`
- Modify: `src/ui/FindingsList.tsx`
- Modify: `src/styles.css`
- Modify: `README.md`

**Interfaces:**
- Consumes: `findingsForCell` from `src/engine/cellFindings.ts`, `scoreDeductions` from `src/engine/score.ts`, `CAPolicy`, `Finding`, `MatrixCell`.
- Produces: `HeatMap` props gain `policies: CAPolicy[]` and `findings: Finding[]`. `FindingsList` props gain optional `pinnedRuleIds?: string[]`. When `pinnedRuleIds` is a non-empty array, the list shows only findings whose `ruleId` is in it, and the heading reads `Related findings (N)`. The severity, family, and policy selects still apply on top of that set. Clearing the cell passes `undefined` and restores `Findings (N)`.

- [ ] **Step 1: Write the failing test**

Create `src/ui/HeatMap.test.tsx`:

```tsx
import { fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { expect, test } from 'vitest';
import type { CoverageMatrix, Finding, MatrixCell, Population } from '../model/types';
import { blankPolicy } from '../model/newPolicy';
import { HeatMap } from './HeatMap';

const cell: MatrixCell = {
  surface: 'graph', control: 'mfa', state: 'partial',
  policyIds: ['pol-1'], reasons: ['grant is MFA or a compliant device'],
};

const matrices: Record<Population, CoverageMatrix> = {
  allUsers: { population: 'allUsers', cells: [cell] },
  admins: { population: 'admins', cells: [] },
  guests: { population: 'guests', cells: [] },
};

const finding: Finding = {
  ruleId: 'BAS-03', title: 'No MFA baseline', family: 'baseline', severity: 'critical', status: 'gap',
  policyIds: ['pol-1'], explanation: 'No enforced MFA policy covers all users.', remediation: 'Require MFA.', references: [],
};

function Harness() {
  const [selected, setSelected] = useState<MatrixCell | null>(null);
  const policy = blankPolicy();
  policy.id = 'pol-1';
  policy.displayName = 'MFA or compliant device';
  return (
    <HeatMap
      matrices={matrices}
      population="allUsers"
      onPopulation={() => undefined}
      selected={selected}
      onSelect={setSelected}
      policies={[policy]}
      findings={[finding]}
    />
  );
}

test('a cell names the policy and lists the related finding', () => {
  render(<Harness />);
  fireEvent.click(screen.getByRole('button', { name: /Microsoft Graph & Graph PowerShell, MFA/ }));
  expect(screen.getByText('MFA or compliant device')).toBeTruthy();
  expect(screen.queryByText('pol-1')).toBeNull();
  expect(screen.getByText('No MFA baseline')).toBeTruthy();
  expect(screen.getByText('grant is MFA or a compliant device')).toBeTruthy();
});
```

The button's accessible name is `` `${surface label}, ${control label}: ${state label}` ``, so it contains both `Microsoft Graph & Graph PowerShell, MFA` and `Partial`. Empty populations still render gap buttons for every other cell. That does not hide the Graph MFA button.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/ui/HeatMap.test.tsx`

Expected: FAIL because `HeatMap` does not accept `policies` and `findings`, and the detail shows raw policy ids.

- [ ] **Step 3: Write the implementation**

`HeatMap` props:

```tsx
policies: CAPolicy[];
findings: Finding[];
```

Import `findingsForCell` from `../engine/cellFindings`. In the detail block, replace the policy id paragraph:

```tsx
{selected.policyIds.length > 0 && (
  <p className="muted">
    Policies: {selected.policyIds.map((id) => policies.find((p) => p.id === id)?.displayName ?? id).join(', ')}
  </p>
)}
{findingsForCell(selected, findings).length > 0 && (
  <>
    <p className="subhead">Related findings</p>
    <ul className="related">
      {findingsForCell(selected, findings).map((finding) => (
        <li key={finding.ruleId}>
          <span className={`badge ${finding.severity}`}>{finding.ruleId}</span> {finding.title}
        </li>
      ))}
    </ul>
  </>
)}
```

Call `findingsForCell` once and store it in a const before the return of the detail, so it is not invoked twice. The component function can compute `const related = selected ? findingsForCell(selected, findings) : []`.

`AnalysisView` already has `result`. Render the score breakdown under the score:

```tsx
<ul className="deductions">
  {scoreDeductions(result.findings).slice(0, 8).map((row) => (
    <li key={`${row.ruleId}-${row.status}`}>
      <span className={`badge ${row.severity}`}>{row.ruleId}</span>
      <span>{row.title}</span>
      <span className="muted">−{row.points}</span>
    </li>
  ))}
</ul>
```

When `scoreDeductions` is empty, do not render the list. Show the full point value, including `0.5`.

Pass policies and findings into `HeatMap`:

```tsx
<HeatMap
  matrices={result.matrices}
  population={population}
  onPopulation={setPopulation}
  selected={selected}
  onSelect={setSelected}
  policies={policies}
  findings={result.findings}
/>
```

Pass pinned ids into `FindingsList`:

```tsx
<FindingsList
  findings={result.findings}
  policies={policies}
  pinnedRuleIds={selected ? findingsForCell(selected, result.findings).map((f) => f.ruleId) : undefined}
/>
```

In `FindingsList`, add `pinnedRuleIds?: string[]` to `Props`. Filter:

```tsx
const pinned = pinnedRuleIds && pinnedRuleIds.length > 0 ? new Set(pinnedRuleIds) : null;
const rows = findings.filter((f) =>
  (pinned === null || pinned.has(f.ruleId))
  && (severity === 'all' || f.severity === severity)
  && (family === 'all' || f.family === family)
  && (policyId === 'all' || f.policyIds.includes(policyId)),
);
```

Heading: `pinned ? \`Related findings (${rows.length})\` : \`Findings (${rows.length})\``.

Add to `src/styles.css`:

```css
.deductions, .related { list-style: none; padding: 0; margin: 0 0 18px; }
.deductions li, .related li { display: flex; gap: 10px; align-items: baseline; padding: 6px 0; border-bottom: 1px solid var(--line); }
.deductions li span:nth-child(2) { flex: 1; }
.findings-scroll { overflow-x: auto; }
```

Wrap the findings `<table className="findings">` in `<div className="findings-scroll">`.

In `README.md`, after the heat-map color table, add:

```md
The score starts at 100. The Analysis step lists each finding that lowers it. Click a heat-map cell to see the policies that contribute to it and the findings for that resource and control.
```

- [ ] **Step 4: Run the tests**

Run: `npx vitest run src/ui/HeatMap.test.tsx src/App.test.tsx && npx tsc -b --pretty false`

Expected: PASS. `tsc` exits 0. The App test still finds `BAS-03` on the Analysis step.

- [ ] **Step 5: Commit**

```bash
git add src/ui/HeatMap.tsx src/ui/HeatMap.test.tsx src/ui/AnalysisView.tsx src/ui/FindingsList.tsx src/styles.css README.md
git commit -m "feat(ui): explain the score and the selected heat-map cell"
```

---

### Task 7: License hints and friendly-name rows

**Files:**
- Modify: `src/ui/labels.ts`
- Modify: `src/ui/TenantSetup.tsx`
- Create: `src/ui/TenantSetup.test.tsx`

**Interfaces:**
- Consumes: `LICENSE_FIELDS` in `src/ui/labels.ts`. `TenantProfile.displayNames: Record<string, string>`.
- Produces: each license field gains `hint: string`. `TenantSetup` keeps writing `displayNames` as a record. Blank rows live in component state so two new rows do not share the `''` key.

Hints, copied into `LICENSE_FIELDS`:

| key | hint |
|---|---|
| `entraP1` | Conditional Access itself. Token protection is also gated on P1. |
| `entraP2` | Sign-in risk and user risk. Insider risk also needs Purview. |
| `intune` | Managed-device findings and the managed-device column. |
| `workloadIdPremium` | Workload identity policies. |
| `defenderForCloudApps` | Stored on the profile. No current rule reads this license. |
| `purviewInsiderRisk` | Insider risk, together with Entra ID P2. |

- [ ] **Step 1: Write the failing test**

Create `src/ui/TenantSetup.test.tsx`:

```tsx
import { fireEvent, render, screen } from '@testing-library/react';
import { useState } from 'react';
import { expect, test } from 'vitest';
import { DEFAULT_TENANT, type TenantProfile } from '../model/types';
import { TenantSetup } from './TenantSetup';

function Harness() {
  const [tenant, setTenant] = useState<TenantProfile>(DEFAULT_TENANT);
  return <TenantSetup tenant={tenant} onChange={setTenant} />;
}

test('two new friendly-name rows can hold different ids', () => {
  render(<Harness />);
  fireEvent.click(screen.getByRole('button', { name: 'Add name' }));
  fireEvent.click(screen.getByRole('button', { name: 'Add name' }));
  const ids = screen.getAllByLabelText('Object ID');
  fireEvent.change(ids[0], { target: { value: 'aaa' } });
  fireEvent.change(ids[1], { target: { value: 'bbb' } });
  expect(screen.getAllByLabelText('Object ID')).toHaveLength(2);
  expect((screen.getAllByLabelText('Object ID')[0] as HTMLInputElement).value).toBe('aaa');
  expect((screen.getAllByLabelText('Object ID')[1] as HTMLInputElement).value).toBe('bbb');
});

test('a friendly-name row can be removed', () => {
  render(<Harness />);
  fireEvent.click(screen.getByRole('button', { name: 'Add name' }));
  fireEvent.click(screen.getByRole('button', { name: 'Remove name' }));
  expect(screen.queryByLabelText('Object ID')).toBeNull();
});

test('Entra ID P2 explains what it changes', () => {
  render(<Harness />);
  expect(screen.getByText('Sign-in risk and user risk. Insider risk also needs Purview.')).toBeTruthy();
});
```

`@testing-library/jest-dom` is already a dev dependency. `toHaveLength` and `toBeTruthy` are used elsewhere via vitest's expect. If `toHaveLength` is missing, use `expect(screen.getAllByLabelText('Object ID').length).toBe(2)`.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/ui/TenantSetup.test.tsx`

Expected: FAIL. There is no Remove name button, and adding two names collapses them onto one object key.

- [ ] **Step 3: Write the implementation**

Extend `LICENSE_FIELDS` entries with the `hint` strings from the table above.

In `TenantSetup`, under each checkbox label, render `<span className="muted">{f.hint}</span>` inside the `<label className="check">` so the hint is associated with the checkbox. The checkbox's accessible name must stay exactly `Entra ID P2` (and the other current labels). Put the hint in a sibling `<p className="muted">` after the label, not inside the label, so `getByLabelText('Entra ID P2')` in `src/App.test.tsx` still matches.

Friendly names: stop using `Object.entries(tenant.displayNames)` as the row identity.

```tsx
const [rows, setRows] = useState<{ key: string; id: string; name: string }[]>(() =>
  Object.entries(tenant.displayNames).map(([id, name]) => ({ key: id || newId(), id, name })),
);

function publish(next: { key: string; id: string; name: string }[]) {
  setRows(next);
  const displayNames: Record<string, string> = {};
  for (const row of next) {
    if (row.id.trim()) displayNames[row.id.trim()] = row.name;
  }
  onChange({ ...tenant, displayNames });
}
```

Import `newId` from `../model/normalize`. It already falls back when `crypto.randomUUID` is missing.

Add name:

```tsx
onClick={() => publish([...rows, { key: newId(), id: '', name: '' }])}
```

Each row's Object ID input `aria` is the visible text `Object ID` via the existing `<label className="field">`. Remove button:

```tsx
<button type="button" className="btn secondary" aria-label="Remove name" onClick={() => publish(rows.filter((row) => row.key !== item.key))}>
  Remove
</button>
```

There is one Remove button per row. `getByRole('button', { name: 'Remove name' })` matches when one row exists. When writing the label, use `aria-label="Remove name"` so the visible word can stay "Remove".

Changing Object ID updates that row's `id` and calls `publish`. Changing Display name updates `name` and calls `publish`.

Do not sync `rows` from `tenant` in an effect. The parent is controlled, but row keys are local. Sample load unmounts this step only when the user navigates; if the tenant prop changes while mounted (sample load stays on Policies, not Tenant), no effect is required.

- [ ] **Step 4: Run the tests**

Run: `npx vitest run src/ui/TenantSetup.test.tsx src/App.test.tsx`

Expected: PASS. The P2 checkbox test in `App.test.tsx` still finds the label `Entra ID P2`.

- [ ] **Step 5: Commit**

```bash
git add src/ui/labels.ts src/ui/TenantSetup.tsx src/ui/TenantSetup.test.tsx
git commit -m "fix(ui): license hints and distinct friendly-name rows"
```

---

### Task 8: Full test and build

**Files:**
- Modify: none, unless a previous task left a type error.

- [ ] **Step 1: Run the suite and the production build**

Run: `npm test && npm run build`

Expected: Vitest passes. `tsc -b` and `vite build` exit 0.

- [ ] **Step 2: Commit only if Step 1 required a fix**

If you changed a file to make the suite pass, commit that fix with a message that names the failure. If Step 1 passed with a clean tree, do not create an empty commit.

---

## Self-review

Spec section 6 items this plan implements:

- Clicking a cell shows contributing policies and related findings — Task 2 and Task 6.
- Findings stay filterable by severity, family, and policy — Task 6 keeps those selects and adds the cell pin on top.
- Policy list cards — Task 3 adds the assignment line the cards were missing.
- Target-resources picker warnings — Task 5 splits the Graph warning from other client apps and makes exclusions a catalog, which section 6 asks for on the picker.

Explicitly not in this plan:

- Live directory search for users and groups. The app has no Graph connection.
- A new color theme, a print-preview pane, or a change to HTML/CSV export columns.
- Platform include (only Windows, and so on). The wizard can exclude platforms today. Adding include-platform is a policy-model behavior change and belongs in its own plan.
- Sorting or persisting manual-checklist checkboxes.

Placeholder scan: every task has a failing test, the command, the code, and a commit. Rule ids in Task 2 are the ids in `docs/superpowers/specs/2026-10-26-ca-gap-evaluator-design.md`.

Type consistency: `pointsFor`, `scoreDeductions`, `ScoreDeduction`, `findingsForCell`, `policyCardSummary`, `PolicyCardSummary`, `pickerWarning`, and `pinnedRuleIds` are spelled the same in the task that defines them and the tasks that use them.
