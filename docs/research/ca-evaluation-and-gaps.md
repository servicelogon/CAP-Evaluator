# Microsoft Entra Conditional Access: Evaluation Semantics, Schema, and Coverage-Gap Rules

Research date: 2026-10-26. Sources are Microsoft Learn (learn.microsoft.com), Microsoft Graph docs, Microsoft Message Center archives, and the CISA SCuBA Entra ID baseline (`cisagov/ScubaGear`, `baselines/aad.md`, main branch as of this date).

Conventions:

- **UNVERIFIED** means I could not confirm the claim against a primary source during this pass. Treat it as a hypothesis to test against a real tenant.
- **DISCREPANCY** means two official Microsoft sources disagree. Both sides are recorded.
- JSON paths are relative to a `conditionalAccessPolicy` object returned by `GET /identity/conditionalAccess/policies`.

---

## 0. Key recent changes (2024–2026) a gap tool must account for

| Change | Status / date | Impact on evaluation | Source |
|---|---|---|---|
| **Microsoft-managed policies** (MMP) | Created report-only, auto-enabled ≥30 days later unless set to Off. Current set: block high-risk agents (preview), block legacy auth, block device code flow, MFA for admins on admin portals, MFA for all users, MFA for per-user-MFA users, MFA + reauth for risky sign-ins, block high-risk users, require remediation for high-risk users, phishing-resistant auth for admins (Baseline security mode). Can't be renamed/deleted; only state + exclusions editable. Names start with `Microsoft-managed:` | Tool must count them as real policies, and flag ones the admin set to `disabled`. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies |
| **Baseline security mode (BSM)** policies | Two CA policies from M365 admin center: "Require phishing resistant authentication for admins" and "Block legacy authentication". "Created by" shows Baseline security mode; created by the admin, not by Microsoft. | Same as above. | same |
| **Authentication flows condition** (`authenticationFlows.transferMethods`) | In Graph **v1.0**. Device code flow control is broadly recommended; the Learn conditions page still labels the section "(preview)", and the authentication-transfer page says "currently in preview". GA status of each flow is **UNVERIFIED**. Since Sept 2024, authentication-flows policies targeting All resources are also enforced on Device Registration Service (`01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9`). | Device code flow block is a first-class gap check. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows |
| **"Require approved client app" retirement** | **DISCREPANCY.** The Learn migration article says that on **June 30, 2026** the control and any policy using it become **read-only**: you can't create or edit them, but you can disable or delete them, and **existing enabled policies keep enforcing**. Message Center MC1220751 (Jan 2026) says that after retirement "you will no longer be able to enforce this control, it will be as if this grant is not selected." The grant-controls page still says "early March 2026" (stale). | Flag any policy whose `builtInControls` contains `approvedApplication`. Under the MC interpretation, a policy with `approvedApplication` alone, or `OR` with only that control, may be a no-op. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/migrate-approved-client-app ; https://mc.merill.net/message/MC1220751 |
| **"All resources" + resource exclusions: baseline-scope enforcement** | **DISCREPANCY on date.** The Target resources page says the rollout starts "in phases starting in March, 2026". The dedicated article says "Rollout … began on June 15, 2026". Previously, an All-resources policy with **any** excluded app silently skipped low-privilege scopes (`openid`, `profile`, `email`, `offline_access`, `User.Read`, `User.Read.All`, `User.ReadBasic.All`, `People.Read`, `People.Read.All`, `GroupMember.Read.All`, `Member.Read.Hidden`). Now these are evaluated as Azure AD Graph (`00000002-0000-0000-c000-000000000000`). A "customize behavior" opt-out exists. | Tenants using the legacy-behavior opt-out still have the old hole. Detecting the opt-out via Graph is **UNVERIFIED**. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps ; https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-enforcement-resource-exclusions |
| **Token protection** (session control) | GA for **native apps** on Windows, iOS/iPadOS, and macOS. Browser apps are preview, and only for apps accessing Azure Resource Manager. The Apple "Supported devices" subsection is still labeled "(Preview)" on the same page (inconsistent). Resources: Exchange Online, SharePoint Online, Teams, plus AVD and Windows 365 on Windows. P1. | Graph property is **beta-only**: `sessionControls.secureSignInSession`. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection ; https://learn.microsoft.com/en-us/entra/identity/conditional-access/deployment-guide-token-protection-windows |
| **Insider risk condition** | GA July–Aug 2024 (MC807451). Requires Purview Adaptive Protection plus Entra ID P2. Graph v1.0 `insiderRiskLevels` (`minor`, `moderate`, `elevated`). | Optional maturity rule. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-insider-risk ; https://mc.merill.net/message/MC807451 |
| **Agent identities (Entra Agent ID)** | Preview. Agent identities support **only Block**. Agent users support Block or Require compliant device. Policies scoped via "Users" (All users, groups, roles, guests) **do not apply to agent user accounts**. Requires Agent 365 + ≥P1/E3, or M365 E7. New beta properties: `clientApplications.includeAgentIdServicePrincipals`/`excludeAgentIdServicePrincipals`/`agentIdServicePrincipalFilter`, `conditions.agentIdRiskLevels`, `users.includeUsers: ["AllAgentIdUsers"]`, `applications.includeApplications: ["AllAgentIdResources"]`. | "All users" MFA policies don't cover agent users; separate rules are needed. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id ; https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant ; https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/beta/api/conditionalaccessroot-post-policies.md |
| **Require risk remediation** grant (`riskRemediation`) | New evolvable enum member, returned only with header `Prefer: include-unknown-enum-members`. Must be combined with `authenticationStrength` using AND. Automatically applies sign-in frequency every time. Precedence: Block > risk remediation > password change. | Accept as a valid replacement for `passwordChange` in high-user-risk checks. | https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0 ; managed-policies page |
| **Register security information covers WHfB / macOS Platform SSO** | From **July 6, 2026**, policies on the `urn:user:registersecurityinfo` user action apply during Windows Hello for Business and macOS Platform SSO credential registration. | Weak registration policies now also gate WHfB enrollment. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration |
| **Azure DevOps removed from Windows Azure Service Management API** | Sept 2–18, 2025 (MC1123830). Policies on `797f4846-ba00-4fd7-ba43-dac1f8f63013` no longer cover Azure DevOps (`499b84ac-1321-427f-aa17-267ca6975798`). | Azure-management gap rule must also check Azure DevOps when All resources isn't used. | https://mc.merill.net/message/MC1123830 ; cloud-apps page ("no longer cover Azure DevOps") |
| **Location condition renamed "Network"** | The UI moved it to Assignments. Graph is unchanged (`conditions.locations`). Adds the "All Compliant Network locations" option (Global Secure Access). | None for the schema. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network |
| **Classic policies** | Stopped enforcing after July 10, 2024. | Ignore them, or flag if present. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common |
| GSA `applications.networkAccess` / `globalSecureAccess` | Deprecated; stopped returning data June 1, 2025. | Ignore. | https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta |

---

## 1. Policy evaluation semantics

Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies (unless noted)

1. **All applicable policies must be satisfied.** "Multiple Conditional Access policies can apply to an individual user at any time. In this case, all applicable policies must be satisfied." For example, MFA in one policy plus compliant device in another means both are required. There is no priority or ordering between policies.
2. **Block wins.** In Phase 2 (enforcement), "If there's a policy that is configured with the block grant control, enforcement stops here and the user is blocked." A grant in another policy can't override a block.
3. **Assignments are ANDed.** "All assignments are logically combined using AND. If you have more than one assignment configured, all assignments must be satisfied to trigger a policy." Users ∧ target resources ∧ network ∧ each configured condition. Within a single condition, the included values are ORed. For example, `includePlatforms: ["android","iOS"]` matches either platform.
4. **Exclude beats include.** "When organizations both include and exclude a user or group, the user or group is excluded from the policy. The exclude action overrides the include action." The same applies to apps, platforms, locations, and so on (each condition has include/exclude). Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups
5. **Two-phase evaluation.** Phase 1 collects session details (network, device identity) for **enabled and report-only** policies. Phase 2 enforces **enabled** policies only. Unmet grants are prompted in this order: MFA → compliant device → hybrid joined → approved client app → app protection → password change → terms of use → custom controls. Session controls apply only after all grants are satisfied.
6. **States** (`state`):
   - `enabled`: enforced.
   - `enabledForReportingButNotEnforced` (report-only): evaluated and logged as Report-only Success, Failure, User action required, or Not applied. Never enforced. **User actions** (security info registration, device registration) **can't be evaluated in report-only.** Report-only policies that require a compliant device can still show certificate prompts on macOS, iOS, and Android. Report-only GPS-location policies still prompt for GPS, and declining may cause a block. Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only ; network page.
   - `disabled`: ignored.
7. **Grant operator.** `grantControls.operator` is `AND` (require all selected controls; the default) or `OR` (require one of the selected controls). With OR, "prompts appear in the defined order. Once the policy requirements are satisfied, access is granted." The weakest alternative therefore defines the policy's strength. Graph may return `operator: "OR"` even for a single control such as `block`, so don't infer intent from the operator when there's only one control.
8. **Tokens and timing.** Role- and group-targeted policies are evaluated only at token issuance. Users newly added to a role or group aren't covered until they get a new token. CA runs **after first-factor authentication**, so it isn't a DoS or front-line control. Location is re-evaluated at token refresh, which defaults to roughly hourly. Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview ; network page.
9. **Minimum for an enforceable policy.** Name, users (or workload/agent identities), target resources, and grant or block (or session) controls. A policy with `includeUsers: ["None"]` or no target resources applies to nobody.
10. **Client apps default.** New policies apply to all client app types even when the client-apps condition isn't configured (`clientAppTypes: ["all"]`).
11. **Unsupported role types.** CA "doesn't support users assigned a directory role scoped to an administrative unit or directory roles scoped directly to an object, like through custom roles." Only **built-in, tenant-scoped** directory roles are evaluated.
12. **PIM-eligible role holders are NOT covered** by `includeRoles` until they activate. Microsoft's PIM docs say: "During activation, the user doesn't have a role yet, so the Conditional Access policy wouldn't apply" (https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings). SpecterOps confirmed the same for both include and exclude (https://specterops.io/blog/2024/06/20/how-privileged-identity-management-affects-conditional-access-policies/). Mitigations: target admins by group as well as role; use PIM "On activation, require Conditional Access authentication context".
13. **Group limits.** A user or group belonging to more than 2048 groups (direct + nested) "might be blocked." Nested groups are honored. Groups that contain **service principals** do **not** apply policy to those SPs.
14. **When licenses expire**, policies aren't disabled or deleted. They stay enforced but become read-only.
15. **Service principals are not covered by user-scoped policies.** "Calls made by service principals aren't blocked by Conditional Access policies scoped to users." Source: template user-exclusions text on many pages, e.g. https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa

---

## 2. Conditions and their gotchas

### 2.1 Users, groups, roles, guests (`conditions.users`)

- `includeUsers` special values: `All`, `None`, `GuestsOrExternalUsers` (legacy "all guests" value), and `AllAgentIdUsers` (beta, agent users). Otherwise it holds user object IDs. `excludeUsers` likewise accepts IDs and `GuestsOrExternalUsers`.
- "All users" means all directory users **including B2B guests**, but **not agent users** (see 0).
- `includeRoles`/`excludeRoles` hold **role template IDs** of built-in roles (Graph calls them "Role IDs"; see §6). Only **active** assignments count (see §1.12). Admin-unit-scoped and custom roles are ignored.
- `includeGuestsOrExternalUsers`/`excludeGuestsOrExternalUsers` → `conditionalAccessGuestsOrExternalUsers`:
  - `guestOrExternalUserTypes` is a **flags enum serialized as a comma-separated string** with values `none`, `internalGuest`, `b2bCollaborationGuest`, `b2bCollaborationMember`, `b2bDirectConnectUser`, `otherExternalUser`, `serviceProvider`, `unknownFutureValue`.
  - `externalTenants` has `membershipKind` set to `all` (`#microsoft.graph.conditionalAccessAllExternalTenants`) or `enumerated` (`#microsoft.graph.conditionalAccessEnumeratedExternalTenants`, which has a `members` array of tenant IDs).
  - Source: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessguestsorexternalusers?view=graph-rest-1.0 ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessexternaltenants?view=graph-rest-1.0
- B2B direct connect policies also apply to B2B collaboration users accessing Teams/SharePoint who are eligible for direct connect.
- `serviceProvider` covers CSP/GDAP partner admins. Broad guest blocks can break GDAP.
- Exchange ActiveSync gotcha: EAS can only be scoped when assigning to users/groups. Selecting All users, all guests, or roles "causes all users to be subject of the policy."
- Template-created policies exclude **only the creating admin** by default. Watch for leftover per-admin exclusions.

### 2.2 Workload identities (`conditions.clientApplications`)

- `includeServicePrincipals`: SP object IDs or `ServicePrincipalsInMyTenant`. Also `excludeServicePrincipals` and `servicePrincipalFilter` (custom security attributes).
- **Single-tenant SPs registered in your tenant only.** Microsoft and third-party SaaS apps, multitenant apps, and **managed identities are NOT covered**.
- Requires **Workload Identities Premium** to create or modify. Without it, existing policies keep working but are read-only.
- Grant is **Block only**. Supported conditions: locations, service principal risk (`servicePrincipalRiskLevels`: `low`/`medium`/`high`/`none`), and authentication context. Authentication context can't be combined with users in the same policy.
- Use the **Enterprise app (SP) object ID**, not the app-registration object ID.
- Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity

### 2.3 Agents (preview, beta API)

- Agent identities (app-only): `clientApplications.includeAgentIdServicePrincipals` (`All` or IDs), `excludeAgentIdServicePrincipals`, and `agentIdServicePrincipalFilter` (`CustomSecurityAttribute.*` rules). **Block only.**
- Agent users: `users.includeUsers: ["AllAgentIdUsers"]` or specific IDs. Group-based scoping of agent users isn't supported. Grants are Block or compliant device.
- Agent risk: `conditions.agentIdRiskLevels` (`low`/`medium`/`high`). Agent resources: `applications.includeApplications: ["AllAgentIdResources"]`.
- On-behalf-of (delegated) agent calls are governed by the **user's** policies.
- No CA applies to: blueprint token requests to create agents; the `AAD Token Exchange Endpoint: Public` (`fb60f99c-7a34-4190-8149-302f77469936`); tenants with **security defaults**; API-key access.
- Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id ; beta create-policy examples (link in 0).

### 2.4 Target resources (`conditions.applications`)

- `includeApplications`: `All`, `None`, `Office365`, `MicrosoftAdminPortals`, `AllAgentIdResources` (beta), or appIds.
  - `MicrosoftAdminPortals` = Exchange Admin Center `497effe9-df71-4043-a8bb-14cf78c4b63b`, Azure portal `c44b4083-3bb0-49c1-b47d-974e53cbdf3c`, M365 portal `00000006-0000-0ff1-ce00-000000000000`, and Security & Compliance `80ccca67-54bd-44ab-8625-4b79c4dc7775`. It does **not** include the backend APIs those portals call.
  - Windows Azure Service Management API is `797f4846-ba00-4fd7-ba43-dac1f8f63013`. The appId isn't on the Learn page; it's confirmed by Microsoft Q&A and MC1123830. It covers ARM, the Azure portal and Entra admin center, Azure CLI/PowerShell, Data Lake, App Insights API, and Log Analytics API. It **doesn't** cover Azure DevOps or Microsoft Graph PowerShell.
  - Microsoft Graph itself can't be targeted. It's evaluated against the underlying resources.
  - Some apps aren't in the picker and are only covered by `All`, e.g. Azure AD Graph `00000002-0000-0000-c000-000000000000`.
- `excludeApplications`: any exclusion on an All-resources policy historically created the baseline-scope hole (see 0).
- `includeUserActions`: `urn:user:registersecurityinfo`, `urn:user:registerdevice`.
  - Device registration only supports MFA or authentication strength. Client apps and device filters aren't available. The tenant device setting "Require MFA to register or join devices" **must be No**, or the CA user-action policy isn't properly enforced.
  - User actions can't be evaluated in report-only.
- `includeAuthenticationContextClassReferences`: **DISCREPANCY.** Graph says `c1`–`c25`; the Learn target-resources page says up to 99 (`c1`–`c99`).
- `applicationFilter`: custom-security-attribute rule.
- Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta

### 2.5 Risk (P2)

- `signInRiskLevels` / `userRiskLevels`: `low`, `medium`, `high`, `hidden`, `none`, `unknownFutureValue`.
- `passwordChange` must be AND with `mfa`, the policy must target All resources with no exclusions, and the only other conditions allowed are users and userRisk. `riskRemediation` must be AND with `authenticationStrength`. The two controls can't be combined with each other.
- Risky users are blocked from registering MFA, so users need MFA registered before risk occurs.
- Microsoft's risky-sign-in MMP excludes guests. Risk remediation isn't supported for guests.
- Source: grant-controls Graph page; https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant ; managed-policies page.

### 2.6 Insider risk

- `insiderRiskLevels`: `minor`, `moderate`, `elevated` (flags string). Requires Purview Insider Risk Management with **Adaptive Protection** enabled, plus Entra ID P2.
- Microsoft's template blocks `elevated` for All users/All resources and excludes B2B direct connect, service provider, and other external users.
- Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-insider-risk ; https://learn.microsoft.com/en-us/entra/identity/monitoring-health/recommendation-insider-risk-condition

### 2.7 Device platforms (`conditions.platforms`)

- Values: `android`, `iOS`, `windows`, `windowsPhone`, `macOS`, `linux`, `all`, `unknownFutureValue`.
- **Platform comes from the unverified user-agent and is spoofable.** Use it in block policies or alongside compliance or app-protection policies, never as the sole basis for granting.
- An **unknown platform** (e.g. ChromeOS, or a spoofed/blank UA) matches only `all`. Microsoft recommends a block policy that includes `all` and excludes the supported platforms in use.
- macOS/Linux can't be used when approved-app or APP are the only grant controls, or with "require all".
- Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions ; https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-unknown-unsupported

### 2.8 Network / locations (`conditions.locations`)

- `includeLocations`/`excludeLocations`: named-location IDs, `All`, or `AllTrusted`. `AllTrusted` = trusted-marked named locations **plus legacy MFA trusted IPs** (IPv4 only; not recommended).
- The UI also offers "All Compliant Network locations" (Global Secure Access). Its Graph ID is **UNVERIFIED**.
- IP ranges must be public, and only CIDR masks greater than /8 are allowed. Limits are 195 named locations and 2000 ranges each.
- Country locations can resolve by IP or GPS (Authenticator, hourly prompts, jailbreak check), with an optional "include unknown countries/regions".
- **Proxies/VPNs**: CA uses the egress IP and ignores XFF.
- **Gotcha: location-only trust.** Policies that exclude `AllTrusted` from MFA let anyone on the corporate egress IP (including a compromised device or a malicious insider) skip MFA, and trusted IPs are often over-broad.
- Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network

### 2.9 Client apps (`conditions.clientAppTypes`)

- Values: `all`, `browser`, `mobileAppsAndDesktopClients`, `exchangeActiveSync`, `easSupported`, `other`. `easUnsupported` is deprecated in favor of `exchangeActiveSync`.
- **Legacy authentication = `exchangeActiveSync` + `other`.** "Other" covers SMTP, Autodiscover, Exchange Online remote PowerShell, EWS, IMAP4, MAPI/HTTP, OAB, Outlook Anywhere (RPC/HTTP), Outlook Service, POP3, and Reporting Web Services.
- Legacy clients can't do MFA or pass device state, so any grant (MFA, compliant device) effectively blocks them. Only an **All-users policy whose `clientAppTypes` covers legacy** blocks them. A policy with `clientAppTypes: ["browser","mobileAppsAndDesktopClients"]` and MFA leaves legacy auth **unaddressed**.
- For EAS: Exchange Online should be the only cloud app, and platform scoping is possible only through the Graph API.
- Source: conditions page.

### 2.10 Filter for devices (`conditions.devices.deviceFilter`)

- `{ "mode": "include" | "exclude", "rule": "<dynamic-device syntax>" }`. Properties: deviceId, displayName, deviceOwnership, enrollmentProfileName, isCompliant, manufacturer, mdmAppId, model, operatingSystem, operatingSystemVersion, physicalIds, profileType, systemLabels, trustType (`AzureAD`/`ServerAD`/`Workplace`), extensionAttribute1–15. Maximum 3072 characters.
- **Unregistered devices have all-null properties.** Positive operators never match them; negative operators always do.
  - Therefore an **exclude** filter with a positive operator (e.g. exclude `device.extensionAttribute1 -eq "SAW"`) correctly keeps unregistered devices in scope.
  - An **include** filter with positive operators (e.g. include `device.isCompliant -eq True`) silently skips unregistered devices.
- extensionAttributes are only available when the device is Intune-managed, compliant, or hybrid joined.
- `deviceStates` is deprecated and can't coexist with `devices`.
- Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-condition-filters-for-devices

### 2.11 Authentication flows (`conditions.authenticationFlows.transferMethods`)

- Flags string: `none`, `deviceCodeFlow`, `authenticationTransfer`, `unknownFutureValue`, e.g. `"deviceCodeFlow,authenticationTransfer"`.
- **Protocol tracking**: a session that started with device code flow or authentication transfer remains tracked through refreshes. Later non-DCF requests in that session can be blocked (`AADSTS530036`).
- Since Sept 2024, these policies are enforced on Device Registration Service when targeting All resources. Exclude `01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9` if DCF is used for registration.
- Hybrid-joined/compliant grants don't work with DCF; use MFA instead.
- Microsoft's MMP blocks DCF by default for tenants with no DCF use in the past 25 days (Feb 2025 announcement).
- Source: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows ; https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows ; https://techcommunity.microsoft.com/blog/microsoft-entra-blog/new-microsoft-managed-policies-to-raise-your-identity-security-posture/4286758

### 2.12 Other (beta)

- `conditions.times` appears (null) in beta responses. It's an old, unsupported condition; treat it as **UNVERIFIED/ignore**.
- `partialEnablementStrategy` and `templateId` appear in beta responses. `templateId` is also in v1.0.

---

## 3. Grant and session controls

### 3.1 Grant controls (`grantControls`)

| Control | Graph | Notes | Source |
|---|---|---|---|
| Block | `builtInControls: ["block"]` | Most restrictive; wins over everything. | grant page |
| Require MFA | `"mfa"` | Satisfied by Windows Hello for Business, external authentication methods, and possibly federated MFA claims. **Custom controls do not satisfy MFA.** | grant page; managed-policies FAQ |
| Authentication strength | `authenticationStrength: { id }` | Built-in IDs: MFA `00000000-0000-0000-0000-000000000002`, Passwordless MFA `…0003`, Phishing-resistant MFA `…0004` (`windowsHelloForBusiness`, `fido2`, `x509CertificateMultiFactor`). **Can't be combined with `mfa` in the same policy.** External authentication methods are incompatible with authentication strengths. Doesn't restrict first-factor entry. Requires P1. | https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths ; https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-list-policies?view=graph-rest-1.0 |
| Compliant device | `"compliantDevice"` | Requires Intune (or a supported third-party MDM for Windows). Edge InPrivate counts as noncompliant. Doesn't block Authenticator's `UserAuthenticationMethod.Read`. | grant page |
| Hybrid joined | `"domainJoinedDevice"` | Windows only. | grant page |
| Approved client app | `"approvedApplication"` | **Retired / read-only from June 30, 2026** (see DISCREPANCY in 0). iOS/Android only. | migrate page |
| App protection policy | `"compliantApplication"` | Intune MAM. iOS/Android GA; Edge on Windows preview. Kaizala, Skype for Business, and Visio don't support it. | grant page |
| Password change | `"passwordChange"` | Must be AND with `mfa`, All resources, and user risk. | Graph grant page |
| Risk remediation | `"riskRemediation"` | Must be AND with `authenticationStrength`. Needs the `Prefer: include-unknown-enum-members` header to be returned. | Graph grant page |
| Terms of use | `termsOfUse: [ids]` | — | grant page |
| Custom controls | `customAuthenticationFactors: [ids]` | Preview/legacy; replaced by external authentication methods. | grant page |
| Agent users | Block or `compliantDevice` only. Agent identities: Block only. | | grant page |

### 3.2 Session controls (`sessionControls`)

| Control | Graph (v1.0 unless noted) | Values / gotchas |
|---|---|---|
| App enforced restrictions | `applicationEnforcedRestrictions: { isEnabled }` | Exchange Online and SharePoint Online only. |
| CA App Control (MDCA) | `cloudAppSecurity: { isEnabled, cloudAppSecurityType }` | `mcasConfigured`, `monitorOnly`, `blockDownloads`. Requires Defender for Cloud Apps. Edge for Business can also be used via Purview DLP. |
| Sign-in frequency | `signInFrequency: { isEnabled, type: days\|hours, value, authenticationType: primaryAndSecondaryAuthentication\|secondaryAuthentication, frequencyInterval: timeBased\|everyTime }` | `everyTime` is meant for risky users, risky sign-ins, and Intune enrollment. Known issue: authentication strength and SIF can be satisfied at different times. |
| Persistent browser | `persistentBrowser: { isEnabled, mode: always\|never }` | "All apps should be selected for this session control to work correctly." |
| CAE customization | **beta** `continuousAccessEvaluation: { mode }` | `strictEnforcement`, `disabled`, `strictLocation` (evolvable). `disabled` only works with All resources and no conditions. |
| Disable resilience defaults | `disableResilienceDefaults: bool` | `true` means sessions aren't extended during an Entra outage. |
| Token protection | **beta** `secureSignInSession: { isEnabled }` | Portal: "Require token protection for sign-in sessions". Scope to Windows/iOS/macOS, `mobileAppsAndDesktopClients`, and supported resources. Requires P1. |
| GSA security profile | **beta** `globalSecureAccessFilteringProfile` | Entra Internet Access. |

Sources: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-beta ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-1.0 ; https://learn.microsoft.com/en-us/graph/api/resources/signinfrequencysessioncontrol?view=graph-rest-1.0 ; https://learn.microsoft.com/en-us/graph/api/resources/persistentbrowsersessioncontrol?view=graph-rest-1.0 ; https://learn.microsoft.com/en-us/graph/api/resources/cloudappsecuritysessioncontrol?view=graph-rest-1.0 ; https://learn.microsoft.com/en-us/graph/api/resources/continuousaccessevaluationsessioncontrol?view=graph-rest-beta ; https://learn.microsoft.com/en-us/graph/api/resources/securesigninsessioncontrol?view=graph-rest-beta ; https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-session

> Practical note: read policies from **beta** to see `secureSignInSession`, `continuousAccessEvaluation`, agent properties, and `agentIdRiskLevels`. v1.0 omits them. Send `Prefer: include-unknown-enum-members` to see `riskRemediation` and `strictLocation`.

---

## 4. Common CA gaps: rationale

1. **Legacy auth not blocked.** Legacy protocols can't do MFA. Microsoft says more than 99% of password spray uses legacy auth. Required by SCuBA MS.AAD.1.1v1 (BOD 25-01) and is an MMP/BSM policy.
2. **No MFA for all users on all resources.** Microsoft "recommends creating a baseline multifactor authentication policy targeting all users and all resources (without any resource exclusions)". SCuBA MS.AAD.3.2v2.
3. **Admins without phishing-resistant authentication strength.** Microsoft template (14 roles), SCuBA MS.AAD.3.6v1 (highly privileged roles), and BSM policy. SCuBA MS.AAD.3.1v1 goes further and requires phishing-resistant MFA for **all users**.
4. **Break-glass exclusions (good) vs broad exclusions (bad).** Microsoft recommends excluding emergency-access accounts (and sync accounts). Excluding large groups, roles, guests, or apps creates holes. SCuBA notes "unaccounted exceptions" as a coverage-gap source.
5. **Guests not covered.** "All users" includes guests, but many tenants scope MFA to an employees group. Microsoft has a "Require MFA for guest access" template.
6. **No device compliance/managed-device requirement.** SCuBA MS.AAD.3.7v1 (SHOULD) uses compliant OR hybrid joined. Microsoft's "Secure foundation" templates use compliant OR hybrid OR MFA, and "Require compliant device".
7. **Device code flow not blocked.** A phishing vector (e.g. Storm-2372-style campaigns, **UNVERIFIED** attribution). SCuBA MS.AAD.3.9v1 and an MMP.
8. **No risk-based policies.** SCuBA MS.AAD.2.1v1/2.3v1 (block high user / high sign-in risk); MMPs for risky sign-ins and high-risk users. Requires P2.
9. **Unknown/unsupported platforms not blocked.** Microsoft Zero Trust template; defeats UA-based gaps.
10. **Security info registration not protected.** An attacker with a password can register their own MFA. Microsoft template; SCuBA MS.AAD.3.8v1 (managed device for registration).
11. **Device registration not protected.** An attacker could register a device to obtain a PRT or satisfy device-based policies. Microsoft "Require MFA for device registration".
12. **Azure management not protected.** ARM/CLI/PowerShell are high privilege. Microsoft template. Note the Azure DevOps split.
13. **No sign-in frequency for admins/unmanaged devices** and **persistent browser on unmanaged devices.** Microsoft template "Require reauthentication… / No persistent browser session" (1h SIF + never persistent for non-hybrid or noncompliant devices).
14. **Report-only only.** No enforcement. Common after template deployment and MMP rollout.
15. **Workload identities unprotected.** SPs bypass user CA. SCuBA recommends CA for workload identities but doesn't mandate it (license).
16. **High-risk users not forced to remediate.** Microsoft template / MMP (P2).
17. **Location-only trust.** Excluding `AllTrusted` from MFA or compliance policies.
18. **Policies scoped to empty or deleted groups** → no-op.
19. **Disabled policies.** Includes MMPs turned off.
20. **Policies excluding roles.** Excluding roles (especially Global Administrator) removes the highest-value accounts.
21. **OR-weakened grants.** e.g. `mfa OR compliantDevice` means a compliant device alone skips MFA. `compliantDevice OR domainJoinedDevice OR mfa` (the Microsoft template) is intentional for users but too weak for admins. `mfa OR approvedApplication` may become a no-op post-retirement (**UNVERIFIED** per DISCREPANCY).
22. **Exchange ActiveSync** not included in a legacy block (`clientAppTypes` missing `exchangeActiveSync`).
23. **Authentication transfer** not controlled where personal devices are disallowed (Microsoft `policy-block-authentication-flows`). Low severity; it's a convenience feature on by default.

---

## 5. Microsoft Graph `conditionalAccessPolicy` schema

Endpoints: `GET https://graph.microsoft.com/{v1.0|beta}/identity/conditionalAccess/policies`. Permission: `Policy.Read.All`. Named locations: `/identity/conditionalAccess/namedLocations`. Auth strengths: `/policies/authenticationStrengthPolicies` (v1.0) or `/identity/conditionalAccess/authenticationStrength/policies` (beta).

### 5.1 Top level

| Property | v1.0 | beta | Notes |
|---|---|---|---|
| `id`, `displayName`, `createdDateTime`, `modifiedDateTime` | ✅ | ✅ | |
| `state` | ✅ | ✅ | `enabled`, `disabled`, `enabledForReportingButNotEnforced` |
| `templateId` | ✅ | ✅ (in responses) | Set when created from a template |
| `conditions`, `grantControls`, `sessionControls` | ✅ | ✅ | |
| `description` | — | ✅ "Not used" | |
| `deletedDateTime` | — | ✅ | Soft-delete (30 days; `/deletedItems`) |
| `partialEnablementStrategy` | — | appears in responses | Undocumented — **UNVERIFIED** |

### 5.2 `conditions` (`conditionalAccessConditionSet`)

| Property | Type | v1.0 | beta | Values |
|---|---|---|---|---|
| `users` | conditionalAccessUsers | ✅ | ✅ | `includeUsers`, `excludeUsers`, `includeGroups`, `excludeGroups`, `includeRoles`, `excludeRoles`, `includeGuestsOrExternalUsers`, `excludeGuestsOrExternalUsers` |
| `applications` | conditionalAccessApplications | ✅ | ✅ | `includeApplications`, `excludeApplications`, `includeUserActions`, `includeAuthenticationContextClassReferences`, `applicationFilter {mode, rule}` |
| `clientApplications` | conditionalAccessClientApplications | ✅ | ✅ | `includeServicePrincipals`, `excludeServicePrincipals`, `servicePrincipalFilter`; beta also `includeAgentIdServicePrincipals`, `excludeAgentIdServicePrincipals`, `agentIdServicePrincipalFilter` |
| `clientAppTypes` | collection | ✅ | ✅ | `all`, `browser`, `mobileAppsAndDesktopClients`, `exchangeActiveSync`, `easSupported`, `other` |
| `platforms` | `{includePlatforms, excludePlatforms}` | ✅ | ✅ | `android`, `iOS`, `windows`, `windowsPhone`, `macOS`, `linux`, `all` |
| `locations` | `{includeLocations, excludeLocations}` | ✅ | ✅ | IDs, `All`, `AllTrusted` |
| `devices` | `{deviceFilter {mode, rule}}` | ✅ | ✅ | `include`/`exclude` |
| `deviceStates` | — | — | ✅ deprecated | |
| `signInRiskLevels`, `userRiskLevels` | collection | ✅ | ✅ | `low`, `medium`, `high`, `hidden`, `none` |
| `servicePrincipalRiskLevels` | collection | ✅ | ✅ | `low`, `medium`, `high`, `none` |
| `insiderRiskLevels` | flags string | ✅ | ✅ | `minor`, `moderate`, `elevated` |
| `agentIdRiskLevels` | flags string | — | ✅ | `low`, `medium`, `high` |
| `authenticationFlows` | `{transferMethods}` | ✅ | ✅ | flags string: `none`, `deviceCodeFlow`, `authenticationTransfer` |

Sources: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-1.0 ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessconditionset?view=graph-rest-beta ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessusers?view=graph-rest-beta ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessplatforms?view=graph-rest-1.0 ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesslocations?view=graph-rest-1.0 ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessdevices?view=graph-rest-1.0 ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessclientapplications?view=graph-rest-beta ; https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessauthenticationflows?view=graph-rest-1.0

Parsing gotchas:

- Absent conditions come back as `null` (`platforms`, `locations`, `devices`, `authenticationFlows`) or `[]` (risk arrays). Treat **null/empty as "not configured = applies to everything"**.
- Flags enums (`guestOrExternalUserTypes`, `transferMethods`, `insiderRiskLevels`, `agentIdRiskLevels`) are **comma-separated strings**, not arrays. Split on `,`.
- Enum casing in responses: `iOS`, `macOS`, `AND`/`OR`. Some docs show lowercase `and`; compare case-insensitively.
- `grantControls` may be `null` for session-only policies. `grantControls.authenticationStrength` is returned inline (with `@odata.context`). Whether `allowedCombinations` is always expanded in list responses is **UNVERIFIED**; fetch by ID from authenticationStrengthPolicies if it's missing.

### 5.3 `grantControls`

`operator` (`AND`/`OR`), `builtInControls` (`block`, `mfa`, `compliantDevice`, `domainJoinedDevice`, `approvedApplication`, `compliantApplication`, `passwordChange`, `riskRemediation`*, `unknownFutureValue`), `customAuthenticationFactors[]`, `termsOfUse[]`, and the `authenticationStrength` relationship. Source: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessgrantcontrols?view=graph-rest-1.0

### 5.4 `sessionControls`

v1.0: `applicationEnforcedRestrictions`, `cloudAppSecurity`, `disableResilienceDefaults`, `persistentBrowser`, `signInFrequency`. Beta adds `continuousAccessEvaluation`, `secureSignInSession`, and `globalSecureAccessFilteringProfile` (see §3.2).

### 5.5 Realistic full example (beta GET shape)

```json
{
  "id": "8b9d1c3e-0a4f-4f7e-9d61-2c5a7e1f0b11",
  "templateId": null,
  "displayName": "CA101-Admins-AllResources-PhishingResistantMFA-SIF4h",
  "createdDateTime": "2026-03-04T15:22:10.1234567Z",
  "modifiedDateTime": "2026-09-30T11:02:44.7654321Z",
  "state": "enabled",
  "deletedDateTime": null,
  "partialEnablementStrategy": null,
  "conditions": {
    "userRiskLevels": [],
    "signInRiskLevels": [],
    "servicePrincipalRiskLevels": [],
    "insiderRiskLevels": null,
    "agentIdRiskLevels": null,
    "clientAppTypes": ["all"],
    "platforms": null,
    "locations": null,
    "times": null,
    "deviceStates": null,
    "devices": null,
    "clientApplications": null,
    "authenticationFlows": null,
    "applications": {
      "includeApplications": ["All"],
      "excludeApplications": [],
      "includeUserActions": [],
      "includeAuthenticationContextClassReferences": [],
      "applicationFilter": null
    },
    "users": {
      "includeUsers": [],
      "excludeUsers": [],
      "includeGroups": ["4f1c2b9a-7d3e-4e21-8b0a-9e6f5d4c3b2a"],
      "excludeGroups": ["d2a7e0c1-55b4-4b0f-a1e9-0c3b7f6a9e88"],
      "includeRoles": [
        "62e90394-69f5-4237-9190-012177145e10",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
        "c4e39bd9-1100-46d3-8c65-fb160da0071f",
        "b0f54661-2d74-4c50-afa3-1ec803f12efe",
        "158c047a-c907-4556-b7ef-446551a6b5f7",
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
        "29232cdf-9323-42fd-ade2-1d097af3e4de",
        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
        "966707d0-3269-4727-9be2-8c3a10f19b9d",
        "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
        "e8611ab8-c189-46e8-94e1-60213ab1f814",
        "194ae4cb-b126-40b2-bd5b-6091b380977d",
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
        "fe930be7-5e62-47db-91af-98c3a49a38b1"
      ],
      "excludeRoles": [],
      "includeGuestsOrExternalUsers": null,
      "excludeGuestsOrExternalUsers": null
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": [],
    "customAuthenticationFactors": [],
    "termsOfUse": [],
    "authenticationStrength": {
      "id": "00000000-0000-0000-0000-000000000004",
      "displayName": "Phishing-resistant MFA",
      "policyType": "builtIn",
      "requirementsSatisfied": "mfa",
      "allowedCombinations": ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"]
    }
  },
  "sessionControls": {
    "applicationEnforcedRestrictions": null,
    "cloudAppSecurity": null,
    "continuousAccessEvaluation": null,
    "secureSignInSession": null,
    "disableResilienceDefaults": null,
    "persistentBrowser": { "isEnabled": true, "mode": "never" },
    "signInFrequency": {
      "isEnabled": true,
      "type": "hours",
      "value": 4,
      "authenticationType": "primaryAndSecondaryAuthentication",
      "frequencyInterval": "timeBased"
    }
  }
}
```

`includeGroups` holds a "PIM-eligible admins" group, which covers eligible-but-inactive admins (§1.12). `excludeGroups` is the break-glass group.

Other canonical shapes:

```json
// Block legacy authentication
{ "conditions": { "users": { "includeUsers": ["All"], "excludeGroups": ["<breakglass>"] },
  "applications": { "includeApplications": ["All"] },
  "clientAppTypes": ["exchangeActiveSync", "other"] },
  "grantControls": { "operator": "OR", "builtInControls": ["block"] }, "state": "enabled" }

// Block device code flow
{ "conditions": { "users": { "includeUsers": ["All"], "excludeGroups": ["<breakglass>"] },
  "applications": { "includeApplications": ["All"] }, "clientAppTypes": ["all"],
  "authenticationFlows": { "transferMethods": "deviceCodeFlow" } },
  "grantControls": { "operator": "OR", "builtInControls": ["block"] }, "state": "enabled" }

// Workload identity: block outside trusted IPs (Workload ID Premium)
{ "conditions": { "clientApplications": { "includeServicePrincipals": ["ServicePrincipalsInMyTenant"] },
  "applications": { "includeApplications": ["All"] },
  "locations": { "includeLocations": ["All"], "excludeLocations": ["AllTrusted"] } },
  "grantControls": { "operator": "AND", "builtInControls": ["block"] }, "state": "enabled" }

// Guests: MFA for all external user types, all tenants
{ "conditions": { "users": { "includeGuestsOrExternalUsers": {
      "guestOrExternalUserTypes": "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider",
      "externalTenants": { "@odata.type": "#microsoft.graph.conditionalAccessAllExternalTenants", "membershipKind": "all" } } },
  "applications": { "includeApplications": ["All"] }, "clientAppTypes": ["all"] },
  "grantControls": { "operator": "OR", "builtInControls": ["mfa"] }, "state": "enabled" }
```

---

## 6. Privileged role template IDs

All IDs verified against https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference. In CA, `includeRoles`/`excludeRoles` use these template IDs.

**Microsoft "Require phishing-resistant MFA for admins" list** (identical to the MMP / "MFA for admins" 14-role list; https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa):

| Role | Template ID | SCuBA "highly privileged" |
|---|---|---|
| Global Administrator | `62e90394-69f5-4237-9190-012177145e10` | ✅ |
| Application Administrator | `9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3` | ✅ |
| Authentication Administrator | `c4e39bd9-1100-46d3-8c65-fb160da0071f` | |
| Billing Administrator | `b0f54661-2d74-4c50-afa3-1ec803f12efe` | |
| Cloud Application Administrator | `158c047a-c907-4556-b7ef-446551a6b5f7` | ✅ |
| Conditional Access Administrator | `b1be1c3e-b65d-4f19-8427-f6fa0d97feb9` | |
| Exchange Administrator | `29232cdf-9323-42fd-ade2-1d097af3e4de` | ✅ |
| Helpdesk Administrator | `729827e3-9c14-49f7-bb1b-9608f156bbb8` | |
| Password Administrator | `966707d0-3269-4727-9be2-8c3a10f19b9d` | |
| Privileged Authentication Administrator | `7be44c8a-adaf-4e2a-84d6-ab2649e08a13` | |
| Privileged Role Administrator | `e8611ab8-c189-46e8-94e1-60213ab1f814` | ✅ |
| Security Administrator | `194ae4cb-b126-40b2-bd5b-6091b380977d` | |
| SharePoint Administrator | `f28a1f50-f6e7-4571-818b-6a12f2af6b6c` | ✅ |
| User Administrator | `fe930be7-5e62-47db-91af-98c3a49a38b1` | ✅ |

SCuBA's list (https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md) also adds **Hybrid Identity Administrator** `8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2`.

**Other commonly targeted roles** (recommended extended set for the tool; my judgment, not a Microsoft list):

| Role | Template ID |
|---|---|
| Intune Administrator | `3a2c62db-5318-420d-8d74-23affee5d9d5` |
| Global Reader | `f2ef992c-3afb-46b9-b7cf-a126ee74c451` |
| Security Operator | `5f2222b1-57c3-48ba-8ad5-d4759f1fde6f` |
| Security Reader | `5d6b6bb7-de71-4623-b4af-96380a352509` |
| Teams Administrator | `69091246-20e8-4a56-aa4d-066075b2a7a8` |
| Authentication Policy Administrator | `0526716b-113d-4c15-b2c8-68e3c22b9f80` |
| Compliance Administrator | `17315797-102d-40b4-93e0-432062caca18` |
| Groups Administrator | `fdd7a751-b60b-444a-984c-02652fe8fa1c` |
| Cloud Device Administrator | `7698a772-787b-4ac8-901f-60d6b08affd2` |
| Domain Name Administrator | `8329153b-31d0-4727-b945-745eb3bc5f31` |
| External Identity Provider Administrator | `be2f45a1-457d-42af-a067-6ec1fa63bc45` |
| Exchange Recipient Administrator | `31392ffb-586c-42d1-9346-e59415a2cc4e` |
| Identity Governance Administrator | `45d8d3c5-c802-45c6-b32a-1d70b5e1e86e` |
| Lifecycle Workflows Administrator | `59d46f88-662b-457b-bceb-5c3809e5908f` |
| Attribute Assignment Administrator | `58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d` |
| Authentication Extensibility Administrator | `25a516ed-2fa0-40ea-a2d0-12923a21473a` |
| Global Secure Access Administrator | `ac434307-12b9-4fa1-a708-88bf58caabc1` |
| Windows 365 Administrator | `11451d60-acb2-45eb-a7d6-43d0f0125c13` |
| Microsoft Entra Joined Device Local Administrator | `9f06204d-73c1-4d4c-880a-6edb90606fd8` |
| Agent ID Administrator | `db506228-d27e-4b7d-95e5-295956d6615f` |
| Directory Synchronization Accounts (exclude-candidate; sync service only) | `d29b2b05-8046-44ba-8758-1e26182fcf32` |
| Directory Writers | `9360feb5-f418-4baa-8175-e2a00bac4301` |
| Partner Tier2 Support | `e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8` |

---

## 7. Licensing

| Feature | License | Source |
|---|---|---|
| Conditional Access (any policy), authentication strengths, named locations, filter for devices, session controls (SIF, persistent browser, app-enforced restrictions, CAE, resilience), token protection, authentication flows | **Entra ID P1** (or M365 Business Premium; included in M365 E3/E5/E7 and Entra Suite) | https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview ; https://learn.microsoft.com/en-us/entra/fundamentals/licensing ; auth-strength and token-protection prerequisites |
| Sign-in risk, user risk, password change / risk remediation for risk | **Entra ID P2** (ID Protection) | overview; licensing |
| Insider risk condition | **Entra ID P2** + Purview Insider Risk Management with **Adaptive Protection**. The exact Purview SKU (e.g. M365 E5 / E5 Compliance / IRM add-on) is **UNVERIFIED**. | recommendation-insider-risk-condition; MC807451 |
| Workload identities (SP targeting, SP risk) | **Microsoft Entra Workload ID Premium** | workload-identity page |
| Agents (agent identities, agent users, agent risk) | **Agent 365 + ≥ Entra P1 / M365 E3**, or **M365 E7** | agent-id page; licensing |
| Require compliant device, require app protection policy, approved client app | **Microsoft Intune** (P1 still needed for CA) | grant page |
| Conditional Access App Control (`cloudAppSecurity`) | **Microsoft Defender for Cloud Apps** (or Purview DLP for Edge for Business). Exact SKU bundles are **UNVERIFIED** in this pass. | session page |
| PIM, authentication context on PIM activation | Entra ID P2 / ID Governance (**UNVERIFIED** exact SKU this pass) | PIM docs |
| Compliant Network (GSA) location, GSA security profile | Entra Internet/Private Access (Entra Suite). **UNVERIFIED** exact SKU. | network page |
| CA Optimization Agent | Security Copilot SCUs + P1 | report-only page |
| Microsoft-managed policies | Deployed per eligibility. The risky-sign-in and high-risk-user policies need P2. The MMP page header says "P2 or Business Premium is required to use CA features" (inconsistent with P1 elsewhere). | managed-policies page |

The tool should detect license availability (e.g. `GET /subscribedSkus` service plans `AAD_PREMIUM`, `AAD_PREMIUM_P2`, `INTUNE_A`, `ADALLOM_S_STANDALONE`, Workload ID; the service-plan names are **UNVERIFIED** this pass) and downgrade or skip rules that are impossible to satisfy.

---

## 8. Evaluation model for the tool

Recommended predicates (pseudocode over the Graph JSON):

```
isEnforced(p)        = p.state == "enabled"
isReportOnly(p)      = p.state == "enabledForReportingButNotEnforced"
allUsers(p)          = "All" in p.conditions.users.includeUsers
allResources(p)      = "All" in p.conditions.applications.includeApplications
noAppExclusions(p)   = empty(p.conditions.applications.excludeApplications)
coversAllClients(p)  = clientAppTypes == ["all"] OR {browser,mobileAppsAndDesktopClients,exchangeActiveSync,other} ⊆ clientAppTypes
coversLegacy(p)      = "all" in clientAppTypes OR {"exchangeActiveSync","other"} ⊆ clientAppTypes
unconditioned(p)     = platforms null-or-(include ["all"] AND exclude [])
                      AND locations null-or-(include ["All"] AND exclude [])
                      AND empty(signInRiskLevels) AND empty(userRiskLevels)
                      AND insiderRiskLevels null AND devices.deviceFilter null
                      AND authenticationFlows null
isBlock(p)           = "block" in grantControls.builtInControls
mfaEquivalent(ctrl)  = ctrl == "mfa" OR ctrl is authenticationStrength with requirementsSatisfied=="mfa"
requiresMfa(p)       = operator=="AND": any(ctrl is mfaEquivalent)
                       operator=="OR" : all(ctrl is mfaEquivalent)        // each alternative must be MFA
phishResistant(as)   = as.id == "00000000-0000-0000-0000-000000000004"
                       OR as.allowedCombinations ⊆ {"windowsHelloForBusiness","fido2","x509CertificateMultiFactor"}
                       // custom strengths may add combinationConfigurations (e.g. FIDO2 AAGUID restrictions): still phishing resistant
exclusionsOf(p)      = excludeUsers ∪ excludeGroups(expanded) ∪ excludeRoles ∪ excludeGuestsOrExternalUsers
breakGlass           = user-configured set (UPNs/object IDs/group); default heuristic: ≤ 2–4 cloud-only accounts,
                       not synced, with Global Admin, named like 'breakglass'/'emergency' (heuristic = UNVERIFIED best practice)
```

A baseline requirement **R** is "met" if some `isEnforced` policy satisfies R's scope and control, **after subtracting exclusions** (only break-glass and approved service accounts are tolerated). The same match with `isReportOnly` gives a "report-only only" finding. Because policies are ANDed, a user is protected by control C if **any** enforced policy that applies to them requires C. Gaps come from scope, not conflicts. Block policies narrow access and never weaken another policy.

---

## Gap rule catalog

Severity reflects default exposure; tune for tenant context. "Licensing" is what's required to **remediate**. All rules should run on the **beta** endpoint with `Prefer: include-unknown-enum-members`.

| ID | Title | Severity | Detection logic (Graph JSON) | Licensing | Remediation | Source |
|---|---|---|---|---|---|---|
| CA-001 | Legacy authentication not blocked | **Critical** | No `isEnforced` policy where `allUsers` ∧ `allResources` ∧ `coversLegacy` ∧ `isBlock`, with exclusions ⊆ breakGlass. Also flag if the only legacy-auth block is report-only (an MMP/BSM left in report-only counts as not met). | P1 | Enable the "Block legacy authentication" MMP/BSM, or create the policy: `clientAppTypes:["exchangeActiveSync","other"]`, block. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies ; SCuBA MS.AAD.1.1v1 |
| CA-002 | Exchange ActiveSync not covered by legacy block | High | A legacy block exists with `"other"` in `clientAppTypes` but without `"exchangeActiveSync"` (or `"all"`). | P1 | Add `exchangeActiveSync`. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-conditions |
| CA-003 | No MFA baseline for all users on all resources | **Critical** | No `isEnforced` policy with `allUsers` ∧ `allResources` ∧ `noAppExclusions` ∧ `coversAllClients` ∧ `unconditioned` ∧ `requiresMfa`, exclusions ⊆ breakGlass. Policies that exclude `AllTrusted` don't count (see CA-017). | P1 | Enable the "MFA for all users" MMP or create an equivalent policy (MFA or auth strength ≥ `…0002`). | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps ; SCuBA MS.AAD.3.2v2 |
| CA-004 | All-resources MFA policy has resource exclusions | Medium | The CA-003 candidate has non-empty `excludeApplications`. Report each excluded appId. Note the baseline-scope change (June 2026) and the possible legacy opt-out (**UNVERIFIED** detection). | P1 | Remove exclusions. Use separate, narrowly scoped policies for exceptions. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-enforcement-resource-exclusions |
| CA-005 | Admin roles not required to use phishing-resistant authentication strength | **Critical** | For each of the 14 role IDs (§6; optionally + Hybrid Identity Admin), there is no `isEnforced` policy where the role ∈ `includeRoles` (or `allUsers`), `allResources`, `unconditioned`, and `authenticationStrength` is `phishResistant` (AND, or the sole OR alternative). Report missing roles. | P1 | Enable the BSM/Microsoft template "Require phishing-resistant MFA for admins". | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa ; SCuBA MS.AAD.3.6v1 |
| CA-006 | Admin roles lack any MFA (fallback check) | **Critical** | Same as CA-005 but with `requiresMfa`. Fires only if CA-003 is also unmet for those users. | P1 | MFA-for-admins policy / MMP. | managed-policies page |
| CA-007 | PIM-eligible admins not covered by role-scoped policies | High | Admin policies scope only via `includeRoles` (no `includeGroups`/`allUsers`), AND the tenant has eligible assignments (`GET /roleManagement/directory/roleEligibilityScheduleInstances`) for those roles whose principals aren't covered by another enforced MFA/phishing-resistant policy. | P2 (PIM) | Also include a group of eligible admins, or `allUsers`. Set PIM "On activation, require authentication context" with a policy scoped to users (not the role). | https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings ; https://specterops.io/blog/2024/06/20/how-privileged-identity-management-affects-conditional-access-policies/ |
| CA-008 | Overly broad exclusions | High (Critical if the policy is CA-001/003/005) | Any enforced baseline policy where exclusions ⊄ breakGlass: `excludeGroups` with > N members (default N = 5) after transitive expansion, any `excludeRoles`, `excludeGuestsOrExternalUsers` non-null, or `excludeUsers` containing `GuestsOrExternalUsers`. | P1 | Reduce exclusions to break-glass accounts. Replace service-account exclusions with workload identities or managed identities. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups |
| CA-009 | Break-glass accounts not excluded (lockout risk) | Medium | Configured break-glass IDs aren't in the exclusions of every enforced policy that would block or require controls for all users or admins (excluding risk-based or legacy policies where including them is acceptable). | — | Exclude emergency-access accounts and monitor their sign-ins. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa |
| CA-010 | Policy excludes privileged roles | High | Any enforced policy with `excludeRoles` ∩ {14 admin roles} ≠ ∅ (especially `62e90394-…`). | P1 | Remove the role exclusion; exclude specific break-glass accounts instead. | users/groups page |
| CA-011 | Guests/external users not required to MFA | High | No enforced MFA policy covers guests: neither `allUsers`, `GuestsOrExternalUsers` ∈ `includeUsers`, nor `includeGuestsOrExternalUsers` with all six user types and `membershipKind:"all"`. Also flag the MFA baseline if it excludes guests. | P1 | "Require MFA for guest access" template. Consider cross-tenant MFA trust. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policy-common |
| CA-012 | No managed-device requirement | Medium | No enforced policy with `allUsers` ∧ `allResources` and grant containing `compliantDevice` or `domainJoinedDevice` (AND, or OR among only device controls). Also note the Microsoft variant (`compliantDevice OR domainJoinedDevice OR mfa`) as partial. | P1 + Intune | Require compliant or hybrid joined device (SCuBA MS.AAD.3.7v1). At minimum, enforce for admins. | SCuBA MS.AAD.3.7v1 |
| CA-013 | Admins not required to use a managed device | High | No enforced admin-role policy (§6 roles) requiring `compliantDevice`/`domainJoinedDevice` (AND). | P1 + Intune | "Require compliant or hybrid joined device for administrators" template. | templates page |
| CA-014 | Device code flow not blocked | High | No enforced policy where `allUsers` ∧ `allResources` ∧ `transferMethods` contains `deviceCodeFlow` ∧ `isBlock`, with only documented exclusions (break-glass, Teams Rooms accounts or device filters). Device Registration Service exclusion `01cb2876-…` is acceptable. | P1 | Enable the "Block device code flow" MMP or create the policy. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows ; SCuBA MS.AAD.3.9v1 |
| CA-015 | Authentication transfer not controlled | Low | No enforced block policy with `transferMethods` containing `authenticationTransfer` (informational where BYOD is disallowed). | P1 | Block authentication transfer for groups that may not use personal devices. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-transfer |
| CA-016 | No sign-in risk policy | High | P2 present AND no enforced policy with `allUsers`, `allResources`, and `signInRiskLevels` ⊇ {`high`} requiring `block` or MFA/auth strength (+ SIF `everyTime` recommended). Exclude guests per MMP. | P2 | Enable the "MFA and reauthentication for risky sign-ins" MMP, or block high (SCuBA). | SCuBA MS.AAD.2.3v1 ; managed-policies page |
| CA-017 | Location-only trust bypasses MFA | High | An MFA baseline (CA-003 candidate) has `locations.excludeLocations` containing `AllTrusted` or any named location, OR `includeLocations` ≠ `All`. Also check whether `AllTrusted` includes MFA trusted IPs (legacy MFA service settings; detection via Graph is **UNVERIFIED**). | P1 | Remove the location exclusion. Use device compliance/token protection instead of IP trust. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network |
| CA-018 | High-risk users not blocked or remediated | High | P2 present AND no enforced policy with `allUsers`, `allResources`, `userRiskLevels` ⊇ {`high`} and either `block`, (`passwordChange` AND `mfa`), or (`riskRemediation` AND `authenticationStrength`). | P2 | Enable the "Require remediation for high-risk users" or "Block access for high-risk users" MMP. | managed-policies page ; SCuBA MS.AAD.2.1v1 |
| CA-019 | Unknown/unsupported device platforms not blocked | Medium | No enforced policy with `includePlatforms:["all"]` + non-empty `excludePlatforms`, `allUsers`, `allResources`, and `isBlock`. | P1 | "Block access for unknown or unsupported device platform" template. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-unknown-unsupported |
| CA-020 | Platform condition used to grant/relax access | Medium | An enforced non-block policy uses `platforms` to *exclude* platforms from an MFA/device requirement (UA spoofing lets an attacker claim an excluded platform). | P1 | Use platforms only to scope block or compliance/APP policies; cover excluded platforms elsewhere. | conditions page |
| CA-021 | Security info registration not protected | High | No enforced policy with `includeUserActions` containing `urn:user:registersecurityinfo` (users All, guests handled), grant requiring MFA/auth strength or a managed device (location-only conditions are weak). Note WHfB/Platform SSO enforcement since July 6, 2026. | P1 | "Securing security info registration" template (TAP for onboarding). SCuBA also suggests a managed device (MS.AAD.3.8v1). | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration |
| CA-022 | Device registration/join not protected | Medium | No enforced policy with `urn:user:registerdevice` requiring `mfa`/auth strength. If one exists, also check the tenant device setting "Require MFA to register or join devices" is **No** (otherwise CA isn't properly enforced). | P1 | "Require MFA for device registration" policy. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps |
| CA-023 | Azure management not protected | High | No enforced `allUsers` policy whose `includeApplications` contains `All` (no exclusion of `797f4846-…`) or `797f4846-ba00-4fd7-ba43-dac1f8f63013`, requiring MFA. Sub-finding: Azure DevOps `499b84ac-1321-427f-aa17-267ca6975798` not covered when not using `All`. | P1 | "Require MFA for Azure management" template; add Azure DevOps. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-azure-mgmt ; https://mc.merill.net/message/MC1123830 |
| CA-024 | No sign-in frequency / persistent browser control for unmanaged devices | Medium | No enforced policy (`allUsers`, `allResources`) with a device filter targeting non-managed devices (e.g. `device.trustType -ne "ServerAD" -or device.isCompliant -ne True`, include mode) setting `signInFrequency.isEnabled` and `persistentBrowser.mode:"never"`. | P1 | "Require reauthentication / no persistent browser" template (1h SIF, never persistent). | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-persistent-browser |
| CA-025 | Persistent browser "always" on unmanaged scope | Medium | Any enforced policy with `persistentBrowser.mode == "always"` whose scope isn't restricted to managed devices (no device filter, or a filter that matches unregistered devices). Also flag `persistentBrowser` on policies not targeting `All` resources (control won't work correctly). | P1 | Set `never` for unmanaged devices; restrict `always` to compliant/hybrid devices. | session/persistent-browser Graph page |
| CA-026 | Admins lack sign-in frequency | Low | No enforced admin-role policy with `signInFrequency.isEnabled` (e.g. ≤ 12 hours; threshold is my judgment, **UNVERIFIED** as a Microsoft number). | P1 | Add SIF for privileged roles, or rely on PIM activation reauthentication. | session page |
| CA-027 | Baseline policies only in report-only | High | For every rule above, a policy meets the requirement only when `state == "enabledForReportingButNotEnforced"`. Report as "configured but not enforced". Note user-action policies give no report-only telemetry. | — | Review policy impact, then switch to On. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only |
| CA-028 | Disabled policies (incl. Microsoft-managed opted out) | Low (Medium if MMP) | `state == "disabled"`. Higher severity if `displayName` starts with `Microsoft-managed:` (`templateId` usage for MMPs is **UNVERIFIED**) or the policy would satisfy a Critical rule. | — | Delete stale policies or re-enable them. Document MMP opt-outs. | managed-policies page |
| CA-029 | Policy scoped to empty, deleted, or nonexistent objects | Medium | For each enforced/report-only policy, `includeGroups` where all groups have 0 transitive members (`/groups/{id}/transitiveMembers/$count`), `includeUsers` IDs that don't resolve, roles with no active assignments, or SP IDs that don't resolve. The policy is effectively a no-op. Similarly, `excludeGroups` referencing unknown IDs. | — | Fix the scope or delete the policy. | users/groups page (scope semantics) |
| CA-030 | OR-weakened grant | High for admins/MFA baseline; Medium otherwise | `operator == "OR"` and the alternatives mix MFA-equivalent with non-MFA controls (`compliantDevice`, `domainJoinedDevice`, `compliantApplication`, `approvedApplication`, `termsOfUse`). Effective strength = weakest alternative. Exception: the documented user template (compliant OR hybrid OR MFA) is Medium. For admins it's High. | P1 | Split into separate policies (both are then required), or use AND. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies |
| CA-031 | Uses retired "Require approved client app" | Medium (High if sole control) | `"approvedApplication"` ∈ `builtInControls`. If it's the sole control or OR only with itself, the policy may be unenforceable (MC1220751) or frozen read-only (Learn). **DISCREPANCY.** | Intune | Recreate with `compliantApplication` (APP); disable or delete the old policy. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/migrate-approved-client-app ; https://mc.merill.net/message/MC1220751 |
| CA-032 | Workload identities unprotected | Medium (High if SPs hold high-privilege app roles) | Workload ID Premium present AND no enforced policy with `clientApplications.includeServicePrincipals` (`ServicePrincipalsInMyTenant` or IDs) requiring block outside `locations` or `servicePrincipalRiskLevels` ⊇ {`high`}. Without the license, report informational. | Workload ID Premium | Location-based block and SP-risk block for single-tenant SPs. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/workload-identity |
| CA-033 | Service principals assumed covered via groups | Low | A policy's `includeGroups` contains groups that have service-principal members (CA isn't enforced for SPs via groups). | — | Target SPs directly via `clientApplications`. | workload-identity page |
| CA-034 | Agent users/identities unprotected | Medium (preview) | Tenant has agent identities or agent users AND no enforced policy with `includeAgentIdServicePrincipals` / `includeUsers` containing `AllAgentIdUsers` (block high `agentIdRiskLevels`, allow-list via `agentIdServicePrincipalFilter`). Note that "All users" policies don't cover agent users. | Agent 365 + P1, or M365 E7 | Enable the "Block high risk agents" MMP; create allow-list policies. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id |
| CA-035 | MFA baseline doesn't cover all client app types | High | The CA-003 candidate has `clientAppTypes` ≠ `["all"]` and omits `browser` or `mobileAppsAndDesktopClients`. | P1 | Set `clientAppTypes:["all"]`. | conditions page |
| CA-036 | Include-mode device filter with positive operators on a protective policy | Medium | `deviceFilter.mode == "include"` with only positive operators (`-eq`, `-startsWith`, `-in`, `-contains`) on a policy that grants or requires controls means unregistered (attacker) devices aren't matched. Conversely, `mode == "exclude"` with negative operators excludes unregistered devices. | P1 | Invert the logic: exclude-mode + positive operators, or include-mode + negative operators. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-condition-filters-for-devices |
| CA-037 | Custom controls used as MFA | Medium | `customAuthenticationFactors` non-empty on a policy intended as MFA. Custom controls don't satisfy the MFA claim. | P1 | Migrate to external authentication methods. | managed-policies FAQ |
| CA-038 | Insider risk not used | Low | P2 + Purview Adaptive Protection present (detection **UNVERIFIED**) AND no enforced policy with `insiderRiskLevels` containing `elevated` + block. | P2 + Purview IRM | "Block access for users with insider risk" template. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-insider-risk |
| CA-039 | Resilience defaults disabled broadly | Low | `sessionControls.disableResilienceDefaults == true` on a broad (`allUsers`/`allResources`) policy: outage means lockout. (May be intentional for high-security apps.) | P1 | Restrict to specific sensitive apps/users. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-session |
| CA-040 | CAE disabled | Low | Beta `continuousAccessEvaluation.mode == "disabled"`. | P1 | Remove the customization; consider `strictLocation`. | https://learn.microsoft.com/en-us/graph/api/resources/continuousaccessevaluationsessioncontrol?view=graph-rest-beta |
| CA-041 | No token protection for privileged/sensitive users | Low (maturity) | No enforced policy with beta `secureSignInSession.isEnabled == true` covering admins on Windows/macOS/iOS for Exchange/SharePoint/Teams. | P1 | Pilot token protection via report-only. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection |
| CA-042 | Policies with no effective controls | Low | `grantControls` null/empty AND `sessionControls` all null/disabled; or `includeUsers:["None"]` with no groups/roles/guests/SPs; or `includeApplications:["None"]` with no user actions/auth contexts. | — | Delete, or configure controls. | concept-conditional-access-policies |
| CA-043 | Security defaults state inconsistent | Info | `GET /policies/identitySecurityDefaultsEnforcementPolicy` `isEnabled == true` while CA policies exist, or `isEnabled == false` with no CA baseline. (Mutual exclusivity of security defaults and CA is well known but not re-verified this pass: **UNVERIFIED**.) | — | Use CA (P1) or keep security defaults. | https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview |

### Notes on rule implementation

- **Group expansion**: use `transitiveMembers` for includes and excludes. Nested groups are honored by CA.
- **Exclusion arithmetic**: compute, per baseline rule, the set of identities *not* covered (included minus excluded) and compare it to the break-glass allow-list. Report counts and the top identities.
- **Licensing gating**: downgrade P2/Workload/Intune/Agent-dependent rules to "informational" if the SKU is absent.
- **Graph version**: read from beta for completeness. Fall back to v1.0 and mark beta-only checks (CA-034, CA-040, CA-041, `riskRemediation`) as "not assessable".
