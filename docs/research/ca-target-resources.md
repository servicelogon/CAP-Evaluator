# Conditional Access — Target Resources Coverage (research notes)

Research date: 2026-10-26. Sources are Microsoft Learn unless noted. Documentation history was checked against the public `MicrosoftDocs/entra-docs` GitHub repo, which is the source of the Learn pages.

Labels used in this document:

- **VERIFIED**: stated on a current Microsoft Learn page (URL cited).
- **VERIFIED (history)**: confirmed from the git history of the Learn source in `MicrosoftDocs/entra-docs`.
- **COMMUNITY**: reported by Microsoft Q&A answers, MSRC-confirmed researcher posts, or blogs, but not stated on a Learn reference page.
- **UNVERIFIED**: could not be confirmed from an authoritative source. Treat as a hypothesis.

Primary sources:

- [S1] Targeting resources in CA policies — https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps
- [S2] Office 365 app reference — https://learn.microsoft.com/en-us/entra/identity/conditional-access/reference-office-365-application-contents
- [S3] Enforcement for baseline scopes — https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-enforcement-resource-exclusions
- [S4] Graph `conditionalAccessApplications` (v1.0) — https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-1.0
- [S5] Graph `conditionalAccessApplications` (beta) — https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessapplications?view=graph-rest-beta
- [S6] Service dependencies — https://learn.microsoft.com/en-us/entra/identity/conditional-access/service-dependencies
- [S7] Mandatory MFA for Azure and admin portals — https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication
- [S8] Require MFA for admin portals — https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-mfa-admin-portals
- [S9] Require MFA for Azure management — https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-old-require-mfa-azure-mgmt
- [S10] Require device compliance — https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance
- [S11] Grant controls — https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-grant
- [S12] Authentication flows (device code / transfer) — https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows
- [S13] Security info registration policy — https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration
- [S14] Troubleshooting / audience reporting — https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access
- [S15] Azure DevOps CA — https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/conditional-access-policies?view=azure-devops
- [S16] Intune MFA for enrollment — https://learn.microsoft.com/en-us/intune/device-enrollment/configure-multifactor-authentication
- [S17] Terms of use (Intune Enrollment ToU limitation) — https://learn.microsoft.com/en-us/entra/identity/conditional-access/terms-of-use
- [S18] Compliant/hybrid/MFA policy — https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-alt-all-users-compliant-hybrid-or-mfa
- [S19] Zero Trust common policies — https://learn.microsoft.com/en-us/security/zero-trust/zero-trust-identity-device-access-policies-common
- [S20] Verify first-party apps — https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in
- [S21] Power Platform first-party app IDs — https://learn.microsoft.com/en-us/power-platform/admin/apps-to-allow
- [S22] Purview encryption and Entra config (RMS) — https://learn.microsoft.com/en-us/purview/encryption-azure-ad-configuration
- [S23] Azure AD PowerShell migration FAQ — https://learn.microsoft.com/en-us/powershell/azure/active-directory/migration-faq?view=azureadps-2.0
- [S24] GSA Microsoft traffic CA — https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-target-resource-microsoft-365-profile
- [S25] Graph Internet Access tutorial — https://learn.microsoft.com/en-us/graph/tutorial-entra-internet-access
- [S26] CA for agents — https://learn.microsoft.com/en-us/entra/identity/conditional-access/agent-id
- [S27] Microsoft-managed policies — https://learn.microsoft.com/en-us/entra/identity/conditional-access/managed-policies
- [S28] Doc source history — https://github.com/MicrosoftDocs/entra-docs/commits/main/docs/identity/conditional-access/concept-conditional-access-cloud-apps.md

---

## 0. Recent changes (2024–2026) at a glance

| When | Change | Status / source |
|---|---|---|
| Between Nov 2023 and Mar 2024 | The "Microsoft Azure Management" target was renamed "Windows Azure Service Management API". The app ID stayed `797f4846-ba00-4fd7-ba43-dac1f8f63013`. | VERIFIED (history) [S28] |
| May–Oct 2026 | In many tenants the CA picker now shows app `797f4846-…` as **"Azure Resource Manager"**. Learn still uses "Windows Azure Service Management API". | COMMUNITY ([Q&A, Oct 2026](https://learn.microsoft.com/en-us/answers/questions/6027179/windows-azure-service-management-api-not-available); [Q&A](https://learn.microsoft.com/en-us/answers/questions/5866691/az-login-with-no-mfa)) |
| Sep 2024 | Authentication-flows policies (for example, device code) targeting **All resources** began enforcing on Device Registration Service. | VERIFIED [S12] |
| Oct 2024 / Feb 2025 / Oct 1 2025 | Mandatory Azure MFA. Phase 1 covers the Azure portal, Entra admin center and Intune admin center, plus the M365 admin center from Feb 2025. Phase 2 covers CLI, PowerShell, mobile app, IaC and REST create/update/delete calls. Phase 2 can be postponed to Jul 1 2026 at the latest. | VERIFIED [S7] |
| Mar 30 2024 → 2025 | MSOnline and AzureAD PowerShell were deprecated. MSOnline retired Apr–May 2025. AzureAD retired mid-Oct to mid-Nov 2025. Azure AD Graph API retired around Sep 2025. | VERIFIED [S23]; [Entra blog](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/important-update-azuread-powershell-retirement/4364989) |
| Sep 2025 | Windows Azure Service Management API CA policies **no longer cover Azure DevOps**. ADO must be targeted directly (`499b84ac-1321-427f-aa17-267ca6975798`). | VERIFIED [S1][S15] |
| Feb 2026 | The documented "Microsoft Admin Portals" membership changed from 8 named portals to **4 resource app IDs**, with an explicit statement that backend services are not included. | VERIFIED (history) [S28]; current [S1] |
| Mar 2026 → Jun 15 2026 | **Baseline-scope enforcement**. All-resources policies that have resource exclusions now enforce on sign-ins that request only OIDC or low-privilege directory scopes. [S1] says phased rollout "starting in March 2026". [S3] says rollout "began on June 15, 2026". | VERIFIED [S1][S3] (the two pages give different dates) |
| Early Mar 2026 | "Require approved client app" grant retired. Migrate to "Require app protection policy". | VERIFIED [S11] |
| Jul 6 2026 | Policies targeting **Register security information** now apply to Windows Hello for Business and macOS Platform SSO credential registration. | VERIFIED [S13] |
| Nov 2025 (Ignite) onward | New target types: **All agent resources (Preview)**, plus agent identities and agent users as subjects. | VERIFIED [S1][S26] |
| Jun 1 2025 | Graph beta `applications.networkAccess` and `applications.globalSecureAccess` were deprecated and stopped returning data. GSA profiles are now represented as applications. | VERIFIED [S5] |

---

## 1. Office 365 app group

- Graph value: `includeApplications` / `excludeApplications` contains the literal string **`Office365`** [S4].
- Microsoft recommends the group over individual apps to avoid service-dependency inconsistencies. For example, Exchange metadata can be exposed through Search, and Teams depends on SharePoint and Exchange [S1][S2][S6].
- **Membership** [S2] (display names only; Microsoft does not publish app IDs for the list and says it "is subject to change"):

  AI Hub Services; App Studio for Microsoft Teams; Augmentation Loop; Call Recorder; Connectors; Copilot Data Platform; DataSecurityInvestigation; Device Management Service; EDU Assignments; EnrichmentSvc; Enterprise Copilot Platform; Groups Service; IC3 Gateway; IC3 Gateway Non Cae; Insights Services; INT Augmentation Loop 1P; Legacy Smart Compose; Loop; Loop Web Application; Loop Web Service; M365 Admin Services; M365 Auditing Public Protected Web API app; M365ChatClient; make.gov.powerapps.us; make.powerapps.com; Media Analysis and Transformation Service; Message Recall; Messaging Async Media; MessagingAsyncMediaProd; Microsoft 365 eSignature; Microsoft 365 eSignature PPE; Microsoft 365 Reporting Service; Microsoft Discovery Service; Microsoft Exchange Online Protection; Microsoft Flow Portal; Microsoft Flow Portal GCC; Microsoft Forms; Microsoft Forms Web; Microsoft Information Protection API; Microsoft Office; Microsoft Office 365 Portal; Microsoft People Cards Service; Microsoft Planner; Microsoft Planner Client; Microsoft SharePoint Online - SharePoint Home; Microsoft Stream Portal; Microsoft Stream Service; Microsoft Teams; Microsoft Teams - T4L Web Client; Microsoft Teams - Teams And Channels Service; Microsoft Teams Analytics; Microsoft Teams Chat Aggregator; Microsoft Teams Graph Service; Microsoft Teams Mailhook; Microsoft Teams Retail Service; Microsoft Teams Services; Microsoft Teams Targeting Application; Microsoft Teams UIS; Microsoft Teams Web Client; Microsoft To-Do web app; Microsoft Todo web app; Microsoft Virtual Events Portal; Microsoft Virtual Events Services; Microsoft Visio Data Visualizer; Microsoft Whiteboard Services; MSAI Substrate Meeting Intelligence; Natural Language Editor; O365 Diagnostic Service; O365 Suite UX; O365 Suite UX PathFinder; OCPS Checkin Service; Office 365; Office 365 Exchange Microservices; Office 365 Exchange Online; Office 365 Search Service; Office 365 SharePoint Online; Office Collab Actions; Office Delve; Office Hive; Office Hive Fairfax; Office MRO Device Manager Service; Office Notification Service; Office Online Add-in SSO; Office Online Augmentation Loop SSO; Office Online Core SSO; Office Online Loki SSO; Office Online Maker SSO; Office Online Print SSO; Office Online Search SSO; Office Online Service; Office Online Speech SSO; Office Scripts Service (+ INT/Local/Test); Office Shredding Service; Office.com; Office365 Shell DoD WCSS-Client; Office365 Shell WCSS-Client; OfficeClientService; OfficeHome; OfficePowerPointSGS; OfficeServicesManager; Olympus; OMEX External; One Outlook Web; OneDrive; OneDrive SyncEngine; OneNote; OneOutlook; Outlook Browser Extension; Outlook Service for Exchange; PowerApps Service; Project for the web; ProjectWorkManagement (+ _AdminTools, _USGov); Protection Center; Reply-At-Mention; SharePoint Notification Services (+ Fairfax); SharePoint Online Web Client Extensibility (+ Isolated); Skype and Teams Tenant Admin API; Skype for Business; Skype for Business Online; Skype Presence Service; Sway; Targeted Messaging Service; Teams CMD Services Artifacts; Teams Device Management Services; Teams Walkie Talkie Service (+ GCC); Viva Engage.

- Members relevant to gap analysis:
  - **Microsoft Office 365 Portal** (`00000006-0000-0ff1-ce00-000000000000`) and **Protection Center** (`80ccca67-…`) are both in Office 365 **and** in Microsoft Admin Portals.
  - **M365 Admin Services** and **Skype and Teams Tenant Admin API** are admin back-ends that are in Office365 but not in Admin Portals.
  - make.powerapps.com, PowerApps Service and Microsoft Flow Portal are in Office365. Power Platform admin center (`065d9450-…`) is **not** listed.
- App IDs for key members:
  - Exchange Online: `00000002-0000-0ff1-ce00-000000000000` [S21]
  - SharePoint Online: `00000003-0000-0ff1-ce00-000000000000` (COMMUNITY: first-party list derived from docs; widely used)
  - Microsoft Teams Services: `cc15fd57-2c6c-4117-a88c-83b1d56b4bbe` [S21]
  - Office 365 Portal: `00000006-0000-0ff1-ce00-000000000000` [S1]
  - Protection Center: `80ccca67-54bd-44ab-8625-4b79c4dc7775` [S1]
  - **UNVERIFIED**: there is no official Microsoft list mapping every Office 365 member to an app ID. Microsoft directs admins to enumerate service principals owned by tenant `f8cdef31-a31e-4b4a-93e4-5f571e91255a` and notes this "approximates" the suite [S2].

---

## 2. Microsoft Admin Portals app group

- Graph value: **`MicrosoftAdminPortals`** [S4].
- **Current membership** [S1] (since late Feb 2026): "policy is enforced for tokens issued to specific underlying resource application IDs":

| Member | App ID |
|---|---|
| Exchange Admin Center | `497effe9-df71-4043-a8bb-14cf78c4b63b` |
| Azure portal | `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` |
| Microsoft Office 365 Portal | `00000006-0000-0ff1-ce00-000000000000` |
| Microsoft 365 Security and Compliance Center (Protection Center) | `80ccca67-54bd-44ab-8625-4b79c4dc7775` |

- Caveats from [S1]:
  - "The app grouping **doesn't include the backend services** that those portals might call or depend on." Use audience reporting [S14] to find dependencies.
  - The grouping is meant for include scenarios. It is "not intended to function as a bulk exclusion mechanism".
  - Block policies on Admin Portals also block end users from the M365 self-install page, which lives in the M365 admin center.
  - It is used by the Microsoft-managed policy "MFA for admins accessing Microsoft Admin portals", which covers 14 roles [S27].
- **Before the change** (VERIFIED (history) [S28], through Jan 2026): the docs listed portal names: Azure portal, Exchange admin center, Microsoft 365 admin center, Microsoft 365 Defender portal, Microsoft Entra admin center, Microsoft Intune admin center, Microsoft Purview compliance portal, Microsoft Teams admin center ("We're continually adding more…"). An interim Feb 25 2026 revision mapped them as:
  - Entra admin center → Azure portal app ID `c44b4083…`
  - Intune admin center → `c44b4083…`
  - Purview portal → `80ccca67…`
  - Teams admin center → `00000006…`
- CIS M365 v4 (5.2.2.8) and third-party tools still quote a 10-portal list that also includes Power Platform and SharePoint admin centers. That list is **not** on Microsoft Learn (COMMUNITY: [Tenable/CIS](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v4.0.0_L2_E5.audit:f2fc6a68b5652036e394347d5e7081af)).

### Portal-by-portal coverage

Covered at sign-in means the token for the portal front end is issued to one of the four IDs. Backend calls the portal makes after sign-in (Graph, Intune API, ARM, and so on) are evaluated against their own resources.

| Admin surface | Front-end covered by `MicrosoftAdminPortals`? | Evidence | Backend/API covered? |
|---|---|---|---|
| Azure portal | **Yes** (`c44b4083`) | [S1] | ARM (`797f4846` group) **no** |
| Microsoft Entra admin center | **Yes**, it uses the Azure portal app ID | [S1] ("Azure portal, which also covers the Microsoft Entra admin center"), [S7] | Microsoft Graph **no**, and Graph is not targetable |
| Microsoft Intune admin center | **Yes at sign-in**, it uses `c44b4083` | [S7] table; history [S28] | **No**. Microsoft Intune API `0000000a-0000-0000-c000-000000000000`, Microsoft Graph and Intune portal extension (`5926fc8e-…`) are separate resources. UNVERIFIED which audiences the portal actually requests; check audience reporting. |
| Microsoft Intune / Microsoft Intune Enrollment (apps) | **No**. These are not portals. | [S1] | n/a |
| Exchange admin center | **Yes** (`497effe9`) | [S1] | Exchange Online `00000002-0000-0ff1…` **no**. Exchange Online PowerShell **no**. |
| Microsoft 365 admin center | **Yes** (`00000006`) | [S1][S7] | M365 Admin Services, Graph and ARM **no**. Partly in Office365. |
| Teams admin center | **Likely yes** (`00000006`) | interim Feb 2026 doc only [S28]. **UNVERIFIED** in current doc. | Skype and Teams Tenant Admin API **no** (it is in Office365) |
| Microsoft Purview portal | **Likely yes** (`80ccca67`) | interim Feb 2026 doc only [S28]. **UNVERIFIED** in current doc. | no |
| Microsoft Defender portal (security.microsoft.com) | **UNVERIFIED**. Listed by name until Jan 2026. The app-ID mapping was never published. Plausibly `80ccca67` or another app. | [S28] | no |
| SharePoint admin center | **UNVERIFIED / probably no**. It is served by SharePoint Online (`00000003-0000-0ff1…`), which is in Office365, not Admin Portals. | CIS lists it; Learn never did | — |
| Power Platform admin center (`065d9450-1e87-434e-ac2f-69af271549ed` [S21]) | **UNVERIFIED / probably no**. Never in the Learn list. | — | — |
| Azure CLI, Azure PowerShell, Graph PowerShell, Exchange/Teams PowerShell | **No**. Up to Mar 2025 the docs said Admin Portals "applies to interactive sign-ins to the listed admin portals only… not Microsoft Graph or ARM APIs". | [S28] history | — |

---

## 3. Windows Azure Service Management API (Azure management)

- App ID `797f4846-ba00-4fd7-ba43-dac1f8f63013`. Formerly "Microsoft Azure Management". It may now display as "Azure Resource Manager" (COMMUNITY, 2026). A tool should **key on app ID, never display name**.
  - ID source: Learn Dev Box doc (https://learn.microsoft.com/en-us/azure/dev-box/how-to-configure-intune-conditional-access-policies) and Microsoft Q&A.
- In Azure Government, target "Azure Government Cloud Management API" instead [S1].
- **Grouping includes the app IDs of** [S1]:
  - Azure Resource Manager
  - Azure portal (which also covers the **Microsoft Entra admin center** and Microsoft Engage Center)
  - Azure Data Lake
  - Application Insights API
  - Log Analytics API
- **Indirectly affected** clients and services (they depend on the Azure API) [S1]: Azure CLI, Azure Data Factory portal, Azure Event Hubs, Azure PowerShell, Azure Service Bus, Azure SQL Database, Azure Synapse, classic deployment model APIs, Microsoft 365 admin center, Microsoft IoT Central, Microsoft Defender Multitenant management, SQL Managed Instance, Visual Studio subscriptions administrator portal.
- **IaC tools** (Bicep, ARM templates, Terraform azurerm) call ARM through CLI or PowerShell identities, so they are covered by the ARM target [S7]. Mandatory MFA treats IaC as "use Azure CLI or Azure PowerShell IDs".
  - Bicep and ARM are not named individually in [S1]. Coverage follows from their use of `management.azure.com`.
- **Not covered**:
  - **Azure DevOps** since Sep 2025 [S1][S15]
  - **Microsoft Graph PowerShell** and Microsoft Graph API [S1]
  - Graph Explorer (uses Graph)
  - Azure AD Graph and directory reads
  - Entra admin center **API calls**: the portal front end is covered via `c44b4083`, but the data plane is Graph
- The [S6] dependency table shows Azure Data Lake, Power Apps and Visual Studio depend on this target with early-bound enforcement. The Azure portal also early-binds to Exchange, SharePoint, M365 Reporting Service and Windows 365.
- Mandatory MFA (platform enforcement, not CA) [S7]:
  - Phase 2 is enforced server-side on `https://management.azure.com` for create, update and delete operations.
  - Microsoft Graph APIs are "generally" not in scope.
  - Workload identities are not in scope.
  - CA exclusions do not exempt users from this enforcement.

---

## 4. Microsoft Graph–based admin tooling

| Tool | Client app ID | How it appears to CA | Source |
|---|---|---|---|
| Microsoft Graph PowerShell ("Microsoft Graph Command Line Tools") | `14d82eec-204b-4c2f-b7e8-296a70dab67e` | Public client, so it **cannot be targeted as a resource**. The resource is Microsoft Graph, which is **not individually targetable**. | [S20] (ID), [S1] |
| Graph Explorer | `de8bc8b5-d9f9-48b1-a8ad-b748da725064` | Web app calling Graph. Community reports show it can be selected or blocked in CA (for example a guest block in 2022, or via custom-security-attribute filter). **UNVERIFIED** in current Learn. | [S20] (ID); COMMUNITY ([office365itpros](https://office365itpros.com/2022/08/29/graph-explorer-guest-access/)) |
| Microsoft Graph (resource) | `00000003-0000-0000-c000-000000000000` | "Admins can assign a CA policy to Microsoft cloud apps … **except for Microsoft Graph** … an umbrella resource. Use audience reporting to see underlying services." | [S1] |
| Windows Azure Active Directory / Azure AD Graph (resource) | `00000002-0000-0000-c000-000000000000` | Not in the picker. It is included in **All resources** and can be targeted only via a **custom security attribute app filter**. Since 2026 it is the evaluation audience for baseline scopes. | [S1][S3] |
| Azure Active Directory PowerShell (AzureAD/MSOnline) | `1b730954-1685-4b74-9bfd-dac224a7b894` | **Retired**: MSOnline Apr–May 2025, AzureAD mid-Oct to mid-Nov 2025 | [S21] (ID), [S23] |
| Microsoft Entra PowerShell | **UNVERIFIED** client ID | Uses Graph, so it has the same limits as Graph PowerShell | — |
| Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Public client. Covered when calling ARM via `797f4846`. Graph calls (for example `az ad`) are **not** covered by ARM. | [S7][S21] |
| Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` | Same as Azure CLI. `Get-AzAD*` calls Graph. | [S7][S21] |
| Azure mobile app | `0c1307d4-29d6-4389-a11c-5cbe7f65d7fa` | Calls ARM | [S7] |

**How to protect Graph-based tooling in CA:**

1. Use **All resources** with no exclusions. This is the only documented way to cover Graph, since Graph itself can't be selected.
2. Alternatively, target `Windows Azure Active Directory` via a custom-security-attribute filter [S1].
3. Outside CA, set "Assignment required" or "Enabled for users to sign in = No" on the Graph Command Line Tools and Graph Explorer service principals (COMMUNITY).
4. Use custom app registrations for Graph PowerShell; tenant-owned apps can be targeted (COMMUNITY: ourcloudnetwork.com).

Since the baseline-scopes change, a public client requesting only `User.Read` (such as Azure CLI) is evaluated against Azure AD Graph under All-resources policies that have exclusions [S3].

---

## 5. Apps with special or limited CA behavior

| App / resource | ID | Behavior | Source |
|---|---|---|---|
| Microsoft Intune Enrollment | `d4ebce55-015a-49b5-a083-c84d1797ae8c` | Targetable. **Not created automatically in new tenants**, so admins must create the service principal. Use it to require MFA at enrollment ("Don't configure device-based access rules for Microsoft Intune enrollment"). Not supported for per-device Terms of Use; exclude it from ToU policies. | [S16][S17] |
| Microsoft Intune | `0000000a-0000-0000-c000-000000000000` | Targetable. With Apple ADE, MFA on Intune prompts at Setup Assistant **and** every Company Portal sign-in. | [S16]; ID COMMUNITY |
| Microsoft Intune Web Company Portal | `74bcdadc-2fdc-4bb3-8459-76d06952a0e9` | "Require compliant device" **does not block** Intune enrollment or access to this app. This is a built-in carve-out, so **no exclusion is needed**. Community reports say it requests Azure AD Graph as its resource. | [S18][S19]; COMMUNITY |
| Microsoft Intune Company Portal (client) | `9ba1a5c7-f17a-4de9-a1f1-6178c8d51223` | Client app, not a resource | [S21] |
| Device Registration Service | `01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9` | Governed by the **Register or join devices** user action, which allows only MFA or auth strength. Since Sep 2024, authentication-flows policies on **All resources** apply to it, and it can be excluded by ID. MSRC confirmed by design that location and other grant controls are not enforced for device registration (VULN-153600). | [S1][S12]; COMMUNITY ([Cloudbrothers](https://cloudbrothers.info/conditional-access-bypasses/)) |
| Microsoft Authentication Broker | `29d9ed98-a469-4536-ade2-f981bc1d605e` | A client and broker, not normally a CA resource. Broker sign-ins show "CA: Not applied" by design; evaluate the target resource instead. It cannot be excluded via the UI. | COMMUNITY ([Q&A](https://learn.microsoft.com/en-us/answers/questions/5874646/microsoft-authentication-broker-showing-single-fac)) |
| Microsoft Authenticator | `4813382a-8fa7-425e-ab75-3b753aab3abb` | "Require compliant device" doesn't block Authenticator's `UserAuthenticationMethod.Read` scope. `ReadWrite` is enforced. | [S10][S11][S21] |
| Microsoft Defender for Endpoint (mobile) | `dd47d17a-3194-4d86-bfd5-c6ae6f5651e3` | Not an approved app, but allowed to report posture. No exclusion needed. | [S11] |
| Microsoft Rights Management Services | `00000012-0000-0000-c000-000000000000` | Targetable, though it may need searching in the picker. Policies covering RMS that include external users break opening of encrypted content unless MFA trust or guest accounts are set up. Microsoft says to remove RMS or exclude external users. Admin accounts are not recommended in RMS policies. | [S22]; https://learn.microsoft.com/en-us/purview/azure-rights-management-learn-about |
| Windows Store for Business / Universal Store Service APIs | `45a330b1-b1ec-4cc1-9161-9f03992aa49f` | Microsoft recommends excluding it from device-compliance policies when using Windows Subscription Activation | [S10][S19] |
| AAD Token Exchange Endpoint: Public | `fb60f99c-7a34-4190-8149-302f77469936` | CA does not apply to intermediate agent token exchanges here | [S26] |
| Azure DevOps | `499b84ac-1321-427f-aa17-267ca6975798` | Must be targeted directly. Not covered by the ARM group since Sep 2025. | [S15] |
| Client (public/native) apps generally | — | **Cannot be selected as targets**. CA applies to the resource. Confidential clients requesting ID tokens are also evaluated as the client. | [S1] |
| Apps without a service principal | — | Not in the picker. Covered only by **All resources**, or by creating the service principal (`New-MgServicePrincipal`). | [S1] |

**Service dependencies** [S6]:

- Early-bound means the user must satisfy the downstream policy before using the calling app. Late-bound means it is deferred until a token is requested for the downstream service.
- Teams → Exchange and SharePoint (early-bound); Planner, Stream and Whiteboard (late-bound).
- M365 portal → Exchange, SharePoint, Teams Services, M365 Reporting, Windows 365.
- Intune Portal Extension → Microsoft Intune and Windows 365.
- Power Apps → ARM, Azure AD Graph, SharePoint, Exchange.
- Power Automate → Power Apps. Project → Dynamics CRM.
- SharePoint → SharePoint Online Web Client Extensibility (+ Isolated).
- **A SharePoint-only policy therefore affects Teams**. Microsoft recommends the Office 365 group.

---

## 6. User actions and authentication context

Graph `includeUserActions` values: `urn:user:registersecurityinfo` and `urn:user:registerdevice` [S4].

### Register security information

- Applies to combined registration, Authenticator sign-in and passwordless phone sign-in registration.
- From **Jul 6 2026** it also applies to WHfB and macOS Platform SSO credential registration [S13].
- MSA guests with "Require MFA" must register with the org. Other-IdP guests (for example Google) are **blocked** [S1].
- TAP satisfies MFA, which helps with new-user bootstrap. TAP doesn't work for guests [S13].

### Register or join devices

- **Only "Require MFA" and "Require auth strength" are available**. All other grants are disabled [S1].
- WHfB and device-bound passkeys are not supported because they need an already-registered device [S1].
- **Client apps, Filters for devices and Device state conditions are unavailable** [S1].
- You **must set** Devices > Device settings "Require MFA to register or join devices with Microsoft Entra" to **No**. Otherwise the CA user action "isn't properly enforced" [S1].
- The location condition is not enforced for device registration (COMMUNITY, MSRC-confirmed, see section 5).

### Authentication context

- Up to 99 definitions (c1–c99) [S1]. The Graph beta doc still says `includeAuthenticationContextClassReferences` supports c1–c25 [S5]; the two docs disagree.
- Must be **published to apps** to be usable downstream.
- Consumed by SharePoint (sensitivity labels), Defender for Cloud Apps, custom apps and PIM role activation [S1].
- Works with users **or** workload identities, but not both in the same policy [S1].
- An auth-context policy only fires when the resource requests that context (the `acrs` claim). A policy on an auth context that no app or PIM setting uses protects nothing.
- Deleting a context still used by apps leaves data unprotected [S1].

---

## 7. "All resources" (formerly "All cloud apps")

- Graph: `includeApplications: ["All"]` [S4]. `"None"` is also a valid value; it is used in the UI and in Intune docs ("Under Select, choose None") [S16]. **UNVERIFIED**: `None` is not listed in the v1.0 property description but appears in practice.
- **With no resource exclusions**, the policy is enforced for "all token requests from websites and services", including:
  - GSA traffic profiles
  - Non-targetable resources such as Azure AD Graph (`00000002-0000-0000-c000-000000000000`)
  - Apps with no service principal in the tenant

  Microsoft recommends a baseline MFA policy on all users and all resources **without resource exclusions** [S1].
- **Legacy behavior when an All-resources policy had any resource exclusion**: these low-privilege scopes were silently exempt [S1].
  - Native clients and SPAs: Azure AD Graph and MS Graph `email`, `offline_access`, `openid`, `profile`, `User.Read` (+ `People.Read` on MS Graph).
  - Confidential clients that were excluded: also `User.Read.All`, `User.ReadBasic.All`, `People.Read.All`, `GroupMember.Read.All`, `Member.Read.Hidden`.
- **New behavior (rollout started Jun 15 2026 per [S3]; "starting March 2026" per [S1])**: baseline scopes are evaluated as directory access against **Windows Azure Active Directory** (`00000002-0000-0000-c000-000000000000`). Examples now challenged: VS Code desktop (`openid`/`profile`), Azure CLI (`User.Read` only), and excluded confidential web apps requesting `User.Read`/`People.Read`.
  - **Unchanged**: apps requesting any scope beyond the baseline, and excluded confidential clients requesting only OIDC scopes.
  - Tenant settings at https://aka.ms/BaselineScopesSettingsUX. Options are Enable enforcement (default after rollout), **Customize behavior** (a placeholder app that keeps legacy behavior per policy when excluded), or **Disable enforcement** (not recommended; creates gaps).
  - Detecting affected policies: `GET /v1.0/identity/conditionalAccess/policies?$filter=conditions/applications/includeApplications/any(a:a eq 'All') and conditions/applications/excludeApplications/any()`.
  - **Limitation for a tool**: the tenant-level baseline-scopes setting is not in the CA policy object. No Graph API for it is documented. **UNVERIFIED**.
- **Required for some controls**: "Require password change" (user risk) must use All resources [S11].
- **Sign-ins that All resources does not cover**:
  - Service principals or workload identities, unless the policy targets workload identities [S9].
  - Intermediate agent token exchanges and blueprint creation calls [S26].
  - Resources not using Entra token issuance (API keys) [S26].
  - Broker or PRT sign-ins where the event shows "Not applied" (COMMUNITY).
  - The built-in carve-outs: Intune enrollment, Web Company Portal and Authenticator `UserAuthenticationMethod.Read` under compliant-device grants [S10][S18].
  - **UNVERIFIED**: a complete Microsoft list of "no-resource" or "CA-exempt" sign-in types has not been published.
- Mandatory Azure MFA is enforced at the platform regardless of CA exclusions [S7].

---

## 8. Global Secure Access and other newer target types

- **All internet resources with Global Secure Access**: targets the Internet Access traffic forwarding profile. Graph uses appId **`5dc48733-b5df-475c-a49b-fa307ef00853`** in `includeApplications` [S25]. It is also used to link web content filtering profiles via the session control `globalSecureAccessFilteringProfile`.
- The **Microsoft traffic profile** and Private Access apps are each backed by a service principal; the profile object returns `servicePrincipal.appId` [S25]. The M365 traffic profile app ID is **UNVERIFIED**; read it from `/beta/networkAccess/forwardingProfiles` at runtime.
- To enforce only the Internet profile and not Microsoft traffic, use Select resources > "Internet resources" [S24].
- The older `networkAccess` / `globalSecureAccess` properties are deprecated (data stopped Jun 1 2025) [S5].
- **All agent resources (Preview)**: enforces the policy for token requests to agent identity blueprint principals and agent identities [S1].
  - Agent users are **not** covered by "Users" assignments. Use Agents > Agent users [S26].
  - Agent identities support only Block [S11].
  - Agent scenarios need Agent 365 or E7 licensing [S26].
  - Graph value for "All agent resources": **UNVERIFIED**.
- **Custom security attribute app filter** (`applicationFilter`): targets apps by attribute, including otherwise non-pickable apps such as Azure AD Graph [S1][S4].

---

## 9. Key app IDs and Graph values (reference)

| Name | appId / value | Confidence |
|---|---|---|
| All resources | `All` | VERIFIED [S4] |
| None | `None` | Commonly used; UNVERIFIED in v1.0 property doc |
| Office 365 group | `Office365` | VERIFIED [S4] |
| Microsoft Admin Portals group | `MicrosoftAdminPortals` | VERIFIED [S4] |
| User action: register security info | `urn:user:registersecurityinfo` | VERIFIED [S4] |
| User action: register/join device | `urn:user:registerdevice` | VERIFIED [S4] |
| Office 365 Exchange Online | `00000002-0000-0ff1-ce00-000000000000` | VERIFIED [S21] |
| Office 365 SharePoint Online | `00000003-0000-0ff1-ce00-000000000000` | COMMUNITY (docs-derived list) |
| Microsoft Teams Services (resource) | `cc15fd57-2c6c-4117-a88c-83b1d56b4bbe` | VERIFIED [S21] |
| Microsoft Teams (client) | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` | VERIFIED [S21] |
| Microsoft Graph | `00000003-0000-0000-c000-000000000000` | VERIFIED [S1] |
| Windows Azure Active Directory (Azure AD Graph) | `00000002-0000-0000-c000-000000000000` | VERIFIED [S1] |
| Azure portal | `c44b4083-3bb0-49c1-b47d-974e53cbdf3c` | VERIFIED [S1][S7] |
| Exchange Admin Center | `497effe9-df71-4043-a8bb-14cf78c4b63b` | VERIFIED [S1] |
| Microsoft Office 365 Portal | `00000006-0000-0ff1-ce00-000000000000` | VERIFIED [S1] |
| M365 Security & Compliance Center (Protection Center) | `80ccca67-54bd-44ab-8625-4b79c4dc7775` | VERIFIED [S1] |
| Windows Azure Service Management API | `797f4846-ba00-4fd7-ba43-dac1f8f63013` | VERIFIED (Learn Dev Box doc) |
| Azure DevOps | `499b84ac-1321-427f-aa17-267ca6975798` | VERIFIED [S15] |
| Microsoft Intune | `0000000a-0000-0000-c000-000000000000` | COMMUNITY |
| Microsoft Intune Enrollment | `d4ebce55-015a-49b5-a083-c84d1797ae8c` | VERIFIED [S16][S17] |
| Microsoft Intune Web Company Portal | `74bcdadc-2fdc-4bb3-8459-76d06952a0e9` | COMMUNITY |
| Microsoft Intune Company Portal (client) | `9ba1a5c7-f17a-4de9-a1f1-6178c8d51223` | VERIFIED [S21] |
| Device Registration Service | `01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9` | VERIFIED [S12] |
| Microsoft Graph Command Line Tools (Graph PowerShell) | `14d82eec-204b-4c2f-b7e8-296a70dab67e` | VERIFIED [S20] |
| Graph Explorer | `de8bc8b5-d9f9-48b1-a8ad-b748da725064` | VERIFIED [S20] |
| Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | VERIFIED [S7] |
| Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` | VERIFIED [S7] |
| Azure mobile app | `0c1307d4-29d6-4389-a11c-5cbe7f65d7fa` | VERIFIED [S7] |
| Azure Active Directory PowerShell (retired) | `1b730954-1685-4b74-9bfd-dac224a7b894` | VERIFIED [S21] |
| Power Platform admin center | `065d9450-1e87-434e-ac2f-69af271549ed` | VERIFIED [S21] |
| Microsoft Rights Management Services | `00000012-0000-0000-c000-000000000000` | VERIFIED [S22] |
| Windows Store for Business / Universal Store Service APIs | `45a330b1-b1ec-4cc1-9161-9f03992aa49f` | VERIFIED [S10] |
| Microsoft Authentication Broker | `29d9ed98-a469-4536-ade2-f981bc1d605e` | COMMUNITY |
| Microsoft Authenticator App | `4813382a-8fa7-425e-ab75-3b753aab3abb` | VERIFIED [S21] |
| All internet resources with GSA | `5dc48733-b5df-475c-a49b-fa307ef00853` | VERIFIED [S25] |
| Microsoft first-party owner tenant | `f8cdef31-a31e-4b4a-93e4-5f571e91255a` | VERIFIED [S2][S20] |

---

## Implications for gap analysis

Suggested rules. "Admins" means policies scoped to privileged directory roles or groups. Each rule should resolve targets **by app ID** and treat display names as informational.

### A. Admin protection coverage

1. **ADMIN-PORTALS-ONLY.** Admins are covered only by a policy whose include set is `MicrosoftAdminPortals`, with no policy covering them on `All`. Flag HIGH. The four front-end IDs leave Microsoft Graph uncovered (Graph PowerShell, Graph Explorer, Entra admin center data plane), as well as ARM/CLI/PowerShell, the Intune API (`0000000a…`), Exchange Online PowerShell, the Teams admin API and SharePoint admin. Recommend an All-resources policy for admins.
2. **INTUNE-ADMIN-GAP.** Policy targets `MicrosoftAdminPortals` but not `0000000a-0000-0000-c000-000000000000`, Graph (only via All), or All. Report: "Intune admin center sign-in is covered via the Azure portal ID, but Intune/Graph API calls the portal makes are not." Recommend All resources. Confirm with audience reporting.
3. **DEFENDER/PURVIEW/TEAMS/SPO/PPAC portal coverage.** If a policy relies on Admin Portals for these, emit INFO/WARN. Mapping is not authoritatively documented after Feb 2026 (Defender, SharePoint admin and Power Platform admin are UNVERIFIED). Recommend All resources, or explicit targets such as `065d9450…` for PPAC and SharePoint Online for SPO admin.
4. **AZURE-MGMT-ONLY.** Admin MFA/phishing-resistant policy targets only `797f4846…`. Flag that Graph-based tooling and M365 admin surfaces are uncovered. Also flag that Azure DevOps (`499b84ac…`) has not been covered since Sep 2025.
5. **NO-GRAPH-COVERAGE.** No enabled policy for a population uses `All` without that population being excluded. Microsoft Graph and Azure AD Graph cannot be selected directly, so Graph PowerShell (`14d82eec…`) and Graph Explorer are then unprotected for that population. Exception: a policy using an `applicationFilter` that matches `00000002-0000-0000-c000-000000000000`.
6. **TARGETING-CLIENT-ID.** A policy includes or excludes a public client ID: Graph Command Line Tools `14d82eec…`, Azure CLI `04b07795…`, Azure PowerShell `1950a258…`, Teams client `1fec8e78…`, Microsoft Authentication Broker `29d9ed98…`, or Company Portal `9ba1a5c7…`. Flag as likely ineffective. CA applies to resources; public clients are not evaluated as targets.
7. **ROLE-SCOPE.** Admin policies scoped by directory roles don't cover custom or AU-scoped roles or Exchange RBAC (Organization Management) [S8]. Pair with group- or All-users-based All-resources policies.

### B. "All resources" with exclusions

8. **ALL-WITH-EXCLUSIONS.** `includeApplications` contains `All` and `excludeApplications` is non-empty. Report each excluded app's risk. The baseline-scopes enforcement change makes these policies apply to OIDC- and `User.Read`-only sign-ins, but only if the tenant hasn't disabled enforcement or used Customize behavior. The policy object doesn't expose that setting, so flag as "verify Baseline scopes setting (aka.ms/BaselineScopesSettingsUX)". If the tool's evidence predates Jun 15 2026, assume the legacy exemption.
9. **EXCLUDED-OFFICE365 / EXCLUDED-ADMINPORTALS.** Excluding `Office365` or `MicrosoftAdminPortals` from an All policy removes large surfaces. Admin Portals is documented as "not intended" for bulk exclusion.
10. **EXCLUDED-HIGH-VALUE.** Flag exclusions of Exchange (`00000002-0000-0ff1…`), SharePoint (`00000003-0000-0ff1…`), Teams Services, `797f4846…`, Azure portal, Microsoft Intune, Device Registration Service (`01cb2876…`, only acceptable in auth-flow policies for device-code registration), or Microsoft Rights Management Services (`00000012…`, often excluded for B2B encryption, so recommend MFA trust instead).
11. **UNNEEDED-INTUNE-EXCLUSION.** Compliant-device policies excluding Microsoft Intune Enrollment, Microsoft Intune Web Company Portal or Microsoft Intune. Microsoft documents these exclusions as unnecessary [S18][S19]. Each one adds an exclusion, which matters for rule 8, and weakens coverage. Exception: ToU policies must exclude Intune Enrollment [S17].
12. **NO-BASELINE.** No enabled policy targets `All` users + `All` resources with an MFA or auth-strength grant and **zero** resource exclusions. This is Microsoft's recommended baseline [S1].

### C. Workload, granularity and dependency gaps

13. **SINGLE-M365-APP.** Policy targets Exchange or SharePoint individually instead of `Office365`. Warn about dependency leakage: Teams and Search metadata, inconsistent prompts, early/late-bound effects [S2][S6]. In particular, a SharePoint-only block or compliant-device policy also affects Teams.
14. **OFFICE365-ASSUMED-ADMIN.** `Office365` includes M365 Admin Services, Office 365 Portal, Protection Center, and the Skype and Teams Tenant Admin API. But a policy targeting only Office365 doesn't cover Azure portal, Exchange Admin Center (`497effe9`) or Graph. Don't treat Office365 coverage as admin coverage.
15. **MISSING-SP.** Targeted app IDs that don't exist as service principals in the tenant, such as Intune Enrollment, which isn't auto-created in new tenants. Such a policy protects nothing. Apps without a service principal are covered only by All.
16. **DISPLAY-NAME DRIFT.** Never match on "Windows Azure Service Management API", "Microsoft Azure Management" or "Azure Resource Manager". Use `797f4846-ba00-4fd7-ba43-dac1f8f63013`. Same for Graph Command Line Tools / "Microsoft Graph PowerShell".
17. **AZURE-GOV.** In Azure Government tenants, expect "Azure Government Cloud Management API" rather than `797f4846`.

### D. User actions and auth context

18. **NO-SECURITY-INFO-POLICY.** No policy targets `urn:user:registersecurityinfo`. An attacker with a password can register MFA from anywhere. Recommend auth strength or trusted location plus TAP. Note the Jul 6 2026 WHfB and Platform SSO scope change.
19. **REGISTERDEVICE-MISCONFIG.** A policy on `urn:user:registerdevice` uses grants other than MFA or auth strength, or uses device, client-app or device-filter conditions. These are unsupported. Also warn when the tenant device setting "Require MFA to register or join devices" is Yes, which breaks enforcement. If the tool can read device registration policy, check `/policies/deviceRegistrationPolicy` (multiFactorAuthConfiguration; field name **UNVERIFIED**).
20. **DEVICE-REG-LOCATION-ASSUMPTION.** Policies that try to restrict device registration via location or compliant network: flag as ineffective (COMMUNITY/MSRC).
21. **ORPHAN-AUTH-CONTEXT.** A policy targets an auth context (`c#`) that isn't published, or isn't referenced by any SharePoint label, PIM role setting or MDCA policy. Informational: the policy protects nothing. Also flag auth-context policies that mix users and workload identities.

### E. Newer target types

22. **GSA.** If GSA is deployed (forwarding profiles enabled) and no policy targets All, the Internet Access app `5dc48733…` or the Microsoft traffic profile app, flag that tunnel and internet traffic lacks CA. Flag policies still using deprecated `networkAccess`/`globalSecureAccess` properties.
23. **AGENTS.** If agent identities or agent users exist, check for policies under the Agents assignment and "All agent resources". "All users" does not cover agent users [S26].

### F. Non-CA enforcement context (informational)

24. Mandatory Azure MFA (Phase 1/2) enforces MFA on Azure portal, Entra admin center, Intune admin center, M365 admin center and ARM writes regardless of CA. A tool should not treat that as phishing-resistant coverage, nor as coverage of Graph APIs or read operations.

---

## Open items / UNVERIFIED summary

- The Defender portal, SharePoint admin center and Power Platform admin center mapping to Microsoft Admin Portals is undocumented after Feb 2026. Teams admin center → `00000006` and Purview → `80ccca67` come only from an interim Feb 2026 doc revision.
- Which backend audiences the Intune admin center actually requests (`0000000a`, Graph, Intune portal extension `5926fc8e…`). Confirm with sign-in audience reporting.
- The conflicting baseline-scope rollout dates: "starting March 2026" in [S1] vs "began June 15, 2026" in [S3].
- No documented Graph API for reading the Baseline scopes tenant setting.
- Whether Graph Explorer (`de8bc8b5…`) is reliably targetable as a CA resource in 2026. Community evidence says yes for some scenarios.
- App IDs from community or docs-derived lists only: SharePoint Online, Microsoft Intune, Intune Web Company Portal, Microsoft Authentication Broker.
- The Graph string value for "All agent resources" and the Microsoft traffic profile app ID.
- `None` as an `includeApplications` value is used widely but is not enumerated in the v1.0 property description.
- Authentication context limit: Graph beta says c1–c25, Entra docs say up to 99.
- No complete list of sign-in types that All resources never evaluates.
