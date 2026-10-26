// Template IDs from https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
export const GLOBAL_ADMIN = '62e90394-69f5-4237-9190-012177145e10';
export const HYBRID_IDENTITY_ADMIN = '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2';

// Microsoft "Require phishing-resistant MFA for admins" / managed-policy 14-role list
export const PRIVILEGED_ROLES: { id: string; name: string }[] = [
  { id: GLOBAL_ADMIN, name: 'Global Administrator' },
  { id: '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', name: 'Application Administrator' },
  { id: 'c4e39bd9-1100-46d3-8c65-fb160da0071f', name: 'Authentication Administrator' },
  { id: 'b0f54661-2d74-4c50-afa3-1ec803f12efe', name: 'Billing Administrator' },
  { id: '158c047a-c907-4556-b7ef-446551a6b5f7', name: 'Cloud Application Administrator' },
  { id: 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', name: 'Conditional Access Administrator' },
  { id: '29232cdf-9323-42fd-ade2-1d097af3e4de', name: 'Exchange Administrator' },
  { id: '729827e3-9c14-49f7-bb1b-9608f156bbb8', name: 'Helpdesk Administrator' },
  { id: '966707d0-3269-4727-9be2-8c3a10f19b9d', name: 'Password Administrator' },
  { id: '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', name: 'Privileged Authentication Administrator' },
  { id: 'e8611ab8-c189-46e8-94e1-60213ab1f814', name: 'Privileged Role Administrator' },
  { id: '194ae4cb-b126-40b2-bd5b-6091b380977d', name: 'Security Administrator' },
  { id: 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', name: 'SharePoint Administrator' },
  { id: 'fe930be7-5e62-47db-91af-98c3a49a38b1', name: 'User Administrator' },
];

export const EXTENDED_ROLES: { id: string; name: string }[] = [
  { id: HYBRID_IDENTITY_ADMIN, name: 'Hybrid Identity Administrator' },
  { id: '3a2c62db-5318-420d-8d74-23affee5d9d5', name: 'Intune Administrator' },
  { id: 'f2ef992c-3afb-46b9-b7cf-a126ee74c451', name: 'Global Reader' },
  { id: '5f2222b1-57c3-48ba-8ad5-d4759f1fde6f', name: 'Security Operator' },
  { id: '5d6b6bb7-de71-4623-b4af-96380a352509', name: 'Security Reader' },
  { id: '69091246-20e8-4a56-aa4d-066075b2a7a8', name: 'Teams Administrator' },
  { id: '0526716b-113d-4c15-b2c8-68e3c22b9f80', name: 'Authentication Policy Administrator' },
  { id: '17315797-102d-40b4-93e0-432062caca18', name: 'Compliance Administrator' },
  { id: 'fdd7a751-b60b-444a-984c-02652fe8fa1c', name: 'Groups Administrator' },
  { id: '7698a772-787b-4ac8-901f-60d6b08affd2', name: 'Cloud Device Administrator' },
  { id: '8329153b-31d0-4727-b945-745eb3bc5f31', name: 'Domain Name Administrator' },
  { id: 'be2f45a1-457d-42af-a067-6ec1fa63bc45', name: 'External Identity Provider Administrator' },
  { id: '31392ffb-586c-42d1-9346-e59415a2cc4e', name: 'Exchange Recipient Administrator' },
  { id: '45d8d3c5-c802-45c6-b32a-1d70b5e1e86e', name: 'Identity Governance Administrator' },
  { id: '59d46f88-662b-457b-bceb-5c3809e5908f', name: 'Lifecycle Workflows Administrator' },
  { id: '58a13ea3-c632-46ae-9ee0-9c0d43cd7f3d', name: 'Attribute Assignment Administrator' },
  { id: '25a516ed-2fa0-40ea-a2d0-12923a21473a', name: 'Authentication Extensibility Administrator' },
  { id: 'ac434307-12b9-4fa1-a708-88bf58caabc1', name: 'Global Secure Access Administrator' },
  { id: '11451d60-acb2-45eb-a7d6-43d0f0125c13', name: 'Windows 365 Administrator' },
  { id: '9f06204d-73c1-4d4c-880a-6edb90606fd8', name: 'Microsoft Entra Joined Device Local Administrator' },
  { id: 'db506228-d27e-4b7d-95e5-295956d6615f', name: 'Agent ID Administrator' },
  { id: 'd29b2b05-8046-44ba-8758-1e26182fcf32', name: 'Directory Synchronization Accounts' },
  { id: '9360feb5-f418-4baa-8175-e2a00bac4301', name: 'Directory Writers' },
  { id: 'e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8', name: 'Partner Tier2 Support' },
];

const NAMES = new Map([...PRIVILEGED_ROLES, ...EXTENDED_ROLES].map(r => [r.id.toLowerCase(), r.name]));
const PRIVILEGED = new Set(PRIVILEGED_ROLES.map(r => r.id.toLowerCase()));

export function roleName(id: string): string | undefined {
  return NAMES.get(id.toLowerCase());
}

export function isPrivilegedRole(id: string): boolean {
  return PRIVILEGED.has(id.toLowerCase());
}
