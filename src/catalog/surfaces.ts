import type { Licenses } from '../model/types';
import type { SurfaceId } from './apps';

export type ControlId = 'legacyBlocked' | 'mfa' | 'phishResistant' | 'managedDevice' | 'deviceCodeBlocked' | 'signInRisk' | 'userRisk' | 'session';

export const SURFACES: { id: SurfaceId; label: string; description: string }[] = [
  { id: 'allResources', label: 'All resources',
    description: 'Every token request, including non-targetable resources and apps without a service principal; covered only by a policy that targets All resources.' },
  { id: 'office365', label: 'Office 365 (Exchange, SharePoint, Teams)',
    description: 'Exchange Online, SharePoint Online and Teams; covered by policies targeting All resources, the Office 365 group, or each of these apps.' },
  { id: 'adminPortals', label: 'Admin portal sign-ins',
    description: 'Front-end sign-in to the Azure portal (including the Entra and Intune admin centers), Exchange admin center, Microsoft 365 admin center and Protection Center; covered by All resources or Microsoft Admin Portals, but not the APIs those portals call.' },
  { id: 'azureManagement', label: 'Azure management (ARM, CLI, PowerShell)',
    description: 'Azure Resource Manager calls from the Azure portal, Azure CLI, Azure PowerShell and IaC tools; covered by All resources or Windows Azure Service Management API.' },
  { id: 'graph', label: 'Microsoft Graph & Graph PowerShell',
    description: 'Microsoft Graph cannot be targeted directly; only an All resources policy covers Graph PowerShell, Graph Explorer and admin-center API calls.' },
  { id: 'intuneApi', label: 'Intune APIs',
    description: 'Microsoft Intune service APIs called by the Intune admin center and devices; covered by All resources or by targeting Microsoft Intune, not by Microsoft Admin Portals.' },
  { id: 'azureDevOps', label: 'Azure DevOps',
    description: 'Azure DevOps sign-ins; covered by All resources or by targeting Azure DevOps directly, no longer by Windows Azure Service Management API since Sep 2025.' },
  { id: 'thirdParty', label: 'Third-party & custom apps',
    description: 'SaaS and line-of-business apps registered in the tenant; covered by All resources or by targeting each app individually.' },
  { id: 'registerSecurityInfo', label: 'Register security info',
    description: 'Registering MFA and passwordless methods (including Windows Hello and Platform SSO); covered only by a policy on the Register security information user action.' },
  { id: 'registerDevice', label: 'Register or join devices',
    description: 'Registering or joining devices to Microsoft Entra; covered only by a policy on the Register or join devices user action, which supports MFA or auth strength only.' },
];

export const CONTROLS: { id: ControlId; label: string; license?: keyof Licenses; licenseLabel?: string }[] = [
  { id: 'legacyBlocked', label: 'Legacy auth blocked' },
  { id: 'mfa', label: 'MFA' },
  { id: 'phishResistant', label: 'Phishing-resistant MFA' },
  { id: 'managedDevice', label: 'Managed device', license: 'intune', licenseLabel: 'Microsoft Intune' },
  { id: 'deviceCodeBlocked', label: 'Device code flow blocked' },
  { id: 'signInRisk', label: 'Sign-in risk', license: 'entraP2', licenseLabel: 'Microsoft Entra ID P2' },
  { id: 'userRisk', label: 'User risk', license: 'entraP2', licenseLabel: 'Microsoft Entra ID P2' },
  { id: 'session', label: 'Session controls' },
];

const APPLICABLE: Partial<Record<SurfaceId, ControlId[]>> = {
  registerDevice: ['mfa', 'phishResistant'],
  registerSecurityInfo: ['mfa', 'phishResistant', 'managedDevice'],
};

export function isNA(surface: SurfaceId, control: ControlId): boolean {
  const applicable = APPLICABLE[surface];
  return applicable !== undefined && !applicable.includes(control);
}
