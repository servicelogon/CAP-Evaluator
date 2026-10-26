import { CATALOG_DATE } from '../catalog/apps';
import type { CAPolicy, TenantProfile } from '../model/types';

export interface ExportBundle {
  catalogDate: string;
  tenant: TenantProfile;
  value: CAPolicy[];
}

export function policiesToJson(policies: CAPolicy[], tenant: TenantProfile): string {
  const bundle: ExportBundle = { catalogDate: CATALOG_DATE, tenant, value: policies };
  return JSON.stringify(bundle, null, 2);
}
