import type { TenantClient } from '@terminal3/t3n-sdk';

export interface AdministrativePrivateMapAcl {
  readonly writers: { readonly only: number[] };
  readonly readers: { readonly only: number[] };
}

export function administrativePrivateMapAcl(numericContractId: number): AdministrativePrivateMapAcl {
  if (!Number.isInteger(numericContractId) || numericContractId <= 0) {
    throw new Error('numericContractId must be a positive integer');
  }
  return {
    writers: { only: [] },
    readers: { only: [numericContractId] },
  };
}

export async function ensureAdministrativePrivateMap(
  tenant: TenantClient,
  tail: string,
  numericContractId: number,
): Promise<string> {
  const acl = administrativePrivateMapAcl(numericContractId);
  try {
    await tenant.maps.create({
      tail,
      visibility: 'private',
      ...acl,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.toLowerCase().includes('already')) {
      throw new Error(`Unable to create ${tail} private map safely`);
    }
    try {
      await tenant.maps.update(tail, acl);
    } catch {
      throw new Error(`Unable to reconcile ${tail} private map ACL safely`);
    }
  }
  return tenant.canonicalName(tail);
}
