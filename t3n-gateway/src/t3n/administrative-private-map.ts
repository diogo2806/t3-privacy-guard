import type { TenantClient } from '@terminal3/t3n-sdk';

export interface AdministrativePrivateMapAcl {
  readonly writers: { readonly only: number[] };
  readonly readers: { readonly only: number[] };
}

export type AdministrativePrivateMapDiagnosticCode =
  | 'INSUFFICIENT_CREDIT'
  | 'AUTHENTICATION'
  | 'ACCESS_DENIED'
  | 'NETWORK'
  | 'READ_BACK_MISMATCH'
  | 'UNKNOWN';

export class AdministrativePrivateMapError extends Error {
  constructor(
    readonly diagnosticCode: AdministrativePrivateMapDiagnosticCode,
    message: string,
  ) {
    super(message);
    this.name = 'AdministrativePrivateMapError';
  }
}

function diagnosticText(error: unknown, depth = 0): string {
  if (depth > 2 || error == null) return '';
  if (typeof error === 'string') return error.toLowerCase();
  if (error instanceof Error) {
    return [error.name, error.message, diagnosticText(error.cause, depth + 1)].join(' ').toLowerCase();
  }
  if (typeof error !== 'object') return String(error).toLowerCase();

  const record = error as Record<string, unknown>;
  return [
    record.name,
    record.code,
    record.message,
    record.status,
    record.statusCode,
    diagnosticText(record.cause, depth + 1),
  ]
    .filter((value) => value != null)
    .map((value) => String(value))
    .join(' ')
    .toLowerCase();
}

export function classifyAdministrativePrivateMapError(error: unknown): AdministrativePrivateMapDiagnosticCode {
  if (error instanceof AdministrativePrivateMapError) return error.diagnosticCode;
  const text = diagnosticText(error);
  if (text.includes('insufficientcredit') || text.includes('insufficient credit')) return 'INSUFFICIENT_CREDIT';
  if (
    text.includes('authentication')
    || text.includes('unauthorized')
    || text.includes('invalid api key')
    || text.includes('invalid credential')
    || text.includes('status 401')
    || text.includes('statuscode 401')
  ) return 'AUTHENTICATION';
  if (
    text.includes('accessdenied')
    || text.includes('access denied')
    || text.includes('forbidden')
    || text.includes('permission denied')
    || text.includes('not authorized')
    || text.includes('status 403')
    || text.includes('statuscode 403')
  ) return 'ACCESS_DENIED';
  if (
    text.includes('network')
    || text.includes('econn')
    || text.includes('enotfound')
    || text.includes('etimedout')
    || text.includes('timeout')
    || text.includes('fetch failed')
    || text.includes('socket')
    || text.includes('dns')
  ) return 'NETWORK';
  return 'UNKNOWN';
}

function sanitizedAdministrativePrivateMapError(
  operation: string,
  tail: string,
  error: unknown,
): AdministrativePrivateMapError {
  const diagnosticCode = classifyAdministrativePrivateMapError(error);
  switch (diagnosticCode) {
    case 'INSUFFICIENT_CREDIT':
      return new AdministrativePrivateMapError(
        diagnosticCode,
        `T3N ${operation} failed for ${tail} private map: insufficient credit; replenish T3N account credits and retry`,
      );
    case 'AUTHENTICATION':
      return new AdministrativePrivateMapError(
        diagnosticCode,
        `T3N ${operation} failed for ${tail} private map: authentication rejected`,
      );
    case 'ACCESS_DENIED':
      return new AdministrativePrivateMapError(
        diagnosticCode,
        `T3N ${operation} failed for ${tail} private map: access denied`,
      );
    case 'NETWORK':
      return new AdministrativePrivateMapError(
        diagnosticCode,
        `T3N ${operation} failed for ${tail} private map: network unavailable`,
      );
    default:
      return new AdministrativePrivateMapError(
        'UNKNOWN',
        `Unable to ${operation} ${tail} private map administratively`,
      );
  }
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

export async function readAdministrativePrivateMapEntry(
  tenant: TenantClient,
  tail: string,
  key: string,
): Promise<string | null> {
  try {
    return await tenant.maps.entryGet(tail, key);
  } catch (error) {
    throw sanitizedAdministrativePrivateMapError('read', tail, error);
  }
}

export async function writeAndVerifyAdministrativePrivateMapEntry(
  tenant: TenantClient,
  tail: string,
  key: string,
  value: string,
): Promise<void> {
  try {
    await tenant.maps.entrySet(tail, key, value);
  } catch (error) {
    throw sanitizedAdministrativePrivateMapError('write', tail, error);
  }

  let readBack: string | null;
  try {
    readBack = await tenant.maps.entryGet(tail, key);
  } catch (error) {
    throw sanitizedAdministrativePrivateMapError('verify', tail, error);
  }

  if (readBack !== value) {
    throw new AdministrativePrivateMapError(
      'READ_BACK_MISMATCH',
      `T3N read-back mismatch for ${tail} private map after administrative write`,
    );
  }
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
      throw sanitizedAdministrativePrivateMapError('create', tail, error);
    }
    try {
      await tenant.maps.update(tail, acl);
    } catch (updateError) {
      throw sanitizedAdministrativePrivateMapError('reconcile ACL for', tail, updateError);
    }
  }
  return tenant.canonicalName(tail);
}
