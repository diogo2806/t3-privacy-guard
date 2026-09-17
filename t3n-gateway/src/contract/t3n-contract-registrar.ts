import { getContractVersion, getNodeUrl } from '@terminal3/t3n-sdk';

const TENANT_CONTRACTS_SCRIPT = 'tee:tenant/contracts';
const CONTRACT_REGISTER_FUNCTION = 'contract-register';

export interface ContractRegistrationClient {
  executeWithBlob(
    request: {
      readonly script_name: string;
      readonly script_version: string;
      readonly function_name: string;
      readonly input: Readonly<Record<string, unknown>>;
    },
    blob: Blob,
  ): Promise<unknown>;
}

export interface ContractRegistrationResult {
  readonly name: string;
  readonly contract_id: number;
}

export interface RegisterContractRequest {
  readonly client: ContractRegistrationClient;
  readonly canonicalContractId: string;
  readonly version: string;
  readonly wasm: Uint8Array;
  readonly resolveTenantContractsVersion?: () => Promise<string>;
}

function normalizeContractId(value: unknown): number {
  if (typeof value === 'number') {
    if (Number.isSafeInteger(value) && value > 0) return value;
    throw new Error('T3N contract registration returned an invalid numeric contract id');
  }

  if (typeof value === 'string' && /^[1-9][0-9]*$/.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed) && parsed > 0) return parsed;
  }

  throw new Error('T3N contract registration returned an invalid numeric contract id');
}

function responseText(raw: unknown): string {
  if (typeof raw === 'string') return raw;
  if (raw instanceof Uint8Array) return Buffer.from(raw).toString('utf8');
  throw new Error('T3N contract registration returned an invalid response');
}

export function parseContractRegistrationResult(
  raw: unknown,
  expectedContractId: string,
): ContractRegistrationResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(responseText(raw));
  } catch (error) {
    if (error instanceof Error && error.message === 'T3N contract registration returned an invalid response') throw error;
    throw new Error('T3N contract registration returned an invalid response');
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('T3N contract registration returned an invalid response');
  }

  const record = parsed as Record<string, unknown>;
  if (record.name !== expectedContractId) {
    throw new Error('T3N contract registration returned an unexpected canonical contract id');
  }

  return {
    name: expectedContractId,
    contract_id: normalizeContractId(record.contract_id),
  };
}

export async function registerContractWithDurableId(
  request: RegisterContractRequest,
): Promise<ContractRegistrationResult> {
  const scriptVersion = await (request.resolveTenantContractsVersion
    ? request.resolveTenantContractsVersion()
    : getContractVersion(getNodeUrl(), TENANT_CONTRACTS_SCRIPT));

  const raw = await request.client.executeWithBlob(
    {
      script_name: TENANT_CONTRACTS_SCRIPT,
      script_version: scriptVersion,
      function_name: CONTRACT_REGISTER_FUNCTION,
      input: {
        name: request.canonicalContractId,
        version: request.version,
      },
    },
    new Blob([Buffer.from(request.wasm)]),
  );

  return parseContractRegistrationResult(raw, request.canonicalContractId);
}
