import { execFile } from 'node:child_process';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { promisify } from 'node:util';
import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import {
  AgentCardRegistry,
  buildAgentCardForSession,
  serializeAgentCard,
} from '../agent/agent-card.js';
import {
  publishAgentCardToOrganization,
  type AgentCardPublicationRequest,
} from '../agent/agent-card-publisher.js';
import type { AgentSession } from '../agent/agent-session.js';
import {
  EXECUTOR_DELEGATION_REQUIREMENTS,
  PROPOSAL_DELEGATION_REQUIREMENTS,
  type DelegationGrantRequest,
  type DelegationService,
} from '../agent/delegation-service.js';
import type { ExecutorSession } from '../agent/executor-session.js';
import { compareContractVersions } from '../config/contract-version.js';
import type { GatewayConfig } from '../config/env.js';
import type { PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import type { T3nSession } from '../t3n/session.js';

const execFileAsync = promisify(execFile);
const DEFAULT_STATE_PATH = '/data/t3n-runtime-provisioning.json';
const DEFAULT_WASM_PATH = '/app/runtime/privacy_guard_contract.wasm';
const REMOTE_STATE_MAP_TAIL = 'privacy-guard-runtime';
const REMOTE_STATE_KEY = 'provisioning';
const MAX_CARD_VERIFY_ATTEMPTS = 4;

export interface RuntimeProvisioningState {
  readonly tenantDid: string;
  readonly contractId: string;
  readonly contractVersion: string;
  readonly numericContractId: number;
  readonly updatedAt: string;
}

export interface RuntimeProvisioningResult {
  readonly enabled: boolean;
  readonly contractResolved: boolean;
  readonly contractRegistered: boolean;
  readonly numericContractIdAvailable: boolean;
  readonly policyReconciled: boolean;
  readonly remediationReconciled: boolean;
  readonly proposalDelegationReconciled: boolean;
  readonly executorDelegationReconciled: boolean;
  readonly agentCardState: string;
}

interface RuntimeProvisioningDependencies {
  readonly runAdminScript?: (scriptName: string, env: NodeJS.ProcessEnv) => Promise<void>;
  readonly sleep?: (milliseconds: number) => Promise<void>;
}

interface ContractResolution {
  readonly contractId: string;
  readonly contractVersion: string;
  readonly numericContractId: number | null;
  readonly registered: boolean;
}

interface ProvisioningControlPlane {
  canonicalName(tail: string): string;
  executeControl(name: string, input: Record<string, string>): Promise<unknown>;
  readonly maps: {
    create(input: {
      tail: string;
      visibility: 'private';
      writers: { only: number[] };
      readers: { only: number[] };
    }): Promise<unknown>;
    update(tail: string, patch: {
      writers: { only: number[] };
      readers: { only: number[] };
    }): Promise<unknown>;
  };
}

export interface AdminProvisioningStep {
  readonly scriptName: 'setup-policy.js' | 'setup-remediation-secrets.js';
  readonly env: NodeJS.ProcessEnv;
}

export type ContractVersionAction = 'REGISTER' | 'REUSE';

export function contractVersionAction(resolvedVersion: string | null, packagedVersion: string): ContractVersionAction {
  if (resolvedVersion === null) return 'REGISTER';
  const comparison = compareContractVersions(resolvedVersion, packagedVersion);
  if (comparison > 0) {
    throw new Error(`Resolved T3N contract version ${resolvedVersion} is newer than packaged ${packagedVersion}`);
  }
  return comparison < 0 ? 'REGISTER' : 'REUSE';
}

export async function reconcileAgentCardIndependently(
  reconcile: () => Promise<string>,
  observe: () => Promise<string>,
): Promise<string> {
  try {
    return await reconcile();
  } catch {
    try {
      return await observe();
    } catch {
      return 'UNAVAILABLE';
    }
  }
}

function booleanOverride(raw: string | undefined): boolean | null {
  if (raw == null || !raw.trim()) return null;
  const normalized = raw.trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  throw new Error('T3N_RUNTIME_PROVISIONING must be true or false when configured');
}

export function runtimeProvisioningEnabled(config: Pick<GatewayConfig, 'network'>, env: NodeJS.ProcessEnv = process.env): boolean {
  const override = booleanOverride(env.T3N_RUNTIME_PROVISIONING);
  if (override !== null) return override;
  return config.network === 'testnet' && env.NODE_ENV === 'production';
}

function isSafeHttpsEndpoint(value: string | undefined): value is string {
  if (!value?.trim()) return false;
  try {
    const parsed = new URL(value.trim());
    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, '');
    return parsed.protocol === 'https:'
      && !parsed.username
      && !parsed.password
      && hostname.length > 0
      && hostname !== 'example.invalid'
      && !hostname.endsWith('.invalid')
      && hostname !== 'postman-echo.com';
  } catch {
    return false;
  }
}

export function configuredEnterpriseHosts(env: NodeJS.ProcessEnv = process.env): string[] {
  const candidates = [env.SECURITY_API_URL, env.SECURITY_VERIFICATION_URL];
  const hosts = candidates
    .filter(isSafeHttpsEndpoint)
    .map((value) => new URL(value.trim()).hostname.toLowerCase().replace(/\.$/, ''));
  return [...new Set(hosts)].sort();
}

export function executorDelegationGrantRequest(
  contractId: string,
  contractVersion: string,
  env: NodeJS.ProcessEnv = process.env,
): DelegationGrantRequest {
  return {
    contractId,
    versionReq: contractVersion,
    functions: [...EXECUTOR_DELEGATION_REQUIREMENTS.functions],
    scopes: [...EXECUTOR_DELEGATION_REQUIREMENTS.scopes],
    allowedHosts: configuredEnterpriseHosts(env),
  };
}

function remediationConfigurationReady(env: NodeJS.ProcessEnv): boolean {
  const key = env.SECURITY_API_KEY?.trim();
  return Boolean(
    key
    && !key.startsWith('replace-with-')
    && isSafeHttpsEndpoint(env.SECURITY_API_URL)
    && isSafeHttpsEndpoint(env.SECURITY_VERIFICATION_URL),
  );
}

export function buildAdminProvisioningPlan(
  numericContractId: number | null,
  env: NodeJS.ProcessEnv = process.env,
): AdminProvisioningStep[] {
  const childEnv: NodeJS.ProcessEnv = { ...env };
  if (numericContractId !== null) {
    childEnv.T3N_CONTRACT_NUMERIC_ID = String(numericContractId);
  } else {
    delete childEnv.T3N_CONTRACT_NUMERIC_ID;
  }

  const steps: AdminProvisioningStep[] = [
    { scriptName: 'setup-policy.js', env: { ...childEnv } },
  ];
  if (remediationConfigurationReady(env)) {
    steps.push({ scriptName: 'setup-remediation-secrets.js', env: { ...childEnv } });
  }
  return steps;
}

export function provisioningStateMatches(
  state: RuntimeProvisioningState,
  expected: Pick<RuntimeProvisioningState, 'tenantDid' | 'contractId' | 'contractVersion'>,
): boolean {
  return state.tenantDid === expected.tenantDid
    && state.contractId === expected.contractId
    && state.contractVersion === expected.contractVersion
    && Number.isInteger(state.numericContractId)
    && state.numericContractId > 0;
}

export function parseProvisioningState(value: string): RuntimeProvisioningState | null {
  try {
    const parsed = JSON.parse(value) as Partial<RuntimeProvisioningState>;
    if (
      typeof parsed.tenantDid !== 'string'
      || typeof parsed.contractId !== 'string'
      || typeof parsed.contractVersion !== 'string'
      || typeof parsed.numericContractId !== 'number'
      || !Number.isInteger(parsed.numericContractId)
      || parsed.numericContractId <= 0
      || typeof parsed.updatedAt !== 'string'
    ) return null;
    return parsed as RuntimeProvisioningState;
  } catch {
    return null;
  }
}

function extractControlValue(value: unknown, depth = 0): string | null {
  if (depth > 4) return null;
  if (typeof value === 'string') return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8');
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  for (const key of ['value', 'data', 'result']) {
    const extracted = extractControlValue(record[key], depth + 1);
    if (extracted != null) return extracted;
  }
  return null;
}

function errorText(error: unknown): string {
  const record = error && typeof error === 'object' ? error as Record<string, unknown> : null;
  return [
    error instanceof Error ? error.message : null,
    typeof record?.detail === 'string' ? record.detail : null,
  ].filter((value): value is string => Boolean(value)).join(' ').toLowerCase();
}

function isMissingMapOrEntry(error: unknown): boolean {
  const text = errorText(error);
  return text.includes('map not found') || text.includes('entry not found') || text.includes('key not found');
}

function isAlreadyExists(error: unknown): boolean {
  return errorText(error).includes('already');
}

async function readProvisioningState(path: string): Promise<RuntimeProvisioningState | null> {
  try {
    return parseProvisioningState(await readFile(path, 'utf8'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    return null;
  }
}

async function persistProvisioningState(path: string, state: RuntimeProvisioningState): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(state, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
}

async function persistLocalProvisioningCache(path: string, state: RuntimeProvisioningState): Promise<void> {
  try {
    await persistProvisioningState(path, state);
  } catch {
    console.warn('Local T3N provisioning cache could not be persisted; remote T3N provisioning state remains authoritative');
  }
}

export async function readRemoteProvisioningState(control: ProvisioningControlPlane): Promise<RuntimeProvisioningState | null> {
  const mapName = control.canonicalName(REMOTE_STATE_MAP_TAIL);
  try {
    const raw = extractControlValue(await control.executeControl('map-entry-get', {
      map_name: mapName,
      key: REMOTE_STATE_KEY,
    }));
    return raw ? parseProvisioningState(raw) : null;
  } catch (error) {
    if (isMissingMapOrEntry(error)) return null;
    throw new Error('Remote T3N provisioning state could not be read');
  }
}

export async function persistRemoteProvisioningState(
  control: ProvisioningControlPlane,
  state: RuntimeProvisioningState,
): Promise<void> {
  const restrictedAcl = {
    writers: { only: [state.numericContractId] },
    readers: { only: [state.numericContractId] },
  };
  try {
    await control.maps.create({
      tail: REMOTE_STATE_MAP_TAIL,
      visibility: 'private',
      ...restrictedAcl,
    });
  } catch (error) {
    if (!isAlreadyExists(error)) throw new Error('Remote T3N provisioning state map could not be created');
    await control.maps.update(REMOTE_STATE_MAP_TAIL, restrictedAcl);
  }

  const mapName = control.canonicalName(REMOTE_STATE_MAP_TAIL);
  await control.executeControl('map-entry-set', {
    map_name: mapName,
    key: REMOTE_STATE_KEY,
    value: JSON.stringify(state),
  });
  const verified = await readRemoteProvisioningState(control);
  if (
    !verified
    || !provisioningStateMatches(verified, state)
    || verified.numericContractId !== state.numericContractId
    || verified.updatedAt !== state.updatedAt
  ) {
    throw new Error('Remote T3N provisioning state read-back did not match the current contract');
  }
}

function configuredNumericContractId(env: NodeJS.ProcessEnv): number | null {
  const value = Number(env.T3N_CONTRACT_NUMERIC_ID);
  return Number.isInteger(value) && value > 0 ? value : null;
}

async function defaultRunAdminScript(scriptName: string, env: NodeJS.ProcessEnv): Promise<void> {
  const scriptPath = resolve(process.cwd(), 'dist', 'scripts', scriptName);
  try {
    await execFileAsync(process.execPath, [scriptPath], {
      cwd: process.cwd(),
      env,
      timeout: 30_000,
      maxBuffer: 1024 * 1024,
    });
  } catch {
    throw new Error(`Runtime provisioning step ${scriptName} failed`);
  }
}

async function resolveOrRegisterContract(
  config: GatewayConfig,
  tenantSession: T3nSession,
  contractService: PrivacyGuardContractService,
  env: NodeJS.ProcessEnv,
): Promise<ContractResolution> {
  const tenantDid = tenantSession.getTenantDid();
  const canonicalContractId = await contractService.canonicalContractId();
  const statePath = env.T3N_RUNTIME_PROVISIONING_STATE_PATH?.trim() || DEFAULT_STATE_PATH;

  let identity: { contractId: string; contractVersion: string } | null = null;
  try {
    identity = await contractService.identity();
  } catch {
    identity = null;
  }

  if (identity && identity.contractId !== canonicalContractId) {
    throw new Error('Resolved T3N contract id is not canonical for the authenticated Tenant');
  }

  let tenant: TenantClient | null = null;
  const tenantControl = async (): Promise<TenantClient> => {
    if (!tenant) {
      tenant = new TenantClient({
        t3n: tenantSession.getClient(),
        baseUrl: getNodeUrl(),
        tenantDid,
      });
      await tenant.tenant.me();
    }
    return tenant;
  };

  const versionAction = contractVersionAction(identity?.contractVersion ?? null, config.contractVersion);
  if (identity && versionAction === 'REUSE') {
    let numericContractId = configuredNumericContractId(env);
    if (numericContractId === null) {
      const localState = await readProvisioningState(statePath);
      if (localState && provisioningStateMatches(localState, {
        tenantDid,
        contractId: identity.contractId,
        contractVersion: identity.contractVersion,
      })) {
        numericContractId = localState.numericContractId;
      }
    }

    if (numericContractId === null) {
      const remoteState = await readRemoteProvisioningState(await tenantControl());
      if (remoteState && provisioningStateMatches(remoteState, {
        tenantDid,
        contractId: identity.contractId,
        contractVersion: identity.contractVersion,
      })) {
        numericContractId = remoteState.numericContractId;
      }
    }

    if (numericContractId === null) {
      throw new Error('Numeric contract id is unavailable for the current packaged contract and no valid remote T3N provisioning state exists');
    }

    const state: RuntimeProvisioningState = {
      tenantDid,
      contractId: identity.contractId,
      contractVersion: identity.contractVersion,
      numericContractId,
      updatedAt: new Date().toISOString(),
    };
    await persistRemoteProvisioningState(await tenantControl(), state);
    await persistLocalProvisioningCache(statePath, state);
    return {
      contractId: identity.contractId,
      contractVersion: identity.contractVersion,
      numericContractId,
      registered: false,
    };
  }

  const tenantClient = await tenantControl();
  const wasmPath = resolve(env.T3N_CONTRACT_WASM_PATH?.trim() || DEFAULT_WASM_PATH);
  const wasm = await readFile(wasmPath);
  const registration = await tenantClient.contracts.register({
    tail: config.contractTail,
    version: config.contractVersion,
    wasm,
  });
  if (!Number.isInteger(registration.contract_id) || registration.contract_id <= 0) {
    throw new Error('T3N contract registration returned an invalid numeric contract id');
  }

  const verified = await contractService.identity();
  if (verified.contractId !== canonicalContractId || verified.contractVersion !== config.contractVersion) {
    throw new Error('T3N contract identity did not match the just-registered contract');
  }

  const state: RuntimeProvisioningState = {
    tenantDid,
    contractId: verified.contractId,
    contractVersion: verified.contractVersion,
    numericContractId: registration.contract_id,
    updatedAt: new Date().toISOString(),
  };
  await persistRemoteProvisioningState(tenantClient, state);
  await persistLocalProvisioningCache(statePath, state);
  return {
    contractId: verified.contractId,
    contractVersion: verified.contractVersion,
    numericContractId: registration.contract_id,
    registered: true,
  };
}

type AgentCardPublisher = (request: AgentCardPublicationRequest) => Promise<void>;

export async function reconcileAgentCard(
  config: GatewayConfig,
  tenantSession: T3nSession,
  agentSession: AgentSession,
  registry: AgentCardRegistry,
  sleep: (milliseconds: number) => Promise<void>,
  publish: AgentCardPublisher = publishAgentCardToOrganization,
): Promise<string> {
  let registration = await registry.verify();
  if (registration.state === 'REGISTERED') return registration.state;
  if (!config.orgDid || !config.agentApiKey) return registration.state;

  const card = serializeAgentCard(buildAgentCardForSession(agentSession, config.a2aPublicUrl));
  await publish({
    ownerDid: config.orgDid,
    agentDid: agentSession.getAgentDid(),
    adminDid: tenantSession.getTenantDid(),
    card,
    adminClient: tenantSession.getClient(),
    secrets: [config.apiKey, config.agentApiKey],
  });

  for (let attempt = 1; attempt <= MAX_CARD_VERIFY_ATTEMPTS; attempt += 1) {
    registration = await registry.verify();
    if (registration.state === 'REGISTERED') return registration.state;
    if (attempt < MAX_CARD_VERIFY_ATTEMPTS) await sleep(1_000);
  }
  throw new Error(`Published Agent Card did not verify as REGISTERED (${registration.state})`);
}

export async function reconcileRuntimeProvisioning(
  config: GatewayConfig,
  tenantSession: T3nSession,
  agentSession: AgentSession,
  executorSession: ExecutorSession,
  proposalDelegation: DelegationService,
  executorDelegation: DelegationService,
  contractService: PrivacyGuardContractService,
  agentCardRegistry: AgentCardRegistry,
  env: NodeJS.ProcessEnv = process.env,
  dependencies: RuntimeProvisioningDependencies = {},
): Promise<RuntimeProvisioningResult> {
  if (!runtimeProvisioningEnabled(config, env)) {
    return {
      enabled: false,
      contractResolved: false,
      contractRegistered: false,
      numericContractIdAvailable: false,
      policyReconciled: false,
      remediationReconciled: false,
      proposalDelegationReconciled: false,
      executorDelegationReconciled: false,
      agentCardState: 'NOT_CHECKED',
    };
  }

  const runAdminScript = dependencies.runAdminScript ?? defaultRunAdminScript;
  const sleep = dependencies.sleep ?? ((milliseconds: number) => new Promise<void>((resolveDelay) => setTimeout(resolveDelay, milliseconds)));

  await tenantSession.connect();
  if (config.agentApiKey) await agentSession.connect();
  if (config.executorApiKey) await executorSession.connect();

  const contract = await resolveOrRegisterContract(config, tenantSession, contractService, env);
  let policyReconciled = false;
  let remediationReconciled = false;
  let proposalDelegationReconciled = false;
  let executorDelegationReconciled = false;

  for (const step of buildAdminProvisioningPlan(contract.numericContractId, env)) {
    await runAdminScript(step.scriptName, step.env);
    if (step.scriptName === 'setup-policy.js') policyReconciled = true;
    if (step.scriptName === 'setup-remediation-secrets.js') remediationReconciled = true;
  }

  if (config.agentApiKey) {
    await proposalDelegation.grant({
      contractId: contract.contractId,
      versionReq: contract.contractVersion,
      functions: [...PROPOSAL_DELEGATION_REQUIREMENTS.functions],
      scopes: [...PROPOSAL_DELEGATION_REQUIREMENTS.scopes],
      allowedHosts: [],
    });
    proposalDelegationReconciled = true;
  }

  if (config.executorApiKey) {
    await executorDelegation.grant(executorDelegationGrantRequest(contract.contractId, contract.contractVersion, env));
    executorDelegationReconciled = true;
  }

  let agentCardState = 'UNAVAILABLE';
  if (config.agentApiKey) {
    agentCardState = await reconcileAgentCardIndependently(
      () => reconcileAgentCard(config, tenantSession, agentSession, agentCardRegistry, sleep),
      async () => (await agentCardRegistry.verify()).state,
    );
  }

  return {
    enabled: true,
    contractResolved: true,
    contractRegistered: contract.registered,
    numericContractIdAvailable: contract.numericContractId !== null,
    policyReconciled,
    remediationReconciled,
    proposalDelegationReconciled,
    executorDelegationReconciled,
    agentCardState,
  };
}
