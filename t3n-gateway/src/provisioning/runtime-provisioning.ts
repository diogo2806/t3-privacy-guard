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
import { publishAgentCardToOrganization } from '../agent/agent-card-publisher.js';
import type { AgentSession } from '../agent/agent-session.js';
import {
  EXECUTOR_DELEGATION_REQUIREMENTS,
  PROPOSAL_DELEGATION_REQUIREMENTS,
  type DelegationService,
} from '../agent/delegation-service.js';
import type { ExecutorSession } from '../agent/executor-session.js';
import type { GatewayConfig } from '../config/env.js';
import type { PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import type { T3nSession } from '../t3n/session.js';

const execFileAsync = promisify(execFile);
const DEFAULT_STATE_PATH = '/data/t3n-runtime-provisioning.json';
const DEFAULT_WASM_PATH = '/app/runtime/privacy_guard_contract.wasm';
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

function remediationConfigurationReady(env: NodeJS.ProcessEnv): boolean {
  const key = env.SECURITY_API_KEY?.trim();
  return Boolean(
    key
    && !key.startsWith('replace-with-')
    && isSafeHttpsEndpoint(env.SECURITY_API_URL)
    && isSafeHttpsEndpoint(env.SECURITY_VERIFICATION_URL),
  );
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

async function readProvisioningState(path: string): Promise<RuntimeProvisioningState | null> {
  try {
    const parsed = JSON.parse(await readFile(path, 'utf8')) as Partial<RuntimeProvisioningState>;
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
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    return null;
  }
}

async function persistProvisioningState(path: string, state: RuntimeProvisioningState): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(state, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
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

  if (identity) {
    if (identity.contractId !== canonicalContractId) throw new Error('Resolved T3N contract id is not canonical for the authenticated Tenant');
    if (identity.contractVersion !== config.contractVersion) {
      throw new Error(`Resolved T3N contract version ${identity.contractVersion} does not match configured ${config.contractVersion}`);
    }
    const state = await readProvisioningState(statePath);
    const persistedNumericId = state && provisioningStateMatches(state, {
      tenantDid,
      contractId: identity.contractId,
      contractVersion: identity.contractVersion,
    }) ? state.numericContractId : null;
    return {
      contractId: identity.contractId,
      contractVersion: identity.contractVersion,
      numericContractId: configuredNumericContractId(env) ?? persistedNumericId,
      registered: false,
    };
  }

  const tenant = new TenantClient({
    t3n: tenantSession.getClient(),
    baseUrl: getNodeUrl(),
    tenantDid,
  });
  await tenant.tenant.me();
  const wasmPath = resolve(env.T3N_CONTRACT_WASM_PATH?.trim() || DEFAULT_WASM_PATH);
  const wasm = await readFile(wasmPath);
  const registration = await tenant.contracts.register({
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
  await persistProvisioningState(statePath, state);
  return {
    contractId: verified.contractId,
    contractVersion: verified.contractVersion,
    numericContractId: registration.contract_id,
    registered: true,
  };
}

async function reconcileAgentCard(
  config: GatewayConfig,
  tenantSession: T3nSession,
  agentSession: AgentSession,
  registry: AgentCardRegistry,
  sleep: (milliseconds: number) => Promise<void>,
): Promise<string> {
  let registration = await registry.verify();
  if (registration.state === 'REGISTERED') return registration.state;
  if (!config.orgDid || !config.agentApiKey) return registration.state;

  const card = serializeAgentCard(buildAgentCardForSession(agentSession, config.a2aPublicUrl));
  await publishAgentCardToOrganization({
    ownerDid: config.orgDid,
    agentDid: agentSession.getAgentDid(),
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

  let agentCardState = 'UNAVAILABLE';
  if (config.agentApiKey) {
    agentCardState = await reconcileAgentCard(config, tenantSession, agentSession, agentCardRegistry, sleep);
  }

  const contract = await resolveOrRegisterContract(config, tenantSession, contractService, env);
  let policyReconciled = false;
  let remediationReconciled = false;
  let proposalDelegationReconciled = false;
  let executorDelegationReconciled = false;

  if (contract.numericContractId !== null) {
    const childEnv = {
      ...env,
      T3N_CONTRACT_NUMERIC_ID: String(contract.numericContractId),
    };
    await runAdminScript('setup-policy.js', childEnv);
    policyReconciled = true;

    if (remediationConfigurationReady(env)) {
      await runAdminScript('setup-remediation-secrets.js', childEnv);
      remediationReconciled = true;
    }
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

  const enterpriseHosts = configuredEnterpriseHosts(env);
  if (config.executorApiKey && remediationConfigurationReady(env) && enterpriseHosts.length > 0) {
    await executorDelegation.grant({
      contractId: contract.contractId,
      versionReq: contract.contractVersion,
      functions: [...EXECUTOR_DELEGATION_REQUIREMENTS.functions],
      scopes: [...EXECUTOR_DELEGATION_REQUIREMENTS.scopes],
      allowedHosts: enterpriseHosts,
    });
    executorDelegationReconciled = true;
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
