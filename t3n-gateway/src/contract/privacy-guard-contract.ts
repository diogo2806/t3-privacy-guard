import { getContractVersion, getNodeUrl } from '@terminal3/t3n-sdk';
import type { AgentSession } from '../agent/agent-session.js';
import type { T3nSession } from '../t3n/session.js';
import type { GatewayConfig } from '../config/env.js';

export type PolicyDecisionType = 'ALLOW' | 'REDACT' | 'DENY';
export interface PolicyEvaluationRequest { readonly request_id:string; readonly agent_did:string; readonly action:string; readonly resource:string; readonly purpose:string; readonly host?:string; readonly fields:string[]; }
export interface PolicyDecision { readonly request_id:string; readonly decision:PolicyDecisionType; readonly reason_code:string; readonly reason:string; readonly allowed_fields:string[]; readonly redacted_fields:string[]; }
export interface RemediationResult { readonly request_id:string; readonly status:'COMPLETED'; readonly http_code:number; readonly operation_id?:string|null; }

function isDecision(value: unknown): value is PolicyDecision { if(!value||typeof value!=='object')return false; const c=value as Partial<PolicyDecision>; return typeof c.request_id==='string'&&(c.decision==='ALLOW'||c.decision==='REDACT'||c.decision==='DENY')&&typeof c.reason_code==='string'&&typeof c.reason==='string'&&Array.isArray(c.allowed_fields)&&Array.isArray(c.redacted_fields); }
function isRemediation(value: unknown): value is RemediationResult { if(!value||typeof value!=='object')return false; const c=value as Partial<RemediationResult>; return typeof c.request_id==='string'&&c.status==='COMPLETED'&&typeof c.http_code==='number'; }

export class PrivacyGuardContractService {
  constructor(private readonly config: GatewayConfig, private readonly tenantSession: T3nSession, private readonly agentSession: AgentSession) {}
  async canonicalContractId(): Promise<string> { await this.tenantSession.connect(); const tenantId=this.tenantSession.getTenantDid().slice('did:t3n:'.length); return `z:${tenantId}:${this.config.contractTail}`; }
  private async version(contractId:string):Promise<string>{ return getContractVersion(getNodeUrl(),contractId); }

  async evaluate(request: Omit<PolicyEvaluationRequest,'agent_did'>): Promise<PolicyDecision> {
    await this.agentSession.connect(); const contractId=await this.canonicalContractId();
    const result=await this.agentSession.getClient().executeAndDecode({ contract_id:contractId, contract_version:await this.version(contractId), function_name:'evaluate-action', input:{...request,agent_did:this.agentSession.getAgentDid()} });
    if(!isDecision(result)) throw new Error('T3N contract returned an invalid policy decision');
    return result;
  }

  async remediate(request: Omit<PolicyEvaluationRequest,'agent_did'|'host'>): Promise<RemediationResult> {
    await this.agentSession.connect(); const contractId=await this.canonicalContractId();
    const result=await this.agentSession.getClient().executeAndDecode({ contract_id:contractId, contract_version:await this.version(contractId), function_name:'execute-remediation', input:{...request,agent_did:this.agentSession.getAgentDid()} });
    if(!isRemediation(result)) throw new Error('T3N contract returned an invalid remediation result');
    return result;
  }
}
