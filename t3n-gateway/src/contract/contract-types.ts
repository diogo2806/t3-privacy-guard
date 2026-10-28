// Wire types and response validators shared by the T3N contract service and the self-hosted runtime client.
// Kept free of the T3N SDK so the self-hosted gateway never loads it.

export type PolicyDecisionType = 'ALLOW' | 'REDACT' | 'DENY';

export interface ActivityAnnotated {
  readonly activity_sequence?: number;
  readonly activity_hash?: string;
}

export interface PolicyEvaluationRequest {
  readonly request_id: string;
  readonly agent_did: string;
  readonly action: string;
  readonly resource: string;
  readonly purpose: string;
  readonly host?: string;
  readonly fields: string[];
  readonly private_refs?: string[];
}

export interface PolicyDecision extends ActivityAnnotated {
  readonly request_id: string;
  readonly decision: PolicyDecisionType;
  readonly reason_code: string;
  readonly reason: string;
  readonly allowed_fields: string[];
  readonly redacted_fields: string[];
  readonly allowed_private_refs: string[];
  readonly redacted_private_refs: string[];
  readonly policy_version: string | null;
  readonly policy_hash: string | null;
  readonly requires_human_authorization: boolean;
}

export interface RemediationExecutionRequest {
  readonly incident_id?: string;
  readonly action_id?: string;
  readonly decision_id?: string;
  readonly request_id: string;
  readonly action: string;
  readonly resource: string;
  readonly purpose: string;
  readonly approved_host: string;
  readonly fields: string[];
  readonly normal_payload: Record<string, string>;
  readonly private_refs?: string[];
  readonly policy_version: string;
  readonly policy_hash: string;
  readonly executor_did?: string;
  readonly authorization_proof?: string;
}

export interface RemediationResult extends ActivityAnnotated {
  readonly request_id: string;
  readonly status: 'PENDING_VERIFICATION';
  readonly http_code: number;
  readonly operation_id?: string | null;
  readonly policy_version: string;
  readonly policy_hash: string;
}

export interface PayloadMinimizationProof {
  readonly must_egress_seen: boolean;
  readonly must_not_egress_seen: boolean;
}

export interface RemediationVerificationRequest {
  readonly request_id: string;
  readonly operation_id: string;
  readonly action?: 'revoke-credential' | 'notify-security';
  readonly expected_state: 'REVOKED' | 'DELIVERED';
}

export interface RemediationVerificationResult extends ActivityAnnotated {
  readonly request_id: string;
  readonly status: 'VERIFIED' | 'UNVERIFIED';
  readonly observed_state?: string | null;
  readonly recipient_resolved?: boolean | null;
  readonly payload_proof?: PayloadMinimizationProof | null;
}

export interface ContractIdentity { readonly contractId: string; readonly contractVersion: string; }

function validPolicyMetadata(version: unknown, hash: unknown): boolean {
  return (version == null && hash == null)
    || (typeof version === 'string' && version.length > 0 && typeof hash === 'string' && /^[a-f0-9]{64}$/.test(hash));
}

export function isPolicyDecision(value: unknown): value is PolicyDecision {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<PolicyDecision>;
  return typeof candidate.request_id === 'string'
    && (candidate.decision === 'ALLOW' || candidate.decision === 'REDACT' || candidate.decision === 'DENY')
    && typeof candidate.reason_code === 'string'
    && typeof candidate.reason === 'string'
    && Array.isArray(candidate.allowed_fields)
    && Array.isArray(candidate.redacted_fields)
    && Array.isArray(candidate.allowed_private_refs)
    && Array.isArray(candidate.redacted_private_refs)
    && validPolicyMetadata(candidate.policy_version, candidate.policy_hash)
    && typeof candidate.requires_human_authorization === 'boolean';
}

export function isRemediationResult(value: unknown): value is RemediationResult {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<RemediationResult>;
  return typeof candidate.request_id === 'string'
    && candidate.status === 'PENDING_VERIFICATION'
    && typeof candidate.http_code === 'number'
    && typeof candidate.policy_version === 'string'
    && typeof candidate.policy_hash === 'string'
    && /^[a-f0-9]{64}$/.test(candidate.policy_hash);
}

export function isVerificationResult(value: unknown): value is RemediationVerificationResult {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<RemediationVerificationResult>;
  const proof = candidate.payload_proof;
  const validProof = proof == null
    || (typeof proof === 'object'
      && typeof proof.must_egress_seen === 'boolean'
      && typeof proof.must_not_egress_seen === 'boolean');
  return typeof candidate.request_id === 'string'
    && (candidate.status === 'VERIFIED' || candidate.status === 'UNVERIFIED')
    && (candidate.observed_state == null || typeof candidate.observed_state === 'string')
    && (candidate.recipient_resolved == null || typeof candidate.recipient_resolved === 'boolean')
    && validProof;
}

export interface ActivityReference {
  readonly sequence: number;
  readonly hash: string;
}

export function annotate<T extends object>(result: T, activity?: ActivityReference): T & ActivityAnnotated {
  return activity ? { ...result, activity_sequence: activity.sequence, activity_hash: activity.hash } : result;
}

