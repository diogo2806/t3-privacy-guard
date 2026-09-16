import type { SanitizedError } from '../security/sanitize.js';

export type PrincipalIdentityRole = 'tenant' | 'proposal-agent' | 'protected-executor';

export interface PrincipalIdentitySnapshot {
  readonly tenantDid: string | null;
  readonly proposalAgentDid: string | null;
  readonly protectedExecutorDid: string | null;
}

export class PrincipalIdentityConflictError extends Error {
  constructor() {
    super('T3N authenticated principal identity separation is invalid: configured principals must use distinct DIDs');
    this.name = 'PrincipalIdentityConflictError';
  }
}

export function assertDistinctPrincipalDids(snapshot: PrincipalIdentitySnapshot): void {
  const authenticatedDids = [snapshot.tenantDid, snapshot.proposalAgentDid, snapshot.protectedExecutorDid]
    .filter((did): did is string => Boolean(did));
  if (new Set(authenticatedDids).size !== authenticatedDids.length) {
    throw new PrincipalIdentityConflictError();
  }
}

interface ReadyStatus {
  readonly ready: boolean;
  readonly lastError: SanitizedError | null;
}

export class PrincipalIdentityGuard {
  private readonly dids: Record<PrincipalIdentityRole, string | null> = {
    tenant: null,
    'proposal-agent': null,
    'protected-executor': null,
  };

  recordAuthenticated(role: PrincipalIdentityRole, did: string): void {
    this.dids[role] = did;
    this.assertDistinct();
  }

  clear(role: PrincipalIdentityRole): void {
    this.dids[role] = null;
  }

  snapshot(): PrincipalIdentitySnapshot {
    return {
      tenantDid: this.dids.tenant,
      proposalAgentDid: this.dids['proposal-agent'],
      protectedExecutorDid: this.dids['protected-executor'],
    };
  }

  assertDistinct(): void {
    assertDistinctPrincipalDids(this.snapshot());
  }

  protectStatus<T extends ReadyStatus>(status: T): T {
    try {
      this.assertDistinct();
      return status;
    } catch (error) {
      if (!(error instanceof PrincipalIdentityConflictError)) throw error;
      return {
        ...status,
        ready: false,
        lastError: {
          category: 'AUTHENTICATION',
          message: error.message,
        },
      };
    }
  }
}
