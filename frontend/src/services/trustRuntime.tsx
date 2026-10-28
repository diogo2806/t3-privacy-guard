import { createContext, useContext } from 'react';

export interface TrustRuntimeInfo { readonly selfHosted: boolean; readonly name: string; }

export const T3N_RUNTIME: TrustRuntimeInfo = { selfHosted: false, name: 'T3N' };
export const SELF_HOSTED_RUNTIME: TrustRuntimeInfo = { selfHosted: true, name: 'Guard runtime' };

// Only an explicit selfhosted network switches the copy; anything else, including an unknown status, keeps T3N.
export function trustRuntimeOf(status: { network?: string | null } | null | undefined): TrustRuntimeInfo {
  return status?.network === 'selfhosted' ? SELF_HOSTED_RUNTIME : T3N_RUNTIME;
}

export const TrustRuntimeContext = createContext<TrustRuntimeInfo>(T3N_RUNTIME);

export function useTrustRuntime(): TrustRuntimeInfo {
  return useContext(TrustRuntimeContext);
}
