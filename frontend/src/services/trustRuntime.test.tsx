import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { SELF_HOSTED_RUNTIME, T3N_RUNTIME, TrustRuntimeContext, trustRuntimeOf, useTrustRuntime } from './trustRuntime';

function RuntimeName() {
  return <span>{useTrustRuntime().name}</span>;
}

afterEach(() => {
  cleanup();
});

describe('trustRuntimeOf', () => {
  it('names the self-hosted guard-runtime only for the selfhosted network', () => {
    expect(trustRuntimeOf({ network: 'selfhosted' })).toBe(SELF_HOSTED_RUNTIME);
    expect(SELF_HOSTED_RUNTIME).toEqual({ selfHosted: true, name: 'Guard runtime' });
  });

  it('keeps T3N for T3N networks, unexpected values and a missing status', () => {
    for (const status of [{ network: 'testnet' }, { network: 'production' }, { network: 'SELFHOSTED' }, { network: null }, {}, null, undefined]) {
      expect(trustRuntimeOf(status)).toBe(T3N_RUNTIME);
    }
    expect(T3N_RUNTIME).toEqual({ selfHosted: false, name: 'T3N' });
  });
});

describe('useTrustRuntime', () => {
  it('defaults to T3N outside a provider', () => {
    render(<RuntimeName />);
    expect(screen.getByText('T3N')).toBeInTheDocument();
  });

  it('reads the runtime supplied by the provider', () => {
    render(<TrustRuntimeContext.Provider value={SELF_HOSTED_RUNTIME}><RuntimeName /></TrustRuntimeContext.Provider>);
    expect(screen.getByText('Guard runtime')).toBeInTheDocument();
  });
});
