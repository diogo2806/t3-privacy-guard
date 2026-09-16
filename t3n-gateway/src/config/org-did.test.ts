import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigurationError, readGatewayConfig, validateCanonicalT3nDid } from './env.js';

const publicKeySpki = 'MCowBQYDK2VwAyEAW3EwSatHmT/ZSgrqu/G3ecXJrTviA5SjAoCwIfwau6A=';
const baseEnv = {
  T3N_API_KEY: `0x${'1'.repeat(64)}`,
  GATEWAY_SERVICE_TOKEN: 'gateway-service-token-1234567890123456',
  REMEDIATION_AUTH_PUBLIC_KEY_SPKI: publicKeySpki,
};

test('accepts a canonical organization DID and preserves it in gateway configuration', () => {
  const config = readGatewayConfig({
    ...baseEnv,
    T3N_ORG_DID: ' did:t3n:organization123 ',
  });

  assert.equal(config.orgDid, 'did:t3n:organization123');
});

test('keeps organization DID optional for runtime paths that do not publish Agent Cards', () => {
  assert.equal(readGatewayConfig(baseEnv).orgDid, null);
});

test('rejects malformed or non-canonical organization DIDs', () => {
  for (const value of [
    'organization123',
    'did:example:organization123',
    'did:t3n:',
    'did:t3n:organization-123',
    'did:t3n:organization/123',
    'DID:T3N:organization123',
  ]) {
    assert.throws(
      () => readGatewayConfig({ ...baseEnv, T3N_ORG_DID: value }),
      (error: unknown) => error instanceof ConfigurationError
        && error.message === 'T3N_ORG_DID must be a canonical did:t3n:<id>',
      value,
    );
  }
});

test('canonical DID validation never echoes an invalid value', () => {
  const invalid = 'did:t3n:bad/value-that-should-not-be-echoed';
  assert.throws(
    () => validateCanonicalT3nDid(invalid, 'T3N_ORG_DID'),
    (error: unknown) => error instanceof ConfigurationError
      && !error.message.includes(invalid),
  );
});
