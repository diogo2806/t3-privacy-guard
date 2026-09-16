import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigurationError, readGatewayConfig } from './env.js';

const publicKeySpki = 'MCowBQYDK2VwAyEAW3EwSatHmT/ZSgrqu/G3ecXJrTviA5SjAoCwIfwau6A=';
const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${publicKeySpki}\n-----END PUBLIC KEY-----`;
const publicKeyPemBase64 = Buffer.from(publicKeyPem, 'ascii').toString('base64');
const baseEnv = {
  T3N_API_KEY: `0x${'44'.repeat(32)}`,
  GATEWAY_SERVICE_TOKEN: 'g'.repeat(32),
};

test('normalizes SPKI PEM and base64-wrapped PEM to DER base64', () => {
  for (const configuredKey of [publicKeyPem, publicKeyPemBase64]) {
    const config = readGatewayConfig({
      ...baseEnv,
      REMEDIATION_AUTH_PUBLIC_KEY_SPKI: configuredKey,
    });
    assert.equal(config.remediationAuthorizationPublicKeySpki, publicKeySpki);
  }
});

test('continues to accept canonical SPKI DER base64', () => {
  const config = readGatewayConfig({
    ...baseEnv,
    REMEDIATION_AUTH_PUBLIC_KEY_SPKI: publicKeySpki,
  });
  assert.equal(config.remediationAuthorizationPublicKeySpki, publicKeySpki);
});

test('rejects PEM with trailing data', () => {
  assert.throws(
    () => readGatewayConfig({
      ...baseEnv,
      REMEDIATION_AUTH_PUBLIC_KEY_SPKI: `${publicKeyPem}\nunexpected`,
    }),
    ConfigurationError,
  );
});
