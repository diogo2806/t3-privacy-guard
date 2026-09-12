import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigurationError, readGatewayConfig } from './env.js';

test('rejects missing API key', () => {
  assert.throws(() => readGatewayConfig({}), ConfigurationError);
});

test('defaults to testnet and port 3001', () => {
  const config = readGatewayConfig({ T3N_API_KEY: 'test-secret' });
  assert.equal(config.network, 'testnet');
  assert.equal(config.port, 3001);
});

test('rejects unknown network', () => {
  assert.throws(
    () => readGatewayConfig({ T3N_API_KEY: 'test-secret', T3N_NETWORK: 'staging' }),
    ConfigurationError,
  );
});
