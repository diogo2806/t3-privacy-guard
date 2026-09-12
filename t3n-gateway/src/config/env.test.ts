import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigurationError, readGatewayConfig } from './env.js';

test('rejects missing tenant API key', () => {
  assert.throws(() => readGatewayConfig({}), ConfigurationError);
});

test('defaults to testnet and port 3001', () => {
  const config = readGatewayConfig({ T3N_API_KEY: 'tenant-secret' });
  assert.equal(config.network, 'testnet');
  assert.equal(config.port, 3001);
  assert.equal(config.agentApiKey, null);
});

test('rejects reuse of tenant key as agent key', () => {
  assert.throws(
    () => readGatewayConfig({ T3N_API_KEY: 'same-secret', T3N_AGENT_API_KEY: 'same-secret' }),
    ConfigurationError,
  );
});

test('rejects unknown network', () => {
  assert.throws(
    () => readGatewayConfig({ T3N_API_KEY: 'tenant-secret', T3N_NETWORK: 'staging' }),
    ConfigurationError,
  );
});
