import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigurationError, readGatewayConfig } from './env.js';

const baseEnv = {
  T3N_API_KEY: 'tenant-secret',
  GATEWAY_SERVICE_TOKEN: 'gateway-service-token-1234567890123456',
  REMEDIATION_CAPABILITY_KEY: 'remediation-capability-key-123456789012',
};

function aiEnv(url: string) {
  return {
    ...baseEnv,
    AI_PROVIDER: 'openai-compatible',
    AI_API_URL: url,
    AI_API_KEY: 'provider-test-key',
    AI_MODEL: 'tool-model',
  };
}

test('rejects missing tenant API key', () => {
  assert.throws(() => readGatewayConfig({
    GATEWAY_SERVICE_TOKEN: baseEnv.GATEWAY_SERVICE_TOKEN,
    REMEDIATION_CAPABILITY_KEY: baseEnv.REMEDIATION_CAPABILITY_KEY,
  }), ConfigurationError);
});

test('defaults to testnet, disabled AI, persistent trust floor and current contract version', () => {
  const config = readGatewayConfig(baseEnv);
  assert.equal(config.network, 'testnet');
  assert.equal(config.port, 3001);
  assert.equal(config.agentApiKey, null);
  assert.equal(config.executorApiKey, null);
  assert.equal(config.contractVersion, '0.4.0');
  assert.equal(config.remediationReplayStorePath, '/data/remediation-capability-nonces.json');
  assert.equal(config.trustManifestFloorStorePath, '/data/t3n-trust-floor.json');
  assert.equal(config.aiProvider, 'disabled');
  assert.equal(config.aiApiKey, null);
  assert.equal(config.aiModel, null);
});

test('accepts distinct tenant proposal-agent and executor credentials', () => {
  const config = readGatewayConfig({
    ...baseEnv,
    T3N_AGENT_API_KEY: 'proposal-agent-secret',
    T3N_EXECUTOR_API_KEY: 'protected-executor-secret',
  });
  assert.equal(config.agentApiKey, 'proposal-agent-secret');
  assert.equal(config.executorApiKey, 'protected-executor-secret');
});

test('accepts a custom persistent trust manifest floor path', () => {
  assert.equal(readGatewayConfig({ ...baseEnv, T3N_TRUST_FLOOR_STORE_PATH: '/state/t3n-floor.json' }).trustManifestFloorStorePath, '/state/t3n-floor.json');
});

test('rejects explicitly empty persistent state paths', () => {
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_TRUST_FLOOR_STORE_PATH: '   ' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, REMEDIATION_REPLAY_STORE_PATH: '   ' }), ConfigurationError);
});

test('accepts HTTPS remote and explicit loopback HTTP AI providers', () => {
  for (const url of [
    'https://provider.example/v1/chat/completions',
    'http://localhost:11434/v1/chat/completions',
    'http://127.0.0.1:11434/v1/chat/completions',
    'http://127.1.2.3:11434/v1/chat/completions',
    'http://[::1]:11434/v1/chat/completions',
  ]) {
    assert.equal(readGatewayConfig(aiEnv(url)).aiApiUrl, url);
  }
});

test('rejects remote or non-loopback HTTP AI providers', () => {
  for (const url of [
    'http://provider.example/v1/chat/completions',
    'http://10.0.0.2/v1/chat/completions',
    'http://172.18.0.5/v1/chat/completions',
    'http://0.0.0.0/v1/chat/completions',
    'http://evil-localhost.example/v1/chat/completions',
  ]) {
    assert.throws(() => readGatewayConfig(aiEnv(url)), ConfigurationError, url);
  }
});

test('rejects AI provider URLs containing embedded credentials', () => {
  assert.throws(
    () => readGatewayConfig(aiEnv('https://user:password@provider.example/v1/chat/completions')),
    ConfigurationError,
  );
});

test('rejects enabled AI provider without model or key', () => {
  assert.throws(() => readGatewayConfig({ ...baseEnv, AI_PROVIDER: 'openai-compatible' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, AI_PROVIDER: 'unknown-provider' }), ConfigurationError);
});

test('rejects reuse of tenant key as proposal-agent or executor key', () => {
  assert.throws(
    () => readGatewayConfig({ ...baseEnv, T3N_API_KEY: 'same-secret', T3N_AGENT_API_KEY: 'same-secret' }),
    ConfigurationError,
  );
  assert.throws(
    () => readGatewayConfig({ ...baseEnv, T3N_API_KEY: 'same-secret', T3N_EXECUTOR_API_KEY: 'same-secret' }),
    ConfigurationError,
  );
});

test('rejects reuse of proposal-agent key as executor key', () => {
  assert.throws(
    () => readGatewayConfig({ ...baseEnv, T3N_AGENT_API_KEY: 'same-delegated-secret', T3N_EXECUTOR_API_KEY: 'same-delegated-secret' }),
    ConfigurationError,
  );
});

test('rejects missing or weak internal security secrets', () => {
  assert.throws(() => readGatewayConfig({ T3N_API_KEY: 'tenant-secret' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, GATEWAY_SERVICE_TOKEN: 'short' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, REMEDIATION_CAPABILITY_KEY: 'short' }), ConfigurationError);
});

test('rejects unknown network', () => {
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_NETWORK: 'staging' }), ConfigurationError);
});
