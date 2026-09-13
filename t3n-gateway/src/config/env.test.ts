import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigurationError, readGatewayConfig } from './env.js';

const baseEnv = {
  T3N_API_KEY: 'tenant-secret',
  GATEWAY_SERVICE_TOKEN: 'gateway-service-token-1234567890123456',
  REMEDIATION_AUTH_PUBLIC_KEY: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
  REMEDIATION_AUTH_KEY_ID: 'primary-v2',
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
    REMEDIATION_AUTH_PUBLIC_KEY: baseEnv.REMEDIATION_AUTH_PUBLIC_KEY,
    REMEDIATION_AUTH_KEY_ID: baseEnv.REMEDIATION_AUTH_KEY_ID,
  }), ConfigurationError);
});

test('defaults to testnet, disabled AI, no public A2A, persistent trust floor and current contract version', () => {
  const config = readGatewayConfig(baseEnv);
  assert.equal(config.network, 'testnet');
  assert.equal(config.port, 3001);
  assert.equal(config.agentApiKey, null);
  assert.equal(config.executorApiKey, null);
  assert.equal(config.contractVersion, '0.4.0');
  assert.equal(config.remediationAuthorizationPublicKey, baseEnv.REMEDIATION_AUTH_PUBLIC_KEY);
  assert.equal(config.remediationAuthorizationKeyId, 'primary-v2');
  assert.equal(config.remediationReplayStorePath, '/data/remediation-capability-nonces.json');
  assert.equal(config.trustManifestFloorStorePath, '/data/t3n-trust-floor.json');
  assert.equal(config.aiProvider, 'disabled');
  assert.equal(config.aiApiKey, null);
  assert.equal(config.aiModel, null);
  assert.equal(config.a2aPublicUrl, null);
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

test('accepts and normalizes an HTTPS public A2A endpoint', () => {
  const config = readGatewayConfig({ ...baseEnv, A2A_PUBLIC_URL: 'https://guard.example/a2a/' });
  assert.equal(config.a2aPublicUrl, 'https://guard.example/a2a');
});

test('rejects unsafe, local, private or non-A2A public endpoints', () => {
  for (const url of [
    'http://guard.example/a2a',
    'https://user:password@guard.example/a2a',
    'https://guard.example/a2a?redirect=https://evil.example',
    'https://guard.example/a2a#fragment',
    'https://guard.example/not-a2a',
    'https://localhost/a2a',
    'https://service.local/a2a',
    'https://127.0.0.1/a2a',
    'https://10.0.0.2/a2a',
    'https://172.18.0.5/a2a',
    'https://192.168.1.10/a2a',
    'https://169.254.1.1/a2a',
    'https://[::1]/a2a',
    'https://[fd00::1]/a2a',
    'https://[fe80::1]/a2a',
    'javascript:alert(1)',
  ]) {
    assert.throws(() => readGatewayConfig({ ...baseEnv, A2A_PUBLIC_URL: url }), ConfigurationError, url);
  }
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

test('rejects missing or malformed internal security configuration', () => {
  assert.throws(() => readGatewayConfig({ T3N_API_KEY: 'tenant-secret' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, GATEWAY_SERVICE_TOKEN: 'short' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, REMEDIATION_AUTH_PUBLIC_KEY: 'not-a-key' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, REMEDIATION_AUTH_KEY_ID: 'invalid key id' }), ConfigurationError);
});

test('rejects unknown network', () => {
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_NETWORK: 'staging' }), ConfigurationError);
});
