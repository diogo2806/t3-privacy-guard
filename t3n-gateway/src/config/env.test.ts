import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigurationError, readGatewayConfig } from './env.js';

const baseEnv = {
  T3N_API_KEY: 'tenant-secret',
  GATEWAY_SERVICE_TOKEN: 'gateway-service-token-1234567890123456',
  REMEDIATION_CAPABILITY_KEY: 'remediation-capability-key-123456789012',
};

function aiEnv(url: string): NodeJS.ProcessEnv {
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

test('defaults to testnet, disabled AI and current contract version', () => {
  const config = readGatewayConfig(baseEnv);
  assert.equal(config.network, 'testnet');
  assert.equal(config.port, 3001);
  assert.equal(config.agentApiKey, null);
  assert.equal(config.contractVersion, '0.3.0');
  assert.equal(config.remediationReplayStorePath, '/data/remediation-capability-nonces.json');
  assert.equal(config.aiProvider, 'disabled');
  assert.equal(config.aiApiKey, null);
  assert.equal(config.aiModel, null);
});

test('accepts HTTPS for remote OpenAI-compatible providers', () => {
  const config = readGatewayConfig(aiEnv('https://provider.example/v1/chat/completions'));
  assert.equal(config.aiProvider, 'openai-compatible');
  assert.equal(config.aiApiUrl, 'https://provider.example/v1/chat/completions');
  assert.equal(config.aiModel, 'tool-model');
});

test('allows HTTP only on explicit loopback hosts', () => {
  for (const url of [
    'http://localhost:11434/v1/chat/completions',
    'http://127.0.0.1:11434/v1/chat/completions',
    'http://127.10.20.30:11434/v1/chat/completions',
    'http://[::1]:11434/v1/chat/completions',
  ]) {
    assert.equal(readGatewayConfig(aiEnv(url)).aiApiUrl, url);
  }
});

test('rejects remote or non-loopback HTTP provider URLs', () => {
  for (const url of [
    'http://provider.example/v1/chat/completions',
    'http://10.0.0.2:11434/v1/chat/completions',
    'http://172.18.0.5:11434/v1/chat/completions',
    'http://0.0.0.0:11434/v1/chat/completions',
    'http://evil-localhost.example/v1/chat/completions',
  ]) {
    assert.throws(() => readGatewayConfig(aiEnv(url)), ConfigurationError);
  }
});

test('rejects embedded credentials and unsupported schemes in AI provider URL', () => {
  assert.throws(() => readGatewayConfig(aiEnv('https://user:password@provider.example/v1/chat/completions')), ConfigurationError);
  assert.throws(() => readGatewayConfig(aiEnv('ftp://provider.example/v1/chat/completions')), ConfigurationError);
});

test('rejects enabled AI provider without model or key', () => {
  assert.throws(() => readGatewayConfig({ ...baseEnv, AI_PROVIDER: 'openai-compatible' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, AI_PROVIDER: 'unknown-provider' }), ConfigurationError);
});

test('rejects reuse of tenant key as agent key', () => {
  assert.throws(
    () => readGatewayConfig({ ...baseEnv, T3N_API_KEY: 'same-secret', T3N_AGENT_API_KEY: 'same-secret' }),
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
