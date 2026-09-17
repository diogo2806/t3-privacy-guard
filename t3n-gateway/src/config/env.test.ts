import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigurationError, readGatewayConfig, rejectDocumentationPlaceholder } from './env.js';

const publicKeySpki = 'MCowBQYDK2VwAyEAW3EwSatHmT/ZSgrqu/G3ecXJrTviA5SjAoCwIfwau6A=';
const tenantKey = `0x${'11'.repeat(32)}`;
const proposalSecpKey = `0x${'22'.repeat(32)}`;
const executorSecpKey = `0x${'33'.repeat(32)}`;
const proposalOrgKey = 't3n_key_proposal01.secret_value_1234567890';
const executorOrgKey = 't3n_key_executor01.secret_value_0987654321';
const baseEnv = {
  T3N_API_KEY: tenantKey,
  GATEWAY_SERVICE_TOKEN: 'gateway-service-token-1234567890123456',
  REMEDIATION_AUTH_PUBLIC_KEY_SPKI: publicKeySpki,
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
    REMEDIATION_AUTH_PUBLIC_KEY_SPKI: publicKeySpki,
  }), ConfigurationError);
});

test('rejects tenant credentials that are not exact secp256k1 private keys without echoing them', () => {
  for (const invalid of ['tenant-secret', '0x1234', proposalOrgKey]) {
    assert.throws(
      () => readGatewayConfig({ ...baseEnv, T3N_API_KEY: invalid }),
      (error: unknown) => error instanceof ConfigurationError
        && error.message === 'T3N_API_KEY must be a 0x-prefixed 32-byte secp256k1 private key'
        && !error.message.includes(invalid),
    );
  }
});

test('defaults to testnet, disabled AI, versioned remediation key, no public A2A, no organization DID, persistent trust floor and packaged contract version', () => {
  const config = readGatewayConfig(baseEnv);
  assert.equal(config.network, 'testnet');
  assert.equal(config.port, 3001);
  assert.equal(config.agentApiKey, null);
  assert.equal(config.executorApiKey, null);
  assert.equal(config.orgDid, null);
  assert.equal(config.contractVersion, '0.4.2');
  assert.equal(config.remediationAuthorizationPublicKeySpki, publicKeySpki);
  assert.equal(config.remediationAuthorizationKeyId, 'primary');
  assert.equal(config.remediationReplayStorePath, '/data/remediation-capability-nonces.json');
  assert.equal(config.trustManifestFloorStorePath, '/data/t3n-trust-floor.json');
  assert.equal(config.aiProvider, 'disabled');
  assert.equal(config.aiApiKey, null);
  assert.equal(config.aiModel, null);
  assert.equal(config.a2aPublicUrl, null);
});

test('normalizes legacy 0.4.0 and 0.4.1 deployment settings to packaged contract 0.4.2', () => {
  assert.equal(readGatewayConfig({ ...baseEnv, T3N_CONTRACT_VERSION: '0.4.0' }).contractVersion, '0.4.2');
  assert.equal(readGatewayConfig({ ...baseEnv, T3N_CONTRACT_VERSION: '0.4.1' }).contractVersion, '0.4.2');
  assert.equal(readGatewayConfig({ ...baseEnv, T3N_CONTRACT_VERSION: '0.4.2' }).contractVersion, '0.4.2');
});

test('rejects contract versions that do not match the packaged artifact or supported legacy migration', () => {
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_CONTRACT_VERSION: '0.4.3' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_CONTRACT_VERSION: '0.5.0' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_CONTRACT_VERSION: 'invalid' }), ConfigurationError);
});

test('accepts and validates a canonical organization DID', () => {
  assert.equal(readGatewayConfig({ ...baseEnv, T3N_ORG_DID: ' did:t3n:organization123 ' }).orgDid, 'did:t3n:organization123');
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_ORG_DID: 'did:web:organization.example' }), ConfigurationError);
});

test('accepts an explicit safe remediation authorization key id', () => {
  assert.equal(readGatewayConfig({ ...baseEnv, REMEDIATION_AUTH_KEY_ID: 'rotation-2026-09' }).remediationAuthorizationKeyId, 'rotation-2026-09');
});

test('rejects unsafe remediation authorization key ids', () => {
  for (const keyId of ['', '../../bad', 'contains space', 'x'.repeat(33)]) {
    assert.throws(() => readGatewayConfig({ ...baseEnv, REMEDIATION_AUTH_KEY_ID: keyId }), ConfigurationError);
  }
});

test('accepts distinct secp256k1 and organization-owned proposal/executor credentials', () => {
  const orgConfig = readGatewayConfig({
    ...baseEnv,
    T3N_AGENT_API_KEY: proposalOrgKey,
    T3N_EXECUTOR_API_KEY: executorOrgKey,
  });
  assert.equal(orgConfig.agentApiKey, proposalOrgKey);
  assert.equal(orgConfig.executorApiKey, executorOrgKey);

  const secpConfig = readGatewayConfig({
    ...baseEnv,
    T3N_AGENT_API_KEY: proposalSecpKey,
    T3N_EXECUTOR_API_KEY: executorSecpKey,
  });
  assert.equal(secpConfig.agentApiKey, proposalSecpKey);
  assert.equal(secpConfig.executorApiKey, executorSecpKey);
});

test('rejects unsupported or malformed proposal/executor credentials without echoing them', () => {
  const invalidValues = ['proposal-agent-secret', 't3n_key_missing-secret', '0x1234'];
  for (const invalid of invalidValues) {
    for (const name of ['T3N_AGENT_API_KEY', 'T3N_EXECUTOR_API_KEY'] as const) {
      assert.throws(
        () => readGatewayConfig({ ...baseEnv, [name]: invalid }),
        (error: unknown) => error instanceof ConfigurationError
          && error.message.includes(`${name} must be a supported`)
          && !error.message.includes(invalid),
      );
    }
  }
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
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_AGENT_API_KEY: tenantKey }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_EXECUTOR_API_KEY: tenantKey }), ConfigurationError);
});

test('rejects reuse of proposal-agent key as executor key', () => {
  assert.throws(
    () => readGatewayConfig({ ...baseEnv, T3N_AGENT_API_KEY: proposalOrgKey, T3N_EXECUTOR_API_KEY: proposalOrgKey }),
    ConfigurationError,
  );
});

test('rejects missing or invalid internal security configuration', () => {
  assert.throws(() => readGatewayConfig({ T3N_API_KEY: tenantKey }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, GATEWAY_SERVICE_TOKEN: 'short' }), ConfigurationError);
  assert.throws(() => readGatewayConfig({ ...baseEnv, REMEDIATION_AUTH_PUBLIC_KEY_SPKI: 'not-an-ed25519-spki' }), ConfigurationError);
});

test('rejects documented gateway service token without echoing it', () => {
  const placeholder = 'replace-with-at-least-32-random-characters';
  assert.throws(
    () => readGatewayConfig({ ...baseEnv, GATEWAY_SERVICE_TOKEN: placeholder }),
    (error: unknown) => error instanceof ConfigurationError
      && error.message === 'GATEWAY_SERVICE_TOKEN must be replaced with a runtime-specific value'
      && !error.message.includes(placeholder),
  );
});

test('rejects documented remediation API key before setup can use it', () => {
  const placeholder = 'replace-with-synthetic-or-real-remediation-key';
  assert.throws(
    () => rejectDocumentationPlaceholder(placeholder, 'SECURITY_API_KEY'),
    (error: unknown) => error instanceof ConfigurationError
      && error.message === 'SECURITY_API_KEY must be replaced with a runtime-specific value'
      && !error.message.includes(placeholder),
  );
  assert.doesNotThrow(() => rejectDocumentationPlaceholder('runtime-remediation-key-value', 'SECURITY_API_KEY'));
});

test('rejects unknown network', () => {
  assert.throws(() => readGatewayConfig({ ...baseEnv, T3N_NETWORK: 'staging' }), ConfigurationError);
});
