import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentCardRegistry, buildAgentCardForSession, serializeAgentCard } from '../agent/agent-card.js';
import { AgentSession } from '../agent/agent-session.js';
import { readGatewayConfig } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const gatewayRoot = resolve(scriptDir, '../..');
const config = readGatewayConfig();
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required to publish the public Agent Card');

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const agentSession = new AgentSession(config, trustFloorStore);
await agentSession.connect();
const agentDid = agentSession.getAgentDid();
const cardPath = resolve(process.env.AGENT_CARD_OUTPUT ?? resolve(gatewayRoot, 'agent-card.json'));
await writeFile(cardPath, serializeAgentCard(buildAgentCardForSession(agentSession, config.a2aPublicUrl)), { encoding: 'utf8', mode: 0o600 });

const binaryName = process.platform === 'win32' ? 't3n.cmd' : 't3n';
const cliPath = resolve(gatewayRoot, 'node_modules', '.bin', binaryName);
if (!existsSync(cliPath)) throw new Error('Local T3N CLI is unavailable. Run npm install in t3n-gateway first.');

console.info(`Publishing public Agent Card for ${agentDid} on ${config.network}. This is a mutable T3N operation and may consume credits.`);
const publish = spawnSync(cliPath, ['agent', 'host-card', '--file', cardPath, '--env', config.network], {
  cwd: gatewayRoot,
  env: { ...process.env, T3N_API_KEY: config.agentApiKey, T3N_ENV: config.network },
  stdio: 'inherit',
  shell: process.platform === 'win32',
});
if (publish.error || publish.status !== 0) throw new Error('T3N Agent Card publication failed');

const registry = new AgentCardRegistry(agentSession, undefined, undefined, config.a2aPublicUrl);
let registration = await registry.verify();
for (let attempt = 1; registration.state !== 'REGISTERED' && attempt < 4; attempt += 1) {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_000));
  registration = await registry.verify();
}
if (registration.state !== 'REGISTERED') throw new Error(`Published Agent Card did not verify as REGISTERED (${registration.state})`);
console.info(JSON.stringify(registration, null, 2));
