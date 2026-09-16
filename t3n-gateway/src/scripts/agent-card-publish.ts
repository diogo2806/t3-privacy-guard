import { writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentCardRegistry, buildAgentCardForSession, serializeAgentCard } from '../agent/agent-card.js';
import { publishAgentCardToOrganization } from '../agent/agent-card-publisher.js';
import { AgentSession } from '../agent/agent-session.js';
import { readGatewayConfig } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const gatewayRoot = resolve(scriptDir, '../..');
const config = readGatewayConfig();
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required to publish the public Agent Card');
if (!config.orgDid) throw new Error('T3N_ORG_DID is required to publish the public Agent Card');

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const adminSession = new T3nSession(config, trustFloorStore);
const agentSession = new AgentSession(config, trustFloorStore);
await adminSession.connect();
await agentSession.connect();

const agentDid = agentSession.getAgentDid();
const card = serializeAgentCard(buildAgentCardForSession(agentSession, config.a2aPublicUrl));
const cardPath = resolve(process.env.AGENT_CARD_OUTPUT ?? resolve(gatewayRoot, 'agent-card.json'));
await writeFile(cardPath, card, { encoding: 'utf8', mode: 0o600 });

console.info(`Publishing public Agent Card for ${agentDid} owned by ${config.orgDid} on ${config.network}. This is a mutable T3N operation and may consume credits.`);
await publishAgentCardToOrganization({
  ownerDid: config.orgDid,
  agentDid,
  card,
  adminClient: adminSession.getClient(),
  secrets: [config.apiKey, config.agentApiKey],
});

const registry = new AgentCardRegistry(agentSession, undefined, undefined, config.a2aPublicUrl);
let registration = await registry.verify();
for (let attempt = 1; registration.state !== 'REGISTERED' && attempt < 4; attempt += 1) {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_000));
  registration = await registry.verify();
}
if (registration.state !== 'REGISTERED') throw new Error(`Published Agent Card did not verify as REGISTERED (${registration.state})`);
console.info(JSON.stringify(registration, null, 2));
