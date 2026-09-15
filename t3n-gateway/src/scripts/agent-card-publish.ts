import { createOrgDataClientFromSession, getNodeUrl } from '@terminal3/t3n-sdk';
import { AgentCardRegistry, buildAgentCardForSession, serializeAgentCard } from '../agent/agent-card.js';
import { AgentSession } from '../agent/agent-session.js';
import { readGatewayConfig } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';

const config = readGatewayConfig();
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required to publish the public Agent Card');

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const agentSession = new AgentSession(config, trustFloorStore);
await agentSession.connect();
const agentDid = agentSession.getAgentDid();
const card = serializeAgentCard(buildAgentCardForSession(agentSession, config.a2aPublicUrl));
const orgData = createOrgDataClientFromSession(agentSession.getClient(), getNodeUrl());

console.info(`Publishing public Agent Card for ${agentDid} on ${config.network}. This is a mutable T3N operation and may consume credits.`);
await orgData.agentCardSet({ ownerDid: agentDid, agentDid, card });
await orgData.agentCardPublish({ ownerDid: agentDid, agentDid });

const registry = new AgentCardRegistry(agentSession, undefined, undefined, config.a2aPublicUrl);
let registration = await registry.verify();
for (let attempt = 1; registration.state !== 'REGISTERED' && attempt < 4; attempt += 1) {
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_000));
  registration = await registry.verify();
}
if (registration.state !== 'REGISTERED') throw new Error(`Published Agent Card did not verify as REGISTERED (${registration.state})`);
console.info(JSON.stringify(registration, null, 2));
