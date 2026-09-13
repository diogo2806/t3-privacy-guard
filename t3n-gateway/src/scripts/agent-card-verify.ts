import { AgentCardRegistry } from '../agent/agent-card.js';
import { AgentSession } from '../agent/agent-session.js';
import { readGatewayConfig } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';

const config = readGatewayConfig();
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required to verify public Agent onboarding');

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const agentSession = new AgentSession(config, trustFloorStore);
await agentSession.connect();
const registration = await new AgentCardRegistry(agentSession, undefined, undefined, config.a2aPublicUrl).verify();
console.info(JSON.stringify(registration, null, 2));
if (registration.state !== 'REGISTERED') process.exitCode = 1;
