import { AgentCardRegistrationService } from '../agent/agent-card.js';
import { AgentSession } from '../agent/agent-session.js';
import { readGatewayConfig } from '../config/env.js';
import { assertNoSecretLeak } from '../evidence/leak-detector.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';

const config = readGatewayConfig();
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required to verify Agent Card registration');

const session = new AgentSession(config, new TrustManifestFloorStore(config.trustManifestFloorStorePath));
await session.connect();
const result = await new AgentCardRegistrationService(session, config.network).verify();
const serialized = `${JSON.stringify(result, null, 2)}\n`;
assertNoSecretLeak(serialized, [config.apiKey, config.agentApiKey, config.gatewayServiceToken, config.remediationCapabilityKey]);
process.stdout.write(serialized);
if (result.agentRegistrationState !== 'REGISTERED') process.exitCode = 1;
