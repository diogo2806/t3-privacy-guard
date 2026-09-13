import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AgentCardRegistrationService, buildAgentCard, serializeAgentCard } from '../agent/agent-card.js';
import { AgentSession } from '../agent/agent-session.js';
import { readGatewayConfig } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';

const config = readGatewayConfig();
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required to publish an Agent Card');

const session = new AgentSession(config, new TrustManifestFloorStore(config.trustManifestFloorStorePath));
await session.connect();
const agentDid = session.getAgentDid();
const serialized = serializeAgentCard(buildAgentCard(agentDid));
const directory = await mkdtemp(join(tmpdir(), 't3-privacy-guard-agent-card-'));
const cardPath = join(directory, 'agent-card.json');

try {
  await writeFile(cardPath, serialized, { encoding: 'utf8', mode: 0o600 });
  const executable = process.platform === 'win32' ? 't3n.cmd' : 't3n';
  const publish = spawnSync(executable, ['agent', 'host-card', '--file', cardPath, '--env', config.network], {
    cwd: process.cwd(),
    env: { ...process.env, T3N_API_KEY: config.agentApiKey },
    stdio: 'inherit',
  });
  if (publish.error) throw publish.error;
  if (publish.status !== 0) throw new Error('T3N Agent Card publication failed');

  const verified = await new AgentCardRegistrationService(session, config.network).verify();
  if (verified.agentRegistrationState !== 'REGISTERED') {
    throw new Error(`Published Agent Card did not verify as REGISTERED (${verified.agentRegistrationState})`);
  }
  process.stdout.write(`${JSON.stringify(verified, null, 2)}\n`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
