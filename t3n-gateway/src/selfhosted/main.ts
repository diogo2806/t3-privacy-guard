import { readSelfHostedGatewayConfig } from '../config/env.js';
import { GuardRuntimeClient } from './guard-runtime-client.js';
import { createSelfHostedApp } from './self-hosted-app.js';
import { SelfHostedRuntime } from './self-hosted-runtime.js';

const config = readSelfHostedGatewayConfig();
const runtime = new SelfHostedRuntime(new GuardRuntimeClient(config.guardRuntime), config.guardRuntime);
const app = createSelfHostedApp(config, runtime);

app.listen(config.port, '0.0.0.0', () => {
  console.info(`t3n-gateway listening on port ${config.port} (trust runtime: selfhosted, guard-runtime: ${new URL(config.guardRuntime.url).host})`);
});

void runtime.tenantStatus().then((status) => {
  if (!status.ready) console.error('guard-runtime is not reachable yet; evaluation and remediation fail closed until it is');
});
