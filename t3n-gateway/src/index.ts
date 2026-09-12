import express from 'express';
import { readGatewayConfig } from './config/env.js';
import { createStatusRouter } from './http/status-router.js';
import { sanitizeError } from './security/sanitize.js';
import { T3nSession } from './t3n/session.js';

const config = readGatewayConfig();
const session = new T3nSession(config);
const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));

app.get('/health', (_request, response) => {
  response.json({ status: 'UP', service: 't3n-gateway' });
});
app.use('/internal/t3n', createStatusRouter(session));

app.listen(config.port, '0.0.0.0', () => {
  console.info(`t3n-gateway listening on port ${config.port}`);
});

void session.connect().catch((error) => {
  const safe = sanitizeError(error, [config.apiKey]);
  console.error(`Initial T3N connection failed [${safe.category}]: ${safe.message}`);
});
