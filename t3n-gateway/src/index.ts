import express from 'express';

const app = express();
const port = Number(process.env.T3N_GATEWAY_PORT ?? 3001);

app.disable('x-powered-by');
app.get('/health', (_request, response) => {
  response.json({ status: 'UP', service: 't3n-gateway' });
});

app.listen(port, '0.0.0.0', () => {
  console.info(`t3n-gateway listening on port ${port}`);
});
